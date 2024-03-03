from rest_framework.views import APIView
from rest_framework import permissions, status, pagination
from rest_framework.response import Response
from rest_framework.exceptions import NotFound
from rest_framework.parsers import MultiPartParser, FormParser
from django.core.paginator import InvalidPage
from urllib.parse import urlencode, urlparse, urlunparse, parse_qs
from ..serializers import EventSerializer, EventViewSerializer, CommentEventReportSerializer, CommentEventSerializer, CommentEventReactionSerializer, UserParticipateSerializer, EventParticipantsSerializer, EventAddSerializer, EventReportSerializer, EventEditSerializer
from ..models import Category, Province, City, Event, EventImage, EventReport, OrderedTicket, Ticket, CommentEvent, CommentEventReaction, CommentEventReport, Series
from .functions import token_verify, actual_comments
from django.utils import timezone
from django.db.models import Count, Value, CharField, BooleanField, Q, OuterRef, Subquery, Exists, ExpressionWrapper, F, Func
from django.db.models.functions import Concat, JSONObject, Coalesce
from django.contrib.gis.db.models.functions import Distance
from django.contrib.gis.measure import D
import math
import datetime
from django.contrib.postgres.expressions import ArraySubquery
from django.core.exceptions import ValidationError

class EventsPagePagination(pagination.PageNumberPagination):
    page_size = 50
    page_query_param = 'page'

    def paginate_queryset_custom(self, queryset, request, view=None):

        page_size = self.get_page_size(request)
        if not page_size:
            return None

        paginator = self.django_paginator_class(queryset, page_size)
        page_number = self.get_page_number(request, paginator)

        try:
            self.page = paginator.page(page_number)
        except InvalidPage as exc:

            if not page_number.isdigit() or int(page_number) == 0:
                self.page = paginator.page(1)

            elif int(page_number) > paginator.num_pages:
                self.page = paginator.page(paginator.num_pages)

            else:
                msg = self.invalid_page_message.format(
                    page_number=page_number, message=str(exc)
                )
                raise NotFound(msg)

        if paginator.num_pages > 1 and self.template is not None:
            self.display_page_controls = True

        self.request = request
        return list(self.page)

    def get_paginated_response_custom(self, serializer, events_data, category, value_not_found):

        page_delete = False

        parsed_url = urlparse(self.request.build_absolute_uri())
        params = parse_qs(parsed_url.query)

        for key in value_not_found.keys():
            if key in params and value_not_found[key] is not None:
                del params[key]
                if key == "page":
                    page_delete = True

        if page_delete is True or ('page' in params and not params['page'][0].isdigit()):
            del params['page']
        elif 'page' in params:
            if int(params['page'][0]) == 0:
                del params['page']
            else:
                params['page'] = [self.page.number]

        parsed_url = parsed_url._replace(query=urlencode(params, doseq=True))
        new_url = urlunparse(parsed_url)

        events = {
            'links': {
                'next': self.get_next_link(),
                'previous': self.get_previous_link(),
                'current': new_url
            },
            'count': self.page.paginator.count,
            'category': category
        }
        data = serializer(events_data, many=True).data

        return events, data

    def generate(self, events_data, serializer, category, value_not_found, request):
        events = self.paginate_queryset_custom(events_data, request)
        output_events, output_data = self.get_paginated_response_custom(
            serializer, events, category, value_not_found)
        return output_events, output_data


class EventsListView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = EventSerializer
    pagination_class = EventsPagePagination

    def get(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                excluded_params = ["name", "province", "city", "distance",
                                   "category", "starDate", "endDate", "page", "ordering"]
                name = request.GET.get('name', None)
                province = request.GET.get('province', None)
                city = request.GET.get('city', None)
                distance = request.GET.get('distance', None)
                category = request.GET.get('category', None)
                startDate = request.GET.get('startDate', None)
                endDate = request.GET.get('endDate', None)
                page = request.GET.get('page', None)
                ordering = request.GET.get('ordering', 'newest')
                value_not_found = {}

                for key, value in request.GET.items():
                    if key not in excluded_params:
                        value_not_found[key] = value

                queryset = None

                filter_list = {'verificated': "verificated",
                               'event_date__gte': timezone.now()}
                distance_true = False
                category_paginate = None
                order_by = None

                if ordering == "newest":
                    order_by = '-id'
                elif ordering == "location":
                    order_by = 'location_distance'
                elif ordering == "popularity":
                    order_by = '-num_reputation'
                elif ordering == "event_date":
                    order_by = 'event_date'
                else:
                    value_not_found["ordering"] = ordering
                    order_by = '-id'

                if name != None:
                    filter_list['title__icontains'] = name
                else:
                    value_not_found["name"] = name

                if category != None and Category.objects.filter(type=category).exists():
                    filter_list['category__type'] = category
                    category_paginate = category
                else:
                    value_not_found["category"] = category

                if startDate != None and endDate != None:

                    filter_list['event_date__range'] = [
                        startDate, endDate]
                else:
                    value_not_found["startDate"] = startDate
                    value_not_found["endDate"] = endDate

                if province != None and Province.objects.filter(name=province).exists():
                    filter_list['city__county__province__name'] = province

                    if city != None and City.objects.filter(county__province__name=province, name=city).exists():

                        filter_list['city__name'] = city

                        if distance != None and distance.isdigit():
                            origin_city = City.objects.get(
                                county__province__name=province, name=city)

                            del filter_list['city__county__province__name']
                            del filter_list['city__name']

                            distance_true = True

                        else:
                            value_not_found["distance"] = distance

                    else:
                        value_not_found["city"] = city
                        value_not_found["distance"] = distance
                else:
                    value_not_found["province"] = province
                    value_not_found["city"] = city
                    value_not_found["distance"] = distance

                user = request.user

                subquery_num_reputation = Event.objects.filter(pk=OuterRef(
                    'pk')).annotate(num_reputation=Count('participants_event')).values('num_reputation')

                subquery_participant_self = Event.objects.filter(pk=OuterRef('pk'),
                                                                 participants_event__username=user.username)

                subquery_main_image = EventImage.objects.filter(
                    event=OuterRef('pk'), main=True).values('image')
                
                subquery_main_image_thumbnail = EventImage.objects.filter(
                    event=OuterRef('pk'), main=True).values('image_thumbnail')

                time_now = timezone.now()

                if distance_true is False:
                    if order_by == 'location_distance':
                        value_not_found["ordering"] = ordering
                        order_by = '-id'

                    if len(filter_list) > 0:

                        queryset = Event.objects.select_related('user', 'category', 'city').filter(
                            **filter_list).annotate(location_distance=Distance('city__geo_location', user.city.geo_location), num_reputation=Subquery(subquery_num_reputation), gps_googlemap=Concat(Value('https://www.google.com/maps/dir/?api=1&origin='), user.city.geo_location[1], Value(','), user.city.geo_location[0], Value('&destination='),  output_field=CharField()), province=F('city__county__province__name'), user_image=F('user__image_thumbnail'), participant_self=Exists(subquery_participant_self), current=ExpressionWrapper(Q(event_date__gte=time_now), output_field=BooleanField()), image=Subquery(subquery_main_image), image_thumbnail=Subquery(subquery_main_image_thumbnail)).order_by(order_by)
                    else:
                        

                        queryset = Event.objects.select_related('user', 'category', 'city').all().annotate(location_distance=Distance('city__geo_location', user.city.geo_location), num_reputation=Subquery(subquery_num_reputation), gps_googlemap=Concat(Value(
                            'https://www.google.com/maps/dir/?api=1&origin='), user.city.geo_location[1], Value(','), user.city.geo_location[0], Value('&destination='),  output_field=CharField()), province=F('city__county__province__name'), user_image=F('user__image_thumbnail'), participant_self=Exists(subquery_participant_self), current=ExpressionWrapper(Q(event_date__gte=time_now), output_field=BooleanField()), image=Subquery(subquery_main_image)).order_by(order_by)[:300]
                else:

                    queryset = Event.objects.select_related('user', 'category', 'city').filter(**filter_list, city__in=City.objects.filter(geo_location__distance_lte=(
                        origin_city.geo_location, D(km=distance)))).annotate(location_distance=Distance('city__geo_location', origin_city.geo_location), num_reputation=Subquery(subquery_num_reputation), gps_googlemap=Concat(Value('https://www.google.com/maps/dir/?api=1&origin='), origin_city.geo_location[1], Value(','), origin_city.geo_location[0], Value('&destination='),  output_field=CharField()), province=F('city__county__province__name'), user_image=F('user__image_thumbnail'), participant_self=Exists(subquery_participant_self), current=ExpressionWrapper(Q(event_date__gte=time_now), output_field=BooleanField()), image=Subquery(subquery_main_image), image_thumbnail=Subquery(subquery_main_image_thumbnail)).order_by(order_by)

                paginator = EventsPagePagination()


                events, data = paginator.generate(
                    queryset, EventSerializer, category_paginate, value_not_found, request)

                max_pages = math.ceil(events['count']/50)

                if not str(page).isdigit() or max_pages < int(page) or 1 > int(page):
                    value_not_found["page"] = page

                return Response(
                    {'success': 'Pobrano wydarzenia', 'events': events, 'value_not_found': value_not_found,
                        'data': data, "code": "7665"},
                    status=status.HTTP_200_OK
                )

        except Exception as e:
            print(e)
            print(f"Typ błędu: {type(e).__name__}")
            print(f"Kod błędu: {e.args[0]}")
            print("Traceback:")
            import traceback
            traceback.print_tb(e.__traceback__)

            return Response(
                {'detail': 'Coś poszło nie tak z próbą pobrania danych', "code": "1165"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class EventView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = EventViewSerializer

    def delete(self, request, slug, uuid):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:

                if Event.objects.filter(slug=slug, uuid=uuid).exists():
                    event = Event.objects.get(slug=slug, uuid=uuid)
                    user = request.user

                    if event.user == user:
                        event.delete()
                        return Response(
                            {'success': 'Sukces',
                                "code": "1400"},
                            status=status.HTTP_200_OK)
                    else:

                        return Response(
                            {'detail': 'Nie możesz usunąć wydarzenia, które nie zostało utworzone przez Ciebie',
                                "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                else:

                    return Response(
                        {'detail': 'Nie istnieje takie wydarzenie',
                            "code": "1300"},
                        status=status.HTTP_400_BAD_REQUEST
                    )

        except Exception as e:
            print(e)
            print(f"Typ błędu: {type(e).__name__}")
            print(f"Kod błędu: {e.args[0]}")
            print("Traceback:")
            import traceback
            traceback.print_tb(e.__traceback__)

            return Response(
                {'detail': 'Coś poszło nie tak z próbą pobrania danych', "code": "1165"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def get(self, request, slug, uuid):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                if Event.objects.filter(slug=slug, uuid=uuid).exists():

                    user = request.user



                    ticket_filter = {}
                    ticket_annotate = {}

                    if not (user.is_admin or Event.objects.filter(slug=slug, uuid=uuid, user__id=user.id).exists()):
                        ticket_filter['was_allowed'] = True
                    else:
                        ticket_annotate['new_price'] = F('new_price')
                        
                        
                    subquery_num_reputation = Event.objects.filter(pk=OuterRef('pk')).values('pk').annotate(
                        num_reputation=Count('participants_event')
                    ).values('num_reputation')
                    


                    subquery_participant_self = Event.objects.filter(pk=OuterRef('pk'),
                                                                     participants_event__username=user.username)

                    subquery_image = EventImage.objects.filter(event__pk=OuterRef(
                        'pk')).annotate(data=JSONObject(id=F('id'), order=F('order'), image=F('image'))).values('data').order_by('order')

                    subquery_report_type = EventReport.objects.filter(
                        event__pk=OuterRef('pk'), user=user
                    ).values('type')[:1]


                    time_now = timezone.now()



                    subquery_my_tickets = OrderedTicket.objects.filter(ticket__id=OuterRef('id'), refunded=False, order__user__id=user.id).values('ticket__id').annotate(count=Count('ticket__id')).values('count')

                    subquery_my_not_paid_tickets = OrderedTicket.objects.filter(Q(order__is_paid=False)&Q(order__order_expires_at__gte=time_now), ticket__id=OuterRef('id'), order__user__id=user.id).values('ticket__id').annotate(count=Count('ticket__id')).values('count')


                    subquery_reserved_tickets = OrderedTicket.objects.filter((Q(order__is_paid=True)|Q(order__order_expires_at__gte=time_now))&Q(refunded=False), ticket__id=OuterRef('id')).annotate(count=Func(F('id'), function='Count')).values('count')


                    subquery_tickets = Ticket.objects.filter(event__pk=OuterRef('pk'), **ticket_filter).annotate(data=JSONObject(id=F('id'), ticket_type=F('ticket_type'),ticket_details=F('ticket_details'), verificated=F('verificated'), was_allowed=F('was_allowed'), default_price=F('default_price'), price=F('price'), quantity=F('quantity'), reserved_tickets=Coalesce(Subquery(subquery_reserved_tickets), Value(0)), my_tickets=Coalesce(Subquery(subquery_my_tickets), Value(0)), my_not_paid_tickets=Coalesce(Subquery(subquery_my_not_paid_tickets), Value(0)), **ticket_annotate)).values('data').order_by('-price')



                    event = Event.objects.select_related('user', 'category', 'city', 'series').annotate(
                                                                        location_distance=Distance('city__geo_location', user.city.geo_location), 
                                                                       num_reputation=Subquery(subquery_num_reputation), 
                                                                       gps_googlemap=Concat(Value('https://www.google.com/maps/dir/?api=1&origin='), 
                                                                                            user.city.geo_location[1], 
                                                                                            Value(','), 
                                                                                            user.city.geo_location[0], 
                                                                                            Value('&destination='),  
                                                                                            output_field=CharField()), 
                                                                        province=F('city__county__province__name'), 
                                                                        user_image=F('user__image_thumbnail'), 
                                                                        participant_self=Exists(subquery_participant_self), 
                                                                        my_report=Subquery(subquery_report_type), 
                                                                        current=Q(event_date__gte=time_now), 
                                                                        series_details=F('series__description'),
                                                                        tickets=ArraySubquery(subquery_tickets), 
                                                                        user_client=Value(user, output_field=CharField()), 
                                                                        image=ArraySubquery(subquery_image)).get(slug__iexact=slug, uuid=uuid)




                    if event.verificated == "verificated" or user == event.user or user.is_admin == True:
                        if event.verificated == "rejected":
                            code = "1213"
                            response_text = "Wydarzenie jest przeznaczone do usunięcia."

                        else:
                            code = "7667"
                            response_text = "Pobrano wydarzenie"
                        event = EventViewSerializer(event)
                        return Response(
                            {'success': response_text,
                                'data': event.data, "code": code},
                            status=status.HTTP_200_OK
                        )
                    else:
                        return Response(
                            {'detail': 'Wydarzenie nie przeszło weryfikacji',
                                "code": "1201"},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                else:
                    return Response(
                        {'detail': 'Nie znaleziono takiego wydarzenia', "code": "1300"},
                        status=status.HTTP_400_BAD_REQUEST
                    )

        except Exception as e:
            print(e)
            print(f"Typ błędu: {type(e).__name__}")
            print(f"Kod błędu: {e.args[0]}")
            print("Traceback:")
            import traceback
            traceback.print_tb(e.__traceback__)

            return Response(
                {'detail': 'Coś poszło nie tak z próbą pobrania danych', "code": "1165"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class CommentEventView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = CommentEventSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                data = request.data
                slug = data['slug']
                uuid = data['uuid']
                text = data['text']
                id_reply = data['id_reply']

                user = request.user

                if not text == "":

                    if Event.objects.filter(slug__iexact=slug, uuid=uuid).exists():

                        event = Event.objects.get(
                            slug__iexact=slug, uuid=uuid)

                        if event.verificated == "verificated":

                            if id_reply == "":
                                CommentEvent.objects.create(
                                    event=event, author=request.user, text=text)
                            else:
                                if CommentEvent.objects.filter(id=id_reply).exists():
                                    CommentEvent.objects.create(
                                        event=event, author=request.user, text=text, parent_comment=CommentEvent.objects.get(id=id_reply))
                                else:

                                    comments_filtered, count = actual_comments(
                                        user, slug, uuid)

                                    return Response(
                                        {'detail': 'Nie ma takiego komentarza do odpowiedzi', 'meta': {'count': count},
                                         'data': comments_filtered.data,
                                            "code": "1011"},
                                        status=222
                                    )

                            comments_filtered, count = actual_comments(
                                user, slug, uuid)

                            return Response(
                                {'success': 'Utworzono komentarz', 'meta': {'count': count},
                                    'data': comments_filtered.data, "code": "7667"},
                                status=status.HTTP_200_OK
                            )
                        else:

                            if user.is_admin:
                                return Response(
                                    {'detail': 'Można komentować tylko wydarzenia, które są w danej chwili zweryfikowane.', "is_admin": user.is_admin, "status": {"status": event.verificated, "details": event.verificated_details},
                                        "code": "9011"},
                                    status=223
                                )

                            elif event.user == user:
                                return Response(
                                    {'detail': 'Można komentować tylko wydarzenia, które są w danej chwili zweryfikowane.', "is_admin": "organizator", "status": {"status": event.verificated, "details": event.verificated_details},
                                        "code": "9011"},
                                    status=223
                                )

                            else:
                                return Response(
                                    {'detail': 'Można komentować tylko wydarzenia, które są w danej chwili zweryfikowane.', "is_admin": user.is_admin,
                                        "code": "9011"},
                                    status=223
                                )
                    else:
                        return Response(
                            {'detail': 'Wydarzenie nie istnieje',
                             "code": "9011"},
                            status=224
                        )
                else:
                    return Response(
                        {'detail': 'Nie możesz wstawić pustego komentarza',
                            "code": "9011"},
                        status=status.HTTP_400_BAD_REQUEST
                    )

        except ValidationError:

            return Response(
                {'detail': 'Błędne UUID', "code": "9011"},
                status=status.HTTP_400_BAD_REQUEST
            )

        except Exception as e:
            print(e)
            print(f"Typ błędu: {type(e).__name__}")
            print(f"Kod błędu: {e.args[0]}")
            print("Traceback:")
            import traceback
            traceback.print_tb(e.__traceback__)

            return Response(
                {'detail': 'Coś poszło nie tak z próbą pobrania danych', "code": "1165"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def get(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:

                slug = request.GET.get('slug', None)
                uuid = request.GET.get('uuid', None)

                user = request.user

                comments_filtered, count = actual_comments(user, slug, uuid)

                return Response(
                    {'success': 'Pobrano komentarze', 'meta': {'count': count},
                     'data': comments_filtered.data, "code": "7667"},
                    status=status.HTTP_200_OK
                )

        except Exception as e:
            print(e)
            print(f"Typ błędu: {type(e).__name__}")
            print(f"Kod błędu: {e.args[0]}")
            print("Traceback:")
            import traceback
            traceback.print_tb(e.__traceback__)

            return Response(
                {'detail': 'Coś poszło nie tak z próbą pobrania danych', "code": "1165"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def delete(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                data = request.data
                slug = data['slug']
                uuid = data['uuid']
                id = data['id']

                if Event.objects.filter(slug__iexact=slug, uuid=uuid).exists():

                    user = request.user

                    if CommentEvent.objects.filter(id=id).exists():
                        comment = CommentEvent.objects.get(id=id)

                        if comment.author == user or comment.event.user == user:

                            comment.delete()

                            comments_filtered, count = actual_comments(
                                user, slug, uuid)

                            return Response(
                                {'success': 'Sukces', 'meta': {'count': count},
                                 'data': comments_filtered.data, "code": "1401"},
                                status=status.HTTP_200_OK
                            )
                        else:

                            return Response(
                                {'detail': 'Nie możesz usunąć nieswój komentarz',
                                    "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )
                    else:

                        comments_filtered, count = actual_comments(
                            user, slug, uuid)

                        return Response(
                            {'detail': 'Nie ma takiego komentarza', 'meta': {'count': count},
                                'data': comments_filtered.data,
                                "code": "1011"},
                            status=222
                        )

                else:
                    return Response(
                        {'detail': 'Wydarzenie nie istnieje',
                         "code": "9011"},
                        status=224
                    )

        except Exception as e:
            print(e)
            print(f"Typ błędu: {type(e).__name__}")
            print(f"Kod błędu: {e.args[0]}")
            print("Traceback:")
            import traceback
            traceback.print_tb(e.__traceback__)

            return Response(
                {'detail': 'Coś poszło nie tak z próbą pobrania danych', "code": "1165"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class CommentEventReactionView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = CommentEventReactionSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                data = request.data
                id_comment = data['id_comment']
                type = data['type']
                slug = data['slug']
                uuid = data['uuid']

                if Event.objects.filter(slug__iexact=slug, uuid=uuid).exists():
                    user = request.user

                    if str(id_comment).isdigit() and CommentEvent.objects.filter(id=id_comment).exists():
                        comment_event = CommentEvent.objects.get(id=id_comment)

                        if CommentEventReaction.objects.filter(comment=comment_event, user=user).exists():
                            comment_event_reaction = CommentEventReaction.objects.get(
                                comment=comment_event, user=user)

                            if (type == "Like" and comment_event_reaction.type == "Dislike") or (type == "Dislike" and comment_event_reaction.type == "Like"):

                                CommentEventReaction.edit_reaction(
                                    comment_event, type, comment_event_reaction)

                                return Response(
                                    {'success': 'Zmieniono reakcję do komentarza',
                                     "code": "7667"},
                                    status=status.HTTP_200_OK
                                )

                            elif type == "Delete":
                                CommentEventReaction.delete_reaction(
                                    comment_event, comment_event_reaction)

                                return Response(
                                    {'success': 'Usunięto reakcję do komentarza',
                                        "code": "7667"},
                                    status=status.HTTP_200_OK
                                )

                            else:
                                return Response(
                                    {'detail': 'Już reakcja została dodana.',
                                        "code": "9011"},
                                    status=status.HTTP_400_BAD_REQUEST
                                )
                        else:
                            if type == "Like" or type == "Dislike":
                                CommentEventReaction.create_reaction(
                                    comment_event, user, type)

                                return Response(
                                    {'success': 'Dodano reakcję do komentarza',
                                     "code": "7667"},
                                    status=status.HTTP_200_OK
                                )

                            elif type == "Delete":
                                return Response(
                                    {'detail': 'Nie można usunąć opinii przed jej wyrażeniem',
                                        "code": "9011"},
                                    status=status.HTTP_400_BAD_REQUEST
                                )

                            else:
                                return Response(
                                    {'detail': 'Błędny typ opinii', "code": "9011"},
                                    status=status.HTTP_400_BAD_REQUEST
                                )

                    else:

                        comments_filtered, count = actual_comments(
                            user, slug, uuid)

                        return Response(
                            {'detail': 'Nie ma takiego komentarza', 'meta': {'count': count},
                                'data': comments_filtered.data,
                                "code": "1011"},
                            status=222
                        )

                else:
                    return Response(
                        {'detail': 'Wydarzenie nie istnieje',
                         "code": "9011"},
                        status=224
                    )

        except Exception as e:
            print(e)
            print(f"Typ błędu: {type(e).__name__}")
            print(f"Kod błędu: {e.args[0]}")
            print("Traceback:")
            import traceback
            traceback.print_tb(e.__traceback__)

            return Response(
                {'detail': 'Coś poszło nie tak z próbą pobrania danych', "code": "1165"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class CommentEventReportView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = CommentEventReportSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                data = request.data
                id_comment = data['id_comment']
                type = data['type']
                details = data['details']
                slug = data['slug']
                uuid = data['uuid']

                if len(details) <= 150:

                    if Event.objects.filter(slug__iexact=slug, uuid=uuid).exists():
                        user = request.user
                        if str(id_comment).isdigit() and CommentEvent.objects.filter(id=id_comment).exists():
                            comment_event = CommentEvent.objects.get(
                                id=id_comment)

                            if not comment_event.is_blocked:

                                if not CommentEventReport.objects.filter(comment=comment_event, user=user).exists():
                                    CommentEventReport.objects.create(
                                        comment=comment_event, user=user, type=type, details=details)

                                    return Response(
                                        {'success': 'Sukces', "code": "1010"},
                                        status=status.HTTP_200_OK
                                    )
                                else:

                                    return Response(
                                        {'detail': 'Ten komentarz został już zgłoszony przez użytkownika',
                                            "code": "9011"},
                                        status=status.HTTP_400_BAD_REQUEST
                                    )
                            else:
                                comments_filtered, count = actual_comments(
                                    user, slug, uuid)
                                return Response(
                                    {'detail': 'Ten komentarz jest już zablokowany przez administrację', 'meta': {'count': count},
                                     'data': comments_filtered.data,
                                        "code": "1012"},
                                    status=222
                                )
                        else:

                            comments_filtered, count = actual_comments(
                                user, slug, uuid)

                            return Response(
                                {'detail': 'Nie ma takiego komentarza', 'meta': {'count': count},
                                 'data': comments_filtered.data,
                                    "code": "1011"},
                                status=222
                            )

                    else:
                        return Response(
                            {'detail': 'Wydarzenie nie istnieje',
                             "code": "9011"},
                            status=224
                        )
                else:
                    return Response(
                        {'detail': 'Długoś twoich szczegółów nie może być większa niż 150 znaków',
                            "code": "9011"},
                        status=status.HTTP_400_BAD_REQUEST
                    )

        except Exception as e:
            print(e)
            print(f"Typ błędu: {type(e).__name__}")
            print(f"Kod błędu: {e.args[0]}")
            print("Traceback:")
            import traceback
            traceback.print_tb(e.__traceback__)

            return Response(
                {'detail': 'Coś poszło nie tak z próbą pobrania danych', "code": "1165"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class UserParticipateView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = UserParticipateSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                data = request.data
                id_event = data['id_event']

                user = request.user

                # 5052

                # 5054

                if str(id_event).isdigit() and Event.objects.filter(id=id_event).exists():

                    event = Event.objects.get(id=id_event)

                    if event.user != user:

                        if event.verificated == "verificated":

                            if event.event_date >= timezone.now().date():

                                if not event.participants_event.filter(
                                        username=user.username).exists():

                                    event.participants_event.add(user)
                                    # user.save(generate_thumbnail=False)
                                    # event.save()
                                    return Response(
                                        {'success': 'Sukces',
                                            "code": "1050"},
                                        status=status.HTTP_200_OK
                                    )
                                else:
                                    event.participants_event.remove(user)
                                    # user.save(generate_thumbnail=False)
                                    # event.save()

                                    return Response(
                                        {'success': 'Sukces',
                                            "code": "1051"},
                                        status=status.HTTP_200_OK
                                    )
                            else:
                                return Response(
                                    {'detail': 'To wydarzenie już się odbyło',
                                        "code": "9011"},
                                    status=status.HTTP_400_BAD_REQUEST
                                )
                        else:

                            if user.is_admin:
                                return Response(
                                    {'detail': 'Można brać udział tylko wydarzenia, które są w danej chwili zweryfikowane.', "is_admin": user.is_admin, "status": {"status": event.verificated, "details": event.verificated_details},
                                        "code": "9011"},
                                    status=223
                                )

                            else:
                                return Response(
                                    {'detail': 'Można brać udział tylko wydarzenia, które są w danej chwili zweryfikowane.', "is_admin": user.is_admin,
                                        "code": "9011"},
                                    status=223
                                )

                    else:
                        return Response(
                            {'detail': 'Nie możesz brać udziału w swoim wydarzeniu, ponieważ jesteś jego organizatorem',
                             "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )

                else:
                    return Response(
                        {'detail': 'Wydarzenie nie istnieje',
                         "code": "9011"},
                        status=224
                    )

        except Exception as e:
            print(e)
            print(f"Typ błędu: {type(e).__name__}")
            print(f"Kod błędu: {e.args[0]}")
            print("Traceback:")
            import traceback
            traceback.print_tb(e.__traceback__)

            return Response(
                {'detail': 'Coś poszło nie tak z próbą pobrania danych', "code": "1165"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class EventParticipantsView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = EventParticipantsSerializer

    def get(self, request, slug, uuid):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:

                if Event.objects.filter(slug=slug, uuid=uuid).exists():
                    user = request.user
                    event = Event.objects.get(slug=slug, uuid=uuid)
                    # max_profiles = 15

                    not_admin_annotate = {}
                    if not user.is_admin:
                        not_admin_annotate["blocked_users"] = user

                    friends = user.friends_list.filter(
                        take_part_events=event).order_by('?')[:15]
                    friends_count = user.friends_list.filter(
                        take_part_events=event).count()
                    rest_users = event.participants_event.exclude(
                        Q(id=user.id) | Q(friends__id=user.id)).exclude(blocked_by=user).exclude(**not_admin_annotate).order_by('?')[:15]
                    rest_users_count = event.participants_event.exclude(
                        Q(id=user.id) | Q(friends__id=user.id)).count()

                    friends = EventParticipantsSerializer(friends, many=True)
                    rest_users = EventParticipantsSerializer(
                        rest_users, many=True)

                    return Response(
                        {'success': 'Pobrano uczestników wydarzenia', "participants": {"friends": {"meta": {"count": friends_count}, "data": friends.data}, "rest_users": {"meta": {"count": rest_users_count}, "data": rest_users.data}},
                         "code": "34324"},
                        status=status.HTTP_200_OK
                    )
                else:
                    return Response(
                        {'detail': 'Nie znaleziono takiego wydarzenia', "code": "9011"},
                        status=status.HTTP_400_BAD_REQUEST
                    )

        except Exception as e:
            print(e)
            print(f"Typ błędu: {type(e).__name__}")
            print(f"Kod błędu: {e.args[0]}")
            print("Traceback:")
            import traceback
            traceback.print_tb(e.__traceback__)

            return Response(
                {'detail': 'Coś poszło nie tak z próbą pobrania danych', "code": "1165"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class EventAddView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = EventAddSerializer
    parser_classes = [MultiPartParser, FormParser]

    def check_scheduler(self, temp):
        if isinstance(temp, list):
            for schedule in eval(temp):
                if isinstance(schedule, list):
                    if isinstance(schedule[0], str) or isinstance(schedule[1], str):
                        if schedule[0] == "" or schedule[1] == "":
                            return Response(
                                {'detail': 'W godzinie rozpoczęcia wydarzenia została podana pusta wartość.',
                                    "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )

                        else:
                            return Response(
                                {'detail': 'W godzinie rozpoczęcia wydarzenia została podana litera.',
                                    "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )

                    else:
                        if not (schedule[0] >= 0 and schedule[0] <= 23):
                            return Response(
                                {'detail': 'Godzina rozpoczęcia nie mieści się w zakresie 0-23',
                                    "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )

                        if not (schedule[1] >= 0 and schedule[1] <= 59):
                            return Response(
                                {'detail': 'Minuta rozpoczęcia nie mieści się w zakresie 0-59',
                                    "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )

                    if isinstance(schedule[2], str) or isinstance(schedule[3], str):
                        if schedule[2] != "" or schedule[3] != "":
                            return Response(
                                {'detail': 'W godzinie zakończenia wydarzenia została podana litera.',
                                    "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )
                    else:
                        if not (schedule[2] >= 0 and schedule[2] <= 23):
                            return Response(
                                {'detail': 'Godzina zakończenia nie mieści się w zakresie 0-23',
                                    "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )

                        if not (schedule[3] >= 0 and schedule[3] <= 59):
                            return Response(
                                {'detail': 'Minuta zakończenia nie mieści się w zakresie 0-59',
                                    "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )
                else:
                    return Response(
                        {'detail': 'Nie podajesz harmonogramu w szablonie  [[<int:godzina rozpoczecia>,<int:minuta rozpoczecia>,<int:godzina zakończenia>,<int:minuta zakończenia>,"<str:opis>"],[<opcjonalnie kolejna godzina pod poprzedni wzór>]]',
                            "code": "9011"},
                        status=status.HTTP_400_BAD_REQUEST
                    )
        else:
            return Response(
                {'detail': 'Nie podajesz harmonogramu w szablonie  [[<int:godzina rozpoczecia>,<int:minuta rozpoczecia>,<int:godzina zakończenia>,<int:minuta zakończenia>,"<str:opis>"],[<opcjonalnie kolejna godzina pod poprzedni wzór>]]',
                    "code": "9011"},
                status=status.HTTP_400_BAD_REQUEST
            )

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:

                data = request.data
                title = data['title']
                text = data['text']
                category = data['category']
                series = data['series']
                event_date = data['event_date']
                province = data['province']
                city = data['city']
                schedule = data['schedule']
                image0 = data['image0']
                image1 = data.get('image1', "")
                image2 = data.get('image2', "")
                image3 = data.get('image3', "")
                image4 = data.get('image4', "")
                image5 = data.get('image5', "")
                image6 = data.get('image6', "")
                image7 = data.get('image7', "")
                image_optional_keys = [image1, image2, image3,
                                       image4, image5, image6, image7]
                image_found = [image0, image1, image2, image3,
                               image4, image5, image6, image7]

                all_optional_images_is_images = True
                all_next_images_are_null = False
                user = request.user

                if not Event.objects.filter(title=title).exists():

                    if len(title) > 5:
                        if len(text) > 49:
                            if len(schedule) > 0:
                                self.check_scheduler(schedule)
                                if Category.objects.filter(type=category).exists():
                                    category_obj = Category.objects.get(
                                        type=category)
                                    if Series.objects.filter(author=user, name=series).exists() or series == "":
                                        if series == "":
                                            series_obj = None
                                        else:
                                            series_obj = Series.objects.get(
                                                author=user, name=series)
                                        try:
                                            time_now = timezone.now().date()
                                            event_date_convert = datetime.datetime.strptime(
                                                event_date, "%Y-%m-%d").date()
                                            if time_now <= event_date_convert:
                                                if Province.objects.filter(name=province).exists():
                                                    province_obj = Province.objects.get(
                                                        name=province)
                                                    if City.objects.filter(county__province=province_obj, name=city).exists():
                                                        city_obj = City.objects.get(
                                                            county__province=province_obj, name=city)

                                                        if image0 and image0.content_type in ['image/jpeg', 'image/png', 'image/gif']:
                                                            for image in image_optional_keys:

                                                                if all_next_images_are_null and image != "":
                                                                    return Response(
                                                                        {'detail': 'Nie możesz wstawiać luki pomiędzy zdjęciami',
                                                                         "code": "9011"},
                                                                        status=status.HTTP_400_BAD_REQUEST
                                                                    )

                                                                if image != "" and image != "" and image.content_type not in ['image/jpeg', 'image/png', 'image/gif']:
                                                                    all_optional_images_is_images = False
                                                                elif image == "":
                                                                    image_found.remove(
                                                                        image)
                                                                    all_next_images_are_null = True

                                                            if all_optional_images_is_images:

                                                                if user.is_admin:
                                                                    verificated = "verificated"
                                                                    code = "1211"
                                                                else:
                                                                    verificated = "awaiting"
                                                                    code = "1210"

                                                                new_event = Event.objects.create(
                                                                    user=user, category=category_obj, title=title, text=text, event_date=event_date_convert, city=city_obj, series=series_obj, schedule=schedule, verificated=verificated)
                                                                for index, image_uploaded in enumerate(image_found):

                                                                    if index == 0:
                                                                        main = True
                                                                    else:
                                                                        main = False

                                                                    EventImage.objects.create(
                                                                        event=new_event, image=image_uploaded, order=index, author=user, main=main)
                                                                return Response(
                                                                    {'success': 'Utworzono wydarzenie', 'slug': new_event.slug, 'uuid': new_event.uuid,
                                                                        "code": code},
                                                                    status=status.HTTP_200_OK)
                                                            else:
                                                                return Response(
                                                                    {'detail': 'Jeden z dodatkowych obrazków nie jest plikiem graficznym',
                                                                        "code": "9011"},
                                                                    status=status.HTTP_400_BAD_REQUEST
                                                                )
                                                        else:
                                                            return Response(
                                                                {'detail': 'Główny obrazek nie jest plikiem graficznym',
                                                                    "code": "9011"},
                                                                status=status.HTTP_400_BAD_REQUEST
                                                            )
                                                    else:
                                                        return Response(
                                                            {'detail': 'Nie ma takiego miasta w tym województwie',
                                                                "code": "9011"},
                                                            status=status.HTTP_400_BAD_REQUEST
                                                        )

                                                else:
                                                    return Response(
                                                        {'detail': 'Nie ma takiego województwa',
                                                            "code": "9011"},
                                                        status=status.HTTP_400_BAD_REQUEST
                                                    )
                                            else:
                                                return Response(
                                                    {'detail': 'Nie możesz stworzyć wydarzenia, które odbyło się w przeszłości',
                                                        "code": "9011"},
                                                    status=status.HTTP_400_BAD_REQUEST
                                                )
                                        except Exception as e:
                                            print(e)
                                            print(
                                                f"Typ błędu: {type(e).__name__}")
                                            print(f"Kod błędu: {e.args[0]}")
                                            print("Traceback:")
                                            import traceback
                                            traceback.print_tb(e.__traceback__)
                                            return Response(
                                                {'detail': 'Została podana zła data.',
                                                    "code": "9011"},
                                                status=status.HTTP_400_BAD_REQUEST
                                            )
                                    else:
                                        return Response(
                                            {'detail': 'Nie ma takiej serii utworzonej przez użytkownika.',
                                                "code": "9011"},
                                            status=status.HTTP_400_BAD_REQUEST
                                        )

                                else:
                                    return Response(
                                        {'detail': 'Nie ma takiej kategorii',
                                            "code": "9011"},
                                        status=status.HTTP_400_BAD_REQUEST
                                    )
                            else:
                                return Response(
                                    {'detail': 'Nie został wysłany harmonogram wydarzenia. Musisz podać chociaż godzine rozpoczęcia.',
                                        "code": "9011"},
                                    status=status.HTTP_400_BAD_REQUEST
                                )
                        else:
                            return Response(
                                {'detail': 'Opis musi posiadać minimum 50 znaków',
                                    "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )

                    else:
                        return Response(
                            {'detail': 'Tytuł musi posiadać więcej niż 5 znaków',
                                "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                else:
                    return Response(
                        {'detail': 'Istnieje takie wydarzenie',
                            "code": "1250"},
                        status=status.HTTP_400_BAD_REQUEST
                    )

        except Exception as e:
            print(e)
            print(f"Typ błędu: {type(e).__name__}")
            print(f"Kod błędu: {e.args[0]}")
            print("Traceback:")
            import traceback
            traceback.print_tb(e.__traceback__)

            return Response(
                {'detail': 'Coś poszło nie tak z próbą pobrania danych', "code": "1165"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class EventReportView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = EventReportSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                data = request.data
                id_event = data['id_event']
                type = data['type']
                details = data.get('details', None)

                if str(id_event).isdigit() and Event.objects.filter(id=id_event).exists():
                    user = request.user
                    event = Event.objects.get(id=id_event)

                    if not event.user == user:
                        if event.verificated == "verificated":
                            if not EventReport.objects.filter(event=event, user=user).exists():
                                EventReport.objects.create(
                                    event=event, user=user, type=type, details=details)

                                return Response(
                                    {'success': 'Sukces', "code": "1010"},
                                    status=status.HTTP_200_OK
                                )
                            else:
                                return Response(
                                    {'detail': 'Już wcześniej zgłosiłeś te wydarzenie',
                                        "code": "9011"},
                                    status=status.HTTP_400_BAD_REQUEST
                                )
                        else:

                            if user.is_admin:
                                return Response(
                                    {'detail': 'Można zgłaszać tylko wydarzenia, które są w danej chwili zweryfikowane.', "is_admin": user.is_admin, "status": {"status": event.verificated, "details": event.verificated_details},
                                        "code": "9011"},
                                    status=223
                                )

                            else:
                                return Response(
                                    {'detail': 'Można zgłaszać tylko wydarzenia, które są w danej chwili zweryfikowane.', "is_admin": user.is_admin,
                                        "code": "9011"},
                                    status=223
                                )

                    else:
                        return Response(
                            {'detail': 'Nie możesz zgłosić wydarzenia, które sam utworzyłeś',
                                "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )

                else:
                    return Response(
                        {'detail': 'Wydarzenie nie istnieje',
                         "code": "9011"},
                        status=224
                    )

        except Exception as e:
            print(e)
            print(f"Typ błędu: {type(e).__name__}")
            print(f"Kod błędu: {e.args[0]}")
            print("Traceback:")
            import traceback
            traceback.print_tb(e.__traceback__)

            return Response(
                {'detail': 'Coś poszło nie tak z próbą pobrania danych', "code": "1165"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class EventEditView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = EventEditSerializer
    parser_classes = [MultiPartParser, FormParser]

    def check_scheduler(self, temp):
        if isinstance(temp, list):
            for schedule in eval(temp):
                if isinstance(schedule, list):
                    if isinstance(schedule[0], str) or isinstance(schedule[1], str):
                        if schedule[0] == "" or schedule[1] == "":
                            return Response(
                                {'detail': 'W godzinie rozpoczęcia wydarzenia została podana pusta wartość.',
                                    "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )

                        else:
                            return Response(
                                {'detail': 'W godzinie rozpoczęcia wydarzenia została podana litera.',
                                    "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )

                    else:
                        if not (schedule[0] >= 0 and schedule[0] <= 23):
                            return Response(
                                {'detail': 'Godzina rozpoczęcia nie mieści się w zakresie 0-23',
                                    "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )

                        if not (schedule[1] >= 0 and schedule[1] <= 59):
                            return Response(
                                {'detail': 'Minuta rozpoczęcia nie mieści się w zakresie 0-59',
                                    "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )

                    if isinstance(schedule[2], str) or isinstance(schedule[3], str):
                        if schedule[2] != "" or schedule[3] != "":
                            return Response(
                                {'detail': 'W godzinie zakończenia wydarzenia została podana litera.',
                                    "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )
                    else:
                        if not (schedule[2] >= 0 and schedule[2] <= 23):
                            return Response(
                                {'detail': 'Godzina zakończenia nie mieści się w zakresie 0-23',
                                    "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )

                        if not (schedule[3] >= 0 and schedule[3] <= 59):
                            return Response(
                                {'detail': 'Minuta zakończenia nie mieści się w zakresie 0-59',
                                    "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )
                else:
                    return Response(
                        {'detail': 'Nie podajesz harmonogramu w szablonie  [[<int:godzina rozpoczecia>,<int:minuta rozpoczecia>,<int:godzina zakończenia>,<int:minuta zakończenia>,"<str:opis>"],[<opcjonalnie kolejna godzina pod poprzedni wzór>]]',
                            "code": "9011"},
                        status=status.HTTP_400_BAD_REQUEST
                    )
        else:
            return Response(
                {'detail': 'Nie podajesz harmonogramu w szablonie  [[<int:godzina rozpoczecia>,<int:minuta rozpoczecia>,<int:godzina zakończenia>,<int:minuta zakończenia>,"<str:opis>"],[<opcjonalnie kolejna godzina pod poprzedni wzór>]]',
                    "code": "9011"},
                status=status.HTTP_400_BAD_REQUEST
            )

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:

                data = request.data
                id = data['id']
                title = data['title']
                text = data['text']
                category = data['category']
                series = data.get('series', None)
                event_date = data['event_date']
                province = data['province']
                city = data['city']
                schedule = data['schedule']
                image0 = data['image0']
                image1 = data.get('image1', "")
                image2 = data.get('image2', "")
                image3 = data.get('image3', "")
                image4 = data.get('image4', "")
                image5 = data.get('image5', "")
                image6 = data.get('image6', "")
                image7 = data.get('image7', "")
                image_optional_keys = [image1, image2, image3,
                                       image4, image5, image6, image7]

                already_update_images = {}
                new_images = {}

                all_next_images_are_null = False

                user = request.user

                if str(id).isdigit() and Event.objects.filter(id=id).exists():
                    event = Event.objects.get(id=id)

                    if event.user == user:
                        if len(title) > 5:
                            if len(text) > 49:
                                if len(schedule) > 0:
                                    self.check_scheduler(schedule)

                                    ###
                                    if event.verificated != "rejected":
                                        diffrence_time = int(
                                            (timezone.now() - event.edit_time).total_seconds())

                                        if diffrence_time > 180:
                                            if Category.objects.filter(type=category).exists():
                                                category_obj = Category.objects.get(
                                                    type=category)
                                                if Series.objects.filter(author=user, name=series).exists() or series == "":
                                                    if series == "":
                                                        series_obj = None
                                                    else:
                                                        series_obj = Series.objects.get(
                                                            author=user, name=series)

                                                    try:
                                                        time_now = timezone.now().date()
                                                        event_date_convert = datetime.datetime.strptime(
                                                            event_date, "%Y-%m-%d").date()
                                                        if time_now <= event_date_convert:
                                                            if Province.objects.filter(name=province).exists():
                                                                province_obj = Province.objects.get(
                                                                    name=province)
                                                                if City.objects.filter(county__province=province_obj, name=city).exists():
                                                                    city_obj = City.objects.get(
                                                                        county__province=province_obj, name=city)
                                                                    if isinstance(image0, str):
                                                                        if str(image0).isdigit():
                                                                            if EventImage.objects.filter(id=image0).exists():
                                                                                eventimage0 = EventImage.objects.get(
                                                                                    id=image0)
                                                                                if eventimage0.author == user:
                                                                                    already_update_images[0] = eventimage0

                                                                                else:
                                                                                    return Response(
                                                                                        {'detail': 'Podany obrazek nie należy do użytkownika',
                                                                                         "code": "9011"},
                                                                                        status=status.HTTP_400_BAD_REQUEST
                                                                                    )

                                                                            else:
                                                                                return Response(
                                                                                    {'detail': 'Podany obrazek nie istnieje w bazie',
                                                                                     "code": "9011"},
                                                                                    status=status.HTTP_400_BAD_REQUEST
                                                                                )
                                                                        elif image0 == "":
                                                                            return Response(
                                                                                {'detail': 'Musisz uzupełnić wydarzenie przynajmniej jednym obrazkiem',
                                                                                 "code": "9011"},
                                                                                status=status.HTTP_400_BAD_REQUEST
                                                                            )
                                                                        else:
                                                                            return Response(
                                                                                {'detail': 'W miejscu ID podałeś literę',
                                                                                 "code": "9011"},
                                                                                status=status.HTTP_400_BAD_REQUEST
                                                                            )

                                                                    else:
                                                                        if image0 and image0.content_type in ['image/jpeg', 'image/png', 'image/gif']:
                                                                            new_images[0] = image0

                                                                        else:
                                                                            return Response(
                                                                                {'detail': 'Główny obrazek nie jest plikiem graficznym',
                                                                                 "code": "9011"},
                                                                                status=status.HTTP_400_BAD_REQUEST
                                                                            )

                                                                    for index, image in enumerate(image_optional_keys):
                                                                        if all_next_images_are_null and image != "":
                                                                            return Response(
                                                                                {'detail': 'Nie możesz wstawiać luki pomiędzy zdjęciami',
                                                                                 "code": "9011"},
                                                                                status=status.HTTP_400_BAD_REQUEST
                                                                            )

                                                                        if isinstance(image, str):

                                                                            if str(image).isdigit():
                                                                                if EventImage.objects.filter(id=image).exists():
                                                                                    temp_image = EventImage.objects.get(
                                                                                        id=image)
                                                                                    if temp_image.author == user:
                                                                                        already_update_images[index +
                                                                                                              1] = temp_image
                                                                                    else:
                                                                                        return Response(
                                                                                            {'detail': 'Podany obrazek nie należy do użytkownika',
                                                                                             "code": "9011"},
                                                                                            status=status.HTTP_400_BAD_REQUEST
                                                                                        )
                                                                                else:
                                                                                    return Response(
                                                                                        {'detail': 'Jeden z opcjonalnych podanych obrazków nie istnieje w bazie',
                                                                                         "code": "9011"},
                                                                                        status=status.HTTP_400_BAD_REQUEST
                                                                                    )

                                                                            elif image == "":
                                                                                all_next_images_are_null = True
                                                                            else:
                                                                                return Response(
                                                                                    {'detail': 'W miejscu ID podałeś literę',
                                                                                     "code": "9011"},
                                                                                    status=status.HTTP_400_BAD_REQUEST
                                                                                )

                                                                        else:
                                                                            if image and image.content_type in ['image/jpeg', 'image/png', 'image/gif']:
                                                                                new_images[index +
                                                                                           1] = image
                                                                            else:
                                                                                return Response(
                                                                                    {'detail': 'Jeden z dodatkowych obrazków nie jest plikiem graficznym',
                                                                                     "code": "9011"},
                                                                                    status=status.HTTP_400_BAD_REQUEST
                                                                                )

                                                                    images_to_delete = EventImage.objects.filter(event=event).exclude(
                                                                        pk__in=[obj.pk for obj in already_update_images.values()])
                                                                    images_to_delete.delete()
                                                                    event.title = title
                                                                    event.text = text
                                                                    event.category = category_obj
                                                                    event.series = series_obj
                                                                    event.event_date = event_date_convert
                                                                    event.city = city_obj
                                                                    event.schedule = schedule
                                                                    if user.is_admin:
                                                                        event.verificated = "verificated"
                                                                        code = "1211"
                                                                    else:
                                                                        event.verificated = "awaiting"
                                                                        code = "1210"
                                                                    event.save()

                                                                    for index in range(8):

                                                                        if index in already_update_images:
                                                                            change_order = already_update_images[index]
                                                                            if change_order.order != index:
                                                                                change_order.order = index
                                                                                if index == 0:
                                                                                    change_order.main = True
                                                                                else:
                                                                                    change_order.main = False
                                                                                change_order.save(
                                                                                    generate_thumbnail=False)
                                                                        elif index in new_images:
                                                                            if index == 0:
                                                                                main = True
                                                                            else:
                                                                                main = False
                                                                            EventImage.objects.create(
                                                                                event=event, author=user, image=new_images[index], order=index, main=main)

                                                                    return Response(
                                                                        {'success': 'Zmodyfikowano wydarzenie', 'slug': event.slug, 'uuid': event.uuid,
                                                                                    "code": code},
                                                                        status=status.HTTP_200_OK)
                                                                else:
                                                                    return Response(
                                                                        {'detail': 'Nie ma takiego miasta w tym województwie',
                                                                            "code": "9011"},
                                                                        status=status.HTTP_400_BAD_REQUEST
                                                                    )

                                                            else:
                                                                return Response(
                                                                    {'detail': 'Nie ma takiego województwa',
                                                                        "code": "9011"},
                                                                    status=status.HTTP_400_BAD_REQUEST
                                                                )
                                                        else:
                                                            return Response(
                                                                {'detail': 'Nie możesz edytować wydarzenia, które odbyło się w przeszłości',
                                                                    "code": "9011"},
                                                                status=status.HTTP_400_BAD_REQUEST
                                                            )
                                                    except Exception as e:
                                                        print(e)
                                                        print(
                                                            f"Typ błędu: {type(e).__name__}")
                                                        print(
                                                            f"Kod błędu: {e.args[0]}")
                                                        print("Traceback:")
                                                        import traceback
                                                        traceback.print_tb(
                                                            e.__traceback__)
                                                        return Response(
                                                            {'detail': 'ERRROR.',
                                                                "code": "9011"},
                                                            status=status.HTTP_400_BAD_REQUEST
                                                        )
                                                else:
                                                    return Response(
                                                        {'detail': 'Nie ma takiej serii utworzonej przez użytkownika.',
                                                            "code": "9011"},
                                                        status=status.HTTP_400_BAD_REQUEST
                                                    )

                                            else:
                                                return Response(
                                                    {'detail': 'Nie ma takiej kategorii',
                                                        "code": "9011"},
                                                    status=status.HTTP_400_BAD_REQUEST
                                                )
                                        else:

                                            minutes = diffrence_time // 60
                                            seconds = diffrence_time % 60

                                            if minutes == 0:
                                                response = f'Minęło dopiero {seconds} sekund.'

                                            elif minutes == 1:
                                                response = f'Minęła dopiero {minutes} minuta i {seconds} sekund.'

                                            else:
                                                response = f'Minęły dopiero {minutes} minuty i {seconds} sekund.'

                                            return Response(
                                                {'detail': response,
                                                    "code": "1513"},
                                                status=status.HTTP_400_BAD_REQUEST
                                            )
                                    else:
                                        return Response(
                                            {'success': 'Wydarzenie jest przeznaczone do usunięcia.', 'slug': event.slug, 'uuid': event.uuid,
                                                "code": "1212"},
                                            status=223
                                        )
                                else:
                                    return Response(
                                        {'detail': 'Nie został wysłany harmonogram wydarzenia. Musisz podać chociaż godzine rozpoczęcia.',
                                            "code": "9011"},
                                        status=status.HTTP_400_BAD_REQUEST
                                    )
                            else:
                                return Response(
                                    {'detail': 'Opis musi posiadać minimum 50 znaków',
                                        "code": "9011"},
                                    status=status.HTTP_400_BAD_REQUEST
                                )

                        else:
                            return Response(
                                {'detail': 'Tytuł musi posiadać więcej niż 5 znaków',
                                    "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )
                    else:
                        return Response(
                            {'detail': 'Nie jesteś organizatorem wydarzenia.',
                                "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                else:
                    return Response(
                        {'detail': 'Nie ma takiego wydarzenia z takim ID.',
                            "code": "1300"},
                        status=224
                    )

        except Exception as e:
            print(e)
            print(f"Typ błędu: {type(e).__name__}")
            print(f"Kod błędu: {e.args[0]}")
            print("Traceback:")
            import traceback
            traceback.print_tb(e.__traceback__)

            return Response(
                {'detail': 'Coś poszło nie tak z próbą pobrania danych', "code": "1165"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
