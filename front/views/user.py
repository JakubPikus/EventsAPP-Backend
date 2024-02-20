from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import permissions, status, pagination
from rest_framework.exceptions import NotFound
from ..serializers import UserFriendsSerializer, UserEventsSerializer
from ..models import MyUser, Friendship_Request, Event, EventImage, Category
from django.db.models import Count, OuterRef, Subquery, F, Value, CharField, BooleanField, Q, When, Exists, Case, JSONField, ExpressionWrapper
from django.db.models.functions import JSONObject, Concat
from .functions import token_verify
from django.contrib.postgres.expressions import ArraySubquery
from django.core.paginator import InvalidPage
from urllib.parse import urlencode, urlparse, urlunparse, parse_qs
from django.utils import timezone
import math
from django.contrib.gis.db.models.functions import Distance

class UserView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = UserFriendsSerializer

    def get(self, request, username):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                if MyUser.objects.filter(username=username).exists():

                    user_request = request.user
                    user_target = MyUser.objects.get(username=username)

                    if not user_target.blocked_users.filter(id=user_request.id).exists() or user_request.is_admin:

                        user_annotate = {}
                        if user_request.username == username:
                            user_annotate["friends_count"] = Count('friends')
                            user_annotate["friends_together_count"] = Value(
                                None, output_field=BooleanField())
                            user_annotate["friendslist_together"] = Value(
                                None, output_field=BooleanField())
                            user_annotate["friendslist_strange"] = ArraySubquery(MyUser.objects.filter(friends__id=OuterRef(
                                'id')).annotate(data=JSONObject(id=F('id'), username=F('username'), image_thumbnail=F('image_thumbnail'))).values('data').order_by('?'))

                        else:
                            user_annotate["friends_count"] = Count(
                                'friends_list')
                            user_annotate["friends_together_count"] = Count(
                                'friends_list', filter=Q(friends_list__in=user_request.friends.all()))

                            user_annotate["friendslist_together"] = ArraySubquery(MyUser.objects.filter(pk=OuterRef('pk')).filter(
                                friends__in=user_request.friends.all()).annotate(data=JSONObject(id=F('id'), username=F('friends__username'), image_thumbnail=F('friends__image_thumbnail'))).values('data'))

                            not_admin_annotate = {}

                            if not user_request.is_admin:
                                not_admin_annotate["blocked_users"] = user_request

                            user_annotate["friendslist_strange"] = ArraySubquery(MyUser.objects.filter(
                                friends_list__pk=OuterRef('pk')).exclude(
                                friends_list=user_request).exclude(blocked_by=user_request).exclude(**not_admin_annotate).annotate(
                                data=JSONObject(id=F('id'), username=F('username'), image_thumbnail=F('image_thumbnail'))).values('data').order_by('?'))

                        ##################

                        # SUBQUERY DO STATUSU "IS_FRIEND"

                        subquery_is_friend = MyUser.objects.filter(
                            friends__pk=OuterRef('pk'), username=user_request.username)

                        subquery_get_request = Friendship_Request.objects.filter(
                            from_user__pk=OuterRef('pk'), to_user=user_request)

                        subquery_send_request = Friendship_Request.objects.filter(
                            to_user__pk=OuterRef('pk'), from_user=user_request)

                        subquery_is_blocked = MyUser.objects.filter(
                            blocked_users__pk=OuterRef('pk'), username=user_request.username)

                        subquery_get_blocked = MyUser.objects.filter(
                            pk=OuterRef('pk'), blocked_users=user_request)

                        ##################

                        # SUBQUERY DO ODZNAK

                        user_main_badge_exclude = {}
                        if user_target.main_badge != None:
                            user_main_badge_exclude["id"] = user_target.main_badge.id

                        subquery_badges = user_target.activated_badges.filter(verificated="verificated").exclude(**user_main_badge_exclude).annotate(
                            data=JSONObject(name=F('name'), image=F('image'))).values('data')

                        #############

                        user = MyUser.objects.select_related(
                            'city', 'main_badge').annotate(is_friend=Case(
                                When(Exists(subquery_is_blocked),
                                     then=Value("Blocked")),
                                When(Exists(subquery_get_blocked),
                                     then=Value("a) Get_block")),
                                When(Exists(subquery_is_friend),
                                     then=Value('a) True')),
                                When(Exists(subquery_send_request), then=Value(
                                    "b) Send_request")),
                                When(Exists(subquery_get_request), then=Value(
                                    "c) Get_request")),

                                default=Value('d) False'), output_field=CharField()), main_badge_data=Case(
                                When(main_badge__isnull=True, then=Value(None)),
                                default=JSONObject(
                                    name=F('main_badge__name'), image=F('main_badge__image')),
                                output_field=JSONField()
                            ), badges=ArraySubquery(subquery_badges), **user_annotate).get(username=username)

                        user = UserFriendsSerializer(
                            user, context={'user': user_target})
                        

                        # print("xdddd")
                        # stripe.api_key = settings.STRIPE_SECRET_KEY_TEST
                        # stripe.checkout.Session.expire('cs_test_a1ua1PC4ww5sUlojNL8rSpyPNbnSu71Q86tN9CKrfRQVijsdjRQWlCqmd8')

                        return Response(
                            {'success': 'Pobrano wydarzenie',
                                'data': user.data, "code": "7667"},
                            status=status.HTTP_200_OK
                        )
                    else:
                        return Response(
                            {'detail': 'Jesteś zablokowany przez tego użytkownika',
                             "code": "1302"},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                else:
                    return Response(
                        {'detail': 'Nie ma takiego użytkownika',
                         "code": "1301"},
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


class UserEventsPagePagination(pagination.PageNumberPagination):

    page_size = 30
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

    def get_paginated_response_custom(self, serializer, events_paginated, categories, value_not_found):

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

        meta = {
            'links': {
                'next': self.get_next_link(),
                'previous': self.get_previous_link(),
                'current': new_url
            },
            'count': self.page.paginator.count,
            'categories': categories,

        }
        data = serializer(events_paginated, many=True).data

        return meta, data

    def generate(self, queryset, serializer, categories, value_not_found, request):

        events = self.paginate_queryset_custom(
            queryset, request)
        meta, data = self.get_paginated_response_custom(
            serializer, events, categories, value_not_found)
        return meta, data


class UserEventsView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = UserEventsSerializer
    pagination_class = UserEventsPagePagination

    def get(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:

                excluded_params = ["username", "page",
                                   "type", "events_category", "ordering"]
                username = request.GET.get('username', None)
                page = request.GET.get('page', "1")
                type = request.GET.get('type', None)
                events_category = request.GET.get('events_category', None)
                ordering = request.GET.get('ordering', 'newest')
                value_not_found = {}

                for key, value in request.GET.items():
                    if key not in excluded_params:
                        value_not_found[key] = value

                if MyUser.objects.filter(username=username).exists():

                    order_by = None

                    user = request.user

                    if type == None or type == "created_future" or type == "created_past" or type == "future" or type == "past" or ((type == "awaiting" or type == "need_improvement" or type == "rejected") and user.username == username):

                        filter_list = {}

                        if ordering == "newest":
                            order_by = '-id'
                        elif ordering == "popularity":
                            order_by = '-num_reputation'
                        elif ordering == "event_date":
                            order_by = 'event_date'
                        else:
                            value_not_found["ordering"] = ordering
                            order_by = '-id'

                        if type == "created_future":
                            filter_list['event_date__gte'] = timezone.now()
                            filter_list['user__username'] = username
                            filter_list['verificated'] = "verificated"
                        elif type == "created_past":
                            filter_list['event_date__lt'] = timezone.now()
                            filter_list['user__username'] = username
                            filter_list['verificated'] = "verificated"

                        elif type == "future":
                            filter_list['event_date__gte'] = timezone.now()
                            filter_list['participants_event__username'] = username
                            filter_list['verificated'] = "verificated"
                        elif type == "past":
                            filter_list['event_date__lt'] = timezone.now()
                            filter_list['participants_event__username'] = username
                            filter_list['verificated'] = "verificated"

                        elif type == "awaiting":
                            filter_list['user__username'] = username
                            filter_list['verificated'] = "awaiting"
                        elif type == "need_improvement":
                            filter_list['user__username'] = username
                            filter_list['verificated'] = "need_improvement"
                        elif type == "rejected":
                            filter_list['user__username'] = username
                            filter_list['verificated'] = "rejected"

                        else:
                            filter_list['event_date__gte'] = timezone.now()
                            filter_list['participants_event__username'] = username
                            value_not_found["type"] = type

                        if events_category != None and Category.objects.filter(type=events_category).exists() and not "type" in value_not_found:
                            filter_list['category__type'] = events_category
                        elif events_category != "all":
                            value_not_found["events_category"] = events_category

                        subquery_num_reputation = Event.objects.filter(pk=OuterRef('pk')).values('pk').annotate(
                            num_reputation=Count('participants_event')
                        ).values('num_reputation')

                        subquery_participant_self = Event.objects.filter(pk=OuterRef('pk'),
                                                                         participants_event__username=user.username)
                        subquery_main_image = EventImage.objects.filter(
                            event=OuterRef('pk'), main=True).values('image_thumbnail')

                        time_now = timezone.now()
                        queryset = Event.objects.select_related('user', 'category', 'city').filter(
                            **filter_list).annotate(location_distance=Distance('city__geo_location', user.city.geo_location), num_reputation=Subquery(subquery_num_reputation), gps_googlemap=Concat(Value('https://www.google.com/maps/dir/?api=1&origin='), user.city.geo_location[1], Value(','), user.city.geo_location[0], Value('&destination='),  output_field=CharField()), province=F('city__county__province__name'), user_image=F('user__image_thumbnail'), participant_self=Exists(subquery_participant_self), current=ExpressionWrapper(Q(event_date__gte=time_now), output_field=BooleanField()), image=Subquery(subquery_main_image))

                        paginator = UserEventsPagePagination()



                        category_filter = {key: value for key, value in filter_list.items() if key != 'category__type'}
                        categories = Event.objects.filter(**category_filter).values_list('category__type', flat=True).distinct()


                        queryset = queryset.order_by(order_by)

                        meta, data = paginator.generate(
                            queryset, UserEventsSerializer, categories, value_not_found, request)

                        max_pages = math.ceil(meta['count']/30)

                        if not str(page).isdigit() or max_pages < int(page) or 1 > int(page):
                            value_not_found["page"] = page

                        return Response(
                            {'success': 'Pobrano wydarzenia', 'meta': meta,
                                'value_not_found': value_not_found,  'data': data, "code": "7667"},
                            status=status.HTTP_200_OK
                        )
                    else:
                        return Response(
                            {'detail': 'Nie masz dostępu do tej strony',
                             "code": "1377"},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                else:
                    return Response(
                        {'detail': 'Nie ma takiego użytkownika', 'username': username,
                         "code": "1301"},
                        status=222
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

