from rest_framework.views import APIView
from rest_framework import permissions, status
from rest_framework.response import Response
from ..serializers import EventsRandomSerializer, EventsRandomReactionSerializer
from ..models import Event, EventImage, City
from .functions import token_verify
from django.db.models import Value, CharField, OuterRef, Count, Subquery, F, Q
from django.db.models.functions import JSONObject, Concat
from django.contrib.postgres.expressions import ArraySubquery
from django.contrib.gis.db.models.functions import Distance
from django.contrib.gis.measure import D
from django.utils import timezone


class EventsRandomView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = EventsRandomSerializer

    def get(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                distance = request.GET.get('distance', None)

                if distance != None:
                    if distance.isdigit():
                        user = request.user

                        subquery_num_reputation = Event.objects.filter(pk=OuterRef(
                            'pk')).annotate(num_reputation=Count('participants_event')).values('num_reputation')

                        subquery_image = EventImage.objects.filter(event__pk=OuterRef(
                            'pk')).annotate(data=JSONObject(id=F('id'), order=F('order'), image=F('image'))).values('data').order_by('order')

                        filter_list = {}

                        if not user.is_admin:
                            filter_list["verificated"] = "verificated"

                        subquery_series_events = Event.objects.filter(**filter_list, series=OuterRef(
                            'series')).annotate(data=JSONObject(title=F('title'), event_date=F('event_date'), slug=F('slug'), uuid=F('uuid'), verificated=F('verificated'), num_reputation=Subquery(Event.objects.filter(pk=OuterRef('pk')).values('pk').annotate(
                                num_reputation=Count('participants_event')
                            ).values('num_reputation')), image=Subquery(EventImage.objects.filter(
                                event=OuterRef('pk'), main=True).values('image_thumbnail')), city=F('city__name'), province=F('city__county__province__name'), category=F('category__type'))).values('data').order_by('event_date')

                        events = Event.objects.select_related(
                            'user', 'category', 'city', 'series').filter(~Q(user=user), ~Q(participants_event=user), ~Q(visitors_event=user), verificated="verificated", event_date__gte=timezone.now(), city__in=City.objects.filter(geo_location__distance_lte=(
                                user.city.geo_location, D(km=distance)))).annotate(location_distance=Distance('city__geo_location', user.city.geo_location), num_reputation=Subquery(subquery_num_reputation), gps_googlemap=Concat(Value('https://www.google.com/maps/dir/?api=1&origin='), user.city.geo_location[1], Value(','), user.city.geo_location[0], Value('&destination='),  output_field=CharField()), province=F('city__county__province__name'), user_image=F('user__image_thumbnail'), image=ArraySubquery(subquery_image), series_events=ArraySubquery(subquery_series_events), series_details=F('series__description')).order_by('?')[:10]

                        if len(events) > 0:

                            events = EventsRandomSerializer(events, many=True)

                            return Response(
                                {'success': 'Pobrano wydarzenia', 'data': events.data,
                                 "code": "7667"},
                                status=status.HTTP_200_OK
                            )
                        else:
                            return Response(
                                {'success': 'Brak dostępnych wydarzeń', 'data': "empty",
                                 "code": "660"},
                                status=status.HTTP_200_OK
                            )

                    else:
                        return Response(
                            {'detail': 'Dystans nie jest liczbą.',
                                "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                else:
                    return Response(
                        {'detail': 'Nie podano dystansu.',
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
                {'detail': 'Coś poszło nie tak z próbą pobrania danych',
                    "code": "1165"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class EventsRandomReactionView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = EventsRandomReactionSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                data = request.data
                id_event = data['id_event']
                type = data['type']

                if str(id_event).isdigit() and Event.objects.filter(id=id_event).exists():
                    if type == "Like" or type == "Dislike":
                        event = Event.objects.get(id=id_event)
                        if event.verificated == "verificated":
                            user = request.user

                            if not event.visitors_event.filter(username=user.username).exists():

                                event.visitors_event.add(user)

                                if type == "Like":
                                    event.participants_event.add(user)

                                return Response(
                                    {'success': 'Zagłosowano poprawnie',
                                        "code": "7667"},
                                    status=status.HTTP_200_OK
                                )

                            else:
                                return Response(
                                    {'detail': 'Już wylosowałeś te wydarzenie.',
                                        "code": "9011"},
                                    status=status.HTTP_400_BAD_REQUEST
                                )
                        else:
                            return Response(
                                {'detail': 'Wydarzenie nie jest aktywne.',
                                 "code": "1406"},
                                status=223
                            )

                    else:
                        return Response(
                            {'detail': 'Możesz przesłać typ reakcji "Like" albo "Dislike".',
                                "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )

                else:
                    return Response(
                        {'detail': 'Wydarzenie nie istnieje', "code": "1405"},
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
