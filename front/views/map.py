from rest_framework.views import APIView
from rest_framework import permissions, status
from rest_framework.response import Response
from ..serializers import EventsProvinceMapSerializer, EventsCountyMapSerializer
from ..models import Province, County, Event, EventImage
from .functions import token_verify
from django.db.models import Count, Q, F, OuterRef, Subquery
from django.db.models.functions import JSONObject
from django.contrib.postgres.expressions import ArraySubquery
from django.utils import timezone
from datetime import timedelta


class EventsProvinceMapView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = EventsProvinceMapSerializer

    def get(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:

                time_now = timezone.now()

                province_events = Province.objects.all().annotate(
                    count=Count('county__city__event',  filter=Q(county__city__event__event_date__range=(time_now, time_now + timedelta(days=90)))))

                province_events = EventsProvinceMapSerializer(
                    province_events, many=True)

                return Response(
                    {'success': 'Pobrano wydarzenia', "data": province_events.data,
                     "code": "7667"},
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
                {'detail': 'Coś poszło nie tak z próbą pobrania danych',
                    "code": "1165"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class EventsCountyMapView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = EventsCountyMapSerializer

    def get(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                province_id = request.GET.get('province', None)
                if province_id != None:
                    if province_id.isdigit():
                        if Province.objects.filter(id=province_id).exists():

                            user = request.user

                            time_now = timezone.now()
                            filter_subquery_list = {}
                            filter_list = {}
                            if not user.is_admin:
                                filter_subquery_list["verificated"] = "verificated"
                                filter_list["city__event__verificated"] = "verificated"

                            subquery_county_events = Event.objects.filter(**filter_subquery_list, event_date__range=(time_now, time_now + timedelta(days=90)), city__county__id=OuterRef(
                                'id')).annotate(data=JSONObject(id=F('id'), title=F('title'), event_date=F('event_date'), slug=F('slug'), uuid=F('uuid'), verificated=F('verificated'), num_reputation=Subquery(Event.objects.filter(pk=OuterRef('pk')).values('pk').annotate(
                                    num_reputation=Count('participants_event')
                                ).values('num_reputation')), image=Subquery(EventImage.objects.filter(
                                    event=OuterRef('pk'), main=True).values('image_thumbnail')), city=F('city__name'), user=F('user__username'), province=F('city__county__province__name'), category=F('category__type'))).values('data').order_by('participants_event')

                            county_events = County.objects.filter(province__id=province_id).annotate(
                                count=Count('city__event',  filter=(Q(city__event__event_date__range=(
                                    time_now, time_now + timedelta(days=90))) & Q(**filter_list))),
                                county_events=ArraySubquery(
                                    subquery_county_events)
                            )

                            county_events = EventsCountyMapSerializer(
                                county_events, many=True)

                            return Response(
                                {'success': 'Pobrano wydarzenia', "data": county_events.data,
                                 "code": "7667"},
                                status=status.HTTP_200_OK
                            )
                        else:
                            return Response(
                                {'detail': 'Nie ma takiego województwa o takim ID.',
                                    "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )

                    else:
                        return Response(
                            {'detail': 'ID województwa nie jest liczbą.',
                                "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                else:
                    return Response(
                        {'detail': 'Nie podano ID województwa.',
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
