from rest_framework import permissions, status, pagination
from rest_framework.views import APIView
from rest_framework.response import Response
from ..serializers import EventHomescreenSerializer, CategorySerializer, ProvinceSerializer, CitySerializer
from ..models import Event, EventImage, Category, Province, City
from .functions import token_verify
import datetime
from datetime import timedelta
from django.db.models import Count, OuterRef, Subquery, F, Value, CharField
from django.db.models.functions import JSONObject, Concat
from django.contrib.gis.db.models.functions import Distance
from django.contrib.postgres.expressions import ArraySubquery


class LimitSetPagination(pagination.LimitOffsetPagination):

    limit_query_param = 'limit'
    offset_query_param = 'offset'

    def get_paginated_response_custom(self, serializer, random, location, popular, MAX_PAGE):
        events = {
            'links': {
                'next': self.get_next_link(),
                'previous': self.get_previous_link()
            },
            'count': MAX_PAGE
        }
        data = {
            'random': serializer(random, many=True).data,
            'location': serializer(location, many=True).data,
            'popular': serializer(popular, many=True).data,
        }

        return events, data

    def generate(self, random_data, location_data, population_data, serializer, page_size, MAX_PAGE, request):

        self.max_limit = page_size

        random = self.paginate_queryset(random_data, request)
        location = self.paginate_queryset(location_data, request)
        population = self.paginate_queryset(population_data, request)

        events, data = self.get_paginated_response_custom(
            serializer, random, location, population, MAX_PAGE)
        return events, data


class EventsHomescreenView(APIView):

    serializer_class = EventHomescreenSerializer
    pagination_class = LimitSetPagination
    throttle_classes = []

    def set_cookie(self, location_pks, random_pks, popular_pks):
        response = Response(status=status.HTTP_200_OK)

        response.set_cookie(
            key="pkl_homescreen",
            value=location_pks,
            expires=datetime.datetime.strftime(datetime.datetime.utcnow(
            ) + timedelta(minutes=4), "%a, %d-%b-%Y %H:%M:%S GMT",),
            secure=True,
            httponly=False,
            samesite="None"
        )

        response.set_cookie(
            key="pkr_homescreen",
            value=random_pks,
            expires=datetime.datetime.strftime(datetime.datetime.utcnow(
            ) + timedelta(minutes=4), "%a, %d-%b-%Y %H:%M:%S GMT",),
            secure=True,
            httponly=False,
            samesite="None"
        )

        response.set_cookie(
            key="pkp_homescreen",
            value=popular_pks,
            expires=datetime.datetime.strftime(datetime.datetime.utcnow(
            ) + timedelta(minutes=4), "%a, %d-%b-%Y %H:%M:%S GMT",),
            secure=True,
            httponly=False,
            samesite="None"
        )

        return response

    def get_list_sorted_obj(self, location_pks, random_pks, popular_pks, user):



        subquery_num_reputation = Event.objects.filter(pk=OuterRef('pk')).annotate(num_reputation=Count('participants_event')).values('num_reputation')



        subquery_series_events = Event.objects.filter(series=OuterRef(
            'series')).annotate(data=JSONObject(id=F('id'),title=F('title'), event_date=F('event_date'), slug=F('slug'), uuid=F('uuid'), verificated=F('verificated'), num_reputation=Subquery(Event.objects.filter(pk=OuterRef('pk')).values('pk').annotate(
                num_reputation=Count('participants_event')
            ).values('num_reputation')), image=Subquery(EventImage.objects.filter(
                event=OuterRef('pk'), main=True).values('image_thumbnail')), city=F('city__name'), province=F('city__county__province__name'), category=F('category__type'))).values('data').order_by('event_date')

        


        location_list = list(Event.objects.select_related('user', 'category', 'city', 'series').annotate(province=F('city__county__province__name'), image_thumbnail=Subquery(EventImage.objects.filter(
            event=OuterRef('pk'), main=True).values('image_thumbnail')), image=Subquery(EventImage.objects.filter(
            event=OuterRef('pk'), main=True).values('image')), location_distance=Distance('city__geo_location', user.city.geo_location), num_reputation=Subquery(subquery_num_reputation), gps_googlemap=Concat(Value('https://www.google.com/maps/dir/?api=1&origin='), user.city.geo_location[1], Value(','), user.city.geo_location[0], Value('&destination='),  output_field=CharField()), user_image=F('user__image_thumbnail'), series_events=ArraySubquery(subquery_series_events), series_details=F('series__description')   ).filter(
            pk__in=location_pks))

        random_list = list(Event.objects.select_related('user', 'category', 'city', 'series').annotate(province=F('city__county__province__name'), image_thumbnail=Subquery(EventImage.objects.filter(
            event=OuterRef('pk'), main=True).values('image_thumbnail')), image=Subquery(EventImage.objects.filter(
            event=OuterRef('pk'), main=True).values('image')), location_distance=Distance('city__geo_location', user.city.geo_location), num_reputation=Subquery(subquery_num_reputation), gps_googlemap=Concat(Value('https://www.google.com/maps/dir/?api=1&origin='), user.city.geo_location[1], Value(','), user.city.geo_location[0], Value('&destination='),  output_field=CharField()), user_image=F('user__image_thumbnail'), series_events=ArraySubquery(subquery_series_events), series_details=F('series__description')).filter(
            pk__in=random_pks))

        popular_list = list(Event.objects.select_related('user', 'category', 'city', 'series').annotate(province=F('city__county__province__name'), image_thumbnail=Subquery(EventImage.objects.filter(
            event=OuterRef('pk'), main=True).values('image_thumbnail')), image=Subquery(EventImage.objects.filter(
            event=OuterRef('pk'), main=True).values('image')), location_distance=Distance('city__geo_location', user.city.geo_location), num_reputation=Subquery(subquery_num_reputation), gps_googlemap=Concat(Value('https://www.google.com/maps/dir/?api=1&origin='), user.city.geo_location[1], Value(','), user.city.geo_location[0], Value('&destination='),  output_field=CharField()), user_image=F('user__image_thumbnail'), series_events=ArraySubquery(subquery_series_events), series_details=F('series__description')).filter(
            pk__in=popular_pks))




        location_list.sort(
            key=lambda obj: location_pks.index(obj.pk))

        random_list.sort(
            key=lambda obj: random_pks.index(obj.pk))

        popular_list.sort(
            key=lambda obj: popular_pks.index(obj.pk))

        return location_list, random_list, popular_list

    def get(self, request):
        MAX_PAGE = 144
        try:

            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                request_data = request.GET
                if "limit" in request_data:
                    limit = int(request_data.get('limit'))

                    paginator = LimitSetPagination()
                    user = request.user

                    if request.COOKIES.get("pkl_homescreen") is None or request.COOKIES.get("pkr_homescreen") is None or request.COOKIES.get("pkp_homescreen") is None:

                        

                        location_pks = list(Event.objects.location_objects(
                            request, int(MAX_PAGE/3)))

                        random_pks = list(
                            Event.objects.random_objects(int(MAX_PAGE/3)))

                        popular_pks = list(
                            Event.objects.popular_objects(int(MAX_PAGE/3)))
                        # tutej

                        response = self.set_cookie(
                            location_pks, random_pks, popular_pks)

                    else:
                        response = Response(status=status.HTTP_200_OK)

                        pkl_homescreen_cookie = request.COOKIES.get("pkl_homescreen").strip('][').split(', ')
                        pkr_homescreen_cookie = request.COOKIES.get("pkr_homescreen").strip('][').split(', ')
                        pkp_homescreen_cookie = request.COOKIES.get("pkp_homescreen").strip('][').split(', ')


                        if pkl_homescreen_cookie != ['']:
                            location_pks = list(map(int, pkl_homescreen_cookie))
                        else:
                            location_pks = []


                        if pkr_homescreen_cookie != ['']:
                            random_pks = list(map(int, pkr_homescreen_cookie))
                        else:
                            random_pks = [] 



                        if pkp_homescreen_cookie != ['']:
                            popular_pks = list(map(int, pkp_homescreen_cookie))
                        else:
                            popular_pks = []

                        
                    location_list, random_list, popular_list = self.get_list_sorted_obj(
                        location_pks, random_pks, popular_pks, user)

                    events, data = paginator.generate(
                        random_list, location_list, popular_list, EventHomescreenSerializer, limit, MAX_PAGE, request)



                    response.data = {
                        'events': events, 'data': data, 'success': 'Pobrano dane', 'code': '9200'}

                    return response
                else:
                    return Response(
                        {'detail': 'Brak parametru "limit"', "code": "9280"},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR
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


class CategoryActiveView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = CategorySerializer

    def get(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                categorys = Category.objects.all()
                categorys = CategorySerializer(categorys, many=True)
                return Response(
                    {'success': "Pobrano dane",
                        'categorys': categorys.data, 'code': "9200"},
                    status=status.HTTP_200_OK
                )

        except Exception as e:
            print(e)
            return Response(
                {'detail': 'Coś poszło nie tak z próbą pobrania danych', "code": "545"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class ProvinceView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = ProvinceSerializer
    throttle_classes = []

    def get(self, request):
        try:


            provinces = Province.objects.all().order_by('name')
            provinces = ProvinceSerializer(provinces, many=True)
            return Response(
                {'success': "Pobrano dane",
                    'provinces': provinces.data, 'code': "9200"},
                status=status.HTTP_200_OK
            )

        except Exception as e:
            print(e)
            return Response(
                {'detail': 'Coś poszło nie tak z próbą pobrania danych', "code": "1145"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class CityView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = CitySerializer
    throttle_classes = []

    def post(self, request):
        try:

            data = request.data
            province_id = data['province_id']

            subquery_province = Province.objects.filter(county__city__id=OuterRef(
                'id')).annotate(data=JSONObject(id=F('id'), name=F('name'))).values('data')

            cities = City.objects.select_related(
                'county').filter(county__province__id=province_id).annotate(province=ArraySubquery(subquery_province)).order_by('name')

            cities = CitySerializer(cities, many=True)
            return Response(
                {'success': "Pobrano dane",
                    'cities': cities.data, 'code': "9200"},
                status=status.HTTP_200_OK
            )

        except Exception as e:
            print(e)
            return Response(
                {'detail': 'Coś poszło nie tak z próbą pobrania danych', "code": "1165"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

