from rest_framework.views import APIView
from rest_framework import permissions, status
from rest_framework.response import Response
from ..serializers import SeriesSerializer, EventsViaSeriesSerializer, EventsNoSeriesSerializer, EventsEditSeriesSerializer, SeriesEditSerializer
from .functions import token_verify
from ..models import MyUser, Series, Event, EventImage
from django.utils import timezone
from django.db.models import OuterRef, Count, Exists, F, Q, Subquery
from django.db.models.functions import JSONObject
from django.contrib.postgres.expressions import ArraySubquery


class SeriesView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = SeriesSerializer

    def get(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                user = request.GET.get('user', None)

                if not user is None:
                    if MyUser.objects.filter(username=user).exists():
                        series = Series.objects.select_related(
                            'author').filter(author__username=user)

                        series = SeriesSerializer(series, many=True)
                        return Response(
                            {'success': 'Sukces', 'data': series.data,
                             "code": "7667"},
                            status=status.HTTP_200_OK
                        )
                    else:
                        return Response(
                            {'detail': 'Nie ma takiego użytkownika.',
                             "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                else:
                    return Response(
                        {'detail': 'Zabrakło danych o nazwie użytkownika.',
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

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                data = request.data
                name = data['name']
                description = data['description']

                if not Series.objects.filter(name=name).exists():
                    if len(name) >= 3 and len(name) <= 100:
                        if len(description) >= 3 and len(description) <= 200:
                            Series.objects.create(
                                author=request.user, name=name, description=description)

                            return Response(
                                {'success': "Utworzono serię " + name,
                                    "code": "1422"},
                                status=status.HTTP_200_OK
                            )
                        else:
                            return Response(
                                {'detail': 'Opis musi zawierać chociaż 3 znaki oraz maksymalnie 200 znaków.',
                                    "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )
                    else:
                        return Response(
                            {'detail': 'Nazwa musi zawierać chociaż 3 znaki oraz maksymalnie 100 znaków.',
                                "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )

                else:
                    return Response(
                        {'detail': 'Istnieje seria o takiej nazwie',
                            "code": "1440"},
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

    def delete(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                data = request.data
                name = data['name']
                user = request.user

                if Series.objects.filter(name=name).exists():
                    series = Series.objects.get(author=user, name=name)

                    if series.author == user:

                        events = Event.objects.filter(series=series)
                        events.update(series=None)

                        for event in events:
                            event.series = None
                            event.save()
                        series.delete()

                        return Response(
                            {'success': 'Sukces',
                                "code": "1423"},
                            status=status.HTTP_200_OK
                        )

                    else:
                        return Response(
                            {'detail': 'Nie możesz usunąć serii, która nie należy do Ciebie.',
                                "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )

                else:
                    return Response(
                        {'detail': 'Nie istnieje seria wydarzeń o takiej nazwie.',
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



class EventsViaSeriesView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = EventsViaSeriesSerializer

    def get(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                user = request.user
                time_now = timezone.now()

                # ///////////
                subquery_num_reputation = Event.objects.filter(pk=OuterRef('pk')).values('pk').annotate(
                    num_reputation=Count('participants_event')
                ).values('num_reputation')
                subquery_main_image = EventImage.objects.filter(
                    event=OuterRef('pk'), main=True).values('image_thumbnail')

                subquery_events = Event.objects.filter(
                    series=OuterRef('pk')).annotate(data=JSONObject(id=F('id'), series=F('series__name'), slug=F('slug'), uuid=F('uuid'), title=F('title'),   category=F('category__type'), event_date=F('event_date'), city=F('city__name'), province=F('city__county__province__name'), verificated=F('verificated'), num_reputation=Subquery(subquery_num_reputation), current=Q(event_date__gte=time_now), image=Subquery(subquery_main_image))).values('data').order_by('event_date')

                subquery_series_current = Event.objects.filter(
                    series=OuterRef('pk'), event_date__gte=time_now)

                # ///////////
                events_series = Series.objects.filter(
                    author=user).annotate(data=ArraySubquery(subquery_events), current=Exists(subquery_series_current)).order_by('-id')

                events_series = EventsViaSeriesSerializer(
                    events_series, many=True)

                # ///////////

                events_no_series = Event.objects.select_related(
                    'category', 'city', 'series').filter(user=user, series=None).annotate(province=F('city__county__province__name'), num_reputation=Subquery(subquery_num_reputation), current=Q(event_date__gte=time_now), image=Subquery(subquery_main_image)).order_by('event_date')

                events_no_series = EventsNoSeriesSerializer(
                    events_no_series, many=True)

                return Response(
                    {'success': 'Pobrano wydarzenia', 'events_no_series': events_no_series.data,
                        'events_with_series': events_series.data, "code": "7667"},
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


class EventsEditSeriesView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = EventsEditSeriesSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                data = request.data
                id_event = data['id_event']
                series = data['series']
                user = request.user

                if str(id_event).isdigit() and Event.objects.filter(id=id_event).exists():
                    event = Event.objects.get(id=id_event)
                    if event.user == user:
                        if series != "":
                            if Series.objects.filter(author=user, name=series).exists():
                                series = Series.objects.get(
                                    author=user, name=series)
                                if event.series != series:
                                    event.series = series
                                    event.save()
                                    return Response(
                                        {'success': 'Sukces',
                                            "code": "1420"},
                                        status=status.HTTP_200_OK
                                    )
                                else:
                                    return Response(
                                        {'detail': 'Twoje wydarzenie już jest przypisane do tej serii.',
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
                                {'detail': 'Nie podałeś serii.',
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

    def delete(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                data = request.data
                id_event = data['id_event']
                user = request.user

                if str(id_event).isdigit() and Event.objects.filter(id=id_event).exists():
                    event = Event.objects.get(id=id_event)
                    if event.user == user:
                        if event.series != None:
                            event.series = None
                            event.save()
                            return Response(
                                {'success': 'Sukces',
                                    "code": "1421"},
                                status=status.HTTP_200_OK
                            )
                        else:
                            return Response(
                                {'detail': 'Nie możesz usunąć wydarzenia z serii, w momencie gdy nie jest przypisane do żadnej serii.',
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


class SeriesEditView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = SeriesEditSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                data = request.data
                series = data['series']
                name = data['name']
                description = data['description']
                user = request.user

                if Series.objects.filter(name=series).exists():
                    series_obj = Series.objects.get(name=series)
                    if not Series.objects.filter(name=name).exists() or series == name:
                        if series_obj.author == user:
                            if not (series_obj.name == name and series_obj.description == description):
                                if len(name) >= 3 and len(name) <= 100:
                                    if len(description) >= 3 and len(description) <= 200:
                                        if series_obj.name == name:

                                            series_obj.description = description
                                            series_obj.save()

                                            return Response(
                                                {'success': series + " -> " + description,
                                                    "code": "1424"},
                                                status=status.HTTP_200_OK
                                            )
                                        else:
                                            series_obj.description = description
                                            series_obj.name = name
                                            series_obj.save()

                                            return Response(
                                                {'success': series + " -> " + name,
                                                    "code": "1424"},
                                                status=status.HTTP_200_OK
                                            )

                                    else:
                                        return Response(
                                            {'detail': 'Opis musi zawierać chociaż 3 znaki oraz maksymalnie 200 znaków.',
                                                "code": "9011"},
                                            status=status.HTTP_400_BAD_REQUEST
                                        )
                                else:
                                    return Response(
                                        {'detail': 'Nazwa musi zawierać chociaż 3 znaki oraz maksymalnie 100 znaków.',
                                            "code": "9011"},
                                        status=status.HTTP_400_BAD_REQUEST
                                    )
                            else:
                                return Response(
                                    {'detail': 'Wykryto te same wartości',
                                        "code": "1425"},
                                    status=status.HTTP_400_BAD_REQUEST
                                )
                        else:
                            return Response(
                                {'detail': 'Dane wydarzenie nie zostało utworzone przez użytkownika.',
                                    "code": "1440"},
                                status=status.HTTP_400_BAD_REQUEST
                            )
                    else:
                        return Response(
                            {'detail': 'Istnieje seria o takiej nazwie',
                                "code": "1440"},
                            status=status.HTTP_400_BAD_REQUEST
                        )

                else:
                    return Response(
                        {'detail': 'Nie istnieje seria o takiej nazwie.',
                            "code": "1440"},
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
