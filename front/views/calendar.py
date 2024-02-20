from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import permissions, status
from ..serializers import EventsViaCalendarSerializer
from ..models import Event, EventImage
from .functions import token_verify
from django.utils import timezone
from django.db.models import OuterRef, Count, Q, F, Subquery, CharField, Value
import calendar



class EventsViaCalendarView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = EventsViaCalendarSerializer

    def get(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                year = request.GET.get('year', None)
                month = request.GET.get('month', None)

                if not year is None:
                    if str(year).isdigit() and int(year) >= 2013 and int(year) <= 2033:
                        if not month is None:
                            if str(month).isdigit() and int(month) >= 0 and int(month) <= 11:

                                user = request.user
                                time_now = timezone.now()

                                num_days = calendar.monthrange(
                                    int(year), int(month)+1)[1]

                                start_date = year + "-" + \
                                    str(int(month)+1).zfill(2) + "-01"

                                end_date = year + "-" + \
                                    str(int(month)+1).zfill(2) + \
                                    "-" + str(num_days)

                                subquery_num_reputation = Event.objects.filter(pk=OuterRef('pk')).values('pk').annotate(
                                    num_reputation=Count('participants_event')
                                ).values('num_reputation')
                                subquery_main_image = EventImage.objects.filter(
                                    event=OuterRef('pk'), main=True).values('image_thumbnail')

                                queryset = Event.objects.select_related('user', 'category', 'city').filter(
                                    (Q(participants_event__username=user.username) & Q(verificated="verificated")) | Q(user__username=user.username), event_date__range=[start_date, end_date]).annotate(num_reputation=Subquery(subquery_num_reputation), type=F('verificated'), province=F('city__county__province__name'), current=Q(event_date__gte=time_now), image=Subquery(subquery_main_image), user_client=Value(user, output_field=CharField())).order_by('-id').distinct()

                                events_data = EventsViaCalendarSerializer(
                                    queryset, many=True).data

                                data = {}

                                for day in range(num_days):
                                    data[day+1] = []

                                for event in events_data:
                                    length_date = len(event["event_date"])
                                    data[int(event["event_date"]
                                             [length_date-2:])].append(event)

                                return Response(
                                    {'success': 'Pobrano wydarzenia',
                                        "data": data, "code": "7667"},
                                    status=status.HTTP_200_OK
                                )
                            else:
                                return Response(
                                    {'detail': 'Miesiąc nie znajduje się w przedziale 0-11.',
                                        "code": "9011"},
                                    status=status.HTTP_400_BAD_REQUEST
                                )
                        else:
                            return Response(
                                {'detail': 'Nie podano miesiąca.',
                                    "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )
                    else:
                        return Response(
                            {'detail': 'Rok nie znajduje się w przedziale 2013-2033.',
                                "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                else:
                    return Response(
                        {'detail': 'Nie podano roku.',
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
