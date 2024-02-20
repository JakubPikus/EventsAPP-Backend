from rest_framework.views import APIView
from rest_framework import permissions, status, pagination
from rest_framework.response import Response
from ..serializers import AdminLogsSerializer, AdminReportsInputSerializer, AdminReportsEventsSerializer, AdminReportsCommentsSerializer, AdminReportsBadgesSerializer, AdminReportedValidateSerializer, AdminLogExistingSerializer, AdminCommentReportedValidateSerializer, AdminAwaitingsInputSerializer, AdminAwaitingsEventsSerializer, AdminAwaitingsBadgesSerializer, AdminAwaitingsTicketsSerializer, AdminAwaitedValidateSerializer, AdminAwaitedValidateTicketsSerializer, AdminBanUsersIPSerializer, AdminBanUsersSerializer, AdminBanIPsSerializer, AdminBanValidateSerializer, AdminAccountsLogoutSerializer, AdminPaychecksSerializer, AdminPaychecksEventsSerializer, AdminPaychecksTicketsSerializer, AdminPaycheckGatewaySerializer, AdminMissingTicketsPaycheckSerializer, AdminTicketPaycheckValidateSerializer
from ..models import AdminLog, EventReport, CommentEventReport, BadgeReport, Event, CommentEvent, Badge, OrderedTicket, Ticket, IPAddressValidator, MyUser, IPAddress, Paycheck, GatewayPaycheck, AwaitingsTicketsRefund
from .functions import token_verify, admin_verify, send_websocket_notification, is_valid_datetime_format, check_orderedtickets_ids, check_file_is_pdf
import ast
from django.db.models import Value, CharField, OuterRef, Func, F, Q, Exists, Count, Subquery, Sum, ExpressionWrapper, Case, When, DecimalField, Min
from django.db.models.functions import JSONObject, Concat, Coalesce
from django.http import QueryDict
from django.contrib.postgres.expressions import ArraySubquery
from django.contrib.postgres.aggregates import ArrayAgg
from django.db.models.fields.json import KeyTextTransform
from django.utils import timezone


class AdminLogsView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = AdminLogsSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            response_admin_verify = admin_verify(request)
            if response_admin_verify is not None:
                return response_admin_verify

            else:
                data = request.data
                cursor_id = data['cursor_id']
                excluded_ids = data['excluded_ids']

                if excluded_ids != "" and not isinstance(excluded_ids, list):

                    try:
                        literal_eval_excluded_ids = ast.literal_eval(
                            excluded_ids)

                        set_excluded_ids = set(literal_eval_excluded_ids)

                    except:

                        return Response(
                            {'detail': 'Przesyłana wartość w "excluded_ids" musi mieć format list z liczbami określającymi ID logów do pominięcia, lub pozostaw pustą wartość.',
                                "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                else:
                    set_excluded_ids = set(excluded_ids)

                filter_logs = {}
                if cursor_id != 0 and cursor_id != "0":
                    filter_logs['id__lt'] = cursor_id

                admin_logs = AdminLog.objects.select_related('user').filter(
                    ~Q(id__in=set_excluded_ids), **filter_logs).annotate(user_image=F('user__image_thumbnail'), new=Value(False)).order_by("-id")[:25]

                admin_logs = AdminLogsSerializer(admin_logs, many=True)

                return Response(
                    {
                        'success': 'sukces', 'data': admin_logs.data, "code": "7667"},
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


class AdminLogsRefreshView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = AdminLogsSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            response_admin_verify = admin_verify(request)
            if response_admin_verify is not None:
                return response_admin_verify
            else:
                data = request.data
                cursor_id = data['cursor_id']
                excluded_ids = data['excluded_ids']

                if excluded_ids != "" and not isinstance(excluded_ids, list):

                    try:
                        literal_eval_excluded_ids = ast.literal_eval(
                            excluded_ids)

                        set_excluded_ids = set(literal_eval_excluded_ids)

                    except:

                        return Response(
                            {'detail': 'Przesyłana wartość w "excluded_ids" musi mieć format list z liczbami określającymi ID logów do pominięcia, lub pozostaw pustą wartość.',
                                "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                else:
                    set_excluded_ids = set(excluded_ids)

                admin_logs = AdminLog.objects.select_related('user').filter(
                    ~Q(id__in=set_excluded_ids), id__gt=cursor_id).annotate(user_image=F('user__image_thumbnail'), new=Value(True)).order_by("-id")[:25]

                admin_logs = AdminLogsSerializer(admin_logs, many=True)

                return Response(
                    {
                        'success': 'sukces', 'data': admin_logs.data, "code": "7667"},
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


class LimitAdminPagination(pagination.LimitOffsetPagination):

    limit_query_param = 'limit'
    offset_query_param = 'offset'

    def modify_url_mode_with_replace(self, url, new_mode_value):
        if url is None:
            return url

        base_url, _, query_string = url.partition('?')

        query_dict = QueryDict(query_string, mutable=True)

        query_dict['mode'] = new_mode_value

        new_url = f"{base_url}?{query_dict.urlencode()}"

        return new_url

    def get_paginated_response_custom(self, data, mode):

        meta = {
            'links': {
                'next': self.modify_url_mode_with_replace(self.get_next_link(), mode),
                'previous': self.modify_url_mode_with_replace(self.get_previous_link(), mode),
            },
            'count': self.count
        }
        data = data

        return meta, data

    def generate(self, data, page_size, mode, request):

        self.max_limit = page_size
        data = self.paginate_queryset(data, request)
        meta, data = self.get_paginated_response_custom(data, mode)

        return meta, data


class AdminReportsView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = AdminReportsInputSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            response_admin_verify = admin_verify(request)
            if response_admin_verify is not None:
                return response_admin_verify
            else:

                data = request.data

                excluded_ids = data['excluded_ids']
                mode = data['mode']
                name = data['name']
                response = {}
                end_pagination = {}
                excluded_ids_return = {
                    'events': [],
                    'comments': [],
                    'badges': []
                }

                if excluded_ids != "" and not isinstance(excluded_ids, list):

                    try:
                        literal_eval_excluded_ids = ast.literal_eval(
                            excluded_ids)

                        set_excluded_ids = set(literal_eval_excluded_ids)

                    except:

                        return Response(
                            {'detail': 'Przesyłana wartość w "excluded_ids" musi mieć format list z liczbami określającymi ID obiektów do pominięcia, lub pozostaw pustą wartość.',
                                "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                else:
                    set_excluded_ids = set(excluded_ids)

                if mode == "start" or mode == "events" or mode == "comments" or mode == "badges":

                    if not (mode == "start" and len(set_excluded_ids) != 0):

                        subquery_events_reported_by = EventReport.objects.filter(event=OuterRef('id')).annotate(data=JSONObject(id=F('user__id'), user=F(
                            'user__username'), user_image=F('user__image_thumbnail'), type=F('type'), details=F('details'), created_time=F('created_time'))).values('data').order_by('-created_time')

                        subquery_comments_reported_by = CommentEventReport.objects.filter(comment=OuterRef('id')).annotate(data=JSONObject(id=F('user__id'), user=F(
                            'user__username'), user_image=F('user__image_thumbnail'), type=F('type'), details=F('details'), created_time=F('created_time'))).values('data').order_by('-created_time')

                        subquery_badges_reported_by = BadgeReport.objects.filter(badge=OuterRef('id')).annotate(data=JSONObject(id=F('user__id'), user=F(
                            'user__username'), user_image=F('user__image_thumbnail'), type=F('type'), details=F('details'), created_time=F('created_time'))).values('data').order_by('-created_time')

                        if mode == "start" or mode == "events":
                            events = Event.objects.select_related('user').filter(~Q(id__in=set_excluded_ids), Q(verificated="verificated") | Q(verificated="awaiting"),
                                                                                 Exists(EventReport.objects.filter(event=OuterRef('id'))), Q(title__icontains=name) | Q(user__username__icontains=name)).annotate(user_image=F('user__image_thumbnail'), reported_by=ArraySubquery(subquery_events_reported_by), count_types=JSONObject(
                                                                                     all_types=Count(
                                                                                         'eventreport'),
                                                                                     type0=Count('eventreport', filter=Q(
                                                                                         eventreport__type='Naruszenie regulaminu')),
                                                                                     type1=Count('eventreport', filter=Q(
                                                                                         eventreport__type='Dyskryminacja')),
                                                                                     type2=Count('eventreport', filter=Q(
                                                                                         eventreport__type='Fałszywe informacje')),
                                                                                     type3=Count('eventreport', filter=Q(
                                                                                         eventreport__type='Niezgodność z zasadami społeczności')),
                                                                                     type4=Count('eventreport', filter=Q(
                                                                                         eventreport__type='Niewłaściwe zachowanie organizatora')),
                                                                                     type5=Count('eventreport', filter=Q(
                                                                                         eventreport__type='Propagowanie nielegalnych działań')))).annotate(all_types_value=KeyTextTransform('all_types', 'count_types')).order_by('-all_types_value')[:6]
                            events = AdminReportsEventsSerializer(
                                events, many=True)

                            if len(events.data) < 6:
                                end_pagination['events'] = True
                            else:
                                end_pagination['events'] = False

                            for event in events.data:
                                excluded_ids_return['events'].append(
                                    event['id'])

                            response['data'] = events.data
                            response['end_pagination'] = end_pagination['events']
                            response['excluded_ids'] = excluded_ids_return['events']
                            response['limit'] = 6

                        if mode == "start" or mode == "comments":

                            comments = CommentEvent.objects.select_related('author').filter(~Q(id__in=set_excluded_ids),
                                                                                            Exists(CommentEventReport.objects.filter(comment=OuterRef('id'))), Q(text__icontains=name) | Q(author__username__icontains=name)).annotate(user=F('author__username'), user_image=F('author__image_thumbnail'), slug=F('event__slug'), uuid=F('event__uuid'), reported_by=ArraySubquery(subquery_comments_reported_by), count_types=JSONObject(
                                                                                                all_types=Count(
                                                                                                    'commenteventreport'),
                                                                                                type0=Count('commenteventreport', filter=Q(
                                                                                                    commenteventreport__type='Treści reklamowe lub spam')),
                                                                                                type1=Count('commenteventreport', filter=Q(
                                                                                                    commenteventreport__type='Materiały erotyczne i pornograficzne')),
                                                                                                type2=Count('commenteventreport', filter=Q(
                                                                                                    commenteventreport__type='Wykorzystywanie dzieci')),
                                                                                                type3=Count('commenteventreport', filter=Q(
                                                                                                    commenteventreport__type='Propagowanie terroryzmu')),
                                                                                                type4=Count('commenteventreport', filter=Q(
                                                                                                    commenteventreport__type='Nękanie lub dokuczanie')),
                                                                                                type5=Count('commenteventreport', filter=Q(
                                                                                                    commenteventreport__type='Nieprawdziwe informacje')))).annotate(all_types_value=KeyTextTransform('all_types', 'count_types')).order_by('-all_types_value')[:6]

                            comments = AdminReportsCommentsSerializer(
                                comments, many=True)

                            if len(comments.data) < 6:
                                end_pagination['comments'] = True
                            else:
                                end_pagination['comments'] = False

                            for comment in comments.data:
                                excluded_ids_return['comments'].append(
                                    comment['id'])

                            response['data'] = comments.data
                            response['end_pagination'] = end_pagination['comments']
                            response['excluded_ids'] = excluded_ids_return['comments']
                            response['limit'] = 6

                        if mode == "start" or mode == "badges":

                            badges = Badge.objects.select_related('creator').filter(~Q(id__in=set_excluded_ids), Q(verificated="verificated") | Q(verificated="awaiting"),
                                                                                    Exists(BadgeReport.objects.filter(
                                                                                        badge=OuterRef('id'))), Q(name__icontains=name) | Q(creator__username__icontains=name)
                                                                                    ).annotate(user=F('creator__username'), user_image=F('creator__image_thumbnail'), slug=F('event__slug'), uuid=F('event__uuid'), reported_by=ArraySubquery(subquery_badges_reported_by),
                                                                                               count_types=JSONObject(
                                                                                        all_types=Count(
                                                                                            'badgereport'),
                                                                                        type0=Count('badgereport', filter=Q(
                                                                                            badgereport__type='Naruszenie regulaminu')),
                                                                                        type1=Count('badgereport', filter=Q(
                                                                                            badgereport__type='Dyskryminacja')),
                                                                                        type2=Count('badgereport', filter=Q(
                                                                                            badgereport__type='Fałszywe informacje')),
                                                                                        type3=Count('badgereport', filter=Q(
                                                                                            badgereport__type='Niezgodność z zasadami społeczności')),
                                                                                        type4=Count('badgereport', filter=Q(
                                                                                            badgereport__type='Obraźliwa miniaturka')),
                                                                                        type5=Count('badgereport', filter=Q(
                                                                                            badgereport__type='Propagowanie nielegalnych działań')))).annotate(all_types_value=KeyTextTransform('all_types', 'count_types')).order_by('-all_types_value')[:6]

                            badges = AdminReportsBadgesSerializer(
                                badges, many=True)

                            if len(badges.data) < 6:
                                end_pagination['badges'] = True
                            else:
                                end_pagination['badges'] = False

                            for badge in badges.data:
                                excluded_ids_return['badges'].append(
                                    badge['id'])

                            response['data'] = badges.data
                            response['end_pagination'] = end_pagination['badges']
                            response['excluded_ids'] = excluded_ids_return['badges']
                            response['limit'] = 6

                        if mode == "start":
                            response = {}

                            response['data'] = {
                                'events': {
                                    'data': events.data,
                                    'end_pagination': end_pagination['events'],
                                    'excluded_ids': excluded_ids_return['events'],
                                    'limit': 6,

                                },
                                'comments': {
                                    'data': comments.data,
                                    'end_pagination': end_pagination['comments'],
                                    'excluded_ids': excluded_ids_return['comments'],
                                    'limit': 6,
                                },
                                'badges': {
                                    'data': badges.data,
                                    'end_pagination': end_pagination['badges'],
                                    'excluded_ids': excluded_ids_return['badges'],
                                    'limit': 6,
                                }
                            }

                        return Response(
                            {
                                'success': 'Sukces', **response, "code": "2000"},
                            status=status.HTTP_200_OK
                        )
                    else:
                        return Response(
                            {'detail': 'Podczas pobrania początkowego nie możesz przesyłać ID do ominięcia. Należy przesłać pustą listę.',
                                "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                else:
                    return Response(
                        {'detail': 'Musisz przekazać wartość "mode" jeden z "start", "events", "comments" lub "badges"',
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


class AdminEventReportedValidateView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = AdminReportedValidateSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            response_admin_verify = admin_verify(request)
            if response_admin_verify is not None:
                return response_admin_verify
            else:
                data = request.data
                event_id = data['target_id']
                actual_status = data['actual_status']
                details = data['details']
                type = data['type']
                change_user_count_reports = True
                if event_id != "":

                    if type == "need_improvement" or type == "remove" or type == "cancel":

                        if actual_status == "verificated" or actual_status == "awaiting":

                            if Event.objects.filter(id=event_id).exists():

                                event = Event.objects.get(id=event_id)

                                if EventReport.objects.filter(event=event).exists():

                                    if event.verificated == actual_status or (event.verificated == "verificated" and actual_status == "awaiting"):
                                        # EVENT MOZE PRZYJMOWAC JEDYNIE STAN "AWAITING" I "VERIFICATED", PODCZAS INNYCH STANÓW NIE MOZNA DAWAĆ REPORTY, JAK I ZMIANA NA TE STANY POWODUJE USUNIECIE REPORTOW
                                        #
                                        #
                                        #
                                        # GDY EVENT "AWAITING" A ACTUAL STATUS "VERIFICATED" TO ZNACZY ZE UZYTKOWNIK WPROWADZIL ZMIANY DO SWOJEGO WYDARZENIA I TRZEBA ZAKTUALIZOWAC MODEL W PANELU ADMINISTRACYJNYM
                                        #
                                        # (BARDZO RZADKI PRZYPADEK) GDY EVENT "VERIFICATED" A ACTUAL STATUS "AWAITING" TO ZNACZY ZE WYDARZENIE ZMIENILO SWOJ STAN NA ZWERYFIKOWANY I KTOS ODRAZU WYSLAL NOWE ZGLOSZENIE, TUTAJ TRESC WYDARZENIA SIE NIE ZMIENIA TYLKO JEDYNIE ZGLOSZENIA WIEC "PASS"
                                        #
                                        # PODMIANA W REDUCERZE: NAZWA, STAN WERYFIKACJI, SLUG, UUID
                                        #
                                        #

                                        user = request.user

                                        if type == "need_improvement":

                                            event.verificated = "need_improvement"
                                            event.verificated_details = details
                                            event.save()

                                            send_websocket_notification([event.user], 2, event, timezone.now(), False)

                                            code = "2010"
                                            change_user_count_reports = False

                                            admin_log = AdminLog.objects.create(
                                                user=user, action_flag="to_improvement", content_type="Event", id_content_type=event_id)

                                        elif type == "remove":
                                            event.verificated = "rejected"
                                            event.verificated_details = details
                                            event.rejected_time = timezone.now()

                                            event.save()

                                            send_websocket_notification([event.user], 3, event, timezone.now(), False)

                                            code = "2011"
                                            change_user_count_reports = False

                                            admin_log = AdminLog.objects.create(
                                                user=user, action_flag="deletion", content_type="Event", id_content_type=event_id)

                                        else:


                                            code = "2012"
                                            admin_log = AdminLog.objects.create(
                                                user=user, action_flag="clear", content_type="Event", id_content_type=event_id)

                                        reports = EventReport.objects.filter(
                                            event=event)
                                        

                                        reports.delete(
                                            minus_count=change_user_count_reports)

                                        admin_log.user_image = user.image_thumbnail
                                        admin_log = AdminLogExistingSerializer(
                                            admin_log)

                                        return Response(
                                            {
                                                'success': "Sukces", 'data': admin_log.data, "code": code},
                                            status=status.HTTP_200_OK
                                        )
                                    else:
                                        return Response(
                                            {'detail': 'Wykryto zmiany w wydarzeniu', 'data': {
                                                "title": event.title, "verificated": event.verificated,  "slug": event.slug, "uuid": event.uuid
                                            },
                                                "code": "2015"},
                                            status=224
                                        )

                                else:

                                    if event.verificated == "verificated" or event.verificated == "awaiting":
                                        # Nie było zgłoszeń lub zostały oczyszczone przed administratora.

                                        return Response(
                                            {'detail': 'Brak zgłoszeń',
                                                "code": "2013"},
                                            status=223
                                        )
                                    else:
                                        # Nie było zgłoszeń lub zostało już ocenione przez administratora.

                                        return Response(
                                            {'detail': 'Brak zgłoszeń',
                                                "code": "2014"},
                                            status=223
                                        )

                            else:
                                return Response(
                                    {'detail': 'Nie znaleziono takiego wydarzenia.',
                                     "code": "2016"},
                                    status=223
                                )
                        else:
                            return Response(
                                {'detail': 'Wartość "actual_status" musi być równa "verificated" lub "awaiting"',
                                 "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )
                    else:
                        return Response(
                            {'detail': 'Jako typ akcji możesz podać jedynie "need_improvement", "remove" albo "cancel"',
                             "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                else:

                    return Response(
                        {'detail': 'Nie podano ID wydarzenia.',
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


class AdminBadgeReportedValidateView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = AdminReportedValidateSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            response_admin_verify = admin_verify(request)
            if response_admin_verify is not None:
                return response_admin_verify
            else:
                data = request.data
                badge_id = data['target_id']
                actual_status = data['actual_status']
                details = data['details']
                type = data['type']
                change_user_count_reports = True

                if badge_id != "":

                    if type == "need_improvement" or type == "remove" or type == "cancel":

                        if actual_status == "verificated" or actual_status == "awaiting":

                            if Badge.objects.filter(id=badge_id).exists():

                                badge = Badge.objects.get(id=badge_id)

                                if BadgeReport.objects.filter(badge=badge).exists():

                                    if badge.verificated == actual_status or (badge.verificated == "verificated" and actual_status == "awaiting"):

                                        user = request.user

                                        if type == "need_improvement":

                                            badge.verificated = "need_improvement"
                                            badge.verificated_details = details
                                            badge.save(
                                                generate_thumbnail=False)
                                            
                                            send_websocket_notification([badge.creator], 5, badge, timezone.now(), False)

                                            code = "2020"
                                            change_user_count_reports = False

                                            admin_log = AdminLog.objects.create(
                                                user=user, action_flag="to_improvement", content_type="Badge", id_content_type=badge_id)

                                        elif type == "remove":
                                            badge.verificated = "rejected"
                                            badge.verificated_details = details
                                            badge.save(
                                                generate_thumbnail=False)
                                            owners_with_main = badge.users_with_main_badge.all()
                                            owners_without_main = badge.badge_owners.exclude(id__in=owners_with_main.values_list('id', flat=True))

                                            send_websocket_notification([badge.creator], 6, badge, timezone.now(), False)
                                            send_websocket_notification(owners_without_main, 10, badge, timezone.now(), False)
                                            send_websocket_notification(owners_with_main, 11, badge, timezone.now(), False)

                                            
                                            code = "2021"
                                            change_user_count_reports = False
                                            admin_log = AdminLog.objects.create(
                                                user=user, action_flag="deletion", content_type="Badge", id_content_type=badge_id)

                                        else:
                                            code = "2022"
                                            admin_log = AdminLog.objects.create(
                                                user=user, action_flag="clear", content_type="Badge", id_content_type=badge_id)

                                        reports = BadgeReport.objects.filter(
                                            badge=badge)
                                        reports.delete(
                                            minus_count=change_user_count_reports)

                                        admin_log.user_image = user.image_thumbnail
                                        admin_log = AdminLogExistingSerializer(
                                            admin_log)

                                        return Response(
                                            {
                                                'success': "Sukces", 'data': admin_log.data, "code": code},
                                            status=status.HTTP_200_OK
                                        )
                                    else:
                                        return Response(
                                            {'detail': 'Wykryto zmiany w odznace', 'data': {
                                                "name": badge.name, "image": badge.image, "verificated": badge.verificated},
                                                "code": "2025"},
                                            status=224
                                        )

                                else:

                                    if badge.verificated == "verificated" or badge.verificated == "awaiting":
                                        # Nie było zgłoszeń lub zostały oczyszczone przed administratora.

                                        return Response(
                                            {'detail': 'Brak zgłoszeń',
                                                "code": "2023"},
                                            status=223
                                        )
                                    else:
                                        # Nie było zgłoszeń lub zostało już ocenione przez administratora.

                                        return Response(
                                            {'detail': 'Brak zgłoszeń',
                                                "code": "2024"},
                                            status=223
                                        )

                            else:
                                return Response(
                                    {'detail': 'Nie znaleziono takiej odznaki.',
                                     "code": "2026"},
                                    status=223
                                )
                        else:
                            return Response(
                                {'detail': 'Wartość "actual_status" musi być równa "verificated" lub "awaiting"',
                                 "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )
                    else:
                        return Response(
                            {'detail': 'Jako typ akcji możesz podać jedynie "need_improvment", "remove" albo "cancel"',
                             "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                else:

                    return Response(
                        {'detail': 'Nie podano ID odznaki.',
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


class AdminCommentReportedValidateView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = AdminCommentReportedValidateSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            response_admin_verify = admin_verify(request)
            if response_admin_verify is not None:
                return response_admin_verify
            else:
                data = request.data
                print(data)
                comment_id = data['target_id']
                details = data['details']
                type = data['type']

                if comment_id != "":

                    if type == "remove" or type == "cancel":

                        if CommentEvent.objects.filter(id=comment_id).exists():

                            comment = CommentEvent.objects.get(id=comment_id)

                            # SYTUACJA GDY KOMENTARZ NIE ZOSTAŁ OCENIONY
                            if CommentEventReport.objects.filter(comment=comment).exists():
                                user = request.user
                                if type == "remove":
                                    comment.is_blocked = True
                                    comment.reported_details = details
                                    comment.save()

                                    send_websocket_notification([comment.author], 7, comment, timezone.now(), False)

                                    code = "2031"
                                    change_user_count_reports = False
                                    admin_log = AdminLog.objects.create(
                                        user=user, action_flag="deletion", content_type="CommentEvent", id_content_type=comment_id)
                                else:
                                    code = "2032"
                                    admin_log = AdminLog.objects.create(
                                        user=user, action_flag="clear", content_type="CommentEvent", id_content_type=comment_id)
                                    change_user_count_reports = True

                                reports = CommentEventReport.objects.filter(
                                    comment=comment)
                                reports.delete(
                                    minus_count=change_user_count_reports)
                                admin_log.user_image = user.image_thumbnail
                                admin_log = AdminLogExistingSerializer(
                                    admin_log)

                                return Response(
                                    {
                                        'success': "Sukces", 'data': admin_log.data, "code": code},
                                    status=status.HTTP_200_OK
                                )

                            else:

                                if comment.is_blocked == False:
                                    # Nie było zgłoszeń lub zostały oczyszczone przed administratora.

                                    return Response(
                                        {'detail': 'Brak zgłoszeń',
                                            "code": "2033"},
                                        status=223
                                    )
                                else:
                                    # Nie było zgłoszeń lub zostało już ocenione przez administratora.

                                    return Response(
                                        {'detail': 'Brak zgłoszeń',
                                            "code": "2034"},
                                        status=223
                                    )
                        else:
                            return Response(
                                {'detail': 'Nie znaleziono takiego komentarza.',
                                    "code": "2036"},
                                status=223
                            )

                    else:
                        return Response(
                            {'detail': 'Jako typ akcji możesz podać jedynie "remove" albo "cancel"',
                             "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                else:

                    return Response(
                        {'detail': 'Nie podano ID wiadomości.',
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


class AdminAwaitingEventsView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = AdminAwaitingsInputSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            response_admin_verify = admin_verify(request)
            if response_admin_verify is not None:
                return response_admin_verify
            else:

                data = request.data

                excluded_ids = data['excluded_ids']
                mode = data['mode']
                name = data['name']
                response = {}
                end_pagination = {}
                excluded_ids_return = {
                    'events': [],
                    'badges': [],
                    'tickets': [],
                }

                if excluded_ids != "" and not isinstance(excluded_ids, list):

                    try:
                        literal_eval_excluded_ids = ast.literal_eval(
                            excluded_ids)

                        set_excluded_ids = set(literal_eval_excluded_ids)

                    except:

                        return Response(
                            {'detail': 'Przesyłana wartość w "excluded_ids" musi mieć format list z liczbami określającymi ID obiektów do pominięcia, lub pozostaw pustą wartość.',
                                "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                else:
                    set_excluded_ids = set(excluded_ids)

                if mode == "start" or mode == "events" or mode == "badges" or mode == "tickets":

                    if not (mode == "start" and len(set_excluded_ids) != 0):

                        if mode == "start" or mode == "events":

                            events = Event.objects.select_related('user').filter(~Q(id__in=set_excluded_ids), Q(title__icontains=name) | Q(user__username__icontains=name),
                                                                                 verificated="awaiting").annotate(user_image=F('user__image_thumbnail')).order_by('edit_time')[:6]

                            events = AdminAwaitingsEventsSerializer(
                                events, many=True)

                            if len(events.data) < 6:
                                end_pagination['events'] = True
                            else:
                                end_pagination['events'] = False

                            for event in events.data:
                                excluded_ids_return['events'].append(
                                    event['id'])

                            response['data'] = events.data
                            response['end_pagination'] = end_pagination['events']
                            response['excluded_ids'] = excluded_ids_return['events']
                            response['limit'] = 6

                        if mode == "start" or mode == "badges":

                            badges = Badge.objects.select_related('creator').filter(~Q(id__in=set_excluded_ids), Q(name__icontains=name) | Q(creator__username__icontains=name), verificated="awaiting").annotate(user=F(
                                'creator__username'), user_image=F('creator__image_thumbnail'), slug=F('event__slug'), uuid=F('event__uuid')).order_by('edit_time')[:12]

                            badges = AdminAwaitingsBadgesSerializer(
                                badges, many=True)

                            if len(badges.data) < 6:
                                end_pagination['badges'] = True
                            else:
                                end_pagination['badges'] = False

                            for badge in badges.data:
                                excluded_ids_return['badges'].append(
                                    badge['id'])

                            response['data'] = badges.data
                            response['end_pagination'] = end_pagination['badges']
                            response['excluded_ids'] = excluded_ids_return['badges']
                            response['limit'] = 12


                        if mode == "start" or mode == "tickets":

                            time_now = timezone.now()

                            subquery_reserved_tickets = OrderedTicket.objects.filter((Q(order__is_paid=True)|Q(order__order_expires_at__gte=time_now))&Q(refunded=False), ticket__id=OuterRef('id')).annotate(count=Func(F('id'), function='Count')).values('count')

                            tickets = Ticket.objects.filter(~Q(id__in=set_excluded_ids), Q(ticket_type__icontains=name) | Q(event__user__username__icontains=name), verificated="awaiting").annotate(user=F(
                                'event__user__username'), user_image=F('event__user__image_thumbnail'), event_title=F('event__title'), reserved_tickets=Subquery(subquery_reserved_tickets), slug=F('event__slug'), uuid=F('event__uuid')).order_by('edit_time')[:12]

                            tickets = AdminAwaitingsTicketsSerializer(
                                tickets, many=True)

                            if len(tickets.data) < 12:
                                end_pagination['tickets'] = True
                            else:
                                end_pagination['tickets'] = False

                            for ticket in tickets.data:
                                excluded_ids_return['tickets'].append(
                                    ticket['id'])

                            response['data'] = tickets.data
                            response['end_pagination'] = end_pagination['tickets']
                            response['excluded_ids'] = excluded_ids_return['tickets']
                            response['limit'] = 12


                        if mode == "start":
                            response = {}

                            response['data'] = {
                                'events': {
                                    'data': events.data,
                                    'end_pagination': end_pagination['events'],
                                    'excluded_ids': excluded_ids_return['events'],
                                    'limit': 6,

                                },
                                'badges': {
                                    'data': badges.data,
                                    'end_pagination': end_pagination['badges'],
                                    'excluded_ids': excluded_ids_return['badges'],
                                    'limit': 12,
                                },
                                'tickets': {
                                    'data': tickets.data,
                                    'end_pagination': end_pagination['tickets'],
                                    'excluded_ids': excluded_ids_return['tickets'],
                                    'limit': 12,
                                }
                            }

                        return Response(
                            {
                                'success': 'Sukces', **response, "code": "2000"},
                            status=status.HTTP_200_OK
                        )

                    else:
                        return Response(
                            {'detail': 'Podczas pobrania początkowego nie możesz przesyłać ID do ominięcia. Należy przesłać pustą listę.',
                                "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )

                else:
                    return Response(
                        {'detail': 'Musisz przekazać wartość "mode" jeden z "start", "events" lub "badges"',
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


class AdminEventAwaitedValidateView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = AdminAwaitedValidateSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            response_admin_verify = admin_verify(request)
            if response_admin_verify is not None:
                return response_admin_verify
            else:
                data = request.data
                event_id = data['target_id']
                actual_edit_time = data['actual_edit_time']
                details = data['details']
                type = data['type']
                change_user_count_reports = True

                if event_id != "":

                    if type == "need_improvement" or type == "remove" or type == "accepted":

                        if is_valid_datetime_format(actual_edit_time):

                            if Event.objects.filter(id=event_id).exists():

                                event = Event.objects.get(id=event_id)

                                if event.verificated == "awaiting":

                                    if event.edit_time.strftime('%Y-%m-%dT%H:%M') == actual_edit_time:

                                        user = request.user

                                        if type == "need_improvement":

                                            event.verificated = "need_improvement"
                                            event.verificated_details = details
                                            event.save()

                                            send_websocket_notification([event.user], 2, event, timezone.now(), False)

                                            code = "2010"

                                            admin_log = AdminLog.objects.create(
                                                user=user, action_flag="to_improvement", content_type="Event", id_content_type=event_id)

                                        elif type == "remove":
                                            event.verificated = "rejected"
                                            event.verificated_details = details
                                            event.save()

                                            send_websocket_notification([event.user], 3, event, timezone.now(), False)

                                            code = "2011"
                                            change_user_count_reports = False
                                            admin_log = AdminLog.objects.create(
                                                user=user, action_flag="deletion", content_type="Event", id_content_type=event_id)

                                        else:

                                            event.verificated = "verificated"
                                            event.verificated_details = ""
                                            event.save()

                                            send_websocket_notification([event.user], 1, event, timezone.now(), False)

                                            code = "2042"
                                            admin_log = AdminLog.objects.create(
                                                user=user, action_flag="confirmation", content_type="Event", id_content_type=event_id)

                                        reports = EventReport.objects.filter(
                                            event=event)
                                        
                                        if len(reports) > 0:
                                            reports.delete(minus_count=change_user_count_reports)
                                        

                                        admin_log.user_image = user.image_thumbnail
                                        admin_log = AdminLogExistingSerializer(
                                            admin_log)

                                        return Response(
                                            {
                                                'success': "Sukces", 'data': admin_log.data, "code": code},
                                            status=status.HTTP_200_OK
                                        )
                                    else:
                                        return Response(
                                            {'detail': 'Wykryto zmiany w wydarzeniu', 'data': {
                                                "title": event.title, "slug": event.slug, "uuid": event.uuid, "text": event.text, "edit_time": event.edit_time.strftime('%Y-%m-%dT%H:%M')
                                            },
                                                "code": "2015"},
                                            status=224
                                        )

                                else:

                                    # Wydarzenie nie jest oczekujące lub wydarzenie zostało juz zweryfikowane, przesłane do poprawy lub przesłane do usunięcia.

                                    return Response(
                                        {'detail': 'Wydarzenie juz było weryfikowane',
                                            "code": "2043"},
                                        status=223
                                    )

                            else:
                                return Response(
                                    {'detail': 'Nie znaleziono takiego wydarzenia.',
                                        "code": "2016"},
                                    status=223
                                )
                        else:
                            return Response(
                                {'detail': 'Przesyłana wartość aktualnej edycji musi mieć format jak w przykładzie "2023-09-21T15:43".',
                                 "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )

                    else:
                        return Response(
                            {'detail': 'Jako typ akcji możesz podać jedynie "need_improvement", "remove" albo "cancel"',
                             "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                else:

                    return Response(
                        {'detail': 'Nie podano ID wydarzenia.',
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


class AdminBadgeAwaitedValidateView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = AdminAwaitedValidateSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            response_admin_verify = admin_verify(request)
            if response_admin_verify is not None:
                return response_admin_verify
            else:
                data = request.data
                badge_id = data['target_id']
                actual_edit_time = data['actual_edit_time']
                details = data['details']
                type = data['type']
                change_user_count_reports = True

                if badge_id != "":

                    if type == "need_improvement" or type == "remove" or type == "accepted":

                        if is_valid_datetime_format(actual_edit_time):

                            if Badge.objects.filter(id=badge_id).exists():

                                badge = Badge.objects.get(id=badge_id)

                                if badge.verificated == "awaiting":

                                    if badge.edit_time.strftime('%Y-%m-%dT%H:%M') == actual_edit_time:

                                        user = request.user

                                        if type == "need_improvement":

                                            badge.verificated = "need_improvement"
                                            badge.verificated_details = details
                                            badge.save(
                                                generate_thumbnail=False)
                                            
                                            send_websocket_notification([badge.creator], 5, badge, timezone.now(), False)

                                            code = "2010"

                                            admin_log = AdminLog.objects.create(
                                                user=user, action_flag="to_improvement", content_type="Badge", id_content_type=badge_id)

                                        elif type == "remove":
                                            badge.verificated = "rejected"
                                            badge.verificated_details = details
                                            badge.save(
                                                generate_thumbnail=False)
                                            
                                            send_websocket_notification([badge.creator], 6, badge, timezone.now(), False)

                                            code = "2011"
                                            change_user_count_reports = False

                                            admin_log = AdminLog.objects.create(
                                                user=user, action_flag="deletion", content_type="Badge", id_content_type=badge_id)

                                        else:

                                            badge.verificated = "verificated"
                                            badge.verificated_details = ""
                                            badge.save(
                                                generate_thumbnail=False)
                                            
                                            send_websocket_notification([badge.creator], 4, badge, timezone.now(), False)

                                            code = "2044"
                                            admin_log = AdminLog.objects.create(
                                                user=user, action_flag="confirmation", content_type="Badge", id_content_type=badge_id)

                                        reports = BadgeReport.objects.filter(
                                            badge=badge)
                                        
                                        if len(reports) > 0:
                                            reports.delete(minus_count=change_user_count_reports)

                                        admin_log.user_image = user.image_thumbnail
                                        admin_log = AdminLogExistingSerializer(
                                            admin_log)

                                        return Response(
                                            {
                                                'success': "Sukces", 'data': admin_log.data, "code": code},
                                            status=status.HTTP_200_OK
                                        )
                                    else:
                                        return Response(
                                            {'detail': 'Wykryto zmiany w odznace', 'data': {
                                                "name": badge.name, "image": badge.image, "edit_time": badge.edit_time.strftime('%Y-%m-%dT%H:%M')
                                            },
                                                "code": "2015"},
                                            status=224
                                        )

                                else:

                                    # Wydarzenie nie jest oczekujące lub wydarzenie zostało juz zweryfikowane, przesłane do poprawy lub przesłane do usunięcia.

                                    return Response(
                                        {'detail': 'Odznaka już była weryfikowana',
                                            "code": "2045"},
                                        status=223
                                    )

                            else:
                                return Response(
                                    {'detail': 'Nie znaleziono takiej odznaki.',
                                        "code": "2026"},
                                    status=223
                                )
                        else:
                            return Response(
                                {'detail': 'Przesyłana wartość aktualnej edycji musi mieć format jak w przykładzie "2023-09-21T15:43".',
                                 "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )

                    else:
                        return Response(
                            {'detail': 'Jako typ akcji możesz podać jedynie "need_improvement", "remove" albo "cancel"',
                             "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                else:

                    return Response(
                        {'detail': 'Nie podano ID wydarzenia.',
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



class AdminTicketAwaitedValidateView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = AdminAwaitedValidateTicketsSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            response_admin_verify = admin_verify(request)
            if response_admin_verify is not None:
                return response_admin_verify
            else:
                data = request.data
                ticket_id = data['target_id']
                actual_edit_time = data['actual_edit_time']
                details = data['details']
                type = data['type']
                stripe_id = data['stripe_id']

                if ticket_id != "":

                    if type == "need_improvement" or type == "remove" or type == "accepted":

                        if is_valid_datetime_format(actual_edit_time):

                            if Ticket.objects.filter(id=ticket_id).exists():

                                ticket = Ticket.objects.get(id=ticket_id)

                                if ticket.verificated == "awaiting":

                                    if ticket.edit_time.strftime('%Y-%m-%dT%H:%M') == actual_edit_time:


                                        user = request.user

                                        if type == "need_improvement" and ticket.was_allowed == False:

                                            ticket.verificated = "need_improvement"
                                            ticket.verificated_details = details
                                            ticket.save()
                                            
                                            send_websocket_notification([ticket.event.user], 13, ticket, timezone.now(), False)

                                            code = "2038"

                                            admin_log = AdminLog.objects.create(user=user, action_flag="to_improvement", content_type="Ticket", id_content_type=ticket_id)

                                        elif type == "remove" and ticket.was_allowed == False:
                                            ticket.verificated = "rejected"
                                            ticket.verificated_details = details
                                            ticket.save()
                                            
                                            send_websocket_notification([ticket.event.user], 14, ticket, timezone.now(), False)

                                            code = "2037"

                                            admin_log = AdminLog.objects.create(user=user, action_flag="deletion", content_type="Ticket", id_content_type=ticket_id)

                                        elif type == "accepted":

                                            if len(stripe_id) == 30:

                                                ticket.verificated = "verificated"
                                                ticket.verificated_details = ""
                                                ticket.was_allowed = True
                                                ticket.stripe_id = stripe_id
                                                ticket.price = ticket.new_price
                                                ticket.save()
                                                
                                                send_websocket_notification([ticket.event.user], 12, ticket, timezone.now(), False)

                                                code = "2046"
                                                admin_log = AdminLog.objects.create(user=user, action_flag="confirmation", content_type="Ticket", id_content_type=ticket_id)
                                            else:
                                                return Response(
                                                    {'detail': 'Nie został przesłany 30-znakowy parametr stripe_id.',
                                                        "code": "9011"},
                                                    status=status.HTTP_400_BAD_REQUEST
                                                )

                                        else:
                                            return Response(
                                                {'detail': 'Gdy bilet zostanie oficjalnie dopuszczony do sprzedaży, możesz jedynie zaakceptować obniżenie jego ceny.',
                                                "code": "9011"},
                                                status=status.HTTP_400_BAD_REQUEST
                                            )


                                        admin_log.user_image = user.image_thumbnail
                                        admin_log = AdminLogExistingSerializer(admin_log)

                                        return Response(
                                            {
                                                'success': "Sukces", 'data': admin_log.data, "code": code},
                                            status=status.HTTP_200_OK
                                        )
                                        
                                    else:
                                        return Response(
                                            {'detail': 'Wykryto zmiany w bilecie', 'data': {
                                                "stripe_id": ticket.stripe_id, 
                                                "ticket_type": ticket.ticket_type, 
                                                "ticket_details":ticket.ticket_details,
                                                "default_price": ticket.default_price,
                                                "price": ticket.price,
                                                "new_price": ticket.new_price,
                                                "quantity": ticket.quantity,
                                                "was_allowed": ticket.was_allowed,
                                                "edit_time": ticket.edit_time.strftime('%Y-%m-%dT%H:%M')
                                            },
                                                "code": "2015"},
                                            status=224
                                        )

                                else:

                                    # Wydarzenie nie jest oczekujące lub wydarzenie zostało juz zweryfikowane, przesłane do poprawy lub przesłane do usunięcia.

                                    return Response(
                                        {'detail': 'Bilet już był weryfikowany',
                                            "code": "2045"},
                                        status=223
                                    )

                            else:
                                return Response(
                                    {'detail': 'Nie znaleziono takiego biletu.',
                                        "code": "2026"},
                                    status=223
                                )
                        else:
                            return Response(
                                {'detail': 'Przesyłana wartość aktualnej edycji musi mieć format jak w przykładzie "2023-09-21T15:43".',
                                "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )

                    else:
                        return Response(
                            {'detail': 'Jako typ akcji możesz podać jedynie "need_improvement", "remove" albo "cancel"',
                            "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                  
                else:

                    return Response(
                        {'detail': 'Nie podano ID biletu.',
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

        
class AdminBanUsersIPView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = AdminBanUsersIPSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            response_admin_verify = admin_verify(request)
            if response_admin_verify is not None:
                return response_admin_verify
            else:

                data = request.data

                excluded_ids = data['excluded_ids']
                mode = data['mode']
                name = data['name']
                response = {}
                end_pagination = {}
                excluded_ids_return = {
                    'users': [],
                    'ips': []
                }

                if excluded_ids != "" and not isinstance(excluded_ids, list):

                    try:
                        literal_eval_excluded_ids = ast.literal_eval(
                            excluded_ids)

                        set_excluded_ids = set(literal_eval_excluded_ids)

                    except:

                        return Response(
                            {'detail': 'Przesyłana wartość w "excluded_ids" musi mieć format list z liczbami określającymi ID obiektów do pominięcia, lub pozostaw pustą wartość.',
                                "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                else:
                    set_excluded_ids = set(excluded_ids)

                if mode == "start" or mode == "users" or mode == "ips":

                    if not (mode == "start" and len(set_excluded_ids) != 0):

                        ip_address = request.META.get('REMOTE_ADDR')
                        user = request.user

                        if mode == "start" or mode == "users":

                            subquery_ip_address = IPAddressValidator.objects.filter(user__id=OuterRef(
                                'id'), ip_address__is_banned=False).annotate(data=JSONObject(
                                    id=F('ip_address__id'),
                                    ip_address=F('ip_address__ip_address'),
                                    is_banned=F('ip_address__is_banned'),
                                    is_verificated=F('is_verificated'),
                                    last_login_time=F('last_login_time'),
                                    last_login_city=F('last_login_city__name'),
                                    last_login_province=F(
                                        'last_login_city__county__province__name'),
                                    name_device=F('name_device'),
                                )).values('data').order_by('-last_login_time')

                            users = MyUser.objects.select_related('city').filter(~Q(id__in=set_excluded_ids), is_banned=False, username__icontains=name).annotate(
                                count_reports=JSONObject(
                                    all=F(
                                        'count_reported_events') + F('count_reported_badges') + F('count_reported_comments'),
                                    events=F('count_reported_events'),
                                    badges=F('count_reported_badges'),
                                    comments=F('count_reported_comments')),
                                count_active_objects=JSONObject(
                                    events=Count('created_events', filter=~Q(
                                        created_events__verificated='rejected'), distinct=True),
                                    badges=Count('created_badges', filter=~Q(
                                        created_badges__verificated='rejected'), distinct=True),
                                    comments=Count('created_comments', filter=Q(
                                        created_comments__is_blocked=False), distinct=True),
                                    all=Count('created_events', filter=~Q(created_events__verificated='rejected'), distinct=True) + Count('created_badges', filter=~Q(created_badges__verificated='rejected'), distinct=True) + Count('created_comments', filter=Q(created_comments__is_blocked=False), distinct=True)),
                                count_deleted=JSONObject(
                                    all=F(
                                        'count_deleted_events') + F('count_deleted_badges') + F('count_deleted_comments'),
                                    events=F('count_deleted_events'),
                                    badges=F('count_deleted_badges'),
                                    comments=F('count_deleted_comments')),
                                province=F('city__county__province__name'),
                                details=ArraySubquery(subquery_ip_address)

                            ).annotate(all_reports_value=KeyTextTransform('all', 'count_reports')).order_by('-all_reports_value')[:6]

                            users = AdminBanUsersSerializer(
                                users, many=True)

                            #####################

                            if len(users.data) < 6:
                                end_pagination['users'] = True
                            else:
                                end_pagination['users'] = False

                            for user in users.data:
                                excluded_ids_return['users'].append(
                                    user['id'])

                            response['data'] = users.data
                            response['end_pagination'] = end_pagination['users']
                            response['excluded_ids'] = excluded_ids_return['users']
                            response['limit'] = 6

                        if mode == "start" or mode == "ips":

                            subquery_users = IPAddressValidator.objects.filter(ip_address__id=OuterRef(
                                'id'), user__is_banned=False).annotate(data=JSONObject(
                                    id=F('user__id'),
                                    username=F('user__username'),
                                    email=F('user__email'),
                                    is_admin=F('user__is_admin'),
                                    is_banned=F('user__is_banned'),
                                    first_name=F('user__first_name'),
                                    last_name=F('user__last_name'),
                                    image_thumbnail=Concat(
                                        Value('/media/'), F('user__image_thumbnail'), output_field=CharField()),
                                    count_reports=JSONObject(
                                        all=F(
                                            'user__count_reported_events') + F('user__count_reported_badges') + F('user__count_reported_comments'),
                                        events=F(
                                            'user__count_reported_events'),
                                        badges=F(
                                            'user__count_reported_badges'),
                                        comments=F(
                                            'user__count_reported_comments')
                                    ),
                                    count_active_objects=JSONObject(
                                        events=Count('user__created_events', filter=~Q(
                                            user__created_events__verificated='rejected'), distinct=True),
                                        badges=Count('user__created_badges', filter=~Q(
                                            user__created_badges__verificated='rejected'), distinct=True),
                                        comments=Count('user__created_comments', filter=Q(
                                            user__created_comments__is_blocked=False), distinct=True),
                                        all=Count('user__created_events', filter=~Q(user__created_events__verificated='rejected'), distinct=True) +
                                        Count('user__created_badges', filter=~Q(user__created_badges__verificated='rejected'), distinct=True) +
                                        Count('user__created_comments', filter=Q(
                                            user__created_comments__is_blocked=False), distinct=True)
                                    ),
                                    count_deleted=JSONObject(
                                        all=F(
                                            'user__count_deleted_events') + F('user__count_deleted_badges') + F('user__count_deleted_comments'),
                                        events=F('user__count_deleted_events'),
                                        badges=F('user__count_deleted_badges'),
                                        comments=F('user__count_deleted_comments')),
                                    city=F('user__city__name'),
                                    province=F(
                                        'user__city__county__province__name'),
                                    is_verificated=F('is_verificated'),
                                    last_login_time=F('last_login_time'),
                                    last_login_city=F('last_login_city__name'),
                                    last_login_province=F(
                                        'last_login_city__county__province__name'),
                                    name_device=F('name_device')
                                )).values('data').order_by('-last_login_time')

                            ips_name_filter = IPAddressValidator.objects.filter(
                                user__username__icontains=name
                            ).values("ip_address__id").distinct()

                            subquery_active_events = Event.objects.filter(~Q(verificated="rejected"), user__validators_of_user__ip_address__id=OuterRef(
                                'id')).values('user__validators_of_user__ip_address__id').annotate(count=Count('id')).values('count')

                            subquery_active_badges = Badge.objects.filter(~Q(verificated="rejected"), creator__validators_of_user__ip_address__id=OuterRef(
                                'id')).values('creator__validators_of_user__ip_address__id').annotate(count=Count('id')).values('count')

                            subquery_active_comments = CommentEvent.objects.filter(is_blocked=False, author__validators_of_user__ip_address__id=OuterRef(
                                'id')).values('author__validators_of_user__ip_address__id').annotate(count=Count('id')).values('count')

                            ips = IPAddress.objects.filter(
                                ~Q(id__in=set_excluded_ids), is_banned=False, id__in=ips_name_filter).annotate(
                                    count_reports=JSONObject(
                                        all=Sum('users_of_ip__user__count_reported_events') + Sum(
                                            'users_of_ip__user__count_reported_badges') + Sum('users_of_ip__user__count_reported_comments'),
                                        events=Sum(
                                            'users_of_ip__user__count_reported_events'),
                                        badges=Sum(
                                            'users_of_ip__user__count_reported_badges'),
                                        comments=Sum('users_of_ip__user__count_reported_comments')),
                                    count_active_objects=JSONObject(
                                        comments=Coalesce(Subquery(
                                            subquery_active_comments), Value(0)),
                                        events=Coalesce(Subquery(
                                            subquery_active_events), Value(0)),
                                        badges=Coalesce(
                                            Subquery(subquery_active_badges), Value(0)),
                                        all=Coalesce(Subquery(
                                            subquery_active_comments), Value(0)) + Coalesce(Subquery(
                                                subquery_active_events), Value(0)) + Coalesce(
                                            Subquery(subquery_active_badges), Value(0))),
                                    count_deleted=JSONObject(
                                        all=Sum('users_of_ip__user__count_deleted_events') + Sum(
                                            'users_of_ip__user__count_deleted_badges') + Sum('users_of_ip__user__count_deleted_comments'),
                                        events=Sum(
                                            'users_of_ip__user__count_deleted_events'),
                                        badges=Sum(
                                            'users_of_ip__user__count_deleted_badges'),
                                        comments=Sum('users_of_ip__user__count_deleted_comments')),
                                    details=ArraySubquery(subquery_users)
                            ).annotate(all_reports_value=KeyTextTransform('all', 'count_reports')).order_by('-all_reports_value')[:6]

                            ips = AdminBanIPsSerializer(ips, many=True)

                            #################

                            if len(ips.data) < 6:
                                end_pagination['ips'] = True
                            else:
                                end_pagination['ips'] = False

                            for ip in ips.data:
                                excluded_ids_return['ips'].append(
                                    ip['id'])

                            response['data'] = ips.data
                            response['end_pagination'] = end_pagination['ips']
                            response['excluded_ids'] = excluded_ids_return['ips']
                            response['limit'] = 6

                        if mode == "start":
                            response = {}

                            response['data'] = {
                                'users': {
                                    'data': users.data,
                                    'end_pagination': end_pagination['users'],
                                    'excluded_ids': excluded_ids_return['users'],
                                    'limit': 6,

                                },
                                'ips': {
                                    'data': ips.data,
                                    'end_pagination': end_pagination['ips'],
                                    'excluded_ids': excluded_ids_return['ips'],
                                    'limit': 6,
                                    'self_ip': ip_address,
                                }
                            }


                        return Response(
                            {
                                'success': 'Sukces', **response, "code": "2000"},
                            status=status.HTTP_200_OK
                        )

                    else:
                        return Response(
                            {'detail': 'Podczas pobrania początkowego nie możesz przesyłać ID do ominięcia. Należy przesłać pustą listę.',
                                "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )

                else:
                    return Response(
                        {'detail': 'Musisz przekazać wartość "mode" jeden z "start", "users" lub "ips"',
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


class AdminUserBanValidateView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = AdminBanValidateSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            response_admin_verify = admin_verify(request)
            if response_admin_verify is not None:
                return response_admin_verify
            else:
                data = request.data
                user_id = data['target_id']

                if user_id != "":

                    if MyUser.objects.filter(id=user_id).exists():

                        target_user = MyUser.objects.get(id=user_id)
                        user = request.user

                        if not target_user.id == user.id:

                            if target_user.is_banned == False:

                                target_user.is_banned = True
                                target_user.save(generate_thumbnail=False)

                                admin_log = AdminLog.objects.create(
                                    user=user, action_flag="ban_user", content_type="MyUser", id_content_type=user_id)
                                admin_log.user_image = user.image_thumbnail
                                admin_log = AdminLogExistingSerializer(
                                    admin_log)

                                return Response(
                                    {
                                        'success': "Sukces", 'data': admin_log.data, "code": "2050"},
                                    status=status.HTTP_200_OK
                                )

                            else:

                                # Użytkownik jest juz zbanowany

                                return Response(
                                    {'detail': 'Użytkownik jest już zbanowany',
                                        "code": "2052"},
                                    status=223
                                )
                        else:

                            return Response(
                                {'detail': 'Nie możesz zbanować samego siebie.',
                                 "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )

                    else:
                        return Response(
                            {'detail': 'Nie znaleziono takiego użytkownika.', 'statistic_change': True,
                                "code": "2051"},
                            status=223
                        )

                else:

                    return Response(
                        {'detail': 'Nie podano ID użytkownika.',
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


class AdminIPBanValidateView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = AdminBanValidateSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            response_admin_verify = admin_verify(request)
            if response_admin_verify is not None:
                return response_admin_verify
            else:
                data = request.data
                ip_id = data['target_id']

                if ip_id != "":

                    if IPAddress.objects.filter(id=ip_id).exists():

                        target_ipaddress = IPAddress.objects.get(id=ip_id)
                        ip_address = request.META.get('REMOTE_ADDR')

                        if not target_ipaddress.ip_address == ip_address:

                            if target_ipaddress.is_banned == False:

                                user = request.user

                                target_ipaddress.is_banned = True
                                target_ipaddress.save()

                                queryset_users = MyUser.objects.filter(~Q(id=user.id), ip_validator__ip_address=target_ipaddress)

                                send_websocket_notification(queryset_users, 9, target_ipaddress, timezone.now(), False)

                                admin_log = AdminLog.objects.create(
                                    user=user, action_flag="ban_ip", content_type="IPAddress", id_content_type=ip_id)
                                admin_log.user_image = user.image_thumbnail
                                admin_log = AdminLogExistingSerializer(
                                    admin_log)

                                return Response(
                                    {
                                        'success': "Sukces", 'data': admin_log.data, "code": "2055"},
                                    status=status.HTTP_200_OK
                                )

                            else:

                                # Użytkownik jest juz zbanowany

                                return Response(
                                    {'detail': 'Adres IP jest już zbanowany',
                                        "code": "2057"},
                                    status=223
                                )
                        else:

                            return Response(
                                {'detail': 'Nie możesz zbanować adresu IP, z którego wykonujesz akcje.',
                                 "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )

                    else:
                        return Response(
                            {'detail': 'Nie znaleziono takiego adresu IP.',
                                "code": "2056"},
                            status=223
                        )

                else:

                    return Response(
                        {'detail': 'Nie podano ID adresu IP.',
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


class AdminAccountsLogoutView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = AdminAccountsLogoutSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            response_admin_verify = admin_verify(request)
            if response_admin_verify is not None:
                return response_admin_verify
            else:
                data = request.data
                target_id = data['target_id']
                type = data['type']
                extra_id = data.get('ipaddress_id', None)

                if target_id != "":

                    if type == "all_ips" or type == "all_users" or type == "single":

                        user = request.user
                        ip_address = request.META.get('REMOTE_ADDR')

                        if type == "all_ips":
                            if MyUser.objects.filter(id=target_id).exists():
                                target_user = MyUser.objects.get(id=target_id)

                                if not target_user.id == user.id:

                                    if target_user.is_banned == False:

                                        validators = target_user.validators_of_user.all()

                                        validators.update(is_verificated=False)

                                        admin_log = AdminLog.objects.create(
                                            user=user, action_flag="logout", content_type="MyUser", id_content_type=target_id)
                                        admin_log.user_image = user.image_thumbnail
                                        admin_log = AdminLogExistingSerializer(
                                            admin_log)

                                        return Response(
                                            {
                                                'success': "Sukces", 'data': admin_log.data, "code": "2060"},
                                            status=status.HTTP_200_OK
                                        )

                                    else:
                                        # Użytkownik jest juz zbanowany

                                        return Response(
                                            {'detail': 'Ten użytkownik jest zbanowny',
                                                "code": "2052"},
                                            status=223
                                        )
                                else:

                                    return Response(
                                        {'detail': 'Nie możesz wykonać akcji wymuszenia wylogowania na samego siebie.',
                                         "code": "9011"},
                                        status=status.HTTP_400_BAD_REQUEST
                                    )

                            else:  # TUTAJ
                                return Response(
                                    {'detail': 'Nie znaleziono takiego użytkownika.', 'statistic_change': True,
                                        "code": "2051"},
                                    status=223
                                )

                        elif type == "all_users":

                            if IPAddress.objects.filter(id=target_id).exists():
                                target_ipaddress = IPAddress.objects.get(
                                    id=target_id)

                                if not target_ipaddress.ip_address == ip_address:

                                    if target_ipaddress.is_banned == False:

                                        validators = target_ipaddress.users_of_ip.all()

                                        validators.update(is_verificated=False)

                                        admin_log = AdminLog.objects.create(
                                            user=user, action_flag="logout", content_type="IPAddress", id_content_type=target_id)
                                        admin_log.user_image = user.image_thumbnail
                                        admin_log = AdminLogExistingSerializer(
                                            admin_log)

                                        return Response(
                                            {
                                                'success': "Sukces", 'data': admin_log.data, "code": "2061"},
                                            status=status.HTTP_200_OK
                                        )

                                    else:
                                        # Użytkownik jest juz zbanowany

                                        return Response(
                                            {'detail': 'Ten adres IP jest zbanowny',
                                                "code": "2057"},
                                            status=223
                                        )
                                else:

                                    return Response(
                                        {'detail': 'Nie możesz wykonać akcji wymuszenia wylogowania na adres IP, z którego korzystasz.',
                                         "code": "9011"},
                                        status=status.HTTP_400_BAD_REQUEST
                                    )

                            else:
                                return Response(
                                    {'detail': 'Nie znaleziono takiego adresu IP.',
                                        "code": "2056"},
                                    status=223
                                )

                        else:

                            if extra_id != "":

                                if MyUser.objects.filter(id=target_id).exists():

                                    target_user = MyUser.objects.get(
                                        id=target_id)

                                    if target_user.is_banned == False:

                                        if IPAddress.objects.filter(id=extra_id).exists():

                                            target_ipaddress = IPAddress.objects.get(
                                                id=extra_id)

                                            if not target_ipaddress.ip_address == ip_address or not target_user.id == user.id:

                                                if target_ipaddress.is_banned == False:

                                                    if IPAddressValidator.objects.filter(user=target_user, ip_address=target_ipaddress).exists():

                                                        target_ipaddressvalidator = IPAddressValidator.objects.get(
                                                            user=target_user, ip_address=target_ipaddress)
                                                        target_ipaddressvalidator.is_verificated = False
                                                        target_ipaddressvalidator.save()

                                                        admin_log = AdminLog.objects.create(
                                                            user=user, action_flag="logout", content_type="IPAddressValidator", id_content_type=target_ipaddressvalidator.id)
                                                        admin_log.user_image = user.image_thumbnail
                                                        admin_log = AdminLogExistingSerializer(
                                                            admin_log)

                                                        return Response(
                                                            {
                                                                'success': "Sukces", 'data': admin_log.data, "code": "2062"},
                                                            status=status.HTTP_200_OK
                                                        )
                                                    else:

                                                        return Response(
                                                            {'detail': 'Validator został usunięty z bazy danych',
                                                                "code": "2058"},
                                                            status=225
                                                        )

                                                else:
                                                    # Użytkownik jest juz zbanowany

                                                    return Response(
                                                        {'detail': 'Ten adres IP jest zbanowny',
                                                            "code": "2057"},
                                                        status=223
                                                    )
                                            else:

                                                return Response(
                                                    {'detail': 'Nie możesz wymusić wylogowania na samego siebie.',
                                                     "code": "9011"},
                                                    status=status.HTTP_400_BAD_REQUEST
                                                )

                                        else:
                                            return Response(
                                                {'detail': 'Nie znaleziono takiego adresu IP.',
                                                    "code": "2056"},
                                                status=223
                                            )

                                    else:
                                        # Użytkownik jest juz zbanowany

                                        return Response(
                                            {'detail': 'Ten użytkownik jest zbanowny',
                                                "code": "2052"},
                                            status=223
                                        )

                                else:  # TUTAJ
                                    return Response(
                                        {'detail': 'Nie znaleziono takiego użytkownika.', 'statistic_change': True,
                                            "code": "2051"},
                                        status=223
                                    )
                            else:

                                return Response(
                                    {'detail': 'Nie podano ID adresu IP.',
                                     "code": "9011"},
                                    status=status.HTTP_400_BAD_REQUEST
                                )

                    else:
                        return Response(
                            {'detail': 'Jako typ akcji możesz podać jedynie "all_ips", "all_users" albo "single"',
                             "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )

                else:

                    return Response(
                        {'detail': 'Nie podano ID celu.',
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


class AdminPaychecksView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = AdminPaychecksSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            response_admin_verify = admin_verify(request)
            if response_admin_verify is not None:
                return response_admin_verify
            else:

                data = request.data

                excluded_ids = data['excluded_ids']
                mode = data['mode']
                name = data['name']
                response = {}
                end_pagination = {}
                excluded_ids_return = {
                    'events': [],
                    'tickets': [],
                }
                time_now = timezone.now()

                user = request.user

                if excluded_ids != "" and not isinstance(excluded_ids, list):

                    try:
                        literal_eval_excluded_ids = ast.literal_eval(
                            excluded_ids)

                        set_excluded_ids = set(literal_eval_excluded_ids)

                    except:

                        return Response(
                            {'detail': 'Przesyłana wartość w "excluded_ids" musi mieć format list z liczbami określającymi ID obiektów do pominięcia, lub pozostaw pustą wartość.',
                                "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                else:
                    set_excluded_ids = set(excluded_ids)

                if mode == "start" or mode == "events" or mode == "tickets":

                    if not (mode == "start" and len(set_excluded_ids) != 0):

                        if mode == "start" or mode == "events":


                            subquery_exist_bought_ticket = OrderedTicket.objects.filter(
                                                    ticket__event__id=OuterRef('id'),
                                                    order__is_paid=True,
                                                    refunded=False
                                                )

                            subquery_paid_event = Paycheck.objects.filter(event__id=OuterRef('id'))



                            subquery_payment_information_event = GatewayPaycheck.objects.filter(created_by=user, remove_time__gte=time_now, event__id=OuterRef('id')).annotate(data=JSONObject(bank_number=OuterRef('user__bank_number'),uuid_gateway=F('uuid') )).values('data')


                            
                            events = Event.objects.select_related('user').filter(~Q(id__in=set_excluded_ids), Q(title__icontains=name) | Q(user__username__icontains=name), ~(Exists(subquery_paid_event)), Exists(subquery_exist_bought_ticket),
                                    verificated="verificated", allow_paycheck=True).annotate(
                                        user_image=F('user__image_thumbnail'), 
                                        payment_locked=Exists(GatewayPaycheck.objects.filter(~Q(created_by=user), remove_time__gte=time_now, event__id=OuterRef('id'))),
                                        payment_locked_expires = Subquery(GatewayPaycheck.objects.filter(remove_time__gte=time_now, event__id=OuterRef('id')).order_by('-remove_time').values('remove_time')[:1]),
                                        price_before_commission=Subquery(subquery_exist_bought_ticket.values('ticket__event').annotate(total=Sum('purchase_price')).values('total')), 
                                        price=ExpressionWrapper(F('price_before_commission') * 0.95, output_field=DecimalField()),
                                        payment_information=Case(When(Exists(GatewayPaycheck.objects.filter(created_by=user, remove_time__gte=time_now, event__id=OuterRef('id'))), then=Subquery(subquery_payment_information_event)), default=Value(None))
                                        ).order_by('event_date')[:6]

                       
                            
                            events = AdminPaychecksEventsSerializer(events, many=True)



                            if len(events.data) < 6:
                                end_pagination['events'] = True
                            else:
                                end_pagination['events'] = False

                            for event in events.data:
                                excluded_ids_return['events'].append(
                                    event['id'])

                            response['data'] = events.data
                            response['end_pagination'] = end_pagination['events']
                            response['excluded_ids'] = excluded_ids_return['events']
                            response['limit'] = 6

                      

                        if mode == "start" or mode == "tickets":


                            subquery_payment_information_tickets = GatewayPaycheck.objects.filter(created_by=user, remove_time__gte=time_now, id=OuterRef('gatewaypaycheck__id')).annotate(data=JSONObject(bank_number=OuterRef('order__user__bank_number'),uuid_gateway=F('uuid') )).values('data')


                            tickets = OrderedTicket.objects.filter(Q(ticket__ticket_type__icontains=name) | Q(order__user__username__icontains=name) | Q(first_name__icontains=name) | Q(last_name__icontains=name), ~(Exists(Paycheck.objects.filter(tickets__id=OuterRef('id')))), ~(Exists(AwaitingsTicketsRefund.objects.filter(tickets__id=OuterRef('id')))), refunded=True, used=False).values(
                                'ticket__event__id',
                                'order__user__id',
                                'gatewaypaycheck__id'
                            ).annotate(
                            price=Sum('purchase_price'),
                            total_tickets=Count('id'),
                            ticket_details=ArrayAgg(
                                        JSONObject(
                                            id=F('id'),
                                            price=F('purchase_price'),
                                            first_name=F('first_name'),
                                            last_name=F('last_name'),
                                            date_of_birth=F('date_of_birth'),
                                            ticket_type=F('ticket__ticket_type')
                                        ), ordering=("-purchase_price", "id")
                            ),
                            all_orderedtickets_ids=ArrayAgg('id'),
                            event_id=F('ticket__event__id'),
                            min_paid_time_order=Min('order__paid_time'),
                            payment_locked=Exists(GatewayPaycheck.objects.filter(~Q(created_by=user), remove_time__gte=time_now, id=OuterRef('gatewaypaycheck__id'))),
                            payment_locked_expires = Subquery(GatewayPaycheck.objects.filter(remove_time__gte=time_now, id=OuterRef('gatewaypaycheck__id')).values('remove_time')),
                            id=Min('id'),
                            title=F('ticket__event__title'),
                            slug=F('ticket__event__slug'), 
                            uuid=F('ticket__event__uuid'),
                            user=F('order__user__username'),
                            user_id=F('order__user__id'),
                            user_image=F('order__user__image_thumbnail'),
                            payment_information=Case(When(Exists(GatewayPaycheck.objects.filter(created_by=user, remove_time__gte=time_now, id=OuterRef('gatewaypaycheck__id'))), then=Subquery(subquery_payment_information_tickets)), default=Value(None))
                            ).order_by('min_paid_time_order').filter(~Q(id__in=set_excluded_ids))[:6]


                         
                            tickets = AdminPaychecksTicketsSerializer(tickets, many=True)



                            if len(tickets.data) < 6:
                                end_pagination['tickets'] = True
                            else:
                                end_pagination['tickets'] = False

                            for ticket in tickets.data:
                                excluded_ids_return['tickets'].append(
                                    ticket['id'])


                            response['data'] = tickets.data
                            response['end_pagination'] = end_pagination['tickets']
                            response['excluded_ids'] = excluded_ids_return['tickets']
                            response['limit'] = 6


                        if mode == "start":
                            response = {}

                            response['data'] = {
                                'events': {
                                    'data': events.data,
                                    'end_pagination': end_pagination['events'],
                                    'excluded_ids': excluded_ids_return['events'],
                                    'limit': 6,
                                },
                                'tickets': {
                                    'data': tickets.data,
                                    'end_pagination': end_pagination['tickets'],
                                    'excluded_ids': excluded_ids_return['tickets'],
                                    'limit': 6,
                                }
                            }

                        return Response(
                            {
                                'success': 'Sukces', **response, "code": "2000"},
                            status=status.HTTP_200_OK
                        )



                    else:
                        return Response(
                            {'detail': 'Podczas pobrania początkowego nie możesz przesyłać ID do ominięcia. Należy przesłać pustą listę.',
                                "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )

                else:
                    return Response(
                        {'detail': 'Musisz przekazać wartość "mode" jeden z "start", "events" lub "tickets"',
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


class AdminPaycheckGatewayView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = AdminPaycheckGatewaySerializer


    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            response_admin_verify = admin_verify(request)
            if response_admin_verify is not None:
                return response_admin_verify
            else:
                data = request.data

                event_id = data['event_id']
                user_id = data['user_id']
                orderedticket_ids = data.get('orderedticket_ids', None)
                mode = data['mode']
                user = request.user
                time_now = timezone.now()

                

                
                if mode == "tickets" or mode == "events":

                    if str(event_id).isdigit() and Event.objects.filter(id=event_id).exists():


                        if str(user_id).isdigit() and MyUser.objects.filter(~Q(bank_number=""), id=user_id).exists():


                            if mode == "tickets":
                                    
                                error_response, set_orderedticket_ids = check_orderedtickets_ids(orderedticket_ids)
                                if error_response != None:
                                    return error_response
                                

                                tickets_request_to_refund = OrderedTicket.objects.filter(~(Exists(Paycheck.objects.filter(tickets__id=OuterRef('id')))), id__in=set_orderedticket_ids, refunded=True, used=False, order__user__id=user_id, ticket__event__id=event_id)


                                if len(tickets_request_to_refund) != 0:

                                    if len(tickets_request_to_refund) == len(set_orderedticket_ids):


                                        if not GatewayPaycheck.objects.filter(~Q(created_by=user), tickets__in=set_orderedticket_ids, remove_time__gte=time_now).exists():


                                            new_gateway = GatewayPaycheck.objects.create(created_by=user)
                                            new_gateway.tickets.set(set_orderedticket_ids)

                                            bank_number = MyUser.objects.get(id=user_id).bank_number


                                            return Response(
                                                {
                                                    'success': "Sukces", 'bank_number': bank_number, 'payment_locked_expires':new_gateway.remove_time, 'uuid_gateway': new_gateway.uuid,  "code": '2163'},
                                                status=status.HTTP_200_OK
                                            )

                                        else:


                                            payment_locked_expires = GatewayPaycheck.objects.filter(~Q(created_by=user), tickets__in=set_orderedticket_ids, remove_time__gte=time_now).order_by('-remove_time').first().remove_time



                                            return Response(
                                                {'detail': 'Inny administrator już rozpoczął akcję zwrotów biletów.', 'payment_locked_expires': payment_locked_expires,
                                                    "code": "2162"},
                                                status=225
                                            )
                                            
                                    else:

                                        # PRZYPADEK GDY JEDEN Z NASZYCH BILETOW NIEISTNIEJE LUB ZOSTAL JUZ OPLACONY W JAKIS SPOSOB JAKO POJEDYNCZY


                                        # POBIERAMY WSZYSTKIE ZWROCONE I NIEOPLACONE BILETY USERA POD DANE WYDARZENIE
                                        all_tickets_user_refunded_in_event = OrderedTicket.objects.filter(~(Exists(Paycheck.objects.filter(tickets__id=OuterRef('id')))), refunded=True, used=False, order__user__id=user_id, ticket__event__id=event_id)


                                        # WYCIAGAMY Z NICH SUME DO ZWROTU
                                        total_price = all_tickets_user_refunded_in_event.aggregate(Sum('purchase_price'))['purchase_price__sum']


                                        # WYKONUJEMY SERIALIZER NA NOWYCH ZWRÓCONYCH TICKETACH ABY DODAC JE DO REDUCERA
                                        new_created_refund_tickets = all_tickets_user_refunded_in_event.filter(~Q(id__in=set_orderedticket_ids))

                                        new_created_refund_tickets = AdminMissingTicketsPaycheckSerializer(new_created_refund_tickets, many=True)



                                        return Response(
                                            {'detail': 'Przynajmniej jeden bilet został już opłacony.','all_ids': all_tickets_user_refunded_in_event.values_list('id', flat=True), 'total_price': total_price, 'data': new_created_refund_tickets.data,
                                                "code": "2142"},
                                            status=224
                                        )
                                else:
                                    return Response(
                                        {'detail': 'Bilety zostały już zwrócone przez innego administratora.',
                                            "code": "2165"},
                                        status=223
                                    )
                                
                            elif mode == "events":


                                if str(event_id).isdigit() and Event.objects.filter(id=event_id, verificated="verificated", allow_paycheck=True).exists():


                                    if not Paycheck.objects.filter(event__id=event_id).exists():


                                        if not GatewayPaycheck.objects.filter(~Q(created_by=user), event__id=event_id, remove_time__gte=time_now).exists():

                                            new_gateway = GatewayPaycheck.objects.create(created_by=user, event=Event.objects.get(id=event_id))

                                            bank_number = MyUser.objects.get(id=user_id).bank_number


                                            return Response(
                                                {
                                                    'success': "Sukces", 'bank_number': bank_number, 'payment_locked_expires':new_gateway.remove_time, 'uuid_gateway': new_gateway.uuid, "code": '2163'},
                                                status=status.HTTP_200_OK
                                            )
                                        

                                        else:

                                            payment_locked_expires = GatewayPaycheck.objects.filter(~Q(created_by=user), event__id=event_id, remove_time__gte=time_now).order_by('-remove_time').first().remove_time



                                            return Response(
                                                {'detail': 'Inny administrator już rozpoczął akcję opłacenia wydarzenia.', 'payment_locked_expires': payment_locked_expires,
                                                    "code": "2162"},
                                                status=225
                                            )
                                        
                                    else:
                                        return Response(
                                            {'detail': 'Wydarzenie zostało już opłacone przez innego administratora.',
                                                "code": "2165"},
                                            status=223
                                        )
                                else:
                                    return Response(
                                        {'detail': 'Wydarzenie nie spełnia wymagań do wypłaty.',
                                            "code": "2164"},
                                        status=223
                                    )
                        else:
                            return Response(
                                {'detail': 'Nie ma takiego użytkownika z podpiętym numerem bankowym.',
                                    "code": "2026"},
                                status=status.HTTP_400_BAD_REQUEST
                            )
                    else:
                        return Response(
                            {'detail': 'Nie ma takiego wydarzenia.', 'delete_tickets': True,
                                "code": "2113"},
                            status=status.HTTP_400_BAD_REQUEST
                        )

                else:
                    return Response(
                        {'detail': 'Typ akcji musi określac tickets albo events.',
                            "code": "2026"},
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

class AdminTicketPaycheckValidateView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = AdminTicketPaycheckValidateSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            response_admin_verify = admin_verify(request)
            if response_admin_verify is not None:
                return response_admin_verify
            else:
                data = request.data
                uuid_gateway = data['uuid_gateway']
                pdf_confirm_payment = data['pdf_confirm_payment']
                user = request.user
                time_now = timezone.now()


                error_response_pdf = check_file_is_pdf(pdf_confirm_payment)
                if error_response_pdf != None:
                    return error_response_pdf


                if GatewayPaycheck.objects.filter(created_by=user, uuid=uuid_gateway, remove_time__gte=time_now).exists():


                    my_gateway = GatewayPaycheck.objects.get(created_by=user, uuid=uuid_gateway, remove_time__gte=time_now)

                    my_gateway.set_paid(pdf_confirm_payment, 'tickets')

                    send_websocket_notification([my_gateway.paycheck.user], 17, my_gateway, timezone.now(), False)

                    admin_log = AdminLog.objects.create(user=user, action_flag="paycheck", content_type="GatewayPaycheck", id_content_type=my_gateway.id)
                    admin_log.user_image = user.image_thumbnail
                    admin_log = AdminLogExistingSerializer(admin_log)

                    return Response(
                        {
                            'success': "Sukces", 'data': admin_log.data, "code": '2165'},
                        status=status.HTTP_200_OK
                    )
         
                else:
                    return Response(
                        {'detail': 'Twoja bramka została zamknięta.',
                            "code": "2167"},
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
                {'detail': 'Coś poszło nie tak z próbą pobrania danych',
                    "code": "1165"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class AdminEventPaycheckValidateView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = AdminTicketPaycheckValidateSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            response_admin_verify = admin_verify(request)
            if response_admin_verify is not None:
                return response_admin_verify
            else:
                data = request.data
                uuid_gateway = data['uuid_gateway']
                pdf_confirm_payment = data['pdf_confirm_payment']
                user = request.user
                time_now = timezone.now()


                error_response_pdf = check_file_is_pdf(pdf_confirm_payment)
                if error_response_pdf != None:
                    return error_response_pdf


                if GatewayPaycheck.objects.filter(created_by=user, uuid=uuid_gateway, remove_time__gte=time_now).exists():


                    my_gateway = GatewayPaycheck.objects.get(created_by=user, uuid=uuid_gateway, remove_time__gte=time_now)

                    my_gateway.set_paid(pdf_confirm_payment, 'events')

                    send_websocket_notification([my_gateway.paycheck.user], 17, my_gateway, timezone.now(), False)

                    admin_log = AdminLog.objects.create(user=user, action_flag="paycheck", content_type="GatewayPaycheck", id_content_type=my_gateway.id)
                    admin_log.user_image = user.image_thumbnail
                    admin_log = AdminLogExistingSerializer(admin_log)

                    return Response(
                        {
                            'success': "Sukces", 'data': admin_log.data, "code": '2165'},
                        status=status.HTTP_200_OK
                    )
         
                else:
                    return Response(
                        {'detail': 'Twoja bramka została zamknięta.',
                            "code": "2167"},
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
                {'detail': 'Coś poszło nie tak z próbą pobrania danych',
                    "code": "1165"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

