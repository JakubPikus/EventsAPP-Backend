from rest_framework import permissions, status, pagination
from rest_framework.views import APIView
from rest_framework.response import Response
from ..serializers import FriendsListSerializer, FriendshipListSerializer, LastMessagesListSerializer, UserConversationSerializer, PasswordChangeSerializer, FindProfileByIdSerializer, NotificationsListSerializer
from ..models import ActiveMessage, Friendship_Request, MyUser, DeleteModel, Notification
from .functions import token_verify, remove_cookies, append_extra_data_notification
from django.db.models import Count, OuterRef, Subquery, Value, Q, F, Exists, Case, When, CharField
from django.db.models.functions import JSONObject, Coalesce
from django.contrib.postgres.expressions import ArraySubquery
from django.apps import apps
import ast
import datetime



class FriendsListView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = FriendsListSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify

            else:
                user = request.user
                data = request.data
                excluded_ids = data['excluded_ids']
                excluded_ids_return = []
                response = {}

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

                count_sent_to_me = ActiveMessage.objects.filter(
                    recipient__id=user.id,
                    sender__id=OuterRef('id')
                ).values('sender__id').annotate(count=Count('sender__id')).values('count')

                count_sent_by_me = ActiveMessage.objects.filter(
                    sender__id=user.id,
                    recipient__id=OuterRef('id')
                ).values('recipient__id').annotate(count=Count('recipient__id')).values('count')

                friends = user.friends.filter(~Q(id__in=set_excluded_ids), is_banned=False).annotate(
                    count_messages=Coalesce(Subquery(count_sent_by_me), Value(0)) + Coalesce(Subquery(count_sent_to_me), Value(0)), is_friend=Value(True)).order_by('-count_messages')[:14]

                friends = FriendsListSerializer(friends, many=True)

                if len(friends.data) < 14:
                    response['end_pagination'] = True
                else:
                    response['end_pagination'] = False

                for friend in friends.data:
                    excluded_ids_return.append(friend['id'])

                response['excluded_ids'] = excluded_ids_return

                if len(set_excluded_ids) == 0:

                    invite_me = Friendship_Request.objects.filter(
                        from_user__id=OuterRef('id'),
                        to_user__id=user.id
                    )

                    invite_me_created_at = Friendship_Request.objects.filter(
                        from_user__id=OuterRef('id'),
                        to_user__id=user.id
                    ).values('created_at')

                    invitations = MyUser.objects.annotate(invited_me_exists=Exists(
                        invite_me)).filter(Q(invited_me_exists=True)).annotate(is_friend=Value(False), created_at=Subquery(invite_me_created_at)).order_by('-created_at')[:5]

                    invitations = FriendshipListSerializer(
                        invitations, many=True)

                    if len(invitations.data) < 5:
                        end_pagination_invitations = True
                    else:
                        end_pagination_invitations = False

                    excluded_ids_return_invitations = []

                    for invitation in invitations.data:
                        excluded_ids_return_invitations.append(
                            invitation['id'])

                    invitation_per_sender = Friendship_Request.objects.filter(
                        to_user=user
                    ).values_list('from_user', flat=True)

                    response['invitations'] = {
                        'data': invitations.data,
                        'meta': {
                            'end_pagination': end_pagination_invitations,
                            'excluded_ids': excluded_ids_return_invitations,
                            'all_ids': invitation_per_sender,

                        },
                    }

                return Response(
                    {
                        'success': "Sukces",
                        'data': friends.data,
                        'meta': {**response},
                        "code": "8000"},
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


class LastMessagesListView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = LastMessagesListSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                user = request.user
                data = request.data
                excluded_ids = data['excluded_ids']
                excluded_ids_return = []
                response = {}

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

                sent_to_me = ActiveMessage.objects.filter(
                    recipient__id=user.id,
                    sender__id=OuterRef('id')
                )

                sent_by_me = ActiveMessage.objects.filter(
                    sender__id=user.id,
                    recipient__id=OuterRef('id')
                )

                latest_timestamp = ActiveMessage.objects.filter(
                    Q(sender__id=OuterRef('id'), recipient__id=user.id) |
                    Q(recipient__id=OuterRef('id'), sender__id=user.id)
                ).values('timestamp').order_by('-timestamp')[:1]

                is_friend_subquery = MyUser.objects.filter(
                    id=OuterRef('id'),
                    friends=user
                )

                blocked_by_target_user_subquery = MyUser.objects.filter(
                    id=OuterRef('id'),
                    blocked_users=user
                )
                block_target_user_subquery = MyUser.objects.filter(
                    id=user.id,
                    blocked_users__id=OuterRef('id')
                )

                latest_message = ActiveMessage.objects.filter(
                    Q(sender__id=OuterRef('id'), recipient__id=user.id) |
                    Q(recipient__id=OuterRef('id'), sender__id=user.id)
                ).annotate(data=JSONObject(message_id=F('message_id'), author=F('sender__id'), content=F('content'), timestamp=F('timestamp'), status=Case(When(is_delivered=True, then=Value("is_delivered")), default=Value('is_send'), output_field=CharField()))).values('data').order_by('-timestamp')[:1]

                data = MyUser.objects.annotate(
                    sent_to_me_exists=Exists(sent_to_me),
                    sent_by_me_exists=Exists(sent_by_me),
                    latest_timestamp=Subquery(latest_timestamp)
                ).filter(~Q(id__in=set_excluded_ids), Q(sent_to_me_exists=True) | Q(sent_by_me_exists=True), is_banned=False
                         ).annotate(messages=JSONObject(data=ArraySubquery(latest_message)), is_friend=Exists(is_friend_subquery), blocked_by_target_user=Exists(blocked_by_target_user_subquery), block_target_user=Exists(block_target_user_subquery)).order_by('-latest_timestamp').distinct()[:14]

                data = LastMessagesListSerializer(data, many=True)

                if len(data.data) < 14:
                    response['end_pagination'] = True
                else:
                    response['end_pagination'] = False

                for last_conversation in data.data:
                    excluded_ids_return.append(last_conversation['id'])

                response['excluded_ids'] = excluded_ids_return

                if len(set_excluded_ids) == 0:

                    messages_per_sender = ActiveMessage.objects.filter(
                        recipient__id=user.id, is_seen=False
                    ).values('sender').annotate(message_count=Count('message_id'))

                    # Tworzenie słownika z wyników
                    result_dict = {
                        item['sender']: item['message_count'] for item in messages_per_sender}

                    count_unread_messages = ActiveMessage.objects.filter(
                        recipient__id=user.id, is_seen=False
                    ).count()

                    response['new_messages'] = {
                        'count': count_unread_messages,
                        'users': result_dict
                    }

                return Response(
                    {
                        'success': "Sukces", 'data': data.data, 'meta': {**response}, "code": "8000"},
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


class UserConversationView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = UserConversationSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:

                data = request.data

                cursor_id = data['cursor_id']
                target_user_id = data['target_user_id']
                end_pagination = False

                response = {}

                if target_user_id != None:

                    if MyUser.objects.filter(id=target_user_id).exists():

                        target_user = MyUser.objects.get(id=target_user_id)

                        user = request.user

                        status_blocked_by_target_user = target_user.blocked_users.filter(
                            id=user.id).exists()

                        status_your_block_target_user = user.blocked_users.filter(
                            id=target_user.id).exists()

                        filter_cursor = {}

                        if cursor_id != None and cursor_id != "":
                            filter_cursor['message_id__lt'] = cursor_id

                        messages = ActiveMessage.objects.filter((Q(sender__id=user.id) & Q(
                            recipient__id=target_user_id)) | (Q(sender__id=target_user_id) & Q(recipient__id=user.id)), **filter_cursor).annotate(author=F('sender__id'), status=Case(When(is_delivered=True, then=Value("is_delivered")), default=Value('is_send'), output_field=CharField())).order_by('-message_id')[:7]

                        messages = UserConversationSerializer(
                            messages, many=True)

                        if len(messages.data) < 7:
                            end_pagination = True

                        if messages.data:
                            last_message_id = messages.data[-1]['message_id']
                        else:
                            last_message_id = None

                        ActiveMessage.objects.filter(sender__id=target_user_id,
                                                     recipient__id=user.id, is_seen=False).update(is_seen=True)

                        response['data'] = messages.data
                        response['end_pagination'] = end_pagination
                        response['cursor_id'] = last_message_id

                        return Response(
                            {
                                'success': 'Sukces', 'data': response, 'meta': {'status_blocked_by_target_user': status_blocked_by_target_user, 'status_your_block_target_user': status_your_block_target_user}, "code": "3000"},
                            status=status.HTTP_200_OK
                        )
                    else:
                        return Response(
                            {'detail': 'Nie ma takiego użytkownika',
                                "code": "1301"},
                            status=222
                        )

                else:
                    return Response(
                        {'detail': 'Musisz podać ID użytkownika',
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


class WebsocketClearCookiesView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = PasswordChangeSerializer

    def get(self, request):
        try:
            response = remove_cookies(status.HTTP_200_OK)
            response.data = {
                "success": "Ciasteczka zostały oczyszczone", "code": "1926"}
            return response
        except Exception as e:
            print(e)
            print(f"Typ błędu: {type(e).__name__}")
            print(f"Kod błędu: {e.args[0]}")
            print("Traceback:")
            import traceback
            traceback.print_tb(e.__traceback__)
            return Response(
                {'detail': 'Coś poszło nie tak z próbą załadowania użytkownika', "code": "945"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class InvitationsListView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = FriendshipListSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                user = request.user
                data = request.data
                excluded_ids = data['excluded_ids']
                excluded_ids_return = []
                response = {}

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

                invite_me = Friendship_Request.objects.filter(
                    from_user__id=OuterRef('id'),
                    to_user__id=user.id
                )

                invite_me_created_at = Friendship_Request.objects.filter(
                    from_user__id=OuterRef('id'),
                    to_user__id=user.id
                ).values('created_at')

                invitations = MyUser.objects.annotate(invited_me_exists=Exists(
                    invite_me)).filter(~Q(id__in=set_excluded_ids), Q(invited_me_exists=True)).annotate(is_friend=Value(False), created_at=Subquery(invite_me_created_at)).order_by('-created_at')[:5]

                invitations = FriendshipListSerializer(invitations, many=True)

                if len(invitations.data) < 5:
                    response['end_pagination'] = True
                else:
                    response['end_pagination'] = False

                for invitation in invitations.data:
                    excluded_ids_return.append(invitation['id'])

                response['excluded_ids'] = excluded_ids_return

                return Response(
                    {
                        'success': "Sukces",
                        'data': invitations.data,
                        'meta': {**response},
                        "code": "8000"},
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


class FindProfileByIdView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = FindProfileByIdSerializer

    def get(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                target_id = request.GET.get('id', None)

                if target_id != None:

                    if MyUser.objects.filter(id=target_id).exists():

                        target_user = MyUser.objects.get(id=target_id)

                        target_user = FindProfileByIdSerializer(target_user)

                        return Response(
                            {
                                'success': 'Pobrano użytkownika', 'data': target_user.data, "code": "9100"},
                            status=status.HTTP_200_OK
                        )
                    else:
                        return Response(
                            {'detail': 'Nie znaleziono takiego użytkownika',
                                "code": "9100"},
                            status=222
                        )
                else:
                    return Response(
                        {'detail': 'Nie został podany ID usera',
                         "code": "9100"},
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


class RefreshInvitationsAndNewMessagesIdsView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = FindProfileByIdSerializer

    def get(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                user = request.user

                ids_invitations = Friendship_Request.objects.filter(
                    to_user=user
                ).values_list('from_user', flat=True)

                count_unread_messages = ActiveMessage.objects.filter(
                    recipient=user, is_seen=False
                ).count()

                messages_per_sender = ActiveMessage.objects.filter(
                    recipient__id=user.id, is_seen=False
                ).values('sender').annotate(message_count=Count('message_id'))

                result_dict = {
                    item['sender']: item['message_count'] for item in messages_per_sender}

                response = {
                    'invitations': {
                        'all_ids': ids_invitations
                    },
                    'new_messages': {
                        'count': count_unread_messages,
                        'users': result_dict,
                    },
                }

                return Response(
                    {
                        'success': 'Pobrano użytkownika', 'data': {**response}, "code": "9100"},
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


class NotificationsListView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = NotificationsListSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            
            if response_verify is not None:
                return response_verify
            else:

                user = request.user
                data = request.data
                cursor_date = data['cursor_date']
                queryset_objects = {}
                queryset_response = []
                ids = {
                    'MyUser': [],
                    'IPAddress': [],
                    'Event': [],
                    'CommentEvent': [],
                    'Badge': [],
                    'Ticket': [],
                    'Order': [],
                    'AwaitingsTicketsRefund': [],
                    'GatewayPaycheck': [],
                }
                deleted_models_schemation = {
                        'MyUser': 0,
                        'IPAddress': 1,
                        'Event': 2,
                        'CommentEvent': 3,
                        'Badge': 4,
                        'Ticket': 5,
                        'Order': 6,
                        'AwaitingsTicketsRefund': 7,
                        'GatewayPaycheck': 8,
                    }
                
                response_meta = {}
                index = 0

                # ZASZYFROWANY FORMAT POWIADOMIEN DLA USERA
                notifications_array = eval(user.user_notifications.notifications_array)
                
                
                # POBIERAMY WSZYSTKIE USUNIETE MODELE DO KTORYCH NAWIAZUJĄ POWIADOMIENIA, ABY ODFILTROWAC Z TYCH MODELI KTORYCH NIE MA W BAZIE
                # POWIADOMIENIA SAME W SOBIE SĄ CO 24H USUWANE Z TAKICH MODELI
                deleted_models_schemas = DeleteModel.objects.in_bulk()


                # POBIERAMY TE SCHEMATY POWIADOMIEŃ, KTÓRE ISTNIEJĄ W NASZEJ LIŚCIE
                notifications_fetch_ids = set(notification[0] for notification in notifications_array)
                notifications_schemas = Notification.objects.in_bulk(notifications_fetch_ids)




                # USTALENIE POZYCJI CURSORA W PAGINACJI

                if cursor_date != "":
                    try:
                        date_time_obj = datetime.datetime.strptime(cursor_date, "%Y-%m-%dT%H:%M:%S.%f")


                        for i, notification in enumerate(notifications_array):
                            created_at = datetime.datetime.strptime(notification[2], "%Y-%m-%dT%H:%M:%S.%f")
                            if created_at >= date_time_obj:
                                index = i + 1
                            else:
                                break

                    except ValueError as e:
                        print(e)
                        print(f"Typ błędu: {type(e).__name__}")
                        print(f"Kod błędu: {e.args[0]}")
                        print("Traceback:")
                        import traceback
                        traceback.print_tb(e.__traceback__)

                        return Response(
                            {'detail': 'Przesyłana wartość w "cursor_date" musi mieć format DateTime np "2023-11-30T01:57:37.645666", lub pozostaw ją pustą.',
                                "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                    
                else:
                    count_new_messages = 0

                    for notification in notifications_array:

                        notification_schema_id, content_id, _ , viewed = notification

                        notification_schema = notifications_schemas.get(notification_schema_id)
                        deleted_model_schema = deleted_models_schemas.get(deleted_models_schemation[notification_schema.content_type])

                        if viewed == 0 and content_id not in eval(deleted_model_schema.ids_array):
                            count_new_messages += 1

                    response_meta['new_count'] = count_new_messages


                # TWORZYMY LISTE ID OBIEKTÓW NIEZBĘDNYCH, DO WYKONANIA NASZYCH POWIADOMIEŃ, ABY W KOLEJNYM ETAPIE POBRAC TYLKO JE
                


                ids_loop_count = 0
                for data in notifications_array[index:]:

                    notification_schema_id, content_id, _ , _ = data

                    notification_schema = notifications_schemas.get(notification_schema_id)
                    deleted_model_schema = deleted_models_schemas.get(deleted_models_schemation[notification_schema.content_type])


                    if content_id not in eval(deleted_model_schema.ids_array):
                        ids_loop_count += 1  
                        if content_id not in ids[notification_schema.content_type]:
                            ids[notification_schema.content_type].append(content_id)

                    if ids_loop_count >= 14:
                        break


                # WYKONUJEMY QUERYSET DLA OBIEKTÓW, KTÓRE SĄ NAM POTRZEBNE DO WYKONANIA POWIADOMIEŃ I ZAPISUJEMY W "queryset_objects", ORAZ DLA "EVENT" I "COMMENTEVENT" PRZYPISUJEMY WARTOSCI ZWIAZANE Z PRZEKIEROWYWANIEM I POPRAWNYM WYSWIETLANIEM WE FRONCIE
                
                
                for key in ids:
                    if len(ids[key]) > 0:

                        queryset_objects[key] = apps.get_model(
                            "front", key).objects.in_bulk(ids[key])
                        
                        output = append_extra_data_notification(queryset_objects, key, ids[key], user.id, True)



                # DLA KAZDEGO Z POWIADOMIEN BUDUJEMY ODPOWIEDZ W POSTACI JSON

                queryset_loop_count = 0
                
                for notification in notifications_array[index:]:
                    notification_schema_id, content_id, created_at, _ = notification


                    notification_schema = notifications_schemas.get(notification_schema_id)
                    deleted_model_schema = deleted_models_schemas.get(deleted_models_schemation[notification_schema.content_type])


                    if content_id not in eval(deleted_model_schema.ids_array):

                        queryset_loop_count += 1

                        queryset_response.append({
                            'created_at': created_at,
                            'text': notification_schema.text,
                            'object_type': notification_schema.content_type,
                            'object': notification_schema.get_object_data(output[notification_schema.content_type][content_id])
                        })
                    if queryset_loop_count >= 14:
                        break

                if len(queryset_response) < 14:
                    response_meta['end_pagination'] = True
                else:
                    response_meta['end_pagination'] = False


                if len(queryset_response) > 0:
                    response_meta['cursor_date'] = queryset_response[-1]['created_at']
                else:
                    response_meta['cursor_date'] = None

                
                return Response(
                    {
                        'success': "Sukces",
                        'cursor_date': cursor_date,
                        'data': queryset_response,
                        'meta': {**response_meta},
                        "code": "8000"},
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
