from rest_framework.views import APIView
from rest_framework import permissions, status
from rest_framework.response import Response
from ..serializers import FindFriendsSerializer, FriendsActionSerializer, FriendsRequestReactionSerializer, FriendsRemoveSerializer
from ..models import MyUser, Event, Friendship_Request
from .functions import token_verify, send_websocket_notification
import ast
from django.db.models import Value, CharField, OuterRef, Func, F, Q, Exists, Subquery, Case, When
from django.db.models.functions import JSONObject
from django.contrib.postgres.expressions import ArraySubquery
from django.utils import timezone

class FindFriendsView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = FindFriendsSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                data = request.data
                target_username = data['target_username']
                excluded_ids = data['excluded_ids']

                if excluded_ids != "" and not isinstance(excluded_ids, list):

                    try:
                        literal_eval_excluded_ids = ast.literal_eval(
                            excluded_ids)

                        set_excluded_ids = set(literal_eval_excluded_ids)

                    except:

                        return Response(
                            {'detail': 'Przesyłana wartość w "excluded_ids" musi mieć format list z liczbami określającymi ID użytkowników do pominięcia, lub pozostaw pustą wartość.',
                                "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                else:
                    set_excluded_ids = set(excluded_ids)

                user = request.user

                time_now = timezone.now()

                subquery_together_friends = MyUser.objects.filter(pk=OuterRef(
                    'pk')).filter(friends__in=user.friends.all()).annotate(data=JSONObject(id=F('friends__id'),username=F('friends__username'), image_thumbnail=F('friends__image_thumbnail'))).values('data')

                subquery_events_count = Event.objects.filter(
                    user__id=OuterRef('id')).annotate(count=Func(F('id'), function='Count')).values('count')

                subquery_events_actual_count = Event.objects.filter(
                    user__id=OuterRef('id'), event_date__gte=time_now, verificated="verificated").annotate(count=Func(F('id'), function='Count')).values('count')

                subquery_friends_count = MyUser.objects.filter(
                    friends__id=OuterRef('id')).annotate(count=Func(F('id'), function='Count')).values('count')

                #################

                subquery_is_friend = MyUser.objects.filter(
                    friends__pk=OuterRef('pk'), username=user.username)

                subquery_get_request = Friendship_Request.objects.filter(
                    from_user__pk=OuterRef('pk'), to_user=user)

                subquery_send_request = Friendship_Request.objects.filter(
                    to_user__pk=OuterRef('pk'), from_user=user)

                subquery_get_blocked = MyUser.objects.filter(
                    pk=OuterRef('pk'), blocked_users=user)

                #############

                not_admin_annotate = {}
                if not user.is_admin:
                    not_admin_annotate["blocked_users"] = user

                target_users = MyUser.objects.select_related('city').filter(~Q(id__in=set_excluded_ids), username__icontains=target_username, is_verificated=True).exclude(username=user.username).exclude(blocked_by=user).exclude(**not_admin_annotate).annotate(province=F("city__county__province__name"), is_friend=Case(When(Exists(subquery_get_blocked),
                                                                                                                                                                                                                                                                                                                                   then=Value("a) Get_block")), When(Exists(subquery_is_friend), then=Value('a) True')), When(Exists(subquery_send_request), then=Value("b) Send_request")), When(
                    Exists(subquery_get_request), then=Value("c) Get_request")), default=Value('d) False'), output_field=CharField()), together_friends=ArraySubquery(subquery_together_friends), events_count=Subquery(subquery_events_count), events_actual_count=Subquery(subquery_events_actual_count), friends_count=Subquery(subquery_friends_count)).order_by("is_friend")[:12]

                target_count = MyUser.objects.select_related('city').filter(
                    username__icontains=target_username, is_verificated=True).exclude(username=user.username).exclude(blocked_by=user).exclude(**not_admin_annotate).count()

                target_users = FindFriendsSerializer(
                    target_users, many=True)

                return Response(
                    {
                        'success': 'Pobrano użytkowników', 'count': target_count, 'data': target_users.data, "code": "7667"},
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




class FriendRequestView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = FriendsActionSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                data = request.data
                invite_user_id = data['id_target']
                type_action = data['type']
                user = request.user

                if invite_user_id != "":
                    if type_action == "Send" or type_action == "Cancel":

                        if MyUser.objects.filter(id=invite_user_id).exists():
                            invite_user = MyUser.objects.get(id=invite_user_id)

                            if not invite_user.blocked_users.filter(id=user.id).exists():

                                if not user.blocked_users.filter(id=invite_user.id).exists():

                                    if user.username != invite_user.username:
                                        if not invite_user.friends.filter(id=user.id).exists() or not user.friends.filter(id=invite_user.id).exists():
                                            if not Friendship_Request.objects.filter(from_user=invite_user, to_user=user).exists():

                                                if type_action == "Send":
                                                    if not Friendship_Request.objects.filter(from_user=user, to_user=invite_user).exists():
                                                        Friendship_Request.objects.create(
                                                            from_user=user, to_user=invite_user)
                                                        return Response(
                                                            {'success': 'Sukces', 'type': 'invite',
                                                                "code": "1100"},
                                                            status=status.HTTP_200_OK)
                                                    else:

                                                        return Response(
                                                            {'detail': 'Ten użytkownik jest już przez Ciebie zaproszony', "react_target_user": 'Someone_invited_firstly', "target_user": {"id": invite_user.id, "username": invite_user.username},
                                                                "code": "2072"},
                                                            status=223
                                                        )

                                                else:

                                                    if Friendship_Request.objects.filter(from_user=user, to_user=invite_user).exists():
                                                        Friendship_Request.objects.filter(
                                                            from_user=user, to_user=invite_user).delete()
                                                        return Response(
                                                            {'success': 'Sukces', 'type': 'back',
                                                                "code": "1101"},
                                                            status=status.HTTP_200_OK)
                                                    else:

                                                        # Próbujesz cofnąć zaproszenie, którego nie ma. Możliwe, że drugi użytkownik odpowiedział już negatywnie na Twoją prośbę.

                                                        return Response(
                                                            {'detail': 'Błąd w cofaniu zaproszenia.', "react_target_user": "Declined", "target_user": {"id": invite_user.id, "username": invite_user.username},
                                                                "code": "1660"},
                                                            status=223
                                                        )

                                            else:
                                                # Już wcześniej otrzymałeś zaproszenie od tego użytkownika

                                                return Response(
                                                    {'detail': 'Błąd w wysyłaniu zaproszenia', "react_target_user": 'Invited_you_first', "target_user": {"id": invite_user.id, "username": invite_user.username},
                                                        "code": "1661"},
                                                    status=223
                                                )
                                        else:
                                            # Nie możesz zaprosić użytkownika, którego masz już w znajomych
                                            return Response(
                                                {'detail': 'Błąd w cofaniu zaproszenia', "react_target_user": "Accepted", "user": {"username": user.username, "image_thumbnail": user.image_thumbnail.name}, "target_user": {"id": invite_user.id, "username": invite_user.username, "image_thumbnail": invite_user.image_thumbnail.name},
                                                    "code": "1662"},
                                                status=223
                                            )

                                    else:
                                        return Response(
                                            {'detail': 'Nie możesz wysłać zaproszenia do samego siebie',
                                                "code": "9011"},
                                            status=status.HTTP_400_BAD_REQUEST
                                        )
                                else:
                                    return Response(
                                        {'detail': 'Użytkownik jest zablokowany', "react_target_user": "Blocked_by_you", "target_user": {"id": invite_user.id, "username": invite_user.username}, "is_admin": user.is_admin,
                                            "code": "2071"},
                                        status=223
                                    )
                            else:
                                return Response(
                                    {'detail': 'Zostałeś zablokowany', "react_target_user": "Blocked_you", "target_user": {"id": invite_user.id, "username": invite_user.username}, "is_admin": user.is_admin,
                                        "code": "1663"},
                                    status=223
                                )

                        else:
                            return Response(
                                {'detail': 'Nie znaleziono takiego użytkownika',
                                    "code": "1301"},
                                status=222
                            )
                    else:
                        return Response(
                            {'detail': 'Wykryto złą akcję. Możesz skorzystać z "Send" oraz "Cancel"',
                                "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                else:
                    return Response(
                        {'detail': 'Nie możesz zostawić pustego miejsca w miejscu podania ID usera',
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


class FriendRequestReactionView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = FriendsRequestReactionSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                data = request.data
                request_user_id = data['id_target']
                type = data['type']
                user = request.user

                if type == "accept" or type == "reject":
                    if MyUser.objects.filter(id=request_user_id).exists():
                        accept_user = MyUser.objects.get(id=request_user_id)
                        if user.username != accept_user.username:
                            if Friendship_Request.objects.filter(from_user=accept_user, to_user=user).exists():
                                if type == "accept":
                                    user.friends.add(accept_user)
                                    accept_user.friends.add(user)
                                    Friendship_Request.objects.filter(
                                        from_user=accept_user, to_user=user).delete()
                                    
                                    send_websocket_notification([accept_user], 0, user, timezone.now(), True)

                                    return Response(
                                        {'success': 'Sukces',
                                            "code": "1102", "type_reaction": type, "user": {"id": user.id, "username": user.username, "image_thumbnail": user.image_thumbnail.name}, "target_user": {"id": accept_user.id, "username": accept_user.username, "image_thumbnail": accept_user.image_thumbnail.name}},
                                        status=status.HTTP_200_OK)
                                elif type == "reject":
                                    Friendship_Request.objects.filter(
                                        from_user=accept_user, to_user=user).delete()
                                    return Response(
                                        {'success': 'Sukces',
                                            "code": "1103", "type_reaction": type, "user": {"id": user.id, "username": user.username, "image_thumbnail": user.image_thumbnail.name}},
                                        status=status.HTTP_200_OK)

                            else:

                                user_is_blocked = accept_user.blocked_users.filter(
                                    id=user.id).exists()

                                target_blocked_by_us = user.blocked_users.filter(
                                    id=accept_user.id).exists()

                                if user_is_blocked:

                                    user_is_friend = False

                                    details = "Zostałeś zablokowany"
                                    code = "1663"

                                elif target_blocked_by_us:
                                    user_is_friend = False

                                    details = "Ten użytkownik jest przez Ciebie zablokowany"
                                    code = "2071"

                                elif accept_user.friends.filter(id=user.id).exists():

                                    user_is_friend = True

                                    # "Nie możesz zareagować na zaproszenie, którego nie ma"
                                    details = "Użytkownik jest już twoim znajomym"
                                    code = "1662"

                                else:
                                    user_is_friend = False

                                    details = "Błąd podczas odpowiedzi na zaproszenie"
                                    code = "1664"

                                return Response(
                                    {'detail': details, 'user_is_blocked': user_is_blocked, 'user_is_friend': user_is_friend, 'target_blocked_by_us': target_blocked_by_us, "target_user": {"id": accept_user.id, "username": accept_user.username, "image_thumbnail": accept_user.image_thumbnail.name}, "is_admin": user.is_admin, "user": {"id": user.id, "username": user.username, "image_thumbnail": user.image_thumbnail.name},
                                     "code": code},
                                    status=223
                                )

                        else:
                            return Response(
                                {'detail': 'Nie możesz potwierdzić zaproszenia od samego siebie',
                                    "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )

                    else:
                        return Response(
                            {'detail': 'Nie znaleziono takiego użytkownika',
                                "code": "1301"},
                            status=222
                        )

                else:
                    return Response(
                        {'detail': 'Zły stan. Może być albo "accept", albo "reject"',
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


class FriendRemoveView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = FriendsRemoveSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                data = request.data

                remove_user_id = data['id_target']
                user = request.user
                if MyUser.objects.filter(id=remove_user_id).exists():
                    remove_user = MyUser.objects.get(id=remove_user_id)
                    if user.username != remove_user.username:
                        if remove_user.friends.filter(id=user.id).exists() or user.friends.filter(id=remove_user.id).exists():
                            remove_user.friends.remove(user)
                            user.friends.remove(remove_user)

                            return Response(
                                {'success': 'Sukces',
                                    "code": "1104", "remove_user": {"id": remove_user.id, "username": remove_user.username}, "user": user.id},

                                status=status.HTTP_200_OK)
                        else:

                            if remove_user.blocked_users.filter(id=user.id).exists():
                                user_is_blocked = True

                                detail = "Zostałeś zablokowany"
                                code = "1663"
                            else:
                                user_is_blocked = False
                                # "Nie możesz usunąć użytkownika z listy znajomych, jeśli na niej się nie znajduje."
                                detail = "Błąd podczas usuwania znajomego"
                                code = "1665"

                            return Response(
                                {'detail': detail, 'user_is_blocked': user_is_blocked, "remove_user": {"id": remove_user.id, "username": remove_user.username}, "user": user.id, "is_admin": user.is_admin,
                                    "code": code},
                                status=223
                            )

                    else:
                        return Response(
                            {'detail': 'Nie możesz usunąć samego siebie',
                                "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )

                else:
                    return Response(
                        {'detail': 'Nie znaleziono takiego użytkownika',
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
