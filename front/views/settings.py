from rest_framework.views import APIView
from rest_framework import permissions, status
from rest_framework.response import Response
from .functions import token_verify, email_verification, remove_cookies
from ..custom_refresh_token import CustomRefreshToken
from ..models import MyUser, City, IPAddressValidator, Friendship_Request, CustomOutstandingToken, CustomBlacklistedToken, GmailUser, FacebookUser, CodeRegistration, ChangeEmailWaiting, Province, Badge, OrderedTicket, Event, GatewayPaycheck, AwaitingsTicketsRefund, Ticket, Paycheck
from ..serializers import UserSerializer, CheckUserLocationSerializer, UserLoginLocationsSerializer, UserBlockUsersSerializer, LogoutFromDevicesSerializer, LoginGoogleSerializer, LoginFacebookSerializer, PasswordChangeSerializer, EmailChangeSerializer, EmailChangeConfirmSerializer, UserEditSerializer, BadgesViaSettingsSerializer, BadgeDeleteSerializer, BankNumberViewSerializer
from django.db.models import Value, CharField, OuterRef, F, Q, Exists, Case, When, BooleanField, Subquery
from django.db.models.functions import JSONObject
from django.contrib.gis.geos import Point
from django.contrib.gis.db.models.functions import Distance
from django.contrib.auth import authenticate
from django.template.loader import render_to_string
from django.conf import settings
from django.utils import timezone
from django.shortcuts import redirect
from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
from django.core.mail import EmailMessage
import ast
import requests
import re
from ips_config import BACKEND_IP



class ChangeUserLocationView(APIView):
    permission_classes = (permissions.AllowAny, )

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                data = request.data

                if request.user.is_authenticated:
                    user = MyUser.objects.annotate(
                        gmail=JSONObject(social_id=F('gmailuser__social_id'), first_name=F('gmailuser__first_name'), last_name=F('gmailuser__last_name'), image=F('gmailuser__image')), facebook=JSONObject(social_id=F('facebookuser__social_id'), first_name=F('facebookuser__first_name'), last_name=F('facebookuser__last_name'), image=F('facebookuser__image'))).get(id=request.user.id)

                    if "province" and "city" in data["location"]:
                        user.city = City.objects.get(
                            name=data["location"]["city"], county__province__name=data["location"]["province"])

                    elif "id" and "name" in data["location"]:
                        user.city = City.objects.get(id=data["location"]["id"])

                    user.save(generate_thumbnail=False)

                    response = Response(status=status.HTTP_200_OK)

                    response.set_cookie(
                        key="pkl_homescreen",
                        value="",
                        expires=0,
                        max_age=0,
                        secure=True,
                        httponly=False,
                        samesite="None"
                    )

                    response.set_cookie(
                        key="pkr_homescreen",
                        value="",
                        expires=0,
                        max_age=0,
                        secure=True,
                        httponly=False,
                        samesite="None"
                    )

                    response.set_cookie(
                        key="pkp_homescreen",
                        value="",
                        expires=0,
                        max_age=0,
                        secure=True,
                        httponly=False,
                        samesite="None"
                    )
                    response.data = {
                        'user': UserSerializer(user).data, 'success': 'Zmiana miasta', 'code': '950'}

                    return response
                else:
                    return Response(
                        {'detail': 'Brak zalogowanego użytkownika', "code": "7665"},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR
                    )

        except Exception as e:
            print(e)
            return Response(
                {'detail': 'Coś poszło nie tak z próbą pobrania danych', "code": "1165"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class ChangeUserDistanceView(APIView):
    permission_classes = (permissions.AllowAny, )

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                data = request.data

                if request.user.is_authenticated:
                    user = MyUser.objects.annotate(
                        gmail=JSONObject(social_id=F('gmailuser__social_id'), first_name=F('gmailuser__first_name'), last_name=F('gmailuser__last_name'), image=F('gmailuser__image')), facebook=JSONObject(social_id=F('facebookuser__social_id'), first_name=F('facebookuser__first_name'), last_name=F('facebookuser__last_name'), image=F('facebookuser__image'))).get(id=request.user.id)

                    distance = data.get('distance', None)

                    if distance != None:
                        if str(distance).isdigit():
                            if distance >= 2 and distance <= 400:

                                user.distance = distance
                                user.save(generate_thumbnail=False)

                                return Response(
                                    {'success': "Zmiana dystansu",
                                     'user': UserSerializer(user).data, 'code': "951"},
                                    status=status.HTTP_200_OK
                                )
                            else:
                                return Response(
                                    {'detail': 'Dystans nie mieści się w przedziale 2-400',
                                        "code": "7665"},
                                    status=status.HTTP_400_BAD_REQUEST
                                )
                        else:
                            return Response(
                                {'detail': 'Dystans nie jest liczbą', "code": "7665"},
                                status=status.HTTP_400_BAD_REQUEST
                            )

                    else:
                        return Response(
                            {'detail': 'Nie podano nowego dystansu', "code": "7665"},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                else:
                    return Response(
                        {'detail': 'Brak zalogowanego użytkownika', "code": "7665"},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR
                    )

        except Exception as e:
            print(e)
            return Response(
                {'detail': 'Coś poszło nie tak z próbą pobrania danych', "code": "1165"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class CheckUserLocationView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = CheckUserLocationSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify

            else:
                data = request.data
                longitude = data.get('longitude', None)
                latitude = data.get('latitude', None)

                if request.user.is_authenticated:

                    if longitude != None:
                        if latitude != None:

                            closest_city = City.objects.annotate(distance=Distance(
                                'geo_location', Point(longitude, latitude, srid=4326))).order_by('distance').first()

                            return Response(
                                {'success': "Sprawdzono lokalizację",
                                    'city': {'name': closest_city.name, 'id': closest_city.id}, 'code': "9600"},
                                status=status.HTTP_200_OK
                            )
                            
                        else:
                            return Response(
                                {'detail': 'Szerokość geograficzna nie została podana',
                                    "code": "7665"},
                                status=status.HTTP_400_BAD_REQUEST
                            )

                    else:
                        return Response(
                            {'detail': 'Długość geograficzna nie została podana',
                                "code": "7665"},
                            status=status.HTTP_400_BAD_REQUEST
                        )

                else:
                    return Response(
                        {'detail': 'Brak zalogowanego użytkownika', "code": "7665"},
                        status=status.HTTP_400_BAD_REQUEST
                    )

        except Exception as e:
            print(e)
            return Response(
                {'detail': 'Coś poszło nie tak z próbą pobrania danych', "code": "1165"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class UserLoginLocationsView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = UserLoginLocationsSerializer

    def get(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:

                user = request.user
                ip_address = request.META.get('REMOTE_ADDR')

                ip_validators_current = IPAddressValidator.objects.select_related(
                    'ip_address').filter(ip_address__ip_address=ip_address, user=user).annotate(city=F('last_login_city__name'), county=F('last_login_city__county__name'), province=F('last_login_city__county__province__name')).first()

                ip_validators_other = IPAddressValidator.objects.select_related(
                    'ip_address').filter(~Q(ip_address__ip_address=ip_address), user=user, is_verificated=True).annotate(city=F('last_login_city__name'), county=F('last_login_city__county__name'), province=F('last_login_city__county__province__name')).order_by('-last_login_time')

                ip_validators_current = UserLoginLocationsSerializer(
                    ip_validators_current)

                ip_validators_other = UserLoginLocationsSerializer(
                    ip_validators_other, many=True)

                return Response(
                    {'success': 'Pobrano wydarzenia', 'ip_validators': {'current': ip_validators_current.data, 'other': ip_validators_other.data},
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


class UserBlockUsersView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = UserBlockUsersSerializer

    def get(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:

                user = request.user

                blocked_users = user.blocked_users.all().order_by('username')

                blocked_users = UserBlockUsersSerializer(
                    blocked_users, many=True)

                return Response(
                    {'success': 'Pobrano wydarzenia', 'blocked_users': blocked_users.data,
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

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                data = request.data
                id_target = data['id_target']
                user = request.user

                if MyUser.objects.filter(id=id_target).exists():

                    target_user = MyUser.objects.get(id=id_target)

                    if user.username != target_user.username:

                        if target_user.blocked_users.filter(id=user.id).exists():

                            target_blocked_user = True

                        else:
                            target_blocked_user = False

                        if not user.blocked_users.filter(id=target_user.id).exists():

                            if target_user.friends.filter(id=user.id).exists() or user.friends.filter(id=target_user.id).exists():
                                target_user.friends.remove(user)
                                user.friends.remove(target_user)

                            friendship_request_to_delete = Friendship_Request.objects.filter(Q(from_user=target_user, to_user=user) |
                                                                                             Q(from_user=user, to_user=target_user))

                            friendship_request_to_delete.delete()

                            user.blocked_users.add(target_user)

                            return Response(
                                {'success': 'Użytkownik został zablokowany', 'request_user_id': user.id, 'target_blocked_user': target_blocked_user,
                                    "code": "1652"},
                                status=status.HTTP_200_OK
                            )
                        else:

                            return Response(
                                {'detail': 'Ten użytkownik już jest przez Ciebie zablokowany.',  'target_blocked_user': target_blocked_user,
                                    "code": "2071"},
                                status=223
                            )
                    else:
                        return Response(
                            {'detail': 'Nie możesz zablokować samego siebie.',
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

    def delete(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                data = request.data
                id_target = data['id_target']
                user = request.user

                if MyUser.objects.filter(id=id_target).exists():

                    target_user = MyUser.objects.get(id=id_target)

                    if user.username != target_user.username:

                        if target_user.blocked_users.filter(id=user.id).exists():

                            target_blocked_user = True
                            if user.is_admin:
                                code = "1649"
                            else:
                                code = "1650"

                            is_friend = "a) Get_block"
                            extra_data = None
                        else:

                            #################

                            subquery_is_friend = MyUser.objects.filter(
                                friends__pk=OuterRef('pk'), username=user.username)

                            subquery_get_request = Friendship_Request.objects.filter(
                                from_user__pk=OuterRef('pk'), to_user=user)

                            subquery_send_request = Friendship_Request.objects.filter(
                                to_user__pk=OuterRef('pk'), from_user=user)

                            #############

                            is_friend = MyUser.objects.filter(id=id_target).annotate(is_friend=Case(When(Exists(subquery_is_friend), then=Value('a) True')), When(Exists(subquery_send_request), then=Value("b) Send_request")), When(
                                Exists(subquery_get_request), then=Value("c) Get_request")), default=Value('d) False'), output_field=CharField())).values_list('is_friend', flat=True)[0]

                            if is_friend == 'a) True':
                                extra_data = {
                                    'id': user.id,
                                    'username': user.username,
                                    'image_thumbnail': user.image_thumbnail.name

                                }

                            else:
                                extra_data = None

                            # TUTAJ ZAPYTANIE DO BAZY JAKI JEST STAN NASZEGO IS_FRIEND

                            target_blocked_user = False
                            code = "1651"

                        if user.blocked_users.filter(id=target_user.id).exists():

                            user.blocked_users.remove(target_user)

                            return Response(
                                {'success': 'Użytkownik został odblokowany', 'target_blocked_user': target_blocked_user, "is_admin": user.is_admin,
                                    "code": code},
                                status=status.HTTP_200_OK
                            )
                        else:
                            return Response(
                                {'detail': 'Ten użytkownik nie jest przez Ciebie zablokowany.', 'target_blocked_user': target_blocked_user, 'is_friend': {'status': is_friend, 'self_user': extra_data},
                                    "code": "2070"},
                                status=223
                            )
                    else:
                        return Response(
                            {'detail': 'Nie możesz odblokować samego siebie.',
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


class LogoutFromDevicesView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = LogoutFromDevicesSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                data = request.data
                devices_id_list = data['devices_id_list']
                user = request.user
                if devices_id_list != "":
                    if not isinstance(devices_id_list, list):
                        try:
                            literal_eval_devices_id_list = ast.literal_eval(
                                devices_id_list)

                            set_devices_id_list = set(
                                literal_eval_devices_id_list)
                        except:
                            return Response(
                                {'detail': 'Przesyłana wartość w "devices_id_list" musi mieć format list z liczbami określającymi ID kodów aktywacyjnych do rezerwacji.',
                                    "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )
                    else:
                        set_devices_id_list = set(devices_id_list)

                    if IPAddressValidator.objects.filter(id__in=set_devices_id_list).exists():

                        ip_validators = IPAddressValidator.objects.filter(
                            id__in=set_devices_id_list)

                        ip_address = request.META.get('REMOTE_ADDR')

                        if not any(ip_validator.ip_address.ip_address == ip_address for ip_validator in ip_validators):

                            if ip_validators.count() == len(set_devices_id_list):

                                if all(ip_validator.user == user for ip_validator in ip_validators):

                                    ip_validators.update(is_verificated=False)

                                    refresh_token = request.COOKIES.get(
                                        settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'])

                                    today = timezone.now()

                                    tokens_to_blacklist = CustomOutstandingToken.objects.select_related('user').filter(
                                        ~Q(token=refresh_token), ip_validator__in=ip_validators, expires_at__gt=today, customblacklistedtoken__isnull=True)
                    

                                    for active_token in tokens_to_blacklist:

                                        token = CustomRefreshToken(
                                            active_token.token)
                                        token.blacklist()

                                    return Response(
                                        {'success': 'Sukces', "code": "1600"},
                                        status=status.HTTP_200_OK
                                    )

                                else:
                                    return Response(
                                        {'detail': 'Przekazujesz IP Validator, który nie należy do Ciebie.',
                                            "code": "9011"},
                                        status=status.HTTP_400_BAD_REQUEST
                                    )
                            else:
                                retrieved_ids = {
                                    validator.id for validator in ip_validators}
                                missing_ids = set_devices_id_list - retrieved_ids

                                return Response(
                                    {'detail': 'Przynajmniej jeden z twoich przekazywanych id IP Validatorów nie istnieje.', 'data': missing_ids,
                                        "code": "1601"},
                                    status=222
                                )
                        else:
                            return Response(
                                {'detail': 'Jedno z twoich urządzeń, z których chcesz się wylogować jest te aktualne, z którego teraz korzystasz. Możesz wylogowywać się jedynie z innych urządzeń.',
                                    "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )
                    else:
                        return Response(
                            {'detail': 'Żaden z twoich przekazywanych id IP Validatorów nie istnieje.', 'data': set_devices_id_list,
                                "code": "1601"},
                            status=222
                        )
                else:
                    return Response(
                        {'detail': 'Musisz podać przynajmniej listę jednoelementową z ID Ip Validatorów.',
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


class LinkGoogleView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = LoginGoogleSerializer

    def delete(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                user = request.user

                if GmailUser.objects.filter(user=user).exists():

                    google_profile = GmailUser.objects.get(user=user)

                    google_profile.delete()

                    return Response(
                        {'success': 'Sukces',
                            "code": "1700"},
                        status=status.HTTP_200_OK
                    )
                else:
                    return Response(
                        {'detail': 'Twoje konto nie jest powiązane z żadnym kontem Google',
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

    def get(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                data = request.GET
                code = data['code']

                user = request.user

                if not GmailUser.objects.filter(user=user).exists():

                    request_data = {
                        'code': code,
                        'client_id': '298963308775-ao9rr2jc1hobam57co8qpvkpkvjierpb.apps.googleusercontent.com',
                        'client_secret': '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',
                        'redirect_uri': f'{BACKEND_IP}/api/account/link/google',
                        'grant_type': 'authorization_code'
                    }

                    res = requests.post(
                        "https://oauth2.googleapis.com/token", data=request_data)

                    # 118143322891147953844

                    if res.ok:

                        access_token = res.json()['access_token']
                        res_user = requests.get(
                            "https://www.googleapis.com/oauth2/v3/userinfo",
                            params={'access_token': access_token}
                        )

                        if res_user.ok:

                            res_data = res_user.json()

                            if not GmailUser.objects.filter(social_id=res_data['sub']).exists():

                                image_response = requests.get(
                                    res_data['picture'])
                                file_name = 'gmail_images/{}.jpg'.format(
                                    res_data['sub'])
                                file_path = default_storage.save(
                                    file_name, ContentFile(image_response.content))

                                GmailUser.objects.create(
                                    user=user, social_id=res_data['sub'], first_name=res_data['given_name'], last_name=res_data['family_name'], image=file_path)

                                response = redirect(
                                    "https://localhost:3000/settings?success=gmail_linked")

                                return response

                            else:
                                response = redirect(
                                    f"https://localhost:3000/settings?error=gmail_usage")

                                return response

                        else:
                            return Response(
                                {'detail': 'Problem z userem', "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )

                    else:
                        return Response(
                            {'detail': 'Problem z żądaniem', "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                else:
                    return Response(
                        {'detail': 'Te konto jest już powiązane z kontem Google',
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
                {'detail': 'Coś poszło nie tak z próbą połączenia konta google',
                    "code": "1165"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class LinkFacebookView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = LoginFacebookSerializer

    def delete(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                user = request.user

                if FacebookUser.objects.filter(user=user).exists():

                    facebook_profile = FacebookUser.objects.get(user=user)

                    facebook_profile.delete()

                    return Response(
                        {'success': 'Sukces',
                            "code": "1701"},
                        status=status.HTTP_200_OK
                    )
                else:
                    return Response(
                        {'detail': 'Twoje konto nie jest powiązane z żadnym kontem Facebook', "code": "9011"},
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

    def get(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                data = request.GET
                code = data['code']

                user = request.user

                if not FacebookUser.objects.filter(user=user).exists():

                    request_data = {
                        'client_id': '774823227400031',
                        'redirect_uri': f'{BACKEND_IP}/api/account/link/facebook',
                        'client_secret': '409b148a85f45a8a5ba19c3d610450f0',
                        'code': code
                    }

                    # res = requests.get(
                    #     "https://graph.facebook.com/v16.0/oauth/access_token", params=request_data)
                    res = requests.get(
                        "https://graph.facebook.com/v17.0/oauth/access_token", params=request_data)

                    # 118143322891147953844

                    if res.ok:
                        print(res.json())
                        print("===============")
                        access_token = res.json()['access_token']

                        request_user_data = {
                            'fields': "id,name,first_name,last_name,email,picture",
                            'access_token': access_token
                        }


                        res_user = requests.get(
                            "https://graph.facebook.com/me",
                            params=request_user_data
                        )

                        if res_user.ok:

                            res_data = res_user.json()

                            

                            if not FacebookUser.objects.filter(social_id=res_data['id']).exists():

                                image_response = requests.get(
                                    res_data['picture']['data']['url'])
                                
                                print(res_data)
                                file_name = 'facebook_images/{}.jpg'.format(
                                    res_data['id'])

                                file_path = default_storage.save(
                                    file_name, ContentFile(image_response.content))

                                FacebookUser.objects.create(
                                    user=user, social_id=res_data['id'], first_name=res_data['first_name'], last_name=res_data['last_name'], image=file_path)

                                response = redirect(
                                    "https://localhost:3000/settings?success=facebook_linked")
                                return response

                            else:
                                response = redirect(
                                    f"https://localhost:3000/settings?error=facebook_usage")

                                return response

                        else:
                            return Response(
                                {'detail': 'Problem z userem', "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )

                    else:
                        return Response(
                            {'detail': 'Problem z żądaniem', "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                else:
                    return Response(
                        {'detail': 'Te konto jest już powiązane z kontem Facebook',
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
                {'detail': 'Coś poszło nie tak z próbą połączenia konta facebook',
                    "code": "1165"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class PasswordChangeView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = PasswordChangeSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                data = request.data
                password = data['password']

                user = request.user

                user_auth = authenticate(
                    username=user.username, password=password)

                if user_auth is not None:

                    CodeRegistration.objects.create(user=user)
                    if CodeRegistration.objects.filter(user=user).exists():
                        topic = 'Zmiana hasła hasła - nowy kod.'
                        ip_address = request.META.get('REMOTE_ADDR')
                        email = email_verification(
                            request, topic, user, ip_address)
                        if email.send():
                            return Response(
                                {'success': 'Sukces', "code": "900"},
                                status=status.HTTP_200_OK
                            )
                        else:
                            return Response(
                                {'detail': "Coś poszło nie tak przy wysyłanie e-maila",
                                    'code': "943"},
                                status=status.HTTP_400_BAD_REQUEST
                            )

                    else:
                        return Response(
                            {'detail': "Coś poszło nie tak podczas generowaniu kodu",
                                'code': "902"},
                            status=status.HTTP_400_BAD_REQUEST
                        )

                else:
                    return Response(
                        {"detail": "Złe dane logowania", "code": "1710"},
                        status=status.HTTP_404_NOT_FOUND
                    )
        except Exception as e:
            print(e)
            return Response(
                {'detail': 'Coś poszło nie tak z próbą załadowania użytkownika', "code": "945"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class EmailChangeView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = EmailChangeSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                data = request.data
                user = request.user

                email_regex = r"[^@]+@[^@]+\.[^@]+"

                new_email = data['new_email']

                if re.match(email_regex, new_email):

                    if not MyUser.objects.filter(email=new_email).exists():

                        CodeRegistration.objects.create(user=user)
                        if CodeRegistration.objects.filter(user=user).exists():
                            old_topic = 'Zmiana e-maila na nowy - kod.'
                            ip_address = request.META.get('REMOTE_ADDR')
                            old_email = email_verification(
                                request, old_topic, user, ip_address)
                            if old_email.send():

                                if ChangeEmailWaiting.objects.filter(user=user).exists():
                                    room_waiting = ChangeEmailWaiting.objects.get(
                                        user=user)
                                    room_waiting.email = new_email
                                    room_waiting.save()

                                else:
                                    room_waiting = ChangeEmailWaiting.objects.create(
                                        user=user, email=new_email)

                                new_topic = 'Przypisywanie nowego e-maila do konta - kod.'
                                message = render_to_string('template_email.html', {
                                    'username': user.username,
                                    'code': room_waiting.code_random,
                                    'ip_address': ip_address,
                                    'protocol': 'https' if request.is_secure() else 'http'
                                })
                                new_email = EmailMessage(
                                    new_topic, message, to=[new_email])

                                if new_email.send():

                                    return Response(
                                        {'success': 'Sukces', "code": "1720"},
                                        status=status.HTTP_200_OK
                                    )
                                else:
                                    return Response(
                                        {'detail': "Coś poszło nie tak przy wysyłaniu wiadomosci na nowe konto e-mail",
                                            'code': "943"},
                                        status=status.HTTP_400_BAD_REQUEST
                                    )
                            else:
                                return Response(
                                    {'detail': "Coś poszło nie tak przy wysyłaniu wiadomości na stare konto e-mail",
                                        'code': "943"},
                                    status=status.HTTP_400_BAD_REQUEST
                                )

                        else:
                            return Response(
                                {'detail': "Coś poszło nie tak podczas generowaniu kodu",
                                    'code': "902"},
                                status=status.HTTP_400_BAD_REQUEST
                            )

                    else:
                        return Response(
                            {'detail': "Istnieje już użytkownik przypisany do tego e-maila.",
                                'code': "1721"},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                else:
                    return Response(
                        {'detail': "Twój nowy e-mail nie przypomina konstrukcji e-maila",
                            'code': "902"},
                        status=status.HTTP_400_BAD_REQUEST
                    )
        except Exception as e:
            print(e)
            return Response(
                {'detail': 'Coś poszło nie tak z próbą załadowania użytkownika', "code": "945"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class EmailChangeConfirmView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = EmailChangeConfirmSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                data = request.data
                user = request.user

                old_code = data['old_code']
                new_code = data['new_code']

                if ChangeEmailWaiting.objects.filter(user=user).exists():
                    change_email_waiting = ChangeEmailWaiting.objects.get(
                        user=user)

                    if CodeRegistration.objects.filter(user=user, code_random=old_code).exists():

                        if change_email_waiting.code_random == new_code:

                            user.email = change_email_waiting.email
                            user.save(generate_thumbnail=False)

                            change_email_waiting.delete()
                            CodeRegistration.objects.filter(user=user).delete()
                            # Usuwanie innych próśb użytkowników, którzy chcieli wcześniej zmienić przypisanie konta na ten sam nowy e-mail
                            ChangeEmailWaiting.objects.filter(
                                email=user.email).delete()

                            return Response(
                                {'success': 'Sukces',
                                    'new_email': user.email, "code": "1722"},
                                status=status.HTTP_200_OK
                            )
                        else:
                            return Response(
                                {'detail': "Podajesz zły kod przesłany na nowy e-mail.",
                                    'code': "1724"},
                                status=status.HTTP_400_BAD_REQUEST
                            )

                    else:
                        return Response(
                            {'detail': "Podajesz zły kod przesłany na stary e-mail.",
                                'code': "1724"},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                else:
                    # Nie możesz potwierdzić zmiany e-maila, jeśli wpierw nie wysłałeś takiego żądania. Jeśli udało Ci się wcześniej wysłać takie żądanie z tym e-mailem, a dostajesz te powiadomienie, możliwe że inny użytkownik zdążył przypisać sobie ten sam e-mail, na którego próbujesz zmienić przypisanie swojego konta.
                    return Response(
                        {'detail': "Nie wykryto prośby o zmianę e-maila",
                            'code': "1723"},
                        status=223
                    )

        except Exception as e:
            print(e)
            return Response(
                {'detail': 'Coś poszło nie tak z próbą załadowania użytkownika', "code": "945"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class GenerateNewCodeEmailChangeView(APIView):
    permission_classes = (permissions.AllowAny, )

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                user = request.user
                ip_address = request.META.get('REMOTE_ADDR')

                if ChangeEmailWaiting.objects.filter(user=user).exists():
                    change_email_waiting = ChangeEmailWaiting.objects.get(
                        user=user)

                    change_email_waiting.save()

                    new_topic = 'Przypisywanie nowego e-maila do konta - nowy kod.'
                    message = render_to_string('template_email.html', {
                        'username': user.username,
                        'code': change_email_waiting.code_random,
                        'ip_address': ip_address,
                        'protocol': 'https' if request.is_secure() else 'http'
                    })
                    new_email = EmailMessage(
                        new_topic, message, to=[change_email_waiting.email])

                    if new_email.send():

                        return Response(
                            {'success': 'Sukces', "code": "1725"},
                            status=status.HTTP_200_OK
                        )
                    else:
                        return Response(
                            {'detail': "Coś poszło nie tak przy wysyłaniu wiadomosci na nowe konto e-mail",
                                'code': "943"},
                            status=status.HTTP_400_BAD_REQUEST
                        )

                else:
                    # Nie możesz potwierdzić zmiany e-maila, jeśli wpierw nie wysłałeś takiego żądania. Jeśli udało Ci się wcześniej wysłać takie żądanie z tym e-mailem, a dostajesz te powiadomienie, możliwe że inny użytkownik zdążył przypisać sobie ten sam e-mail, na którego próbujesz zmienić przypisanie swojego konta.
                    return Response(
                        {'detail': "Nie wykryto prośby o zmianę e-maila",
                            'code': "1723"},
                        status=223
                    )

        except Exception as e:
            print(e)
            return Response(
                {'detail': 'Coś poszło nie tak z próbą załadowania użytkownika', "code": "945"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class AccountDeleteView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = PasswordChangeSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                data = request.data
                password = data['password']

                user = request.user

                user_auth = authenticate(
                    username=user.username, password=password)

                if user_auth is not None:

                    user_auth.delete()
                    response = remove_cookies(status.HTTP_200_OK)
                    response.data = {
                        "success": "Konto usunięte", "code": "1726"}
                    return response

                else:
                    return Response(
                        {"detail": "Złe dane logowania", "code": "1710"},
                        status=status.HTTP_404_NOT_FOUND
                    )
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


class UserEditView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = UserEditSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                data = request.data
                username = data['username']
                first_name = data['first_name']
                last_name = data['last_name']
                province = data['province']
                city = data['city_target']
                image = data['image']

                user = request.user

                if len(username) >= 5:

                    if len(first_name) >= 3:

                        if len(last_name) >= 3:

                            if MyUser.objects.filter(username=username).exists():
                                target_user = MyUser.objects.get(
                                    username=username)

                                if target_user.id != user.id:
                                    return Response(
                                        {'detail': 'Istnieje już inny użytkownik o takim username.',
                                            "code": "1810"},
                                        status=status.HTTP_400_BAD_REQUEST
                                    )

                            if Province.objects.filter(name=province).exists():

                                province_obj = Province.objects.get(
                                    name=province)
                                if City.objects.filter(county__province=province_obj, name=city).exists():
                                    city_obj = City.objects.get(
                                        county__province=province_obj, name=city)

                                    if not (user.username == username and user.first_name == first_name and user.last_name == last_name and user.city == city_obj and (user.image == image or image == "")):

                                        if isinstance(image, str):
                                            if image != "" and user.image != image:

                                                return Response(
                                                    {'detail': 'W miejscu na plik graficzny próbujesz przesłać string.',
                                                        "code": "9011"},
                                                    status=status.HTTP_400_BAD_REQUEST
                                                )

                                        elif image and not image.content_type in ['image/jpeg', 'image/png', 'image/gif']:

                                            return Response(
                                                {'detail': 'Przesyłane zdjęcie nie jest plikiem graficznym.',
                                                    "code": "9011"},
                                                status=status.HTTP_400_BAD_REQUEST
                                            )

                                        user.username = username
                                        user.first_name = first_name
                                        user.last_name = last_name
                                        user.city = city_obj

                                        filter_save = {}
                                        if image != "" and user.image != image:
                                            user.image = image
                                            filter_save["generate_thumbnail"] = True
                                        else:
                                            filter_save["generate_thumbnail"] = False
                                        user.save(**filter_save)

                                        user = UserEditSerializer(user)

                                        return Response(
                                            {'success': 'Sukces',
                                                'data': user.data, "code": "1800"},
                                            status=status.HTTP_200_OK
                                        )

                                    else:
                                        return Response(
                                            {'detail': 'Żadne zmiany nie zostały wprowadzone',
                                                "code": "1815"},
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
                                {'detail': 'Nazwisko musi posiadac przynajmniej 3 znaki.',
                                    "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )

                    else:
                        return Response(
                            {'detail': 'Imie musi posiadac przynajmniej 3 znaki.',
                                "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )

                else:
                    return Response(
                        {'detail': 'Username musi posiadać przynajmniej 5 znaków.',
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
                {'detail': 'Coś poszło nie tak z próbą załadowania użytkownika', "code": "945"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class BadgesViaSettingsView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = BadgesViaSettingsSerializer

    def get(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:

                user = request.user

                badges = user.activated_badges.filter(
                    verificated="verificated").annotate(
                    main=Case(
                        When(id=user.main_badge_id, then=True),
                        default=False,
                        output_field=BooleanField()
                    )
                )

                badges = BadgesViaSettingsSerializer(badges, many=True)

                return Response(
                    {'success': 'Sukces', 'data': badges.data,  "code": "1900"},
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
                {'detail': 'Coś poszło nie tak z próbą połączenia konta facebook',
                    "code": "1165"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class BadgeSetMainView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = BadgeDeleteSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:

                data = request.data
                badge_id = data['badge_id']

                user = request.user

                if Badge.objects.filter(id=badge_id).exists():

                    badge = Badge.objects.get(id=badge_id)

                    if badge.verificated == "verificated":

                        if badge.badge_owners.filter(id=user.id).exists():

                            if user.main_badge != badge:

                                user.main_badge = badge
                                user.save(generate_thumbnail=False)

                                return Response(
                                    {'success': 'Sukces', "code": "1920"},
                                    status=status.HTTP_200_OK
                                )
                            else:
                                return Response(
                                    {'success': 'Użytkownik ma już ustawioną tą odznakę jako główną.',
                                        "code": "1920"},
                                    status=224
                                )
                        else:
                            return Response(
                                {'detail': 'Użytkownik nie posiada podanej odznaki.',
                                    "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )
                    else:
                        return Response(
                            {'detail': 'Ta odznaka nie ma statusu zweryfikowanej.',
                                "code": "1930"},
                            status=223
                        )
                else:
                    return Response(
                        {'detail': 'Ta odznaka nie istnieje lub została usunięta.',
                            "code": "1930"},
                        status=223
                    )

        except Exception as e:
            print(e)
            print(f"Typ błędu: {type(e).__name__}")
            print(f"Kod błędu: {e.args[0]}")
            print("Traceback:")
            import traceback
            traceback.print_tb(e.__traceback__)

            return Response(
                {'detail': 'Coś poszło nie tak z próbą połączenia konta facebook',
                    "code": "1165"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class BankNumberChangeView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = PasswordChangeSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                data = request.data
                password = data['password']

                user = request.user

                user_auth = authenticate(
                    username=user.username, password=password)

                if user_auth is not None:

                    CodeRegistration.objects.create(user=user)
                    if CodeRegistration.objects.filter(user=user).exists():
                        topic = 'Zmiana numeru bankowego - nowy kod.'
                        ip_address = request.META.get('REMOTE_ADDR')
                        email = email_verification(
                            request, topic, user, ip_address)
                        if email.send():
                            return Response(
                                {'success': 'Sukces', "code": "899"},
                                status=status.HTTP_200_OK
                            )
                        else:
                            return Response(
                                {'detail': "Coś poszło nie tak przy wysyłanie e-maila",
                                    'code': "943"},
                                status=status.HTTP_400_BAD_REQUEST
                            )

                    else:
                        return Response(
                            {'detail': "Coś poszło nie tak podczas generowaniu kodu",
                                'code': "902"},
                            status=status.HTTP_400_BAD_REQUEST
                        )

                else:
                    return Response(
                        {"detail": "Złe dane logowania", "code": "1710"},
                        status=status.HTTP_404_NOT_FOUND
                    )
        except Exception as e:
            print(e)
            return Response(
                {'detail': 'Coś poszło nie tak z próbą załadowania użytkownika', "code": "945"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        


class BankNumberView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = BankNumberViewSerializer


    def get(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:

                user= request.user
                time_now = timezone.now()
                

                
                
                subquery_started_refunding = OrderedTicket.objects.filter(order__user__id=OuterRef('id'), refunded=True, paycheck__isnull=True)

                subquery_future_event = Event.objects.filter(Exists(Ticket.objects.filter(event__id=OuterRef('id'), was_allowed=True)), user__id=OuterRef('id'), event_date__gte=time_now.date(), to_start_refund=False)

                subquery_past_not_paid_event = Event.objects.filter(
                    ~(Exists(Paycheck.objects.filter(event__id=OuterRef('id')))) 
                    & 
                    Exists(OrderedTicket.objects.filter(ticket__event__id=OuterRef('id'), refunded=False)), 
                    user__id=OuterRef('id'), 
                    event_date__lt=time_now.date(), verificated="verificated")

                subquery_blocked_change_bank_account = GatewayPaycheck.objects.filter(Q(tickets__order__user__id=OuterRef('id'))|Q(event__user__id=OuterRef('id')), Q(remove_time__gte=time_now)&Q(paycheck__isnull=True))

                subquery_amount_awaiting_refunding = AwaitingsTicketsRefund.objects.filter(user__id=OuterRef('id')).values('amount')

                myuser = MyUser.objects.annotate(
                blocked_remove_bank_account=JSONObject(
                    started_refunding=Exists(subquery_started_refunding),
                    future_event=Exists(subquery_future_event),
                    past_not_paid_event=Exists(subquery_past_not_paid_event)
                ),
                blocked_change_bank_account=Exists(subquery_blocked_change_bank_account),
                amount_awaiting_refunding=Subquery(subquery_amount_awaiting_refunding)
                ).get(id=user.id)

                bank_number = BankNumberViewSerializer(myuser)

                return Response(
                    {'success': 'Sukces', 'data': bank_number.data, "code": "123123"},
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
        
    def post(self, request):
        try:
            response_verify = token_verify(request)
            
            if response_verify is not None:
                return response_verify
            else:

                user = request.user
                data = request.data
                code = data['code']
                status_connect = data['status_connect'] 
                new_bank_number = data.get('new_bank_number', None)

                if CodeRegistration.objects.filter(user=user).exists():
                    code_backend = CodeRegistration.objects.filter(user=user).values_list('code_random', flat=True)

                    if code in code_backend:

                        time_now = timezone.now()

                        if status_connect == True:

                            if new_bank_number.isdigit() and len(new_bank_number) == 26:

                                if not GatewayPaycheck.objects.filter(Q(tickets__order__user__id=user.id)|Q(event__user__id=user.id), Q(remove_time__gte=time_now)&Q(paycheck__isnull=True)).exists():


                                    CodeRegistration.objects.filter(user=user).delete()

                                    if user.bank_number != "":
                                        status_unpinned = False
                                    else:
                                        status_unpinned = True
                                        AwaitingsTicketsRefund.objects.filter(user__id=user.id).delete()

                                        

                                    user.bank_number = new_bank_number
                                    user.save(generate_thumbnail=False)


                                    return Response(
                                        {'success': 'Sukces','data': new_bank_number,'status_unpinned':status_unpinned,  "code": "2075"},
                                        status=status.HTTP_200_OK
                                    )
                                
                                else:
                                    return Response(
                                        {'detail': 'Nie możesz zmienić aktualnie swojego konta bankowego.',
                                        "code": "2170"},
                                        status=222
                                    )
                            else:
                                return Response(
                                        {'detail': 'Input musi składać się z samych liczb i posiadać długość 26 znaków',  "code": "123123"},
                                        status=status.HTTP_400_BAD_REQUEST
                                    )
                        else:

                            

                            started_refunding = OrderedTicket.objects.filter(order__user__id=user.id, refunded=True, paycheck__isnull=True).exists()

                            future_event = Event.objects.filter(Exists(Ticket.objects.filter(event__id=OuterRef('id'), was_allowed=True)), user__id=user.id, event_date__gte=time_now.date(), to_start_refund=False).exists()

                            past_not_paid_event = Event.objects.filter(~(Exists(Paycheck.objects.filter(event__id=OuterRef('id')))) & Exists(OrderedTicket.objects.filter(ticket__event__id=OuterRef('id'), refunded=False)), user__id=user.id, event_date__lt=time_now.date(), verificated="verificated").exists()



                            if not any([started_refunding, future_event, past_not_paid_event]):

                                CodeRegistration.objects.filter(user=user).delete()

                                user.bank_number = ""
                                user.save(generate_thumbnail=False)

                                return Response(
                                    {'success': 'Sukces',  "code": "2076"},
                                    status=status.HTTP_200_OK
                                )
                            else:
                                return Response(
                                    {'detail': 'Nie możesz odpiąć aktualnie swojego konta bankowego.', 
                                     'blocked_remove_bank_account': {
                                        'started_refunding': started_refunding,
                                        'future_event': future_event,
                                        'past_not_paid_event': past_not_paid_event 
                                     },
                                    "code": "2171"},
                                    status=222
                                )
                            

                        
                    else:
                        return Response(
                            {'detail': 'Błąd kodu', "code": "601"},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                else:
                    return Response(
                        {'detail': 'Brak kodów', "code": "601"},
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
        








