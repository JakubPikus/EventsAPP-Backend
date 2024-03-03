from rest_framework.views import APIView
from ..serializers import LogoutSerializer, LoginSerializer, RegisterSerializer, UserSerializer, AccountConfirmSerializer, PasswordResetSerializer, PasswordResetConfirmSerializer, LoginGoogleSerializer, LoginFacebookSerializer
from rest_framework import permissions, status
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle
from rest_framework_simplejwt.exceptions import TokenError
from django.conf import settings
from django.contrib.auth import authenticate
from ..custom_refresh_token import CustomRefreshToken, CustomBlacklistedToken
from .functions import remove_cookies, check_banned_status, get_tokens_for_user, add_cookies, get_location_from_ip, send_websocket_notification, email_verification
from ..models import IPAddressValidator, MyUser, IPAddress, CodeRegistration, City, GmailUser, FacebookUser
from user_agents import parse
from django.db.models import  Case, When, Value, BooleanField, F
from django.db.models.functions import JSONObject
from django.middleware import csrf
from django.shortcuts import redirect
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import ensure_csrf_cookie
from urllib.parse import urlencode
from ips_config import BACKEND_IP
import requests
import datetime



# THROTTLING BLOCK
class LogoutView(APIView):
    serializer_class = LogoutSerializer
    permission_classes = (permissions.AllowAny, )
    throttle_classes = []

    def post(self, request):
        try:
            try:
                refreshToken = request.COOKIES.get(
                    settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'])

                token = CustomRefreshToken(refreshToken)
                token.blacklist()
            except:
                pass
            response = remove_cookies(status.HTTP_200_OK)
            response.data = {"success": "Wylogowano", "code": "400"}
            return response

        except Exception as e:
            print(e)
            print(f"Typ błędu: {type(e).__name__}")
            print(f"Kod błędu: {e.args[0]}")
            print("Traceback:")
            import traceback
            traceback.print_tb(e.__traceback__)

            return Response(
                {'detail': 'Coś poszło nie tak z próbą wylogowania', "code": "445"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class MyTokenRefreshView(APIView):
    authentication_classes = ()

    def post(self, request):
        try:

            refreshToken = request.COOKIES.get(
                settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'])

            token = CustomRefreshToken(refreshToken)
            ip_address = request.META.get('REMOTE_ADDR')
            user_id = token['user_id']

            response_banned = check_banned_status(user_id, ip_address)
            if response_banned is not None:
                return response_banned

            elif not CustomBlacklistedToken.objects.filter(token__token=refreshToken).exists():

                token.blacklist()

                user = MyUser.objects.get(id=user_id)

                ip_validator = IPAddressValidator.objects.get(
                    user=user, ip_address__ip_address=ip_address)

                newToken = get_tokens_for_user(user, ip_validator)
                response = add_cookies(newToken, status.HTTP_200_OK)
                response.data = {
                    'success': 'Token został odświeżony', "code": "500"}
                return response
            else:  # JAK ACCESS NIE MA I REFRESH WCZESNIEJ ZABLOKOWANY
                response = remove_cookies(440)
                response.data = {
                    'detail': 'Refresh token znajduje się na czarnej liście', "code": "440"}

                return response

        except TokenError:

            response = remove_cookies(418)
            response.data = {
                'detail': 'Refresh token jest niepoprawny', "code": "418"}

            return response

        except Exception as e:
            print(e)
            print(f"Typ błędu: {type(e).__name__}")
            print(f"Kod błędu: {e.args[0]}")
            print("Traceback:")
            import traceback
            traceback.print_tb(e.__traceback__)

            return Response(
                {'detail': 'Coś poszło nie tak z próbą odświeżenia tokena', "code": "545"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class LoginView(APIView):
    serializer_class = LoginSerializer
    throttle_classes = []

    def post(self, request, format=None):
        try:
            data = request.data
            username = data['username']
            password = data['password']
            user_auth = authenticate(username=username, password=password)
            name_device = parse(request.META.get('HTTP_USER_AGENT'))
            ip_address = request.META.get('REMOTE_ADDR')
            if user_auth is not None:
                if user_auth.is_verificated:
                    ip_address_obj, created = IPAddress.objects.get_or_create(
                        ip_address=ip_address)

                    if not ip_address_obj.is_banned:

                        user = MyUser.objects.annotate(pinned_bank=Case(When(bank_number="", then=Value(False)),default=Value(True),output_field=BooleanField()), gmail=JSONObject(social_id=F('gmailuser__social_id'), first_name=F('gmailuser__first_name'), last_name=F('gmailuser__last_name'), image=F('gmailuser__image')), facebook=JSONObject(
                            social_id=F('facebookuser__social_id'), first_name=F('facebookuser__first_name'), last_name=F('facebookuser__last_name'), image=F('facebookuser__image'))).get(id=user_auth.id)

                        closest_city = get_location_from_ip(ip_address)

                        if not user.is_banned:

                            if IPAddressValidator.objects.filter(user=user, ip_address=ip_address_obj).exists():
                                ip_validator_obj = IPAddressValidator.objects.get(
                                    user=user, ip_address=ip_address_obj)

                                ip_validator_obj.last_login_city = closest_city
                                ip_validator_obj.name_device = name_device
                                ip_validator_obj.save(update_login_time=True)

                                if ip_validator_obj.is_verificated:
                                    tokens = get_tokens_for_user(
                                        user, ip_validator_obj)
                                    response = add_cookies(
                                        tokens, status.HTTP_200_OK)
                                    response["X-CSRFToken"] = csrf.get_token(
                                        request)

                                    user = LoginSerializer(user)
                                    response.data = {
                                        "success": "Zalogowano", "user": user.data, 'code': "200"}
                                    return response
                                else:
                                    return Response(
                                        {"success": "Adres IP jest niezweryfikowany", "user": {
                                            "username": username}, "code": "287", },
                                        status=224
                                    )

                            else:
                                IPAddressValidator.objects.create(
                                    user=user, ip_address=ip_address_obj, last_login_city=closest_city, name_device=name_device)
                                CodeRegistration.objects.create(user=user)

                                send_websocket_notification([user], 8, ip_address_obj, timezone.now(), False)


                                topic = 'Wykryto nowe logowanie na konto ' + \
                                    user.username + ' z nowego adresu IP - ' + \
                                        ip_address + \
                                    " (" + closest_city.name + ")"
                                email = email_verification(
                                    request, topic, user, ip_address)
                                if email.send():
                                    return Response(
                                        {"success": "Logowanie z nowego adresu IP", "user": {
                                            "username": username}, "code": "288", },
                                        status=224
                                    )

                        else:

                            return Response(
                                {"detail": "Logowanie nie powiodło się",
                                    "code": "422", },
                                status=422
                            )
                    else:

                        return Response(
                            {"detail": "Logowanie nie powiodło się", "code": "421", },
                            status=421
                        )
                else:

                    return Response(
                        {"success": "Użytkownik jest niezweryfikowany", "user": {
                            "username": username, "email": user_auth.email}, "code": "286", },
                        status=224
                    )
            else:
                return Response(
                    {"detail": "Złe dane logowania", "code": "202"},
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
                {'detail': 'Coś poszło nie tak z próbą zalogowania', "code": "245"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class RegisterView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = RegisterSerializer
    throttle_classes = []

    def post(self, request):

        try:
            data = request.data
            username = data['username']
            password = data['password']
            re_password = data['re_password']
            email = data['email']
            first_name = data['first_name']
            last_name = data['last_name']
            province = data['province']
            city = data['city']

            if password == re_password:
                if len(password) >= 8:
                    ip_address = request.META.get('REMOTE_ADDR')

                    ip_address_obj, created = IPAddress.objects.get_or_create(
                        ip_address=ip_address)

                    if not ip_address_obj.is_banned:
                        if not MyUser.objects.filter(email=email).exists():
                            if not MyUser.objects.filter(username=username).exists():
                                user = MyUser.objects.create_user(
                                    username=username,
                                    password=password,
                                    email=email,
                                    first_name=first_name,
                                    last_name=last_name,
                                    city=City.objects.get(
                                        name=city, county__province__name=province)
                                )
                                user.save()

                                if MyUser.objects.filter(username=username).exists():

                                    closest_city = get_location_from_ip(
                                        ip_address)
                                    name_device = parse(
                                        request.META.get('HTTP_USER_AGENT'))

                                    IPAddressValidator.objects.create(
                                        user=user, ip_address=ip_address_obj, last_login_city=closest_city, name_device=name_device)
                                    CodeRegistration.objects.create(user=user)
                                    if CodeRegistration.objects.filter(user=user).exists():
                                        topic = 'Aktywacja swojego konta.'
                                        email = email_verification(
                                            request, topic, user, ip_address)
                                        if email.send():

                                            return Response(
                                                {'success': "Konto zostało utworzone",
                                                    'code': "100"},
                                                status=status.HTTP_201_CREATED
                                            )
                                        else:
                                            return Response(
                                                {'detail': "Coś poszło nie tak",
                                                    'code': "144"},
                                                status=status.HTTP_400_BAD_REQUEST
                                            )
                                    else:
                                        return Response(
                                            {'detail': "Coś poszło nie tak",
                                                'code': "144"},
                                            status=status.HTTP_400_BAD_REQUEST
                                        )
                                else:
                                    return Response(
                                        {'detail': "Coś poszło nie tak",
                                            'code': "144"},
                                        status=status.HTTP_400_BAD_REQUEST
                                    )
                            else:
                                return Response(
                                    {'detail': "Istnieje osoba z takim nickiem",
                                        'code': "101"},
                                    status=status.HTTP_400_BAD_REQUEST
                                )
                        else:
                            return Response(
                                {'detail': "Istnieje już konto przypisane do tego emaila",
                                    'code': "102"},
                                status=status.HTTP_400_BAD_REQUEST
                            )
                    else:

                        return Response(
                            {"detail": "Rejestracja nie powiodła się", "code": "421", },
                            status=421
                        )

                else:
                    return Response(
                        {'detail': "Hasło musi składać się z conajmniej 8 znaków",
                            'code': "103"},
                        status=status.HTTP_400_BAD_REQUEST
                    )
            else:
                return Response(
                    {'detail': "Hasła nie pasują do siebie", 'code': "104"},
                    status=status.HTTP_400_BAD_REQUEST
                )
        except Exception as e:
            print(e)
            return Response(
                {'detail': 'Coś poszło nie tak z próbą rejestracji', 'code': "145"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


@ method_decorator(ensure_csrf_cookie, name='dispatch')
class LoadUserView(APIView):
    permission_classes = (permissions.AllowAny,)
    throttle_classes = []

    def get(self, request, format=None):
        try:
            if request.COOKIES.get(settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH']) is not None and request.COOKIES.get(settings.SIMPLE_JWT['AUTH_COOKIE']) is None:

                return Response(
                    {"detail": "Token wygasł lub go brak", "code": "301"},
                    status=status.HTTP_403_FORBIDDEN
                )

            else:

                token_refresh = request.COOKIES.get(
                    settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'])

                try:
                    # RefreshToken(token_refresh).check_blacklist()
                    CustomRefreshToken(token_refresh).check_blacklist()

                    user_request = request.user
                    if user_request.is_authenticated:

                        user = MyUser.objects.annotate(pinned_bank=Case(When(bank_number="", then=Value(False)),default=Value(True),output_field=BooleanField()),gmail=JSONObject(social_id=F('gmailuser__social_id'), first_name=F('gmailuser__first_name'), last_name=F('gmailuser__last_name'), image=F('gmailuser__image')), facebook=JSONObject(social_id=F('facebookuser__social_id'), first_name=F('facebookuser__first_name'), last_name=F('facebookuser__last_name'), image=F('facebookuser__image'))).get(id=user_request.id)

                        user = UserSerializer(user)
                        response = Response({'success': 'Pomyślnie pobrano użytkownika', 'user': user.data, "code": "300"},
                                            status=status.HTTP_200_OK)
                        response["X-CSRFToken"] = csrf.get_token(request)
                        return response

                    else:
                        return Response(
                            {"detail": "Brak zalogowanego użytkownika", "code": "302"},
                            status=status.HTTP_401_UNAUTHORIZED
                        )

                except TokenError:
                    # GDY ZDALNIE Z PANELU DODA SIE DANY TOKEN DO BLACKLISTY (REFRESH)

                    response = remove_cookies(status.HTTP_401_UNAUTHORIZED)
                    response.data = {
                        'detail': 'Wylogowano', "code": "322"}
                    return response

        except Exception as e:
            print(e)
            print(f"Typ błędu: {type(e).__name__}")
            print(f"Kod błędu: {e.args[0]}")
            print("Traceback:")
            import traceback
            traceback.print_tb(e.__traceback__)
            return Response(
                {'detail': 'Coś poszło nie tak z próbą załadowania użytkownika', "code": "345"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class GenerateNewCodeConfirmView(APIView):
    permission_classes = (permissions.AllowAny, )
    throttle_classes = [AnonRateThrottle]

    def post(self, request):
        try:
            data = request.data
            user = data['user']

            if "email" in user:
                if MyUser.objects.filter(email=user["email"]).exists():
                    user = MyUser.objects.get(email=user["email"])
                else:
                    return Response(
                        {'detail': "Nie ma takiego użytkownika", 'code': "723"},
                        status=status.HTTP_400_BAD_REQUEST
                    )

            elif "username" in user:
                if MyUser.objects.filter(username=user["username"]).exists():
                    user = MyUser.objects.get(username=user["username"])
                else:
                    return Response(
                        {'detail': "Nie ma takiego użytkownika", 'code': "723"},
                        status=status.HTTP_400_BAD_REQUEST
                    )
            else:
                return Response(
                    {'detail': "Coś poszło nie tak", 'code': "726"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            CodeRegistration.objects.create(user=user)
            if CodeRegistration.objects.filter(user=user).exists():
                topic = 'Nowy kod autoryzujący.'
                ip_address = request.META.get('REMOTE_ADDR')
                email = email_verification(request, topic, user, ip_address)
                if email.send():

                    return Response(
                        {'success': "Nowy kod został wygenerowany", 'code': "700"},
                        status=status.HTTP_201_CREATED
                    )
                else:
                    return Response(
                        {'detail': "Coś poszło nie tak", 'code': "744"},
                        status=status.HTTP_400_BAD_REQUEST
                    )
            else:
                return Response(
                    {'detail': "Coś poszło nie tak", 'code': "744"},
                    status=status.HTTP_400_BAD_REQUEST
                )

        except Exception as e:
            print(e)
            return Response(
                {'detail': 'Coś poszło nie tak z próbą załadowania użytkownika', "code": "745"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class AccountConfirmView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = AccountConfirmSerializer
    throttle_classes = []

    def post(self, request):
        try:
            data = request.data
            username = data['username']
            code_random = data['code_random']

            if MyUser.objects.filter(username=username).exists():

                user = MyUser.objects.annotate(pinned_bank=Case(When(bank_number="", then=Value(False)),default=Value(True),output_field=BooleanField()),
                    gmail=JSONObject(social_id=F('gmailuser__social_id'), first_name=F('gmailuser__first_name'), last_name=F('gmailuser__last_name'), image=F('gmailuser__image')), facebook=JSONObject(social_id=F('facebookuser__social_id'), first_name=F('facebookuser__first_name'), last_name=F('facebookuser__last_name'), image=F('facebookuser__image'))).get(username=username)

                code_random_backend = CodeRegistration.objects.filter(
                    user=user).values_list('code_random', flat=True)
                if code_random in code_random_backend:
                    ip_request = request.META.get('REMOTE_ADDR')
                    closest_city = get_location_from_ip(ip_request)
                    name_device = parse(request.META.get('HTTP_USER_AGENT'))

                    ip_address, created = IPAddress.objects.get_or_create(
                        ip_address=ip_request)
                    

                    if not ip_address.is_banned:

                        if not user.is_banned:
                            if not user.is_verificated:
                                user.is_verificated = True
                                user.save(generate_thumbnail=False)
                            ip_validator, created = IPAddressValidator.objects.get_or_create(
                                user=user, ip_address=ip_address)
                            
                            

                            ip_validator.is_verificated = True
                            ip_validator.last_login_city = closest_city
                            ip_validator.name_device = name_device
                            ip_validator.save(update_login_time=True)

                            CodeRegistration.objects.filter(user=user).delete()

                            tokens = get_tokens_for_user(user, ip_validator)
                            response = add_cookies(tokens, status.HTTP_200_OK)

                            response["X-CSRFToken"] = csrf.get_token(request)
                            user = LoginSerializer(user)
                            response.data = {"success": "Zalogowano",
                                             "user": user.data, 'code': "600"}
                            return response
                        else:
                            CodeRegistration.objects.filter(user=user).delete()

                            return Response(
                                {"detail": "Potwierdzanie nie powiodło się",
                                    "code": "422", },
                                status=422
                            )

                    else:
                        CodeRegistration.objects.filter(user=user).delete()

                        return Response(
                            {"detail": "Potwierdzanie nie powiodło się",
                                "code": "421", },
                            status=421
                        )

                else:
                    return Response(
                        {'detail': 'Błąd kodu', "code": "601"},
                        status=status.HTTP_400_BAD_REQUEST
                    )

            else:
                return Response(
                    {'detail': 'Taki użytkownik nie istnieje', "code": "602"},
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
                {'detail': 'Coś poszło nie tak z próbą załadowania użytkownika', "code": "645"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class PasswordResetView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = PasswordResetSerializer
    throttle_classes = [AnonRateThrottle]

    def post(self, request):
        try:
            data = request.data
            email_data = data['email']
            if MyUser.objects.filter(email=email_data).exists():
                user = MyUser.objects.get(email=email_data)
                ip_address = request.META.get('REMOTE_ADDR')

                ip_address_obj = IPAddress.objects.get(ip_address=ip_address)

                if not ip_address_obj.is_banned:

                    if not user.is_banned:

                        CodeRegistration.objects.create(user=user)
                        if CodeRegistration.objects.filter(user=user).exists():
                            topic = 'Ustawienie nowego hasła - nowy kod.'
                            email = email_verification(
                                request, topic, user, ip_address)
                            if email.send():
                                return Response(
                                    {'success': 'Sukces', 'user': {
                                        "email": email_data}, "code": "900"},
                                    status=status.HTTP_200_OK
                                )
                            else:
                                return Response(
                                    {'detail': "Coś poszło nie tak", 'code': "943"},
                                    status=status.HTTP_400_BAD_REQUEST
                                )

                        else:
                            return Response(
                                {'detail': "Coś poszło nie tak", 'code': "902"},
                                status=status.HTTP_400_BAD_REQUEST
                            )
                    else:

                        return Response(
                            {"detail": "Reset hasła nie powiódł się",
                                "code": "422", },
                            status=422
                        )
                else:

                    return Response(
                        {"detail": "Reset hasła nie powiódł się", "code": "421", },
                        status=421
                    )
            else:
                return Response(
                    {'detail': 'Nie znaleziono takiego użytkownika', "code": "901"},
                    status=status.HTTP_400_BAD_REQUEST
                )
        except Exception as e:
            print(e)
            return Response(
                {'detail': 'Coś poszło nie tak z próbą załadowania użytkownika', "code": "945"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class PasswordResetConfirmView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = PasswordResetConfirmSerializer
    throttle_classes = [AnonRateThrottle]

    def post(self, request):
        try:
            data = request.data
            email = data['email']
            code = data['code']
            password = data['password']
            re_password = data['re_password']
            if MyUser.objects.filter(email=email).exists():
                user = MyUser.objects.get(email=email)
                ip_address = IPAddress.objects.get(
                    ip_address=request.META.get('REMOTE_ADDR'))

                if not ip_address.is_banned:

                    if not user.is_banned:

                        if CodeRegistration.objects.filter(user=user).exists():
                            
                            code_backend = CodeRegistration.objects.filter(
                                user=user).values_list('code_random', flat=True)

                            if code in code_backend:
                                if password == re_password:
                                    if not user.is_verificated:
                                        user.is_verificated = True
                                    user.set_password(password)
                                    user.save(generate_thumbnail=False)

                                    CodeRegistration.objects.filter(
                                        user=user).delete()
                                    return Response(
                                        {'success': 'Sukces', "code": "990"},
                                        status=status.HTTP_200_OK
                                    )

                                else:
                                    return Response(
                                        {'detail': 'Hasła do siebie nie pasują',
                                            "code": "993"},
                                        status=status.HTTP_400_BAD_REQUEST
                                    )

                            else:
                                return Response(
                                    {'detail': 'Błąd kodu', "code": "991"},
                                    status=status.HTTP_400_BAD_REQUEST
                                )

                        else:
                            return Response(
                                {'detail': 'Coś poszło nie tak', "code": "901"},
                                status=status.HTTP_400_BAD_REQUEST
                            )
                    else:
                        CodeRegistration.objects.filter(user=user).delete()

                        return Response(
                            {"detail": "Reset hasła nie powiódł się",
                                "code": "422", },
                            status=422
                        )

                else:
                    CodeRegistration.objects.filter(user=user).delete()
                    return Response(
                        {"detail": "Reset hasła nie powiódł się", "code": "421", },
                        status=421
                    )

            else:
                return Response(
                    {'detail': 'Nie znaleziono takiego użytkownika', "code": "901"},
                    status=status.HTTP_400_BAD_REQUEST
                )
        except Exception as e:
            print(e)
            return Response(
                {'detail': 'Coś poszło nie tak z próbą załadowania użytkownika', "code": "945"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class LoginGoogleView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = LoginGoogleSerializer
    authentication_classes = ()

    # 118143322891147953844

    def get(self, request):
        try:
            data = request.GET
            code = data['code']

            request_data = {
                'code': code,
                'client_id': '298963308775-ao9rr2jc1hobam57co8qpvkpkvjierpb.apps.googleusercontent.com',
                'client_secret': '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',
                'redirect_uri': f'{BACKEND_IP}/api/account/login/google',
                'grant_type': 'authorization_code'
            }

            res = requests.post(
                "https://oauth2.googleapis.com/token", data=request_data)

            if res.ok:

                access_token = res.json()['access_token']
                res_user = requests.get(
                    "https://www.googleapis.com/oauth2/v3/userinfo",
                    params={'access_token': access_token}
                )

                if res_user.ok:

                    social_id = res_user.json()['sub']

                    if GmailUser.objects.filter(social_id=social_id).exists():
                        user = GmailUser.objects.get(
                            social_id=social_id).user

                        name_device = parse(
                            request.META.get('HTTP_USER_AGENT'))
                        ip_address = request.META.get('REMOTE_ADDR')

                        if user.is_verificated:
                            closest_city = get_location_from_ip(ip_address)

                            ip_address_obj, created = IPAddress.objects.get_or_create(
                                ip_address=ip_address)

                            if not ip_address_obj.is_banned:

                                if not user.is_banned:

                                    ip_validator_obj, created = IPAddressValidator.objects.get_or_create(
                                        user=user, ip_address=ip_address_obj)

                                    ip_validator_obj.last_login_city = closest_city
                                    ip_validator_obj.name_device = name_device
                                    ip_validator_obj.is_verificated = True
                                    ip_validator_obj.save(
                                        update_login_time=True)

                                    tokens = get_tokens_for_user(
                                        user, ip_validator_obj)
                                    response = redirect(
                                        "https://localhost:3000")
                                    response.set_cookie(
                                        key=settings.SIMPLE_JWT['AUTH_COOKIE'],
                                        value=tokens["access_token"],
                                        expires=datetime.datetime.strftime(datetime.datetime.utcnow(
                                        ) + settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'], "%a, %d-%b-%Y %H:%M:%S GMT",),
                                        secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
                                        httponly=settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
                                        samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE']
                                    )

                                    response.set_cookie(
                                        key=settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'],
                                        value=tokens["refresh_token"],
                                        expires=datetime.datetime.strftime(datetime.datetime.utcnow(
                                        ) + settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'], "%a, %d-%b-%Y %H:%M:%S GMT",),
                                        secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
                                        httponly=settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
                                        samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE']
                                    )
                                    response["X-CSRFToken"] = csrf.get_token(
                                        request)
                                    return response

                                else:
                                    params = urlencode(
                                        {"error": "user_banned"})
                                    response = redirect(
                                        f"https://localhost:3000?{params}")

                                    return response

                            else:
                                params = urlencode(
                                    {"error": "ip_banned"})
                                response = redirect(
                                    f"https://localhost:3000?{params}")

                                return response
                        else:
                            params = urlencode(
                                {"error": "not_verificated"})
                            response = redirect(
                                f"https://localhost:3000?{params}")

                            return response

                    else:
                        # response = redirect("https://localhost:3000")
                        # response.data = {'detail': 'Twoje główne konto nie jest powiązane z socialmedia. Zaloguj się sposobem mailowym, a następnie połącz swoje konto aby korzystać z możliwości szybkiego logowania', "code": "999"}

                        params = urlencode(
                            {"error": "social_user"})
                        response = redirect(f"https://localhost:3000?{params}")
                        return response

                else:
                    return Response(
                        {'detail': 'Problem z userem', "code": "596"},
                        status=status.HTTP_400_BAD_REQUEST
                    )

            else:
                return Response(
                    {'detail': 'Problem z żądaniem', "code": "595"},
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
                {'detail': 'Coś poszło nie tak z próbą logowania kontem google',
                    "code": "1165"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class LoginFacebookView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = LoginFacebookSerializer


    # https://graph.facebook.com/me?fields=id,first_name,last_name,email,picture&access_token=EAALAspc7n18BAG7m09lUKd3aEaEuLrPMitRgiS3oivMjY0tXZCeE7uTkZCZC5wWXh0JSczUCgJXgah8c8ElCiZCQAydIZCNuMno9SqarZA7vaEZAdYp6TF2hVvR0SYFf7g7OFqHcZBcm414ZB4By6Cz5RmhY3t0Kkl7jZA68XZAaVonYNMgmwnFlyxIMYAC25kHHmZBsyWrzTZBLRJbOIoyOWKrZBHGRurujM7X1xapZCflpfDtnQZDZD
    # 9364677030240030

    def get(self, request):
        try:
            data = request.GET
            code = data['code']

            request_data = {
                'client_id': '774823227400031',
                'redirect_uri': f'{BACKEND_IP}/api/account/login/facebook',
                'client_secret': '409b148a85f45a8a5ba19c3d610450f0',
                'code': code
            }

            res = requests.get(
                "https://graph.facebook.com/v16.0/oauth/access_token", params=request_data)

            if res.ok:
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
                    social_id = res_user.json()['id']
                    if FacebookUser.objects.filter(social_id=social_id).exists():
                        user = FacebookUser.objects.get(
                            social_id=social_id).user
                        

                        
                        name_device = parse(
                            request.META.get('HTTP_USER_AGENT'))
                        ip_address = request.META.get('REMOTE_ADDR')

                        if user.is_verificated:
                            closest_city = get_location_from_ip(ip_address)

                            ip_address_obj, created = IPAddress.objects.get_or_create(
                                ip_address=ip_address)

                            if not ip_address_obj.is_banned:

                                if not user.is_banned:

                                    ip_validator_obj, created = IPAddressValidator.objects.get_or_create(
                                        user=user, ip_address=ip_address_obj)

                                    ip_validator_obj.last_login_city = closest_city
                                    ip_validator_obj.name_device = name_device
                                    ip_validator_obj.is_verificated = True
                                    ip_validator_obj.save(
                                        update_login_time=True)

                                    tokens = get_tokens_for_user(
                                        user, ip_validator_obj)
                                    response = redirect(
                                        "https://localhost:3000")
                                    response.set_cookie(
                                        key=settings.SIMPLE_JWT['AUTH_COOKIE'],
                                        value=tokens["access_token"],
                                        expires=datetime.datetime.strftime(datetime.datetime.utcnow(
                                        ) + settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'], "%a, %d-%b-%Y %H:%M:%S GMT",),
                                        secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
                                        httponly=settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
                                        samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE']
                                    )

                                    response.set_cookie(
                                        key=settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'],
                                        value=tokens["refresh_token"],
                                        expires=datetime.datetime.strftime(datetime.datetime.utcnow(
                                        ) + settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'], "%a, %d-%b-%Y %H:%M:%S GMT",),
                                        secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
                                        httponly=settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
                                        samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE']
                                    )
                                    response["X-CSRFToken"] = csrf.get_token(
                                        request)
                                    return response
                                else:
                                    params = urlencode(
                                        {"error": "user_banned"})
                                    response = redirect(
                                        f"https://localhost:3000?{params}")

                                    return response

                            else:
                                params = urlencode(
                                    {"error": "ip_banned"})
                                response = redirect(
                                    f"https://localhost:3000?{params}")

                                return response
                        else:
                            params = urlencode(
                                {"error": "not_verificated"})
                            response = redirect(
                                f"https://localhost:3000?{params}")

                            return response
                    else:

                        params = urlencode(
                            {"error": "social_user"})
                        response = redirect(f"https://localhost:3000?{params}")
                        return response

                else:

                    return Response(
                        {'detail': 'Problem z żądaniem', "code": "595"},
                        status=status.HTTP_400_BAD_REQUEST
                    )
            else:

                return Response(
                    {'detail': 'Problem z żądaniem', "code": "595"},
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
                {'detail': 'Coś poszło nie tak z próbą logowania kontem facebook',
                    "code": "1165"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
