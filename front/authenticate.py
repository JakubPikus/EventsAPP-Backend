from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken, AuthenticationFailed
from rest_framework_simplejwt.settings import api_settings
from rest_framework.response import Response
from rest_framework import status
from django.utils.translation import gettext_lazy as _
from django.conf import settings
from rest_framework.authentication import CSRFCheck
from rest_framework import exceptions


class CustomAuthentication(JWTAuthentication):

    def enforce_csrf(self, request):
        def dummy_get_response(request):
            return None

        check = CSRFCheck(dummy_get_response)
        check.process_request(request)
        reason = check.process_view(request, None, (), {})
        if reason:
            raise exceptions.PermissionDenied('CSRF Failed: %s' % reason)

    def authenticate(self, request):

        header = self.get_header(request)
        raw_token = request.COOKIES.get(settings.SIMPLE_JWT['AUTH_COOKIE'])

        if header is None:
            raw_token = request.COOKIES.get(
                settings.SIMPLE_JWT['AUTH_COOKIE']) or None
        else:
            raw_token = self.get_raw_token(header)
        if raw_token is None:
            return None

        validated_token = self.get_validated_token(raw_token)

        self.enforce_csrf(request)

        # return self.get_user(validated_token), validated_token

        try:
            user = self.get_user(validated_token)
            return user, validated_token
        except exceptions.AuthenticationFailed as e:
            print("User usunięty")
