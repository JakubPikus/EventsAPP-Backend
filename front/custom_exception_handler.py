from django.http import Http404
from rest_framework import exceptions, status
from django.core.exceptions import PermissionDenied
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework.response import Response
from django.db import connections
from django.conf import settings


def remove_cookies(data, status, headers):
    response = Response(data=data, status=status, headers=headers)

    response.set_cookie(
        key=settings.SIMPLE_JWT['AUTH_COOKIE'],
        value="",
        expires=0,
        max_age=0,
        secure=True,
        httponly=settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
        samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE']
    )

    response.set_cookie(
        key=settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'],
        value="",
        expires=0,
        max_age=0,
        secure=True,
        httponly=settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
        samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE']
    )
    response.set_cookie(
        key="csrftoken",
        value="",
        expires=0,
        max_age=0,
        secure=True,
        samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE']
    )

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

    return response


def set_rollback():
    for db in connections.all():
        if db.settings_dict['ATOMIC_REQUESTS'] and db.in_atomic_block:
            db.set_rollback(True)


def custom_exception_handler(exc, context):

    if isinstance(exc, Http404):
        exc = exceptions.NotFound()
    elif isinstance(exc, PermissionDenied):
        exc = exceptions.PermissionDenied()

    if isinstance(exc, exceptions.APIException):
        headers = {}
        if getattr(exc, 'auth_header', None):
            headers['WWW-Authenticate'] = exc.auth_header
        if getattr(exc, 'wait', None):
            headers['Retry-After'] = '%d' % exc.wait
        if isinstance(exc.detail, (list, dict)):
            data = exc.detail
        else:
            data = {'detail': exc.detail}

        set_rollback()
        if isinstance(exc, InvalidToken):
            response = remove_cookies(data, 419, headers)
            return response
        else:
            return Response(data, status=exc.status_code, headers=headers)

    return None
