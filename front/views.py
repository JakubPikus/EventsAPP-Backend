from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import permissions, status, serializers, authentication, pagination
from rest_framework.throttling import AnonRateThrottle
from rest_framework.parsers import MultiPartParser, FormParser
from front.models import MyUser, CodeRegistration, IPAddress, IPAddressValidator, GmailUser, FacebookUser, Event, Category, City, Province, CommentEvent, CommentEventReaction, CommentEventReport, Friendship_Request, EventImage, Series, EventReport, County, Badge, BadgeCode, BadgeReport, CustomOutstandingToken, CustomBlacklistedToken, ChangeEmailWaiting, AdminLog, ActiveMessage, Notification, NotificationsForUser, DeleteModel, Ticket, OrderedTicket, Order, Paycheck, GatewayPaycheck, AwaitingsTicketsRefund
from .serializers import UserSerializer, RegisterSerializer, LoginSerializer, LogoutSerializer, EventEditSerializer, AccountConfirmSerializer, PasswordResetSerializer, PasswordResetConfirmSerializer, LoginGoogleSerializer, LoginFacebookSerializer, CategorySerializer, ProvinceSerializer, CitySerializer, CheckUserLocationSerializer, EventSerializer, EventHomescreenSerializer, CommentEventSerializer, CommentEventReactionSerializer, CommentEventReportSerializer, UserFriendsSerializer, UserEventsSerializer, UserParticipateSerializer, EventParticipantsSerializer, FriendsActionSerializer, FriendsRequestReactionSerializer, EventViewSerializer, EventAddSerializer, SeriesSerializer, EventReportSerializer, EventsViaSeriesSerializer, EventsNoSeriesSerializer, EventsEditSeriesSerializer, SeriesEditSerializer, EventsViaCalendarSerializer, EventsRandomSerializer, EventsRandomReactionSerializer, EventsProvinceMapSerializer, EventsCountyMapSerializer, FindFriendsSerializer, EventsViaBadgesSerializer, BadgesCodesListSerializer, BadgesCodesCreateSerializer, BadgeEditSerializer, BadgeCreateSerializer, BadgeDeleteSerializer, UserBadgesCreatedSerializer, UserBadgesActivatedSerializer, BadgeActivateSerializer, BadgeCodesReturnedUsedSerializer, BadgeReportSerializer, UserLoginLocationsSerializer, LogoutFromDevicesSerializer, UserBlockUsersSerializer, FriendsRemoveSerializer, PasswordChangeSerializer, EmailChangeSerializer, EmailChangeConfirmSerializer, UserEditSerializer, BadgesViaSettingsSerializer, AdminLogsSerializer, AdminReportsBadgesSerializer, AdminReportsEventsSerializer,  AdminReportsCommentsSerializer, AdminReportedValidateSerializer, AdminLogExistingSerializer, AdminCommentReportedValidateSerializer, AdminAwaitingsEventsSerializer, AdminAwaitingsBadgesSerializer, AdminReportsInputSerializer, AdminAwaitingsInputSerializer, AdminAwaitedValidateSerializer, AdminBanUsersIPSerializer, AdminBanUsersSerializer, AdminBanIPsSerializer, AdminBanValidateSerializer, AdminAccountsLogoutSerializer, FriendsListSerializer, LastMessagesListSerializer, UserConversationSerializer, FriendshipListSerializer, FindProfileByIdSerializer, NotificationsListSerializer, EventTicketsViewSerializer, BankNumberViewSerializer, EventsViaTicketsSerializer, TicketEditSerializer, TicketDeleteSerializer, TicketPaySerializer, OrderedTicketsSerializer, TicketRefundSerializer, OrderedTicketActionSerializer, SoldTicketsViaCalendarSerializer, AdminPaychecksEventsSerializer, AdminAwaitingsTicketsSerializer, AdminPaychecksSerializer, AdminAwaitedValidateTicketsSerializer, AdminPaychecksTicketsSerializer, AdminPaycheckGatewaySerializer, AdminMissingTicketsPaycheckSerializer, AdminTicketPaycheckValidateSerializer, TicketValidateSerializer
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken, Token
from rest_framework_simplejwt.token_blacklist import models as blacklist_models
from django.contrib.auth import authenticate, get_user_model
from django.conf import settings
from django.middleware import csrf
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import ensure_csrf_cookie
from django.template.loader import render_to_string, get_template
from django.core.mail import EmailMessage
from rest_framework_simplejwt.exceptions import TokenError
from django.core.exceptions import ValidationError
from rest_framework.exceptions import NotFound, AuthenticationFailed
from django.core.paginator import InvalidPage
from urllib.parse import urlencode, urlparse, urlunparse, parse_qs
from django.shortcuts import redirect
from django.contrib.gis.db.models.functions import Distance, AsGeoJSON
from django.db.models import Count, Value, CharField, F, Case, When, Max, Min, Sum, BooleanField, Q, OuterRef, Subquery, Exists, ExpressionWrapper, CharField, Func, DecimalField,DateTimeField, ManyToManyField, Prefetch, IntegerField, fields, AutoField, BigIntegerField
from django.db.models.functions import Concat, JSONObject, Length, Coalesce, Cast
from django.db.models.fields.json import KeyTextTransform
from django.contrib.postgres.aggregates import ArrayAgg, JSONBAgg
from django.contrib.postgres.fields import ArrayField, JSONField
from django.contrib.postgres.expressions import ArraySubquery
from django.forms.models import model_to_dict
from django.db import connection
from user_agents import parse
from django.utils.dateparse import parse_date
from decimal import Decimal, InvalidOperation
from xhtml2pdf import pisa
from collections import defaultdict
from PIL import Image
from io import BytesIO
from functools import reduce 
import PyPDF2
import requests
import datetime
import random
import math
import os
import calendar
import ast
import base64
import json
import re
import stripe
import time
from django.apps import apps
from django.contrib.gis.measure import D
from django.contrib.gis.geos import Point
from datetime import timedelta
from django.utils import timezone
from .custom_refresh_token import CustomRefreshToken
from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
from django.db.models.expressions import RawSQL
from django.contrib.admin.models import ADDITION, LogEntry
from django.http import QueryDict, HttpResponse
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from ips_config import BACKEND_IP, FRONTEND_IP



def get_location_from_ip(ip_address):

    # endpoint = f"https://freeipapi.com/api/json/{ip_address}"
    # response = requests.get(endpoint)
    # data = response.json()
    # latitude = float(data['latitude'])
    # longitude = float(data['longitude'])

    latitude = 52.881409
    longitude = 20.619961

    closest_city = City.objects.annotate(distance=Distance(
        'geo_location', Point(longitude, latitude, srid=4326))).order_by('distance').first()

    return closest_city


def email_verification(request, subject, user, ip_address):
    mail_subject = subject
    message = render_to_string('template_email.html', {
        'username': user.username,
        'code': CodeRegistration.objects.filter(user=user).last().code_random,
        'ip_address': ip_address,
        'protocol': 'https' if request.is_secure() else 'http'
    })
    email = EmailMessage(mail_subject, message, to=[user.email])
    return email


def get_tokens_for_user(user, ip_validator):

    refresh = CustomRefreshToken.for_user(user, ip_validator)

    tokens = {
        'refresh_token': str(refresh),
        'access_token': str(refresh.access_token),
    }

    return tokens


def remove_cookies(status):
    response = Response(status=status)
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


def add_cookies(value, status):
    response = Response(status=status)
    response.set_cookie(
        key=settings.SIMPLE_JWT['AUTH_COOKIE'],
        value=value["access_token"],
        expires=datetime.datetime.strftime(datetime.datetime.utcnow(
        ) + settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'], "%a, %d-%b-%Y %H:%M:%S GMT",),
        secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
        httponly=settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
        samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE']
    )

    response.set_cookie(
        key=settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'],
        value=value["refresh_token"],
        expires=datetime.datetime.strftime(datetime.datetime.utcnow(
        ) + settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'], "%a, %d-%b-%Y %H:%M:%S GMT",),
        secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
        httponly=settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
        samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE']
    )
    return response


def check_banned_status(user_id, ip_address):

    if MyUser.objects.filter(id=user_id).exists():

        user = MyUser.objects.get(id=user_id)

        if IPAddress.objects.filter(ip_address=ip_address).exists():

            ip_address_obj = IPAddress.objects.get(
                ip_address=ip_address)

            if ip_address_obj.is_banned:
                response = remove_cookies(421)
                response.data = {
                    "detail": "Zostałeś wylogowany", "code": "421"}
                return response

            elif user.is_banned:
                response = remove_cookies(422)
                response.data = {
                    "detail": "Zostałeś wylogowany", "code": "422"}
                return response

            if IPAddressValidator.objects.filter(user=user, ip_address=ip_address_obj).exists():
                ip_validator = IPAddressValidator.objects.get(
                    user=user, ip_address=ip_address_obj)

                if ip_validator.is_verificated == False:
                    response = remove_cookies(420)
                    response.data = {
                        "detail": "Zostałeś wylogowany z konta", "code": "420"}
                    return response

            else:
                response = remove_cookies(420)
                response.data = {
                    "detail": "Administracja usunęła twoją validację do konta", "code": "420"}
                return response
        else:
            response = remove_cookies(424)
            response.data = {
                "detail": "Administracja usunęła twój Adres IP", "code": "424"}
            return response
    else:
        response = remove_cookies(423)
        response.data = {
            "detail": "Użytkownik został usunięty", "code": "423"}
        return response


def token_verify(request):

    if request.COOKIES.get(settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH']) is not None and request.COOKIES.get(settings.SIMPLE_JWT['AUTH_COOKIE']) is None:
        return Response(
            {"detail": "Token wygasł lub go brak", "code": "401"},
            status=status.HTTP_403_FORBIDDEN
        )

    elif request.COOKIES.get(settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH']) is None and request.COOKIES.get(settings.SIMPLE_JWT['AUTH_COOKIE']) is None:
        response = remove_cookies(420)

        response.data = {
            "detail": "Użytkownik nie jest zalogowany", "code": "420"}
        return response

    else:
        response_banned = check_banned_status(
            request.user.id, request.META.get('REMOTE_ADDR'))
        if response_banned is not None:
            return response_banned


def admin_verify(request):

    if MyUser.objects.filter(username=request.user.username).exists():

        user = MyUser.objects.get(id=request.user.id)

        if user.is_admin == False:
            response = Response(status=425)
            response.data = {
                "detail": "Użytkownik nie jest administratorem.", "code": "430"}
            return response


def actual_comments(user, slug, uuid):

    subquery_report_type = CommentEventReport.objects.filter(
        comment__pk=OuterRef('pk'), user=user
    ).values('type')[:1]

    subquery_my_reaction = CommentEventReaction.objects.filter(comment__id=OuterRef('id'), user=user).values('type')[:1]

    filter_admin = {}

    if user.is_admin:
        filter_admin['text_comment'] = F('text')

    else:
        filter_admin['text_comment'] = Case(When(is_blocked=True, then=None), default=F('text'), output_field=CharField())


    comments = CommentEvent.objects.select_related('author', 'event').filter(event__slug__iexact=slug, event__uuid=uuid).annotate(author_image=F(
        'author__image_thumbnail'), my_reaction=Subquery(subquery_my_reaction), my_report=Subquery(subquery_report_type), **filter_admin).order_by('-id')





    # if user.is_admin:
    #     comments = CommentEvent.objects.select_related('author', 'event').filter(event__slug__iexact=slug, event__uuid=uuid).annotate(author_image=F(
    #         'author__image_thumbnail'), my_reaction=Subquery(subquery_my_reaction), my_report=Subquery(subquery_report_type), text_comment=F('text')).order_by('-id')
    # else:
    #     comments = CommentEvent.objects.select_related('author', 'event').filter(event__slug__iexact=slug, event__uuid=uuid).annotate(author_image=F(
    #         'author__image_thumbnail'), my_reaction=Subquery(subquery_my_reaction), my_report=Subquery(subquery_report_type), text_comment=Case(When(is_blocked=True, then=None), default=F('text'), output_field=CharField())).order_by('-id')

    count = comments.count()
    comments_filtered = comments.filter(
        parent_comment=None)

    comments_filtered = CommentEventSerializer(
        comments_filtered, many=True, context={'is_admin': user.is_admin})

    return comments_filtered, count


def is_valid_datetime_format(s):
    pattern = r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$'
    return bool(re.match(pattern, s))




def append_extra_data_notification(input, key, array, self_id, status):



    if key == "Event":
        events_images_thumbnail = EventImage.objects.filter(event__id__in=array, main=True).annotate(id_event=F('event__id')).values('id_event', 'image_thumbnail' )

        for event_instance in events_images_thumbnail:
            if status:
                input[key][event_instance['id_event']].image_thumbnail = event_instance['image_thumbnail']
            else:
                input.image_thumbnail = event_instance['image_thumbnail']


    elif key == "CommentEvent":

        subquery_image_commentevent_notification = EventImage.objects.filter(event__event__id=OuterRef('id'), main=True).values('image_thumbnail')

        commentevents_images_thumbnail = CommentEvent.objects.filter(id__in=array).annotate(image_thumbnail=Subquery(subquery_image_commentevent_notification), slug=F('event__slug'), uuid=F('event__uuid'), title=F('event__title')).values('id', 'image_thumbnail', 'slug', 'uuid', 'title')

        for commentevent_instance in commentevents_images_thumbnail:

            if status:

                input[key][commentevent_instance['id']].image_thumbnail = commentevent_instance['image_thumbnail']
                input[key][commentevent_instance['id']].slug = commentevent_instance['slug']
                input[key][commentevent_instance['id']].uuid = commentevent_instance['uuid']
                input[key][commentevent_instance['id']].title = commentevent_instance['title']

            else:
                input.image_thumbnail = commentevent_instance['image_thumbnail']
                input.slug = commentevent_instance['slug']
                input.uuid = commentevent_instance['uuid']
                input.title = commentevent_instance['title']

    elif key == "IPAddress":

        subquery_image_ipaddress_notification = MyUser.objects.filter(id=self_id).values('image_thumbnail')

        ipaddress_images_thumbnail = IPAddress.objects.filter(id__in=array).annotate(image_thumbnail=Subquery(subquery_image_ipaddress_notification)).values('id', 'image_thumbnail')
        
        for ipaddress_instance in ipaddress_images_thumbnail:

            if status:
                input[key][ipaddress_instance['id']].image_thumbnail = ipaddress_instance['image_thumbnail']
            else:
                input.image_thumbnail = ipaddress_instance['image_thumbnail']




    elif key == "Ticket":


        subquery_image_ticket_notification = EventImage.objects.filter(event__tickets_of_event__id=OuterRef('id'), main=True).values('image_thumbnail')

        tickets_images_thumbnail = Ticket.objects.filter(id__in=array).annotate(image_thumbnail=Subquery(subquery_image_ticket_notification)).values('id', 'image_thumbnail', 'event_id')



        for ticket_instance in tickets_images_thumbnail:

            if status:
                input[key][ticket_instance['id']].image_thumbnail = ticket_instance['image_thumbnail']
                input[key][ticket_instance['id']].event_id = ticket_instance['event_id']
            else:
                input.image_thumbnail = ticket_instance['image_thumbnail']
                input.event_id = ticket_instance['event_id']

    elif key == "Order": # DO INFORMOWANIA WEBSOCKETEM O ZWROTACH ZE SPRITE

        subquery_image_order_notification = EventImage.objects.filter(event__tickets_of_event__orders_of_tickets__order__id=OuterRef('id'), main=True).distinct().values('image_thumbnail')[:1]

        subquery_used_ids = OrderedTicket.objects.filter(order__user__id=self_id, used=True, ticket__event__id=OuterRef('ordered_tickets__ticket__event_id')).values_list('id', flat=True)

        
        subquery_refunded_paid_ids = OrderedTicket.objects.filter(Exists(Paycheck.objects.filter(tickets__id=OuterRef('id'))), order__user__id=self_id, refunded=True, ticket__event__id=OuterRef('ordered_tickets__ticket__event_id')).values_list('id', flat=True)

        subquery_refunded_not_paid_ids = OrderedTicket.objects.filter(~(Exists(Paycheck.objects.filter(tickets__id=OuterRef('id')))), order__user__id=self_id, refunded=True, ticket__event__id=OuterRef('ordered_tickets__ticket__event_id')).values_list('id', flat=True)


        subquery_exists_stripe_order_refund = Paycheck.objects.filter(tickets__order__id=OuterRef('id'), stripe_refund_checkout_mode=True).order_by('created_at').values('created_at')[:1]

        subquery_order_refund_information = Order.objects.filter(Exists(Paycheck.objects.filter(stripe_refund_checkout_mode=True, tickets__order__id=(OuterRef('id')))) , user__id=self_id, ordered_tickets__ticket__event__id=OuterRef('ordered_tickets__ticket__event_id')).annotate(data=JSONObject(id=F('id'), stripe_refund_order=Subquery(subquery_exists_stripe_order_refund))).distinct().values('data')


        orders_images_thumbnail = Order.objects.filter(id__in=array).annotate(image_thumbnail=Subquery(subquery_image_order_notification), used_ids=ArraySubquery(subquery_used_ids), refunded_paid_ids=ArraySubquery(subquery_refunded_paid_ids), refunded_not_paid_ids=ArraySubquery(subquery_refunded_not_paid_ids), order_refund_information=ArraySubquery(subquery_order_refund_information)).values('id', 'image_thumbnail', 'used_ids', 'refunded_paid_ids', 'refunded_not_paid_ids', 'ordered_tickets__ticket__event_id', 'order_refund_information')



        for order_instance in orders_images_thumbnail:

            if status:
                input[key][order_instance['id']].image_thumbnail = order_instance['image_thumbnail']
                input[key][order_instance['id']].used_ids = order_instance['used_ids']
                input[key][order_instance['id']].refunded_paid_ids = order_instance['refunded_paid_ids']
                input[key][order_instance['id']].refunded_not_paid_ids = order_instance['refunded_not_paid_ids'] 
                input[key][order_instance['id']].event_id = order_instance['ordered_tickets__ticket__event_id'] 
                input[key][order_instance['id']].order_refund_information = order_instance['order_refund_information'] 
                
            else:
                input.image_thumbnail = order_instance['image_thumbnail']
                input.used_ids = order_instance['used_ids']
                input.refunded_paid_ids = order_instance['refunded_paid_ids']
                input.refunded_not_paid_ids = order_instance['refunded_not_paid_ids']
                input.event_id  = order_instance['ordered_tickets__ticket__event_id']
                input.order_refund_information  = order_instance['order_refund_information']
                

    elif key == "AwaitingsTicketsRefund":  # PRZYPADEK GDY AUTOMATYCZNY SYSTEM ZWROTOW CHCE ZWROCIC BILETY, ALE USER POSIADA ZAMOWIENIA W KTORYCH WCZESNIEJ ZWROCIL BILET/UZYL JAKIS, A W DANEJ CHWILI NIE MA PODLACZONEGO KONTA BANKOWEGO

        subquery_orders_refund_amount = OrderedTicket.objects.filter(awaitingsticketsrefund__id=OuterRef('id')).values('order__id').annotate(data=JSONObject(order_id=F('order__id'), amount_total=Sum('purchase_price'))).values('data')
        

        subquery_image_awaitings = EventImage.objects.filter(event__tickets_of_event__orders_of_tickets__awaitingsticketsrefund__id=OuterRef('id'), main=True).distinct().values('image_thumbnail')[:1]

        orders_images_thumbnail = AwaitingsTicketsRefund.objects.filter(id=array[0]).annotate(image_thumbnail=Subquery(subquery_image_awaitings), orders_refund_amount=ArraySubquery(subquery_orders_refund_amount)).values('id', 'image_thumbnail', 'orders_refund_amount')


        for awaitings_instance in orders_images_thumbnail:
            if status:
                input[key][awaitings_instance['id']].image_thumbnail = awaitings_instance['image_thumbnail']
                input[key][awaitings_instance['id']].orders_refund_amount = awaitings_instance['orders_refund_amount']

            else: 
                input.image_thumbnail = awaitings_instance['image_thumbnail']
                input.orders_refund_amount = awaitings_instance['orders_refund_amount']


    elif key == "GatewayPaycheck": # DO INFORMOWANIA O WYKONANIU PRZEZ ADMINISTRATORA ZWROTU PRZELEWOWEGO ZA ZWRÓCONY BILET/WYPLATE ZA WYDARZENIE

       

        subquery_image_event = EventImage.objects.filter(event__gatewaypaycheck__id=OuterRef('id'), main=True).values('image_thumbnail')

        subquery_image_ticket = EventImage.objects.filter(event__tickets_of_event__orders_of_tickets__gatewaypaycheck__id=OuterRef('id'), main=True).distinct().values('image_thumbnail')




        subquery_paycheck_attachments_event = Paycheck.objects.filter(gatewaypaycheck__id=OuterRef('id')).annotate(data=JSONObject(id=F('id'), file=F('refund_confirmation'))).values('data')


        subquery_paycheck_attachments_tickets = Paycheck.objects.filter(gatewaypaycheck__id=OuterRef('id')).values('tickets__order__id').annotate(data=JSONObject(order_id=F('tickets__order__id'), id=F('id'), tickets_details=ArrayAgg(Concat(F('tickets__first_name'), Value(' '), F('tickets__last_name'))), file=F('refund_confirmation'))).values('data')


        subquery_jsonb_django_problem_event = GatewayPaycheck.objects.filter(id=OuterRef('id')).annotate(data=JSONObject(data=Subquery(subquery_paycheck_attachments_event))).values('data')

        subquery_jsonb_django_problem_tickets = GatewayPaycheck.objects.filter(id=OuterRef('id')).annotate(data=JSONObject(data=ArraySubquery(subquery_paycheck_attachments_tickets))).values('data')
        
        # Django ma problem w wykonaniu Case When z output_field ustawionym na ArrayField(JSONObject())

        


        gateways_images_thumbnail = GatewayPaycheck.objects.filter(id__in=array).annotate(image_thumbnail=
        Case(
            When(Exists(Event.objects.filter(id=OuterRef('event__id'))), then=Subquery(subquery_image_event) ),
            default=Subquery(subquery_image_ticket),
            output_field=CharField()
        ),
        paycheck_attachments = Case(
            When(Exists(Event.objects.filter(id=OuterRef('event__id'))), then=Subquery(subquery_jsonb_django_problem_event)),
            default=Subquery(subquery_jsonb_django_problem_tickets),
            output_field=JSONField()
        ),
        ).values('id', 'image_thumbnail', 'paycheck_attachments')


        for gateway_instance in gateways_images_thumbnail:

        
            if status:
                input[key][gateway_instance['id']].image_thumbnail = gateway_instance['image_thumbnail']
                input[key][gateway_instance['id']].paycheck_attachments = gateway_instance['paycheck_attachments']
            else:
                input.image_thumbnail = gateway_instance['image_thumbnail']
                input.paycheck_attachments = gateway_instance['paycheck_attachments']
  
    return input



def send_websocket_notification(users_array, id_notification, object, datetime, status_allow_self_user):

    for user in users_array:

        notification = user.user_notifications.new_notification(id_notification, object, datetime)


        if status_allow_self_user == True:
            notification['user'] = {"id": user.id, "username": user.username, "image_thumbnail": user.image_thumbnail.name}

        user_id_str = str(user.id)

        
        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.group_send)(
            user_id_str,
            {
                'type': 'send_notification',
                'notification': notification,
            }
        )


def check_orderedtickets_ids(orderedticket_ids):

    response = None
    set_orderedticket_ids = None



    if orderedticket_ids == "":

        response = Response(
                {'detail': 'Przesyłana wartość nie może być pusta.',
                    "code": "9011"},
                status=status.HTTP_400_BAD_REQUEST
            )


    elif not isinstance(orderedticket_ids, list):
        

        try:
            literal_eval_orderedticket_ids = ast.literal_eval(
                orderedticket_ids)
            

            if not len(literal_eval_orderedticket_ids) == 0:

                set_orderedticket_ids = set(literal_eval_orderedticket_ids)

                
            else:
                response = Response(
                    {'detail': 'Lista biletów musi określać przynajmniej 1 bilet.',
                        "code": "9011"},
                    status=status.HTTP_400_BAD_REQUEST
                )


        except:

            response = Response(
                {'detail': 'Przesyłana wartość musi mieć format list z liczbami określającymi ID zamówionych biletów.',
                    "code": "9011"},
                status=status.HTTP_400_BAD_REQUEST
            )
    elif not len(orderedticket_ids) == 0:
        set_orderedticket_ids = set(orderedticket_ids)


    else:
        response = Response(
                {'detail': 'Lista musi określać przynajmniej 1 obiekt.',
                    "code": "9011"},
                status=status.HTTP_400_BAD_REQUEST
            )
    return response, set_orderedticket_ids



def check_file_is_pdf(file):
    response = None
    try:
        reader = PyPDF2.PdfReader(file)
        if not len(reader.pages) > 0:
            response = Response(
                    {'detail': 'Podany plik nie jest formatu PDF.',
                        "code": "2166"},
                    status=status.HTTP_400_BAD_REQUEST
                )
    except Exception as e:
        response = Response(
                {'detail': 'Podany plik nie jest formatu PDF.',
                    "code": "2166"},
                status=status.HTTP_400_BAD_REQUEST
            )
    return response





# THROTTLING BLOCK
class LogoutView(APIView):
    serializer_class = LogoutSerializer
    permission_classes = (permissions.AllowAny, )
    throttle_classes = []

    def post(self, request):
        try:
            # response_verify = token_verify(request)
            # if response_verify is not None:
            #     return response_verify
            # else:

            try:
                refreshToken = request.COOKIES.get(
                    settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'])
                # token = RefreshToken(refreshToken)

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

            # 118143322891147953844

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

                # https://graph.facebook.com/me?fields=id,first_name,last_name,email,picture&access_token=EAALAspc7n18BAG7m09lUKd3aEaEuLrPMitRgiS3oivMjY0tXZCeE7uTkZCZC5wWXh0JSczUCgJXgah8c8ElCiZCQAydIZCNuMno9SqarZA7vaEZAdYp6TF2hVvR0SYFf7g7OFqHcZBcm414ZB4By6Cz5RmhY3t0Kkl7jZA68XZAaVonYNMgmwnFlyxIMYAC25kHHmZBsyWrzTZBLRJbOIoyOWKrZBHGRurujM7X1xapZCflpfDtnQZDZD
                # 9364677030240030
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

        


        location_list = list(Event.objects.select_related('user', 'category', 'city', 'series').annotate(province=F('city__county__province__name'), image=Subquery(EventImage.objects.filter(
            event=OuterRef('pk'), main=True).values('image_thumbnail')),location_distance=Distance('city__geo_location', user.city.geo_location), num_reputation=Subquery(subquery_num_reputation), gps_googlemap=Concat(Value('https://www.google.com/maps/dir/?api=1&origin='), user.city.geo_location[1], Value(','), user.city.geo_location[0], Value('&destination='),  output_field=CharField()), user_image=F('user__image_thumbnail'), series_events=ArraySubquery(subquery_series_events), series_details=F('series__description')   ).filter(
            pk__in=location_pks))

        random_list = list(Event.objects.select_related('user', 'category', 'city', 'series').annotate(province=F('city__county__province__name'), image=Subquery(EventImage.objects.filter(
            event=OuterRef('pk'), main=True).values('image_thumbnail')), location_distance=Distance('city__geo_location', user.city.geo_location), num_reputation=Subquery(subquery_num_reputation), gps_googlemap=Concat(Value('https://www.google.com/maps/dir/?api=1&origin='), user.city.geo_location[1], Value(','), user.city.geo_location[0], Value('&destination='),  output_field=CharField()), user_image=F('user__image_thumbnail'), series_events=ArraySubquery(subquery_series_events), series_details=F('series__description')).filter(
            pk__in=random_pks))

        popular_list = list(Event.objects.select_related('user', 'category', 'city', 'series').annotate(province=F('city__county__province__name'), image=Subquery(EventImage.objects.filter(
            event=OuterRef('pk'), main=True).values('image_thumbnail')), location_distance=Distance('city__geo_location', user.city.geo_location), num_reputation=Subquery(subquery_num_reputation), gps_googlemap=Concat(Value('https://www.google.com/maps/dir/?api=1&origin='), user.city.geo_location[1], Value(','), user.city.geo_location[0], Value('&destination='),  output_field=CharField()), user_image=F('user__image_thumbnail'), series_events=ArraySubquery(subquery_series_events), series_details=F('series__description')).filter(
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
    # serializer_class = CitySerializer

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
                            # if user.city != closest_city:

                            #     return Response(
                            #         {'success': "Wykryto nową lokalizację", 'city': CitySerializer(
                            #             closest_city).data, 'code': "9600"},
                            #         status=status.HTTP_201_CREATED
                            #     )
                            # else:
                            #     return Response(
                            #         {'success': 'Wykryto to same miasto', "code": "7669"},
                            #         status=220
                            #     )
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


class EventsPagePagination(pagination.PageNumberPagination):
    page_size = 50
    page_query_param = 'page'

    def paginate_queryset_custom(self, queryset, request, view=None):

        page_size = self.get_page_size(request)
        if not page_size:
            return None

        paginator = self.django_paginator_class(queryset, page_size)
        page_number = self.get_page_number(request, paginator)

        try:
            self.page = paginator.page(page_number)
        except InvalidPage as exc:

            if not page_number.isdigit() or int(page_number) == 0:
                self.page = paginator.page(1)

            elif int(page_number) > paginator.num_pages:
                self.page = paginator.page(paginator.num_pages)

            else:
                msg = self.invalid_page_message.format(
                    page_number=page_number, message=str(exc)
                )
                raise NotFound(msg)

        if paginator.num_pages > 1 and self.template is not None:
            self.display_page_controls = True

        self.request = request
        return list(self.page)

    def get_paginated_response_custom(self, serializer, events_data, category, value_not_found):

        page_delete = False

        parsed_url = urlparse(self.request.build_absolute_uri())
        params = parse_qs(parsed_url.query)

        for key in value_not_found.keys():
            if key in params and value_not_found[key] is not None:
                del params[key]
                if key == "page":
                    page_delete = True

        if page_delete is True or ('page' in params and not params['page'][0].isdigit()):
            del params['page']
        elif 'page' in params:
            if int(params['page'][0]) == 0:
                del params['page']
            else:
                params['page'] = [self.page.number]

        parsed_url = parsed_url._replace(query=urlencode(params, doseq=True))
        new_url = urlunparse(parsed_url)

        events = {
            'links': {
                'next': self.get_next_link(),
                'previous': self.get_previous_link(),
                'current': new_url
            },
            'count': self.page.paginator.count,
            'category': category
        }
        data = serializer(events_data, many=True).data

        return events, data

    def generate(self, events_data, serializer, category, value_not_found, request):
        events = self.paginate_queryset_custom(events_data, request)
        output_events, output_data = self.get_paginated_response_custom(
            serializer, events, category, value_not_found)
        return output_events, output_data


class EventsListView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = EventSerializer
    pagination_class = EventsPagePagination

    def get(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                excluded_params = ["name", "province", "city", "distance",
                                   "category", "starDate", "endDate", "page", "ordering"]
                name = request.GET.get('name', None)
                province = request.GET.get('province', None)
                city = request.GET.get('city', None)
                distance = request.GET.get('distance', None)
                category = request.GET.get('category', None)
                startDate = request.GET.get('startDate', None)
                endDate = request.GET.get('endDate', None)
                page = request.GET.get('page', None)
                ordering = request.GET.get('ordering', 'newest')
                value_not_found = {}

                for key, value in request.GET.items():
                    if key not in excluded_params:
                        value_not_found[key] = value

                queryset = None

                filter_list = {'verificated': "verificated",
                               'event_date__gte': timezone.now()}
                distance_true = False
                category_paginate = None
                order_by = None

                if ordering == "newest":
                    order_by = '-id'
                elif ordering == "location":
                    order_by = 'location_distance'
                elif ordering == "popularity":
                    order_by = '-num_reputation'
                elif ordering == "event_date":
                    order_by = 'event_date'
                else:
                    value_not_found["ordering"] = ordering
                    order_by = '-id'

                if name != None:
                    filter_list['title__icontains'] = name
                else:
                    value_not_found["name"] = name

                if category != None and Category.objects.filter(type=category).exists():
                    filter_list['category__type'] = category
                    category_paginate = category
                else:
                    value_not_found["category"] = category

                if startDate != None and endDate != None:

                    filter_list['event_date__range'] = [
                        startDate, endDate]
                else:
                    value_not_found["startDate"] = startDate
                    value_not_found["endDate"] = endDate

                if province != None and Province.objects.filter(name=province).exists():
                    filter_list['city__county__province__name'] = province

                    if city != None and City.objects.filter(county__province__name=province, name=city).exists():

                        filter_list['city__name'] = city

                        if distance != None and distance.isdigit():
                            origin_city = City.objects.get(
                                county__province__name=province, name=city)

                            del filter_list['city__county__province__name']
                            del filter_list['city__name']

                            distance_true = True

                        else:
                            value_not_found["distance"] = distance

                    else:
                        value_not_found["city"] = city
                        value_not_found["distance"] = distance
                else:
                    value_not_found["province"] = province
                    value_not_found["city"] = city
                    value_not_found["distance"] = distance

                user = request.user

                subquery_num_reputation = Event.objects.filter(pk=OuterRef(
                    'pk')).annotate(num_reputation=Count('participants_event')).values('num_reputation')

                subquery_participant_self = Event.objects.filter(pk=OuterRef('pk'),
                                                                 participants_event__username=user.username)

                subquery_main_image = EventImage.objects.filter(
                    event=OuterRef('pk'), main=True).values('image')

                time_now = timezone.now()

                if distance_true is False:
                    if order_by == 'location_distance':
                        value_not_found["ordering"] = ordering
                        order_by = '-id'

                    if len(filter_list) > 0:
                        print("e")
                        # num_reputation=Count('participants_event')
                        # Case(When(participants_event__username=user.username, then=True), default=False, output_field=BooleanField())

                        queryset = Event.objects.select_related('user', 'category', 'city').filter(
                            **filter_list).annotate(location_distance=Distance('city__geo_location', user.city.geo_location), num_reputation=Subquery(subquery_num_reputation), gps_googlemap=Concat(Value('https://www.google.com/maps/dir/?api=1&origin='), user.city.geo_location[1], Value(','), user.city.geo_location[0], Value('&destination='),  output_field=CharField()), province=F('city__county__province__name'), user_image=F('user__image_thumbnail'), participant_self=Exists(subquery_participant_self), current=ExpressionWrapper(Q(event_date__gte=time_now), output_field=BooleanField()), image=Subquery(subquery_main_image)).order_by(order_by)
                    else:
                        

                        queryset = Event.objects.select_related('user', 'category', 'city').all().annotate(location_distance=Distance('city__geo_location', user.city.geo_location), num_reputation=Subquery(subquery_num_reputation), gps_googlemap=Concat(Value(
                            'https://www.google.com/maps/dir/?api=1&origin='), user.city.geo_location[1], Value(','), user.city.geo_location[0], Value('&destination='),  output_field=CharField()), province=F('city__county__province__name'), user_image=F('user__image_thumbnail'), participant_self=Exists(subquery_participant_self), current=ExpressionWrapper(Q(event_date__gte=time_now), output_field=BooleanField()), image=Subquery(subquery_main_image)).order_by(order_by)[:300]
                else:

                    queryset = Event.objects.select_related('user', 'category', 'city').filter(**filter_list, city__in=City.objects.filter(geo_location__distance_lte=(
                        origin_city.geo_location, D(km=distance)))).annotate(location_distance=Distance('city__geo_location', origin_city.geo_location), num_reputation=Subquery(subquery_num_reputation), gps_googlemap=Concat(Value('https://www.google.com/maps/dir/?api=1&origin='), origin_city.geo_location[1], Value(','), origin_city.geo_location[0], Value('&destination='),  output_field=CharField()), province=F('city__county__province__name'), user_image=F('user__image_thumbnail'), participant_self=Exists(subquery_participant_self), current=ExpressionWrapper(Q(event_date__gte=time_now), output_field=BooleanField()), image=Subquery(subquery_main_image)).order_by(order_by)

                paginator = EventsPagePagination()


                events, data = paginator.generate(
                    queryset, EventSerializer, category_paginate, value_not_found, request)

                max_pages = math.ceil(events['count']/50)

                if not str(page).isdigit() or max_pages < int(page) or 1 > int(page):
                    value_not_found["page"] = page

                return Response(
                    {'success': 'Pobrano wydarzenia', 'events': events, 'value_not_found': value_not_found,
                        'data': data, "code": "7665"},
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


class EventView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = EventViewSerializer

    def delete(self, request, slug, uuid):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:

                if Event.objects.filter(slug=slug, uuid=uuid).exists():
                    event = Event.objects.get(slug=slug, uuid=uuid)
                    user = request.user

                    if event.user == user:
                        event.delete()
                        return Response(
                            {'success': 'Sukces',
                                "code": "1400"},
                            status=status.HTTP_200_OK)
                    else:

                        return Response(
                            {'detail': 'Nie możesz usunąć wydarzenia, które nie zostało utworzone przez Ciebie',
                                "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                else:

                    return Response(
                        {'detail': 'Nie istnieje takie wydarzenie',
                            "code": "1300"},
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

    def get(self, request, slug, uuid):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                if Event.objects.filter(slug=slug, uuid=uuid).exists():

                    user = request.user



                    ticket_filter = {}
                    ticket_annotate = {}

                    if not (user.is_admin or Event.objects.filter(slug=slug, uuid=uuid, user__id=user.id).exists()):
                        # ticket_filter['verificated'] = "verificated"
                        ticket_filter['was_allowed'] = True
                    else:
                        ticket_annotate['new_price'] = F('new_price')
                        
                        
                    subquery_num_reputation = Event.objects.filter(pk=OuterRef('pk')).values('pk').annotate(
                        num_reputation=Count('participants_event')
                    ).values('num_reputation')
                    


                    subquery_participant_self = Event.objects.filter(pk=OuterRef('pk'),
                                                                     participants_event__username=user.username)

                    subquery_image = EventImage.objects.filter(event__pk=OuterRef(
                        'pk')).annotate(data=JSONObject(id=F('id'), order=F('order'), image=F('image'))).values('data').order_by('order')

                    subquery_report_type = EventReport.objects.filter(
                        event__pk=OuterRef('pk'), user=user
                    ).values('type')[:1]


                    time_now = timezone.now()



                    subquery_my_tickets = OrderedTicket.objects.filter(ticket__id=OuterRef('id'), refunded=False, order__user__id=user.id).values('ticket__id').annotate(count=Count('ticket__id')).values('count')

                    subquery_my_not_paid_tickets = OrderedTicket.objects.filter(Q(order__is_paid=False)&Q(order__order_expires_at__gte=time_now), ticket__id=OuterRef('id'), order__user__id=user.id).values('ticket__id').annotate(count=Count('ticket__id')).values('count')


                    subquery_reserved_tickets = OrderedTicket.objects.filter((Q(order__is_paid=True)|Q(order__order_expires_at__gte=time_now))&Q(refunded=False), ticket__id=OuterRef('id')).annotate(count=Func(F('id'), function='Count')).values('count')


                    subquery_tickets = Ticket.objects.filter(event__pk=OuterRef('pk'), **ticket_filter).annotate(data=JSONObject(id=F('id'), ticket_type=F('ticket_type'),ticket_details=F('ticket_details'), verificated=F('verificated'), was_allowed=F('was_allowed'), default_price=F('default_price'), price=F('price'), quantity=F('quantity'), reserved_tickets=Coalesce(Subquery(subquery_reserved_tickets), Value(0)), my_tickets=Coalesce(Subquery(subquery_my_tickets), Value(0)), my_not_paid_tickets=Coalesce(Subquery(subquery_my_not_paid_tickets), Value(0)), **ticket_annotate)).values('data').order_by('-price')



                    event = Event.objects.select_related(
                        'user', 'category', 'city', 'series').annotate(location_distance=Distance('city__geo_location', user.city.geo_location), num_reputation=Subquery(subquery_num_reputation), gps_googlemap=Concat(Value('https://www.google.com/maps/dir/?api=1&origin='), user.city.geo_location[1], Value(','), user.city.geo_location[0], Value('&destination='),  output_field=CharField()), province=F('city__county__province__name'), user_image=F('user__image_thumbnail'), participant_self=Exists(subquery_participant_self), my_report=Subquery(subquery_report_type), current=Q(event_date__gte=time_now), series_details=F('series__description'),tickets=ArraySubquery(subquery_tickets), user_client=Value(user, output_field=CharField()), image=ArraySubquery(subquery_image)).get(slug__iexact=slug, uuid=uuid)




                    if event.verificated == "verificated" or user == event.user or user.is_admin == True:
                        if event.verificated == "rejected":
                            code = "1213"
                            response_text = "Wydarzenie jest przeznaczone do usunięcia."

                        else:
                            code = "7667"
                            response_text = "Pobrano wydarzenie"
                        event = EventViewSerializer(event)
                        return Response(
                            {'success': response_text,
                                'data': event.data, "code": code},
                            status=status.HTTP_200_OK
                        )
                    else:
                        return Response(
                            {'detail': 'Wydarzenie nie przeszło weryfikacji',
                                "code": "1201"},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                else:
                    return Response(
                        {'detail': 'Nie znaleziono takiego wydarzenia', "code": "1300"},
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


class CommentEventView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = CommentEventSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                data = request.data
                slug = data['slug']
                uuid = data['uuid']
                text = data['text']
                id_reply = data['id_reply']

                user = request.user

                if not text == "":

                    if Event.objects.filter(slug__iexact=slug, uuid=uuid).exists():

                        event = Event.objects.get(
                            slug__iexact=slug, uuid=uuid)

                        if event.verificated == "verificated":

                            if id_reply == "":
                                CommentEvent.objects.create(
                                    event=event, author=request.user, text=text)
                            else:
                                if CommentEvent.objects.filter(id=id_reply).exists():
                                    CommentEvent.objects.create(
                                        event=event, author=request.user, text=text, parent_comment=CommentEvent.objects.get(id=id_reply))
                                else:

                                    comments_filtered, count = actual_comments(
                                        user, slug, uuid)

                                    return Response(
                                        {'detail': 'Nie ma takiego komentarza do odpowiedzi', 'meta': {'count': count},
                                         'data': comments_filtered.data,
                                            "code": "1011"},
                                        status=222
                                    )

                            comments_filtered, count = actual_comments(
                                user, slug, uuid)

                            return Response(
                                {'success': 'Utworzono komentarz', 'meta': {'count': count},
                                    'data': comments_filtered.data, "code": "7667"},
                                status=status.HTTP_200_OK
                            )
                        else:

                            if user.is_admin:
                                return Response(
                                    {'detail': 'Można komentować tylko wydarzenia, które są w danej chwili zweryfikowane.', "is_admin": user.is_admin, "status": {"status": event.verificated, "details": event.verificated_details},
                                        "code": "9011"},
                                    status=223
                                )

                            elif event.user == user:
                                return Response(
                                    {'detail': 'Można komentować tylko wydarzenia, które są w danej chwili zweryfikowane.', "is_admin": "organizator", "status": {"status": event.verificated, "details": event.verificated_details},
                                        "code": "9011"},
                                    status=223
                                )

                            else:
                                return Response(
                                    {'detail': 'Można komentować tylko wydarzenia, które są w danej chwili zweryfikowane.', "is_admin": user.is_admin,
                                        "code": "9011"},
                                    status=223
                                )
                    else:
                        return Response(
                            {'detail': 'Wydarzenie nie istnieje',
                             "code": "9011"},
                            status=224
                        )
                else:
                    return Response(
                        {'detail': 'Nie możesz wstawić pustego komentarza',
                            "code": "9011"},
                        status=status.HTTP_400_BAD_REQUEST
                    )

        except ValidationError:

            return Response(
                {'detail': 'Błędne UUID', "code": "9011"},
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

    def get(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:

                slug = request.GET.get('slug', None)
                uuid = request.GET.get('uuid', None)

                user = request.user

                comments_filtered, count = actual_comments(user, slug, uuid)

                return Response(
                    {'success': 'Pobrano komentarze', 'meta': {'count': count},
                     'data': comments_filtered.data, "code": "7667"},
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

    def delete(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                data = request.data
                slug = data['slug']
                uuid = data['uuid']
                id = data['id']

                if Event.objects.filter(slug__iexact=slug, uuid=uuid).exists():

                    user = request.user

                    if CommentEvent.objects.filter(id=id).exists():
                        comment = CommentEvent.objects.get(id=id)

                        if comment.author == user or comment.event.user == user:

                            comment.delete()

                            comments_filtered, count = actual_comments(
                                user, slug, uuid)

                            return Response(
                                {'success': 'Sukces', 'meta': {'count': count},
                                 'data': comments_filtered.data, "code": "1401"},
                                status=status.HTTP_200_OK
                            )
                        else:

                            return Response(
                                {'detail': 'Nie możesz usunąć nieswój komentarz',
                                    "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )
                    else:

                        comments_filtered, count = actual_comments(
                            user, slug, uuid)

                        return Response(
                            {'detail': 'Nie ma takiego komentarza', 'meta': {'count': count},
                                'data': comments_filtered.data,
                                "code": "1011"},
                            status=222
                        )

                else:
                    return Response(
                        {'detail': 'Wydarzenie nie istnieje',
                         "code": "9011"},
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
                {'detail': 'Coś poszło nie tak z próbą pobrania danych', "code": "1165"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class CommentEventReactionView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = CommentEventReactionSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                data = request.data
                id_comment = data['id_comment']
                type = data['type']
                slug = data['slug']
                uuid = data['uuid']

                if Event.objects.filter(slug__iexact=slug, uuid=uuid).exists():
                    user = request.user

                    if str(id_comment).isdigit() and CommentEvent.objects.filter(id=id_comment).exists():
                        comment_event = CommentEvent.objects.get(id=id_comment)

                        if CommentEventReaction.objects.filter(comment=comment_event, user=user).exists():
                            comment_event_reaction = CommentEventReaction.objects.get(
                                comment=comment_event, user=user)

                            if (type == "Like" and comment_event_reaction.type == "Dislike") or (type == "Dislike" and comment_event_reaction.type == "Like"):

                                CommentEventReaction.edit_reaction(
                                    comment_event, type, comment_event_reaction)

                                return Response(
                                    {'success': 'Zmieniono reakcję do komentarza',
                                     "code": "7667"},
                                    status=status.HTTP_200_OK
                                )

                            elif type == "Delete":
                                CommentEventReaction.delete_reaction(
                                    comment_event, comment_event_reaction)

                                return Response(
                                    {'success': 'Usunięto reakcję do komentarza',
                                        "code": "7667"},
                                    status=status.HTTP_200_OK
                                )

                            else:
                                return Response(
                                    {'detail': 'Już reakcja została dodana.',
                                        "code": "9011"},
                                    status=status.HTTP_400_BAD_REQUEST
                                )
                        else:
                            if type == "Like" or type == "Dislike":
                                CommentEventReaction.create_reaction(
                                    comment_event, user, type)

                                return Response(
                                    {'success': 'Dodano reakcję do komentarza',
                                     "code": "7667"},
                                    status=status.HTTP_200_OK
                                )

                            elif type == "Delete":
                                return Response(
                                    {'detail': 'Nie można usunąć opinii przed jej wyrażeniem',
                                        "code": "9011"},
                                    status=status.HTTP_400_BAD_REQUEST
                                )

                            else:
                                return Response(
                                    {'detail': 'Błędny typ opinii', "code": "9011"},
                                    status=status.HTTP_400_BAD_REQUEST
                                )

                    else:

                        comments_filtered, count = actual_comments(
                            user, slug, uuid)

                        return Response(
                            {'detail': 'Nie ma takiego komentarza', 'meta': {'count': count},
                                'data': comments_filtered.data,
                                "code": "1011"},
                            status=222
                        )

                else:
                    return Response(
                        {'detail': 'Wydarzenie nie istnieje',
                         "code": "9011"},
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
                {'detail': 'Coś poszło nie tak z próbą pobrania danych', "code": "1165"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class CommentEventReportView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = CommentEventReportSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                data = request.data
                id_comment = data['id_comment']
                type = data['type']
                details = data['details']
                slug = data['slug']
                uuid = data['uuid']

                if len(details) <= 150:

                    if Event.objects.filter(slug__iexact=slug, uuid=uuid).exists():
                        user = request.user
                        if str(id_comment).isdigit() and CommentEvent.objects.filter(id=id_comment).exists():
                            comment_event = CommentEvent.objects.get(
                                id=id_comment)

                            if not comment_event.is_blocked:

                                if not CommentEventReport.objects.filter(comment=comment_event, user=user).exists():
                                    CommentEventReport.objects.create(
                                        comment=comment_event, user=user, type=type, details=details)

                                    return Response(
                                        {'success': 'Sukces', "code": "1010"},
                                        status=status.HTTP_200_OK
                                    )
                                else:

                                    return Response(
                                        {'detail': 'Ten komentarz został już zgłoszony przez użytkownika',
                                            "code": "9011"},
                                        status=status.HTTP_400_BAD_REQUEST
                                    )
                            else:
                                comments_filtered, count = actual_comments(
                                    user, slug, uuid)
                                return Response(
                                    {'detail': 'Ten komentarz jest już zablokowany przez administrację', 'meta': {'count': count},
                                     'data': comments_filtered.data,
                                        "code": "1012"},
                                    status=222
                                )
                        else:

                            comments_filtered, count = actual_comments(
                                user, slug, uuid)

                            return Response(
                                {'detail': 'Nie ma takiego komentarza', 'meta': {'count': count},
                                 'data': comments_filtered.data,
                                    "code": "1011"},
                                status=222
                            )

                    else:
                        return Response(
                            {'detail': 'Wydarzenie nie istnieje',
                             "code": "9011"},
                            status=224
                        )
                else:
                    return Response(
                        {'detail': 'Długoś twoich szczegółów nie może być większa niż 150 znaków',
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


class UserView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = UserFriendsSerializer

    def get(self, request, username):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                if MyUser.objects.filter(username=username).exists():

                    user_request = request.user
                    user_target = MyUser.objects.get(username=username)

                    if not user_target.blocked_users.filter(id=user_request.id).exists() or user_request.is_admin:

                        user_annotate = {}
                        if user_request.username == username:
                            user_annotate["friends_count"] = Count('friends')
                            user_annotate["friends_together_count"] = Value(
                                None, output_field=BooleanField())
                            user_annotate["friendslist_together"] = Value(
                                None, output_field=BooleanField())
                            user_annotate["friendslist_strange"] = ArraySubquery(MyUser.objects.filter(friends__id=OuterRef(
                                'id')).annotate(data=JSONObject(id=F('id'), username=F('username'), image_thumbnail=F('image_thumbnail'))).values('data').order_by('?'))

                        else:
                            user_annotate["friends_count"] = Count(
                                'friends_list')
                            user_annotate["friends_together_count"] = Count(
                                'friends_list', filter=Q(friends_list__in=user_request.friends.all()))

                            user_annotate["friendslist_together"] = ArraySubquery(MyUser.objects.filter(pk=OuterRef('pk')).filter(
                                friends__in=user_request.friends.all()).annotate(data=JSONObject(id=F('id'), username=F('friends__username'), image_thumbnail=F('friends__image_thumbnail'))).values('data'))

                            not_admin_annotate = {}

                            if not user_request.is_admin:
                                not_admin_annotate["blocked_users"] = user_request

                            user_annotate["friendslist_strange"] = ArraySubquery(MyUser.objects.filter(
                                friends_list__pk=OuterRef('pk')).exclude(
                                friends_list=user_request).exclude(blocked_by=user_request).exclude(**not_admin_annotate).annotate(
                                data=JSONObject(id=F('id'), username=F('username'), image_thumbnail=F('image_thumbnail'))).values('data').order_by('?'))

                        ##################

                        # SUBQUERY DO STATUSU "IS_FRIEND"

                        subquery_is_friend = MyUser.objects.filter(
                            friends__pk=OuterRef('pk'), username=user_request.username)

                        subquery_get_request = Friendship_Request.objects.filter(
                            from_user__pk=OuterRef('pk'), to_user=user_request)

                        subquery_send_request = Friendship_Request.objects.filter(
                            to_user__pk=OuterRef('pk'), from_user=user_request)

                        subquery_is_blocked = MyUser.objects.filter(
                            blocked_users__pk=OuterRef('pk'), username=user_request.username)

                        subquery_get_blocked = MyUser.objects.filter(
                            pk=OuterRef('pk'), blocked_users=user_request)

                        ##################

                        # SUBQUERY DO ODZNAK

                        user_main_badge_exclude = {}
                        if user_target.main_badge != None:
                            user_main_badge_exclude["id"] = user_target.main_badge.id

                        subquery_badges = user_target.activated_badges.filter(verificated="verificated").exclude(**user_main_badge_exclude).annotate(
                            data=JSONObject(name=F('name'), image=F('image'))).values('data')

                        #############

                        user = MyUser.objects.select_related(
                            'city', 'main_badge').annotate(is_friend=Case(
                                When(Exists(subquery_is_blocked),
                                     then=Value("Blocked")),
                                When(Exists(subquery_get_blocked),
                                     then=Value("a) Get_block")),
                                When(Exists(subquery_is_friend),
                                     then=Value('a) True')),
                                When(Exists(subquery_send_request), then=Value(
                                    "b) Send_request")),
                                When(Exists(subquery_get_request), then=Value(
                                    "c) Get_request")),

                                default=Value('d) False'), output_field=CharField()), main_badge_data=Case(
                                When(main_badge__isnull=True, then=Value(None)),
                                default=JSONObject(
                                    name=F('main_badge__name'), image=F('main_badge__image')),
                                output_field=JSONField()
                            ), badges=ArraySubquery(subquery_badges), **user_annotate).get(username=username)

                        user = UserFriendsSerializer(
                            user, context={'user': user_target})
                        

                        # print("xdddd")
                        # stripe.api_key = settings.STRIPE_SECRET_KEY_TEST
                        # stripe.checkout.Session.expire('cs_test_a1ua1PC4ww5sUlojNL8rSpyPNbnSu71Q86tN9CKrfRQVijsdjRQWlCqmd8')

                        return Response(
                            {'success': 'Pobrano wydarzenie',
                                'data': user.data, "code": "7667"},
                            status=status.HTTP_200_OK
                        )
                    else:
                        return Response(
                            {'detail': 'Jesteś zablokowany przez tego użytkownika',
                             "code": "1302"},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                else:
                    return Response(
                        {'detail': 'Nie ma takiego użytkownika',
                         "code": "1301"},
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


class UserEventsPagePagination(pagination.PageNumberPagination):

    page_size = 30
    page_query_param = 'page'

    def paginate_queryset_custom(self, queryset, request, view=None):

        page_size = self.get_page_size(request)
        if not page_size:
            return None

        paginator = self.django_paginator_class(queryset, page_size)
        page_number = self.get_page_number(request, paginator)

        try:
            self.page = paginator.page(page_number)
        except InvalidPage as exc:

            if not page_number.isdigit() or int(page_number) == 0:
                self.page = paginator.page(1)

            elif int(page_number) > paginator.num_pages:
                self.page = paginator.page(paginator.num_pages)

            else:
                msg = self.invalid_page_message.format(
                    page_number=page_number, message=str(exc)
                )
                raise NotFound(msg)

        if paginator.num_pages > 1 and self.template is not None:
            self.display_page_controls = True

        self.request = request
        return list(self.page)

    def get_paginated_response_custom(self, serializer, events_paginated, categories, value_not_found):

        page_delete = False

        parsed_url = urlparse(self.request.build_absolute_uri())
        params = parse_qs(parsed_url.query)

        for key in value_not_found.keys():
            if key in params and value_not_found[key] is not None:
                del params[key]
                if key == "page":
                    page_delete = True

        if page_delete is True or ('page' in params and not params['page'][0].isdigit()):
            del params['page']
        elif 'page' in params:
            if int(params['page'][0]) == 0:
                del params['page']
            else:
                params['page'] = [self.page.number]

        parsed_url = parsed_url._replace(query=urlencode(params, doseq=True))
        new_url = urlunparse(parsed_url)

        meta = {
            'links': {
                'next': self.get_next_link(),
                'previous': self.get_previous_link(),
                'current': new_url
            },
            'count': self.page.paginator.count,
            'categories': categories,

        }
        data = serializer(events_paginated, many=True).data

        return meta, data

    def generate(self, queryset, serializer, categories, value_not_found, request):

        events = self.paginate_queryset_custom(
            queryset, request)
        meta, data = self.get_paginated_response_custom(
            serializer, events, categories, value_not_found)
        return meta, data


class UserEventsView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = UserEventsSerializer
    pagination_class = UserEventsPagePagination

    def get(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:

                excluded_params = ["username", "page",
                                   "type", "events_category", "ordering"]
                username = request.GET.get('username', None)
                page = request.GET.get('page', "1")
                type = request.GET.get('type', None)
                events_category = request.GET.get('events_category', None)
                ordering = request.GET.get('ordering', 'newest')
                value_not_found = {}

                for key, value in request.GET.items():
                    if key not in excluded_params:
                        value_not_found[key] = value

                if MyUser.objects.filter(username=username).exists():

                    order_by = None

                    user = request.user

                    if type == None or type == "created_future" or type == "created_past" or type == "future" or type == "past" or ((type == "awaiting" or type == "need_improvement" or type == "rejected") and user.username == username):

                        filter_list = {}

                        if ordering == "newest":
                            order_by = '-id'
                        elif ordering == "popularity":
                            order_by = '-num_reputation'
                        elif ordering == "event_date":
                            order_by = 'event_date'
                        else:
                            value_not_found["ordering"] = ordering
                            order_by = '-id'

                        if type == "created_future":
                            filter_list['event_date__gte'] = timezone.now()
                            filter_list['user__username'] = username
                            filter_list['verificated'] = "verificated"
                        elif type == "created_past":
                            filter_list['event_date__lt'] = timezone.now()
                            filter_list['user__username'] = username
                            filter_list['verificated'] = "verificated"

                        elif type == "future":
                            filter_list['event_date__gte'] = timezone.now()
                            filter_list['participants_event__username'] = username
                            filter_list['verificated'] = "verificated"
                        elif type == "past":
                            filter_list['event_date__lt'] = timezone.now()
                            filter_list['participants_event__username'] = username
                            filter_list['verificated'] = "verificated"

                        elif type == "awaiting":
                            filter_list['user__username'] = username
                            filter_list['verificated'] = "awaiting"
                        elif type == "need_improvement":
                            filter_list['user__username'] = username
                            filter_list['verificated'] = "need_improvement"
                        elif type == "rejected":
                            filter_list['user__username'] = username
                            filter_list['verificated'] = "rejected"

                        else:
                            filter_list['event_date__gte'] = timezone.now()
                            filter_list['participants_event__username'] = username
                            value_not_found["type"] = type

                        if events_category != None and Category.objects.filter(type=events_category).exists() and not "type" in value_not_found:
                            filter_list['category__type'] = events_category
                        elif events_category != "all":
                            value_not_found["events_category"] = events_category

                        subquery_num_reputation = Event.objects.filter(pk=OuterRef('pk')).values('pk').annotate(
                            num_reputation=Count('participants_event')
                        ).values('num_reputation')

                        subquery_participant_self = Event.objects.filter(pk=OuterRef('pk'),
                                                                         participants_event__username=user.username)
                        subquery_main_image = EventImage.objects.filter(
                            event=OuterRef('pk'), main=True).values('image_thumbnail')

                        time_now = timezone.now()
                        queryset = Event.objects.select_related('user', 'category', 'city').filter(
                            **filter_list).annotate(location_distance=Distance('city__geo_location', user.city.geo_location), num_reputation=Subquery(subquery_num_reputation), gps_googlemap=Concat(Value('https://www.google.com/maps/dir/?api=1&origin='), user.city.geo_location[1], Value(','), user.city.geo_location[0], Value('&destination='),  output_field=CharField()), province=F('city__county__province__name'), user_image=F('user__image_thumbnail'), participant_self=Exists(subquery_participant_self), current=ExpressionWrapper(Q(event_date__gte=time_now), output_field=BooleanField()), image=Subquery(subquery_main_image))

                        paginator = UserEventsPagePagination()



                        category_filter = {key: value for key, value in filter_list.items() if key != 'category__type'}
                        categories = Event.objects.filter(**category_filter).values_list('category__type', flat=True).distinct()


                        queryset = queryset.order_by(order_by)

                        meta, data = paginator.generate(
                            queryset, UserEventsSerializer, categories, value_not_found, request)

                        max_pages = math.ceil(meta['count']/30)

                        if not str(page).isdigit() or max_pages < int(page) or 1 > int(page):
                            value_not_found["page"] = page

                        return Response(
                            {'success': 'Pobrano wydarzenia', 'meta': meta,
                                'value_not_found': value_not_found,  'data': data, "code": "7667"},
                            status=status.HTTP_200_OK
                        )
                    else:
                        return Response(
                            {'detail': 'Nie masz dostępu do tej strony',
                             "code": "1377"},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                else:
                    return Response(
                        {'detail': 'Nie ma takiego użytkownika', 'username': username,
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


class UserParticipateView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = UserParticipateSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                data = request.data
                id_event = data['id_event']

                user = request.user

                # 5052

                # 5054

                if str(id_event).isdigit() and Event.objects.filter(id=id_event).exists():

                    event = Event.objects.get(id=id_event)

                    if event.user != user:

                        if event.verificated == "verificated":

                            if event.event_date >= timezone.now().date():

                                if not event.participants_event.filter(
                                        username=user.username).exists():

                                    event.participants_event.add(user)
                                    # user.save(generate_thumbnail=False)
                                    # event.save()
                                    return Response(
                                        {'success': 'Sukces',
                                            "code": "1050"},
                                        status=status.HTTP_200_OK
                                    )
                                else:
                                    event.participants_event.remove(user)
                                    # user.save(generate_thumbnail=False)
                                    # event.save()

                                    return Response(
                                        {'success': 'Sukces',
                                            "code": "1051"},
                                        status=status.HTTP_200_OK
                                    )
                            else:
                                return Response(
                                    {'detail': 'To wydarzenie już się odbyło',
                                        "code": "9011"},
                                    status=status.HTTP_400_BAD_REQUEST
                                )
                        else:

                            if user.is_admin:
                                return Response(
                                    {'detail': 'Można brać udział tylko wydarzenia, które są w danej chwili zweryfikowane.', "is_admin": user.is_admin, "status": {"status": event.verificated, "details": event.verificated_details},
                                        "code": "9011"},
                                    status=223
                                )

                            else:
                                return Response(
                                    {'detail': 'Można brać udział tylko wydarzenia, które są w danej chwili zweryfikowane.', "is_admin": user.is_admin,
                                        "code": "9011"},
                                    status=223
                                )

                    else:
                        return Response(
                            {'detail': 'Nie możesz brać udziału w swoim wydarzeniu, ponieważ jesteś jego organizatorem',
                             "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )

                else:
                    return Response(
                        {'detail': 'Wydarzenie nie istnieje',
                         "code": "9011"},
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
                {'detail': 'Coś poszło nie tak z próbą pobrania danych', "code": "1165"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class EventParticipantsView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = EventParticipantsSerializer

    def get(self, request, slug, uuid):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:

                if Event.objects.filter(slug=slug, uuid=uuid).exists():
                    user = request.user
                    event = Event.objects.get(slug=slug, uuid=uuid)
                    # max_profiles = 15

                    not_admin_annotate = {}
                    if not user.is_admin:
                        not_admin_annotate["blocked_users"] = user

                    friends = user.friends_list.filter(
                        take_part_events=event).order_by('?')[:15]
                    friends_count = user.friends_list.filter(
                        take_part_events=event).count()
                    rest_users = event.participants_event.exclude(
                        Q(id=user.id) | Q(friends__id=user.id)).exclude(blocked_by=user).exclude(**not_admin_annotate).order_by('?')[:15]
                    rest_users_count = event.participants_event.exclude(
                        Q(id=user.id) | Q(friends__id=user.id)).count()

                    friends = EventParticipantsSerializer(friends, many=True)
                    rest_users = EventParticipantsSerializer(
                        rest_users, many=True)

                    return Response(
                        {'success': 'Pobrano uczestników wydarzenia', "participants": {"friends": {"meta": {"count": friends_count}, "data": friends.data}, "rest_users": {"meta": {"count": rest_users_count}, "data": rest_users.data}},
                         "code": "34324"},
                        status=status.HTTP_200_OK
                    )
                else:
                    return Response(
                        {'detail': 'Nie znaleziono takiego wydarzenia', "code": "9011"},
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


class EventAddView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = EventAddSerializer
    parser_classes = [MultiPartParser, FormParser]

    def check_scheduler(self, temp):
        if isinstance(temp, list):
            for schedule in eval(temp):
                if isinstance(schedule, list):
                    if isinstance(schedule[0], str) or isinstance(schedule[1], str):
                        if schedule[0] == "" or schedule[1] == "":
                            return Response(
                                {'detail': 'W godzinie rozpoczęcia wydarzenia została podana pusta wartość.',
                                    "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )

                        else:
                            return Response(
                                {'detail': 'W godzinie rozpoczęcia wydarzenia została podana litera.',
                                    "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )

                    else:
                        if not (schedule[0] >= 0 and schedule[0] <= 23):
                            return Response(
                                {'detail': 'Godzina rozpoczęcia nie mieści się w zakresie 0-23',
                                    "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )

                        if not (schedule[1] >= 0 and schedule[1] <= 59):
                            return Response(
                                {'detail': 'Minuta rozpoczęcia nie mieści się w zakresie 0-59',
                                    "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )

                    if isinstance(schedule[2], str) or isinstance(schedule[3], str):
                        if schedule[2] != "" or schedule[3] != "":
                            return Response(
                                {'detail': 'W godzinie zakończenia wydarzenia została podana litera.',
                                    "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )
                    else:
                        if not (schedule[2] >= 0 and schedule[2] <= 23):
                            return Response(
                                {'detail': 'Godzina zakończenia nie mieści się w zakresie 0-23',
                                    "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )

                        if not (schedule[3] >= 0 and schedule[3] <= 59):
                            return Response(
                                {'detail': 'Minuta zakończenia nie mieści się w zakresie 0-59',
                                    "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )
                else:
                    return Response(
                        {'detail': 'Nie podajesz harmonogramu w szablonie  [[<int:godzina rozpoczecia>,<int:minuta rozpoczecia>,<int:godzina zakończenia>,<int:minuta zakończenia>,"<str:opis>"],[<opcjonalnie kolejna godzina pod poprzedni wzór>]]',
                            "code": "9011"},
                        status=status.HTTP_400_BAD_REQUEST
                    )
        else:
            return Response(
                {'detail': 'Nie podajesz harmonogramu w szablonie  [[<int:godzina rozpoczecia>,<int:minuta rozpoczecia>,<int:godzina zakończenia>,<int:minuta zakończenia>,"<str:opis>"],[<opcjonalnie kolejna godzina pod poprzedni wzór>]]',
                    "code": "9011"},
                status=status.HTTP_400_BAD_REQUEST
            )

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:

                data = request.data
                title = data['title']
                text = data['text']
                category = data['category']
                series = data['series']
                event_date = data['event_date']
                province = data['province']
                city = data['city']
                schedule = data['schedule']
                image0 = data['image0']
                image1 = data.get('image1', "")
                image2 = data.get('image2', "")
                image3 = data.get('image3', "")
                image4 = data.get('image4', "")
                image5 = data.get('image5', "")
                image6 = data.get('image6', "")
                image7 = data.get('image7', "")
                image_optional_keys = [image1, image2, image3,
                                       image4, image5, image6, image7]
                image_found = [image0, image1, image2, image3,
                               image4, image5, image6, image7]

                all_optional_images_is_images = True
                all_next_images_are_null = False
                user = request.user

                if not Event.objects.filter(title=title).exists():

                    if len(title) > 5:
                        if len(text) > 49:
                            if len(schedule) > 0:
                                self.check_scheduler(schedule)
                                if Category.objects.filter(type=category).exists():
                                    category_obj = Category.objects.get(
                                        type=category)
                                    if Series.objects.filter(author=user, name=series).exists() or series == "":
                                        if series == "":
                                            series_obj = None
                                        else:
                                            series_obj = Series.objects.get(
                                                author=user, name=series)
                                        try:
                                            time_now = timezone.now().date()
                                            event_date_convert = datetime.datetime.strptime(
                                                event_date, "%Y-%m-%d").date()
                                            if time_now <= event_date_convert:
                                                if Province.objects.filter(name=province).exists():
                                                    province_obj = Province.objects.get(
                                                        name=province)
                                                    if City.objects.filter(county__province=province_obj, name=city).exists():
                                                        city_obj = City.objects.get(
                                                            county__province=province_obj, name=city)

                                                        if image0 and image0.content_type in ['image/jpeg', 'image/png', 'image/gif']:
                                                            for image in image_optional_keys:

                                                                if all_next_images_are_null and image != "":
                                                                    return Response(
                                                                        {'detail': 'Nie możesz wstawiać luki pomiędzy zdjęciami',
                                                                         "code": "9011"},
                                                                        status=status.HTTP_400_BAD_REQUEST
                                                                    )

                                                                if image != "" and image != "" and image.content_type not in ['image/jpeg', 'image/png', 'image/gif']:
                                                                    all_optional_images_is_images = False
                                                                elif image == "":
                                                                    image_found.remove(
                                                                        image)
                                                                    all_next_images_are_null = True

                                                            if all_optional_images_is_images:

                                                                if user.is_admin:
                                                                    verificated = "verificated"
                                                                    code = "1211"
                                                                else:
                                                                    verificated = "awaiting"
                                                                    code = "1210"

                                                                new_event = Event.objects.create(
                                                                    user=user, category=category_obj, title=title, text=text, event_date=event_date_convert, city=city_obj, series=series_obj, schedule=schedule, verificated=verificated)
                                                                for index, image_uploaded in enumerate(image_found):

                                                                    if index == 0:
                                                                        main = True
                                                                    else:
                                                                        main = False

                                                                    EventImage.objects.create(
                                                                        event=new_event, image=image_uploaded, order=index, author=user, main=main)
                                                                return Response(
                                                                    {'success': 'Utworzono wydarzenie', 'slug': new_event.slug, 'uuid': new_event.uuid,
                                                                        "code": code},
                                                                    status=status.HTTP_200_OK)
                                                            else:
                                                                return Response(
                                                                    {'detail': 'Jeden z dodatkowych obrazków nie jest plikiem graficznym',
                                                                        "code": "9011"},
                                                                    status=status.HTTP_400_BAD_REQUEST
                                                                )
                                                        else:
                                                            return Response(
                                                                {'detail': 'Główny obrazek nie jest plikiem graficznym',
                                                                    "code": "9011"},
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
                                                    {'detail': 'Nie możesz stworzyć wydarzenia, które odbyło się w przeszłości',
                                                        "code": "9011"},
                                                    status=status.HTTP_400_BAD_REQUEST
                                                )
                                        except Exception as e:
                                            print(e)
                                            print(
                                                f"Typ błędu: {type(e).__name__}")
                                            print(f"Kod błędu: {e.args[0]}")
                                            print("Traceback:")
                                            import traceback
                                            traceback.print_tb(e.__traceback__)
                                            return Response(
                                                {'detail': 'Została podana zła data.',
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
                                        {'detail': 'Nie ma takiej kategorii',
                                            "code": "9011"},
                                        status=status.HTTP_400_BAD_REQUEST
                                    )
                            else:
                                return Response(
                                    {'detail': 'Nie został wysłany harmonogram wydarzenia. Musisz podać chociaż godzine rozpoczęcia.',
                                        "code": "9011"},
                                    status=status.HTTP_400_BAD_REQUEST
                                )
                        else:
                            return Response(
                                {'detail': 'Opis musi posiadać minimum 50 znaków',
                                    "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )

                    else:
                        return Response(
                            {'detail': 'Tytuł musi posiadać więcej niż 5 znaków',
                                "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                else:
                    return Response(
                        {'detail': 'Istnieje takie wydarzenie',
                            "code": "1250"},
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

                        # for event in events:
                        #     event.series = None
                        #     event.save()
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


class EventReportView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = EventReportSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                data = request.data
                id_event = data['id_event']
                type = data['type']
                details = data.get('details', None)

                if str(id_event).isdigit() and Event.objects.filter(id=id_event).exists():
                    user = request.user
                    event = Event.objects.get(id=id_event)

                    if not event.user == user:
                        if event.verificated == "verificated":
                            if not EventReport.objects.filter(event=event, user=user).exists():
                                EventReport.objects.create(
                                    event=event, user=user, type=type, details=details)

                                return Response(
                                    {'success': 'Sukces', "code": "1010"},
                                    status=status.HTTP_200_OK
                                )
                            else:
                                return Response(
                                    {'detail': 'Już wcześniej zgłosiłeś te wydarzenie',
                                        "code": "9011"},
                                    status=status.HTTP_400_BAD_REQUEST
                                )
                        else:

                            if user.is_admin:
                                return Response(
                                    {'detail': 'Można zgłaszać tylko wydarzenia, które są w danej chwili zweryfikowane.', "is_admin": user.is_admin, "status": {"status": event.verificated, "details": event.verificated_details},
                                        "code": "9011"},
                                    status=223
                                )

                            else:
                                return Response(
                                    {'detail': 'Można zgłaszać tylko wydarzenia, które są w danej chwili zweryfikowane.', "is_admin": user.is_admin,
                                        "code": "9011"},
                                    status=223
                                )

                    else:
                        return Response(
                            {'detail': 'Nie możesz zgłosić wydarzenia, które sam utworzyłeś',
                                "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )

                else:
                    return Response(
                        {'detail': 'Wydarzenie nie istnieje',
                         "code": "9011"},
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
                {'detail': 'Coś poszło nie tak z próbą pobrania danych', "code": "1165"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class EventEditView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = EventEditSerializer
    parser_classes = [MultiPartParser, FormParser]

    def check_scheduler(self, temp):
        if isinstance(temp, list):
            for schedule in eval(temp):
                if isinstance(schedule, list):
                    if isinstance(schedule[0], str) or isinstance(schedule[1], str):
                        if schedule[0] == "" or schedule[1] == "":
                            return Response(
                                {'detail': 'W godzinie rozpoczęcia wydarzenia została podana pusta wartość.',
                                    "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )

                        else:
                            return Response(
                                {'detail': 'W godzinie rozpoczęcia wydarzenia została podana litera.',
                                    "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )

                    else:
                        if not (schedule[0] >= 0 and schedule[0] <= 23):
                            return Response(
                                {'detail': 'Godzina rozpoczęcia nie mieści się w zakresie 0-23',
                                    "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )

                        if not (schedule[1] >= 0 and schedule[1] <= 59):
                            return Response(
                                {'detail': 'Minuta rozpoczęcia nie mieści się w zakresie 0-59',
                                    "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )

                    if isinstance(schedule[2], str) or isinstance(schedule[3], str):
                        if schedule[2] != "" or schedule[3] != "":
                            return Response(
                                {'detail': 'W godzinie zakończenia wydarzenia została podana litera.',
                                    "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )
                    else:
                        if not (schedule[2] >= 0 and schedule[2] <= 23):
                            return Response(
                                {'detail': 'Godzina zakończenia nie mieści się w zakresie 0-23',
                                    "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )

                        if not (schedule[3] >= 0 and schedule[3] <= 59):
                            return Response(
                                {'detail': 'Minuta zakończenia nie mieści się w zakresie 0-59',
                                    "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )
                else:
                    return Response(
                        {'detail': 'Nie podajesz harmonogramu w szablonie  [[<int:godzina rozpoczecia>,<int:minuta rozpoczecia>,<int:godzina zakończenia>,<int:minuta zakończenia>,"<str:opis>"],[<opcjonalnie kolejna godzina pod poprzedni wzór>]]',
                            "code": "9011"},
                        status=status.HTTP_400_BAD_REQUEST
                    )
        else:
            return Response(
                {'detail': 'Nie podajesz harmonogramu w szablonie  [[<int:godzina rozpoczecia>,<int:minuta rozpoczecia>,<int:godzina zakończenia>,<int:minuta zakończenia>,"<str:opis>"],[<opcjonalnie kolejna godzina pod poprzedni wzór>]]',
                    "code": "9011"},
                status=status.HTTP_400_BAD_REQUEST
            )

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:

                data = request.data
                id = data['id']
                title = data['title']
                text = data['text']
                category = data['category']
                series = data.get('series', None)
                event_date = data['event_date']
                province = data['province']
                city = data['city']
                schedule = data['schedule']
                image0 = data['image0']
                image1 = data.get('image1', "")
                image2 = data.get('image2', "")
                image3 = data.get('image3', "")
                image4 = data.get('image4', "")
                image5 = data.get('image5', "")
                image6 = data.get('image6', "")
                image7 = data.get('image7', "")
                image_optional_keys = [image1, image2, image3,
                                       image4, image5, image6, image7]

                already_update_images = {}
                new_images = {}

                all_next_images_are_null = False

                user = request.user

                if str(id).isdigit() and Event.objects.filter(id=id).exists():
                    event = Event.objects.get(id=id)

                    if event.user == user:
                        if len(title) > 5:
                            if len(text) > 49:
                                if len(schedule) > 0:
                                    self.check_scheduler(schedule)

                                    ###
                                    if event.verificated != "rejected":
                                        diffrence_time = int(
                                            (timezone.now() - event.edit_time).total_seconds())

                                        if diffrence_time > 180:
                                            if Category.objects.filter(type=category).exists():
                                                category_obj = Category.objects.get(
                                                    type=category)
                                                if Series.objects.filter(author=user, name=series).exists() or series == "":
                                                    if series == "":
                                                        series_obj = None
                                                    else:
                                                        series_obj = Series.objects.get(
                                                            author=user, name=series)

                                                    try:
                                                        time_now = timezone.now().date()
                                                        event_date_convert = datetime.datetime.strptime(
                                                            event_date, "%Y-%m-%d").date()
                                                        if time_now <= event_date_convert:
                                                            if Province.objects.filter(name=province).exists():
                                                                province_obj = Province.objects.get(
                                                                    name=province)
                                                                if City.objects.filter(county__province=province_obj, name=city).exists():
                                                                    city_obj = City.objects.get(
                                                                        county__province=province_obj, name=city)
                                                                    if isinstance(image0, str):
                                                                        if str(image0).isdigit():
                                                                            if EventImage.objects.filter(id=image0).exists():
                                                                                eventimage0 = EventImage.objects.get(
                                                                                    id=image0)
                                                                                if eventimage0.author == user:
                                                                                    already_update_images[0] = eventimage0

                                                                                else:
                                                                                    return Response(
                                                                                        {'detail': 'Podany obrazek nie należy do użytkownika',
                                                                                         "code": "9011"},
                                                                                        status=status.HTTP_400_BAD_REQUEST
                                                                                    )

                                                                            else:
                                                                                return Response(
                                                                                    {'detail': 'Podany obrazek nie istnieje w bazie',
                                                                                     "code": "9011"},
                                                                                    status=status.HTTP_400_BAD_REQUEST
                                                                                )
                                                                        elif image0 == "":
                                                                            return Response(
                                                                                {'detail': 'Musisz uzupełnić wydarzenie przynajmniej jednym obrazkiem',
                                                                                 "code": "9011"},
                                                                                status=status.HTTP_400_BAD_REQUEST
                                                                            )
                                                                        else:
                                                                            return Response(
                                                                                {'detail': 'W miejscu ID podałeś literę',
                                                                                 "code": "9011"},
                                                                                status=status.HTTP_400_BAD_REQUEST
                                                                            )

                                                                    else:
                                                                        if image0 and image0.content_type in ['image/jpeg', 'image/png', 'image/gif']:
                                                                            new_images[0] = image0

                                                                        else:
                                                                            return Response(
                                                                                {'detail': 'Główny obrazek nie jest plikiem graficznym',
                                                                                 "code": "9011"},
                                                                                status=status.HTTP_400_BAD_REQUEST
                                                                            )

                                                                    for index, image in enumerate(image_optional_keys):
                                                                        if all_next_images_are_null and image != "":
                                                                            return Response(
                                                                                {'detail': 'Nie możesz wstawiać luki pomiędzy zdjęciami',
                                                                                 "code": "9011"},
                                                                                status=status.HTTP_400_BAD_REQUEST
                                                                            )

                                                                        if isinstance(image, str):

                                                                            if str(image).isdigit():
                                                                                if EventImage.objects.filter(id=image).exists():
                                                                                    temp_image = EventImage.objects.get(
                                                                                        id=image)
                                                                                    if temp_image.author == user:
                                                                                        already_update_images[index +
                                                                                                              1] = temp_image
                                                                                    else:
                                                                                        return Response(
                                                                                            {'detail': 'Podany obrazek nie należy do użytkownika',
                                                                                             "code": "9011"},
                                                                                            status=status.HTTP_400_BAD_REQUEST
                                                                                        )
                                                                                else:
                                                                                    return Response(
                                                                                        {'detail': 'Jeden z opcjonalnych podanych obrazków nie istnieje w bazie',
                                                                                         "code": "9011"},
                                                                                        status=status.HTTP_400_BAD_REQUEST
                                                                                    )

                                                                            elif image == "":
                                                                                all_next_images_are_null = True
                                                                            else:
                                                                                return Response(
                                                                                    {'detail': 'W miejscu ID podałeś literę',
                                                                                     "code": "9011"},
                                                                                    status=status.HTTP_400_BAD_REQUEST
                                                                                )

                                                                        else:
                                                                            if image and image.content_type in ['image/jpeg', 'image/png', 'image/gif']:
                                                                                new_images[index +
                                                                                           1] = image
                                                                            else:
                                                                                return Response(
                                                                                    {'detail': 'Jeden z dodatkowych obrazków nie jest plikiem graficznym',
                                                                                     "code": "9011"},
                                                                                    status=status.HTTP_400_BAD_REQUEST
                                                                                )

                                                                    images_to_delete = EventImage.objects.filter(event=event).exclude(
                                                                        pk__in=[obj.pk for obj in already_update_images.values()])
                                                                    images_to_delete.delete()
                                                                    event.title = title
                                                                    event.text = text
                                                                    event.category = category_obj
                                                                    event.series = series_obj
                                                                    event.event_date = event_date_convert
                                                                    event.city = city_obj
                                                                    event.schedule = schedule
                                                                    if user.is_admin:
                                                                        event.verificated = "verificated"
                                                                        code = "1211"
                                                                    else:
                                                                        event.verificated = "awaiting"
                                                                        code = "1210"
                                                                    event.save()

                                                                    for index in range(8):

                                                                        if index in already_update_images:
                                                                            change_order = already_update_images[index]
                                                                            if change_order.order != index:
                                                                                change_order.order = index
                                                                                if index == 0:
                                                                                    change_order.main = True
                                                                                else:
                                                                                    change_order.main = False
                                                                                change_order.save(
                                                                                    generate_thumbnail=False)
                                                                        elif index in new_images:
                                                                            if index == 0:
                                                                                main = True
                                                                            else:
                                                                                main = False
                                                                            EventImage.objects.create(
                                                                                event=event, author=user, image=new_images[index], order=index, main=main)

                                                                    return Response(
                                                                        {'success': 'Zmodyfikowano wydarzenie', 'slug': event.slug, 'uuid': event.uuid,
                                                                                    "code": code},
                                                                        status=status.HTTP_200_OK)
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
                                                                {'detail': 'Nie możesz edytować wydarzenia, które odbyło się w przeszłości',
                                                                    "code": "9011"},
                                                                status=status.HTTP_400_BAD_REQUEST
                                                            )
                                                    except Exception as e:
                                                        print(e)
                                                        print(
                                                            f"Typ błędu: {type(e).__name__}")
                                                        print(
                                                            f"Kod błędu: {e.args[0]}")
                                                        print("Traceback:")
                                                        import traceback
                                                        traceback.print_tb(
                                                            e.__traceback__)
                                                        return Response(
                                                            {'detail': 'ERRROR.',
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
                                                    {'detail': 'Nie ma takiej kategorii',
                                                        "code": "9011"},
                                                    status=status.HTTP_400_BAD_REQUEST
                                                )
                                        else:

                                            minutes = diffrence_time // 60
                                            seconds = diffrence_time % 60

                                            if minutes == 0:
                                                response = f'Minęło dopiero {seconds} sekund.'

                                            elif minutes == 1:
                                                response = f'Minęła dopiero {minutes} minuta i {seconds} sekund.'

                                            else:
                                                response = f'Minęły dopiero {minutes} minuty i {seconds} sekund.'

                                            return Response(
                                                {'detail': response,
                                                    "code": "1513"},
                                                status=status.HTTP_400_BAD_REQUEST
                                            )
                                    else:
                                        return Response(
                                            {'success': 'Wydarzenie jest przeznaczone do usunięcia.', 'slug': event.slug, 'uuid': event.uuid,
                                                "code": "1212"},
                                            status=223
                                        )
                                else:
                                    return Response(
                                        {'detail': 'Nie został wysłany harmonogram wydarzenia. Musisz podać chociaż godzine rozpoczęcia.',
                                            "code": "9011"},
                                        status=status.HTTP_400_BAD_REQUEST
                                    )
                            else:
                                return Response(
                                    {'detail': 'Opis musi posiadać minimum 50 znaków',
                                        "code": "9011"},
                                    status=status.HTTP_400_BAD_REQUEST
                                )

                        else:
                            return Response(
                                {'detail': 'Tytuł musi posiadać więcej niż 5 znaków',
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
                            "code": "1300"},
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


class EventsRandomView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = EventsRandomSerializer

    def get(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                distance = request.GET.get('distance', None)

                if distance != None:
                    if distance.isdigit():
                        user = request.user

                        subquery_num_reputation = Event.objects.filter(pk=OuterRef(
                            'pk')).annotate(num_reputation=Count('participants_event')).values('num_reputation')

                        subquery_image = EventImage.objects.filter(event__pk=OuterRef(
                            'pk')).annotate(data=JSONObject(id=F('id'), order=F('order'), image=F('image'))).values('data').order_by('order')

                        filter_list = {}

                        if not user.is_admin:
                            filter_list["verificated"] = "verificated"

                        subquery_series_events = Event.objects.filter(**filter_list, series=OuterRef(
                            'series')).annotate(data=JSONObject(title=F('title'), event_date=F('event_date'), slug=F('slug'), uuid=F('uuid'), verificated=F('verificated'), num_reputation=Subquery(Event.objects.filter(pk=OuterRef('pk')).values('pk').annotate(
                                num_reputation=Count('participants_event')
                            ).values('num_reputation')), image=Subquery(EventImage.objects.filter(
                                event=OuterRef('pk'), main=True).values('image_thumbnail')), city=F('city__name'), province=F('city__county__province__name'), category=F('category__type'))).values('data').order_by('event_date')

                        events = Event.objects.select_related(
                            'user', 'category', 'city', 'series').filter(~Q(user=user), ~Q(participants_event=user), ~Q(visitors_event=user), verificated="verificated", event_date__gte=timezone.now(), city__in=City.objects.filter(geo_location__distance_lte=(
                                user.city.geo_location, D(km=distance)))).annotate(location_distance=Distance('city__geo_location', user.city.geo_location), num_reputation=Subquery(subquery_num_reputation), gps_googlemap=Concat(Value('https://www.google.com/maps/dir/?api=1&origin='), user.city.geo_location[1], Value(','), user.city.geo_location[0], Value('&destination='),  output_field=CharField()), province=F('city__county__province__name'), user_image=F('user__image_thumbnail'), image=ArraySubquery(subquery_image), series_events=ArraySubquery(subquery_series_events), series_details=F('series__description')).order_by('?')[:10]

                        if len(events) > 0:

                            events = EventsRandomSerializer(events, many=True)

                            return Response(
                                {'success': 'Pobrano wydarzenia', 'data': events.data,
                                 "code": "7667"},
                                status=status.HTTP_200_OK
                            )
                        else:
                            return Response(
                                {'success': 'Brak dostępnych wydarzeń', 'data': "empty",
                                 "code": "660"},
                                status=status.HTTP_200_OK
                            )

                    else:
                        return Response(
                            {'detail': 'Dystans nie jest liczbą.',
                                "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                else:
                    return Response(
                        {'detail': 'Nie podano dystansu.',
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


class EventsRandomReactionView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = EventsRandomReactionSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                data = request.data
                id_event = data['id_event']
                type = data['type']

                if str(id_event).isdigit() and Event.objects.filter(id=id_event).exists():
                    if type == "Like" or type == "Dislike":
                        event = Event.objects.get(id=id_event)
                        if event.verificated == "verificated":
                            user = request.user

                            if not event.visitors_event.filter(username=user.username).exists():

                                event.visitors_event.add(user)

                                if type == "Like":
                                    event.participants_event.add(user)

                                return Response(
                                    {'success': 'Zagłosowano poprawnie',
                                        "code": "7667"},
                                    status=status.HTTP_200_OK
                                )

                            else:
                                return Response(
                                    {'detail': 'Już wylosowałeś te wydarzenie.',
                                        "code": "9011"},
                                    status=status.HTTP_400_BAD_REQUEST
                                )
                        else:
                            return Response(
                                {'detail': 'Wydarzenie nie jest aktywne.',
                                 "code": "1406"},
                                status=223
                            )

                    else:
                        return Response(
                            {'detail': 'Możesz przesłać typ reakcji "Like" albo "Dislike".',
                                "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )

                else:
                    return Response(
                        {'detail': 'Wydarzenie nie istnieje', "code": "1405"},
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
                {'detail': 'Coś poszło nie tak z próbą pobrania danych', "code": "1165"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class EventsProvinceMapView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = EventsProvinceMapSerializer

    def get(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:

                time_now = timezone.now()

                province_events = Province.objects.all().annotate(
                    count=Count('county__city__event',  filter=Q(county__city__event__event_date__range=(time_now, time_now + timedelta(days=90)))))

                province_events = EventsProvinceMapSerializer(
                    province_events, many=True)

                return Response(
                    {'success': 'Pobrano wydarzenia', "data": province_events.data,
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


class EventsCountyMapView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = EventsCountyMapSerializer

    def get(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                province_id = request.GET.get('province', None)
                if province_id != None:
                    if province_id.isdigit():
                        if Province.objects.filter(id=province_id).exists():

                            user = request.user

                            time_now = timezone.now()
                            filter_subquery_list = {}
                            filter_list = {}
                            if not user.is_admin:
                                filter_subquery_list["verificated"] = "verificated"
                                filter_list["city__event__verificated"] = "verificated"

                            subquery_county_events = Event.objects.filter(**filter_subquery_list, event_date__range=(time_now, time_now + timedelta(days=90)), city__county__id=OuterRef(
                                'id')).annotate(data=JSONObject(id=F('id'), title=F('title'), event_date=F('event_date'), slug=F('slug'), uuid=F('uuid'), verificated=F('verificated'), num_reputation=Subquery(Event.objects.filter(pk=OuterRef('pk')).values('pk').annotate(
                                    num_reputation=Count('participants_event')
                                ).values('num_reputation')), image=Subquery(EventImage.objects.filter(
                                    event=OuterRef('pk'), main=True).values('image_thumbnail')), city=F('city__name'), user=F('user__username'), province=F('city__county__province__name'), category=F('category__type'))).values('data').order_by('participants_event')

                            county_events = County.objects.filter(province__id=province_id).annotate(
                                count=Count('city__event',  filter=(Q(city__event__event_date__range=(
                                    time_now, time_now + timedelta(days=90))) & Q(**filter_list))),
                                county_events=ArraySubquery(
                                    subquery_county_events)
                            )

                            county_events = EventsCountyMapSerializer(
                                county_events, many=True)

                            return Response(
                                {'success': 'Pobrano wydarzenia', "data": county_events.data,
                                 "code": "7667"},
                                status=status.HTTP_200_OK
                            )
                        else:
                            return Response(
                                {'detail': 'Nie ma takiego województwa o takim ID.',
                                    "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )

                    else:
                        return Response(
                            {'detail': 'ID województwa nie jest liczbą.',
                                "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                else:
                    return Response(
                        {'detail': 'Nie podano ID województwa.',
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


# class LimitSetFindFriendsPagination(pagination.LimitOffsetPagination):

#     limit_query_param = 'limit'
#     offset_query_param = 'offset'

#     def get_paginated_response_custom(self, data):
#         meta = {
#             'links': {
#                 'next': self.get_next_link(),
#                 'previous': self.get_previous_link()
#             },
#             'count': self.count
#         }
#         data = data

#         return meta, data

#     def generate(self, data, page_size, request):

#         self.max_limit = page_size
#         data = self.paginate_queryset(data, request)
#         meta, data = self.get_paginated_response_custom(data)

#         return meta, data


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


class EventsViaBadgesView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = EventsViaBadgesSerializer

    def get(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                user = request.user
                time_now = timezone.now()
                ordering = request.GET.get('ordering', 'created_time')

                if ordering == "created_time" or ordering == "status":

                    if ordering == "created_time":
                        order_by_settings = ["-created_time", "status"]
                    else:
                        order_by_settings = ["status", "-created_time"]

                    subquery_main_image = EventImage.objects.filter(
                        event=OuterRef('pk'), main=True).values('image_thumbnail')

                    #############

                    subquery_badge_codes = BadgeCode.objects.filter(
                        badge__pk=OuterRef('pk')).annotate(data=JSONObject(id=F('id'), code=F('code'), status=F('status'), activated_by=F('activated_by__username'), created_time=F('created_time'))).order_by(*order_by_settings).values('data')

                    subquery_badge_codes_to_use_count = BadgeCode.objects.filter(
                        badge__pk=OuterRef('pk'), status="a) to_use").annotate(count=Func(F('id'), function='Count')).values('count')

                    subquery_badge_codes_locked_count = BadgeCode.objects.filter(
                        badge__pk=OuterRef('pk'), status="b) locked").annotate(count=Func(F('id'), function='Count')).values('count')

                    subquery_badge_codes_used_count = BadgeCode.objects.filter(
                        badge__pk=OuterRef('pk'), status="c) used").annotate(count=Func(F('id'), function='Count')).values('count')

                    subquery_badges = Badge.objects.filter(
                        event__pk=OuterRef('pk')).annotate(data=JSONObject(id=F('id'), name=F('name'), image=F('image'), verificated=F('verificated'), verificated_details=F('verificated_details'), codes=ArraySubquery(subquery_badge_codes), used_codes_count=Subquery(subquery_badge_codes_used_count), to_use_codes_count=Subquery(subquery_badge_codes_to_use_count), locked_codes_count=Subquery(subquery_badge_codes_locked_count))).values('data')

                    #############

                    events = Event.objects.select_related('category', 'city').filter(
                        user=user, event_date__gte=time_now).annotate(province=F('city__county__province__name'), image=Subquery(subquery_main_image), badges=ArraySubquery(subquery_badges)).order_by('event_date')

                    events = EventsViaBadgesSerializer(events, many=True)

                    return Response(
                        {'success': 'Pobrano wydarzenia', 'data': events.data,
                            "code": "7667"},
                        status=status.HTTP_200_OK
                    )
                else:
                    return Response(
                        {'detail': 'Jako wartość "ordering" akceptowane jest tylko "created_time" lub "is_active".',
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


class BadgeCodesLockedToExportView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = BadgesCodesListSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                data = request.data
                event_id = data['event_id']
                badge_id = data['badge_id']
                badge_codes_id_list = data['badge_codes_id_list']
                user = request.user
                if event_id != "":
                    if badge_id != "":
                        if badge_codes_id_list != "":
                            if not isinstance(badge_codes_id_list, list):
                                try:
                                    literal_eval_badge_codes_id_list = ast.literal_eval(
                                        badge_codes_id_list)

                                    set_badge_codes_id_list = set(
                                        literal_eval_badge_codes_id_list)
                                except:
                                    return Response(
                                        {'detail': 'Przesyłana wartość w "badge_codes_id_list" musi mieć format list z liczbami określającymi ID kodów aktywacyjnych do rezerwacji.',
                                            "code": "9011"},
                                        status=status.HTTP_400_BAD_REQUEST
                                    )
                            else:
                                set_badge_codes_id_list = set(
                                    badge_codes_id_list)

                            if Event.objects.filter(id=event_id).exists():
                                event = Event.objects.get(id=event_id)
                                if event.user == user:

                                    if Badge.objects.filter(event=event, id=badge_id).exists():
                                        badge = Badge.objects.get(
                                            event=event, id=badge_id)

                                        if not badge.verificated == "rejected":

                                            if BadgeCode.objects.filter(badge=badge, id__in=set_badge_codes_id_list).exists():
                                                badge_codes = BadgeCode.objects.filter(
                                                    badge=badge, id__in=set_badge_codes_id_list)

                                                if badge_codes.count() == len(set_badge_codes_id_list):

                                                    if all(badge_code.status == "a) to_use" for badge_code in badge_codes):

                                                        badge_codes.update(
                                                            status="b) locked")

                                                        badge_codes = BadgesCodesListSerializer(
                                                            badge_codes, many=True)

                                                        return Response(
                                                            {'success': 'Sukces', 'locked_codes': {'data': badge_codes.data, 'id_list': set_badge_codes_id_list, 'append_data': None}, 'used_codes': {'data': None, 'id_list': None},
                                                                "code": "1500"},
                                                            status=status.HTTP_200_OK
                                                        )
                                                    elif not any(badge_code.status == "b) locked" for badge_code in badge_codes):

                                                        # NAMIERZENIE NIEUŻYTYCH KODÓW Z TYCH PODANYCH ORAZ ZMIANA ICH STANU NA LOCKED

                                                        not_used_badge_codes = badge_codes.filter(
                                                            Q(activated_by=None))
                                                        not_used_badge_codes.update(
                                                            status="b) locked")

                                                        # NAMIERZENIE UŻYTYCH KODÓW Z TYCH PODANYCH

                                                        used_badge_codes = badge_codes.select_related(
                                                            'activated_by').filter(~Q(activated_by=None))

                                                        # USTALENIE TYCH ID, KTÓRE ZOSTAŁY UŻYTE DO : 1) USUNIĘCIA Z LISTY PODANYCH ID TYCH, KTORE ZOSTAŁY ZUŻYTE; 2) ABY POINFORMOWAĆ REDUCER O ZMIANIE STANU ZUŻYTYCH KODÓW NA "used" AKTYWOWANE PRZEZ x_user
                                                        used_ids = set(
                                                            used_badge_codes.values_list('id', flat=True))

                                                        # USUNIĘCIE TYCH ID KODÓW Z LISTY KTÓRA ZOSTAŁA WYSŁANA DO LOCKOWANIA, KTÓRE WCZEŚNIEJ ZOSTAŁY AKTYWOWANE, ABY ZWRÓCIĆ DO REDUCERA LISTĘ ID DO ZMIANY STANU NA "locked" a nie "used"
                                                        set_badge_codes_id_list -= used_ids

                                                        # UTWORZENIE NOWYCH KODÓW ZE STATUSEM "b) locked" W TAKIEJ ILOŚCI, ILE KODÓW ZOSTAŁO WYKRYTE JAKO UŻYTE
                                                        new_badge_codes = [
                                                            BadgeCode(badge=badge, status="b) locked") for _ in range(len(used_ids))]

                                                        created_badge_codes = BadgeCode.objects.bulk_create(
                                                            new_badge_codes)

                                                        # UZYSKANIE ID UTWORZONYCH OBIEKTÓW TAK, ABY PRZEKSZTAŁCIĆ W QUERYSET PRZED WYKONANIEM "union"
                                                        created_ids = [
                                                            obj.pk for obj in created_badge_codes]

                                                        # POBRANIE QUERYSET UTWORZONYCH OBIEKTÓW
                                                        created_badge_codes_queryset = BadgeCode.objects.filter(
                                                            pk__in=created_ids)

                                                        # SERIALIZACJA UTWORZONYCH KODÓW DO DODANIA DO REDUCERA
                                                        created_badge_codes_serialized = BadgesCodesCreateSerializer(
                                                            created_badge_codes, many=True)

                                                        # POŁĄCZENIE ZE SOBĄ DLA EXPORTU KODÓW:
                                                        #
                                                        # 1) KODY PODANE KTÓRE NIE SĄ UŻYTE
                                                        #
                                                        # 2) KODY UTWORZONE W ILOŚCI TAKIEJ, ILE WYKRYTO UŻYTYCH

                                                        codes_to_export = not_used_badge_codes.union(
                                                            created_badge_codes_queryset)

                                                        # SERIALIZACJA ZSUMOWANYCH KODÓW DO EXPORTU DO POPRAWNEGO ODBIORU PRZEZ GENERATOR EXCEL

                                                        codes_to_export = BadgesCodesListSerializer(
                                                            codes_to_export, many=True)

                                                        # SERIALIZACJA WCZEŚNIEJ UŻYTYCH KODÓW DO POWIADOMIENIA UŻYTKOWNIKA W MODALU O ZMIANIE
                                                        used_badge_codes = BadgeCodesReturnedUsedSerializer(
                                                            used_badge_codes, many=True)

                                                        return Response(
                                                            {'success': 'Sukces', 'locked_codes': {'data': codes_to_export.data, 'id_list': set_badge_codes_id_list, 'append_data': created_badge_codes_serialized.data}, 'used_codes': {"data": used_badge_codes.data, "id_list": used_ids},
                                                                "code": "1500"},
                                                            status=status.HTTP_200_OK
                                                        )

                                                    else:

                                                        return Response(
                                                            {'detail': 'Nie można przekazywać kodu do rezerwacji, który już wcześniej został zarezerwowany.',
                                                             "code": "9011"},
                                                            status=status.HTTP_400_BAD_REQUEST
                                                        )
                                                else:
                                                    return Response(
                                                        {'detail': 'Przynajmniej jeden z twoich przekazywanych ID kodu aktywacyjnego nie istnieje w tej odznace.',
                                                         "code": "9011"},
                                                        status=status.HTTP_400_BAD_REQUEST
                                                    )
                                            else:
                                                return Response(
                                                    {'detail': 'Żaden z twoich przekazywanych ID kodu aktywacyjnego nie istnieje w tej odznace.',
                                                     "code": "9011"},
                                                    status=status.HTTP_400_BAD_REQUEST
                                                )
                                        else:
                                            return Response(
                                                {'detail': 'Odznaka jest odrzucona.', 'status': {"verificated": badge.verificated, "details": badge.verificated_details},
                                                 "code": "1511"},
                                                status=223
                                            )
                                    else:
                                        return Response(
                                            {'detail': 'Taka odznaka nie istnieje.',
                                             "code": "1512"},
                                            status=222
                                        )
                                else:
                                    return Response(
                                        {'detail': 'Te wydarzenie nie należy do Ciebie.',
                                         "code": "9011"},
                                        status=status.HTTP_400_BAD_REQUEST
                                    )
                            else:
                                return Response(
                                    {'detail': 'Nie ma takiego wydarzenia z takim ID.',
                                     "code": "9011"},
                                    status=status.HTTP_400_BAD_REQUEST
                                )
                        else:
                            return Response(
                                {'detail': 'Musisz podać przynajmniej listę jednoelementową z ID kodu aktywacyjnego.',
                                 "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )
                    else:
                        return Response(
                            {'detail': 'Nie podano ID odznaki.',
                             "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                else:
                    return Response(
                        {'detail': 'Nie podano ID wydarzenia',
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


class BadgeCodesCreateView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = BadgesCodesCreateSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                data = request.data
                event_id = data['event_id']
                badge_id = data['badge_id']
                amount = data['amount']
                user = request.user

                if event_id != "":
                    if badge_id != "":
                        if str(amount).isdigit() and int(amount) > 0 and int(amount) <= 100:

                            if Event.objects.filter(id=event_id).exists():
                                event = Event.objects.get(id=event_id)
                                if event.user == user:

                                    if Badge.objects.filter(event=event, id=badge_id).exists():
                                        badge = Badge.objects.get(
                                            event=event, id=badge_id)

                                        if not badge.verificated == "rejected":

                                            badge_codes = [
                                                BadgeCode(badge=badge) for _ in range(int(amount))]

                                            created_badge_codes = BadgeCode.objects.bulk_create(
                                                badge_codes)

                                            created_badge_codes = BadgesCodesCreateSerializer(
                                                created_badge_codes, many=True)

                                            return Response(
                                                {'success': 'Sukces', 'data': created_badge_codes.data,
                                                    "code": "1501"},
                                                status=status.HTTP_200_OK
                                            )
                                        else:
                                            return Response(
                                                {'detail': 'Odznaka jest odrzucona.', 'status': {"verificated": badge.verificated, "details": badge.verificated_details},
                                                 "code": "1511"},
                                                status=223
                                            )
                                    else:
                                        return Response(
                                            {'detail': 'Taka odznaka nie istnieje.',
                                             "code": "1512"},
                                            status=222
                                        )
                                else:
                                    return Response(
                                        {'detail': 'Te wydarzenie nie należy do Ciebie.',
                                         "code": "9011"},
                                        status=status.HTTP_400_BAD_REQUEST
                                    )
                            else:
                                return Response(
                                    {'detail': 'Nie ma takiego wydarzenia z takim ID.',
                                     "code": "9011"},
                                    status=status.HTTP_400_BAD_REQUEST
                                )
                        else:
                            return Response(
                                {'detail': 'Musisz podać ilość nowych kodów (minimum 1).',
                                    "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )
                    else:
                        return Response(
                            {'detail': 'Nie podano ID odznaki.',
                             "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                else:
                    return Response(
                        {'detail': 'Nie podano ID wydarzenia',
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


class BadgeCodesDeleteView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = BadgesCodesListSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                data = request.data
                event_id = data['event_id']
                badge_id = data['badge_id']
                badge_codes_id_list = data['badge_codes_id_list']
                user = request.user
                if event_id != "":
                    if badge_id != "":
                        if badge_codes_id_list != "":
                            if not isinstance(badge_codes_id_list, list):
                                try:
                                    literal_eval_badge_codes_id_list = ast.literal_eval(
                                        badge_codes_id_list)

                                    set_badge_codes_id_list = set(
                                        literal_eval_badge_codes_id_list)
                                except:
                                    return Response(
                                        {'detail': 'Przesyłana wartość w "badge_codes_id_list" musi mieć format list z liczbami określającymi ID kodów aktywacyjnych do rezerwacji.',
                                            "code": "9011"},
                                        status=status.HTTP_400_BAD_REQUEST
                                    )
                            else:
                                set_badge_codes_id_list = set(
                                    badge_codes_id_list)

                            if Event.objects.filter(id=event_id).exists():
                                event = Event.objects.get(id=event_id)
                                if event.user == user:

                                    if Badge.objects.filter(event=event, id=badge_id).exists():
                                        badge = Badge.objects.get(
                                            event=event, id=badge_id)

                                        if not badge.verificated == "rejected":

                                            if BadgeCode.objects.filter(badge=badge, id__in=set_badge_codes_id_list).exists():
                                                badge_codes = BadgeCode.objects.filter(
                                                    badge=badge, id__in=set_badge_codes_id_list)

                                                if badge_codes.count() == len(set_badge_codes_id_list):

                                                    if all(badge_code.status == "a) to_use" for badge_code in badge_codes):

                                                        badge_codes.delete()

                                                        return Response(
                                                            {'success': 'Sukces', 'deleted_codes': {'data': None, 'id_list': set_badge_codes_id_list}, 'used_codes': {"data": None, "id_list": None},
                                                                "code": "1502"},
                                                            status=status.HTTP_200_OK
                                                        )

                                                    elif not any(badge_code.status == "b) locked" for badge_code in badge_codes):

                                                        # NAMIERZENIE NIEUŻYTYCH KODÓW Z TYCH PODANYCH ORAZ USUNIĘCIE ICH

                                                        not_used_badge_codes = badge_codes.filter(
                                                            Q(activated_by=None))

                                                        deleted_codes = BadgeCodesReturnedUsedSerializer(
                                                            not_used_badge_codes, many=True).data

                                                        not_used_badge_codes.delete()

                                                        # NAMIERZENIE UŻYTYCH KODÓW Z TYCH PODANYCH

                                                        used_badge_codes = badge_codes.select_related(
                                                            'activated_by').filter(~Q(activated_by=None))

                                                        # USTALENIE TYCH ID, KTÓRE ZOSTAŁY UŻYTE DO : 1) USUNIĘCIA Z LISTY PODANYCH ID TYCH, KTORE ZOSTAŁY ZUŻYTE; 2) ABY POINFORMOWAĆ REDUCER O ZMIANIE STANU ZUŻYTYCH KODÓW NA "used" AKTYWOWANE PRZEZ x_user
                                                        used_ids = set(
                                                            used_badge_codes.values_list('id', flat=True))

                                                        # USUNIĘCIE TYCH ID KODÓW Z LISTY KTÓRA ZOSTAŁA WYSŁANA DO USUNIĘCIA, KTÓRE WCZEŚNIEJ ZOSTAŁY AKTYWOWANE, ABY ZWRÓCIĆ DO REDUCERA LISTĘ ID USUNIĘTYCH KODÓW
                                                        set_badge_codes_id_list -= used_ids

                                                        # SERIALIZACJA WCZEŚNIEJ UŻYTYCH KODÓW DO POWIADOMIENIA UŻYTKOWNIKA W MODALU O ZMIANIE ICH STANU
                                                        used_badge_codes = BadgeCodesReturnedUsedSerializer(
                                                            used_badge_codes, many=True)

                                                        return Response(
                                                            {'success': 'Sukces', 'deleted_codes': {'data': deleted_codes, 'id_list': set_badge_codes_id_list}, 'used_codes': {"data": used_badge_codes.data, "id_list": used_ids},
                                                                "code": "1502"},
                                                            status=status.HTTP_200_OK
                                                        )

                                                    else:
                                                        return Response(
                                                            {'detail': 'Nie można przekazywać kodu do usunięcia, który już wcześniej został zarezerwowany.',
                                                             "code": "9011"},
                                                            status=status.HTTP_400_BAD_REQUEST
                                                        )
                                                else:
                                                    return Response(
                                                        {'detail': 'Przynajmniej jeden z twoich przekazywanych ID kodu aktywacyjnego nie istnieje w tej odznace.',
                                                         "code": "9011"},
                                                        status=status.HTTP_400_BAD_REQUEST
                                                    )
                                            else:
                                                return Response(
                                                    {'detail': 'Żaden z twoich przekazywanych ID kodu aktywacyjnego nie istnieje w tej odznace.',
                                                     "code": "9011"},
                                                    status=status.HTTP_400_BAD_REQUEST
                                                )
                                        else:
                                            return Response(
                                                {'detail': 'Odznaka jest odrzucona.', 'status': {"verificated": badge.verificated, "details": badge.verificated_details},
                                                 "code": "1511"},
                                                status=223
                                            )
                                    else:
                                        return Response(
                                            {'detail': 'Taka odznaka nie istnieje.',
                                             "code": "1512"},
                                            status=222
                                        )
                                else:
                                    return Response(
                                        {'detail': 'Te wydarzenie nie należy do Ciebie.',
                                         "code": "9011"},
                                        status=status.HTTP_400_BAD_REQUEST
                                    )
                            else:
                                return Response(
                                    {'detail': 'Nie ma takiego wydarzenia z takim ID.',
                                     "code": "9011"},
                                    status=status.HTTP_400_BAD_REQUEST
                                )
                        else:
                            return Response(
                                {'detail': 'Musisz podać przynajmniej listę jednoelementową z ID kodu aktywacyjnego.',
                                 "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )
                    else:
                        return Response(
                            {'detail': 'Nie podano ID odznaki.',
                             "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                else:
                    return Response(
                        {'detail': 'Nie podano ID wydarzenia',
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


class BadgeEditView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = BadgeEditSerializer

    def image_check(self, image, name, badge_name, badge_image):

        if isinstance(image, str):

            if image == "" and name == badge_name:

                return Response(
                    {'detail': 'Twoja edycja musi wprowadzać przynajmniej zmianę nazwy w momencie, kiedy nie chcesz zmieniać obrazka.',
                        "code": "9011"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            else:
                return Response(
                    {'detail': 'Próbujesz przesłać string w miejsce zdjęcia. Musisz podać dokładny odnośnik starego zdjęcia, aby pozostało ono przypisane do odznaki.',
                        "code": "9011"},
                    status=status.HTTP_400_BAD_REQUEST
                )

        elif image and image.content_type not in ['image/jpeg', 'image/png', 'image/gif']:
            return Response(
                {'detail': 'Przesyłane zdjęcie nie jest plikiem graficznym.',
                    "code": "9011"},
                status=status.HTTP_400_BAD_REQUEST
            )

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                data = request.data
                badge_id = data['badge_id']
                name = data['name']
                image = data['image']
                user = request.user

                if badge_id != "":
                    if name != "":
                        if len(name) >= 5 and len(name) <= 50:
                            if Badge.objects.filter(id=badge_id).exists():
                                badge = Badge.objects.get(id=badge_id)

                                if not badge.verificated == "rejected":

                                    if not Badge.objects.filter(name=name).exists() or badge.name == name:

                                        if badge.creator == user:

                                            if not badge.name == name or not badge.image == image:

                                                # if badge.edit_time

                                                diffrence_time = int(
                                                    (timezone.now() - badge.edit_time).total_seconds())

                                                if diffrence_time > 180:

                                                    filter_save = {}
                                                    if badge.image != image:
                                                        self.image_check(
                                                            image, name, badge.name, badge.image)
                                                        badge.image = image
                                                    else:
                                                        filter_save["generate_thumbnail"] = False

                                                    badge.name = name

                                                    if user.is_admin:
                                                        badge.verificated = "verificated"
                                                        code = "1504"
                                                    else:
                                                        badge.verificated = "awaiting"
                                                        code = "1503"
                                                    badge.save(**filter_save)

                                                    return Response(
                                                        {'success': 'Sukces', 'status': badge.verificated, 'image': badge.image.name, 'name': badge.name,
                                                         "code": code},
                                                        status=status.HTTP_200_OK
                                                    )
                                                else:

                                                    minutes = diffrence_time // 60
                                                    seconds = diffrence_time % 60

                                                    if minutes == 0:
                                                        response = f'Minęło dopiero {seconds} sekund.'

                                                    elif minutes == 1:
                                                        response = f'Minęła dopiero {minutes} minuta i {seconds} sekund.'

                                                    else:
                                                        response = f'Minęły dopiero {minutes} minuty i {seconds} sekund.'

                                                    return Response(
                                                        {'detail': response,
                                                         "code": "1513"},
                                                        status=status.HTTP_400_BAD_REQUEST
                                                    )

                                            else:
                                                return Response(
                                                    {'detail': 'Bez zmian.',
                                                     "code": "1505"},
                                                    status=status.HTTP_400_BAD_REQUEST
                                                )
                                        else:
                                            return Response(
                                                {'detail': 'Podana odznaka nie należy do wydarzenia stworzonego przez tego użytkownika.',
                                                 "code": "9011"},
                                                status=status.HTTP_400_BAD_REQUEST
                                            )

                                    else:
                                        return Response(
                                            {'detail': 'Istnieje już odznaka z taką nazwą',
                                             "code": "1510"},
                                            status=status.HTTP_400_BAD_REQUEST
                                        )
                                else:
                                    return Response(
                                        {'detail': 'Odznaka jest odrzucona.', 'status': {"verificated": badge.verificated, "details": badge.verificated_details},
                                         "code": "1511"},
                                        status=223
                                    )

                            else:
                                return Response(
                                    {'detail': 'Taka odznaka nie istnieje.',
                                     "code": "1512"},
                                    status=222
                                )
                        else:
                            return Response(
                                {'detail': 'Nazwa odznaki musi posiadać minimum 5 znaków i maksymalnie 50 znaków.',
                                 "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )
                    else:
                        return Response(
                            {'detail': 'Nie podano nazwy odznaki.',
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


class BadgeCreateView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = BadgeCreateSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                data = request.data
                event_id = data['event_id']
                name = data['name']
                image = data['image']
                user = request.user

                if event_id != "":
                    if name != "":
                        if len(name) >= 5 and len(name) <= 50:
                            if not Badge.objects.filter(name=name).exists():

                                if Event.objects.filter(id=event_id).exists():
                                    event = Event.objects.get(id=event_id)

                                    if event.user == user:

                                        if image != "":

                                            if image.content_type in ['image/jpeg', 'image/png', 'image/gif']:

                                                badge = Badge(
                                                    event=event, creator=user, name=name, image=image)

                                                if user.is_admin:
                                                    badge.verificated = "verificated"
                                                    code = "1507"
                                                else:
                                                    badge.verificated = "awaiting"
                                                    code = "1506"
                                                badge.save()

                                                badge = BadgeCreateSerializer(
                                                    badge)

                                                return Response(
                                                    {'success': 'Sukces', 'data': badge.data,
                                                        "code": code},
                                                    status=status.HTTP_200_OK
                                                )

                                            else:

                                                return Response(
                                                    {'detail': 'Przesyłane zdjęcie nie jest plikiem graficznym.',
                                                     "code": "9011"},
                                                    status=status.HTTP_400_BAD_REQUEST
                                                )
                                        else:

                                            return Response(
                                                {'detail': 'Nie możesz utworzyć odznaki bez przesłania obrazka.',
                                                 "code": "9011"},
                                                status=status.HTTP_400_BAD_REQUEST
                                            )

                                    else:
                                        return Response(
                                            {'detail': 'Podane ID wydarzenia nie należy do tego użytkownika.',
                                             "code": "9011"},
                                            status=status.HTTP_400_BAD_REQUEST
                                        )
                                else:
                                    return Response(
                                        {'detail': 'Nie istnieje takie wydarzenie z podanym ID.',
                                         "code": "9011"},
                                        status=status.HTTP_400_BAD_REQUEST
                                    )
                            else:
                                return Response(
                                    {'detail': 'Istnieje już odznaka z taką nazwą',
                                     "code": "1510"},
                                    status=status.HTTP_400_BAD_REQUEST
                                )
                        else:
                            return Response(
                                {'detail': 'Nazwa odznaki musi posiadać minimum 5 znaków i maksymalnie 50 znaków.',
                                 "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )
                    else:
                        return Response(
                            {'detail': 'Nie podano nazwy odznaki.',
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


class BadgeDeleteView(APIView):
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
                    if badge.creator == user:

                        badge.delete()

                        return Response(
                            {'success': 'Sukces',
                             "code": "1508"},
                            status=status.HTTP_200_OK
                        )
                    else:
                        return Response(
                            {'detail': 'Odznaka przypisana jest nie do wydarzenia utworzonego przez tego użytkownika.',
                             "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )

                else:
                    return Response(
                        {'detail': 'Nie istnieje odznaka z takim ID.',
                            "code": "1512"},
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
                {'detail': 'Coś poszło nie tak z próbą pobrania danych',
                    "code": "1165"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class UserBadgesView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = UserBadgesActivatedSerializer

    def get(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:

                user = request.user

                filter_activated_badges = {}
                if not user.is_admin:
                    filter_activated_badges["verificated"] = "verificated"

                subquery_activated_time = BadgeCode.objects.filter(
                    badge__pk=OuterRef('pk'), activated_by=user
                ).values('activated_time')[:1]

                subquery_report_type = BadgeReport.objects.filter(
                    badge__pk=OuterRef('pk'), user=user
                ).values('type')[:1]

                activated_badges = user.activated_badges.select_related(
                    'event').filter(**filter_activated_badges).annotate(slug_event=F('event__slug'), uuid_event=F('event__uuid'), activated_time=Subquery(subquery_activated_time), my_report=Subquery(subquery_report_type)).order_by('-id')

                created_badges = Badge.objects.filter(creator=user).select_related(
                    'event', 'creator').annotate(slug_event=F('event__slug'), uuid_event=F('event__uuid'))

                activated_badges = UserBadgesActivatedSerializer(
                    activated_badges, many=True)

                created_badges = UserBadgesCreatedSerializer(
                    created_badges, many=True)

                return Response(
                    {'success': 'Pobrano wydarzenia', 'created_badges': created_badges.data, 'activated_badges': activated_badges.data,
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


class BadgeActivateView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = BadgeActivateSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                data = request.data
                code = data['code']
                user = request.user

                if BadgeCode.objects.filter(code__iexact=code).exists():
                    badge_code = BadgeCode.objects.get(code__iexact=code)

                    if badge_code.badge.creator != user:

                        # GDY KOD DO ODZNAKI NIE ZOSTAŁ UŻYTY
                        if badge_code.status != "c) used":

                            # GDY ODZNAKA ANI RAZU NIE BYŁA AKTYWOWANA PRZEZ USERA
                            if not user.activated_badges.filter(id=badge_code.badge.id).exists():
                                if badge_code.badge.verificated == "verificated":  # GDY JEST ZWERYFIKOWANA, NASTĘPUJE PRZYPISANIE

                                    if user.main_badge == None:
                                        set_main_badge = True
                                        user.main_badge = badge_code.badge
                                        user.save(generate_thumbnail=False)

                                    else:
                                        set_main_badge = False

                                    success_response = 'Sukces'
                                    status_response = status.HTTP_200_OK
                                    only_title = False
                                elif badge_code.badge.verificated == "rejected":

                                    success_response = 'Odznaka, którą próbujesz aktywować została usunięta przez portal z powodu naruszeń regulaminu. Niestety, ale ta odznaka nie zostanie przypisana do twojego konta do odwołania, a kod zostanie usunięty. Gdy odznaka zostanie przywrócona, dostaniesz powiadomienie, a odznaka zostanie przypisana do konta.'
                                    status_response = 223
                                    only_title = True
                                    set_main_badge = False

                                elif badge_code.badge.verificated == "awaiting":

                                    success_response = 'Kod jest poprawny, ale odznaka nie przeszła jeszcze weryfikacji, a jej status to "oczekujący". Gdy odznaka zostanie zweryfikowana, dostaniesz powiadomienie, a odznaka zostanie przypisana do konta.'
                                    status_response = 223
                                    only_title = True
                                    set_main_badge = False

                                else:  # TUTAJ GDY ADMIN TO "BADGET", JAK USER TO "TITLE_EVENT"
                                    success_response = 'Kod jest poprawny, ale odznaka nie przeszła jeszcze weryfikacji, a jej status to "wymaga zmian". Gdy odznaka zostanie zweryfikowana, dostaniesz powiadomienie, a odznaka zostanie przypisana do konta.'
                                    status_response = 223
                                    only_title = True
                                    set_main_badge = False

                                badge_code.badge.badge_owners.add(user)
                                badge_code.status = "c) used"
                                badge_code.activated_by = user
                                badge_code.save()
                                was_activated = False

                            #  GDY ODZNAKA BYŁA AKTYWOWANA, ALE MOŻE MIEĆ DOWOLNY STAN:
                            else:

                                set_main_badge = False

                                # GDY USER/ADMIN PROBUJE AKTYWOWAC ODZNAKE, KTÓRĄ JUZ MA I JEST "ZWERYFIKOWANA"
                                if badge_code.badge.verificated == "verificated":
                                    only_title = False
                                    success_response = 'Ta odznaka jest już aktualnie przypisana do twojego konta.'

                                # GDY USER/ADMIN PROBUJE AKTYWOWAC ODZNAKE, KTÓRĄ JUZ MA, ALE JEST DO "USUNIĘCIA"
                                elif badge_code.badge.verificated == "rejected":
                                    only_title = True
                                    success_response = 'Posiadasz już tą odznakę, ale jej status to "do usunięcia".'

                                # GDY USER/ADMIN PROBUJE AKTYWOWAC ODZNAKE, KTÓRĄ JUZ MA, ALE JEST DO "USUNIĘCIA"
                                elif badge_code.badge.verificated == "awaiting":
                                    only_title = True
                                    success_response = 'Posiadasz już tą odznakę, ale jej status to "oczekujący na akceptację".'

                                else:  # GDY USER/ADMIN PROBUJE AKTYWOWAC ODZNAKE, KTÓRĄ JUZ MA, ALE JEST DO "ZWERYFIKOWANIA"
                                    only_title = True
                                    success_response = 'Posiadasz już tą odznakę, ale jej status to "wymaga zmian".'

                                status_response = 223
                                was_activated = True
                                set_main_badge = False


                            if not user.is_admin and only_title:  # JAK NIE ADMIN I TYLKO TYTUL - TO ZWROC SAM TYTUL, STATUS I ID ODZNAKI
                                badge = {"id": badge_code.badge.id,
                                         "verificated": badge_code.badge.verificated,
                                         "title_event": badge_code.badge.event.title}
                            else:
                                badge = BadgeActivateSerializer(
                                    badge_code.badge, context={'user': user}).data

                            return Response(
                                {'success': success_response, 'data': badge, "was_activated": was_activated, "set_main_badge": set_main_badge,
                                    "code": "7667"},
                                status=status_response
                            )

                        else:  # KOD ZOSTAŁ UŻYTY

                            return Response(
                                {'detail': 'Ten kod został już użyty.',
                                    "code": "1551"},
                                status=status.HTTP_400_BAD_REQUEST
                            )

                    else:
                        return Response(
                            {'detail': 'Nie można aktywować kodu, będąc jego stwórcą.',
                             "code": "1553"},
                            status=status.HTTP_400_BAD_REQUEST
                        )

                else:
                    return Response(
                        {'detail': 'Twój kod aktywacyjny jest błędny.',
                         "code": "1550"},
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


class BadgeReportView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = BadgeReportSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                data = request.data
                id_badge = data['id_badge']
                type = data['type']
                details = data.get('details', None)

                if str(id_badge).isdigit() and Badge.objects.filter(id=id_badge).exists():
                    user = request.user
                    badge = Badge.objects.get(id=id_badge)
                    if not badge.creator == user:

                        if badge.verificated == "verificated":

                            if not BadgeReport.objects.filter(badge=badge, user=user).exists():
                                BadgeReport.objects.create(
                                    badge=badge, user=user, type=type, details=details)

                                return Response(
                                    {'success': 'Sukces', "code": "1010"},
                                    status=status.HTTP_200_OK
                                )
                            else:
                                return Response(
                                    {'detail': 'Już wcześniej zgłosiłeś tą odznakę',
                                        "code": "9011"},
                                    status=status.HTTP_400_BAD_REQUEST
                                )

                        else:

                            if user.is_admin:

                                return Response(
                                    {'detail': 'Można zgłaszać tylko te odznaki, które są w danej chwili zweryfikowane.', "is_admin": user.is_admin, "status": {"status": badge.verificated, "details": badge.verificated_details},
                                        "code": "9011"},
                                    status=223
                                )
                            else:
                                return Response(
                                    {'detail': 'Można zgłaszać tylko te odznaki, które są w danej chwili zweryfikowane.', "is_admin": user.is_admin,
                                        "code": "9011"},
                                    status=223
                                )

                    else:
                        return Response(
                            {'detail': 'Nie możesz zgłosić odznaki, którą sam utworzyłeś',
                                "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                else:
                    return Response(
                        {'detail': 'Nie ma takiej odznaki', "code": "9011"},
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
                                        ~Q(token=refresh_token), ip_validator__in=ip_validators, expires_at__gte=today).exclude(id__in=CustomBlacklistedToken.objects.filter(token__ip_validator__in=ip_validators).values_list('token_id', flat=True))

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

                subquery_past_not_paid_event = Event.objects.filter(~(Exists(Paycheck.objects.filter(event__id=OuterRef('id')))) & Exists(OrderedTicket.objects.filter(ticket__event__id=OuterRef('id'), refunded=False)), user__id=OuterRef('id'), event_date__lt=time_now.date(), verificated="verificated")

                subquery_blocked_change_bank_account = GatewayPaycheck.objects.filter(Q(tickets__order__user__id=OuterRef('id'))|Q(event__user__id=OuterRef('id')), remove_time__gte=time_now)

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

                                if not GatewayPaycheck.objects.filter(Q(tickets__order__user__id=user.id)|Q(event__user__id=user.id), remove_time__gte=time_now).exists():


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
        

                            # stripe.api_key = settings.STRIPE_SECRET_KEY_TEST
                            # stripe_temp = stripe.checkout.Session.create(
                            #     success_url="https://localhost:3000/settings",
                            #     line_items=[{"price": "price_1OWu3oABu55SS04Xt7MGzizM", "quantity": 1}],
                            #     mode="payment",
                            # )

    
class EventTicketsView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = EventTicketsViewSerializer


    def get(self, request, slug, uuid):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                if Event.objects.filter(slug=slug, uuid=uuid).exists():

                    user = request.user

                    event = Event.objects.get(slug__iexact=slug, uuid=uuid)
                    time_now = timezone.now().date()

                    if not user == event.user:


                        if event.verificated == "verificated":

                            if time_now <= event.event_date:

                                time_now_sub = timezone.now()


                                if not Order.objects.filter(user__id=user.id, is_paid=False, order_expires_at__gte=time_now_sub).exists():



                                    subquery_reserved_tickets = OrderedTicket.objects.filter((Q(order__is_paid=True)|Q(order__order_expires_at__gte=time_now_sub))&Q(refunded=False), ticket__id=OuterRef('id')).annotate(count=Func(F('id'), function='Count')).values('count')


                                    tickets = event.tickets_of_event.filter(was_allowed=True).annotate(reserved_tickets=Subquery(subquery_reserved_tickets)).order_by('-price')

                                    tickets = EventTicketsViewSerializer(tickets, many=True)


                                    
                                    return Response(
                                        {'success': 'Sukces', 'data': {'id': event.id, 'title': event.title, 'tickets': tickets.data}, "code": "123123"},
                                        status=status.HTTP_200_OK
                                    )
                                else:
                                    return Response(
                                        {'detail': 'Brak opłaconej poprzedniej transakcji.',
                                        "code": "2112"},
                                        status=224
                                    )
                        
                            else:
                                return Response(
                                    {'detail': 'Nie możesz kupić biletu na odbyte już wydarzenie.',
                                        "code": "2115"},
                                    status=223
                                )

                        else:
                            return Response(
                                {'detail': 'Wydarzenie nie jest zweryfikowane',
                                "code": "2120"},
                                status=222
                            )
                    else:
                        return Response(
                            {'detail': 'Nie możesz kupić biletu na swoje wydarzenie', "code": "99999"},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                else:
                    return Response(
                        {'detail': 'Nie znaleziono takiego wydarzenia', "code": "2113"},
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
        

class LimitTicketsPagination(pagination.LimitOffsetPagination):

    limit_query_param = 'limit'
    offset_query_param = 'offset'

    def modify_url_mode_with_replace(self, url, new_mode_value):
        if url is None:
            return url

        base_url, _, query_string = url.partition('?')

        query_dict = QueryDict(query_string, mutable=True)

        if 'order' in query_dict:
            query_dict.pop('order')


        query_dict['mode'] = new_mode_value

        new_url = f"{base_url}?{query_dict.urlencode()}"

        return new_url





    def generate(self, data, max_limit, mode, request):

        self.max_limit = max_limit
        data = self.paginate_queryset(data, request)
        meta = {
            'links': {
                'next':self.modify_url_mode_with_replace(self.get_next_link(), mode),
                'previous': self.modify_url_mode_with_replace(self.get_previous_link(), mode)
            },
        }

        return meta, data






class EventsViaTicketsView(APIView):
    permission_classes = (permissions.AllowAny, )
    pagination_class = LimitTicketsPagination
    serializer_class = EventsViaTicketsSerializer

    def get(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                user = request.user

                request_data = request.GET
                order_id = request_data.get('order', None)
                mode = request_data.get('mode', None)

                time_now = timezone.now()


                response = {}

                subquery_main_image = EventImage.objects.filter(
                        event=OuterRef('pk'), main=True).values('image_thumbnail')

                if "limit" in request_data:
                    limit = int(request_data.get('limit'))


                    if mode == "start" or mode == "created" or mode == "bought":

                        
                        pagination = LimitTicketsPagination()


                        if len(user.bank_number) == 26 and mode != "bought":

                            # #############
                            

                            subquery_exists_paid_ticket = OrderedTicket.objects.filter(ticket__event__id=OuterRef('id'), order__is_paid=True, refunded=False)

                            #############

                            subquery_reserved_tickets = OrderedTicket.objects.filter((Q(order__is_paid=True)|Q(order__order_expires_at__gte=time_now))&Q(refunded=False), ticket__id=OuterRef('id')).annotate(count=Func(F('id'), function='Count')).values('count')

                            
                            subquery_tickets = Ticket.objects.filter(Q(event__event_date__gte=time_now)|Q(was_allowed=True),
                                event__pk=OuterRef('pk')).annotate(data=JSONObject(id=F('id'), stripe_id=F('stripe_id'), ticket_type=F('ticket_type'), ticket_details=F('ticket_details'),default_price=F('default_price'), price=F('price'), new_price=F('new_price'), was_allowed=F('was_allowed'), quantity=F('quantity'), reserved_tickets=Subquery(subquery_reserved_tickets), verificated=F('verificated'), verificated_details=F('verificated_details'), edit_time=F('edit_time'))).order_by('-price').values('data')

                            #############

                            subquery_event_paid_out = Paycheck.objects.filter(event__id=OuterRef('id'))
                            

                            
                            events_created = Event.objects.select_related('category', 'city').filter(Q(event_date__gte=time_now)|(Exists(subquery_exists_paid_ticket) & ~Exists(subquery_event_paid_out)),
                                user=user, verificated="verificated").annotate(current=ExpressionWrapper(Q(event_date__gte=time_now), output_field=BooleanField()), province=F('city__county__province__name'), image=Subquery(subquery_main_image), tickets=ArraySubquery(subquery_tickets)).order_by('event_date')



                            meta_created, data_created = pagination.generate(events_created, limit, 'created', request)


                            events_created = EventsViaTicketsSerializer(data_created, many=True)

                            response['created'] = {
                                'data': events_created.data,
                                'meta': meta_created
                            }


                            



                        if mode != "created":

                            #############

                            subquery_event = Event.objects.filter(id=OuterRef('ordered_tickets__ticket__event__id')).annotate(data=JSONObject(id=F('id'), city=F('city__name'), province=F('city__county__province__name'), slug=F('slug'), uuid=F('uuid'), title=F('title'),current=Q(event_date__gte=time_now), category=F('category__type'), image=Subquery(subquery_main_image), event_date=F('event_date'), verificated=F('verificated'))).values('data')


                            #############


                            subquery_tickets_refund_paid_out = Paycheck.objects.filter(tickets__id=OuterRef('id'))

                            
                            subquery_details_tickets = OrderedTicket.objects.filter(order__id=OuterRef(OuterRef('id')), ticket__id=OuterRef('id')).annotate(data=JSONObject(id=F('id'), purchase_price=F('purchase_price'), first_name=F('first_name'), last_name=F('last_name'), date_of_birth=F('date_of_birth'), used=F('used'), used_time=F('used_time'), refunded=F('refunded'), paid_out=Exists(subquery_tickets_refund_paid_out))).values('data')

                            subquery_bought_tickets = Ticket.objects.filter(orders_of_tickets__order__id=OuterRef('id')).annotate(data=JSONObject(id=F('id'), stripe_id=F('stripe_id'), ticket_type=F('ticket_type'), ticket_details=F('ticket_details'), details=ArraySubquery(subquery_details_tickets))).values('data').distinct()


                            subquery_paycheck_attachments = Paycheck.objects.filter(~Q(refund_confirmation=""), tickets__order__id=OuterRef('id'), stripe_refund_checkout_mode=False).annotate(data=JSONObject(id=F('id'), tickets_details=ArrayAgg(Concat(F('tickets__first_name'), Value(' '), F('tickets__last_name'))), file=F('refund_confirmation'))).values('data')
                            

                            subquery_exists_stripe_order_refund = Paycheck.objects.filter(tickets__order__id=OuterRef('id'), stripe_refund_checkout_mode=True).order_by('created_at').values('created_at')[:1]



                            subquery_awaitings_refund_amount = AwaitingsTicketsRefund.objects.filter(tickets__order__id=OuterRef('id')).annotate(total=Sum('tickets__purchase_price')).values('total')



                            orders_user = Order.objects.filter(Q(is_paid=True)|Q(order_expires_at__gte=time_now), user=user).annotate(event=Subquery(subquery_event), tickets=ArraySubquery(subquery_bought_tickets), expired_refund=~Q(ordered_tickets__ticket__event__event_date__gt=time_now), stripe_refund_order=Subquery(subquery_exists_stripe_order_refund), awaitings_refund_amount=Subquery(subquery_awaitings_refund_amount), paycheck_attachments=ArraySubquery(subquery_paycheck_attachments)).order_by('is_paid', '-created_at').distinct()



                            #############


                            meta_bought, data_bought = pagination.generate(orders_user, limit, 'bought', request)



                            orders_user = OrderedTicketsSerializer(data_bought, many=True)

                            response['bought'] = {
                                'data': orders_user.data,
                                'meta': meta_bought
                            }




                            



                        #############


                        if str(order_id).isdigit():
                            if Order.objects.filter(id=order_id, is_paid=True):
                                success_details = "Zamówienie zostało poprawnie opłacone."
                                code = "2150"

                            elif Order.objects.filter(id=order_id, is_paid=False, order_expires_at__gte=time_now):
                                success_details = "Wystąpił błąd podczas płatności."
                                code = "2152"

                            else:
                                success_details = "Zamówienie zostało opłacone po wygaśnięciu zamówienia."
                                code = "2151"
                        else:
                            success_details = "Pobrano wydarzenia"
                            code = "7667"



                        return Response(
                            {'success': success_details, 'data': {**response},
                                "code": code},
                            status=status.HTTP_200_OK
                        )
                    else:
                        return Response(
                            {'detail': 'Musisz przekazać parametr "mode" określającą wartość start, bought lub created.',
                                "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                else:
                    return Response(
                        {'detail': 'Nie podano limitu danych.',
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


    def post(self, request):
        try:
            response_verify = token_verify(request)
            
            if response_verify is not None:
                return response_verify
            else:

                user = request.user
                data = request.data
                price = data['price']
                ticket_type = data['ticket_type']
                ticket_details = data['ticket_details']
                quantity = data['quantity']
                event_id = data['event_id']
                time_now = timezone.now().date()
                                            



                if len(user.bank_number) == 26:
                    if str(event_id).isdigit() and Event.objects.filter(id=event_id).exists():

                        event = Event.objects.get(id=event_id)


                        if time_now <= event.event_date:
                            if event.user == user:
                                if event.verificated == "verificated":

                                    if not event.tickets_of_event.filter(ticket_type=ticket_type).exists():

                                        if bool(re.match(r'^[0-9]+\.[0-9]{1,2}$', price)) or price.isdigit():
                                            flt_price = float(price)

                                            if flt_price >= 5:

                                                if str(quantity).isdigit() and int(quantity) > 0:

                                                    if len(ticket_type) > 2:
                                                        if len(ticket_details) > 2:

                                                            
                                                            ticket = Ticket.objects.create(event=event, ticket_type=ticket_type, ticket_details=ticket_details,default_price=flt_price, price=flt_price, new_price=flt_price, quantity=quantity)

                                                            return Response(
                                                                {'success': 'Bilet został utworzony','ticket_id':ticket.id, 'edit_time': ticket.edit_time, "code": "2081"},
                                                                status=status.HTTP_200_OK
                                                            )
                                                        else:
                                                            return Response(
                                                                {'detail': 'Opis biletu musi mieć przynajmniej 3 znaki',
                                                                    "code": "9011"},
                                                                status=status.HTTP_400_BAD_REQUEST
                                                            )
                                                    else:
                                                        return Response(
                                                            {'detail': 'Rodzaj biletu musi mieć przynajmniej 3 znaki',
                                                                "code": "9011"},
                                                            status=status.HTTP_400_BAD_REQUEST
                                                        )
                                                else:
                                                    return Response(
                                                        {'detail': 'Przy tworzeniu biletów minimalna ich ilość to 1.',
                                                            "code": "9011"},
                                                        status=status.HTTP_400_BAD_REQUEST
                                                    )
                                            else:
                                                return Response(
                                                    {'detail': 'Cena biletu musi wynosić przynajmniej 5 zł.',
                                                        "code": "9011"},
                                                    status=status.HTTP_400_BAD_REQUEST
                                                )
                                        else:
                                            return Response(
                                                {'detail': 'Musisz podać odpowiedni format ceny np 200 lub 200.23.',
                                                    "code": "9011"},
                                                status=status.HTTP_400_BAD_REQUEST
                                            )
                                    else:
                                            return Response(
                                                {'detail': 'W tym wydarzeniu utworzyłeś już bilet o takiej nazwie.',
                                                    "code": "2090"},
                                                status=status.HTTP_400_BAD_REQUEST
                                            )
                                
                                else:
                                    return Response(
                                        {'detail': 'Można tworzyć bilety tylko do zweryfikowanych wydarzeń.',
                                            "code": "2091"},
                                        status=223
                                    )
                            else:
                                return Response(
                                    {'detail': 'Nie możesz utworzyć biletu do nie swojego wydarzenia.',
                                        "code": "9011"},
                                    status=status.HTTP_400_BAD_REQUEST
                                )
                        else:
                            return Response(
                                {'detail': 'Nie możesz utworzyć biletu na odbyte już wydarzenie.',
                                    "code": "2082"},
                                status=225
                            )
                        
                    else:
                        return Response(
                            {'detail': 'Wydarzenie nie istnieje',
                            "code": "2092"},
                            status=224
                        )
                else:
                    return Response(
                        {'detail': 'Konto bankowe został odpięte.',
                        "code": "2093"},
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
                {'detail': 'Coś poszło nie tak z próbą pobrania danych',
                    "code": "1165"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    



class TicketEditView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = TicketEditSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            
            if response_verify is not None:
                return response_verify
            else:

                user = request.user
                data = request.data
                price = data['price']
                ticket_type = data['ticket_type']
                ticket_details = data['ticket_details']
                quantity = data['quantity']
                verificated = data['verificated']
                ticket_id = data['ticket_id']
                event_id = data['event_id']
                actual_edit_time = data['actual_edit_time']

                time_now = timezone.now().date()




                if len(user.bank_number) == 26:

                    if str(event_id).isdigit() and Event.objects.filter(id=event_id).exists():

                        event = Event.objects.get(id=event_id)

                        if event.verificated == "verificated": 
                                            
                            if time_now <= event.event_date: 

                                if event.user == user: 

                                    if str(ticket_id).isdigit() and Ticket.objects.filter(id=ticket_id).exists(): 

                                        if event.tickets_of_event.filter(id=ticket_id).exists(): 

                                            ticket = Ticket.objects.get(id=ticket_id)

                                            diffrence_time = int((timezone.now() - ticket.edit_time).total_seconds())



                                            if diffrence_time > 180:

                                                input_formatted = datetime.datetime.strptime(actual_edit_time, '%Y-%m-%dT%H:%M:%S.%f%z').replace(tzinfo=None)


                                                if ticket.edit_time == input_formatted:


                                                    if bool(re.match(r'^[0-9]+\.[0-9]{1,2}$', price)) or price.isdigit():
                                                        flt_price = float(price)

                                                        if flt_price >= 5:

                                                            if str(quantity).isdigit() and int(quantity) > 0:

                                                                time_now_sub = timezone.now()


                                                                reserverd_tickets = OrderedTicket.objects.filter((Q(order__is_paid=True)|Q(order__order_expires_at__gte=time_now_sub))&Q(refunded=False), ticket__id=ticket.id).count()


                                                                if int(quantity) >= reserverd_tickets:



                                                                    if (ticket.verificated == "awaiting" or ticket.verificated == "need_improvement") and ticket.was_allowed == False: 

                                                                        if ticket_type == ticket.ticket_type or (ticket_type != ticket.ticket_type and not event.tickets_of_event.filter(ticket_type=ticket_type).exists()):


                                                                            if len(ticket_type) > 2:

                                                                                if len(ticket_details) > 2:

                                                                                    if ticket.was_allowed == False:
                                                                                        ticket.default_price = flt_price
                                                                                        ticket.price = flt_price

                                                                                    ticket.ticket_type = ticket_type
                                                                                    ticket.ticket_details = ticket_details
                                                                                    ticket.new_price = flt_price
                                                                                    ticket.quantity = int(quantity)
                                                                                    ticket.verificated = "awaiting"

                                                                                    ticket.save()
                

                                                                                    return Response(
                                                                                                {'success': 'Bilet został zedytowany', 'edit_time': ticket.edit_time, "code": "2081"},
                                                                                                status=status.HTTP_200_OK
                                                                                            )
                                                                                else:
                                                                                    return Response(
                                                                                        {'detail': 'Opis biletu musi mieć przynajmniej 3 znaki',
                                                                                            "code": "9011"},
                                                                                        status=status.HTTP_400_BAD_REQUEST
                                                                                    )
                                                                            else:
                                                                                return Response(
                                                                                    {'detail': 'Rodzaj biletu musi mieć przynajmniej 3 znaki',
                                                                                        "code": "9011"},
                                                                                    status=status.HTTP_400_BAD_REQUEST
                                                                                )
                                                                        else:
                                                                            return Response(
                                                                                {'detail': 'W tym wydarzeniu utworzyłeś już bilet o takiej nazwie.',
                                                                                    "code": "2095"},
                                                                                status=status.HTTP_400_BAD_REQUEST
                                                                            )
                                                                            



                                                                    elif not ticket.verificated == "rejected" and ticket.was_allowed == True:
                                                                        
                                                                        if float(ticket.price) >= flt_price:

                                                                            if ticket.price != flt_price:
                                                                                ticket.verificated = "awaiting"
                                                                                code = "2081"
                                                                            else:
                                                                                ticket.verificated = "verificated"
                                                                                code = "2083"
                                                                                
                                                                            ticket.quantity = int(quantity)
                                                                            ticket.new_price = flt_price

                                                                            ticket.save()


                                                                            return Response(
                                                                                        {'success': 'Bilet został zedytowany','edit_time': ticket.edit_time, "code": code},
                                                                                        status=status.HTTP_200_OK
                                                                                    )
                                                                        else:
                                                                            return Response(
                                                                                {'detail': 'Gdy bilet zostanie raz zweryfikowany, możesz jedynie obniżyć jego cene.',
                                                                                    "code": "9011"},
                                                                                status=status.HTTP_400_BAD_REQUEST
                                                                            )
                                                                        
                                                                    else:
                                                                        return Response(
                                                                            {'detail': 'Nie można edytować odrzuconych biletów.',
                                                                                "code": "9011"},
                                                                            status=status.HTTP_400_BAD_REQUEST
                                                                        )
                                                                else:
                                                                    return Response(
                                                                        {'detail': 'Ilość biletów jest mniejsza, niż ilość już kupionych biletów.',
                                                                            'reserverd_tickets': reserverd_tickets,
                                                                            "code": "2096"},
                                                                        status=228
                                                                    )


                                                            else:
                                                                return Response(
                                                                    {'detail': 'Minimalna ilość biletów to 1.',
                                                                        "code": "9011"},
                                                                    status=status.HTTP_400_BAD_REQUEST
                                                                )

                                                        else:
                                                            return Response(
                                                                {'detail': 'Cena biletu musi wynosić przynajmniej 5 zł.',
                                                                    "code": "9011"},
                                                                status=status.HTTP_400_BAD_REQUEST
                                                            )
                                                    
                                                    else:
                                                        return Response(
                                                            {'detail': 'Musisz podać odpowiedni format ceny np 200 lub 200.23.',
                                                                "code": "9011"},
                                                            status=status.HTTP_400_BAD_REQUEST
                                                        )
                                                    
                                                else:
                                                    return Response(
                                                        {'detail': 'Podczas próby edycji, stan weryfikacji biletu uległ zmianie.',
                                                        'data': {
                                                            'stripe_id': ticket.stripe_id,
                                                            'verificated': ticket.verificated,
                                                            'verificated_details': ticket.verificated_details,
                                                            'was_allowed': ticket.was_allowed,
                                                            "ticket_type": ticket.ticket_type, 
                                                            "ticket_details":ticket.ticket_details,
                                                            "default_price": ticket.default_price,
                                                            "price": ticket.price,
                                                            "new_price": ticket.new_price,
                                                            "quantity": ticket.quantity,
                                                            "edit_time": ticket.edit_time,
                                                        },
                                                            "code": "2094"},
                                                        status=226
                                                    )
                                            else:

                                                minutes = diffrence_time // 60
                                                seconds = diffrence_time % 60

                                                if minutes == 0:
                                                    response = f'Minęło dopiero {seconds} sekund.'

                                                elif minutes == 1:
                                                    response = f'Minęła dopiero {minutes} minuta i {seconds} sekund.'

                                                else:
                                                    response = f'Minęły dopiero {minutes} minuty i {seconds} sekund.'

                                                return Response(
                                                    {'detail': response,
                                                        "code": "1513"},
                                                    status=status.HTTP_400_BAD_REQUEST
                                                )
                                        
                                        else:
                                            return Response(
                                                {'detail': 'Podany ID biletu nie określa biletu przypisanego do tego wydarzenia.',
                                                    "code": "9011"},
                                                status=status.HTTP_400_BAD_REQUEST
                                            )
                                    
                                    else:
                                        return Response(
                                            {'detail': 'Bilet nie istnieje',
                                            "code": "2092"},
                                            status=225
                                        )
                                        
                                else:
                                    return Response(
                                        {'detail': 'Nie możesz edytować biletu do nie swojego wydarzenia.',
                                            "code": "9011"},
                                        status=status.HTTP_400_BAD_REQUEST
                                    )
                            else:
                                return Response(
                                    {'detail': 'Nie możesz edytować biletu na wydarzenie, które się odbyło.',
                                        "code": "2082"},
                                    status=227
                                )
                        
                        else:
                                    return Response(
                                        {'detail': 'Można edytować bilety tylko do zweryfikowanych wydarzeń.',
                                            "code": "2091"},
                                        status=223
                                    )
                
                    else:
                        return Response(
                            {'detail': 'Wydarzenie nie istnieje',
                            "code": "2092"},
                            status=224
                        )
                
                else:
                    return Response(
                        {'detail': 'Konto bankowe zostało odpięte.',
                        "code": "2093"},
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
                {'detail': 'Coś poszło nie tak z próbą pobrania danych',
                    "code": "1165"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    

class TicketDeleteView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = TicketDeleteSerializer


    def post(self, request):
        try:
            response_verify = token_verify(request)
            
            if response_verify is not None:
                return response_verify
            else:

                user = request.user
                data = request.data

                ticket_id = data['ticket_id']
                event_id = data['event_id']
                time_now = timezone.now().date()
                                            

                if len(user.bank_number) == 26:
                    if str(event_id).isdigit() and Event.objects.filter(id=event_id).exists():

                        event = Event.objects.get(id=event_id)
                        if event.verificated == "verificated":
                            if time_now <= event.event_date:
                                if event.user == user:
                                    
                                    if str(ticket_id).isdigit() and Ticket.objects.filter(id=ticket_id).exists():

                                        if event.tickets_of_event.filter(id=ticket_id).exists():

                                            ticket = Ticket.objects.get(id=ticket_id)

                                            if ticket.was_allowed == False:


                                                ticket.delete()


                                                return Response(
                                                    {'success': 'Sukces', "code": "2100"},
                                                    status=status.HTTP_200_OK
                                                )
                                            else:
                                                return Response(
                                                    {'detail': 'Podczas próby usunięcia, bilet został zweryfikowany.',
                                                   'data': {
                                                        'stripe_id': ticket.stripe_id,
                                                        'verificated': ticket.verificated,
                                                        'verificated_details': ticket.verificated_details,
                                                        'was_allowed': ticket.was_allowed,
                                                        "ticket_type": ticket.ticket_type, 
                                                        "ticket_details":ticket.ticket_details,
                                                        "default_price": ticket.default_price,
                                                        "price": ticket.price,
                                                        "new_price": ticket.new_price,
                                                        "quantity": ticket.quantity,
                                                        "edit_time": ticket.edit_time,
                                                     },
                                                        "code": "2094"},
                                                    status=226
                                                )
                                        
                                        else:
                                            return Response(
                                                {'detail': 'Podany ID biletu nie określa biletu przypisanego do tego wydarzenia.',
                                                    "code": "9011"},
                                                status=status.HTTP_400_BAD_REQUEST
                                            )
                                        
                                    else:
                                        return Response(
                                            {'detail': 'Bilet nie istnieje',
                                            "code": "2092"},
                                            status=225
                                        )
                                    
                                else:
                                    return Response(
                                        {'detail': 'Nie możesz usuwać biletu do nie swojego wydarzenia.',
                                            "code": "9011"},
                                        status=status.HTTP_400_BAD_REQUEST
                                    )
                            else:
                                return Response(
                                    {'detail': 'Nie możesz usuwać biletu na odbyte już wydarzenie.',
                                        "code": "2082"},
                                    status=227
                                )
                        else:
                                return Response(
                                    {'detail': 'Można usuwać bilety tylko do zweryfikowanych wydarzeń.',
                                        "code": "2091"},
                                    status=223
                                )
                        
                    else:
                        return Response(
                            {'detail': 'Wydarzenie nie istnieje',
                            "code": "2092"},
                            status=224
                        )
                else:
                    return Response(
                        {'detail': 'Konto bankowe został odpięte.',
                        "code": "2093"},
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
                {'detail': 'Coś poszło nie tak z próbą pobrania danych',
                    "code": "1165"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        

class TicketPayView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = TicketPaySerializer

    def check_key_exists(self, data, key):
        if key not in data:
            data[key] = {}
        return data

    def personal_data_validation(self, data, ticket, price):

        ordered_tickets_instances = []
        response = None


        for personal_data in data:
            try:
                date_of_birth = parse_date(personal_data['date_of_birth'])
                if not len(personal_data['first_name']) >= 3:
                    response = Response(
                        {'detail': 'Imie musi posiadać przynajmniej 3 znaki.',
                            "code": "9011"},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                elif not len(personal_data['last_name']) >= 3:
                    response = Response(
                        {'detail': 'Nazwisko musi posiadać przynajmniej 3 znaki.',
                            "code": "9011"},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                elif not date_of_birth:
                    response = Response(
                        {'detail': 'Data urodzin musi być w formacie "2024-01-17".',
                            "code": "9011"},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                
                else:
                    ordered_tickets_instances.append(OrderedTicket(ticket=ticket,purchase_price=price, first_name=personal_data['first_name'], last_name=personal_data['last_name'], date_of_birth=personal_data['date_of_birth']))

            except KeyError:
                response = Response(
                    {'detail': 'Każdy bilet musi posiadać informacje o osobie takie jak "first_name", "last_name" oraz "date_of_birth" w poprawnym formacie.',
                        "code": "9011"},
                    status=status.HTTP_400_BAD_REQUEST
                )
        return response, ordered_tickets_instances


    def post(self, request):
        try:
            response_verify = token_verify(request)
            
            if response_verify is not None:
                return response_verify
            else:

                user = request.user
                data = request.data
                event_id = data['event_id']
                tickets_input = data['tickets_data']
                time_now = timezone.now().date()
                error_tickets = {}
                request_schema = []
                tickets_instances_to_create = []
                amount_total = 0

                if not isinstance(tickets_input, dict):
                    try:
                        tickets_data = eval(tickets_input)
                    except:
                        return Response(
                            {'detail': 'Przesyłana wartość "tickets_data" nie jest odpowiedniego formatu.',
                                "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                else:
                    tickets_data = tickets_input



                time_now_sub = timezone.now()


                if reduce(lambda x, y: x + len(y['personal_data']), tickets_data.values(), 0) <= 10:



                    if not Order.objects.filter(Q(order_expires_at__gte=time_now_sub)|Q(order_expires_at=None), user__id=user.id, is_paid=False).exists():
                        
                        if str(event_id).isdigit() and Event.objects.filter(id=event_id).exists():


                            
                            stripe_ids = list(tickets_data.keys())

                            ticket_objects = list(Ticket.objects.filter(stripe_id__in=stripe_ids))

                            event = Event.objects.get(id=event_id)
                            all_tickets_event = list(event.tickets_of_event.all()) 



                            if event.verificated == "verificated":

                                if event.user != user:

                                    if len(ticket_objects) == len(stripe_ids):


                                        if time_now <= event.event_date:

                                        
                                            if all(ticket_obj in all_tickets_event for ticket_obj in ticket_objects):

                                                

                                                # if all(ticket_obj.verificated == "verificated" for ticket_obj in ticket_objects):
                                                if all(ticket_obj.was_allowed for ticket_obj in ticket_objects):

                                                    

                                                    for key in tickets_data:

                                                        ############################## VALIDACJA DANYCH WEJSCIOWYCH ZWIAZANYCH Z BILETEM

                                                        ticket = Ticket.objects.get(stripe_id=key)
                                                        count_ticket_to_buy = len(tickets_data[key]['personal_data'])

                                                        # SPRAWDZENIE CZY CENA W BAZIE DANYCH NIE ZMIENIŁA SIĘ W TRAKCIE ZAKUPU BILETÓW
                                                        try:
                                                            decimal_price = Decimal(tickets_data[key]['price'])
                                                            amount_total += decimal_price * count_ticket_to_buy
                                                            if not decimal_price == ticket.price:
                                                                error_tickets = self.check_key_exists(error_tickets, key)
                                                                error_tickets[key]['new_price'] = ticket.price
                                                        except InvalidOperation:
                                                            return Response(
                                                                {'detail': 'Każdy bilet musi posiadać informacje o cenie określoną w zmiennej "price".',
                                                                    "code": "9011"},
                                                                status=status.HTTP_400_BAD_REQUEST
                                                            )
                                                        
                                                        # SPRAWDZENIE POPRAWNOŚCI ZMIENNYCH ZWIĄZANYMI Z DANYMI OSOBOWYMI

                                                        error_response, ordered_tickets_instances = self.personal_data_validation(tickets_data[key]['personal_data'], ticket, decimal_price)

                                                        if error_response != None:
                                                            return error_response
                                                        else:
                                                            tickets_instances_to_create.extend(ordered_tickets_instances)


                                                        # SPRAWDZENIE CZY JEST DOSTĘPNYCH TYLE BILETÓW DO KUPIENIA
                                                            

                                                            
                                                        reserved_tickets = OrderedTicket.objects.filter((Q(order__is_paid=True)|Q(order__order_expires_at__gte=time_now_sub))&Q(refunded=False), ticket__id=ticket.id).count()
                                                            

                                                        if count_ticket_to_buy > ticket.quantity - reserved_tickets: 
                                                            error_tickets = self.check_key_exists(error_tickets, key)
                                                            error_tickets[key]['quantity'] = {
                                                                'quantity':ticket.quantity,
                                                                'reserved_tickets':reserved_tickets
                                                            }  
                                                        else:
                                                            request_schema.append({"price": key, "quantity": count_ticket_to_buy})


                                                    # IF DO ZWROTU DO FRONTENDU INFORMACJI O BRAKUJĄCYCH BILETACH W BAZIE LUB INNEJ CENIE, GDY W LISCIE ZNAJDĄ SIĘ DANE
                                                    if len(error_tickets) == 0:


                                                        order = Order.objects.create(user=user)

                                                        try:


                                                            stripe.api_key = settings.STRIPE_SECRET_KEY_TEST
                                                            stripe_response = stripe.checkout.Session.create(
                                                                success_url=f'{FRONTEND_IP}/my_tickets?order={order.id}',
                                                                line_items=request_schema,
                                                                mode="payment",
                                                            )
            
                                                            converted_amount_total = int(str(amount_total).replace('.', ''))


                                                            if stripe_response.amount_total == converted_amount_total:

                                                                created_at = datetime.datetime.utcfromtimestamp(stripe_response.created) + timedelta(hours=1)
                                                                order_expires_at_temp = datetime.datetime.utcfromtimestamp(stripe_response.expires_at) + timedelta(hours=1)
                                                                expires_event_date = datetime.datetime.combine(event.event_date, datetime.time(23, 59, 59))
                                                                next_try_at_temp = created_at + timedelta(minutes=5)


                                                                if order_expires_at_temp > expires_event_date:
                                                                    order_expires_at = expires_event_date
                                                                else:
                                                                    order_expires_at = order_expires_at_temp


                                                                if next_try_at_temp > expires_event_date:
                                                                    next_try_at = expires_event_date
                                                                else:
                                                                    next_try_at = next_try_at_temp

                                                                
                                                                for ticket_instance in tickets_instances_to_create:
                                                                    ticket_instance.order = order

                                                                created_orderedtickets = OrderedTicket.objects.bulk_create(tickets_instances_to_create)

                                                                created_ids = [created_orderedticket.id for created_orderedticket in created_orderedtickets]

                                                                order.stripe_payment_intent_id=stripe_response.id
                                                                order.stripe_created_at = created_at
                                                                order.order_expires_at = order_expires_at
                                                                order.next_try_at = next_try_at
                                                                order.orderedtickets_ids_array = created_ids
                                                                order.save()


                                                                return Response(
                                                                        {'success': 'Sukces','url':stripe_response.url, "code": "2110"},
                                                                        status=status.HTTP_200_OK
                                                                    )


                                                            else:
                                                                return Response(
                                                                    {'detail': 'Cena biletu na Stripe nie została odświeżona.',
                                                                        "code": "2119"},
                                                                    status=222
                                                                )

                                                        except stripe.error.StripeError as e:

                                                            order.delete()


                                                            return Response(
                                                                {'detail': 'Wystąpił błąd w połączeniu ze Stripe.',
                                                                    "code": "2118"},
                                                                status=222
                                                            )

                                                    else:
                                                        
                                                        return Response(
                                                            {'detail': 'Zmiana danych biletu podczas zakupu.', 'error_tickets': error_tickets,
                                                                "code": "2117"},
                                                            status=224
                                                        )
                                                else:

                                                    verificated_tickets = []

                                                    for ticket_obj in all_tickets_event:
                                                        if ticket_obj.was_allowed:
                                                            verificated_tickets.append(ticket_obj.id)

                                                    return Response(
                                                        {'detail': 'Nie wszystkie bilety są dopuszczone do kupna.',
                                                        'correct_tickets': verificated_tickets,
                                                            "code": "2116"},
                                                        status=223
                                                    )
                                            
                                            else:
                                                return Response(
                                                    {'detail': 'Nie wszystkie bilety są przypisane do tego wydarzenia.',
                                                        "code": "9011"},
                                                    status=status.HTTP_400_BAD_REQUEST
                                                )
                                        

                                        else:
                                            return Response(
                                                {'detail': 'Nie możesz kupić biletu na odbyte już wydarzenie.',
                                                    "code": "2115"},
                                                status=222
                                            )

                                    else:

                                        exists_tickets = {}
                                        for ticket_obj in all_tickets_event:
                                            if ticket_obj.was_allowed:
                                                exists_tickets[ticket_obj.id] = ticket_obj.stripe_id


                                        return Response(
                                            {'detail': 'Lista biletów została odświeżona.','correct_tickets':exists_tickets,
                                                "code": "2114"},
                                            status=223
                                        )
                                else:
                                        return Response(
                                            {'detail': 'Nie możesz kupić biletu na swoje wydarzenie.',
                                                "code": "9011"},
                                            status=status.HTTP_400_BAD_REQUEST
                                        )
                            else:
                                return Response(
                                    {'detail': 'Wydarzenie nie jest zweryfikowane',
                                    "code": "2120"},
                                    status=226
                                )
                        else:
                            return Response(
                                {'detail': 'Wydarzenie nie istnieje',
                                "code": "2113"},
                                status=226
                            )
                    else:
                        return Response(
                            {'detail': 'Brak opłaconej poprzedniej transakcji.',
                            "code": "2112"},
                            status=225
                        )
                else:
                    return Response(
                        {'detail': 'W pojedynczym zamówieniu możesz kupić maksymalnie 10 biletów.',
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




class TicketGeneratePDFView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = EventsViaTicketsSerializer

    def get_base64_image_data(self, image_url):
        try:
            image_response = requests.get(image_url, verify=False)
            image = Image.open(BytesIO(image_response.content))

            buffered = BytesIO()
            image.save(buffered, format="PNG")
            return base64.b64encode(buffered.getvalue()).decode('utf-8')
        except Exception as e:
            print(f'Error processing image: {e}')
            return ''

    def get(self, request, id):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                user = request.user

                if str(id).isdigit() and OrderedTicket.objects.filter(id=id).exists():

                    ticket = OrderedTicket.objects.get(id=id)

                    if ticket.order.user.id == user.id:

                        if ticket.order.is_paid:

                            if not ticket.refunded and not ticket.ticket.event.to_start_refund:

                                main_image = EventImage.objects.get(event__id=ticket.ticket.event.id, main=True)

                                context = {
                                    'first_name': ticket.first_name,
                                    'last_name': ticket.last_name,
                                    'date_of_birth': ticket.date_of_birth.strftime('%Y-%m-%d'),
                                    'price': ticket.purchase_price,
                                    'purchase_time': ticket.order.paid_time.strftime('%Y-%m-%d %H:%M'),
                                    'event_name': ticket.ticket.event.title,
                                    'ticket_type': ticket.ticket.ticket_type,
                                    'ticket_details': ticket.ticket.ticket_details,
                                }



                                qr_code_data = self.get_base64_image_data(f'{BACKEND_IP}{ticket.qr_code.url}')
                                event_photo_data = self.get_base64_image_data(f'{BACKEND_IP}{main_image.image.url}')

                                context['qr_code'] = f'data:image/png;base64,{qr_code_data}'
                                context['event_photo'] = f'data:image/png;base64,{event_photo_data}'


                                html_content = get_template('template_ticket.html').render(context)

                                response = HttpResponse(content_type='application/pdf', status=status.HTTP_200_OK)
                                response['Content-Disposition'] = f'attachment; filename="ticket_{ticket.id}.pdf"'

                                pisa_status = pisa.CreatePDF(html_content, dest=response, encoding='utf-8')

                                if pisa_status.err:
                                    return HttpResponse('Error generating PDF', status=500)

                                return response
                            
                            else:



                                if Paycheck.objects.filter(tickets__id=ticket.id).exists():
                                    paid_out_status = True
                                    code = "2135"
                                else:
                                    paid_out_status = False
                                    code = "2136"

                                return Response(
                                    {'detail': 'Bilet został przekazany do zwrotu.', 'paid_out_status': paid_out_status,
                                        "code": code},
                                    status=223
                                )
                        

                        else:
                            return Response(
                                {'detail': 'Bilet nie jest opłacony.',
                                    "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )

                    else:
                        return Response(
                            {'detail': 'To nie jest twój bilet.',
                                "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                
                else:
                    return Response(
                        {'detail': 'Nie ma takiego biletu.',
                            "code": "2100"},
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
                {'detail': 'Coś poszło nie tak z próbą pobrania danych',
                    "code": "1165"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class TicketRefundView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = TicketRefundSerializer


    def post(self, request):
        try:
            response_verify = token_verify(request)
            
            if response_verify is not None:
                return response_verify
            else:

                user = request.user
                data = request.data

                event_id = data['event_id']
                orderedticket_id = data['orderedticket_id']
                time_now = timezone.now().date()
                                            

                if len(user.bank_number) == 26:

                    if str(event_id).isdigit() and Event.objects.filter(id=event_id).exists():

                        if str(orderedticket_id).isdigit() and OrderedTicket.objects.filter(id=orderedticket_id).exists():


                            if OrderedTicket.objects.filter(id=orderedticket_id, ticket__event__id=event_id).exists():


                                orderedticket = OrderedTicket.objects.get(id=orderedticket_id)


                                if orderedticket.order.user.id == user.id:


                                    if not orderedticket.used:

                                        if orderedticket.order.is_paid:

                                            if not orderedticket.refunded and not orderedticket.ticket.event.to_start_refund:

                                                if orderedticket.ticket.event.event_date > time_now:
                                                    


                                                    orderedticket.refunded = True

                                                    orderedticket.save()



                                                    return Response(
                                                                {'success': 'Sukces.',
                                                                    "code": "2139"},
                                                                status=status.HTTP_200_OK
                                                            )
                                            
                                                else:
                                                    return Response(
                                                        {'detail': 'Nie możesz zwracać biletów na wydarzenie, które się odbyło lub jest tego samego dnia.',
                                                            "code": "2134"},
                                                        status=226
                                                    )
                                            
                                            else:
                                                
                                                if Paycheck.objects.filter(tickets__id=orderedticket.id).exists():
                                                    paid_out_status = True
                                                    code = "2135"
                                                else:
                                                    paid_out_status = False
                                                    code = "2136"



                                                return Response(
                                                    {'detail': 'Bilet został przekazany już do zwrotu.', 'paid_out_status': paid_out_status,
                                                        "code": code},
                                                    status=225
                                                )
                                        
                                        else:
                                            return Response(
                                                {'detail': 'Bilet nie jest opłacony.',
                                                    "code": "9011"},
                                                status=status.HTTP_400_BAD_REQUEST
                                            )
                                    else:
                                        return Response(
                                            {'detail': 'Próbujesz zwrócić użyty bilet.', 'used_time': orderedticket.used_time,
                                                "code": "2138"},
                                            status=227
                                        )

                                else:
                                    return Response(
                                        {'detail': 'To nie jest twój bilet.',
                                            "code": "9011"},
                                        status=status.HTTP_400_BAD_REQUEST
                                    )

                        
                            else:
                                return Response(
                                    {'detail': 'Podany ID zamówionego biletu nie określa biletu przypisanego do tego wydarzenia.',
                                        "code": "9011"},
                                    status=status.HTTP_400_BAD_REQUEST
                                )
                        
                        else:
                                return Response(
                                    {'detail': 'Bilet nie istnieje',
                                    "code": "2113"},
                                    status=224
                                )
                    else:
                        return Response(
                            {'detail': 'Nie ma takiego wydarzenia.',
                                "code": "2113"},
                            status=223
                        )
                else:
                    return Response(
                        {'detail': 'Konto bankowe został odpięte.',
                        "code": "2137"},
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
                {'detail': 'Coś poszło nie tak z próbą pobrania danych',
                    "code": "1165"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )





class OrderedTicketActionView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = OrderedTicketActionSerializer



    def post(self, request):
        try:
            response_verify = token_verify(request)
            
            if response_verify is not None:
                return response_verify
            else:

                user = request.user
                data = request.data

                event_id = data['event_id']
                order_id = data['order_id']
                action_type = data['action_type']
                orderedticket_ids = data['orderedticket_ids']
                time_now = timezone.now()

                error_response, set_orderedticket_ids = check_orderedtickets_ids(orderedticket_ids)
                if error_response != None:
                    return error_response
                


                if action_type == "cancel" or action_type == "pay":


                    if str(event_id).isdigit() and Event.objects.filter(id=event_id).exists():

                        if str(order_id).isdigit() and Order.objects.filter(id=order_id, user__id=user.id).exists():


                            if Order.objects.filter(id=order_id, ordered_tickets__ticket__event__id=event_id).exists():

                                order = Order.objects.get(id=order_id)

                                all_tickets_order = order.ordered_tickets.all().values_list('id', flat=True)

                                if not order.is_paid:

                                    if time_now <= order.order_expires_at: 


                                        orderedtickets = OrderedTicket.objects.filter(id__in=set_orderedticket_ids)

                                        if len(orderedtickets) == len(set_orderedticket_ids):

                                            if all(ticket.id in all_tickets_order for ticket in orderedtickets):

                                                if action_type == "cancel":

                                                    orderedtickets.delete()

                                                    return Response(
                                                            {'success': 'Bilet zostały anulowany.',
                                                                "code": "2140"},
                                                            status=status.HTTP_200_OK
                                                        )
                                                else:

                                                    if time_now >= order.next_try_at:

                                                        price_comparison_data = OrderedTicket.objects.filter(
                                                            order__user__id=user.id,
                                                            order_id=order_id
                                                        ).values_list('purchase_price', 'ticket__price')

                                                        if all(purchase_price == ticket_price for purchase_price, ticket_price in price_comparison_data):

                                                            temp_request_retry_schema = defaultdict(int)
                                                            
                                                            for ticket_schema in orderedtickets.values('ticket__stripe_id'):
                                                                temp_request_retry_schema[ticket_schema['ticket__stripe_id']] += 1
                                                            
                                                            request_retry_schema = [{'price': key, 'quantity': value} for key, value in temp_request_retry_schema.items()]

                                                            try:

                                                                stripe.api_key = settings.STRIPE_SECRET_KEY_TEST

                                                                try:
                                                                    stripe.checkout.Session.expire(order.stripe_payment_intent_id)
                                                                except:
                                                                    pass

                                                                stripe_retry_response = stripe.checkout.Session.create(
                                                                    success_url=f'{FRONTEND_IP}/my_tickets?order={order.id}',
                                                                    line_items=request_retry_schema,
                                                                    mode="payment",
                                                                )

                                                                if time_now + timezone.timedelta(minutes=5) > order.order_expires_at:
                                                                    next_retry_try_at = order.order_expires_at
                                                                else:
                                                                    next_retry_try_at = time_now + timezone.timedelta(minutes=5)

                                                                order.next_try_at = next_retry_try_at
                                                                order.stripe_payment_intent_id = stripe_retry_response.id
                                                                order.orderedtickets_ids_array = orderedticket_ids


                                                                order.save()

                                                                return Response(
                                                                        {'success': 'Sukces', 'url':stripe_retry_response.url,
                                                                            "code": "2110"},
                                                                        status=status.HTTP_200_OK
                                                                    )

                                                            except stripe.error.StripeError as e:
                                                                return Response(
                                                                    {'detail': 'Wystąpił błąd w połączeniu ze Stripe.',
                                                                        "code": "2118"},
                                                                    status=status.HTTP_400_BAD_REQUEST
                                                                )

                                                        else:

                                                            new_prices_queryset = OrderedTicket.objects.filter(~Q(purchase_price=F('ticket__price')), order__user__id=user.id, order_id=order_id).distinct().values('ticket__id', 'ticket__price')

                                                            new_prices = {entry['ticket__id']: entry['ticket__price'] for entry in new_prices_queryset}

                                                            subquery_new_price = Ticket.objects.filter(id=OuterRef('ticket__id')).values('price')

                                                            OrderedTicket.objects.filter(~Q(purchase_price=F('ticket__price')), order__user__id=user.id, order_id=order_id).update(purchase_price=Subquery(subquery_new_price))


                                                            return Response(
                                                                {'detail': 'Cena biletów została obniżona przez organizatora.', 'new_price': new_prices,
                                                                    "code": "2142"},
                                                                status=227
                                                            )
                                                    else:

                                                        remaining_time = order.next_try_at - time_now

                                                        minutes, seconds = divmod(remaining_time.seconds, 60)

                                                        if minutes == 0:
                                                            detail_remaining = f'Pozostało {seconds} sekund do kolejnej próby opłacenia.'
                                                        else:
                                                            detail_remaining = f'Pozostało {minutes} minut i {seconds} sekund do kolejnej próby opłacenia.'


                                                        return Response(
                                                            {'detail': detail_remaining,
                                                                "code": "2155"},
                                                            status=228
                                                        )



                                            else:
                                                return Response(
                                                    {'detail': 'Nie wszystkie bilety są przypisane do tego wydarzenia.',
                                                        "code": "9011"},
                                                    status=status.HTTP_400_BAD_REQUEST
                                                )
                                        
                                        else:

                                            return Response(
                                                {'detail': 'Przynajmniej jeden bilet nie istnieje.','exists_orderedtickets':all_tickets_order,
                                                    "code": "2142"},
                                                status=226
                                            )
                                    else:
                                        return Response(
                                            {'detail': 'Zamówienie przekroczyło czas na ponowną próbę opłacenia.',
                                                "code": "2115"},
                                            status=224
                                        )
                                    
                                else:

                                    return Response(
                                        {'detail': 'Zamówienie zostało już wcześniej opłacone.', 'paid_time': order.paid_time, 'exists_orderedtickets ': all_tickets_order,
                                            "code": "2141"},
                                        status=225
                                    )
                              
                            else:
                                return Response(
                                    {'detail': 'Podany ID złożonego zamówienia nie określa zamówienia przypisanego do tego wydarzenia.',
                                        "code": "9011"},
                                    status=status.HTTP_400_BAD_REQUEST
                                )
                    
                        else:
                            return Response(
                                {'detail': 'Nie ma takiego zamówienia.',
                                    "code": "2113"},
                                status=223
                            )
                    
                    else:
                        return Response(
                            {'detail': 'Nie ma takiego wydarzenia.',
                                "code": "2113"},
                            status=222
                        )
                else:
                    return Response(
                        {'detail': 'Wartość action_type musi być równa "cancel" lub "pay".',
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
        

        
@csrf_exempt
def payment(request):
    stripe.api_key = settings.STRIPE_SECRET_KEY_TEST
    payload = request.body
    signature_header = request.META['HTTP_STRIPE_SIGNATURE']
    event = None


    try:
        event = stripe.Webhook.construct_event(
            payload, signature_header, settings.STRIPE_WEBHOOK_SECRET_TEST
        )
    except ValueError as e:
        raise HttpResponse(status=400)
    except stripe.error.SignatureVerificationError as e:
        raise HttpResponse(status=400)
    

    if event['type'] == 'checkout.session.completed':
        order_payment_intent_id = event['data']['object']['id']

        if Order.objects.filter(stripe_payment_intent_id=order_payment_intent_id, order_expires_at__gte=timezone.now()):

            order = Order.objects.get(stripe_payment_intent_id=order_payment_intent_id)
            tickets_paid_ids = ast.literal_eval(order.orderedtickets_ids_array)
            tickets_delete = OrderedTicket.objects.filter(~Q(id__in=tickets_paid_ids), order__id=order.id)
            tickets_delete.delete()

            order.set_paid(event['data']['object']['payment_intent'])

        else:
            checkout_session_payment_intent_id = event['data']['object']['payment_intent']

            stripe.Refund.create(payment_intent=checkout_session_payment_intent_id, reason='fraudulent', success_url=f'{FRONTEND_IP}/my_tickets')

    return HttpResponse(status=200)




class LimitSoldPagination(pagination.LimitOffsetPagination):

    limit_query_param = 'limit'
    offset_query_param = 'offset'

    def generate(self, data, max_limit, request):

        self.max_limit = max_limit
        data = self.paginate_queryset(data, request)
        meta = {
            'links': {
                'next': self.get_next_link(),
                'previous': self.get_previous_link()
            },
        }

        return meta, data






class SoldTicketsViaCalendarView(APIView):
    permission_classes = (permissions.AllowAny, )
    pagination_class = LimitSoldPagination
    serializer_class = SoldTicketsViaCalendarSerializer

    def get(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:

                request_data = request.GET
                year = request_data.get('year', None)
                month = request_data.get('month', None)

                if "limit" in request_data:
                    limit = int(request_data.get('limit'))


                    if not year is None:
                        if str(year).isdigit() and int(year) >= 2013 and int(year) <= 2033:
                            if not month is None:
                                if str(month).isdigit() and int(month) >= 0 and int(month) <= 11:

                                    user = request.user

                                    if len(user.bank_number) == 26:

                                        time_now = timezone.now()

                                        num_days = calendar.monthrange(
                                            int(year), int(month)+1)[1]

                                        start_date = year + "-" + \
                                            str(int(month)+1).zfill(2) + "-01"

                                        end_date = year + "-" + \
                                            str(int(month)+1).zfill(2) + \
                                            "-" + str(num_days)
                                        
                                        subquery_main_image = EventImage.objects.filter(event=OuterRef('pk'), main=True).values('image_thumbnail')

                                        subquery_exists_bought_ticket = OrderedTicket.objects.filter(ticket__event__id=OuterRef('id'), order__is_paid=True)


                                        subquery_event_paid_out = Paycheck.objects.filter(event__id=OuterRef('id'))

                                        ###############

                                        subquery_earn_event = OrderedTicket.objects.filter(
                                                    ticket__event__id=OuterRef('id'),
                                                    order__is_paid=True,
                                                    refunded=False
                                                ).values('ticket__event').annotate(total=Sum('purchase_price')).values('total')
                                        
                                        
                                        subquery_refund_event = OrderedTicket.objects.filter(
                                                    ticket__event__id=OuterRef('id'),
                                                    order__is_paid=True,
                                                    refunded=True
                                                ).values('ticket__event').annotate(total=Sum('purchase_price')).values('total')
                                        


                                        ###############


                                        subquery_reserved_tickets = OrderedTicket.objects.filter((Q(order__is_paid=True)|Q(order__order_expires_at__gte=time_now))&Q(refunded=False), ticket__id=OuterRef('id')).annotate(count=Func(F('id'), function='Count')).values('count')


                                        ###############

                                        subquery_sold_tickets = OrderedTicket.objects.filter(ticket__id=OuterRef('id'), order__is_paid=True, refunded=False).values('purchase_price').annotate(count=Count('purchase_price'), total=Sum('purchase_price')).annotate(data=JSONObject(count=F('count'), purchase_price=F('purchase_price'), total=F('total'))).order_by('-purchase_price').values('data')

                                        subquery_refunded_tickets = OrderedTicket.objects.filter(ticket__id=OuterRef('id'), order__is_paid=True, refunded=True).values('purchase_price').annotate(count=Count('purchase_price'), total=Sum('purchase_price')).annotate(data=JSONObject(count=F('count'), purchase_price=F('purchase_price'), total=F('total'))).order_by('-purchase_price').values('data')

                                        subquery_earn_type = OrderedTicket.objects.filter(
                                                    ticket__id=OuterRef('id'),
                                                    order__is_paid=True,
                                                    refunded=False
                                                ).values('ticket__event').annotate(total=Sum('purchase_price')).values('total')
                                        
                                        subquery_refund_type = OrderedTicket.objects.filter(
                                                    ticket__id=OuterRef('id'),
                                                    order__is_paid=True,
                                                    refunded=True
                                                ).values('ticket__event').annotate(total=Sum('purchase_price')).values('total')
                                        


                                        subquery_type_tickets = Ticket.objects.filter(was_allowed=True, event__pk=OuterRef('pk')).annotate(
                                            earn=Coalesce(Subquery(subquery_earn_type), Value(0)),
                                            data=JSONObject(
                                                id=F('id'),
                                                ticket_type=F('ticket_type'),
                                                quantity=F('quantity'),
                                                reserved=Subquery(subquery_reserved_tickets),
                                                statistics=JSONObject(
                                                    sold_tickets=ArraySubquery(subquery_sold_tickets),
                                                    refunded_tickets=ArraySubquery(subquery_refunded_tickets),
                                                    earn=Coalesce(Subquery(subquery_earn_type), Value(0)),
                                                    refund=Coalesce(Subquery(subquery_refund_type), Value(0)),
                                                ),
                                            )).order_by('-earn').values('data')
                                        


                                        subquery_paycheck_attachments = Paycheck.objects.filter(~Q(refund_confirmation=""), event__id=OuterRef('id'), stripe_refund_checkout_mode=False).annotate(data=JSONObject(id=F('id'), file=F('refund_confirmation'))).values('data')

                                        
                                        

                                        events_via_month = Event.objects.select_related('category', 'city').filter(Exists(subquery_exists_bought_ticket), user=user, event_date__range=[start_date, end_date]).annotate(
                                            current=ExpressionWrapper(Q(event_date__gte=time_now), output_field=BooleanField()), 
                                            province=F('city__county__province__name'), 
                                            image=Subquery(subquery_main_image),
                                            tickets=ArraySubquery(subquery_type_tickets),
                                            earn=Coalesce(Subquery(subquery_earn_event), Value(0, output_field=DecimalField())),
                                            refund=Coalesce(Subquery(subquery_refund_event), Value(0, output_field=DecimalField())),
                                            earn_cancel=Case(When((Q(verificated="rejected")&Q(rejected_time__lt=ExpressionWrapper(F('event_date') + timedelta(days=1), output_field=fields.DateField()))),then=Value(True)), default=Value(False), output_field=BooleanField()),
                                            paid_out=Exists(subquery_event_paid_out),
                                            paycheck_attachments=Subquery(subquery_paycheck_attachments)
                                            ).order_by('event_date')


                                        pagination = LimitSoldPagination()

                                        meta, data = pagination.generate(events_via_month, limit, request)

                                        events_via_month_pagination = SoldTicketsViaCalendarSerializer(data, many=True)

                                        return Response(
                                            {'success': 'Pobrano wydarzenia',
                                                "data": events_via_month_pagination.data, 'meta':meta, "code": "7667"},
                                            status=status.HTTP_200_OK
                                        )
                                    else:
                                        return Response(
                                            {'success': 'Do podglądu swoich sprzedanych biletów, musisz mieć podpięte konto bankowe do konta', "code": "7667"},
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
                else:
                    return Response(
                        {'detail': 'Nie podano limitu danych.',
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
        

class PaymentConfirmationPDFView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = EventsViaTicketsSerializer


    def get(self, request, id):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                user = request.user

                if str(id).isdigit() and Paycheck.objects.filter(id=id).exists():

                    paycheck = Paycheck.objects.get(id=id)

                    if paycheck.user.id == user.id:


                        filename = os.path.basename(paycheck.refund_confirmation.name)


                        with open(paycheck.refund_confirmation.path, 'rb') as file:
                            response = HttpResponse(file.read(), content_type='application/pdf')
                            response['Content-Disposition'] = f'attachment; filename="{filename}"'
                            return response
                        
                    else:
                        return Response(
                            {'detail': 'Płatność nie była wykonywana przez tego użytkownika.',
                                "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                
                else:
                    return Response(
                        {'detail': 'Nie ma takiej płatności.',
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
        

@method_decorator(ensure_csrf_cookie, name='dispatch')
class TicketValidateView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = TicketValidateSerializer


    def post(self, request):
        try:
            data = request.data

            uuid_ticket = data['uuid_ticket']

            if OrderedTicket.objects.filter(code=uuid_ticket).exists():

                ticket = OrderedTicket.objects.get(code=uuid_ticket)

                if not ticket.refunded:

                    if not ticket.used:

                        ticket.set_used()

                        return Response(
                                {'success': 'Bilet skasowany pomyślnie', "code": "7667"},
                                status=status.HTTP_200_OK
                            )
                    
                    else:
                        return Response(
                            {'detail': f'Bilet został już wcześniej skasowany - {ticket.used_time}.',
                                "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                
                else:
                    return Response(
                        {'detail': 'Bilet został zwrócony przez zamawiającego.',
                            "code": "9011"},
                        status=status.HTTP_400_BAD_REQUEST
                    )

            else:
                return Response(
                    {'detail': 'Nie ma takiego biletu.',
                        "code": "9011"},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
        except ValidationError:


            return Response(
                    {'detail': 'Przesłana wartość UUID nie jest poprawnego formatu.',
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