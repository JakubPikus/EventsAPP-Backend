from django.contrib.gis.db.models.functions import Distance
from django.contrib.gis.geos import Point
from ..models import City, CodeRegistration, MyUser, Image, IPAddress, IPAddressValidator, CommentEventReaction, CommentEventReport, CommentEvent, EventImage, Ticket, OrderedTicket, Paycheck, AwaitingsTicketsRefund, Order, GatewayPaycheck, Event
from django.template.loader import render_to_string
from django.core.mail import EmailMessage
from ..custom_refresh_token import CustomRefreshToken
from rest_framework.response import Response
from django.conf import settings
import datetime
import re
import ast
import PyPDF2
import requests
import base64
from rest_framework import status
from io import BytesIO
from django.utils import timezone
from django.db.models import OuterRef, Subquery, CharField, Case, When, F, Exists, Sum, Value
from django.db.models.functions import JSONObject, Concat
from ..serializers import CommentEventSerializer
from django.contrib.postgres.fields import JSONField
from django.contrib.postgres.expressions import ArraySubquery
from django.contrib.postgres.aggregates import ArrayAgg
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync






def get_location_from_ip(ip_address):


    endpoint = f"https://freeipapi.com/api/json/{ip_address}"
    response = requests.get(endpoint)
    data = response.json()
    latitude = float(data['latitude'])
    longitude = float(data['longitude'])

    # latitude = 52.881409
    # longitude = 20.619961

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

                    time_now = timezone.now()

                    tokens_to_blacklist = ip_validator.refresh_tokens_of_validator.filter(expires_at__gt=time_now, customblacklistedtoken__isnull=True)
                    
                    for refresh_token in tokens_to_blacklist:
                        token = CustomRefreshToken(refresh_token.token)
                        token.blacklist()


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
        'author__image_thumbnail'), search_user_id=Value(user.id), my_reaction=Subquery(subquery_my_reaction), my_report=Subquery(subquery_report_type), **filter_admin).order_by('-id')


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

