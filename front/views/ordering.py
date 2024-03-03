from rest_framework.views import APIView
from rest_framework import permissions, status, pagination
from rest_framework.response import Response
from ..serializers import EventTicketsViewSerializer, EventsViaTicketsSerializer, OrderedTicketsSerializer, TicketEditSerializer, TicketDeleteSerializer, TicketPaySerializer, TicketRefundSerializer, OrderedTicketActionSerializer, SoldTicketsViaCalendarSerializer, TicketValidateSerializer
from ..models import Event, Order, OrderedTicket, EventImage, Paycheck, Ticket, AwaitingsTicketsRefund, Image
from .functions import token_verify, check_orderedtickets_ids
from django.template.loader import get_template
from django.views.decorators.csrf import csrf_exempt
from django.db.models import Value, OuterRef, Func, F, Q, Subquery, ExpressionWrapper, Exists, BooleanField, Sum, Count, DecimalField, fields, Case, When
from django.db.models.functions import Concat, JSONObject, Coalesce
from django.contrib.postgres.expressions import ArraySubquery
from django.contrib.postgres.aggregates import ArrayAgg
from django.conf import settings
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.utils.dateparse import parse_date
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import ensure_csrf_cookie
from decimal import Decimal, InvalidOperation
from functools import reduce 
from django.http import QueryDict, HttpResponse
from io import BytesIO
from xhtml2pdf import pisa
from collections import defaultdict
import re
import datetime
import stripe
import ast
import calendar
import os
from datetime import timedelta
from ips_config import BACKEND_IP, FRONTEND_IP


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



    def get(self, request, id):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                user = request.user

                if str(id).isdigit() and OrderedTicket.objects.filter(id=id).exists():

                    orderedticket = OrderedTicket.objects.get(id=id)

                    if orderedticket.order.user.id == user.id:

                        if orderedticket.order.is_paid:

                            if not orderedticket.refunded and not orderedticket.ticket.event.to_start_refund:

                                context = orderedticket.generate_ticket_pdf()
                                
                                html_content = get_template('template_ticket.html').render(context)

                                response = HttpResponse(content_type='application/pdf', status=status.HTTP_200_OK)
                                response['Content-Disposition'] = f'attachment; filename="ticket_{orderedticket.id}.pdf"'

                                pisa_status = pisa.CreatePDF(html_content, dest=response, encoding='utf-8')

                                if pisa_status.err:
                                    return HttpResponse('Error generating PDF', status=500)

                                return response
                            
                            else:



                                if Paycheck.objects.filter(tickets__id=orderedticket.id).exists():
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