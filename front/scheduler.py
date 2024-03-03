from apscheduler.schedulers.background import BackgroundScheduler
from django.conf import settings
from django.utils import timezone
from .models import Event, Badge, NotificationsForUser, DeleteModel, Notification, Order, Ticket, OrderedTicket, Paycheck, MyUser, GatewayPaycheck, AwaitingsTicketsRefund
from django.db.models import F, ExpressionWrapper, fields, Exists, OuterRef, Q, Sum
from datetime import timedelta
import stripe
from ips_config import FRONTEND_IP
from .views.functions import send_websocket_notification
from django.db.models.functions import Concat, JSONObject, Length, Coalesce, Cast
from django.contrib.postgres.aggregates import ArrayAgg, JSONBAgg


def start_scheduler():
    scheduler = BackgroundScheduler(settings.APSCHEDULER)
    scheduler.remove_all_jobs()
    scheduler.add_job(delete_remove_objects, 'interval',
                      hours=72, replace_existing=True) ## USUWANIE STARYCH MODELI hours=72
    scheduler.add_job(delete_old_and_notvalid_notification, 'interval',
                    hours=24, replace_existing=True) ## USUWANIE Z POWIADOMIEN TYCH NOTYFIKACJI, KTORE OBEJMUJĄ USUNIETE MODELE
    scheduler.add_job(allow_paycheck_for_event, 'interval', days=7, replace_existing=True) ## JESLI EVENT JEST ZWERYFIKOWANY PO 7 DNIACH OD ZAKONCZENIA, WŁĄCZANA JEST MOZLIWOSC WYPLATY
    scheduler.add_job(manage_stage_gateways_paycheck, 'interval', minutes=15, replace_existing=True) ## ZARZĄDZANIE BRAMKAMI RĘCZNYCH WYPŁAT, KTÓRE SĄ USUWANE DO 25 MINUT PO OTWARCIU

    scheduler.start()





    

def automatic_refund_tickets_rejectedevent():


    stripe.api_key = settings.STRIPE_SECRET_KEY_TEST


    event_ids = Event.objects.filter(verificated="rejected", to_start_refund=False, rejected_time__lt=ExpressionWrapper(F('event_date') + timedelta(days=1), output_field=fields.DateField())).values_list('id', flat=True)
    

    recipients_no_bank_notifications = {}

    time_now = timezone.now()

    for event_id in event_ids:

        customers_id = MyUser.objects.filter(order__ordered_tickets__ticket__event__id=event_id).distinct().values_list('id', flat=True)

    
        recipients_refund_notifications = []

        for customer_id in customers_id:


            Order.objects.filter(ordered_tickets__ticket__event__id=event_id, is_paid=False, user__id=customer_id).delete()


            all_orders_paid = Order.objects.filter(ordered_tickets__ticket__event__id=event_id, is_paid=True, user__id=customer_id).distinct()

            

            # JEŚLI ISTNIEJĄ JAKIES ZAMÓWIENIA, W KTÓRYCH 
            
            #BILET NIE ZOSTAŁ UŻYTY, ANI NIE ZOSTAŁA OPŁACONA JEGO REFUNDACJA ZA ZWROT, 
            #!!ORAZ!!! 
            #ŻADEN BILET NIE MA OTWARTEGO GATEWAYA BO TO ZNACZY ZE ZOSTALA ROZPOCZETA AKCJA ZWROTU, TO COFAMY PLATNOSC W API NA KONTO Z KTOREGO ZOSTALO ZAPLACONE ZA BILETY

            if all_orders_paid.filter(
                ~(Exists(OrderedTicket.objects.filter(order__id=OuterRef('id'), used=True))) & 
                ~(Exists(Paycheck.objects.filter(tickets__order__id=OuterRef('id')))) & 
                ~(Exists(GatewayPaycheck.objects.filter(Q(tickets__order__id=OuterRef('id'))&Q(remove_time__gte=time_now))))
                ).exists():

                orders  = all_orders_paid.filter(~(Exists(OrderedTicket.objects.filter(order__id=OuterRef('id'), used=True))) 
                                                 & ~(Exists(Paycheck.objects.filter(tickets__order__id=OuterRef('id')))) 
                                                 & ~(Exists(GatewayPaycheck.objects.filter(tickets__order__id=OuterRef('id')))))

                success_order_tickets = []

                for order in orders:
                    try:

                        stripe.Refund.create(payment_intent=order.checkout_payment_intent_id, reason='fraudulent')

                        queryset_refunded_tickets = order.ordered_tickets.filter(~(Exists(Paycheck.objects.filter(tickets__id=OuterRef('id')))))

                        success_order_tickets.extend(queryset_refunded_tickets.values_list('id', flat=True))
                       
                    except Exception as e:
                        print(e)
                        print(f"Typ błędu: {type(e).__name__}")
                        print(f"Kod błędu: {e.args[0]}")
                        print("Traceback:")
                        pass


                total_amount = OrderedTicket.objects.filter(id__in=success_order_tickets).aggregate(total=Sum('purchase_price'))['total']

                
                
                if total_amount > 0:

                    user = MyUser.objects.get(id=customer_id)

                    paycheck = Paycheck.objects.create(user=user, amount=total_amount, stripe_refund_checkout_mode=True)
                    paycheck.tickets.set(success_order_tickets)
                    recipients_refund_notifications.append(user)


            # JEŚLI UZYTKOWNIK ODPIAL SWOJE KONTO BANKOWE OD PROFILU, A SYSTEM AUTOMATYCZNEGO ZWROTU WYKRYL, ZE ISTNIEJE JAKIES ZAMÓWIENIE TEGO USERA 
            # W KTORYM ZOSTAL OPLACONY ZWROT LUB BILET ZOSTAL UZYTY I STRONA DOMAGA SIE OD NIEGO PODPIECIA KONTA BANKOWEGO W CELU DOKONANIA PRZELEWU ZA ZWROT
                    
            if MyUser.objects.filter(bank_number="", id=customer_id).exists() and all_orders_paid.filter( 
                                                        (
                                                        Q(Exists(Paycheck.objects.filter(tickets__order__id=OuterRef('id')))) 
                                                        |
                                                        Q(Exists(OrderedTicket.objects.filter(order__id=OuterRef('id'), used=True)))
                                                        )  
                                                        &
                                                        Q(Exists(OrderedTicket.objects.filter(~(Exists(Paycheck.objects.filter(tickets__id=OuterRef('id')))), order__id=OuterRef('id'), used=False)))
                                                        ).exists():


                order_ids_problem = all_orders_paid.filter(
                    (
                        Q(Exists(Paycheck.objects.filter(tickets__order__id=OuterRef('id'))))
                        |
                        Q(Exists(OrderedTicket.objects.filter(order__id=OuterRef('id'), used=True)))
                    )
                    &
                    Q(Exists(OrderedTicket.objects.filter(~(Exists(Paycheck.objects.filter(tickets__id=OuterRef('id')))), order__id=OuterRef('id'), used=False)))
                    ).values_list('id', flat=True)

                orderedtickets_awaiting_to_pin_banknumber = OrderedTicket.objects.filter(
                                        ~(Exists(Paycheck.objects.filter(tickets__id=OuterRef('id')))), 
                                        order__in=order_ids_problem, used=False).values_list('id', flat=True)

                user = MyUser.objects.get(id=customer_id)
                new_awaitings, created = AwaitingsTicketsRefund.objects.get_or_create(user=user )
                new_awaitings.tickets.add(*orderedtickets_awaiting_to_pin_banknumber)
                new_awaitings.set_total_amount()

                recipients_no_bank_notifications[user.id] = {'user': user, 'notification': new_awaitings}

            # PRZYPADKI GDY USER MA PODPIETE KONTO BANKOWE I MA JAKIES ZAMÓWIENIA, W KTORYCH JUZ UZYL BILET LUB DOSTAL PIENIADZE ZA ZWROT LUB ADMIN OTWORZYL WŁAŚNIE GATEWAY DO NIEOPLACONEGO BILETU W CELU WYKONANIA ZWROTU , SĄ OBSLUGIWANE RECZNIE PRZED ADMINA W PANELU ADMINISTRACYJNYM 
            OrderedTicket.objects.filter(order__in=all_orders_paid, used=False).distinct().update(refunded=True)


        send_websocket_notification(recipients_refund_notifications, 15, Order.objects.filter(ordered_tickets__ticket__event__id=event_id).first(), timezone.now(), False)
                
    for user_no_bank in recipients_no_bank_notifications.keys():
        send_websocket_notification([recipients_no_bank_notifications[user_no_bank]['user']], 16, recipients_no_bank_notifications[user_no_bank]['notification'], timezone.now(), False)




def delete_remove_objects():

    time_now = timezone.now()


    badges_rejected_to_deleted = Badge.objects.filter(
        verificated="rejected", to_remove=True)
    badges_rejected_to_deleted.delete()

    badges_rejected_add_flag = Badge.objects.filter(
        verificated="rejected", to_remove=False)
    badges_rejected_add_flag.update(to_remove=True)

    # events_rejected_to_deleted = Event.objects.filter(
    #     verificated="rejected", to_remove=True)
    # events_rejected_to_deleted.delete()

    events_rejected_add_flag = Event.objects.filter(
        verificated="rejected", to_start_refund=True, to_remove=False)
    events_rejected_add_flag.update(to_remove=True)




    automatic_refund_tickets_rejectedevent()
    events_rejected_add_flag = Event.objects.filter(
        verificated="rejected", to_start_refund=False)
    events_rejected_add_flag.update(to_start_refund=True)



    tickets_rejected_to_deleted = Ticket.objects.filter(
        verificated="rejected", to_remove=True)
    tickets_rejected_to_deleted.delete()

    tickets_rejected_add_flag = Ticket.objects.filter(
        verificated="rejected", to_remove=False)
    tickets_rejected_add_flag.update(to_remove=True)


    not_payed_orders = Order.objects.filter(is_paid=False, order_expires_at__lt=time_now)
    not_payed_orders.delete()


def allow_paycheck_for_event():
    time_limit_to_paycheck = timezone.now() - timedelta(days=7)
    Event.objects.filter(verificated="verificated", allow_paycheck=False, event_date__lt=time_limit_to_paycheck).update(allow_paycheck=True)




def manage_stage_gateways_paycheck():

    time_now = timezone.now()

    expired_gateways_paycheck = GatewayPaycheck.objects.filter(remove_time__lt=time_now, stage_to_remove=True, paycheck=None)
    expired_gateways_paycheck.delete() 

    GatewayPaycheck.objects.filter(stage_to_remove=False, paycheck=None).update(stage_to_remove=True, remove_time=time_now+timezone.timedelta(minutes=10))




    


def delete_old_and_notvalid_notification():
    users_notifications = NotificationsForUser.objects.all()
    notifications_schemas = Notification.objects.in_bulk()
    deleted_models = DeleteModel.objects.all()

    deleted_models_schema = {
        'MyUser': [],
        'IPAddress': [],
        'Event': [],
        'CommentEvent': [],
        'Badge': [],
        'Ticket': [],
        'Order': [],
        'GatewayPaycheck': [],
    }


    for deleted_model in deleted_models:
        deleted_models_schema[deleted_model.content_type] = eval(deleted_model.ids_array)


    for user_notifications in users_notifications:
        new_notifications_array = []
        user_notifications_array = eval(user_notifications.notifications_array)


        # ODFILTROWANIE POWIADOMIEN Z OBIEKTÓW, KTÓRE ZOSTAŁY USUNIĘTE

        for simple_notification in user_notifications_array:

            #ROZPAKOWYWUJE POWIADOMIENIE NA KONKRETNE WARTOSCI
            notification_schema_id, content_id, _ , _  = simple_notification
            content_type = notifications_schemas.get(notification_schema_id).content_type

            if content_id not in deleted_models_schema[content_type]:
                new_notifications_array.append(simple_notification)

        


        # JESLI NOWA LISTA DALEJ MA WIECEJ NIZ 42 POWIADOMIENIA, SKRACAMY JĄ:
        #   - JEŚLI INDEX OSTATNIEGO NIEPRZECZYTANEGO POWIADOMIENIA JEST MNIEJSZY/RÓWNY 37, TO SKRACAMY JEDYNIE NOWE POWIADOMIENIA DO 42                                    - 42
        
        #   - JESLI INDEX OSTATNIEGO NIEPRZECZYTANEGO POWIADOMIENIA ZNAJDUJE SIE W PRZEDZIALE 38-65, TO ZOSTAWIAMY WSZYSTKIE NIEPRZECZYTANE WIADOMOSCI + 5 PRZECZYTANYCH    - 70

        #   - JEŚLI INDEX OSTATNIEGO NIEPRZECZYTANEGO POWIADOMIENIA JEST WIEKSZY/ROWNY 66, TO SKRACAMY ILOSC WSZYSTKICH WIADOMOSCI DO 70                                    - 70
        if len(new_notifications_array) > 42:

            index_last_not_seen_notification = 0


            for index, notification in enumerate(new_notifications_array):
               
                if notification[3] == 1:
                    index_last_not_seen_notification = index - 1
                    break  

            if index_last_not_seen_notification <= 37:
                new_notifications_array = new_notifications_array[:42]
            
            elif index_last_not_seen_notification >= 66:
                new_notifications_array = new_notifications_array[:70]

            else:
                new_notifications_array = new_notifications_array[:index_last_not_seen_notification+5]

        user_notifications.notifications_array = new_notifications_array

        user_notifications.save()


    # PO OCZYSZCZANIU WSZYSTKICH POWIADOMIEN USERÓW, OCZYSZCZAMY MODELE ZWIAZANE Z ZAPISYWANIEM NR ID MODELI, KTORE ZOSTALY USUNIETE W PRZECIAGU 24H
    deleted_models.update(ids_array="[]")

        