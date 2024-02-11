from .models import change_main_badge, Badge, CommentEventReport, GatewayPaycheck, AwaitingsTicketsRefund, Ticket, EventReport, BadgeReport, MyUser, IPAddress, Event, CommentEvent, DeleteModel, OrderedTicket, Order
from django.db.models.signals import pre_delete, post_save, pre_save, post_delete
from django.dispatch import receiver
import random
from django.utils import timezone



def append_delete_model_id(type, ids):
    obj = DeleteModel.objects.get(content_type=type)
    list_of_arrays = eval(obj.ids_array)
    list_of_arrays.extend(ids)
    obj.ids_array = list_of_arrays
    obj.save()





@receiver(pre_delete, sender=MyUser)
def pre_delete_myuser(instance, **kwargs):
    append_delete_model_id("MyUser", [instance.id])


@receiver(pre_delete, sender=IPAddress)
def pre_delete_ipaddress(instance, **kwargs):
    append_delete_model_id("IPAddress", [instance.id])

@receiver(pre_delete, sender=Event)
def pre_delete_event(instance, **kwargs):
    append_delete_model_id("Event", [instance.id])
    

@receiver(pre_delete, sender=CommentEvent)
def pre_delete_commentevent(instance, **kwargs):
    append_delete_model_id("CommentEvent", [instance.id])



@receiver(pre_delete, sender=Badge)
def pre_delete_badge(instance, **kwargs):
    change_main_badge(instance)
    append_delete_model_id("Badge", [instance.id])



@receiver(pre_delete, sender=Ticket)
def pre_delete_ticket(instance, **kwargs):
    append_delete_model_id("Ticket", [instance.id])


@receiver(pre_delete, sender=Order)
def pre_delete_order(instance, **kwargs):
    append_delete_model_id("Order", [instance.id])

@receiver(pre_delete, sender=AwaitingsTicketsRefund)
def pre_delete_awaitingsticketsrefund(instance, **kwargs):
    append_delete_model_id("AwaitingsTicketsRefund", [instance.id])


@receiver(pre_delete, sender=GatewayPaycheck)
def pre_delete_gatewaypaycheck(instance, **kwargs):
    if instance.paycheck != None:
        append_delete_model_id("GatewayPaycheck", [instance.id])



@receiver(post_save, sender=CommentEventReport)
def count_author_reports(instance, created, **kwargs):
    if created:
        user = instance.comment.author
        user.count_reported_comments += 1
        user.save(generate_thumbnail=False)


@receiver(post_save, sender=EventReport)
def count_author_reports(instance, created, **kwargs):
    if created:
        user = instance.event.user
        user.count_reported_events += 1
        user.save(generate_thumbnail=False)


@receiver(post_save, sender=BadgeReport)
def count_author_reports(instance, created, **kwargs):
    if created:
        user = instance.badge.creator
        user.count_reported_badges += 1
        user.save(generate_thumbnail=False)


@receiver(post_delete, sender=OrderedTicket)
def post_delete_order_tickets_check(instance, **kwargs):

    try:
        if Order.objects.filter(id=instance.order.id).exists():
            order = Order.objects.get(id=instance.order.id)
            if order.ordered_tickets.count() == 0:
                instance.order.delete()
            
    except Order.DoesNotExist:
        pass


def generator_stripe(base_name):

    name = f'{base_name}-{random.randint(1000,9999)}'

    if not Ticket.objects.filter(stripe_name_product=name).exists():
        return name
    else:
        generator_stripe(base_name)


   

@receiver(post_save, sender=Ticket)
def generate_stripe_name(instance, created, **kwargs):
    if created:
        structure_name = f'{instance.event.id}-{instance.id}-{instance.ticket_type}'

        stripe_name_product = generator_stripe(structure_name)

        instance.stripe_name_product = stripe_name_product
        instance.save()


@receiver(post_save, sender=GatewayPaycheck)
def generate_remove_time_date(instance, created, **kwargs):
    if created:
        instance.remove_time = instance.created_at + timezone.timedelta(minutes=17)
        instance.save()






            



