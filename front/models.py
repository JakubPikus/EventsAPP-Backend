from django.conf import settings
from django.db import models
from django.contrib.gis.db import models as models_gis
from django.utils import timezone
from django.contrib.auth.models import (
    BaseUserManager, AbstractBaseUser
)
import random
import string
import uuid
import qrcode
from datetime import datetime
import os
import secrets
from django.template.defaultfilters import slugify
import time
from django.db.models import Max, Min, OuterRef, Subquery, Count, F, Sum
from django.contrib.gis.measure import D
from django.contrib.gis.db.models.functions import Distance
from django.db import connection
from PIL import Image
from io import BytesIO
from django.core.files.uploadedfile import InMemoryUploadedFile
from django.apps import apps
from django.utils.translation import gettext_lazy as _
from django.core.exceptions import ValidationError, ObjectDoesNotExist
from django.core.validators import MinLengthValidator, MaxLengthValidator
import zlib
from channels.db import database_sync_to_async


# from rest_framework_simplejwt.token_blacklist.models import OutstandingToken


########################### IMPORT LOCALIZATIONS #############################


class Province(models.Model):
    id = models.CharField(primary_key=True, max_length=3, db_index=True)
    name = models.CharField(max_length=100, unique=True)

    def __str__(self):
        return self.name


class County(models.Model):
    id = models.CharField(primary_key=True, max_length=3, db_index=True)
    name = models.CharField(max_length=100)
    province = models.ForeignKey(
        Province, on_delete=models.CASCADE, db_index=True)

    def __str__(self):
        return self.name


class City(models.Model):
    name = models.CharField(max_length=100)
    id = models.CharField(primary_key=True, max_length=10, db_index=True)
    county = models.ForeignKey(
        County, on_delete=models.CASCADE, db_index=True)
    geo_location = models_gis.PointField(
        srid=4326, null=True, blank=True, db_index=True)

    def __str__(self):
        return self.name


############################   AUTH  ############################

class MyUserManager(BaseUserManager):
    def create_user(self, username, email, first_name, last_name, city, password=None):

        if not username:
            raise ValueError('Musisz podać nazwe użytkownika')

        user = self.model(
            username=username,
            email=email,
            first_name=first_name,
            last_name=last_name,
            city=city

        )
        user.set_password(password)
        user.save(using=self._db)
        NotificationsForUser.objects.create(user=user)
        return user

    def create_superuser(self, username, email, password, first_name, last_name, city):

        city_temp = City.objects.get(id="0625444")

        user = self.create_user(
            username,
            email,
            password=password,
            first_name=first_name,
            last_name=last_name,
            city=city_temp
        )
        user.is_admin = True
        user.save(using=self._db)
        return user


class IPAddress(models.Model):
    id = models.AutoField(primary_key=True, db_index=True)
    ip_address = models.CharField(max_length=30, db_index=True)
    is_banned = models.BooleanField(default=False)

    def __str__(self):
        return self.ip_address


class MyUser(AbstractBaseUser):
    id = models.AutoField(primary_key=True, db_index=True)
    username = models.CharField(max_length=200, unique=True, db_index=True)
    email = models.EmailField(
        verbose_name='email address',
        max_length=255,
        unique=True,
        db_index=True
    )
    first_name = models.CharField(max_length=200)
    last_name = models.CharField(max_length=200)
    bank_number = models.CharField(blank=True,max_length=26,validators=[MaxLengthValidator(26), MinLengthValidator(26)])
    city = models.ForeignKey(
        City, on_delete=models.CASCADE, db_index=True)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    is_verificated = models.BooleanField(default=False, db_index=True)
    is_banned = models.BooleanField(default=False, db_index=True)
    ip_validator = models.ManyToManyField(
        IPAddress, through="IPAddressValidator")
    image = models.ImageField(upload_to='user_images',
                              default=settings.DEFAULT_PROFILE_PICTURE)
    image_thumbnail = models.ImageField(
        upload_to='user_thumbnails', blank=True, default=settings.DEFAULT_PROFILE_THUMBNAIL_PICTURE)
    friends = models.ManyToManyField(
        settings.AUTH_USER_MODEL, related_name='friends_list', blank=True)
    blocked_users = models.ManyToManyField(
        settings.AUTH_USER_MODEL, symmetrical=False, related_name='blocked_by', blank=True)
    take_part_events = models.ManyToManyField(
        'Event', related_name='participants_event', blank=True)
    visited_events = models.ManyToManyField(
        'Event', related_name='visitors_event', blank=True)
    activated_badges = models.ManyToManyField(
        'Badge', related_name='badge_owners', blank=True)
    main_badge = models.ForeignKey('Badge', null=True, blank=True,
                                   on_delete=models.SET_NULL, related_name="users_with_main_badge")
    distance = models.IntegerField(default=100)
    count_reported_events = models.IntegerField(default=0)
    count_reported_badges = models.IntegerField(default=0)
    count_reported_comments = models.IntegerField(default=0)
    count_deleted_events = models.IntegerField(default=0)
    count_deleted_badges = models.IntegerField(default=0)
    count_deleted_comments = models.IntegerField(default=0)

    objects = MyUserManager()

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email', 'first_name', 'last_name', 'city']

    def __str__(self):
        return self.username

    def has_perm(self, perm, obj=None):
        return True

    def has_module_perms(self, app_label):
        return True

    @property
    def is_staff(self):
        return self.is_admin

    def generate_thumbnail(request, image, size):
        im = Image.open(image)
        im.thumbnail(size)

        thumb_io = BytesIO()
        im.save(thumb_io, format='JPEG')

        thumb_file = InMemoryUploadedFile(
            thumb_io, None, image.name, 'image/jpeg', thumb_io.tell(), None)

        return thumb_file

    def save(self, generate_thumbnail=True, *args, **kwargs):
        # Sprawdź, czy obiekt Badge istnieje w bazie danych
        try:
            obj = MyUser.objects.get(id=self.id)
        except MyUser.DoesNotExist:
            obj = None

        # Jeśli obiekt istnieje i obrazy są różne, generuj miniaturkę
        if generate_thumbnail and obj is not None and obj.image != self.image:
            thumbnail = self.generate_thumbnail(self.image, (100, 100))
            self.image_thumbnail.save(thumbnail.name, thumbnail, save=False)

        # Jeśli obiekt nie istnieje (czyli jest to nowy obiekt), również generuj miniaturkę
        elif obj is None and generate_thumbnail:
            thumbnail = self.generate_thumbnail(self.image, (100, 100))
            self.image_thumbnail.save(thumbnail.name, thumbnail, save=False)

        super().save(*args, **kwargs)

    @staticmethod
    @database_sync_to_async
    def get_friends(id):

        my_friends = list(MyUser.objects.filter(
            id=id).values_list('friends', flat=True))

        if my_friends[0] == None:
            return None
        else:
            return my_friends

    @staticmethod
    @database_sync_to_async
    def check_blocked_status(self_id, target_id):

        target_user_exists = MyUser.objects.filter(id=target_id).exists()

        blocked_by_target_user = MyUser.objects.filter(
            id=target_id, blocked_users__id=self_id).exists()

        block_target_user = MyUser.objects.filter(
            id=self_id, blocked_users__id=target_id).exists()

        return blocked_by_target_user, block_target_user, target_user_exists


class IPAddressValidator(models.Model):
    id = models.AutoField(primary_key=True, db_index=True)
    user = models.ForeignKey(MyUser, on_delete=models.CASCADE,
                             db_index=True, related_name="validators_of_user")
    ip_address = models.ForeignKey(
        IPAddress, on_delete=models.CASCADE, db_index=True, related_name="users_of_ip")
    is_verificated = models.BooleanField(default=False, db_index=True)
    last_login_time = models.DateTimeField(
        default=timezone.now, editable=False)
    last_login_city = models.ForeignKey(
        City, null=True, blank=True, on_delete=models.SET_NULL, db_index=True)
    name_device = models.CharField(max_length=200, null=True, blank=True)

    class Meta:
        unique_together = [('user', 'ip_address')]

    def __str__(self):
        return self.user.username + " -> " + str(self.ip_address)

    # def save(self, *args, **kwargs):

    #     self.last_login_time = timezone.now()
    #     super(IPAddressValidator, self).save(*args, **kwargs)

    def save(self, update_login_time=False, *args, **kwargs):

        if update_login_time:
            # Aktualizuje pole last_login_time na aktualną datę i czas
            self.last_login_time = timezone.now()
        super(IPAddressValidator, self).save(*args, **kwargs)


class CodeRegistration(models.Model):

    user = models.ForeignKey(MyUser, on_delete=models.CASCADE, db_index=True)
    code_random = models.CharField(blank=True, null=True, max_length=6)

    def save(self, *args, **kwargs):
        code_random = self.code_random
        if not code_random:
            code_random = ''.join(random.choice(string.digits)
                                  for x in range(6))
        while CodeRegistration.objects.filter(code_random=code_random).exists():
            code_random = ''.join(random.choice(string.digits)
                                  for x in range(6))
        self.code_random = code_random
        super(CodeRegistration, self).save(*args, **kwargs)

    def __str__(self):
        return self.user.username + " -> " + str(self.code_random)


class GmailUser(models.Model):
    user = models.OneToOneField(
        MyUser, on_delete=models.CASCADE, primary_key=True, db_index=True)
    social_id = models.CharField(max_length=100, unique=True, db_index=True)
    first_name = models.CharField(max_length=200)
    last_name = models.CharField(max_length=200)
    image = models.ImageField(upload_to='gmail_images')

    def __str__(self):
        return self.user.username + " -> " + self.social_id


class FacebookUser(models.Model):
    user = models.OneToOneField(
        MyUser, on_delete=models.CASCADE, primary_key=True)
    social_id = models.CharField(max_length=100, unique=True, db_index=True)
    first_name = models.CharField(max_length=200)
    last_name = models.CharField(max_length=200)
    image = models.ImageField(upload_to='facebook_images')

    def __str__(self):
        return self.user.username + " -> " + self.social_id


########################### Events #############################


class Category(models.Model):
    id = models.AutoField(primary_key=True, db_index=True)
    type = models.CharField(max_length=50)
    details = models.CharField(max_length=200)
    image = models.ImageField(upload_to='category_img/')

    def __str__(self):
        return self.type


class EventManager(BaseUserManager):
    def random_objects(self, number):

        # ids = random.sample(
        #     list(self.all().values_list('pk', flat=True)), number)

        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT id FROM front_event WHERE verificated='verificated' ORDER BY RANDOM() LIMIT {limit}".format(limit=number))
            ids = [row[0] for row in cursor.fetchall()]

        return ids

    def location_objects(self, request, number):
        

        reach = number * 6
        count = self.filter(verificated="verificated").count()
        if count < number:
            temp = count
        else:
            temp = number

        ids = random.sample(
            list(self.filter(verificated="verificated").annotate(distance=Distance(
                'city__geo_location', City.objects.get(id=request.user.city.id).geo_location)).order_by('distance').values_list('pk', flat=True)[:reach]), temp)

        return ids

    def popular_objects(self, number):
        reach = number * 6
        count = self.filter(verificated="verificated").count()
        if count < number:
            temp = count
        else:
            temp = number

        subquery = self.filter(pk=OuterRef('pk')).values('pk').annotate(
            num_reputation=Count('participants_event')
        ).values('num_reputation')
        ids = random.sample(
            list(self.filter(pk__in=self.random_objects(reach)).annotate(num_reputation=Subquery(subquery))
                 .order_by('-num_reputation', '?').values_list('pk', flat=True)), temp)

        return ids


class Event(models.Model):

    TYPE_CHOICES = (
        ("verificated", "Zweryfikowane"),
        ("awaiting", "Oczekujące na akceptacje"),
        ("need_improvement", "Wymagane poprawy przez organizatora"),
        ("rejected", "Odrzucone"),
    )

    objects = EventManager()
    id = models.AutoField(primary_key=True, db_index=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='created_events', db_index=True)
    category = models.ForeignKey(Category, on_delete=models.CASCADE)

    title = models.CharField(max_length=200)
    text = models.TextField()
    created_time = models.DateTimeField(
        default=timezone.now, editable=False)
    edit_time = models.DateTimeField(default=timezone.now)
    slug = models.SlugField(editable=False)
    event_date = models.DateField(editable=True)
    city = models.ForeignKey(
        City, on_delete=models.CASCADE)
    schedule = models.TextField()
    series = models.ForeignKey(
        'Series', on_delete=models.SET_NULL, null=True, blank=True, related_name='events_for_series')
    verificated = models.CharField(
        max_length=36, choices=TYPE_CHOICES, null=False, default="verificated")
    verificated_details = models.TextField(
        default=None, max_length=150, null=True, blank=True)
    to_remove = models.BooleanField(default=False)
    allow_paycheck = models.BooleanField(default=False)
    to_start_refund = models.BooleanField(default=False)
    rejected_time = models.DateTimeField(null=True, blank=True)

    # def edit_date(self):
    #     self.edit_time = timezone.now()
    #     self.save()

    def save(self, *args, **kwargs):
        try:
            obj = Event.objects.get(id=self.id)
        except Event.DoesNotExist:
            obj = None

        user = self.user

        # GDY OBIEKT ISTNIAL I STAN ZMIENIONY NA REJECTED
        # LUB
        # GDY OBIEKT NIE ISTNIAŁ I JAKO NOWY JEST ODRAZU DO USUNIECIA
        if (obj and obj.verificated != "rejected" and self.verificated == "rejected") or (not obj and self.verificated == "rejected"):
            user.count_deleted_events += 1
            user.save(generate_thumbnail=False)

        # GDY OBIEKT ISTNIAŁ I STAN ZMIENIONY Z REJECTED
        elif obj and obj.verificated == "rejected" and self.verificated != "rejected":
            user.count_deleted_events -= 1
            user.save(generate_thumbnail=False)

        self.slug = slugify(self.title)
        self.edit_time = timezone.now()
        super(Event, self).save(*args, **kwargs)

    def __str__(self):
        return self.title


class Series(models.Model):
    author = models.ForeignKey(
        'MyUser', on_delete=models.CASCADE, db_index=True)
    name = models.CharField(max_length=100)
    description = models.CharField(max_length=200)

    def __str__(self):
        return self.name


class EventImage(models.Model):
    id = models.AutoField(primary_key=True, db_index=True)
    event = models.ForeignKey(
        Event, on_delete=models.CASCADE, related_name='images', db_index=True)
    author = models.ForeignKey('MyUser', on_delete=models.CASCADE)
    image = models.ImageField(upload_to='event_img/')
    image_thumbnail = models.ImageField(
        upload_to='event_thumbnails/', blank=True)
    order = models.IntegerField(default=0)
    main = models.BooleanField(default=False, db_index=True)

    def __str__(self):
        return str(self.event) + " -> " + str(self.image)

    def change_ordering(self, images):
        for i, image in enumerate(images):
            image.order = i
            image.save(generate_thumbnail=False)

    def generate_thumbnail(request, image, size):
        im = Image.open(image)
        rgb_im = im.convert('RGB')
        rgb_im.thumbnail(size)

        thumb_io = BytesIO()
        rgb_im.save(thumb_io, format='JPEG')

        thumb_file = InMemoryUploadedFile(
            thumb_io, None, image.name, 'image/jpeg', thumb_io.tell(), None)

        return thumb_file

    def save(self, generate_thumbnail=True, *args, **kwargs):
        if self.image and generate_thumbnail:
            thumbnail = self.generate_thumbnail(self.image, (225, 225))
            self.image_thumbnail.save(
                thumbnail.name, thumbnail, save=False)
        super().save(*args, **kwargs)


class Friendship_Request(models.Model):
    from_user = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='from_user',
                                  on_delete=models.CASCADE, db_index=True)
    to_user = models.ForeignKey(
        settings.AUTH_USER_MODEL, related_name='to_user', on_delete=models.CASCADE, db_index=True)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        unique_together = [('from_user', 'to_user')]

    def __str__(self):
        return str(self.from_user) + " -> " + str(self.to_user)

    @staticmethod
    @database_sync_to_async
    def user_data(user_id, target_id):

        invitation = Friendship_Request.objects.get(
            from_user__id=user_id, to_user=target_id)

        return invitation.from_user.username, '/media/' + invitation.from_user.image_thumbnail.name, invitation.created_at


class CommentEvent(models.Model):
    id = models.AutoField(primary_key=True, db_index=True)
    event = models.ForeignKey(
        Event, related_name='event', on_delete=models.CASCADE, db_index=True)
    author = models.ForeignKey(settings.AUTH_USER_MODEL,
                               on_delete=models.CASCADE, related_name='created_comments')
    text = models.TextField(max_length=500)
    created_at = models.DateTimeField(default=timezone.now)
    score = models.IntegerField(default=0)
    parent_comment = models.ForeignKey(
        'self', null=True, blank=True, related_name='replies', on_delete=models.CASCADE)
    reported_details = models.TextField(default=None, max_length=150, null=True, blank=True)
    is_blocked = models.BooleanField(default=False)

    def __str__(self):
        return str(self.author) + " -> " + str(self.event)

    def save(self, *args, **kwargs):
        try:
            obj = CommentEvent.objects.get(id=self.id)

        except CommentEvent.DoesNotExist:
            obj = None

        user = self.author

        # GDY OBIEKT ISTNIAL I STAN ZMIENIONY NA REJECTED
        # LUB
        # GDY OBIEKT NIE ISTNIAŁ I JAKO NOWY JEST ODRAZU DO USUNIECIA
        if (obj and obj.is_blocked == False and self.is_blocked == True) or (not obj and self.is_blocked == True):
            user.count_deleted_comments += 1
            user.save(generate_thumbnail=False)

        # GDY OBIEKT ISTNIAŁ I STAN ZMIENIONY Z REJECTED
        elif obj and obj.is_blocked == True and self.is_blocked == False:
            user.count_deleted_comments -= 1
            user.save(generate_thumbnail=False)

        super(CommentEvent, self).save(*args, **kwargs)


class CommentEventReaction(models.Model):
    TYPE_CHOICES = (
        ('Like', 'Like'),
        ('Dislike', 'Dislike'),
        ('Delete', 'Delete'),
    )
    comment = models.ForeignKey(CommentEvent,
                                on_delete=models.CASCADE, db_index=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, db_index=True)
    type = models.CharField(max_length=8, choices=TYPE_CHOICES, null=False)

    class Meta:
        unique_together = [('comment', 'user')]

    def __str__(self):
        return str(self.user) + " -> ( " + str(self.comment) + " ) "

    def edit_reaction(comment, type, comment_reaction):

        if type == "Like":
            comment_reaction.type = "Like"
            comment.score += 2
        else:
            comment_reaction.type = "Dislike"
            comment.score -= 2

        comment_reaction.save()
        comment.save()

    def create_reaction(comment, user, type):
        reaction = CommentEventReaction(comment=comment, user=user, type=type)
        reaction.save()

        if type == "Like":
            comment.score += 1
        else:
            comment.score -= 1

        comment.save()

    def delete_reaction(comment, comment_reaction):

        if comment_reaction.type == "Like":
            comment.score -= 1
        else:
            comment.score += 1
        comment.save()

        comment_reaction.delete()


class Report(models.Model):

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, db_index=True)

    created_time = models.DateTimeField(
        default=timezone.now
    )

    details = models.TextField(
        default=None, max_length=150, null=True, blank=True)

    class Meta:
        abstract = True


class CustomDeleteCommentEventReport(models.QuerySet):
    def delete(self, minus_count=False, *args, **kwargs):
        if minus_count:
            report_count = self.count()
            user = self.first().comment.author
            user.count_reported_comments -= report_count
            user.save(generate_thumbnail=False)
        super().delete(*args, **kwargs)


class CommentEventReport(Report):
    TYPE_CHOICES = (
        ("Treści reklamowe lub spam", "Treści reklamowe lub spam"),
        ("Materiały erotyczne i pornograficzne",
         "Materiały erotyczne i pornograficzne"),
        ("Wykorzystywanie dzieci", "Wykorzystywanie dzieci"),
        ("Propagowanie terroryzmu", "Propagowanie terroryzmu"),
        ("Nękanie lub dokuczanie", "Nękanie lub dokuczanie"),
        ("Nieprawdziwe informacje", "Nieprawdziwe informacje"),
    )

    comment = models.ForeignKey(CommentEvent,
                                on_delete=models.CASCADE)
    type = models.CharField(max_length=47, choices=TYPE_CHOICES, null=False)

    objects = CustomDeleteCommentEventReport.as_manager()

    class Meta:
        unique_together = [('comment', 'user')]

    def __str__(self):
        return str(self.user) + " -> ( " + str(self.comment) + " ) "


class CustomDeleteEventReport(models.QuerySet):
    def delete(self, minus_count=False, *args, **kwargs):
        if minus_count and self.count() > 0:
            report_count = self.count()
            user = self.first().event.user
            user.count_reported_events -= report_count
            user.save(generate_thumbnail=False)
        super().delete(*args, **kwargs)


class EventReport(Report):
    TYPE_CHOICES = (
        ("Naruszenie regulaminu", "Naruszenie regulaminu"),
        ("Dyskryminacja", "Dyskryminacja"),
        ("Fałszywe informacje",
         "Fałszywe informacje"),
        ("Niezgodność z zasadami społeczności",
         "Niezgodność z zasadami społeczności"),
        ("Niewłaściwe zachowanie organizatora",
         "Niewłaściwe zachowanie organizatora"),
        ("Propagowanie nielegalnych działań", "Propagowanie nielegalnych działań"),
    )

    event = models.ForeignKey(Event,
                              on_delete=models.CASCADE)
    type = models.CharField(max_length=47, choices=TYPE_CHOICES, null=False)

    objects = CustomDeleteEventReport.as_manager()

    class Meta:
        unique_together = [('event', 'user')]

    def __str__(self):
        return str(self.user) + " -> ( " + str(self.event) + " ) "


def change_main_badge(badge):

    badge_owners = badge.badge_owners.all()

    owners_to_update = []

    for owner in badge_owners:
        main_change = owner.activated_badges.filter(
            verificated="verificated").exclude(
            id=badge.id).order_by('id').first()
        owner.main_badge = main_change
        owners_to_update.append(owner)
    if owners_to_update:
        MyUser.objects.bulk_update(
            owners_to_update, ['main_badge'], batch_size=500)


class Badge(models.Model):

    TYPE_CHOICES = (
        ("verificated", "Zweryfikowane"),
        ("awaiting", "Oczekujące na akceptacje"),
        ("need_improvement", "Wymagane poprawy przez organizatora"),
        ("rejected", "Odrzucone"),
    )

    id = models.AutoField(primary_key=True, db_index=True)
    creator = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='created_badges', db_index=True)
    name = models.CharField(max_length=50)
    event = models.ForeignKey(Event, on_delete=models.CASCADE)
    image = models.ImageField(upload_to='badge_image')
    verificated = models.CharField(
        max_length=36, choices=TYPE_CHOICES, null=False, default="verificated")
    verificated_details = models.TextField(default=None, null=True, blank=True)
    created_time = models.DateField(
        default=timezone.now, editable=False)
    edit_time = models.DateTimeField(default=timezone.now)
    to_remove = models.BooleanField(default=False)

    def __str__(self):
        return str(self.name) + " -> ( " + str(self.event) + " ) "

    def generate_thumbnail(request, image, size):
        im = Image.open(image)
        rgb_im = im.convert('RGB')
        rgb_im.thumbnail(size)

        thumb_io = BytesIO()
        rgb_im.save(thumb_io, format='JPEG')

        thumb_file = InMemoryUploadedFile(
            thumb_io, None, image.name, 'image/jpeg', thumb_io.tell(), None)

        return thumb_file

    def save(self, generate_thumbnail=True, *args, **kwargs):
        # Sprawdź, czy obiekt Badge istnieje w bazie danych
        try:
            obj = Badge.objects.get(id=self.id)
            if self.verificated != "verificated":
                change_main_badge(obj)

        except Badge.DoesNotExist:
            obj = None

        user = self.creator

        # GDY OBIEKT ISTNIAL I STAN ZMIENIONY NA REJECTED
        # LUB
        # GDY OBIEKT NIE ISTNIAŁ I JAKO NOWY JEST ODRAZU DO USUNIECIA
        if (obj and obj.verificated != "rejected" and self.verificated == "rejected") or (not obj and self.verificated == "rejected"):
            user.count_deleted_badges += 1
            user.save(generate_thumbnail=False)

        # GDY OBIEKT ISTNIAŁ I STAN ZMIENIONY Z REJECTED
        elif obj and obj.verificated == "rejected" and self.verificated != "rejected":
            user.count_deleted_badges -= 1
            user.save(generate_thumbnail=False)

        # Jeśli obiekt istnieje i obrazy są różne, generuj miniaturkę
        if generate_thumbnail and obj is not None and obj.image != self.image:
            thumbnail = self.generate_thumbnail(self.image, (225, 225))
            self.image.save(thumbnail.name, thumbnail, save=False)

        # Jeśli obiekt nie istnieje (czyli jest to nowy obiekt), również generuj miniaturkę
        elif obj is None and generate_thumbnail:
            thumbnail = self.generate_thumbnail(self.image, (225, 225))
            self.image.save(thumbnail.name, thumbnail, save=False)

        self.edit_time = timezone.now()
        super().save(*args, **kwargs)


def generate_unique_code():
    """Generuje unikalny kod."""
    return '-'.join(secrets.token_hex(2).upper() for _ in range(5))


class BadgeCode(models.Model):
    TYPE_CHOICES = (
        ("c) used", "Użyto"),
        ("b) locked", "Zarezerwowano"),
        ("a) to_use", "Do użycia"),
    )
    id = models.AutoField(primary_key=True, db_index=True)
    code = models.CharField(max_length=24, unique=True,
                            default=generate_unique_code, db_index=True)
    badge = models.ForeignKey(Badge, on_delete=models.CASCADE)
    status = models.CharField(
        max_length=20, choices=TYPE_CHOICES, null=False, default="a) to_use")
    activated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True, blank=True)
    created_time = models.DateTimeField(
        default=timezone.now, editable=False)
    activated_time = models.DateTimeField(null=True, blank=True)
    

    def save(self, *args, **kwargs):
        if not self.code:
            self.code = self.generate_unique_code()
        if self.status == "c) used" and not self.activated_time:
            self.activated_time = timezone.now()
        super().save(*args, **kwargs)

    def __str__(self):
        return str(self.badge.name) + " (" + str(self.code) + ")"


class CustomDeleteBadgeReport(models.QuerySet):
    def delete(self, minus_count=False, *args, **kwargs):
        if minus_count:
            report_count = self.count()
            user = self.first().badge.creator
            user.count_reported_badges -= report_count
            user.save(generate_thumbnail=False)
        super().delete(*args, **kwargs)


class BadgeReport(Report):
    TYPE_CHOICES = (
        ("Naruszenie regulaminu", "Naruszenie regulaminu"),
        ("Dyskryminacja", "Dyskryminacja"),
        ("Fałszywe informacje",
         "Fałszywe informacje"),
        ("Niezgodność z zasadami społeczności",
         "Niezgodność z zasadami społeczności"),
        ("Obraźliwa miniaturka",
         "Obraźliwa miniaturka"),
        ("Propagowanie nielegalnych działań", "Propagowanie nielegalnych działań"),
    )

    badge = models.ForeignKey(Badge,
                              on_delete=models.CASCADE)

    type = models.CharField(max_length=47, choices=TYPE_CHOICES, null=False)

    objects = CustomDeleteBadgeReport.as_manager()

    class Meta:
        unique_together = [('badge', 'user')]

    def __str__(self):
        return str(self.user) + " -> ( " + str(self.badge) + " ) "


# class CustomOutstandingToken(OutstandingToken):
#     ip_validator = models.OneToOneField(
#         IPAddressValidator, on_delete=models.CASCADE, db_index=True)


class CustomOutstandingToken(models.Model):
    id = models.BigAutoField(primary_key=True, serialize=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True
    )

    jti = models.CharField(unique=True, max_length=255)
    token = models.TextField()

    created_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField()
    ip_validator = models.ForeignKey(
        IPAddressValidator, on_delete=models.CASCADE)

    class Meta:

        abstract = (
            "rest_framework_simplejwt.token_blacklist" not in settings.INSTALLED_APPS
        )
        ordering = ("user",)

    def __str__(self):
        return "Token for {} ({})".format(
            self.user,
            self.jti,
        )


class CustomBlacklistedToken(models.Model):
    id = models.BigAutoField(primary_key=True, serialize=False)
    token = models.OneToOneField(
        CustomOutstandingToken, on_delete=models.CASCADE)

    blacklisted_at = models.DateTimeField(auto_now_add=True)

    class Meta:

        abstract = (
            "rest_framework_simplejwt.token_blacklist" not in settings.INSTALLED_APPS
        )

    def __str__(self):
        return f"Blacklisted token for {self.token.user}"


class ChangeEmailWaiting(models.Model):
    id = models.BigAutoField(primary_key=True, serialize=False, db_index=True)
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    code_random = models.CharField(blank=True, null=True, max_length=6)
    email = models.EmailField(
        verbose_name='email address',
        max_length=255,
        db_index=True
    )

    def save(self, *args, **kwargs):
        code_random = self.code_random
        if not code_random:
            code_random = ''.join(random.choice(string.digits)
                                  for x in range(6))
        while ChangeEmailWaiting.objects.filter(code_random=code_random).exists():
            code_random = ''.join(random.choice(string.digits)
                                  for x in range(6))
        self.code_random = code_random
        super(ChangeEmailWaiting, self).save(*args, **kwargs)

    def __str__(self):
        return self.user.username + " -> " + self.email


class AdminLog(models.Model):

    ACTION_TYPE_CHOICES = (
        ("confirmation", "Zatwierdzenie"),
        ("deletion", "Usuwanie"),
        ("to_improvement", "Przekazanie do poprawy"),
        ("clear", "Oczyszczone ze zgłoszeń"),
        ("ban_user", "Banowanie użytkownika"),
        ("ban_ip", "Banowanie adresu IP"),
        ("logout", "Wylogowywanie"),
        ("paycheck", "Wypłata środków")
    )

    CONTENT_TYPE_CHOICES = (
        ("MyUser", "Użytkownik"),
        ("IPAddress", "Adres IP"),
        ("IPAddressValidator", "Uwierzytelniacz"),
        ("Event", "Wydarzenie"),
        ("CommentEvent", "Komentarz"),
        ("Badge", "Odznaka"),
        ("Ticket", "Bilet"),
        ("GatewayPaycheck", "Bramka płatności")
    )

    id = models.BigAutoField(primary_key=True, serialize=False, db_index=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    action_time = models.DateTimeField(
        default=timezone.now
    )
    action_flag = models.CharField(
        max_length=36, choices=ACTION_TYPE_CHOICES, null=False)
    content_type = models.CharField(
        max_length=100, choices=CONTENT_TYPE_CHOICES)
    id_content_type = models.IntegerField(default=None, blank=True)

    def model_class(self):
        try:
            return apps.get_model("front", self.content_type)
        except LookupError:
            raise ValidationError(
                "You are trying to save an admin action on a content_type model that does not exist")

    def get_object(self):
        """
        Return an object of this type for the keyword arguments given.
        Basically, this is a proxy around this object_type's get_object() model
        method. The ObjectNotExist exception, if thrown, will not be caught,
        so code that calls this method should catch it.
        """
        try:
            return self.model_class()._base_manager.using(self._state.db).get(id=self.id_content_type)
        except ObjectDoesNotExist:
            raise ValidationError(
                "You are trying to save an admin action on a id_content_type model that does not exist")

    def save(self, *args, **kwargs):
        self.get_object()

        super(AdminLog, self).save(*args, **kwargs)

    def __str__(self):
        return self.user.username + " -> " + self.action_flag + " -> " + self.content_type


class ActiveMessage(models.Model):
    message_id = models.AutoField(primary_key=True, db_index=True)
    sender = models.ForeignKey(
        settings.AUTH_USER_MODEL, related_name="sent_messages", on_delete=models.CASCADE, db_index=True)
    recipient = models.ForeignKey(
        settings.AUTH_USER_MODEL, related_name="received_messages", on_delete=models.CASCADE, db_index=True)
    content = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    is_delivered = models.BooleanField(default=False)
    is_seen = models.BooleanField(default=False)

    @classmethod
    @database_sync_to_async
    def save_message(cls, content, sender_id, recipient_id, status):

        message = cls(content=content, sender_id=sender_id,
                      recipient_id=recipient_id, is_delivered=status, is_seen=status)
        message.save()

        is_friend = message.sender.friends.filter(id=recipient_id).exists()

        if status == True:
            return message.message_id, message.timestamp, is_friend, message.recipient.username, message.recipient.image_thumbnail.name, message.sender.username, message.sender.image_thumbnail.name
        else:
            return message.message_id, message.timestamp, is_friend, message.recipient.username, message.recipient.image_thumbnail.name

    @staticmethod
    @database_sync_to_async
    def async_get_by_id(message_id):
        return ActiveMessage.objects.get(message_id=message_id)

    @staticmethod
    @database_sync_to_async
    def login_set_delivered(user_id):

        undelivered_messages = list(ActiveMessage.objects.filter(
            recipient__id=user_id, is_delivered=False))
        senders_ids = set(
            message.sender_id for message in undelivered_messages)
        ActiveMessage.objects.filter(
            recipient__id=user_id, is_delivered=False).update(is_delivered=True)
        return senders_ids

    @staticmethod
    def delivered(message):
        message.is_delivered = True
        message.save()

    @staticmethod
    def seen(message):
        message.is_seen = True
        message.save()

    def __str__(self):
        return self.sender.username + " -> " + self.recipient.username + " - " + self.content
    


class DeleteModel(models.Model):

    TYPE_CHOICES = (
        ("MyUser", "Użytkownik"),
        ("IPAddress", "Adres IP"),
        ("Event", "Wydarzenie"),
        ("CommentEvent", "Komentarz"),
        ("Badge", "Odznaka"),
        ("Ticket", "Bilet"),
        ("Order", "Zamówienie"),
        ("AwaitingsTicketsRefund", "Zwrot pieniędzy"),
        {"GatewayPaycheck", "Przyznany przelew"}
       
    )


    # ID RODZAJU POWIADOMIENIA
    id = models.IntegerField(primary_key=True, db_index=True)

    # NAZWA USUWANEGO MODELU
    content_type = models.CharField(
        max_length=100, choices=TYPE_CHOICES)
    
    # NUMERY ID USUWANYCH MODELI
    ids_array = models.TextField(default='[]')


    def __str__(self):
        return self.content_type


class Notification(models.Model):

    TYPE_CHOICES = (
        ("MyUser", "Użytkownik"),
        ("IPAddress", "Adres IP"),
        ("Event", "Wydarzenie"),
        ("CommentEvent", "Komentarz"),
        ("Badge", "Odznaka"),
        ("Ticket", "Bilet"),
        ("Order", "Zamówienie"),
        ("AwaitingsTicketsRefund", "Zwrot pieniędzy"),
        {"GatewayPaycheck", "Przyznany przelew"}
    )


    # ID RODZAJU POWIADOMIENIA
    id = models.IntegerField(primary_key=True, db_index=True)


    # NAZWA USUWANEGO MODELU
    content_type = models.CharField(
        max_length=100, choices=TYPE_CHOICES)

    # TEKST POWIADOMIENIA
    text = models.TextField()







    def model_class(self):
        try:
            return apps.get_model("front", self.content_type.type)
        except LookupError:
            raise ValidationError(
                "You are trying to save an admin action on a content_type model that does not exist")

    def get_object_data(self, object):
        """
        Return an object of this type for the keyword arguments given.
        Basically, this is a proxy around this object_type's get_object() model
        method. The ObjectNotExist exception, if thrown, will not be caught,
        so code that calls this method should catch it.
        """
        try:
            if self.content_type == 'MyUser':
                return {
                    'id': object.id,
                    'username': object.username,
                    'image_thumbnail': '/media/' + object.image_thumbnail.name,
                }
            elif self.content_type == 'IPAddress':
                return {
                    'ip_address': object.ip_address,
                    'image_thumbnail': '/media/' + object.image_thumbnail,
                }
            elif self.content_type == 'Event':
                return {
                    'title': object.title,
                    'slug': object.slug,
                    'uuid': str(object.uuid),
                    'image_thumbnail': '/media/' + object.image_thumbnail,

                }
            elif self.content_type == 'CommentEvent':
                return {
                    'id': object.id,
                    'text': object.text,
                    'title': object.title,
                    'slug': object.slug,
                    'uuid': str(object.uuid),
                    'image_thumbnail': '/media/' + object.image_thumbnail,
                }
            elif self.content_type == 'Badge':
                return {
                    'id': object.id,
                    'name': object.name,
                    'image_thumbnail': '/media/' + object.image.name,
                }
            elif self.content_type == 'Ticket':
                
                return {
                    'id': object.id,
                    'ticket_type': object.ticket_type,
                    'image_thumbnail': '/media/' + object.image_thumbnail,
                    'event_id': object.event_id,
                    'verificated': object.verificated,
                    'verificated_details': object.verificated_details,
                    'was_allowed': object.was_allowed,
                    'default_price': str(object.default_price),
                    'price': str(object.price),
                    'new_price': str(object.new_price), 
                }
            elif self.content_type == 'Order':

                return {
                    'image_thumbnail': '/media/' + object.image_thumbnail,
                    'event_id': object.event_id,
                    'ids': {
                        'used': object.used_ids,
                        'refunded_paid': object.refunded_paid_ids,
                        'refunded_not_paid': object.refunded_not_paid_ids,
                    },
                    'order_refund_information': object.order_refund_information, 

                }
            elif self.content_type == 'AwaitingsTicketsRefund':

                return {
                    'id': object.id,
                    'image_thumbnail': '/media/' + object.image_thumbnail,
                    'amount': str(object.amount),
                    'orders_refund_amount': object.orders_refund_amount
                }
            
            elif self.content_type == "GatewayPaycheck":

                if object.event == None:
                    event_id = None
                else:
                    event_id = object.event.id

                return {
                    'id': object.id,
                    'event_id': event_id,
                    'tickets_ids': list(object.tickets.all().values_list('id', flat=True)),
                    'image_thumbnail': '/media/' + object.image_thumbnail,
                    'amount': str(object.paycheck.amount),
                    'paycheck_attachments': object.paycheck_attachments,
                }

            



        except ObjectDoesNotExist:
            print("CATCH ERROR")
            raise ValidationError(
                "You are trying to save an admin action on a id_content_type model that does not exist")

    def __str__(self):
        return str(self.id) + " -> " + self.text


class NotificationsForUser(models.Model):

    id = models.BigAutoField(primary_key=True, serialize=False, db_index=True)
    user = models.OneToOneField(
        MyUser, on_delete=models.CASCADE, related_name='user_notifications')
    notifications_array = models.TextField(default='[]')


    def new_notification(self, id_notification, object, datetime):
        from .views import append_extra_data_notification

        list_of_arrays = eval(self.notifications_array)
        formatted_datetime = datetime.isoformat()
        list_of_arrays.insert(0, [id_notification, object.id, formatted_datetime, 0])
        self.notifications_array = list_of_arrays
        self.save()

        notification_schema = Notification.objects.get(id=id_notification)

        output = append_extra_data_notification(object, notification_schema.content_type, [object.id], self.user.id, False)




        template = {
                'created_at': formatted_datetime,
                'text': notification_schema.text,
                'object_type': notification_schema.content_type,
                'object': notification_schema.get_object_data(output),
            }
        
        
        
        return template
    

    @staticmethod
    @database_sync_to_async
    def set_notifications_seen(user_id):

        notifications = NotificationsForUser.objects.get(user__id=user_id)
        notifications_array = eval(notifications.notifications_array)


        for notification in notifications_array:
            if notification[3] == 0:
                notification[3] = 1

        notifications.notifications_array = notifications_array
        notifications.save()



    def __str__(self):
        return self.user.username + " -> " + self.notifications_array
    


# RODZAJ BILETU DOPISANY DO WYDARZENIA
class Ticket(models.Model):

    TYPE_CHOICES = (
        ("verificated", "Zweryfikowane"), #EDIT TYLKO CENA ORAZ ILOSC OGRANICZONA DO KUPIONYCH
        ("awaiting", "Oczekujące na akceptacje"), #EDIT I DELETE
        ("need_improvement", "Wymagane poprawy przez organizatora"), #EDIT I DELETE + POWOD_DETAILS
        ("rejected", "Odrzucone"), # DELETE + POWOD_DETAILS
    )



    id = models.BigAutoField(primary_key=True, serialize=False, db_index=True)
    stripe_id = models.CharField(max_length=255, blank=True)
    stripe_name_product = models.CharField(max_length=255, blank=True)
    event = models.ForeignKey(Event, on_delete=models.SET_NULL, null=True, related_name="tickets_of_event")
    ticket_type = models.CharField(max_length=255)
    ticket_details = models.TextField()
    default_price = models.DecimalField(max_digits=10, decimal_places=2)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    new_price = models.DecimalField(max_digits=10, decimal_places=2)
    quantity = models.PositiveIntegerField()
    verificated = models.CharField(
        max_length=36, choices=TYPE_CHOICES, null=False, default="awaiting")
    verificated_details = models.TextField(
        default=None, max_length=150, null=True, blank=True)
    was_allowed = models.BooleanField(default=False)
    to_remove = models.BooleanField(default=False)
    edit_time = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return self.event.title + " -> " + self.ticket_type
    

    def save(self, *args, **kwargs):
        self.edit_time = timezone.now()
        super().save(*args, **kwargs)
    


    


class Order(models.Model):
    id = models.BigAutoField(primary_key=True, serialize=False, db_index=True)
    user = models.ForeignKey(MyUser, on_delete=models.CASCADE, editable=False)
    stripe_payment_intent_id = models.CharField(max_length=255) #, unique=True
    checkout_payment_intent_id = models.CharField(blank=True,max_length=100)
    orderedtickets_ids_array = models.TextField(default='[]')
    created_at = models.DateTimeField(default=timezone.now)
    stripe_created_at = models.DateTimeField(blank=True, null=True)
    order_expires_at = models.DateTimeField(blank=True, null=True)
    next_try_at = models.DateTimeField(blank=True, null=True)
    paid_time = models.DateTimeField(blank=True, null=True)
    is_paid = models.BooleanField(default=False)
    to_remove = models.BooleanField(default=False)



    def set_paid(self, checkout_id):
        if self.is_paid == False:
            qrcodes_directory = 'qrcodes'
            if not os.path.exists(f'media//{qrcodes_directory}'):
                os.makedirs(f'media//{qrcodes_directory}')

            if not os.path.exists(f'media//{qrcodes_directory}//{self.user.id}'):
                os.makedirs(f'media//{qrcodes_directory}//{self.user.id}')

            tickets = self.ordered_tickets.all()
            for ticket in tickets:
                ticket.generate_qr_code(qrcodes_directory)
            self.is_paid = True
            self.paid_time = timezone.now()
            self.checkout_payment_intent_id = checkout_id
            self.save()

    def __str__(self):
        return self.user.username + " -> " + self.stripe_payment_intent_id


    

class OrderedTicket(models.Model):
    id = models.BigAutoField(primary_key=True, serialize=False, db_index=True)
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name="ordered_tickets", editable=False)
    ticket = models.ForeignKey(Ticket, on_delete=models.CASCADE, related_name="orders_of_tickets", editable=False)
    purchase_price = models.DecimalField(max_digits=10, decimal_places=2)

    first_name = models.CharField(max_length=200)
    last_name = models.CharField(max_length=200) 
    date_of_birth = models.DateField(editable=True)

    code = models.UUIDField(editable=True, null=True)
    qr_code = models.ImageField(upload_to='qrcodes/')

    used = models.BooleanField(default=False) 
    used_time = models.DateTimeField(null=True, blank=True)

    refunded = models.BooleanField(default=False)



    def generate_qr_code(self, qrcodes_directory):
        if not os.path.exists(f'media//{qrcodes_directory}//{self.order.user.id}//{self.ticket.event.id}'):
            os.makedirs(f'media//{qrcodes_directory}//{self.order.user.id}//{self.ticket.event.id}')
        
        code_value = str(uuid.uuid4())

        path = f'{qrcodes_directory}//{self.order.user.id}//{self.ticket.event.id}//{code_value}.png'
        file_path = f"media//{path}"

        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )


        qr.add_data(f"{self.id}***{self.order.id}***{self.ticket.event.id}***{self.ticket.event.user.id}***{self.first_name}***{self.last_name}***{self.date_of_birth}***{code_value}***{self.ticket.ticket_type}")
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")
        img.save(file_path)

        self.code = code_value
        self.qr_code = path
        self.save()

    def set_used(self):
        if self.used == False:
            self.used = True
            self.used_time = timezone.now()
            self.save()
          

    def __str__(self):
        return self.first_name + " " + self.last_name + " (" + str(self.date_of_birth) + ") => " + self.ticket.event.title + " => " + str(self.code)
    




class Paycheck(models.Model):

    id = models.BigAutoField(primary_key=True, serialize=False, db_index=True)
    user = models.ForeignKey(MyUser, on_delete=models.SET_NULL, null=True, related_name="user_paychecks", db_index=True) 
    created_at = models.DateTimeField(default=timezone.now) 
    amount = models.DecimalField(max_digits=10, decimal_places=2)  

    event = models.OneToOneField(Event, on_delete=models.SET_NULL, null=True, blank=True, db_index=True) 
    tickets = models.ManyToManyField(OrderedTicket, blank=True, db_index=True)  

    stripe_refund_checkout_mode = models.BooleanField(default=False)
    refund_confirmation = models.FileField(upload_to='payment_confirmation/', blank=True, null=True)
    
    bank_number = models.CharField(blank=True,max_length=26,validators=[MaxLengthValidator(26), MinLengthValidator(26)])

    def __str__(self):
        return self.user.username + " -> " + str(self.amount) + " zł"
    
    def save_pdf(self, pdf_file, obj, mode):
       
        folder_name = f"{obj.user.id}/{mode}/{obj.id}/"

        folder_path = os.path.join(settings.MEDIA_ROOT, "payment_confirmation", folder_name)
        if not os.path.exists(folder_path):
            os.makedirs(folder_path)

        file_path = os.path.join(folder_path, pdf_file.name)

        with open(file_path, "wb") as file:
            for chunk in pdf_file.chunks():
                file.write(chunk)

        self.refund_confirmation = os.path.join("payment_confirmation", folder_name, pdf_file.name)
        self.save()
    
    
    

class GatewayPaycheck(models.Model): 

    id = models.BigAutoField(primary_key=True, serialize=False, db_index=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False)
    
    created_by = models.ForeignKey(MyUser, on_delete=models.SET_NULL, null=True, related_name="user_gateways", db_index=True) 

    created_at = models.DateTimeField(default=timezone.now)

    event = models.ForeignKey(Event, on_delete=models.CASCADE, null=True, blank=True, db_index=True)
    tickets = models.ManyToManyField(OrderedTicket, blank=True, db_index=True)

    paycheck = models.OneToOneField(Paycheck, on_delete=models.CASCADE, null=True, blank=True, db_index=True) 

    stage_to_remove = models.BooleanField(default=False)
    remove_time = models.DateTimeField(null=True, blank=True)


    def __str__(self):

        amount_str = "BRAK" if self.paycheck is None else f"{self.paycheck.amount} zł ({self.paycheck.user.username})"

        return self.created_by.username + " -> " + amount_str
    

    def set_paid(self, pdf_file, mode):

        if mode == "tickets":

            obj = self.tickets.first().order

            refund_tickets_ids = self.tickets.all().values_list('id', flat=True)

            amount = self.tickets.all().aggregate(total=Sum('purchase_price'))['total']

            new_paycheck = Paycheck.objects.create(user=obj.user, amount=amount, bank_number=obj.user.bank_number)
            new_paycheck.tickets.set(refund_tickets_ids)
        elif mode == "events":

            obj = self.event

            amount_before_service = OrderedTicket.objects.filter(ticket__event__id=obj.id, order__is_paid=True, refunded=False).aggregate(total=Sum('purchase_price'))['total']

            amount = float(amount_before_service) * 0.95

            new_paycheck = Paycheck.objects.create(user=obj.user, event=obj, amount=amount, bank_number=obj.user.bank_number)

        new_paycheck.save_pdf(pdf_file, obj, mode)

        self.paycheck = new_paycheck
        self.save()

    
class AwaitingsTicketsRefund(models.Model):

    id = models.BigAutoField(primary_key=True, serialize=False, db_index=True)
    user = models.OneToOneField(MyUser, on_delete=models.CASCADE, db_index=True)
    amount = models.DecimalField(max_digits=10, null=True, decimal_places=2)
    tickets = models.ManyToManyField(OrderedTicket, blank=True, db_index=True) 


    def __str__(self):
        return self.user.username + " -> " + str(self.amount) + " zł"
    
    def set_total_amount(self):
        
        self.amount = self.tickets.aggregate(total=Sum('purchase_price'))['total']
        self.save()
          

