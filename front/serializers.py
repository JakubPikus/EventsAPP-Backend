from rest_framework import serializers
from front.models import MyUser, IPAddressValidator, CodeRegistration, Event, Category, Province, City, CommentEvent, CommentEventReaction, CommentEventReport, Friendship_Request, EventImage, Series, EventReport, County, BadgeCode, Badge, BadgeReport, AdminLog, IPAddress, ActiveMessage, NotificationsForUser, Ticket, Order, OrderedTicket
from django.conf import settings
from rest_framework import permissions, status, serializers, pagination
from django.utils import timezone
import datetime
from django.db.models import Count, Value, CharField, F, Case, When, BooleanField, Q, OuterRef, Subquery, Exists, ExpressionWrapper, CharField, Func
from rest_framework.fields import CurrentUserDefault


class LogoutSerializer(serializers.Serializer):
    logout = serializers.CharField(label="Logout", write_only=True)

    class Meta:
        fields = ('logout',)


class LoginSerializer(serializers.ModelSerializer):
    gmail = serializers.JSONField(read_only=True)
    facebook = serializers.JSONField(read_only=True)
    pinned_bank = serializers.BooleanField(read_only=True)

    class Meta:
        model = MyUser
        fields = ('id', 'username', 'password', 'email',
                  'first_name', 'last_name', 'is_verificated', 'city', 'image', 'image_thumbnail', 'distance', 'is_admin', 'gmail', 'facebook', 'pinned_bank')
        read_only_fields = ('id', 'email', 'first_name',
                            'last_name', 'is_verificated', 'city', 'image', 'image_thumbnail', 'distance', 'is_admin', 'gmail', 'facebook', 'pinned_bank')
        extra_kwargs = {'password': {'write_only': True}}
        depth = 3


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        label="Hasło", write_only=True, help_text="Hasło musi się składac z conajmniej 8 znaków.", style={'input_type': 'password'})
    re_password = serializers.CharField(
        label="Powtórz hasło", write_only=True, style={'input_type': 'password'})

    class Meta:
        model = MyUser
        fields = ('username', 'password', 're_password',
                  'email', 'first_name', 'last_name', 'city', )


class UserSerializer(serializers.ModelSerializer):

    gmail = serializers.JSONField(read_only=True)
    facebook = serializers.JSONField(read_only=True)
    pinned_bank = serializers.BooleanField(read_only=True)

    class Meta:
        model = MyUser
        fields = ('id', 'username', 'email', 'first_name',
                  'last_name', 'city', 'is_verificated', 'image', 'image_thumbnail', 'distance', 'is_admin', 'gmail', 'facebook', 'pinned_bank')
        # fields = '__all__'
        depth = 3


class UserFriendsSerializer(serializers.ModelSerializer):
    friends_count = serializers.IntegerField(required=False)
    friends_together_count = serializers.SerializerMethodField()
    friendslist_together = serializers.ListField()
    friendslist_strange = serializers.ListField()
    city = serializers.StringRelatedField()
    is_friend = serializers.CharField()
    badges = serializers.ListField()
    main_badge_data = serializers.JSONField()

    class Meta:
        model = MyUser
        fields = ('id', 'username', 'email', 'first_name', 'city',
                  'image', 'image_thumbnail', 'is_friend', 'friends_count', 'friends_together_count', 'friendslist_together', 'friendslist_strange', 'badges', 'main_badge_data')

    def get_friends_together_count(self, obj):
        if obj.friends_together_count == None:
            return 0
        else:
            return obj.friends_together_count


class AccountConfirmSerializer(serializers.ModelSerializer):
    username = serializers.CharField(label="Username", write_only=True)
    email = serializers.CharField(label="Email", write_only=True)

    class Meta:
        model = CodeRegistration
        fields = ('username', 'email', 'code_random',)


class PasswordResetSerializer(serializers.ModelSerializer):
    class Meta:
        model = MyUser
        fields = ('email',)


class PasswordResetConfirmSerializer(serializers.ModelSerializer):
    code = serializers.CharField(label="Kod", write_only=True)
    password = serializers.CharField(
        label="Hasło", write_only=True, help_text="Hasło musi się składac z conajmniej 8 znaków.", style={'input_type': 'password'})
    re_password = serializers.CharField(
        label="Powtórz hasło", write_only=True, style={'input_type': 'password'})

    class Meta:
        model = MyUser
        fields = ('email', 'code', 'password', 're_password',)


class LoginGoogleSerializer(serializers.ModelSerializer):
    code = serializers.CharField(required=False)


class LoginFacebookSerializer(serializers.ModelSerializer):
    code = serializers.CharField(required=False)
    error = serializers.CharField(required=False)


class CategorySerializer(serializers.ModelSerializer):

    class Meta:
        model = Category
        fields = ('type', 'details',)


class HomeScreenSerializer(serializers.ModelSerializer):

    user = serializers.StringRelatedField()
    category = serializers.StringRelatedField()

    class Meta:
        model = Event
        fields = ('id', 'user', 'category', 'title',
                  'text', 'created_time', 'edit_time', 'image', 'event_date',)


class CategorySerializer(serializers.ModelSerializer):

    class Meta:
        model = Category
        fields = ('type', 'details', 'image',)


class ProvinceSerializer(serializers.ModelSerializer):

    class Meta:
        model = Province
        fields = ('id', 'name',)


class CitySerializer(serializers.ModelSerializer):

    county = serializers.StringRelatedField()
    province_id = serializers.CharField(required=False)
    province = serializers.ListField()

    class Meta:
        model = City
        fields = ('id', 'name', 'county', 'province', 'province_id', )
        read_only_fields = ('id', 'name', 'county', 'province', )
        extra_kwargs = {'province_id': {'write_only': True}}


class CheckUserLocationSerializer(serializers.ModelSerializer):

    longitude = serializers.FloatField(required=True)
    latitude = serializers.FloatField(required=True)

    class Meta:
        model = City
        fields = ('id', 'name', 'province', 'longitude', 'latitude')
        read_only_fields = ('id', 'name', 'province',)


class EventSerializer(serializers.ModelSerializer):

    location_distance = serializers.CharField(required=False)
    gps_googlemap = serializers.SerializerMethodField()
    num_reputation = serializers.CharField(required=False)
    province = serializers.CharField(required=False)
    city = serializers.StringRelatedField()
    user = serializers.StringRelatedField()
    user_image = serializers.CharField(required=False)
    category = serializers.StringRelatedField()
    participant_self = serializers.BooleanField(read_only=True)
    current = serializers.BooleanField(read_only=True)
    image = serializers.CharField(required=False)
    


    series = serializers.StringRelatedField()
    series_details = serializers.CharField(required=False)

    def get_gps_googlemap(self, obj):
        try:
            return obj.gps_googlemap + str(obj.city.geo_location[1]) + ',' + str(obj.city.geo_location[0])
        except:
            pass

    # def get_test(self, obj):
    #     return obj.participants_event.count()

    class Meta:
        model = Event
        # fields = '__all__'
        fields = ('id', 'location_distance', 'gps_googlemap', 'num_reputation', 'province', 'city', 'current',
                  'user', 'user_image', 'category', 'participant_self', 'slug', 'uuid', 'title', 'text', 'created_time', 'edit_time', 'event_date', 'image',  'series', 'series_details', 'schedule')
        read_only_fields = ('id', 'title', 'text', 'image',
                            'event_date', )
        






class EventHomescreenSerializer(serializers.ModelSerializer):

    location_distance = serializers.CharField(required=False)
    gps_googlemap = serializers.SerializerMethodField()
    num_reputation = serializers.CharField(required=False)
    province = serializers.CharField(required=False)
    city = serializers.StringRelatedField()
    user = serializers.StringRelatedField()
    user_image = serializers.CharField(required=False)
    category = serializers.StringRelatedField()
    participant_self = serializers.BooleanField(read_only=True)
    current = serializers.BooleanField(read_only=True)
    image = serializers.CharField(required=False)
    


    series_events = serializers.ListField()
    series = serializers.StringRelatedField()
    series_details = serializers.CharField(required=False)

    def get_gps_googlemap(self, obj):
        try:
            return obj.gps_googlemap + str(obj.city.geo_location[1]) + ',' + str(obj.city.geo_location[0])
        except:
            pass

    # def get_test(self, obj):
    #     return obj.participants_event.count()

    class Meta:
        model = Event
        # fields = '__all__'
        fields = ('id', 'location_distance', 'gps_googlemap', 'num_reputation', 'province', 'city', 'current',
                  'user', 'user_image', 'category', 'participant_self', 'slug', 'uuid', 'title', 'text', 'created_time', 'edit_time', 'event_date', 'image', 'series_events', 'series', 'series_details', 'schedule')
        read_only_fields = ('id', 'title', 'text', 'image',
                            'event_date', )


class EventViewSerializer(serializers.ModelSerializer):

    location_distance = serializers.CharField(required=False)
    user_client = serializers.CharField(required=False)
    gps_googlemap = serializers.SerializerMethodField()
    num_reputation = serializers.CharField(required=False)
    my_report = serializers.CharField(required=False)
    province = serializers.CharField(required=False)
    city = serializers.StringRelatedField()
    user = serializers.StringRelatedField()
    user_image = serializers.CharField(required=False)
    category = serializers.StringRelatedField()
    participant_self = serializers.BooleanField(read_only=True)
    current = serializers.BooleanField(read_only=True)
    image = serializers.ListField()
    series = serializers.StringRelatedField()
    series_details = serializers.CharField(required=False)
    series_events = serializers.SerializerMethodField()
    tickets = serializers.ListField()

    def get_gps_googlemap(self, obj):
        try:
            return obj.gps_googlemap + str(obj.city.geo_location[1]) + ',' + str(obj.city.geo_location[0])
        except:
            pass

    def get_series_events(self, obj):
        if obj.series != None:

            time_now = timezone.now()

            # is_admin = MyUser.objects.get(username=obj.user_client).is_admin
            # print(is_admin)

            events = Event.objects.filter(series=obj.series).values(
                'id', 'title', 'event_date', 'slug', 'uuid', 'verificated', 'user__username').annotate(num_reputation=Subquery(Event.objects.filter(pk=OuterRef('pk')).values('pk').annotate(
                    num_reputation=Count('participants_event')
                ).values('num_reputation')),
                image=Subquery(EventImage.objects.filter(
                    event=OuterRef('pk'), main=True).values('image_thumbnail')),
                province=F('city__county__province__name'), city=F('city__name'), category=F('category__type'),
                participant_self=Case(
                    When(
                        Q(user__username=obj.user_client),
                        then=None
                    ),
                    default=Exists(
                        Event.objects.filter(
                            pk=OuterRef('pk'),
                            participants_event__username=obj.user_client
                        )
                    ),
                    output_field=CharField()),
                    current=Q(event_date__gte=time_now)
            ).order_by('event_date')
            if not MyUser.objects.get(username=obj.user_client).is_admin:
                events = events.filter(Q(verificated="verificated") |
                                       Q(user__username=obj.user_client))

        else:
            events = None
        return events

    class Meta:
        model = Event
        # fields = '__all__'
        fields = ('id', 'verificated', 'verificated_details', 'user_client', 'location_distance', 'gps_googlemap', 'num_reputation', 'my_report', 'province', 'city', 'current',
                  'user', 'user_image', 'category', 'series', 'tickets', 'series_details', 'series_events', 'participant_self', 'slug', 'uuid', 'title', 'text', 'created_time', 'edit_time', 'event_date', 'schedule', 'image')
        read_only_fields = ('id', 'title', 'text', 'image',
                            'event_date',)


class CommentEventSerializer(serializers.ModelSerializer):

    slug = serializers.CharField(write_only=True)
    uuid = serializers.CharField(write_only=True)
    id_reply = serializers.CharField(write_only=True)
    text_comment = serializers.CharField(max_length=500)
    author_image = serializers.CharField(read_only=True)
    event = serializers.StringRelatedField()
    author = serializers.StringRelatedField()
    replies = serializers.SerializerMethodField()
    my_reaction = serializers.CharField(read_only=True)
    my_report = serializers.CharField(read_only=True)
    is_blocked = serializers.BooleanField(read_only=True)

    class Meta:
        model = CommentEvent
        fields = ('id', 'event', 'author', 'author_image', 'text_comment', 'is_blocked', 'score', 'my_reaction', 'my_report',
                  'slug', 'uuid', 'id_reply', 'parent_comment', 'created_at', 'replies', 'is_blocked')
        read_only_fields = ('created_at', 'author',
                            'event', 'id', 'parent_comment', 'author_image', 'created_at', 'score', 'my_reaction', 'my_report', 'is_blocked')

    def get_replies(self, obj):

        is_admin = self.context.get("is_admin")

        if is_admin:
            replies = obj.replies.all().select_related('author', 'event').annotate(author_image=F('author__image_thumbnail'),
                                                                                   my_reaction=F('commenteventreaction__type'), my_report=F('commenteventreport__type'), text_comment=F('text')).order_by('-id')
        else:
            replies = obj.replies.all().select_related('author', 'event').annotate(author_image=F('author__image_thumbnail'),
                                                                                   my_reaction=F('commenteventreaction__type'), my_report=F('commenteventreport__type'), text_comment=Case(When(is_blocked=True, then=None), default=F('text'), output_field=CharField())).order_by('-id')
        return CommentEventSerializer(replies, many=True, context={'is_admin': is_admin}).data

        # context=self.context


class CommentEventReactionSerializer(serializers.ModelSerializer):
    CHOICES = (
        ('Like', 'Like'),
        ('Dislike', 'Dislike'),
        ('Delete', 'Delete'),
    )

    id_comment = serializers.CharField()
    type = serializers.ChoiceField(choices=CHOICES)
    slug = serializers.CharField(write_only=True)
    uuid = serializers.CharField(write_only=True)

    class Meta:
        model = CommentEventReaction
        fields = ('id_comment', 'type', 'slug', 'uuid')


class CommentEventReportSerializer(serializers.ModelSerializer):
    CHOICES = (
        ("Treści reklamowe lub spam", "Treści reklamowe lub spam"),
        ("Materiały erotyczne i pornograficzne",
         "Materiały erotyczne i pornograficzne"),
        ("Wykorzystywanie dzieci", "Wykorzystywanie dzieci"),
        ("Propagowanie terroryzmu", "Propagowanie terroryzmu"),
        ("Nękanie lub dokuczanie", "Nękanie lub dokuczanie"),
        ("Nieprawdziwe informacje", "Nieprawdziwe informacje"),
    )

    id_comment = serializers.CharField()
    type = serializers.ChoiceField(choices=CHOICES)
    details = serializers.CharField(write_only=True, max_length=150)
    slug = serializers.CharField(write_only=True)
    uuid = serializers.CharField(write_only=True)

    class Meta:
        model = CommentEventReport
        fields = ('id_comment', 'type', 'slug', 'uuid', 'details')


class UserEventsSerializer(serializers.ModelSerializer):
    CHOICES_EVENTS = (
        ("created", "created"),
        ("future", "future"),
        ("past", "past"),
    )

    CHOICES_ORDERING = (
        ("newest", "newest"),
        ("popularity", "popularity"),
        ("event_date", "event_date"),
    )

    username = serializers.CharField(write_only=True)
    page = serializers.CharField(write_only=True)
    type = serializers.ChoiceField(
        choices=CHOICES_EVENTS, write_only=True)
    ordering = serializers.ChoiceField(
        choices=CHOICES_ORDERING, write_only=True)
    events_category = serializers.CharField(write_only=True)
    gps_googlemap = serializers.SerializerMethodField()
    location_distance = serializers.CharField(read_only=True)
    num_reputation = serializers.CharField(read_only=True)
    province = serializers.CharField(read_only=True)
    user_image = serializers.CharField(read_only=True)
    city = serializers.StringRelatedField()
    category = serializers.StringRelatedField()
    user = serializers.StringRelatedField()
    participant_self = serializers.BooleanField(read_only=True)
    current = serializers.BooleanField(required=False)
    image = serializers.CharField(required=False)

    def get_gps_googlemap(self, obj):
        try:
            return obj.gps_googlemap + str(obj.city.geo_location[1]) + ',' + str(obj.city.geo_location[0])
        except:
            pass

    class Meta:
        model = Event
        fields = ('id', 'verificated', 'location_distance', 'current', 'gps_googlemap', 'num_reputation', 'province', 'city',
                  'user', 'user_image', 'category', 'participant_self', 'slug', 'uuid', 'title', 'text', 'created_time', 'edit_time', 'event_date', 'image', 'username', 'type', 'events_category', 'page', 'ordering')

        read_only_fields = ('id', 'title', 'text',
                            'event_date', 'user')


class UserParticipateSerializer(serializers.ModelSerializer):
    id_event = serializers.CharField(write_only=True)

    class Meta:
        model = Event
        fields = ('id_event',)


class EventParticipantsSerializer(serializers.ModelSerializer):

    class Meta:
        model = MyUser
        fields = ('id', 'username', 'image_thumbnail')


class FriendsRemoveSerializer(serializers.ModelSerializer):

    id_target = serializers.IntegerField(required=True, write_only=True)

    class Meta:
        model = Friendship_Request
        fields = ('from_user', 'to_user', 'created_at', 'id_target',)
        read_only_fields = ('from_user', 'to_user', 'created_at',)


class FriendsActionSerializer(serializers.ModelSerializer):
    CHOICES = (
        ("Send", "Send"),
        ("Cancel", "Cancel"),
    )

    type = serializers.ChoiceField(choices=CHOICES)
    id_target = serializers.IntegerField(required=True, write_only=True)

    class Meta:
        model = Friendship_Request
        fields = ('from_user', 'to_user', 'created_at', 'id_target', 'type')
        read_only_fields = ('from_user', 'to_user', 'created_at',)


class FriendsRequestReactionSerializer(serializers.ModelSerializer):
    CHOICES_TYPE = (
        ("accept", "accept"),
        ("reject", "reject"),
    )

    id_target = serializers.IntegerField(required=True, write_only=True)
    type = serializers.ChoiceField(
        choices=CHOICES_TYPE, write_only=True)

    class Meta:
        model = Friendship_Request
        fields = ('from_user', 'to_user', 'created_at', 'id_target', 'type')
        read_only_fields = ('from_user', 'to_user', 'created_at',)


class EventAddSerializer(serializers.ModelSerializer):

    image0 = serializers.ImageField(required=True)
    image1 = serializers.ImageField(required=False)
    image2 = serializers.ImageField(required=False)
    image3 = serializers.ImageField(required=False)
    image4 = serializers.ImageField(required=False)
    image5 = serializers.ImageField(required=False)
    image6 = serializers.ImageField(required=False)
    image7 = serializers.ImageField(required=False)
    province = serializers.CharField(required=True)
    category = serializers.CharField(write_only=True)
    city = serializers.CharField(write_only=True)
    series = serializers.CharField(write_only=True)
    schedule = serializers.CharField(write_only=True)

    class Meta:
        model = Event
        fields = ('title', 'text', 'category', 'series', 'event_date', 'province', 'city', 'schedule', 'image0',
                  'image1', 'image2', 'image3', 'image4', 'image5', 'image6', 'image7')
        # read_only_fields = ('participants', 'user')


class EventEditSerializer(serializers.ModelSerializer):

    image0 = serializers.ImageField(required=True)
    image1 = serializers.ImageField(required=False)
    image2 = serializers.ImageField(required=False)
    image3 = serializers.ImageField(required=False)
    image4 = serializers.ImageField(required=False)
    image5 = serializers.ImageField(required=False)
    image6 = serializers.ImageField(required=False)
    image7 = serializers.ImageField(required=False)
    province = serializers.CharField(required=True)
    category = serializers.CharField(write_only=True)
    city = serializers.CharField(write_only=True)
    series = serializers.CharField(write_only=True)
    schedule = serializers.CharField(write_only=True)
    id = serializers.CharField(write_only=True)

    class Meta:
        model = Event
        fields = ('id', 'title', 'text', 'category', 'series', 'event_date', 'province', 'city', 'schedule', 'image0',
                  'image1', 'image2', 'image3', 'image4', 'image5', 'image6', 'image7')


class SeriesSerializer(serializers.ModelSerializer):
    author = serializers.StringRelatedField()

    class Meta:
        model = Series
        fields = '__all__'
        read_only_fields = ('author',)


class EventReportSerializer(serializers.ModelSerializer):
    CHOICES = (
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

    id_event = serializers.CharField()
    type = serializers.ChoiceField(choices=CHOICES)
    details = serializers.CharField()

    class Meta:
        model = EventReport
        fields = ('id_event', 'type', 'details')


class EventsViaSeriesSerializer(serializers.ModelSerializer):
    data = serializers.ListField()
    current = serializers.BooleanField(read_only=True)

    class Meta:
        model = Series
        fields = ('name', 'description', 'current', 'data')


class EventsNoSeriesSerializer(serializers.ModelSerializer):
    category = serializers.StringRelatedField()
    city = serializers.StringRelatedField()
    series = serializers.StringRelatedField()
    current = serializers.BooleanField(read_only=True)
    province = serializers.CharField(required=True)
    num_reputation = serializers.IntegerField(required=False)
    image = serializers.CharField(required=False)

    class Meta:
        model = Event
        fields = ('series', 'id', 'city', 'slug', 'uuid', 'image', 'title', 'current', 'category', 'province',
                  'event_date', 'verificated', 'num_reputation')


class EventsEditSeriesSerializer(serializers.ModelSerializer):
    id_event = serializers.CharField(write_only=True)
    series = serializers.CharField(write_only=True)

    class Meta:
        model = Event
        fields = ('id_event', 'series')


class SeriesEditSerializer(serializers.ModelSerializer):
    series = serializers.CharField(write_only=True)

    class Meta:
        model = Series
        fields = '__all__'
        read_only_fields = ('author',)


class EventsViaCalendarSerializer(serializers.ModelSerializer):
    user_client = serializers.CharField(required=False)
    user = serializers.StringRelatedField()
    category = serializers.StringRelatedField()
    current = serializers.BooleanField(read_only=True)
    province = serializers.CharField(required=True)
    city = serializers.StringRelatedField()
    num_reputation = serializers.IntegerField(required=False)
    image = serializers.CharField(required=False)
    type = serializers.SerializerMethodField()

    def get_type(self, obj):
        if obj.user.username != obj.user_client:
            return "participate"
        else:
            return obj.type

    class Meta:
        model = Event
        fields = ('id', 'title', 'slug', 'uuid', 'category',
                  'event_date', 'city', 'province', 'image', 'num_reputation', 'user_client', 'user', 'type', 'current')


class EventsRandomSerializer(serializers.ModelSerializer):

    location_distance = serializers.CharField(required=False)
    gps_googlemap = serializers.SerializerMethodField()
    num_reputation = serializers.CharField(required=False)
    province = serializers.CharField(required=False)
    city = serializers.StringRelatedField()
    user = serializers.StringRelatedField()
    user_image = serializers.CharField(required=False)
    category = serializers.StringRelatedField()
    image = serializers.ListField()
    series_events = serializers.ListField()
    series = serializers.StringRelatedField()
    series_details = serializers.CharField(required=False)

    def get_gps_googlemap(self, obj):
        try:
            return obj.gps_googlemap + str(obj.city.geo_location[1]) + ',' + str(obj.city.geo_location[0])
        except:
            pass

    class Meta:
        model = Event
        # fields = '__all__'
        fields = ('id',  'location_distance', 'gps_googlemap', 'num_reputation', 'province', 'city',
                  'user', 'user_image', 'category', 'slug', 'uuid', 'title', 'text', 'created_time', 'edit_time', 'event_date', 'schedule', 'image', 'series_events', 'series', 'series_details')
        read_only_fields = ('id', 'title', 'text', 'image',
                            'event_date', )


class EventsRandomReactionSerializer(serializers.ModelSerializer):
    CHOICES = (
        ('Like', 'Like'),
        ('Dislike', 'Dislike'),
    )

    id_event = serializers.CharField()
    type = serializers.ChoiceField(choices=CHOICES)

    class Meta:
        model = Event
        fields = ('id_event', 'type',)


class EventsProvinceMapSerializer(serializers.ModelSerializer):
    count = serializers.IntegerField(required=False)

    class Meta:
        model = Province
        fields = "__all__"
        # fields = ('id_event', 'series')


class EventsCountyMapSerializer(serializers.ModelSerializer):
    count = serializers.IntegerField(required=False)
    county_events = serializers.ListField()

    class Meta:
        model = County
        fields = ('id', 'name', 'count', 'county_events')
        # fields = ('id_event', 'series')


class FindFriendsSerializer(serializers.ModelSerializer):

    target_username = serializers.CharField(required=False)
    excluded_ids = serializers.CharField(required=False)

    city = serializers.StringRelatedField()
    province = serializers.CharField(read_only=True)
    is_friend = serializers.CharField(read_only=True)
    together_friends = serializers.ListField(read_only=True)
    friends_count = serializers.IntegerField(read_only=True)
    events_count = serializers.IntegerField(read_only=True)
    events_actual_count = serializers.IntegerField(read_only=True)

    class Meta:
        model = MyUser
        fields = ('id', 'username', 'first_name', 'last_name',
                  'image_thumbnail', 'city', 'province', 'is_friend', 'together_friends', 'friends_count', 'events_count', 'events_actual_count', 'target_username', 'excluded_ids')
        read_only_fields = ('id', 'username', 'first_name', 'last_name',
                            'image_thumbnail', 'city', 'province', 'is_friend', 'together_friends', 'friends_count', 'events_count', 'events_actual_count')


class EventsViaBadgesSerializer(serializers.ModelSerializer):
    city = serializers.StringRelatedField()
    province = serializers.CharField(read_only=True)
    image = serializers.CharField(required=False)
    category = serializers.StringRelatedField()
    badges = serializers.ListField(read_only=True)

    class Meta:
        model = Event
        fields = ('id', 'city', 'province', 'slug', 'uuid',
                  'image', 'title', 'category', 'event_date', 'badges', 'verificated')


class BadgesCodesListSerializer(serializers.ModelSerializer):

    event_id = serializers.IntegerField(required=True, write_only=True)
    badge_id = serializers.IntegerField(required=True, write_only=True)
    badge_codes_id_list = serializers.CharField(required=True, write_only=True)

    class Meta:
        model = BadgeCode
        fields = ('code', 'event_id', 'badge_id', 'badge_codes_id_list', )
        read_only_fields = ('code',)


class BadgeCodesReturnedUsedSerializer(serializers.ModelSerializer):

    activated_by = serializers.StringRelatedField()

    class Meta:
        model = BadgeCode
        fields = ('id', 'code', 'activated_by', 'created_time')
        read_only_fields = ('id', 'code', 'activated_by', 'created_time')


class BadgesCodesCreateSerializer(serializers.ModelSerializer):

    event_id = serializers.IntegerField(required=True, write_only=True)
    badge_id = serializers.IntegerField(required=True, write_only=True)
    amount = serializers.IntegerField(required=True, write_only=True)
    created_time = serializers.DateTimeField(read_only=True)

    class Meta:
        model = BadgeCode
        fields = ('code', 'event_id', 'badge_id', 'amount',
                  'id', 'status', 'activated_by', 'created_time')
        read_only_fields = ('code', 'id', 'status',
                            'activated_by', 'created_time')


class BadgeEditSerializer(serializers.ModelSerializer):

    badge_id = serializers.IntegerField(required=True, write_only=True)

    class Meta:
        model = Badge
        fields = ('badge_id', 'name', 'image',)


class BadgeCreateSerializer(serializers.ModelSerializer):

    event_id = serializers.IntegerField(required=True, write_only=True)

    class Meta:
        model = Badge
        fields = ('event_id', 'id', 'name', 'image', 'verificated')
        read_only_fields = ('id', 'verificated')


class BadgeDeleteSerializer(serializers.ModelSerializer):

    badge_id = serializers.IntegerField(required=True, write_only=True)

    class Meta:
        model = Badge
        fields = ('badge_id',)


class UserBadgesCreatedSerializer(serializers.ModelSerializer):
    event = serializers.StringRelatedField()
    creator = serializers.StringRelatedField()
    slug_event = serializers.CharField(read_only=True)
    uuid_event = serializers.CharField(read_only=True)

    class Meta:
        model = Badge
        fields = "__all__"


class UserBadgesActivatedSerializer(serializers.ModelSerializer):
    event = serializers.StringRelatedField()
    slug_event = serializers.CharField(read_only=True)
    uuid_event = serializers.CharField(read_only=True)
    activated_time = serializers.DateTimeField(read_only=True)
    my_report = serializers.CharField(required=False)

    class Meta:
        model = Badge
        fields = ('id', 'event', 'slug_event',
                  'uuid_event', 'name', 'image', 'verificated', 'activated_time', 'verificated_details', 'my_report')


class BadgeActivateSerializer(serializers.ModelSerializer):
    code = serializers.CharField(write_only=True)
    event = serializers.StringRelatedField()
    slug_event = serializers.SerializerMethodField()
    uuid_event = serializers.SerializerMethodField()
    title_event = serializers.SerializerMethodField()
    activated_time = serializers.SerializerMethodField()
    my_report = serializers.ReadOnlyField(default=None)

    class Meta:
        model = Badge
        fields = ('id', 'event', 'name', 'image', 'code',
                  'event', 'slug_event', 'uuid_event', 'verificated', 'activated_time', 'title_event', 'verificated_details', 'my_report')
        read_only_fields = ('id', 'event', 'name', 'image',
                            'event', 'slug_event', 'uuid_event', 'verificated', 'activated_time', 'title_event', 'verificated_details', 'my_report')

    def get_slug_event(self, obj):

        return obj.event.slug

    def get_uuid_event(self, obj):

        return obj.event.uuid

    def get_title_event(self, obj):

        return obj.event.title

    def get_activated_time(self, obj):

        user = self.context.get("user")
        print(user)

        activated_time = BadgeCode.objects.get(
            badge__id=obj.id, activated_by=user).activated_time
        print("łoooo")

        return activated_time


class BadgeReportSerializer(serializers.ModelSerializer):
    CHOICES = (
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

    id_badge = serializers.IntegerField()
    type = serializers.ChoiceField(choices=CHOICES)
    details = serializers.CharField()

    class Meta:
        model = Badge
        fields = ('id_badge', 'type', 'details')


class UserLoginLocationsSerializer(serializers.ModelSerializer):
    ip_address = serializers.StringRelatedField()
    city = serializers.CharField(read_only=True)
    county = serializers.CharField(read_only=True)
    province = serializers.CharField(read_only=True)

    class Meta:
        model = IPAddressValidator
        fields = ('id', 'is_verificated', 'last_login_time', 'name_device',
                  'ip_address', 'city', 'county', 'province',)


class LogoutFromDevicesSerializer(serializers.ModelSerializer):

    devices_id_list = serializers.CharField(required=True, write_only=True)

    class Meta:
        model = IPAddressValidator
        fields = ('devices_id_list',)

    # class Meta:
    #     model = CustomOutstandingToken
    #     fields = "__all__"


class UserBlockUsersSerializer(serializers.ModelSerializer):

    id_target = serializers.IntegerField(required=True, write_only=True)

    class Meta:
        model = MyUser
        fields = ('id', 'username', 'image_thumbnail', 'id_target')
        read_only_fields = ('id', 'username', 'image_thumbnail')


class PasswordChangeSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        label="Hasło", write_only=True, style={'input_type': 'password'})

    class Meta:
        model = MyUser
        fields = ('password',)


class EmailChangeSerializer(serializers.ModelSerializer):
    new_email = serializers.CharField(label="New email", write_only=True)

    class Meta:
        model = MyUser
        fields = ('new_email', )


class EmailChangeConfirmSerializer(serializers.ModelSerializer):
    old_code = serializers.CharField(write_only=True)
    new_code = serializers.CharField(write_only=True)

    class Meta:
        model = MyUser
        fields = ('old_code', 'new_code')


class UserEditSerializer(serializers.ModelSerializer):
    image = serializers.ImageField()
    province = serializers.CharField(write_only=True)
    city_target = serializers.CharField(write_only=True)

    class Meta:
        model = MyUser
        fields = ('username', 'first_name', 'last_name',
                  'province', 'city_target', 'image', 'image_thumbnail', 'city')
        depth = 3


class BadgesViaSettingsSerializer(serializers.ModelSerializer):

    main = serializers.BooleanField(read_only=True)

    class Meta:
        model = Badge
        fields = ('id', 'name', 'image', 'main')


class AdminLogsSerializer(serializers.ModelSerializer):
    user = serializers.StringRelatedField()
    user_image = serializers.CharField(read_only=True)
    excluded_ids = serializers.CharField(write_only=True)
    cursor_id = serializers.IntegerField(required=True, write_only=True)
    new = serializers.BooleanField(read_only=True)

    class Meta:
        model = AdminLog
        fields = ('id', 'user', 'user_image', 'action_time', 'action_flag', 'content_type',
                  'id_content_type', 'excluded_ids', 'cursor_id', 'new')
        read_only_fields = ('id', 'user', 'user_image', 'action_time', 'action_flag',
                            'content_type', 'id_content_type', 'new')


class AdminReportsEventsSerializer(serializers.ModelSerializer):

    user = serializers.StringRelatedField()
    user_image = serializers.CharField(read_only=True)
    reported_by = serializers.ListField()
    count_types = serializers.JSONField(read_only=True)

    class Meta:
        model = Event
        fields = ('id', 'verificated', 'slug', 'uuid', 'title',
                  'user', 'user_image', 'reported_by', 'count_types', 'edit_time')


class AdminReportsCommentsSerializer(serializers.ModelSerializer):

    user = serializers.CharField(read_only=True)
    user_image = serializers.CharField(read_only=True)
    slug = serializers.CharField(read_only=True)
    uuid = serializers.CharField(read_only=True)
    reported_by = serializers.ListField()
    count_types = serializers.JSONField(read_only=True)

    class Meta:
        model = CommentEvent
        fields = ('id',  'slug', 'uuid', 'text', 'score', 'user',
                  'user_image', 'reported_by', 'count_types')


class AdminReportsBadgesSerializer(serializers.ModelSerializer):

    user = serializers.CharField(read_only=True)
    user_image = serializers.CharField(read_only=True)
    slug = serializers.CharField(read_only=True)
    uuid = serializers.CharField(read_only=True)
    reported_by = serializers.ListField()
    count_types = serializers.JSONField(read_only=True)

    class Meta:
        model = Badge
        fields = ('id', 'verificated', 'slug', 'uuid',
                  'name', 'image', 'user', 'user_image', 'reported_by', 'count_types', 'edit_time')


class AdminReportedValidateSerializer(serializers.ModelSerializer):

    TYPE_CHOICES = (
        ("need_improvement", "Wymaga zmian"),
        ("remove", "Usunięcie"),
        ("cancel", "Usuń reporty")
    )

    STATUS_CHOICES = (
        ("verificated", "Zweryfikowane"),
        ("awaiting", "Oczekujące na akceptacje"),
    )

    target_id = serializers.IntegerField(required=True, write_only=True)
    details = serializers.CharField(max_length=150, write_only=True)
    type = serializers.ChoiceField(choices=TYPE_CHOICES)
    actual_status = serializers.ChoiceField(choices=STATUS_CHOICES)

    class Meta:
        model = Event
        fields = ('target_id', 'details', 'type', 'actual_status')


class AdminLogExistingSerializer(serializers.ModelSerializer):
    user = serializers.StringRelatedField()
    user_image = serializers.CharField(read_only=True)

    class Meta:
        model = AdminLog
        fields = ('id', 'user', 'user_image', 'action_time',
                  'action_flag', 'content_type', 'id_content_type',)
        read_only_fields = ('id', 'user', 'user_image',
                            'action_time', 'action_flag',)


class AdminCommentReportedValidateSerializer(serializers.ModelSerializer):

    TYPE_CHOICES = (
        ("remove", "Usunięcie"),
        ("cancel", "Usuń reporty")
    )

    target_id = serializers.IntegerField(required=True, write_only=True)
    details = serializers.CharField(max_length=150, write_only=True)
    type = serializers.ChoiceField(choices=TYPE_CHOICES)

    class Meta:
        model = Event
        fields = ('target_id',  'type', 'details')


class AdminAwaitingsEventsSerializer(serializers.ModelSerializer):

    user = serializers.StringRelatedField()
    user_image = serializers.CharField(read_only=True)
    edit_time = serializers.SerializerMethodField()

    def get_edit_time(self, obj):
        try:
            return obj.edit_time.strftime('%Y-%m-%dT%H:%M')
        except:
            pass

    class Meta:
        model = Event
        fields = ('id', 'slug', 'uuid', 'title',
                  'user', 'user_image', 'edit_time', 'text', 'verificated_details')


class AdminAwaitingsBadgesSerializer(serializers.ModelSerializer):

    user = serializers.CharField(read_only=True)
    user_image = serializers.CharField(read_only=True)
    slug = serializers.CharField(read_only=True)
    uuid = serializers.CharField(read_only=True)
    edit_time = serializers.SerializerMethodField()

    def get_edit_time(self, obj):
        try:
            return obj.edit_time.strftime('%Y-%m-%dT%H:%M')
        except:
            pass

    class Meta:
        model = Badge
        fields = ('id', 'slug', 'uuid',
                  'name', 'image', 'user', 'user_image', 'edit_time', 'verificated_details')
        


class AdminAwaitingsTicketsSerializer(serializers.ModelSerializer):

    user = serializers.CharField(read_only=True)
    user_image = serializers.CharField(read_only=True)
    slug = serializers.CharField(read_only=True)
    uuid = serializers.CharField(read_only=True)
    event_title = serializers.CharField(read_only=True)
    edit_time = serializers.SerializerMethodField()
    reserved_tickets = serializers.IntegerField(read_only=True)


    def get_edit_time(self, obj):
        try:
            return obj.edit_time.strftime('%Y-%m-%dT%H:%M')
        except:
            pass

    class Meta:
        model = Ticket
        fields = ('id', 'stripe_id', 'stripe_name_product', 'slug', 'uuid', 'user', 'user_image',
                  'ticket_type', 'ticket_details', 'event_title', 'event_id', 'quantity', 'reserved_tickets', 'edit_time', 'verificated_details', 'was_allowed', 'default_price', 'price', 'new_price')
        



class AdminReportsInputSerializer(serializers.ModelSerializer):

    TYPE_CHOICES = (
        ("start", "Początkowe pobranie"),
        ("events", "Wydarzenia"),
        ("comments", "Komentarze"),
        ("badges", "Odznaki")
    )

    excluded_ids = serializers.CharField(write_only=True)
    mode = serializers.ChoiceField(choices=TYPE_CHOICES)
    name = serializers.CharField(write_only=True)

    class Meta:
        model = AdminLog
        fields = ('excluded_ids', 'mode', 'name')


class AdminAwaitingsInputSerializer(serializers.ModelSerializer):

    TYPE_CHOICES = (
        ("start", "Początkowe pobranie"),
        ("events", "Wydarzenia"),
        ("badges", "Odznaki"),
        ("tickets", "Bilety")
    )

    excluded_ids = serializers.CharField(write_only=True)
    mode = serializers.ChoiceField(choices=TYPE_CHOICES)
    name = serializers.CharField(write_only=True)

    class Meta:
        model = AdminLog
        fields = ('excluded_ids', 'mode', 'name')


class AdminAwaitedValidateSerializer(serializers.ModelSerializer):

    TYPE_CHOICES = (
        ("need_improvement", "Wymaga zmian"),
        ("remove", "Usunięcie"),
        ("accepted", "Zweryfikowane")
    )

    target_id = serializers.IntegerField(required=True, write_only=True)
    details = serializers.CharField(max_length=150, write_only=True)
    type = serializers.ChoiceField(choices=TYPE_CHOICES)
    actual_edit_time = serializers.DateTimeField(
        format='%Y-%m-%d %H:%m', input_formats=None)

    class Meta:
        model = Event
        fields = ('target_id', 'details', 'type', 'actual_edit_time')




class AdminAwaitedValidateTicketsSerializer(serializers.ModelSerializer):

    TYPE_CHOICES = (
        ("need_improvement", "Wymaga zmian"),
        ("remove", "Usunięcie"),
        ("accepted", "Zweryfikowane")
    )

    target_id = serializers.IntegerField(required=True, write_only=True)
    details = serializers.CharField(max_length=150, write_only=True)
    type = serializers.ChoiceField(choices=TYPE_CHOICES)
    actual_edit_time = serializers.DateTimeField(
        format='%Y-%m-%d %H:%m', input_formats=None)
    
    stripe_id = serializers.CharField(max_length=30, write_only=True)

    class Meta:
        model = Event
        fields = ('target_id', 'stripe_id', 'details', 'type', 'actual_edit_time')




class AdminPaycheckGatewaySerializer(serializers.ModelSerializer):

    TYPE_CHOICES = (
        ("tickets", "Zwrot biletów"),
        ("events", "Wypłata za wydarzenie"),
    )


    event_id = serializers.IntegerField(required=True, write_only=True)
    user_id = serializers.IntegerField(write_only=True)
    orderedticket_ids = serializers.CharField(write_only=True)
    mode = serializers.ChoiceField(choices=TYPE_CHOICES)
    
    

    class Meta:
        model = Event
        fields = ('event_id', 'user_id', 'orderedticket_ids', 'mode')


class AdminBanUsersIPSerializer(serializers.ModelSerializer):

    TYPE_CHOICES = (
        ("start", "Początkowe pobranie"),
        ("users", "Użytkownicy"),
        ("ips", "Adresy IP")
    )

    excluded_ids = serializers.CharField(write_only=True)
    mode = serializers.ChoiceField(choices=TYPE_CHOICES)
    name = serializers.CharField(write_only=True)

    class Meta:
        model = AdminLog
        fields = ('excluded_ids', 'mode', 'name')


class AdminBanUsersSerializer(serializers.ModelSerializer):

    city = serializers.StringRelatedField()
    province = serializers.CharField(read_only=True)
    count_reports = serializers.JSONField(read_only=True)
    count_active_objects = serializers.JSONField(read_only=True)
    count_deleted = serializers.JSONField(read_only=True)
    details = serializers.ListField()

    class Meta:
        model = MyUser
        fields = ('id', 'username', 'email', 'is_admin', 'first_name', 'last_name', 'city', 'province',
                  'image_thumbnail', 'count_reports', 'count_active_objects', 'count_deleted', 'details')


class AdminBanIPsSerializer(serializers.ModelSerializer):

    count_reports = serializers.JSONField(read_only=True)
    count_active_objects = serializers.JSONField(read_only=True)
    count_deleted = serializers.JSONField(read_only=True)
    details = serializers.ListField()

    class Meta:
        model = IPAddress
        fields = ('id', 'ip_address', 'count_reports',
                  'count_active_objects', 'count_deleted', 'details')


class AdminBanValidateSerializer(serializers.ModelSerializer):

    target_id = serializers.IntegerField(required=True, write_only=True)

    class Meta:
        model = MyUser
        fields = ('target_id', )


class AdminAccountsLogoutSerializer(serializers.ModelSerializer):

    TYPE_CHOICES = (
        ("all_ips", "Wyloguj konto ze wszystkich adresów IP"),
        ("all_users", "Wyloguj wszystkie konta z tego adresu IP"),
        ("single", "Wyloguj konto z tego adresu IP")
    )

    target_id = serializers.IntegerField(required=True, write_only=True)
    ipaddress_id = serializers.IntegerField(required=False, write_only=True)
    type = serializers.ChoiceField(choices=TYPE_CHOICES)

    class Meta:
        model = MyUser
        fields = ('target_id', 'ipaddress_id', 'type')




class AdminPaychecksSerializer(serializers.ModelSerializer):

    TYPE_CHOICES = (
        ("start", "Początkowe pobranie"),
        ("events", "Wydarzenia"),
        ("tickets", "Bilety")
    )

    excluded_ids = serializers.CharField(write_only=True)
    mode = serializers.ChoiceField(choices=TYPE_CHOICES)
    name = serializers.CharField(write_only=True)

    class Meta:
        model = AdminLog
        fields = ('excluded_ids', 'mode', 'name')



class AdminPaychecksTicketsSerializer(serializers.ModelSerializer):

    event_id = serializers.IntegerField(read_only=True)
    price = serializers.DecimalField(max_digits=10, decimal_places=2, read_only=True)
    total_tickets = serializers.IntegerField(read_only=True)
    ticket_details = serializers.ListField(read_only=True)
    title = serializers.CharField(read_only=True)
    slug = serializers.CharField(read_only=True)
    uuid = serializers.CharField(read_only=True)
    user = serializers.CharField(read_only=True)
    user_id = serializers.IntegerField(read_only=True)
    user_image = serializers.CharField(read_only=True)
    all_orderedtickets_ids = serializers.ListField(read_only=True)
    payment_locked = serializers.BooleanField(read_only=True)
    payment_locked_expires = serializers.DateTimeField(allow_null=True)
    payment_information = serializers.JSONField(read_only=True)



    class Meta:
        model = OrderedTicket
        fields = ('id', 'event_id', 'payment_locked', 'payment_locked_expires', 'slug', 'uuid', 'title', 'user', 'user_id', 'payment_information', 'user_image', 'price', 'total_tickets',  'ticket_details', 'all_orderedtickets_ids',)
        

class AdminPaychecksEventsSerializer(serializers.ModelSerializer):



    user = serializers.StringRelatedField()
    user_image = serializers.CharField(read_only=True)
    price_before_commission = serializers.DecimalField(max_digits=10, decimal_places=2, read_only=True)
    price = serializers.DecimalField(max_digits=10, decimal_places=2, read_only=True)
    payment_locked = serializers.BooleanField(read_only=True)
    payment_locked_expires = serializers.DateTimeField(allow_null=True)
    payment_information = serializers.JSONField(read_only=True)
    
    

   

    class Meta:
        model = Event
        fields = ('id', 'payment_locked', 'payment_locked_expires', 'slug', 'uuid', 'title', 'user', 'user_id', 'payment_information', 'user_image', 'price_before_commission', 'price')




class AdminMissingTicketsPaycheckSerializer(serializers.ModelSerializer):



    class Meta:
        model = OrderedTicket
        fields = ('id', 'purchase_price', 'first_name', 'last_name', 'date_of_birth')
        

class FriendsListSerializer(serializers.ModelSerializer):
    is_friend = serializers.BooleanField(read_only=True)
    excluded_ids = serializers.CharField(write_only=True)

    class Meta:
        model = MyUser
        fields = ('id', 'username', 'image_thumbnail',
                  'is_friend', 'excluded_ids')
        read_only_fields = ('username', 'image_thumbnail')


class LastMessagesListSerializer(serializers.ModelSerializer):

    messages = serializers.JSONField(read_only=True)
    is_friend = serializers.BooleanField(read_only=True)
    excluded_ids = serializers.CharField(write_only=True)
    unread_messages = serializers.IntegerField(read_only=True)
    blocked_by_target_user = serializers.BooleanField(read_only=True)
    block_target_user = serializers.BooleanField(read_only=True)

    class Meta:
        model = MyUser
        fields = ('id', 'username', 'image_thumbnail',
                  'messages', 'is_friend', 'unread_messages', 'excluded_ids', 'blocked_by_target_user', 'block_target_user')
        read_only_fields = ('username', 'image_thumbnail')


class UserConversationSerializer(serializers.ModelSerializer):

    cursor_id = serializers.IntegerField(required=False, write_only=True)
    target_user_id = serializers.IntegerField(required=True, write_only=True)
    author = serializers.IntegerField(read_only=True)
    status = serializers.CharField(read_only=True)

    class Meta:
        model = ActiveMessage
        fields = ('cursor_id', 'target_user_id', 'author', 'content', 'timestamp', 'message_id',
                  'status')
        read_only_fields = ('author', 'content', 'timestamp', 'message_id',
                            'status')


class FriendshipListSerializer(serializers.ModelSerializer):
    is_friend = serializers.BooleanField(read_only=True)
    excluded_ids = serializers.CharField(write_only=True)
    created_at = serializers.DateTimeField(read_only=True)

    class Meta:
        model = MyUser
        fields = ('id', 'username', 'image_thumbnail',
                  'is_friend', 'excluded_ids', 'created_at')
        read_only_fields = ('username', 'image_thumbnail', 'created_at')


class FindProfileByIdSerializer(serializers.ModelSerializer):

    target_id = serializers.IntegerField(write_only=True)

    class Meta:
        model = MyUser
        fields = ('id', 'username', 'image_thumbnail', 'target_id',)
        read_only_fields = ('username', 'image_thumbnail',)






class NotificationsListSerializer(serializers.ModelSerializer):

    cursor_date = serializers.DateTimeField(write_only=True)
    
    class Meta:
        model = NotificationsForUser
        fields = ('id', 'user', 'notifications_array', 'cursor_date')
        read_only_fields = ('user', 'notifications_array')




class EventTicketsViewSerializer(serializers.ModelSerializer):

    reserved_tickets = serializers.IntegerField(read_only=True)


    class Meta:
        model = Ticket
        fields = ('id', 'stripe_id', 'ticket_type','ticket_details','default_price', 'price', 'quantity', 'reserved_tickets')



# class BankNumberViewSerializer(serializers.ModelSerializer):

#     code = serializers.CharField(required=True, write_only=True)
#     status_connect = serializers.BooleanField(required=True, write_only=True)
#     new_bank_number = serializers.IntegerField(required=False, write_only=True)

#     class Meta:
#         model = MyUser
#         fields = ('code', 'status_connect', 'new_bank_number')
        


class BankNumberViewSerializer(serializers.ModelSerializer):

    code = serializers.CharField(required=True, write_only=True)
    status_connect = serializers.BooleanField(required=True, write_only=True)
    new_bank_number = serializers.IntegerField(required=False, write_only=True)

    blocked_remove_bank_account = serializers.JSONField(read_only=True)
    blocked_change_bank_account = serializers.BooleanField(read_only=True)
    amount_awaiting_refunding = serializers.DecimalField(max_digits=10, decimal_places=2, read_only=True)

    class Meta:
        model = MyUser
        fields = ('code', 'status_connect', 'new_bank_number', 'bank_number', 'blocked_remove_bank_account', 'blocked_change_bank_account', 'amount_awaiting_refunding')
        read_only_fields = ('bank_number', 'blocked_remove_bank_account', 'blocked_change_bank_account', 'amount_awaiting_refunding')



class EventsViaTicketsSerializer(serializers.ModelSerializer):
    city = serializers.StringRelatedField()
    province = serializers.CharField(read_only=True)
    image = serializers.CharField(required=False, read_only=True)
    category = serializers.StringRelatedField()
    tickets = serializers.ListField(read_only=True)
    current = serializers.BooleanField(read_only=True)

    event_id = serializers.IntegerField(required=True, write_only=True)
    price = serializers.IntegerField(required=True, write_only=True)
    quantity = serializers.IntegerField(required=True, write_only=True)
    ticket_type = serializers.CharField(required=True, write_only=True)
    ticket_details = serializers.CharField(required=True, write_only=True)



    class Meta:
        model = Event
        fields = ('id', 'city', 'province', 'slug', 'uuid', 'current',
                  'image', 'title', 'category', 'event_date', 'tickets', 'verificated', 'event_id', 'price', 'quantity', 'ticket_type', 'ticket_details')
        read_only_fields = ('image', 'current', 'title', 'event_date', 'verificated')


class TicketEditSerializer(serializers.ModelSerializer):

    VERIFICATED_CHOICES = (
        ("awaiting", "Oczekujące"),
        ("need_improvement", "Wymaga zmian"),
        ("verificated", "Zweryfikowane"),
    )

    ticket_id = serializers.IntegerField(required=True, write_only=True)
    event_id = serializers.IntegerField(required=True, write_only=True)
    price = serializers.IntegerField(required=True, write_only=True)
    quantity = serializers.IntegerField(required=True, write_only=True)
    ticket_type = serializers.CharField(required=True, write_only=True)
    actual_edit_time = serializers.DateTimeField()
    verificated = serializers.ChoiceField(choices=VERIFICATED_CHOICES)
    ticket_details = serializers.CharField(required=True, write_only=True)

    class Meta:
        model = Event
        fields = ( 'ticket_id', 'event_id', 'verificated', 'ticket_type', 'ticket_details', 'price', 'quantity', 'actual_edit_time')


class TicketDeleteSerializer(serializers.ModelSerializer):

    event_id = serializers.IntegerField(required=True, write_only=True)
    ticket_id = serializers.IntegerField(required=True, write_only=True)
   
    class Meta:
        model = Event
        fields = ('event_id', 'ticket_id')



class TicketDeleteSerializer(serializers.ModelSerializer):

    event_id = serializers.IntegerField(required=True, write_only=True)
    ticket_id = serializers.IntegerField(required=True, write_only=True)
   
    class Meta:
        model = Event
        fields = ('event_id', 'ticket_id')
    

class TicketPaySerializer(serializers.ModelSerializer):

    event_id = serializers.IntegerField(required=True, write_only=True)
    tickets_data = serializers.JSONField(required=True, write_only=True)

   
    class Meta:
        model = Ticket
        fields = ('tickets_data', 'event_id')



class OrderedTicketsSerializer(serializers.ModelSerializer):


    event = serializers.JSONField(read_only=True)
    tickets = serializers.ListField()
    expired_refund = serializers.BooleanField(read_only=True)
    stripe_refund_order = serializers.DateTimeField(allow_null=True)
    paycheck_attachments = serializers.ListField()
    awaitings_refund_amount = serializers.DecimalField(max_digits=10, decimal_places=2, read_only=True)
 
   
    class Meta:
        model = Order
        fields = ('id', 'stripe_payment_intent_id', 'created_at', 'stripe_created_at', 'order_expires_at', 'expired_refund', 'stripe_refund_order', 'awaitings_refund_amount', 'is_paid', 'paid_time', 'event', 'tickets', 'paycheck_attachments') 



class TicketRefundSerializer(serializers.ModelSerializer):

    event_id = serializers.IntegerField(required=True, write_only=True)
    orderedticket_id = serializers.IntegerField(required=True, write_only=True)
   
    class Meta:
        model = Event
        fields = ('event_id', 'orderedticket_id')



class OrderedTicketCancelSerializer(serializers.ModelSerializer):

    event_id = serializers.IntegerField(required=True, write_only=True)
    order_id = serializers.IntegerField(required=True, write_only=True)
    orderedticket_ids = serializers.CharField(write_only=True)
    
   
    class Meta:
        model = Order
        fields = ('event_id', 'order_id', 'orderedticket_ids')



class OrderedTicketActionSerializer(serializers.ModelSerializer):

    ACTION_TYPE_CHOICES = (
        ("cancel", "Anulowanie"),
        ("pay", "Opłata"),
    )

    event_id = serializers.IntegerField(required=True, write_only=True)
    order_id = serializers.IntegerField(required=True, write_only=True)
    action_type = serializers.ChoiceField(choices=ACTION_TYPE_CHOICES)
    orderedticket_ids = serializers.CharField(write_only=True)

   
    class Meta:
        model = Order
        fields = ('event_id', 'order_id', 'action_type', 'orderedticket_ids')





class SoldTicketsViaCalendarSerializer(serializers.ModelSerializer):
    category = serializers.StringRelatedField()
    current = serializers.BooleanField(read_only=True)
    province = serializers.CharField(read_only=True)
    city = serializers.StringRelatedField()
    image = serializers.CharField(read_only=True)
    tickets = serializers.ListField()
    paid_out = serializers.BooleanField(read_only=True)
    earn = serializers.DecimalField(max_digits=10, decimal_places=2, read_only=True)
    refund = serializers.DecimalField(max_digits=10, decimal_places=2, read_only=True)
    earn_cancel = serializers.BooleanField(read_only=True)
    paycheck_attachments = serializers.JSONField(read_only=True) 


    class Meta:
        model = Event
        fields = ('id', 'title', 'slug', 'uuid', 'category',
                  'event_date', 'city', 'province', 'image', 'current', 'paid_out', 'earn_cancel', 'earn', 'refund', 'tickets', 'paycheck_attachments')




class AdminTicketPaycheckValidateSerializer(serializers.ModelSerializer):

    uuid_gateway = serializers.CharField(write_only=True)
    pdf_confirm_payment = serializers.FileField(write_only=True)

    class Meta:
        model = OrderedTicket
        fields = ('uuid_gateway', 'pdf_confirm_payment')





class TicketValidateSerializer(serializers.ModelSerializer):

    uuid_ticket = serializers.UUIDField(write_only=True)

    class Meta:
        model = OrderedTicket
        fields = ('uuid_ticket', )