from django.contrib import admin
from front.models import *
from django import forms
from django.contrib.auth.forms import ReadOnlyPasswordHashField
from django.core.exceptions import ValidationError
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.models import Group
from django.contrib import admin
from django.utils.translation import gettext_lazy as _


class UserCreationForm(forms.ModelForm):
    password1 = forms.CharField(label='Password', widget=forms.PasswordInput)
    password2 = forms.CharField(
        label='Password confirmation', widget=forms.PasswordInput)

    class Meta:
        model = MyUser
        fields = ('username', 'email', 'first_name', 'last_name', 'city')

    def clean_password2(self):
        password1 = self.cleaned_data.get("password1")
        password2 = self.cleaned_data.get("password2")
        if password1 and password2 and password1 != password2:
            raise ValidationError("Hasła nie pasują")
        return password2

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password1"])
        if commit:
            user.save()
        return user


class UserChangeForm(forms.ModelForm):
    password = ReadOnlyPasswordHashField()

    class Meta:
        model = MyUser
        fields = ('username', 'email', 'password', 'is_active', 'is_admin')


class UserAdmin(BaseUserAdmin):
    form = UserChangeForm
    add_form = UserCreationForm

    # MENU GLOWNE
    list_display = ('username', 'email', 'is_admin')
    list_filter = ('is_admin',)

    fieldsets = (
        ('Dane użytkownika', {'fields': ('username',
         'email', 'password', 'first_name', 'last_name', 'city', 'image', 'image_thumbnail', 'friends', 'blocked_users', 'take_part_events', 'visited_events', 'activated_badges', 'main_badge', 'distance', 'count_reported_events', 'count_reported_badges', 'count_reported_comments', 'count_deleted_events', 'count_deleted_badges', 'count_deleted_comments', 'bank_number')}),
        ('Permissions', {
         'fields': ('is_admin', 'is_active', 'is_verificated', 'is_banned')}),
    )

    # 'count_deleted_events', 'count_deleted_badges', 'count_deleted_comments

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'email', 'password1', 'password2', 'first_name', 'last_name', 'city'),
        }),
        ('Permissions', {
         'fields': ('is_admin', 'is_active', 'is_verificated')}),
    )
    search_fields = ('username',)
    ordering = ('username',)
    filter_horizontal = ()


class CustomOutstandingTokenAdmin(admin.ModelAdmin):
    list_display = (
        "jti",
        "user",
        "created_at",
        "expires_at",
    )
    search_fields = (
        "user__id",
        "jti",
    )
    ordering = ("user",)

    def get_queryset(self, *args, **kwargs):
        qs = super().get_queryset(*args, **kwargs)

        return qs.select_related("user")

    # Read-only behavior defined below
    actions = None

    def get_readonly_fields(self, *args, **kwargs):
        return [f.name for f in self.model._meta.fields]

    def has_add_permission(self, *args, **kwargs):
        return False

    def has_delete_permission(self, *args, **kwargs):
        return False

    def has_change_permission(self, request, obj=None):
        return request.method in ["GET", "HEAD"] and super().has_change_permission(
            request, obj
        )


admin.site.register(CustomOutstandingToken, CustomOutstandingTokenAdmin)


class CustomBlacklistedTokenAdmin(admin.ModelAdmin):
    list_display = (
        "token_jti",
        "token_user",
        "token_created_at",
        "token_expires_at",
        "blacklisted_at",
    )
    search_fields = (
        "token__user__id",
        "token__jti",
    )
    ordering = ("token__user",)

    def get_queryset(self, *args, **kwargs):
        qs = super().get_queryset(*args, **kwargs)

        return qs.select_related("token__user")

    def token_jti(self, obj):
        return obj.token.jti

    token_jti.short_description = _("jti")
    token_jti.admin_order_field = "token__jti"

    def token_user(self, obj):
        return obj.token.user

    token_user.short_description = _("user")
    token_user.admin_order_field = "token__user"

    def token_created_at(self, obj):
        return obj.token.created_at

    token_created_at.short_description = _("created at")
    token_created_at.admin_order_field = "token__created_at"

    def token_expires_at(self, obj):
        return obj.token.expires_at

    token_expires_at.short_description = _("expires at")
    token_expires_at.admin_order_field = "token__expires_at"


class OrderAdmin(admin.ModelAdmin):
    list_display = ('user', 'stripe_payment_intent_id', 'created_at_formatted','stripe_created_at_formatted', 'next_try_at_formatted', 'order_expires_at_formatted', 'paid_time', 'is_paid')
    readonly_fields = ('user', 'stripe_payment_intent_id', 'checkout_payment_intent_id', 'created_at_formatted','stripe_created_at_formatted','next_try_at_formatted', 'order_expires_at_formatted')

    def created_at_formatted(self, obj):
        return obj.created_at.strftime("%Y-%m-%d %H:%M")

    def stripe_created_at_formatted(self, obj):
        return obj.stripe_created_at.strftime("%Y-%m-%d %H:%M")
    

    def order_expires_at_formatted(self, obj):
        return obj.order_expires_at.strftime("%Y-%m-%d %H:%M")
    
    def next_try_at_formatted(self, obj):
        return obj.next_try_at.strftime("%Y-%m-%d %H:%M")







class OrderedTicketAdmin(admin.ModelAdmin):
    list_display = ('order', 'ticket', 'purchase_price', 'first_name', 'last_name', 'date_of_birth', 'code', 'qr_code', 'used', 'refunded', 'used_time')
    readonly_fields = ('order', 'ticket', 'purchase_price')




admin.site.register(CustomBlacklistedToken, CustomBlacklistedTokenAdmin)
admin.site.register(MyUser, UserAdmin)
admin.site.register(Order, OrderAdmin)
admin.site.register(AwaitingsTicketsRefund)
admin.site.register(GatewayPaycheck)
admin.site.register(Paycheck)
admin.site.register(OrderedTicket, OrderedTicketAdmin)
admin.site.register(Ticket)
admin.site.register(DeleteModel)
admin.site.register(Notification)
admin.site.register(NotificationsForUser)
admin.site.register(ActiveMessage)
admin.site.register(AdminLog)
admin.site.register(ChangeEmailWaiting)
admin.site.register(Friendship_Request)
admin.site.register(Series)
admin.site.register(EventImage)
admin.site.register(CommentEvent)
admin.site.register(CommentEventReport)
admin.site.register(CommentEventReaction)
admin.site.register(GmailUser)
admin.site.register(FacebookUser)
admin.site.register(CodeRegistration)
admin.site.register(IPAddressValidator)
admin.site.register(IPAddress)
admin.site.register(Event)
admin.site.register(EventReport)
admin.site.register(Category)
admin.site.register(Province)
admin.site.register(County)
admin.site.register(City)
admin.site.register(Badge)
admin.site.register(BadgeCode)
admin.site.register(BadgeReport)
admin.site.unregister(Group)
