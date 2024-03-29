from django.urls import path, include
#from .views import RegisterView, LoadUserView, LoginView, LogoutView, MyTokenRefreshView, AccountConfirmView, GenerateNewCodeConfirmView, PasswordResetView, PasswordResetConfirmView, LoginGoogleView, LoginFacebookView, CategoryActiveView, ProvinceView, CityView, EventsHomescreenView, ChangeUserLocationView, ChangeUserDistanceView, CheckUserLocationView, EventsListView, EventView, CommentEventView, CommentEventReactionView, CommentEventReportView, UserView, UserEventsView, UserParticipateView, EventParticipantsView, FriendRequestReactionView, FriendRequestView, FriendRemoveView, EventAddView, SeriesView, EventReportView, EventEditView, EventsViaSeriesView, EventsEditSeriesView, SeriesEditView, EventsViaCalendarView, EventsRandomView, EventsRandomReactionView, EventsProvinceMapView, EventsCountyMapView, FindFriendsView, EventsViaBadgesView, BadgeCodesLockedToExportView, BadgeCodesCreateView, BadgeCodesDeleteView, BadgeEditView, BadgeCreateView, BadgeDeleteView, UserBadgesView, BadgeActivateView, BadgeReportView, UserLoginLocationsView, UserBlockUsersView, LogoutFromDevicesView, LinkGoogleView, LinkFacebookView, PasswordChangeView, EmailChangeView, EmailChangeConfirmView, GenerateNewCodeEmailChangeView, AccountDeleteView, UserEditView, BadgesViaSettingsView, BadgeSetMainView, AdminLogsView, AdminLogsRefreshView, AdminReportsView, AdminEventReportedValidateView, AdminBadgeReportedValidateView, AdminPaychecksView, AdminCommentReportedValidateView, AdminAwaitingEventsView, AdminEventAwaitedValidateView, AdminBadgeAwaitedValidateView, AdminBanUsersIPView, AdminUserBanValidateView, AdminIPBanValidateView, AdminAccountsLogoutView, FriendsListView, LastMessagesListView, UserConversationView, WebsocketClearCookiesView, InvitationsListView, FindProfileByIdView, RefreshInvitationsAndNewMessagesIdsView, NotificationsListView, EventTicketsView, BankNumberView, BankNumberChangeView, EventsViaTicketsView, TicketEditView, TicketDeleteView, TicketPayView, TicketGeneratePDFView, TicketRefundView, OrderedTicketActionView, SoldTicketsViaCalendarView, AdminTicketAwaitedValidateView, AdminPaycheckGatewayView, AdminTicketPaycheckValidateView, AdminEventPaycheckValidateView, PaymentConfirmationPDFView, TicketValidateView
from .views import *
from .views.authorization import *
from .views.data import *
from .views.user import *
from .views.event import *
from .views.friends import *
from .views.series import *
from .views.calendar import *
from .views.map import *
from .views.randomizer import *
from .views.badge import *
from .views.settings import *
from .views.admin import *
from .views.websockets import *
from .views.ordering import *
from .init_models import InitModels
from . import views 

urlpatterns = [
    ##### AUTHORIZATION
    path('account/register', RegisterView.as_view()),  
    path('account/user', LoadUserView.as_view()),  
    path('account/login', LoginView.as_view()),  
    path('account/logout', LogoutView.as_view()),  
    path('token/refresh', MyTokenRefreshView.as_view()),  
    path('account/confirm', AccountConfirmView.as_view()),  
    path('account/generate_new_code', GenerateNewCodeConfirmView.as_view()),  
    path('account/password_reset', PasswordResetView.as_view()),  
    path('account/password_reset_confirm', PasswordResetConfirmView.as_view()),  
    path('account/login/google', LoginGoogleView.as_view()),  
    path('account/login/facebook', LoginFacebookView.as_view()),  

    ######## DATA
    path('category_active', CategoryActiveView.as_view()),
    path('provinces', ProvinceView.as_view()),
    path('cities', CityView.as_view()),
    path('events_homescreen', EventsHomescreenView.as_view()),

    ### USER
     path('user/<str:username>', UserView.as_view()),
    path('events_user', UserEventsView.as_view()),

    ### EVENT
     path('events_list', EventsListView.as_view()),  
    path('event/<slug:slug>-<uuid:uuid>', EventView.as_view()),  
    path('add_event', EventAddView.as_view()), 
    path('event/comment', CommentEventView.as_view()),  
    path('event/comment_reaction', CommentEventReactionView.as_view()),  
    path('event/comment_report', CommentEventReportView.as_view()),  
     path('user_participate', UserParticipateView.as_view()),  
    path('event_participants/<slug:slug>-<uuid:uuid>',  
         EventParticipantsView.as_view()),  
    path('event_report', EventReportView.as_view()), 
    path('edit_event', EventEditView.as_view()), 

    #### FRIENDS
     path('find_friends', FindFriendsView.as_view()), 
     path('friend/request', FriendRequestView.as_view()), 
    path('friend/request_reaction', FriendRequestReactionView.as_view()), 
    path('friend/remove', FriendRemoveView.as_view()), 

    #### SERIES
     path('series', SeriesView.as_view()),
     path('events_series', EventsViaSeriesView.as_view()),
    path('event_edit_series', EventsEditSeriesView.as_view()),
    path('edit_series', SeriesEditView.as_view()),

    #### CALENDAR
     path('events_calendar', EventsViaCalendarView.as_view()),

    ##### MAP
     path('province_map', EventsProvinceMapView.as_view()),
    path('county_map', EventsCountyMapView.as_view()),

    ##### RANDOMIZER
     path('events_random', EventsRandomView.as_view()),
    path('events_random_reaction', EventsRandomReactionView.as_view()),

    ##### BADGE
     path('events_badges', EventsViaBadgesView.as_view()), 
    path('badge_codes_lock', BadgeCodesLockedToExportView.as_view()), 
    path('badge_codes_create', BadgeCodesCreateView.as_view()),  
    path('badge_codes_delete', BadgeCodesDeleteView.as_view()),  
    path('badge_edit', BadgeEditView.as_view()),  
    path('badge_create', BadgeCreateView.as_view()),  
    path('badge_delete', BadgeDeleteView.as_view()),  
    path('user_badges', UserBadgesView.as_view()),  
    path('badge_activate', BadgeActivateView.as_view()),  
    path('badge_report', BadgeReportView.as_view()),  

    #######  SETTINGS
    path('change_user_location', ChangeUserLocationView.as_view()),  
    path('change_user_distance', ChangeUserDistanceView.as_view()),  
    path('check_user_location', CheckUserLocationView.as_view()),  
    path('user_validators', UserLoginLocationsView.as_view()),  
    path('user_block_users', UserBlockUsersView.as_view()),  
    path('logout_devices', LogoutFromDevicesView.as_view()),  
    path('account/link/google', LinkGoogleView.as_view()),  
    path('account/link/facebook', LinkFacebookView.as_view()),  
    path('account/password_change', PasswordChangeView.as_view()),  
    path('account/email_change', EmailChangeView.as_view()),  
    path('account/email_change_confirm', EmailChangeConfirmView.as_view()),  
    path('account/email_change_new_code',
         GenerateNewCodeEmailChangeView.as_view()),  
    path('account/account_delete', AccountDeleteView.as_view()),  
    path('account/account_edit', UserEditView.as_view()),  
    path('account/badges', BadgesViaSettingsView.as_view()),  
    path('account/set_main_badge', BadgeSetMainView.as_view()),  
     path('account/change_bank_number', BankNumberChangeView.as_view()),
    path('account/bank_number', BankNumberView.as_view()),

    ##### ADMINISTRATOR
    path('admin/logs', AdminLogsView.as_view()),
    path('admin/logs_refresh', AdminLogsRefreshView.as_view()),  
    path('admin/reports', AdminReportsView.as_view()),  
    path('admin/events/reports_action', AdminEventReportedValidateView.as_view()),  
    path('admin/badges/reports_action', AdminBadgeReportedValidateView.as_view()),  
    path('admin/comments/reports_action',
         AdminCommentReportedValidateView.as_view()),  
    path('admin/awaitings', AdminAwaitingEventsView.as_view()),  
    path('admin/events/awaitings_action',
         AdminEventAwaitedValidateView.as_view()),  
    path('admin/badges/awaitings_action',
         AdminBadgeAwaitedValidateView.as_view()),  
     path('admin/tickets/awaitings_action',
          AdminTicketAwaitedValidateView.as_view()),  
    path('admin/bans', AdminBanUsersIPView.as_view()),  
    path('admin/users/bans_action', AdminUserBanValidateView.as_view()),  
    path('admin/ips/bans_action', AdminIPBanValidateView.as_view()),  
    path('admin/accounts/logouts_action', AdminAccountsLogoutView.as_view()),  
     path('admin/paychecks', AdminPaychecksView.as_view()),  
     path('admin/open_gateway_paycheck', AdminPaycheckGatewayView.as_view()),  
     path('admin/tickets/paychecks_action', AdminTicketPaycheckValidateView.as_view()),  
     path('admin/events/paychecks_action', AdminEventPaycheckValidateView.as_view()),  

     #### WEBSOCKETS DATA
    path('account/friends', FriendsListView.as_view()), #
    path('account/last_messages', LastMessagesListView.as_view()), #
    path('account/messages', UserConversationView.as_view()), #
    path('account/clear_cookies', WebsocketClearCookiesView.as_view()), #
    path('account/invitations', InvitationsListView.as_view()), #
    path('account/find_user_by_id', FindProfileByIdView.as_view()), #
    path('account/refresh_ids', RefreshInvitationsAndNewMessagesIdsView.as_view()), #
    path('account/notifications', NotificationsListView.as_view()), #

     ### ORDERING
    path('tickets/<slug:slug>-<uuid:uuid>', EventTicketsView.as_view()), #
    path('payment', payment, name='stripe_payment'), #
    path('events_tickets', EventsViaTicketsView.as_view()), #
    path('ticket_edit', TicketEditView.as_view()), #
    path('ticket_delete', TicketDeleteView.as_view()), #
     path('ticket_pay', TicketPayView.as_view()), #
     path('ticket/generate/<int:id>', TicketGeneratePDFView.as_view()), #
     path('ticket_refund', TicketRefundView.as_view()), #
     path('order_action', OrderedTicketActionView.as_view()), #
     path('tickets_calendar', SoldTicketsViaCalendarView.as_view()), #
     path('payment_confirmation/<int:id>', PaymentConfirmationPDFView.as_view()),  #
     path('ticket_validate', TicketValidateView.as_view()), #

]

#InitModels()
