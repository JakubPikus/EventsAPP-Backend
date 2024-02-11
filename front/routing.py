from django.urls import re_path
from . import consumers


# websocket_urlpatterns = [
#     re_path(r'ws/chat/(?P<user_id>\d+)/(?P<recipient_id>\d+)/$',
#             consumers.ChatConsumer),
# ]

websocket_urlpatterns = [
    re_path(r'ws/(?P<user_id>\d+)/$',
            consumers.ConnectingConsumer),
]
