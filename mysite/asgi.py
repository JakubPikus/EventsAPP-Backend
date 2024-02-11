# """
# ASGI config for mysite project.

# It exposes the ASGI callable as a module-level variable named ``application``.

# For more information on this file, see
# https://docs.djangoproject.com/en/4.1/howto/deployment/asgi/
# """

# import os

# from django.core.asgi import get_asgi_application

# os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'mysite.settings')

# application = get_asgi_application()

###########################

# import os
# from django.core.asgi import get_asgi_application
# from channels.routing import ProtocolTypeRouter, URLRouter
# from front import routing  # Upewnij się, że wskazujesz na poprawny moduł routingu!

# os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'mysite.settings')

# application = ProtocolTypeRouter({
#     "http": get_asgi_application(),  # Django ASGI obsługuje protokół HTTP
#     # Django Channels obsługuje protokół WebSocket
#     "websocket": URLRouter(routing.websocket_urlpatterns)
# })


# #######


from front import routing
from channels.routing import ProtocolTypeRouter, URLRouter
from django.core.asgi import get_asgi_application
# import django
import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'mysite.settings')
# django.setup()


application = ProtocolTypeRouter({
    "http": get_asgi_application(),  # Django ASGI obsługuje protokół HTTP
    # Django Channels obsługuje protokół WebSocket
    "websocket": URLRouter(routing.websocket_urlpatterns),
})



