
from channels.generic.websocket import AsyncJsonWebsocketConsumer
import json
from .online_users import OnlineUsers
import asyncio
from channels.layers import get_channel_layer
from channels.db import database_sync_to_async
import re


def get_tokens(data):
    headers = dict(data)

    cookies = headers.get(b'cookie', b'').decode('utf-8')
    match_access_token = re.search(r'access=([^;]*)', cookies)
    match_refresh_token = re.search(r'refresh=([^;]*)', cookies)

    if match_access_token:
        access_token = match_access_token.group(1)
    else:
        access_token = None

    if match_refresh_token:
        refresh_token = match_refresh_token.group(1)
    else:
        refresh_token = None

    return access_token, refresh_token


def verify_token(access_token):
    from rest_framework_simplejwt.authentication import JWTAuthentication
    from rest_framework_simplejwt.exceptions import InvalidToken

    jwt_auth_instance = JWTAuthentication()
    try:
        decoded_token = jwt_auth_instance.get_validated_token(access_token)
    except InvalidToken as e:
        return False

    return decoded_token.payload['exp']


@database_sync_to_async
def check_banned_status(user_id, ip_address):
    from .models import MyUser, IPAddress, IPAddressValidator

    if MyUser.objects.filter(id=user_id).exists():

        user = MyUser.objects.get(id=user_id)

        if IPAddress.objects.filter(ip_address=ip_address).exists():

            ip_address_obj = IPAddress.objects.get(
                ip_address=ip_address)

            if ip_address_obj.is_banned:
                return {
                    "type": "ipaddress_banned",
                    "detail": "Zostałeś wylogowany",
                    "code": "421"
                }

            elif user.is_banned:
                return {
                    "type": "user_banned",
                    "detail": "Zostałeś wylogowany",
                    "code": "422"
                }

            if IPAddressValidator.objects.filter(user=user, ip_address=ip_address_obj).exists():
                ip_validator = IPAddressValidator.objects.get(
                    user=user, ip_address=ip_address_obj)

                if ip_validator.is_verificated == False:
                    return {
                        "type": "logout",
                        "detail": "Zostałeś wylogowany z konta",
                        "code": "420"
                    }

            else:
                return {
                    "type": "logout",
                    "detail": "Administracja usunęła twoją validację do konta",
                    "code": "420"
                }
        else:
            return {
                "type": "ipaddress_deleted",
                "detail": "Administracja usunęła twój Adres IP",
                "code": "424"
            }
    else:
        return {
            "type": "user_deleted",
            "detail": "Użytkownik został usunięty",
            "code": "423"
        }


class ConnectingConsumer(AsyncJsonWebsocketConsumer):

    async def connect(self):
        import time
        from .models import ActiveMessage
        self.user_id = self.scope['url_route']['kwargs']['user_id']
        self.ip_address = self.scope['client'][0]

        access_token, refresh_token = get_tokens(self.scope['headers'])

        response = verify_token(access_token)

        await self.channel_layer.group_add(
            self.user_id,
            self.channel_name
        )

        await self.accept()

        if not response:  # 2) PRZYPADEK GDY TOKEN JEST NIEPOPRAWNY -> WYLOGOWANIE

            self.token_expiry = None

            await self.channel_layer.group_send(
                self.user_id,
                {
                    'type': 'notvalid_access_token',

                }
            )
            return

        elif refresh_token == None and (int(time.time()) > response or access_token == None):

            self.token_expiry = None
            await self.channel_layer.group_send(
                self.user_id,
                {
                    'type': 'tokens_not_found',


                }
            )
            return

        # 2) PRZYPADEK GDY WYKRYTY TOKEN JEST TEN SAM -> NASTEPUJE ROZLACZENIE I PRZEKAZANIE DO REACTA WYMUSZENIE AKCJI ODNOWY
        elif int(time.time()) > response or access_token == None:

            self.token_expiry = 'token_refresh'

        else:        # 2) PRZYPADEK GDY TOKEN JEST PRAWIDŁOWY, NASTĘPUJE PRZYPISANIE TOKENU

            self.token_expiry = response

            OnlineUsers.add(self.user_id, self.channel_name)

        senders_ids = await ActiveMessage.login_set_delivered(self.user_id)
        online_senders = [
            str(sender_id) for sender_id in senders_ids if OnlineUsers.is_online(sender_id)]

        for online_user_id in online_senders:
            await self.channel_layer.group_send(
                online_user_id,
                {
                    'type': 'messages_delivered',
                    'user': self.user_id
                }
            )

    async def disconnect(self, close_code):
        OnlineUsers.remove(self.user_id, self.channel_name)

        await self.channel_layer.group_discard(
            self.user_id,
            self.channel_name
        )


    async def receive(self, text_data):
        import time

        text_data_json = json.loads(text_data)
        event_type = text_data_json.get('event_type')

        # 1) SYTUACJA GDY WYKONUJEMY JAKAS AKCJE A SIE OKAZE ZE TOKEN JEST STARY

        if self.token_expiry == 'token_refresh':

            await self.channel_layer.group_send(
                self.user_id,
                {
                    'type': 'token_refresh',
                    'previous_action': text_data_json,


                }
            )
            return

        elif self.token_expiry != None and int(time.time()) > self.token_expiry:

            await self.channel_layer.group_send(
                self.user_id,
                {
                    'type': 'token_expired',
                    'previous_action': text_data_json,

                }
            )
            return
        else:
            if event_type == 'chat_message':
                await self.handle_chat_message(text_data_json)

            elif event_type == 'online_friends':
                await self.handle_online_friends()

            elif event_type == 'invite_friend':
                await self.handle_invite_friend(text_data_json)

            elif event_type == 'notifications_seen':
                await self.handle_notifications_seen()








                


# ------------------------- WIADOMOSCI --------------------------------


# ODEBRANIE WIADOMOSCI OD NADAWCY I WYSLANIE DO NIEGO ODPOWIEDZI CZY WIADOMOSC WYSLANA (GDY ODBIORCA OFFLINE), CZY WIADOMOSC DOSTARCZONA (GDY ODBIORCA ONLINE)

    async def handle_chat_message(self, data):
        from .models import ActiveMessage, MyUser

        content = data['content']
        recipient_id = str(data['recipient_id'])
        temp_message_id = data['temp_message_id']

        # PRZED WYSLANIEM WIADOMOSCI MUSIMY SPRAWDZIC, CZY NASZ TARGET USER NAS NIE ZABLOKOWAL, ALBO MY GO NIE ZABLOKOWALISMY + ZWROCIC INFORMACJE O NIEPOWODZENIU WYSLANIA WIADOMOSCI I PRZYPISAC MU ODPOWIEDNI STAN PO FRONCIE

        blocked_by_target_user, block_target_user, target_user_exists = await MyUser.check_blocked_status(self.user_id, recipient_id)

        if not target_user_exists:

            await self.channel_layer.group_send(
                self.user_id,
                {
                    'type': 'target_user_deleted',
                    'user_id': recipient_id,


                }
            )

        elif blocked_by_target_user == True or block_target_user == True:

            await self.channel_layer.group_send(
                self.user_id,
                {
                    'type': 'blocked',
                    'temp_message_id': temp_message_id,
                    'to_user_id': recipient_id,
                    'blocked_by_target_user': blocked_by_target_user,
                    'block_target_user': block_target_user,


                }
            )

        elif OnlineUsers.is_online(recipient_id):
            message_id, timestamp, is_friend, username_recipient, image_thumbnail_recipient, username_sender, image_thumbnail_sender = await ActiveMessage.save_message(content, self.user_id, recipient_id, True)
            timestamp_str = timestamp.isoformat()

            

            await self.channel_layer.group_send(
                recipient_id,
                {
                    'type': 'chat_message',
                    'message_id': message_id,
                    'timestamp': timestamp_str,
                    'content': content,
                    'from_user_id': self.user_id,
                    'to_user_id': recipient_id,
                    'from_user_username': username_sender,
                    'from_user_image_thumbnail': image_thumbnail_sender,
                    'is_friend': is_friend


                }
            )

            await self.channel_layer.group_send(
                self.user_id,
                {
                    'type': 'chat_message',
                    'message_id': message_id,
                    'temp_message_id': temp_message_id,
                    'timestamp': timestamp_str,
                    'status': 'is_delivered',
                    'content': content,
                    'from_user_id': self.user_id,
                    'to_user_id': recipient_id,
                    'to_user_username': username_recipient,
                    'to_user_image_thumbnail': image_thumbnail_recipient,
                    'is_friend': is_friend
                }
            )
        else:
            message_id, timestamp, is_friend, username_recipient, image_thumbnail_recipient = await ActiveMessage.save_message(content, self.user_id, recipient_id, False)
            timestamp_str = timestamp.isoformat()

            await self.channel_layer.group_send(
                self.user_id,
                {
                    'type': 'chat_message',
                    'message_id': message_id,
                    'temp_message_id': temp_message_id,
                    'timestamp': timestamp_str,
                    'status': 'is_send',
                    'content': content,
                    'from_user_id': self.user_id,
                    'to_user_id': recipient_id,
                    'to_user_username': username_recipient,
                    'to_user_image_thumbnail': image_thumbnail_recipient,
                    'is_friend': is_friend
                }
            )

    async def chat_message(self, event):

        if event['from_user_id'] == self.user_id:
            await self.send(text_data=json.dumps({
                'event_type': 'acknowledge',
                'temp_message_id': event['temp_message_id'],
                'user': {
                    'id': event['to_user_id'],
                    'username': event['to_user_username'],
                    'image_thumbnail': event['to_user_image_thumbnail'],
                    'is_friend': event['is_friend']

                },
                'message': {
                    'author': event['from_user_id'],
                    'message_id': event['message_id'],
                    'status': event['status'],
                    'content': event['content'],
                    'timestamp': event['timestamp'],
                    
                }


            }))
            return

        await self.send(text_data=json.dumps({

            'event_type': 'message',
            'user': {
                'id': event['from_user_id'],
                'username': event['from_user_username'],
                'image_thumbnail': event['from_user_image_thumbnail'],
                'is_friend': event['is_friend']
            },
            'message': {
                'author': event['from_user_id'],
                'message_id': event['message_id'],
                'status': 'is_delivered',
                'content': event['content'],
                'timestamp': event['timestamp']
            },
        }))

    async def messages_delivered(self, event):

        await self.send(text_data=json.dumps({

            'event_type': 'delivered',
            'user': event['user']
        }))


# INFORMOWANIE UZYTKOWNIKA O SWOICH ZNAJOMYCH ONLINE

    async def handle_online_friends(self):
        from .models import MyUser

        response_banned = await check_banned_status(self.user_id, self.ip_address)
        if response_banned is not None:
            await self.channel_layer.group_send(
                self.user_id,
                {
                    'type': 'banned',
                    'data': response_banned
                }
            )
            return

        my_friends = await MyUser.get_friends(self.user_id)

        if my_friends == None:
            online_friends = []

        else:
            online_friends = [
                my_friend for my_friend in my_friends if OnlineUsers.is_online(my_friend)]

        await self.channel_layer.group_send(
            self.user_id,
            {
                'type': 'online_friends',
                'online_friends': online_friends
            }
        )

    async def online_friends(self, event):

        await self.send(text_data=json.dumps({

            'event_type': 'online_friends',
            'online_friends': event['online_friends']
        }))


# INFORMOWANIE UZYTKOWNIKA O DOSTANIU ZAPROSZENIA

    async def handle_invite_friend(self, data):
        target_id = str(data['target_id'])

        if OnlineUsers.is_online(target_id):
            from .models import Friendship_Request

            username, image_thumbnail, created_at = await Friendship_Request.user_data(self.user_id, target_id)
            created_at_str = created_at.isoformat()

            await self.channel_layer.group_send(
                target_id,
                {
                    'type': 'invite_friend',
                    'from_user_id': self.user_id,
                    'username': username,
                    'image_thumbnail': image_thumbnail,
                    'created_at': created_at_str,

                }
            )

    async def invite_friend(self, event):

        await self.send(text_data=json.dumps({

            'event_type': 'get_invite',
            'user': {
                'id': event['from_user_id'],
                'username': event['username'],
                'image_thumbnail': event['image_thumbnail'],
                'created_at': event['created_at'],

            }

        }))


        

# ZMIANA FLAG POWIADOMIEN W BAZIE NA "ZOBACZONE"

    async def handle_notifications_seen(self):
        from .models import NotificationsForUser

        await NotificationsForUser.set_notifications_seen(self.user_id)

        
        


# INFORMACJA O PRZEDAWNIENIU TOKENA

    async def token_expired(self, event):

        await self.send(text_data=json.dumps({

            'event_type': 'token_expired',
            'previous_action': event['previous_action']
        }))

        await self.close()


# INFORMACJA O WYMUSZENIU ODSWIEZENIA TOKENA

    async def token_refresh(self, event):

        await self.send(text_data=json.dumps({

            'event_type': 'token_refresh',
            'previous_action': event['previous_action']
        }))
        await self.close()


# INFORMACJA O BLEDNYM ACCESSTOKENIE

    async def notvalid_access_token(self, event):

        await self.send(text_data=json.dumps({

            'event_type': 'notvalid_access_token',
        }))
        await self.close()


# INFORMACJA O BRAKU TOKENOW

    async def tokens_not_found(self, event):

        await self.send(text_data=json.dumps({

            'event_type': 'tokens_not_found',
        }))
        await self.close()


# INFORMACJA O ZBANOWANIU/WYLOGOWANIU UZYTKOWNIKA

    async def banned(self, event):

        await self.send(text_data=json.dumps({

            'event_type': 'banned',
            'data': event['data']
        }))
        await self.close()


# INFORMACJA O ZABLOKOWANIU USERA / ZOSTANIEM ZABLOKOWANYM PRZEZ USERA PODCZAS PRÓBY WYSLANIA WIADOMOSCI

    async def blocked(self, event):

        await self.send(text_data=json.dumps({

            'event_type': 'blocked',
            'room_user_id': event['to_user_id'],
            'temp_message_id': event['temp_message_id'],
            'status': 'not_send',
            'blocked_by_target_user': event['blocked_by_target_user'],
            'block_target_user': event['block_target_user'],

        }))


# INFORMOWANIE UZYTKOWNIKA O USUNIĘCIE KONTA PRZEZ TARGET_USER


    async def target_user_deleted(self, event):

        await self.send(text_data=json.dumps({

            'event_type': 'target_user_deleted',
            'user_id': event['user_id']


        }))



# WYSYLANIE POWIADOMIENIA DO UZYTKOWNIKA


    async def send_notification(self, event):

        await self.send(text_data=json.dumps({

            'event_type': 'get_notification',
            'notification': event['notification']


        }))
