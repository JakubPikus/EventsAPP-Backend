import redis
import json
from ips_config import REDIS_HOST, REDIS_PORT


class OnlineUsers:


    REDIS_DB = 0

    PREFIX = 'online_users:'

    @classmethod
    def _get_connection(cls):
        """Zwraca połączenie z Redis."""
        return redis.StrictRedis(host=REDIS_HOST, port=REDIS_PORT, db=cls.REDIS_DB)

    @classmethod
    def add(cls, user_id, channel_name):
        """Dodaje użytkownika do zbioru online."""
        connection = cls._get_connection()
        current_channels = connection.hget(cls.PREFIX, user_id)
        if current_channels:
            current_channels = json.loads(current_channels)
            if channel_name not in current_channels:  # JA JUZ TUTAJ MAM SPRAWDZANIE CZY DANY KLUCZ ISTNIEJE
                current_channels.append(channel_name)
        else:
            current_channels = [channel_name]
        connection.hset(cls.PREFIX, user_id, json.dumps(current_channels))
        # connection.expire(cls.PREFIX + user_id, 300)

    @classmethod
    def remove(cls, user_id, channel_name):
        """Usuwa kanał użytkownika."""
        connection = cls._get_connection()
        current_channels = connection.hget(cls.PREFIX, user_id)
        if current_channels:
            current_channels = json.loads(current_channels)
            if channel_name in current_channels:  # JA JUZ TUTAJ MAM SPRAWDZANIE
                current_channels.remove(channel_name)
            if current_channels:
                connection.hset(cls.PREFIX, user_id,
                                json.dumps(current_channels))
            else:
                connection.hdel(cls.PREFIX, user_id)

    @classmethod
    def is_online(cls, user_id):
        """Sprawdza, czy użytkownik jest online."""
        connection = cls._get_connection()
        return bool(connection.hexists(cls.PREFIX, user_id))
