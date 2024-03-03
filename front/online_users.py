import redis
import json
from ips_config import REDIS_HOST, REDIS_PORT


class OnlineUsers:
    REDIS_DB = 0
    PREFIX = 'online_users:'

    @classmethod
    def _get_connection(cls):
        return redis.StrictRedis(host=REDIS_HOST, port=REDIS_PORT, db=cls.REDIS_DB)

    @classmethod
    def add(cls, user_id, channel_name):
        connection = cls._get_connection()
        current_channels = connection.hget(cls.PREFIX, user_id)
        if current_channels:
            current_channels = json.loads(current_channels)
            if channel_name not in current_channels: 
                current_channels.append(channel_name)
        else:
            current_channels = [channel_name]
        connection.hset(cls.PREFIX, user_id, json.dumps(current_channels))

    @classmethod
    def remove(cls, user_id, channel_name):
        connection = cls._get_connection()
        current_channels = connection.hget(cls.PREFIX, user_id)
        if current_channels:
            current_channels = json.loads(current_channels)
            if channel_name in current_channels:  
                current_channels.remove(channel_name)
            if current_channels:
                connection.hset(cls.PREFIX, user_id,
                                json.dumps(current_channels))
            else:
                connection.hdel(cls.PREFIX, user_id)

    @classmethod
    def is_online(cls, user_id):
        connection = cls._get_connection()
        return bool(connection.hexists(cls.PREFIX, user_id))
