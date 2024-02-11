from decouple import config



DATABASE_HOST = config('DATABASE_HOST', default='localhost')
DATABASE_PORT = config('DATABASE_PORT', default='5432')
DATABASE_USER = config('DATABASE_USER', default='postgres')
DATABASE_PASSWORD = config('DATABASE_PASSWORD', default='12345678')
DATABASE_NAME = config('DATABASE_NAME', default='Inz2023.28')
DATABASE_URL = config('DATABASE_URL', default='postgresql://postgres:12345678@localhost:5432/Inz2023.28')


REDIS_HOST = config('REDIS_HOST', default='127.0.0.1')
REDIS_PORT = config('REDIS_PORT', default=6379)


BACKEND_IP = config('BACKEND_IP', default='https://127.0.0.1:8000')
FRONTEND_IP = config('BACKEND_IP', default='https://localhost:3000')
