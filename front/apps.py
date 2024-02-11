from django.apps import AppConfig
import os
import csv


class FrontConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'front'

    def ready(self):
        import front.signals
        import os
        if os.environ.get('RUN_MAIN', None) == 'true':
            from .scheduler import start_scheduler
            start_scheduler()
