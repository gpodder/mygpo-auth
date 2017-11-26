from django.apps import AppConfig


class RegistrationConfig(AppConfig):
    name = 'mygpoauth.registration'

    def ready(self):
        from . import signals  # pragma: no cover  # noqa
