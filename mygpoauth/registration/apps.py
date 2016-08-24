from django.apps import AppConfig


class RegistrationConfig(AppConfig):
    name = 'registration'

    def ready(self):
        from . import signals  # pragma: no cover  # noqa
