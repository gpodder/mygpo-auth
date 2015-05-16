import uuid

from django.db import models
from django.conf import settings
from django.utils import timezone
from django.contrib.postgres.fields import ArrayField

from mygpoauth.authorization.models import Authorization


def _default_expires():
    return timezone.now() + settings.DEFAULT_TOKEN_EXPIRATION


class AccessToken(models.Model):
    """ A token that an Application can use to access protected resources """

    # the authorization on which the token is based
    authorization = models.ForeignKey(Authorization)

    # the authorized scopes; max length is given by "app:" 32-digit ID
    scopes = ArrayField(models.CharField(max_length=36, blank=False))

    # the string to identify this token
    token = models.UUIDField(unique=True, default=uuid.uuid4)

    # the timestamp at which the token has been created
    created = models.DateTimeField(auto_now=True)

    # the timestamp at which the token expires
    expires = models.DateTimeField(default=_default_expires, db_index=True)
