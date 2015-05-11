import uuid

from django.db import models
from django.conf import settings
from django.contrib.postgres.fields import ArrayField

from mygpoauth.applications.models import Application


class UpdateInfoModel(models.Model):

    created = models.DateTimeField(auto_now_add=True)

    modified = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class Authorization(UpdateInfoModel):
    """ An authorization for an app to a set of scopes granted by a user """

    user = models.ForeignKey(settings.AUTH_USER_MODEL)

    application = models.ForeignKey(Application)

    # max length is given by "app:" 32-digit ID
    scopes = ArrayField(models.CharField(max_length=36, blank=False))

    code = models.UUIDField(default=uuid.uuid4)
