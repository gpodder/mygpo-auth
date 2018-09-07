import random
import string
import uuid

from django.db import models
from django.contrib.postgres.fields import ArrayField


def random_token(length=32):
    return "".join(random.sample(string.ascii_letters + string.digits, length))


class Application(models.Model):
    """ A client application """

    # primary key
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # a human-readable name of the application
    name = models.CharField(max_length=128)

    # description of the app
    description = models.TextField()

    # platform(s) on which the application is running
    platform = models.CharField(max_length=128)

    # the client_id for OAuth 2
    client_id = models.CharField(
        max_length=32, default=random_token, unique=True
    )

    # the client_secret for OAuth 2
    client_secret = models.CharField(max_length=32, default=random_token)

    # the redirect_url for OAuth 2
    redirect_url = models.URLField()

    # URL of the application's logo
    logo_url = models.URLField()

    # URL of the app's website
    website_url = models.URLField()

    def __str__(self):
        return self.name
