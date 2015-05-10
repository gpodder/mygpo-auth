import random
import string

from django.db import models
from django.contrib.postgres.fields import ArrayField


def random_token(length=32):
    return "".join(random.sample(string.ascii_letters+string.digits, length))


class Application(models.Model):
    """ A client application """
    name = models.CharField(max_length=128)
    client_id = models.CharField(max_length=32, default=random_token,
                                 unique=True)
    client_secret = models.CharField(max_length=32, default=random_token)
    redirect_url = models.URLField()

    def __str__(self):
        return self.name
