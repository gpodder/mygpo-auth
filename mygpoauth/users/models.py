from django.contrib.auth.models import User
from django.contrib.auth.validators import ASCIIUsernameValidator


class CustomUser(User):
    """ User model which only accepts ASCII usernames """

    username_validator = ASCIIUsernameValidator()

    class Meta:
        proxy = True
