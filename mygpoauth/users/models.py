import re

from django.core.validators import RegexValidator
from django.contrib.auth.models import User
from django.utils.translation import ugettext_lazy as _


class UsernameValidator(RegexValidator):
    """ Custom validator for usernames """

    regex = r'^\w[\w.+-]*$'
    message = _(
        'Please use only English letters, ' 'numbers, and @/./+/-/_ characters.'
    )
    flags = re.ASCII


class CustomUser(User):
    """ User model which only accepts ASCII usernames """

    username_validator = UsernameValidator()

    class Meta:
        proxy = True
