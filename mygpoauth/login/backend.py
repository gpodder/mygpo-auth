from django.contrib.auth.backends import ModelBackend

from ..users.models import CustomUser as User


class CaseInsensitiveModelBackend(ModelBackend):
    """ Authenticates with a case-insensitive username """

    def authenticate(self, request, username=None, password=None, **kwargs):
        try:
            user = User.objects.get(username__iexact=username)
            if user.check_password(password):
                return user

        except User.DoesNotExist:
            # Run the default password hasher once to reduce the timing
            # difference between an existing and a non-existing user (#20760).
            User().set_password(password)
