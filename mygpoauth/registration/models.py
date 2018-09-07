import uuid

from django.db import models

from ..users.models import CustomUser


class EmailVerification(models.Model):
    """ Status of email verification

    Objects are created using signals after new users have been created """

    user = models.OneToOneField(
        CustomUser,
        on_delete=models.CASCADE,
        related_name='email_verification',
        primary_key=True,
    )

    # Token used to verify
    verification_token = models.UUIDField(
        unique=True, default=uuid.uuid4, editable=False
    )

    # Flag if verification has been completed
    is_verified = models.BooleanField(default=False)
