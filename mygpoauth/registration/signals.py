from django.db.models.signals import post_save
from django.dispatch import receiver
from ..users.models import CustomUser

from . import models


@receiver(post_save, sender=CustomUser)
def create_email_verification(sender, instance, created, **kwargs):
    """ Create EmailVerification objects for new users """

    if not created:
        return

    models.EmailVerification.objects.create(user=instance)
