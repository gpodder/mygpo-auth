# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


def set_uuids(apps, schema_editor):
    # We get the model from the versioned app registry;
    # if we directly import it, it'll be the wrong version
    Authorization = apps.get_model("authorization", "Authorization")
    Application = apps.get_model("applications", "Application")

    auths = Authorization.objects.all()
    for auth in auths:
        auth.application = auth.applicationold.uuid
        auth.save()


class Migration(migrations.Migration):

    dependencies = [
        ('authorization', '0002_unique_together'),
        ('applications', '0006_uuid'),
    ]

    operations = [
        migrations.RenameField(
            model_name='authorization',
            old_name='application',
            new_name='applicationold',
        ),
        migrations.AddField(
            model_name='authorization',
            name='application',
            field=models.UUIDField(default=None, null=True),
        ),
        migrations.RunPython(set_uuids),
    ]
