# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('applications', '0002_apps'),
    ]

    operations = [
        migrations.AddField(
            model_name='application',
            name='logo',
            field=models.ImageField(default=None, upload_to='logos/'),
            preserve_default=False,
        ),
    ]
