# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import mygpoauth.applications.models


class Migration(migrations.Migration):

    dependencies = [
        ('applications', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='application',
            name='redirect_url',
            field=models.URLField(default=''),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name='application',
            name='client_id',
            field=models.CharField(max_length=32, unique=True,
                                   default=mygpoauth.applications.models.
                                   random_token),
        ),
    ]
