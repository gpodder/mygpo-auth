# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import mygpoauth.applications.models


class Migration(migrations.Migration):

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Application',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False,
                                        primary_key=True, auto_created=True)),
                ('name', models.CharField(max_length=128)),
                ('client_id', models.CharField(
                    default=mygpoauth.applications.models.random_token,
                    max_length=32)),
                ('client_secret',
                    models.CharField(default=mygpoauth.applications.
                                     models.random_token,
                                     max_length=32)),
            ],
        ),
    ]
