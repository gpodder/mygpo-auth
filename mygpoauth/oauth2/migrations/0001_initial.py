# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import mygpoauth.oauth2.models
import uuid
import django.contrib.postgres.fields


class Migration(migrations.Migration):

    dependencies = [('authorization', '0002_unique_together')]

    operations = [
        migrations.CreateModel(
            name='AccessToken',
            fields=[
                (
                    'id',
                    models.AutoField(
                        serialize=False,
                        verbose_name='ID',
                        primary_key=True,
                        auto_created=True,
                    ),
                ),
                (
                    'scopes',
                    django.contrib.postgres.fields.ArrayField(
                        base_field=models.CharField(max_length=36), size=None
                    ),
                ),
                ('token', models.UUIDField(unique=True, default=uuid.uuid4)),
                ('created', models.DateTimeField(auto_now=True)),
                (
                    'expires',
                    models.DateTimeField(
                        db_index=True, default=mygpoauth.oauth2.models._default_expires
                    ),
                ),
                (
                    'authorization',
                    models.ForeignKey(
                        to='authorization.Authorization', on_delete=models.CASCADE
                    ),
                ),
            ],
        )
    ]
