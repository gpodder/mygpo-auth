# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import uuid
import django.contrib.postgres.fields
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        ('applications', '0002_apps'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Authorization',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True,
                                        serialize=False, verbose_name='ID')),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('modified', models.DateTimeField(auto_now=True)),
                ('scopes', django.contrib.postgres.fields.ArrayField(
                    base_field=models.CharField(max_length=36), size=None)),
                ('code', models.UUIDField(default=uuid.uuid4)),
                ('application', models.ForeignKey(
                    to='applications.Application', on_delete=models.CASCADE)),
                ('user', models.ForeignKey(to=settings.AUTH_USER_MODEL,
                                           on_delete=models.CASCADE)),
            ],
            options={
                'abstract': False,
            },
        ),
    ]
