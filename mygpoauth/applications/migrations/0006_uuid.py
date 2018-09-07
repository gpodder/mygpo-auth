# -*- coding: utf-8 -*-
# Generated by Django 1.9.1 on 2016-02-07 18:25
from __future__ import unicode_literals

from django.db import migrations, models
import uuid


class Migration(migrations.Migration):

    dependencies = [('applications', '0005_application_website_url')]

    operations = [
        migrations.AddField(
            model_name='application',
            name='uuid',
            field=models.UUIDField(
                default=uuid.uuid4, editable=False, serialize=False
            ),
        ),
        #        migrations.AlterField(
        #            model_name='application',
        #           name='id',
        #            field=models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False),
        #        ),
    ]
