# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('applications', '0003_application_logo'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='application',
            name='logo',
        ),
        migrations.AddField(
            model_name='application',
            name='description',
            field=models.TextField(default=''),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='application',
            name='logo_url',
            field=models.URLField(default=''),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='application',
            name='platform',
            field=models.CharField(max_length=128, default=''),
            preserve_default=False,
        ),
    ]
