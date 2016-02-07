# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('authorization', '0003_fk_uuid'),
    ]

    operations = [
        migrations.AlterUniqueTogether(
            name='authorization',
            unique_together=set([]),
        ),
        migrations.RemoveField(
            model_name='authorization',
            name='applicationold',
        ),
    ]
