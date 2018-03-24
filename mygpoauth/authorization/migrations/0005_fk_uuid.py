# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('authorization', '0004_fk_uuid'),
    ]

    operations = [
        migrations.AlterField(
            model_name='authorization',
            name='application',
            field=models.ForeignKey(to='applications.Application',
                                    on_delete=models.CASCADE),
        ),
    ]
