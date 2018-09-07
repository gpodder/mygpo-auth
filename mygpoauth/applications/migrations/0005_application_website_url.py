# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [('applications', '0004_info_fields')]

    operations = [
        migrations.AddField(
            model_name='application',
            name='website_url',
            field=models.URLField(default=''),
            preserve_default=False,
        )
    ]
