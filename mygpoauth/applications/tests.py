from imp import reload
from django.test import TestCase
from django.db import IntegrityError

from mygpoauth.applications import models


class Applications(TestCase):
    def test_unique_client_id(self):
        app1 = models.Application.objects.create(name='app1', client_id='app')

        with self.assertRaises(IntegrityError):
            app2 = models.Application.objects.create(
                name='app2', client_id='app'
            )

    def test_str(self):
        app1 = models.Application.objects.create(name='app1', client_id='app')

        self.assertEqual(str(app1), app1.name)
