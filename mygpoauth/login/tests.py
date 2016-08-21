import string
import random

from django.test import TestCase
from django.contrib.auth import authenticate

from ..users.models import CustomUser as User


class AuthenticationTests(TestCase):
    """ Provides test data for OAuth tests """

    def setUp(self):
        self.user = User.objects.create(
            username='UserName',
            email='user@example.com',
        )
        self.pwd = "".join(random.sample(string.ascii_letters, 8))
        self.user.set_password(self.pwd)
        self.user.save()

    def tearDown(self):
        self.user.delete()

    def test_case_insensitive_login(self):
        user = authenticate(username=self.user.username.lower(),
                            password=self.pwd)
        self.assertIsNotNone(user)

    def test_invalid_user(self):
        user = authenticate(username='invalid-user',
                            password='pwd')
        self.assertIsNone(user)

    def test_invalid_password(self):
        user = authenticate(username=self.user.username.lower(),
                            password='invalid-password')
        self.assertIsNone(user)
