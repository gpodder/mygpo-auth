import re
from urllib.parse import urlsplit

from django.test import TestCase, Client, override_settings
from django.core import mail
from django.urls import resolve, reverse

from ..users.models import CustomUser as User
from mygpoauth.applications.models import Application


class RegistrationTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.app = Application.objects.create(
            name='Test App',
            client_id='test_app',
            website_url='http://www.app.com/',
        )

    def tearDown(self):
        User.objects.all().delete()
        self.app.delete()

    def test_access_default_registration_page(self):
        url = reverse('registration:register-default')
        with override_settings(DEFAULT_CLIENT_ID=self.app.client_id):
            response = self.client.get(url)
            self.assertEqual(
                response['Location'], '/register/app/' + self.app.client_id
            )

    def test_access_registration_page(self):
        url = reverse('registration:register', args=[self.app.client_id])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

    def test_register(self):
        url = reverse('registration:register', args=[self.app.client_id])
        response = self.client.post(
            url,
            {
                'username': 'john',
                'email': 'john@example.com',
                'password': 'smith',
                'client_id': self.app.client_id,
            },
            follow=False,
        )

        # successful registration redirects to website url
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response['Location'], self.app.website_url)

    def test_invalid_form(self):
        url = reverse('registration:register', args=[self.app.client_id])
        response = self.client.post(
            url,
            {
                'username': 'john',
                'email': 'this-is-not-an-email-address',
                'password': 'smith',
                'client_id': self.app.client_id,
            },
            follow=False,
        )

        # registration form is shown again
        self.assertEqual(response.status_code, 400)

    def test_duplicate_case_insensitive_username(self):
        url = reverse('registration:register', args=[self.app.client_id])
        response = self.client.post(
            url,
            {
                'username': 'john',
                'email': 'john@example.com',
                'password': 'smith',
                'client_id': self.app.client_id,
            },
            follow=False,
        )

        # successful registration redirects to website url
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response['Location'], self.app.website_url)

        response = self.client.post(
            url,
            {
                'username': 'JOHN',
                'email': 'john@example.com',
                'password': 'smith',
                'client_id': self.app.client_id,
            },
            follow=False,
        )

        # duplicate username
        self.assertEqual(response.status_code, 400)

    def test_non_ascii_username_fails(self):
        url = reverse('registration:register', args=[self.app.client_id])
        response = self.client.post(
            url,
            {
                'username': 'äüßé',
                'email': 'test@example.com',
                'password': 'smith',
                'client_id': self.app.client_id,
            },
            follow=False,
        )

        # registration form is shown again
        self.assertEqual(response.status_code, 400)

    def test_email_as_username_fails(self):
        url = reverse('registration:register', args=[self.app.client_id])
        response = self.client.post(
            url,
            {
                'username': 'test@example.com',
                'email': 'test@example.com',
                'password': 'smith',
                'client_id': self.app.client_id,
            },
            follow=False,
        )

        # registration form is shown again
        self.assertEqual(response.status_code, 400)

    def test_email_verification_email(self):
        """ Test that verification email is sent, and that the link works """

        url = reverse('registration:register', args=[self.app.client_id])
        response = self.client.post(
            url,
            {
                'username': 'john',
                'email': 'john@example.com',
                'password': 'smith',
                'client_id': self.app.client_id,
            },
            follow=False,
        )

        # successful registration redirects to website url
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response['Location'], self.app.website_url)

        # Test that one message has been sent.
        self.assertEqual(len(mail.outbox), 1)

        msg = mail.outbox[0]

        # find all URLs
        urls = re.findall(r'https?://.+\b', msg.body)
        rel_urls = [urlsplit(url).path for url in urls]
        url_names = [resolve(rel_url).url_name for rel_url in rel_urls]

        # find the verification URL(s), and make sure there was only one
        verify_urls = [
            url
            for (url, name) in zip(rel_urls, url_names)
            if name == 'verify-email'
        ]
        self.assertEqual(len(verify_urls), 1)

        # verify email address
        self.client.get(verify_urls[0])

        # TODO: verify verification
        user = User.objects.get(username='john')
        self.assertTrue(user.email_verification.is_verified)
