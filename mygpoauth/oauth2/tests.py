import urllib.parse
import json

from django.test import TestCase, Client
from django.core.urlresolvers import reverse

from mygpoauth.applications.models import Application


class OAuth2Flow(TestCase):
    """ Test the OAuth flow """

    def setUp(self):
        self.app = Application.objects.create(
            name='Test',
            redirect_url='https://example.com/test?test=true',
        )
        self.client = Client()

    def tearDown(self):
        self.app.delete()

    def test_login(self):
        """ Test a successful login """
        auth_url = reverse('oauth2:authorize')

        query = urllib.parse.urlencode([
            ('client_id', self.app.client_id),
            ('response_type', '????'),
            ('state', 'some_state'),
            ('scope', 'read write'),
        ])

        # Verify that the Authorization server redirects back correctly
        response = self.client.get(auth_url + '?' + query, follow=False)
        self.assertEquals(response.status_code, 302)

        redir_url = response['Location']
        urlparts = urllib.parse.urlsplit(redir_url)
        scheme, netloc, path, query, fragment = urlparts
        self.assertEquals(scheme, 'https')
        self.assertEquals(netloc, 'example.com')
        self.assertEquals(path, '/test')
        self.assertEquals(fragment, '')

        queries = urllib.parse.parse_qs(query)
        self.assertEquals(queries['test'], ['true'],)
        self.assertEquals(queries['state'], ['some_state'])
        self.assertIn('code', queries.keys())

        code = queries['code']

        # Request access token from authorization_code
        req = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': self.app.redirect_url,
        }
        resp = self.token_request(req)

        # Request access token from refresh_token
        refresh_token = resp['refresh_token']
        req = {
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token,
        }
        resp = self.token_request(req)

    def token_request(self, req):
        """ Carry out (and verify) a successful token request """
        token_url = reverse('oauth2:token')
        response = self.client.post(
            token_url,
            urllib.parse.urlencode(req),
            content_type='application/x-www-form-urlencoded',
            HTTP_AUTHORIZATION=self.app_auth(),
        )

        self.assertEquals(response.status_code, 200)
        resp = json.loads(response.content.decode('ascii'))
        self.assertIn('refresh_token', resp)
        self.assertEquals(resp['token_type'], 'Bearer')
        self.assertIn('access_token', resp)
        self.assertIn('scope', resp)
        self.assertIn('expires_in', resp)
        return resp

    def test_cors(self):
        """ Test CORS headers """
        token_url = reverse('oauth2:token')
        response = self.client.options(token_url)
        self.assertEqual(response['Access-Control-Allow-Origin'], '*')

    def test_missing_token_auth(self):
        """ Test missing Basic Auth for Token Endpoint """
        token_url = reverse('oauth2:token')
        response = self.client.post(
            token_url,
            '',
            content_type='application/x-www-form-urlencoded',
        )
        self.assertEquals(response.status_code, 401)

    def test_invalid_grant_type(self):
        """ Invalid grant type: 400, error = unsupported_grant_type """
        req = {
            'grant_type': 'new_fancy_grant',
        }
        token_url = reverse('oauth2:token')
        response = self.client.post(
            token_url,
            urllib.parse.urlencode(req),
            content_type='application/x-www-form-urlencoded',
            HTTP_AUTHORIZATION=self.app_auth(),
        )

        self.assertEquals(response.status_code, 400)
        resp = json.loads(response.content.decode('ascii'))
        self.assertEquals(resp['error'], 'unsupported_grant_type')

    def test_missing_grant_type(self):
        """ No grant_type results in 400 w/ error = unsupported_grant_type """
        req = {
            'asdf': 'test',
        }
        token_url = reverse('oauth2:token')
        response = self.client.post(
            token_url,
            urllib.parse.urlencode(req),
            content_type='application/x-www-form-urlencoded',
            HTTP_AUTHORIZATION=self.app_auth(),
        )

        self.assertEquals(response.status_code, 400)
        resp = json.loads(response.content.decode('ascii'))
        self.assertEquals(resp['error'], 'unsupported_grant_type')

    def app_auth(self):
        return create_auth_string(self.app.client_id, self.app.client_secret)


def create_auth_string(username, password):
    import base64
    credentials = ("%s:%s" % (username, password)).encode('ascii')
    credentials = base64.b64encode(credentials).decode('ascii')
    auth_string = 'Basic %s' % credentials
    return auth_string
