import urllib.parse
import uuid
import string
import json
import random
import re

from freezegun import freeze_time

from django.conf import settings
from django.test import TestCase, Client
from django.core.urlresolvers import reverse

from mygpoauth.applications.models import Application
from mygpoauth.authorization.models import Authorization
from ..users.models import CustomUser as User


ISSUE_TIME = '2015-05-16T13:47:47Z'


class OAuthTestBase(TestCase):
    """ Provides test data for OAuth tests """

    def setUp(self):
        self.app = Application.objects.create(
            name='Test',
            redirect_url='https://example.com/test?test=true',
        )
        self.user = User.objects.create(
            username='username',
            email='user@example.com',
        )
        pwd = "".join(random.sample(string.ascii_letters, 8))
        self.user.set_password(pwd)
        self.user.save()

        self.client = Client()
        self.client.login(username=self.user.username, password=pwd)

    def tearDown(self):
        Authorization.objects.filter(application=self.app).delete()
        self.app.delete()
        self.user.delete()

    def _get_auth_url(self, scopes, response_type='code', state='some_state',
                      trigger_error=False):
        auth_url = reverse('oauth2:authorize')

        params = [
            ('client_id', self.app.client_id),
            ('response_type', response_type),
            ('state', state),
            ('scope', ' '.join(scopes)),
        ]

        if trigger_error:
            params.append(('trigger_error', 'true'))

        query = urllib.parse.urlencode(params)
        return auth_url + '?' + query

    def _auth_request(self, auth_url):
        """ Perform the request to the authorization endpoint """
        return self.client.get(auth_url)

    def _follow_redirects(self, response, location_pattern, max_redirects=10):
        """ Follow redirects until one directs to location_pattern """
        for n in range(max_redirects):
            self.assertEquals(response.status_code, 302)
            url = response['Location']
            if re.fullmatch(location_pattern, url):
                break
            response = self.client.get(url, follow=False)
        else:
            raise Exception('Max redirects reached')

        return response

    def _fill_auth_form(self, auth_url, scopes):
        """ Fill the authorization form, ie grant the given scopes """
        form_fields = {'scope:' + scope: 'on' for scope in scopes}
        # assume there are other (non-scope) inputs in the form, eg csrf_token
        form_fields.update(other_field='some_value')
        return self.client.post(auth_url, form_fields, follow=False)

    def _catch_redirect(self, response):
        """ Extract the "code" field from the redirect """
        queries = self._verify_redirect_params(response, state='some_state')
        self.assertIn('code', queries.keys())
        self.assertEquals(len(queries['code']), 1)
        code = queries['code'][0]
        return code

    def _tokens_from_auth_code(self, code, scopes):
        """ Request access token from authorization_code """
        req = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': self.app.redirect_url,
        }
        resp = self._token_request(req, set(scopes))
        self.assertEquals(resp['token_type'], 'Bearer')

        # assert that the access_token exists and is a valid UUID
        token = uuid.UUID(resp['access_token'])

        self.assertEquals(set(scopes), set(resp['scope'].split()))

        self.assertEquals(int(resp['expires_in']),
                          settings.DEFAULT_TOKEN_EXPIRATION.total_seconds())
        return resp

    def _get_token_url(self, scopes):
        params = [
            ('scope', ' '.join(scopes)),
        ]
        query = urllib.parse.urlencode(params)
        return reverse('oauth2:token') + '?' + query

    def _token_request(self, req, scopes):
        """ Carry out (and verify) a successful token request """
        token_url = self._get_token_url(scopes)

        response = self.client.post(
            token_url,
            urllib.parse.urlencode(req),
            content_type='application/x-www-form-urlencoded',
            HTTP_AUTHORIZATION=app_auth(self.app),
        )

        self.assertEquals(response.status_code, 200, response.content)
        resp = json.loads(response.content.decode('ascii'))
        self.assertEquals(resp['token_type'], 'Bearer')
        self.assertIn('access_token', resp)

        # from http://tools.ietf.org/html/rfc6749#section-5.1
        # The authorization server MUST include the HTTP "Cache-Control"
        # response header field [RFC2616] with a value of "no-store" in any
        # response containing tokens, credentials, or other sensitive
        # information, as well as the "Pragma" response header field [RFC2616]
        # with a value of "no-cache".
        self.assertEquals(response['Cache-Control'], 'no-store')
        self.assertEquals(response['Pragma'], 'no-cache')

        # Verify that the response contains a Link header (RFC 5988) pointing
        # to the token-info URL
        token = resp['access_token']
        token_info_url = reverse('oauth2:token-info', args=(token,))
        link = '<{target}>; rel="https://gpodder.net/relation/token-info"'\
               .format(target=token_info_url)
        links = response['Link'].split(',')
        self.assertIn(link, links)

        if scopes is not None:
            self.assertEquals(set(resp['scope'].split()), set(scopes))
        self.assertIn('expires_in', resp)
        return resp

    def _verify_redirect_params(self, resp, **params):
        """ Verify that the expected params were included in the redirect """
        self.assertEquals(resp.status_code, 302)

        redir_url = resp['Location']
        urlparts = urllib.parse.urlsplit(redir_url)
        scheme, netloc, path, query, fragment = urlparts
        self.assertEquals(scheme, 'https')
        self.assertEquals(netloc, 'example.com')
        self.assertEquals(path, '/test')
        self.assertEquals(fragment, '')

        queries = urllib.parse.parse_qs(query)
        self.assertEquals(queries['test'], ['true'],)

        for param, value in params.items():
            self.assertEquals(queries[param], [value])

        return queries

    def _get_token_info(self, token, status=200):
        info_url = reverse('oauth2:token-info', args=[token])
        response = self.client.get(info_url)
        self.assertEquals(response.status_code, status, response.content)
        resp = json.loads(response.content.decode('ascii'))
        return resp

    def _perform_auth(self, scopes, expect_auth_page=True):
        """ Perform an authorization for the given scopes """
        auth_url = self._get_auth_url(scopes)
        response = self._auth_request(auth_url)

        if expect_auth_page:
            response = self._fill_auth_form(auth_url, scopes)

        response = self._follow_redirects(response,
                                          'https://example.com/test.+')

        code = self._catch_redirect(response)
        resp = self._tokens_from_auth_code(code, scopes)
        return resp

    def _do_invalid_token_request(self, req, scopes, status, error, auth=None):
        """ Performs an invalid token requests and verifies the result

        If auth is None, the default (correct) authentication information is
        sent. If no authentication header should be sent, an empty string
        should be provided instead. """

        if auth is None:
            auth = app_auth(self.app)

        headers = {}

        if auth:
            headers['HTTP_AUTHORIZATION'] = auth

        token_url = self._get_token_url(scopes)
        response = self.client.post(
            token_url,
            urllib.parse.urlencode(req),
            content_type='application/x-www-form-urlencoded',
            **headers
        )

        self.assertEquals(response.status_code, status)
        resp = json.loads(response.content.decode('ascii'))
        self.assertEquals(resp['error'], error)
        return response


class OAuth2Flow(OAuthTestBase):
    """ Test the OAuth flow """

    @freeze_time(ISSUE_TIME)
    def test_login(self):
        """ Test a successful login """
        SCOPES = ['subscriptions', 'apps:get', 'apps:sync']

        self._perform_auth(SCOPES)

    @freeze_time(ISSUE_TIME)
    def test_login_extend_scopes(self):
        """ Auth with scopes first, extend scopes for 2nd auth """
        SCOPES = ['subscriptions', 'actions:get', 'apps:sync']
        self._perform_auth(SCOPES)
        self._perform_auth(SCOPES + ['app:1234'])

    @freeze_time(ISSUE_TIME)
    def test_login_same_scopes(self):
        """ Auth with same scopes twice, no login page showed on 2nd time """
        SCOPES = ['actions:add', 'apps:get']
        self._perform_auth(SCOPES)
        self._perform_auth(SCOPES, expect_auth_page=False)

    @freeze_time(ISSUE_TIME)
    def test_one_auth_multiple_tokens(self):
        """ Verify that multiple okens can be issued after an auth """
        scopes = ['apps:get', 'app:a', 'app:b']
        auth_url = self._get_auth_url(scopes)
        response = self._auth_request(auth_url)
        response = self._fill_auth_form(auth_url, scopes)
        response = self._follow_redirects(response,
                                          'https://example.com/test.+')
        code = self._catch_redirect(response)

        # retrieve two tokens for the same authorization
        resp1 = self._tokens_from_auth_code(code, scopes)
        resp2 = self._tokens_from_auth_code(code, scopes)
        # ensure that a new token has been issued the second time
        self.assertNotEqual(resp1['access_token'], resp2['access_token'])

    def test_cors(self):
        """ Test CORS headers """
        token_url = reverse('oauth2:token')
        response = self.client.options(token_url)
        self.assertEqual(response['Access-Control-Allow-Origin'], '*')


class TokenInfo(OAuthTestBase):
    """ Tests the Token Info Endpoint """

    @freeze_time(ISSUE_TIME)
    def test_token_info(self):
        """ Verify that the token info returns correct data """
        SCOPES = ['subscriptions', 'apps:get']
        token = self._perform_auth(SCOPES)['access_token']
        info = self._get_token_info(token)

        self.assertCountEqual(info['scopes'], SCOPES)
        self.assertEquals(info['token'], token)
        self.assertEquals(info['app']['url'], None)
        self.assertEquals(info['app']['name'], self.app.name)
        self.assertEquals(info['app']['client_id'], self.app.client_id)
        self.assertEquals(info['created_at'], ISSUE_TIME)
        self.assertEquals(info['user']['login'], self.user.username)

    def test_nonexisting_token(self):
        random = uuid.uuid4()
        self._get_token_info(random.hex, status=404)


class InvalidOAuthFlows(OAuthTestBase):

    def test_deny(self):
        """ Perform an authorization for the given scopes """
        scopes = ['subscriptions', 'apps:get']
        auth_url = self._get_auth_url(scopes)
        response = self._auth_request(auth_url)
        response = self._auth_form_deny(auth_url, scopes)
        response = self._follow_redirects(response,
                                          'https://example.com/test.+')
        self._verify_redirect_params(response, error='access_denied')

    def _auth_form_deny(self, auth_url, scopes):
        """ Fill the authorization form, ie grant the given scopes """
        form_fields = {'scope:' + scope: 'on' for scope in scopes}
        # assume there are other (non-scope) inputs in the form, eg csrf_token
        form_fields.update({'btn:deny': ''})
        return self.client.post(auth_url, form_fields, follow=False)

    def test_token_excess_scope(self):
        """ Authorize for some scopes, request token for other/more """
        scopes1 = ['subscriptions', 'app:a']
        scopes2 = ['subscriptions', 'app:b']
        auth_url = self._get_auth_url(scopes1)
        response = self._auth_request(auth_url)
        response = self._fill_auth_form(auth_url, scopes1)
        response = self._follow_redirects(response,
                                          'https://example.com/test.+')
        code = self._catch_redirect(response)
        req = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': self.app.redirect_url,
        }
        self._do_invalid_token_request(req, scopes2, 400, 'invalid_scope')


class InvalidTokenRequests(OAuthTestBase):
    """ Test invalid requests to token endpoint """

    def test_missing_token_auth(self):
        """ Test missing Basic Auth for Token Endpoint """
        app = Application(client_id='unknown', client_secret='unknown')
        resp = self._do_invalid_token_request({}, [], 401, 'invalid_client',
                                              auth=app_auth(app))
        self.assertTrue(resp['WWW-Authenticate'].startswith('Basic realm="'))

    def test_unknown_client_token_auth(self):
        """ Unknown client when authenticating for Token Endpoint """
        resp = self._do_invalid_token_request({}, [], 401, 'invalid_client',
                                              auth='')
        self.assertTrue(resp['WWW-Authenticate'].startswith('Basic realm="'))

    def test_invalid_grant_type(self):
        """ Invalid grant type: 400, error = unsupported_grant_type """
        req = {
            'grant_type': 'new_fancy_grant',
        }
        self._do_invalid_token_request(req, [], 400, 'unsupported_grant_type')

    def test_missing_grant_type(self):
        """ No grant_type results in 400 w/ error = unsupported_grant_type """
        req = {
            'asdf': 'test',
        }
        self._do_invalid_token_request(req, [], 400, 'unsupported_grant_type')

    def test_missing_grant(self):
        """ No grant results in 400 w/ error = invalid_request """
        req = {
            'grant_type': 'authorization_code',
        }
        self._do_invalid_token_request(req, [], 400, 'invalid_request')

    def test_invalid_grant(self):
        """ The auth code is not a valid UUID

        This is not a requirement by the spec, but by the implementation. This
        should be treated as if the auth code would not exist """

        req = {
            'grant_type': 'authorization_code',
            'code': 'some_invalid_code',
            'redirect_uri': self.app.redirect_url,
        }
        self._do_invalid_token_request(req, [], 400, 'invalid_grant')

    def test_noexisting_grant(self):
        """ The auth code is a valid UUID but does not exist """
        req = {
            'grant_type': 'authorization_code',
            'code': uuid.uuid4().hex,
            'redirect_uri': self.app.redirect_url,
        }
        self._do_invalid_token_request(req, [], 400, 'invalid_grant')


class InvalidAuthRequests(OAuthTestBase):
    """ Test invalid requests to authorization endpoint """

    def test_invalid_scope(self):
        """ Test a request for aninvalid scope """
        self._do_invalid_auth_request(scopes=['invalid scope'],
                                      error='invalid_scope')

    def test_invalid_response_type(self):
        """ Test a request with an invalid response type """
        self._do_invalid_auth_request(response_type='magic_response',
                                      error='unsupported_response_type')

    def test_server_error(self):
        """ Cause a test server error """
        self._do_invalid_auth_request(trigger_error=True, error='server_error')

    def _do_invalid_auth_request(self, response_type='code', scopes=[],
                                 error='', trigger_error=False):
        """ Perform an invalid auth request """
        auth_url = self._get_auth_url(scopes, response_type,
                                      trigger_error=trigger_error)
        # Verify that the Authorization server redirects back correctly
        response = self.client.get(auth_url, follow=False)
        self._verify_redirect_params(response, error=error)


def app_auth(app):
    """ Create the authorization string for the given app """
    return create_auth_string(app.client_id, app.client_secret)


def create_auth_string(username, password):
    """ Create a Basic Auth string for the given credentials """
    import base64
    credentials = ("%s:%s" % (username, password)).encode('ascii')
    credentials = base64.b64encode(credentials).decode('ascii')
    auth_string = 'Basic %s' % credentials
    return auth_string
