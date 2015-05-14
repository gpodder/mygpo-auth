import base64
import uuid
import urllib.parse
from functools import wraps

from django import http
from django.views.generic.base import View
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import get_object_or_404
from django.contrib.auth.models import User

from mygpoauth.applications.models import Application
from mygpoauth.authorization.models import Authorization
from mygpoauth.authorization.scope import parse_scopes, ScopeError
from .exceptions import (MissingGrantType, UnsupportedGrantType, OAuthError,
                         InvalidGrant, InvalidRequest, InvalidScope)


class OAuthView(View):
    """ The base view for the OAuth endpoints

    http://tools.ietf.org/html/rfc6749#section-3 """

    def dispatch(self, request, *args, **kwargs):
        try:
            return super().dispatch(request, *args, **kwargs)

        except OAuthError as e:
            return http.JsonResponse({
                'error': e.error,
                'error_description': e.error_description,
            }, status=400)


def cors(f):
    @wraps(f)
    def _wrapper(request, *args, **kwargs):
        origin = request.META.get('Origin')
        response = f(request, *args, **kwargs)
        response['Access-Control-Max-Age'] = 86400
        response['Access-Control-Allow-Origin'] = '*'
        response['Access-Control-Allow-Methods'] = ('GET, POST, PUT, PATCH, '
                                                    'DELETE, OPTIONS')
        response['Access-Control-Allow-Headers'] = ', '.join([
            'x-requested-with',
            'content-type',
            'accept',
            'origin',
            'authorization',
            'x-csrftoken',
            'user-agent',
            'accept-encoding'
        ])
        response['Allow'] = 'POST, OPTIONS'
        return response
    return _wrapper


def require_application(f):
    @wraps(f)
    def _wrapper(request, *args, **kwargs):
        auth = request.META.get('HTTP_AUTHORIZATION', '')

        if not auth.startswith('Basic '):
            return http.JsonResponse({}, status=401)

        auth = auth[len('Basic '):]
        auth = base64.b64decode(auth.encode('ascii')).decode('ascii')
        client_id, client_secret = auth.split(':')

        application = get_object_or_404(Application,
                                        client_id=client_id,
                                        client_secret=client_secret)

        return f(request, application, *args, **kwargs)
    return _wrapper


class AuthorizeView(OAuthView):
    """ The Authorization Endpoint

    http://tools.ietf.org/html/rfc6749#section-3.1 """

    def get(self, request, *args, **kwargs):

        client_id = request.GET.get('client_id')
        application = get_object_or_404(Application, client_id=client_id)

        response_type = request.GET.get('response_type')
        # http://tools.ietf.org/html/rfc6749#section-3.1.1

        # if present it is included in the redirect url
        state = request.GET.get('state')

        try:
            scopes = parse_scopes(request.GET.get('scope', ''))
        except ScopeError as se:
            raise InvalidScope(str(se))

        # TODO: get logged in user
        user = User.objects.first()

        auth, created = Authorization.objects.update_or_create(
            user=user,
            application=application,
            defaults={
                'scopes': list(scopes),
            }
        )

        # authorization token
        # code=n96wRPxkqNMQ579UFCCrLNlGpt7mok&state=random_state_string
        code = auth.code.hex

        redir_url = self.build_redirect_url(application, code, state)
        return http.HttpResponseRedirect(redir_url)

    def build_redirect_url(self, application, code, state):
        url_parts = urllib.parse.urlsplit(application.redirect_url)
        scheme, netloc, path, query, fragment = url_parts

        queries = urllib.parse.parse_qsl(query)
        query = urllib.parse.urlencode(queries +
                                       [('code', code), ('state', state)])

        url_parts = (scheme, netloc, path, query, fragment)
        return urllib.parse.urlunsplit(url_parts)


class TokenView(OAuthView):
    """ The Token Endpoint

    http://tools.ietf.org/html/rfc6749#section-3.2 """

    @method_decorator(csrf_exempt)
    @method_decorator(cors)
    def dispatch(self, request, *args, **kwargs):
        return super(TokenView, self).dispatch(request, *args, **kwargs)

    def options(self, request):
        return http.HttpResponse('')

    @method_decorator(require_application)
    def post(self, request, application):

        req = urllib.parse.parse_qs(request.body)

        grant_type = req.get(b'grant_type', None)
        if not grant_type:
            raise MissingGrantType

        if req[b'grant_type'] == [b'authorization_code']:

            if len(req.get(b'code', [])) != 1:
                # code parameter missing or duplicated
                raise InvalidRequest

            try:
                code = uuid.UUID(req[b'code'][0].decode('ascii'))
            except ValueError:
                # code is malformed
                raise InvalidGrant

            try:
                auth = Authorization.objects.get(code=code)

            except Authorization.DoesNotExist:
                raise InvalidGrant

            # {b'grant_type': [b'authorization_code'],
            #  b'code': [b'asdf'],
            #  b'redirect_uri': [b'http://django-oauth-toolkit.herokuapp.com/
            #   consumer/exchange/']}
            resp = {
                'refresh_token': 'a',
                'token_type': 'Bearer',
                'access_token': 'b',
                'scope': ' '.join(auth.scopes),
                'expires_in': 3600,
            }

        elif req[b'grant_type'] == [b'refresh_token']:
            # refresh_token
            resp = {
                'refresh_token': 'a',
                'token_type': 'Bearer',
                'access_token': 'b',
                'scope': 'read write',
                'expires_in': 3600,
            }

        else:
            raise UnsupportedGrantType(grant_type)

        return http.JsonResponse(resp)
