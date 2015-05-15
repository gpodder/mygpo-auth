
""" Exceptions for Error responses

according to http://tools.ietf.org/html/rfc6749#section-5.2 """


class OAuthError(Exception):
    pass


class UnsupportedGrantType(OAuthError):
    """ The authorization grant type is not supported by the authorization
    server."""
    error = 'unsupported_grant_type'

    def __init__(self, grant_type):
        self.error_description = ('The grant type "{grant_type}" is not '
                                  'supported'.format(grant_type=grant_type))


class MissingGrantType(UnsupportedGrantType):

    def __init__(self):
        super()
        self.error_description = ('The required parameter "grant_type" is '
                                  'missing.')


class InvalidGrant(OAuthError):
    """ The provided authorization grant (e.g., authorization code, resource
    owner credentials) or refresh token is invalid, expired, revoked, does not
    match the redirection URI used in the authorization request, or was issued
    to another client.  """

    error = 'invalid_grant'
    error_description = 'The given grant was invalid'


class InvalidRequest(OAuthError):
    """ The request is missing a required parameter, includes an unsupported
    parameter value (other than grant type), repeats a parameter, includes
    multiple credentials, utilizes more than one mechanism for authenticating
    the client, or is otherwise malformed."""

    error = 'invalid_request'
    error_description = 'Request was malformed'


class InvalidScope(OAuthError):
    """ The requested scope is invalid, unknown, malformed, or exceeds the
    scope granted by the resource owner."""

    error = 'invalid_scope'
    error_description = 'The requested scope was invalid'


class InvalidClient(OAuthError):
    """ Client authentication failed (

    e.g., unknown client, no client authentication included, or unsupported
    authentication method).  The authorization server MAY return an HTTP 401
    (Unauthorized) status code to indicate which HTTP authentication schemes
    are supported.  If the client attempted to authenticate via the
    "Authorization" request header field, the authorization server MUST respond
    with an HTTP 401 (Unauthorized) status code and include the
    "WWW-Authenticate" response header field matching the authentication scheme
    used by the client. """

    def __init__(self, realm):
        self.realm = realm

    error = 'invalid_client'
    error_description = 'Client authentication failed'


class UnsupportedResponseType(OAuthError):
    """ The authorization server does not support obtaining an authorization
    code using this method. """

    def __init__(self, response_type):
        self.error_description = (
            'The response type "{response_type}" is not supported'
            .format(response_type=response_type))

    error = 'unsupported_response_type'


class AccessDenied(OAuthError):
    """ The resource owner or authorization server denied the request. """

    error = 'access_denied'
    error_description = 'The access has been denied'


class ServerError(OAuthError):
    """ The authorization server encountered an unexpected condition that
    prevented it from fulfilling the request.  (This error code is needed
    because a 500 Internal Server Error HTTP status code cannot be returned to
    the client via an HTTP redirect.) """

    error = 'server_error'
    error_description = 'An unknown error occured'
