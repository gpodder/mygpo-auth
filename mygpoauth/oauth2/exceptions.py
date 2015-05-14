
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
