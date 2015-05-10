
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
