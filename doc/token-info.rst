Token Info Endpoint
===================

..  http:get:: /oauth2/token/(string:token)
    :synopsis: Returns information about an access token

    The token info endpoint returns information about an access token.

    **Example request**:

    .. sourcecode:: http

        GET /oauth2/token/2YotnFZFEjr1zCsicMWpAA HTTP/1.1
        Accept: application/json


    **Example successful response**:

    .. sourcecode:: http

        HTTP/1.1 200 OK
        Content-Type: application/json
        Cache-Control: no-cache
        Pragma: no-cache

        {
            "scopes": ["subscriptions", "suggestions", "favorites"],
            "token": "2YotnFZFEjr1zCsicMWpAA",
            "app": {
                "url": "http://gpodder.org/",
                "name": "gPodder",
                "client_id": "cab216c0509f4d60b227548674694b3b",
            },
            "created_at": "2015-05-22T17:19:51Z",
            "user": {
                "login": "bob",
            }
        }

    **Example error response**:

    .. sourcecode:: http

        HTTP/1.1 404 Not Found
        Content-Type: application/json
        Cache-Control: no-cache
        Pragma: no-cache

        {
            "token": "d294f1f1a91933",
            "error": "Token does not exist."
        }


    :param token: The token for which information should be retrieved

    :>json scopes: List of scopes that this token can access
    :>json token: The token for which information was requested
    :>json app: Information about the app that requested the token
    :>json app/url: The website of the URL
    :>json app/name: A human-readable name of the app
    :>json app/client_id: The app's client_id
    :>json created_at: The timestamp at which the token was created
    :>json user: Information about the user that owns the token
    :>json user/login: The username (login) of the user

    :status 200: the token exists and is still valid
    :status 404: the token either expired or never existed
