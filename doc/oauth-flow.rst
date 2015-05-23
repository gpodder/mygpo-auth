OAuth Flow
==========


1. Redirect users to Authorization page
---------------------------------------

Redirect your users to the gpodder.net authorization page at

    https://mygpo-auth-test.herokuapp.com/oauth2/authorize

with the following query parameters

================= =============================================================
Name              Description
================= =============================================================
``client_id``     The client ID you received when registering your app (see
                  :doc:`register`).
``redirect_uri``  The URL to which the user should be redirected after
                  authorization.
``scope``         A space-delimited set of :doc:`scopes` which the app
                  requests.
``state``         An unguessable random string. It is used to protect against
                  cross-site request forgery attacks.
``response_type`` The string ``code`` indicating that an authorization code is
                  requested.
================= =============================================================


2. User authenticates and authorizes your app
---------------------------------------------

Not implemented yet.


3. The user is redirected back
------------------------------

After successful authorization the user is redirected to the URL that was
specified during registration of the app (see :doc:`register`).

To the URL the following query parameters will be appended.

============ ==================================================================
Name         Description
============ ==================================================================
``code``     The authorization code that you can exchange for an access token
``state``    The state parameter of the previous request. If this does not
             match, the request did not originate from gpodder.net and should
             not be processed.
============ ==================================================================


4. Get an Access Token
----------------------

You can now request an access token that can be used to access the gpodder.net
API.

To retrieve the tokens, issue a ``POST`` request to

    https://mygpo-auth-test.herokuapp.com/oauth2/token

with `HTTP Basic Authentication <http://tools.ietf.org/html/rfc2617>`_, using
the client ID as username and the client secret as password.

The request should contain the following parameters using the
``application/x-www-form-urlencoded`` format in the body.

============== ==================================================================
Name           Description
============== ==================================================================
``grant_type`` The string ``authorization_code``, indicating that an
               authorization code (from step 3) is exchanged for tokens
``code``       The ``code`` value from the redirect
``client_id``  The client ID you received when registering your app (see
               :doc:`register`)
============== ==================================================================

The request should include an ``Accept: application/json`` header.

The response will then contain JSON data with a ``access_token``
attributes.

The ``scope`` attribute contains the list of granted scopes.

The response will also contain a `HTTP Link header
<https://tools.ietf.org/html/rfc5988>`_) with the relation
``https://gpodder.net/relation/token-info``. The target of this link can be
used to discover the URL from which token information can be retrieved (see
next step).

.. code:: json

    Link: </oauth2/token/2YotnFZFEjr1zCsicMWpAA>;
          rel="https://gpodder.net/relation/token-info"

    {
       "access_token": "2YotnFZFEjr1zCsicMWpAA",
       "token_type": "bearer",
       "expires_in": 3600,
       "scope": "subscriptions suggestions"
    }


5. Retrieve Token Information
-----------------------------

information about a token can be retrieved from the token info endpoint. It's
URL SHOULD be discovered from the ``Link`` header of the response in which the
token is issued (see previous step). Alternatively a client MAY chose to use
the following URL

.. code::

    /oauth2/token/{{ token }}


The request SHOULD include an
``Accept: application/json`` header. The response will include the following
information.

The information from this can be used to construct subsequent requests to the
API, eg such that contain the username or app IDs.

.. code:: json

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


6. Accessing API endpoints
--------------------------

Not implemented yet


7. Renew tokens
---------------

The access token has a relatively short expiration time. When the token is
expired it can be renewed by repeating step 4.
