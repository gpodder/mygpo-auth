OAuth Flow
==========


1. Redirect users to Authorization page
---------------------------------------

Redirect your users to the gpodder.net authorization page at

    https://mygpo-auth-test.herokuapp.com/oauth2/authorize

with the following query parameters

================ ==============================================================
Name             Description
================ ==============================================================
``client_id``    The client ID you received when registering your app (see
                 :doc:`register`).
``redirect_uri`` The URL to which the user should be redirected after
                 authorization.
``scope``        A space-delimited set of :doc:`scopes` which the app requests.
``state``        An unguessable random string. It is used to protect against
                 cross-site request forgery attacks.
================ ==============================================================


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


4. Get Access and Refresh Token
-------------------------------

You can now request an access and refresh token that can be used to access the
gpodder.net API.

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

The response will then contain JSON data with ``access_token`` and
``refresh_token`` attributes, containing the respective tokens.

The ``scope`` attribute contains the list of granted scopes.

.. code:: json

     {
       "access_token": "2YotnFZFEjr1zCsicMWpAA",
       "token_type": "bearer",
       "expires_in": 3600,
       "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
       "scope": "subscriptions suggestions"
     }


5. Accessing API endpoints
--------------------------

Not implemented yet


6. Renew tokens
---------------

The access token has a relatively short expiration time. When the token is
expired it can be refreshed from the token endpoint using the refresh token.

This request is similar to step 5 with the following exceptions. It should
contain the following parameters using the
``application/x-www-form-urlencoded`` format in the body.

================= =============================================================
Name              Description
================= =============================================================
``grant_type``    The string ``refresh_token``, indicating that a refresh token
                  is used to retrieve new tokens
``refresh_token`` The refresh_token (from step 4).
``client_id``     The client ID you received when registering your app (see
                  :doc:`register`).
================= =============================================================

