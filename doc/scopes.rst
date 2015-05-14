Scopes
======

Clients can use scopes to specify which type of access they require. Users can
accept or restrict the requested set of scopes.

The following scopes are available.

================= =============================================================
Name              Description
================= =============================================================
(no scope)        Read-only access to all public information (eg podcast lists,
                  public subscriptions, podcast data, etc) and the username
``subscriptions`` Read-only access to all subscriptions
``suggestions``   Access to suggested podcasts
``account``       Read-write access to profile data, settings (except for app
                  settings)
``favorites``     Adding and retrieving favorite episodes
``podcastlists``  Write-access to podcast lists
``apps:get``      List all apps
``apps:sync``     Initiate and stop app synchronization; read sync status
``actions:get``   Read-only access to episode actions
``actions:add``   Submitting of episode actions
``app:<id>``      Read-write access to the app with the specific Id. The app
                  will be created if it does not exist.
================= =============================================================
