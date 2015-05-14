""" This module parses and validates scopes """

import re


class ScopeError(Exception):
    """ Base class for scope errors """


class InvalidScope(ScopeError):
    """ The scope (the part before the colon) is unknown """


class NoSubScopeAllowed(ScopeError):
    """ The scope does not allow a sub-scope """


class InvalidSubScope(ScopeError):
    """ The sub-scope is invalid """


class SubScopeMissing(ScopeError):
    """ A sub-scope is required but was not given """


ALLOWED_SCOPES = {
    'subscriptions': None,
    'suggestions': None,
    'account': None,
    'favorites': None,
    'podcastlists': None,
    'apps': re.compile(r'get|sync'),
    'actions': re.compile(r'get|add'),
    'app': re.compile(r'[\w.-]{1,32}'),
}


def parse_scopes(scope_str):
    """ Split and normalize a scope string

    >>> parse_scopes('subscriptions suggestions account') == \
        {'subscriptions', 'suggestions', 'account'}
    True

    >>> parse_scopes('  account \t favorites    account'   ) == \
        {'account', 'favorites'}
    True

    >>> parse_scopes('') == set()
    True

    >>> parse_scopes('podcastlists app:1235456 app:1235456 app:533545') == \
        {'podcastlists', 'app:1235456', 'app:533545'}
    True
    """
    scopes = scope_str.split()
    scopes = set(scopes)
    scopes = map(validate_scope, scopes)
    return set(scopes)


def validate_scope(scope):
    """ Validates an individual scope string

    >>> validate_scope('podcastlists')
    'podcastlists'

    >>> validate_scope('asdf')
    Traceback (most recent call last):
     ...
    mygpoauth.authorization.scope.InvalidScope: asdf

    >>> validate_scope('subscriptions:all')
    Traceback (most recent call last):
     ...
    mygpoauth.authorization.scope.NoSubScopeAllowed: subscriptions:all

    >>> validate_scope('app')
    Traceback (most recent call last):
     ...
    mygpoauth.authorization.scope.SubScopeMissing: app

    >>> validate_scope('apps:all')
    Traceback (most recent call last):
     ...
    mygpoauth.authorization.scope.InvalidSubScope: apps:all

    >>> validate_scope('actions:get:x')
    Traceback (most recent call last):
     ...
    mygpoauth.authorization.scope.InvalidSubScope: actions:get:x

    """

    # split only at first colon
    parts = scope.split(':', 1)

    main = parts[0]

    # verify if the main part of the scope (before colon) is known
    if main not in ALLOWED_SCOPES:
        raise InvalidScope(scope)

    pattern = ALLOWED_SCOPES[main]

    if not pattern:
        if len(parts) > 1:
            raise NoSubScopeAllowed(scope)

    else:
        if len(parts) == 1:
            raise SubScopeMissing(scope)

        sub = parts[1]

        if not pattern.fullmatch(sub):
            raise InvalidSubScope(scope)

    return scope
