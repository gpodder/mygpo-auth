""" This module parses and validates scopes """

import re
import collections


# Exceptions


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


#
# Scope Groups
#


class ScopeGroup(object):
    """ A Scope Groups represents one or more (related) scopes.

    Each scope group corresponds to the "main" part of a scope (the part before
    the ":"), and can define "sub" parts (after ":"). """

    # by default a scope group does not have any sub-scopes
    sub_pattern = None

    def __init__(self):
        self.scope_keys = []

    def add_scope(self, scope, sub):
        self.scope_keys.append(ScopeKey(scope, sub))


class DefaultScopeGroup(ScopeGroup):
    """ The default permission that any authorized app has"""

    title = 'View public information'
    description = (
        'Read-only access to all public information (eg podcast '
        'lists, public subscriptions, podcast data, etc) and the username'
    )


class SubscriptionsScopeGroup(ScopeGroup):
    """ ScopeGroup for managing subscriptions """

    title = 'See subscriptions'
    description = 'Read-only access to all subscriptions'


class SuggestionsScopeGroup(ScopeGroup):
    title = 'Podcast suggestions'
    description = 'Read-only access to suggested podcasts'


class AccountScopeGroup(ScopeGroup):
    title = 'Modify account settings'
    description = (
        'Read-write access to profile data, settings (except for '
        'app settings)'
    )


class FavoritesScopeGroup(ScopeGroup):
    title = 'Favorite podcasts'
    description = 'Adding and retrieving favorite episodes'


class PodcastListsScopeGroup(ScopeGroup):
    title = 'Create and edit podcast lists'
    description = 'Write-access to podcast lists'


class AppsScopeGroup(ScopeGroup):
    title = 'Access your apps'
    sub_pattern = re.compile(r'get|sync')

    def add_scope(self, scope, sub):
        if sub == 'get':
            self.scope_keys.append(ScopeKey(scope, sub))
        elif sub == 'sync':
            self.scope_keys.append(ScopeKey(scope, sub))
        else:
            raise ValueError(scope)

    @property
    def description(self):
        if len(self.scope_keys) == 1:
            if self.scope_keys[0].key == 'apps:get':
                return 'Listing your apps.'
            else:
                return 'Synchronizing your apps.'
        else:
            return (
                'Listing your apps and changing their synchronization '
                'status.'
            )


class ActionsScopeGroup(ScopeGroup):
    title = 'Episode Actions'
    description = ''
    sub_pattern = re.compile(r'get|add')

    def add_scope(self, scope, sub):
        if sub == 'get':
            self.scope_keys.append(ScopeKey(scope, sub))
        elif sub == 'add':
            self.scope_keys.append(ScopeKey(scope, sub))
        else:
            raise ValueError(scope)


class AppScopeGroup(ScopeGroup):
    sub_pattern = re.compile(r'[\w.-]{1,32}')

    @property
    def title(self):
        if len(self.scope_keys) == 1:
            return 'Manage app "{}"'.format(self.scope_keys[0].summary)

        return 'Manage {} apps'.format(len(self.scope_keys))

    @property
    def description(self):
        if len(self.scope_keys) == 1:
            return 'Read-write access to the app.'
        else:
            return 'Read-write access to these apps:'

    def add_scope(self, scope, sub):
        self.scope_keys.append(ScopeKey(scope, sub))


ScopeKey = collections.namedtuple('ScopeKey', 'key summary')


ALLOWED_SCOPES = {
    'subscriptions': SubscriptionsScopeGroup,
    'suggestions': SuggestionsScopeGroup,
    'account': AccountScopeGroup,
    'favorites': FavoritesScopeGroup,
    'podcastlists': PodcastListsScopeGroup,
    'apps': AppsScopeGroup,
    'actions': ActionsScopeGroup,
    'app': AppScopeGroup,
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

    pattern = ALLOWED_SCOPES[main].sub_pattern

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


def get_scopegroups(scopes, include_default):
    groups = {}

    for scope in scopes:
        if ':' in scope:
            main, sub = scope.split(':')
        else:
            main, sub = scope, None

        if main not in groups:
            groups[main] = ALLOWED_SCOPES[main]()

        groups[main].add_scope(scope, sub)

    groups = list(groups.values())

    if include_default:
        # the default permissions should always be listed first
        groups.insert(0, DefaultScopeGroup())

    return groups
