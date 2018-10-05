from django.test import TestCase

from . import scope


class ScopeGroupTests(TestCase):
    def test_ActionsScopeGroup_invalid_scope(self):
        sg = scope.ActionsScopeGroup()
        with self.assertRaises(ValueError):
            sg.add_scope('actions:test', 'test')

    def test_AppsScopeGroup_invalid_scope(self):
        sg = scope.AppsScopeGroup()
        with self.assertRaises(ValueError):
            sg.add_scope('apps:invalid', 'invalid')
