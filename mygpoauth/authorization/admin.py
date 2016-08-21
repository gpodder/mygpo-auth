from django.contrib import admin
from .models import Authorization


def scope_list(app):
    """
    >>> scope_list(Authorization(scopes=['a', 'b', 'c']))
    'a, b, c'
    """
    return ', '.join(app.scopes)


@admin.register(Authorization)
class ApplicationAdmin(admin.ModelAdmin):

    list_display = ['user', 'application', scope_list]

    list_select_related = ['user', 'application']

    readonly_fields = ['user']

    fields = ['user', 'application', 'scopes', 'code']
