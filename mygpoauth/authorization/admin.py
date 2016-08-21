from django.contrib import admin
from .models import Authorization


@admin.register(Authorization)
class ApplicationAdmin(admin.ModelAdmin):

    def scope_list(self, app):
        return ', '.join(app.scopes)

    list_display = ['user', 'application', 'scope_list']

    list_select_related = ['user', 'application']

    readonly_fields = ['user']

    fields = ['user', 'application', 'scopes', 'code']
