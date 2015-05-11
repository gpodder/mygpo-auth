from django.contrib import admin
from .models import Authorization


@admin.register(Authorization)
class ApplicationAdmin(admin.ModelAdmin):
    pass
