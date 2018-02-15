from django.urls import path
from django.contrib.auth import views as auth_views

from . import views
from . import forms


app_name = 'login'

urlpatterns = [
    path('', auth_views.login, {
        'template_name': 'login/login.html',
        'authentication_form': forms.MyAuthenticationForm,
        },
        name='login'),
]
