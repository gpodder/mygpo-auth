from django.urls import path

from . import views


app_name = 'registration'

urlpatterns = [
    path('', views.DefaultRegistrationView.as_view(), name='register-default'),
    path(
        'app/<str:client_id>',
        views.RegistrationView.as_view(),
        name='register',
    ),
    path(
        'verify/<uuid:token>',
        views.VerifyEmailView.as_view(),
        name='verify-email',
    ),
]
