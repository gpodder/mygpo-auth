from django.conf.urls import url

from . import views


urlpatterns = [

    url(r'^$',
        views.DefaultRegistrationView.as_view(),
        name='register-default'),

    url(r'^app/(?P<client_id>[^/]+)',
        views.RegistrationView.as_view(),
        name='register'),

    url(r'^verify/(?P<token>\w+)',
        views.VerifyEmailView.as_view(),
        name='verify-email'),

]
