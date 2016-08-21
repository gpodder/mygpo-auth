from django.conf.urls import url

from . import views


urlpatterns = [

    url(r'^$',
        views.DefaultRegistrationView.as_view(),
        name='register-default'),

    url(r'^(?P<client_id>\w+)',
        views.RegistrationView.as_view(),
        name='register'),

]
