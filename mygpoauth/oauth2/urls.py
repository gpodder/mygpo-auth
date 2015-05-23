from django.conf.urls import url

from . import views

urlpatterns = [
    url(r'^authorize$', views.AuthorizeView.as_view(), name='authorize'),
    url(r'^token$', views.TokenView.as_view(), name='token'),
    url(r'^token/(?P<token>[\w+]+)$', views.TokenInfoView.as_view(),
        name='token-info'),
]
