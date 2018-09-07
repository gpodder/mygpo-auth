from django.urls import path

from . import views


app_name = 'oauth2'

urlpatterns = [
    path('authorize', views.AuthorizeView.as_view(), name='authorize'),
    path('token', views.TokenView.as_view(), name='token'),
    path('token/<uuid:token>', views.TokenInfoView.as_view(),
        name='token-info'),
]
