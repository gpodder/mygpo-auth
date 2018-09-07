from django.urls import include, path
from django.contrib import admin
from django.views.generic.base import RedirectView

from mygpoauth import oauth2


urlpatterns = [
    # Examples:
    # url(r'^$', 'mygpoauth.views.home', name='home'),
    # url(r'^blog/', include('blog.urls')),
    path(
        '',
        RedirectView.as_view(url='http://mygpo-auth.rtfd.org/', permanent=False),
        name='index',
    ),
    path('admin/', admin.site.urls),
    path('oauth2/', include('mygpoauth.oauth2.urls')),
    path('login/', include('mygpoauth.login.urls')),
    path('register/', include('mygpoauth.registration.urls')),
]
