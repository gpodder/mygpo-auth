from django.conf.urls import include, url
from django.contrib import admin
from django.views.generic.base import RedirectView

from mygpoauth import oauth2


urlpatterns = [
    # Examples:
    # url(r'^$', 'mygpoauth.views.home', name='home'),
    # url(r'^blog/', include('blog.urls')),

    url(r'^$', RedirectView.as_view(url='http://mygpo-auth.rtfd.org/',
                                    permanent=False),
        name='index'),
    url(r'^admin/', admin.site.urls),
    url(r'^oauth2/', include('mygpoauth.oauth2.urls')),
    url(r'^login/', include('mygpoauth.login.urls')),
    url(r'^register/', include('mygpoauth.registration.urls')),
]
