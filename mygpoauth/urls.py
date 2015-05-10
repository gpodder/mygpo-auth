from django.conf.urls import include, url
from django.contrib import admin

from mygpoauth import oauth2


urlpatterns = [
    # Examples:
    # url(r'^$', 'mygpoauth.views.home', name='home'),
    # url(r'^blog/', include('blog.urls')),

    url(r'^admin/', include(admin.site.urls)),
    url(r'^oauth2/', include('mygpoauth.oauth2.urls', namespace='oauth2')),
]
