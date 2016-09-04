from django.views.generic import TemplateView, View
from django.utils.translation import ugettext as _
from django.db import IntegrityError, transaction
from django.core.urlresolvers import reverse
from django.http import HttpResponseRedirect
from django.template.loader import render_to_string
from django.shortcuts import render
from django.contrib.sites.requests import RequestSite
from django.conf import settings

from mygpoauth.applications.models import Application
from mygpoauth.authorization.models import Authorization
from . import forms, models


class DefaultRegistrationView(View):
    """ Redirect to registration page of default app """

    def get(self, request):
        client_id = settings.DEFAULT_CLIENT_ID
        url = reverse('registration:register', args=[client_id])
        return HttpResponseRedirect(url)


class RegistrationView(TemplateView):
    """ Register a new user """

    template_name = 'registration.html'

    def get_context_data(self, client_id, **kwargs):
        context = super().get_context_data(**kwargs)

        form = forms.RegistrationForm()

        app = Application.objects.get(client_id=client_id)

        context['form'] = form
        context['app'] = app
        return context

    def post(self, request, client_id):

        app = Application.objects.get(client_id=client_id)
        form = forms.RegistrationForm(request.POST)

        if not form.is_valid():
            return self._render_error(request, form, app)

        with transaction.atomic():
            try:
                new_user = form.save()

            except IntegrityError as ie:
                if 'user_case_insensitive_unique' in str(ie):
                    form.add_error('username',
                                   _('This username is already taken.'))
                    return self._render_error(request, form, app)

                else:  # pragma: no cover
                    raise

            # we authorize the user for the app he used to register
            Authorization.objects.create(
                user=new_user,
                application=app,
                scopes=[],  # TODO: which scopes? all?
            )

            site = RequestSite(request)
            self.send_verification_mail(new_user, site)

        return HttpResponseRedirect(app.website_url)

    def _render_error(self, request, form, app):
        return render(request, self.template_name, {
            'form': form,
            'app': app,
        }, status=400)

    def send_verification_mail(self, user, site):
        """ Creates and sends verification email to user """
        subj = render_to_string('verification_email_subject.txt', {
            'domain': site.domain,
        })
        # remove trailing newline added by render_to_string
        subj = subj.strip()

        token = user.email_verification.verification_token.hex
        msg = render_to_string('verification_email_message.txt', {
            'domain': site.domain,
            'verification_token': token,
        })
        user.email_user(subj, msg)


class VerifyEmailView(View):
    """ Verify email via token link """

    def get(self, request, token):
        """ Verify email address based on token link """
        ev = models.EmailVerification.objects.get(verification_token=token)
        ev.is_verified = True
        ev.save(update_fields=['is_verified'])

        # TODO: where to redirect?
        return HttpResponseRedirect('/')
