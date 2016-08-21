from django.views.generic import TemplateView
from django.utils.translation import ugettext as _
from django.db import IntegrityError, transaction
from django.http import HttpResponseRedirect
from django.shortcuts import render

from mygpoauth.applications.models import Application
from mygpoauth.authorization.models import Authorization
from . import forms


class RegistrationView(TemplateView):
    """ Register a new user """

    template_name = 'registration.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Pass client-ID to grant initial authorization
        client_id = self.request.GET.get('client_id')

        form = forms.RegistrationForm(initial={
            'client_id': client_id,
            })

        context['form'] = form
        return context

    def post(self, request):

        form = forms.RegistrationForm(request.POST)

        if not form.is_valid():
            return self._render_error(request, form)

        client_id = form.cleaned_data['client_id']
        app = Application.objects.get(client_id=client_id)

        with transaction.atomic():
            try:
                new_user = form.save()

            except IntegrityError as ie:
                if 'user_case_insensitive_unique' in str(ie):
                    form.add_error('username',
                                   _('This username is already taken.'))
                    return self._render_error(request, form)

                else:  # pragma: no cover
                    raise

        # we authorize the user for the app he used to register
        Authorization.objects.create(
            user=new_user,
            application=app,
            scopes=[],  # TODO: which scopes? all?
        )

        return HttpResponseRedirect(app.website_url)

    def _render_error(self, request, form):
        return render(request, self.template_name, {'form': form}, status=400)
