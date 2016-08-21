from django import forms
from django.core.exceptions import ValidationError

from ..users.models import CustomUser as User


class RegistrationForm(forms.ModelForm):

    class Meta:
        model = User
        fields = ['username', 'email', 'password']

        widgets = {
            'username': forms.TextInput(attrs={
                'placeholder': 'Username',
                'autocomplete': 'off',
            }),
            'email': forms.EmailInput(attrs={
                'placeholder': 'Email address',
                'autocomplete': 'off',
            }),
            'password': forms.PasswordInput(attrs={
                'placeholder': 'Password',
                'autocomplete': 'off',
            }),
        }

    def clean(self):
        # It seems that setting the username_validator in
        # CustomUser does not have any effect; therefore
        # we check the username here again
        # https://docs.djangoproject.com/en/dev/ref/contrib/auth/#django.contrib.auth.models.User.username_validator
        validator = self.instance.username_validator
        username = self.cleaned_data['username']
        m = validator.regex.match(username)
        if not m:
            raise ValidationError(message=validator.message)
