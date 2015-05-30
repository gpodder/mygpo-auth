from django.contrib.auth.forms import AuthenticationForm
from django import forms


class MyAuthenticationForm(AuthenticationForm):

    # set attributes on the username field
    username = forms.CharField(
        label='Username',
        widget=forms.TextInput(attrs={
            'placeholder': 'Username',
            'autofocus': 'autofocus',
        })
    )

    password = forms.CharField(
        label='Password',
        widget=forms.PasswordInput(attrs={
            'placeholder': 'Password',
        })
    )
