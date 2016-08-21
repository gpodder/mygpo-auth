from django import forms
from django.contrib.auth import get_user_model

User = get_user_model()


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
