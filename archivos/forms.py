from django import forms
from .models import *
from django.contrib.auth.forms import UserCreationForm as BaseUserCreationForm
from .models import CustomUser

class TaskForm(forms.ModelForm):
    class Meta:
        model = Task
        fields = ['title', 'description', 'important', 'completed']
        widgets = {

            'title' : forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Write a title'}),
            'description' : forms.Textarea(attrs={'class': 'form-control', 'placeholder': 'Write a description'}),
            'important' : forms.CheckboxInput(attrs={'class': 'form-check-input ',}),
            'completed': forms.CheckboxInput(attrs={'class': 'form-check-input '}),
        }


class CustomUserCreationForm(BaseUserCreationForm):
    class Meta(BaseUserCreationForm.Meta):
        model = CustomUser
        fields = ("username", "email", "first_name", "last_name")
    
        
