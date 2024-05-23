from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser

class CustomUserAdmin(UserAdmin):
    search_fields = ['username', 'email']  # Agrega los campos que deseas incluir en la búsqueda

# Registra el administrador para el modelo CustomUser
admin.site.register(CustomUser, CustomUserAdmin)