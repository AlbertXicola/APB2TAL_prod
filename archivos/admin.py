from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser
from  .models import *
# Register your models here.

class TaskAdmin(admin.ModelAdmin):
    readonly_fields = ("created", )

admin.site.register(Task, TaskAdmin)

class CustomUserAdmin(UserAdmin):
    search_fields = ['username', 'email']  # Agrega los campos que deseas incluir en la búsqueda

# Registra el administrador para el modelo CustomUser
admin.site.register(CustomUser, CustomUserAdmin)