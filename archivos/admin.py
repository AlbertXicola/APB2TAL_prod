from django.contrib import admin
from  .models import *
# Register your models here.

class TaskAdmin(admin.ModelAdmin):
    readonly_fields = ("created", )
    
admin.site.register(Task, TaskAdmin)


from django.contrib import admin
from .models import CustomUser

@admin.register(CustomUser)
class CustomUserAdmin(admin.ModelAdmin):
    pass