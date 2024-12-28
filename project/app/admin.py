from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User

# Register your models here.

class CustomUserAdmin(UserAdmin):
    model = User
    list_display = ('id','username', 'email', 'first_name', 'last_name','password')  # Customize the fields you want to display
    list_filter = ('is_staff', 'is_active')
    search_fields = ('username', 'email', 'first_name', 'last_name')

# Register the custom user model with the admin interface
admin.site.register(User, CustomUserAdmin)
