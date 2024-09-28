# admin.py
from django.contrib import admin
from .models import UserProfile, OTPVerification
from django.contrib.auth.models import User

class UserProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'is_email_verified')  # Fields to display in the admin list view
    search_fields = ('user__username', 'user__email')  # Search functionality

class OTPVerificationAdmin(admin.ModelAdmin):
    list_display = ('user','get_email', 'otp', 'expires_at')  # Fields to display in the admin list view
    search_fields = ('user__username', 'user__email', 'otp')  # Search functionality
    def get_email(self, obj):
        return obj.user.email  # Return the email of the associated user
    get_email.short_description = 'Email' 

# Register the models
admin.site.register(UserProfile, UserProfileAdmin)
admin.site.register(OTPVerification, OTPVerificationAdmin)
