from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User, TwoFactorAuth, TrustedDevice

# Register the custom User model with the admin site
@admin.register(User)
class CustomUserAdmin(UserAdmin):
    list_display = ('email', 'username', 'first_name', 'last_name', 'is_staff', 'is_verified')
    search_fields = ('email', 'username', 'first_name', 'last_name')
    readonly_fields = ('date_joined', 'last_login')
    
    fieldsets = (
        (None, {'fields': ('email', 'username', 'password')}),
        ('Personal info', {'fields': ('first_name', 'last_name')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'is_verified', 'groups', 'user_permissions')}),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'username', 'password1', 'password2', 'is_staff', 'is_superuser'),
        }),
    )
    
    ordering = ('email',)

# Register the TwoFactorAuth model with the admin site
@admin.register(TwoFactorAuth)
class TwoFactorAuthAdmin(admin.ModelAdmin):
    list_display = ('user', 'verified', 'totp_enabled', 'totp_verified', 'preferred_method')
    list_filter = ('verified', 'totp_enabled', 'totp_verified', 'preferred_method')
    search_fields = ('user__email', 'user__username')
    readonly_fields = ('secret_key',)

# Register the TrustedDevice model with the admin site
@admin.register(TrustedDevice)
class TrustedDeviceAdmin(admin.ModelAdmin):
    list_display = ('user', 'device_name', 'created_at', 'last_used', 'is_active')
    list_filter = ('is_active', 'created_at', 'last_used')
    search_fields = ('user__email', 'user__username', 'device_name')
    readonly_fields = ('device_id', 'created_at')
