from django.contrib import admin
from .models import (
    UserMFAPreference, 
    WebAuthnCredential, 
    MFABackupCode, 
    MFAChallenge, 
    MFAAttempt
)

@admin.register(UserMFAPreference)
class UserMFAPreferenceAdmin(admin.ModelAdmin):
    list_display = ('user', 'mfa_enabled', 'backup_codes_generated', 'created_at', 'updated_at')
    list_filter = ('mfa_enabled', 'backup_codes_generated', 'created_at')
    search_fields = ('user__username', 'user__email')
    readonly_fields = ('created_at', 'updated_at')
    
    fieldsets = (
        (None, {
            'fields': ('user', 'mfa_enabled')
        }),
        ('Backup Codes', {
            'fields': ('backup_codes_generated', 'last_backup_codes_generated')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )

@admin.register(WebAuthnCredential)
class WebAuthnCredentialAdmin(admin.ModelAdmin):
    list_display = ('user', 'device_name', 'device_type', 'is_primary', 'is_active', 'created_at', 'last_used')
    list_filter = ('device_type', 'is_primary', 'is_active', 'created_at', 'last_used')
    search_fields = ('user__username', 'device_name', 'device_type')
    readonly_fields = ('credential_id', 'public_key', 'sign_count', 'aaguid', 'created_at', 'last_used')
    
    fieldsets = (
        (None, {
            'fields': ('user', 'device_name', 'device_type', 'is_primary', 'is_active')
        }),
        ('Credential Data', {
            'fields': ('credential_id', 'public_key', 'sign_count', 'transports', 'aaguid'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'last_used'),
            'classes': ('collapse',)
        })
    )
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('user')

@admin.register(MFABackupCode)
class MFABackupCodeAdmin(admin.ModelAdmin):
    list_display = ('user', 'code_masked', 'used', 'created_at', 'used_at')
    list_filter = ('used', 'created_at', 'used_at')
    search_fields = ('user__username', 'code')
    readonly_fields = ('code', 'created_at', 'used_at')
    
    def code_masked(self, obj):
        """Show masked version of the code for security"""
        if obj.code:
            return f"{obj.code[:2]}{'*' * 6}{obj.code[-2:]}"
        return "No code"
    code_masked.short_description = "Code (Masked)"
    
    fieldsets = (
        (None, {
            'fields': ('user', 'code', 'used')
        }),
        ('Usage', {
            'fields': ('created_at', 'used_at'),
            'classes': ('collapse',)
        })
    )
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('user')

@admin.register(MFAChallenge)
class MFAChallengeAdmin(admin.ModelAdmin):
    list_display = ('user', 'challenge_type', 'session_key', 'ip_address', 'created_at', 'expires_at', 'is_expired')
    list_filter = ('challenge_type', 'created_at', 'expires_at')
    search_fields = ('user__username', 'session_key', 'ip_address')
    readonly_fields = ('challenge', 'created_at', 'expires_at')
    
    def is_expired(self, obj):
        return obj.is_expired()
    is_expired.boolean = True
    is_expired.short_description = "Expired"
    
    fieldsets = (
        (None, {
            'fields': ('user', 'challenge_type', 'session_key')
        }),
        ('Request Info', {
            'fields': ('ip_address', 'user_agent'),
            'classes': ('collapse',)
        }),
        ('Challenge Data', {
            'fields': ('challenge', 'created_at', 'expires_at'),
            'classes': ('collapse',)
        })
    )
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('user')

@admin.register(MFAAttempt)
class MFAAttemptAdmin(admin.ModelAdmin):
    list_display = ('user', 'attempt_type', 'success', 'credential', 'ip_address', 'created_at')
    list_filter = ('attempt_type', 'success', 'created_at')
    search_fields = ('user__username', 'ip_address', 'error_message')
    readonly_fields = ('user', 'credential', 'attempt_type', 'success', 'error_message', 'ip_address', 'user_agent', 'created_at')
    
    fieldsets = (
        (None, {
            'fields': ('user', 'attempt_type', 'success', 'credential')
        }),
        ('Request Info', {
            'fields': ('ip_address', 'user_agent'),
            'classes': ('collapse',)
        }),
        ('Error Info', {
            'fields': ('error_message',),
            'classes': ('collapse',)
        }),
        ('Timestamp', {
            'fields': ('created_at',),
            'classes': ('collapse',)
        })
    )
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('user', 'credential')
    
    def has_add_permission(self, request):
        return False  # Don't allow manual creation of attempts
    
    def has_change_permission(self, request, obj=None):
        return False  # Don't allow editing attempts

# Admin actions for bulk operations
def cleanup_expired_challenges(modeladmin, request, queryset):
    """Clean up expired MFA challenges"""
    count = MFAChallenge.cleanup_expired()
    modeladmin.message_user(request, f"Cleaned up {count} expired challenges.")
cleanup_expired_challenges.short_description = "Clean up expired challenges"

def disable_mfa_for_users(modeladmin, request, queryset):
    """Disable MFA for selected users"""
    count = 0
    for preference in queryset:
        if preference.mfa_enabled:
            preference.mfa_enabled = False
            preference.save()
            count += 1
    modeladmin.message_user(request, f"Disabled MFA for {count} users.")
disable_mfa_for_users.short_description = "Disable MFA for selected users"

# Add actions to the UserMFAPreference admin
UserMFAPreferenceAdmin.actions = [disable_mfa_for_users]
MFAChallengeAdmin.actions = [cleanup_expired_challenges]
