from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
import secrets
import string

class UserMFAPreference(models.Model):
    """User's MFA preferences and settings"""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='mfa_preference')
    mfa_enabled = models.BooleanField(default=False)
    backup_codes_generated = models.BooleanField(default=False)
    last_backup_codes_generated = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user.username} - MFA: {'Enabled' if self.mfa_enabled else 'Disabled'}"

class WebAuthnCredential(models.Model):
    """WebAuthn/FIDO2 credentials for YubiKey and other authenticators"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='webauthn_credentials')
    credential_id = models.TextField(unique=True)  # Base64 encoded credential ID
    public_key = models.TextField()  # Base64 encoded public key
    sign_count = models.PositiveIntegerField(default=0)
    transports = models.JSONField(default=list)  # Transport methods (usb, nfc, ble, internal)
    
    # Credential metadata
    device_name = models.CharField(max_length=100, blank=True)  # User-friendly name
    device_type = models.CharField(max_length=50, default='security-key')  # security-key, yubikey, etc.
    aaguid = models.CharField(max_length=36, blank=True)  # Authenticator Attestation GUID
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    last_used = models.DateTimeField(null=True, blank=True)
    
    # Security features
    is_primary = models.BooleanField(default=False)  # Primary authenticator
    is_active = models.BooleanField(default=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'is_active']),
            models.Index(fields=['credential_id']),
        ]

    def __str__(self):
        return f"{self.user.username} - {self.device_name or self.device_type} ({self.created_at.strftime('%Y-%m-%d')})"

    def update_last_used(self):
        """Update the last used timestamp"""
        self.last_used = timezone.now()
        self.save(update_fields=['last_used'])

class MFABackupCode(models.Model):
    """Backup codes for MFA recovery"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='mfa_backup_codes')
    code = models.CharField(max_length=10, unique=True)
    used = models.BooleanField(default=False)
    used_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['created_at']
        indexes = [
            models.Index(fields=['user', 'used']),
            models.Index(fields=['code']),
        ]

    def __str__(self):
        return f"{self.user.username} - {'Used' if self.used else 'Active'} backup code"

    @classmethod
    def generate_codes_for_user(cls, user, count=8):
        """Generate backup codes for a user"""
        # Clear existing codes
        cls.objects.filter(user=user).delete()
        
        codes = []
        for _ in range(count):
            # Generate 10-character alphanumeric code
            code = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(10))
            backup_code = cls.objects.create(user=user, code=code)
            codes.append(code)
        
        # Update user preference
        preference, created = UserMFAPreference.objects.get_or_create(user=user)
        preference.backup_codes_generated = True
        preference.last_backup_codes_generated = timezone.now()
        preference.save()
        
        return codes

    def mark_as_used(self):
        """Mark backup code as used"""
        self.used = True
        self.used_at = timezone.now()
        self.save()

class MFAChallenge(models.Model):
    """Temporary storage for MFA challenges during authentication"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='mfa_challenges')
    challenge = models.TextField()  # Base64 encoded challenge
    session_key = models.CharField(max_length=40, unique=True)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    
    # Challenge metadata
    challenge_type = models.CharField(max_length=20, choices=[
        ('webauthn', 'WebAuthn/FIDO2'),
        ('backup', 'Backup Code')
    ], default='webauthn')
    
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()  # Challenge expiration
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['session_key']),
            models.Index(fields=['user', 'expires_at']),
        ]

    def __str__(self):
        return f"{self.user.username} - {self.challenge_type} challenge"

    def is_expired(self):
        """Check if challenge is expired"""
        return timezone.now() > self.expires_at

    @classmethod
    def cleanup_expired(cls):
        """Remove expired challenges"""
        expired_challenges = cls.objects.filter(expires_at__lt=timezone.now())
        count = expired_challenges.count()
        expired_challenges.delete()
        return count

class MFAAttempt(models.Model):
    """Log of MFA authentication attempts"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='mfa_attempts')
    credential = models.ForeignKey(WebAuthnCredential, on_delete=models.SET_NULL, null=True, blank=True)
    
    # Attempt details
    attempt_type = models.CharField(max_length=20, choices=[
        ('webauthn', 'WebAuthn/FIDO2'),
        ('backup', 'Backup Code'),
        ('registration', 'Device Registration')
    ])
    
    success = models.BooleanField()
    error_message = models.TextField(blank=True)
    
    # Request context
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'created_at']),
            models.Index(fields=['success', 'created_at']),
        ]

    def __str__(self):
        return f"{self.user.username} - {self.attempt_type} ({'Success' if self.success else 'Failed'})"

class ActivityLog(models.Model):
    """Log of user activities and actions"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='activity_logs')
    
    # Activity details
    activity_type = models.CharField(max_length=50, choices=[
        ('login', 'Login'),
        ('logout', 'Logout'),
        ('mfa_enabled', 'MFA Enabled'),
        ('mfa_disabled', 'MFA Disabled'),
        ('mfa_setup', 'MFA Setup'),
        ('device_registered', 'Security Device Registered'),
        ('device_removed', 'Security Device Removed'),
        ('backup_codes_generated', 'Backup Codes Generated'),
        ('backup_code_used', 'Backup Code Used'),
        ('password_changed', 'Password Changed'),
        ('profile_updated', 'Profile Updated'),
        ('failed_login', 'Failed Login Attempt'),
        ('failed_mfa', 'Failed MFA Attempt'),
        ('session_started', 'Session Started'),
        ('session_ended', 'Session Ended'),
    ])
    
    description = models.TextField()
    details = models.JSONField(default=dict, blank=True)  # Additional activity details
    
    # Request context
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    session_id = models.CharField(max_length=40, blank=True)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'created_at']),
            models.Index(fields=['activity_type', 'created_at']),
            models.Index(fields=['ip_address', 'created_at']),
        ]
        verbose_name = 'Activity Log'
        verbose_name_plural = 'Activity Logs'

    def __str__(self):
        return f"{self.user.username} - {self.get_activity_type_display()} ({self.created_at.strftime('%Y-%m-%d %H:%M')})"

    @classmethod
    def log_activity(cls, user, activity_type, description, **kwargs):
        """Convenience method to log an activity"""
        return cls.objects.create(
            user=user,
            activity_type=activity_type,
            description=description,
            details=kwargs.get('details', {}),
            ip_address=kwargs.get('ip_address'),
            user_agent=kwargs.get('user_agent'),
            session_id=kwargs.get('session_id')
        )

    def get_icon_class(self):
        """Get FontAwesome icon class for the activity type"""
        icon_map = {
            'login': 'fas fa-sign-in-alt',
            'logout': 'fas fa-sign-out-alt',
            'mfa_enabled': 'fas fa-shield-alt',
            'mfa_disabled': 'fas fa-shield-alt',
            'mfa_setup': 'fas fa-mobile-alt',
            'device_registered': 'fas fa-key',
            'device_removed': 'fas fa-trash',
            'backup_codes_generated': 'fas fa-download',
            'backup_code_used': 'fas fa-key',
            'password_changed': 'fas fa-lock',
            'profile_updated': 'fas fa-user-edit',
            'failed_login': 'fas fa-exclamation-triangle',
            'failed_mfa': 'fas fa-exclamation-triangle',
            'session_started': 'fas fa-play',
            'session_ended': 'fas fa-stop',
        }
        return icon_map.get(self.activity_type, 'fas fa-info-circle')

    def get_status_class(self):
        """Get CSS class for activity status"""
        status_map = {
            'login': 'success',
            'logout': 'info',
            'mfa_enabled': 'success',
            'mfa_disabled': 'warning',
            'mfa_setup': 'success',
            'device_registered': 'success',
            'device_removed': 'warning',
            'backup_codes_generated': 'success',
            'backup_code_used': 'info',
            'password_changed': 'success',
            'profile_updated': 'info',
            'failed_login': 'error',
            'failed_mfa': 'error',
            'session_started': 'success',
            'session_ended': 'info',
        }
        return status_map.get(self.activity_type, 'info')

    def get_time_ago(self):
        """Get human-readable time ago string"""
        from django.utils import timezone
        from datetime import timedelta
        
        now = timezone.now()
        diff = now - self.created_at
        
        if diff.days > 0:
            return f"{diff.days} day{'s' if diff.days != 1 else ''} ago"
        elif diff.seconds >= 3600:
            hours = diff.seconds // 3600
            return f"{hours} hour{'s' if hours != 1 else ''} ago"
        elif diff.seconds >= 60:
            minutes = diff.seconds // 60
            return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
        else:
            return "Just now"
