from django.shortcuts import render, redirect
from django.contrib.auth import login, logout, authenticate, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import HttpResponse, JsonResponse
from django.views.decorators.http import require_http_methods, require_POST
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.models import User
from django.utils import timezone
from django.conf import settings
from django.urls import reverse
import logging
import json
import base64
import xml.etree.ElementTree as ET
from datetime import timedelta
import os

# Set up logging first
logger = logging.getLogger(__name__)

# Import MFA models
from .models import (
    UserMFAPreference, 
    WebAuthnCredential, 
    MFABackupCode, 
    MFAChallenge, 
    MFAAttempt,
    ActivityLog
)

# WebAuthn imports
try:
    from webauthn import generate_registration_options, verify_registration_response
    from webauthn import generate_authentication_options, verify_authentication_response
    from webauthn.helpers.structs import (
        PublicKeyCredentialCreationOptions,
        PublicKeyCredentialRequestOptions,
        AuthenticatorSelectionCriteria,
        UserVerificationRequirement,
        AttestationConveyancePreference,
        AuthenticatorAttachment,
        PublicKeyCredentialDescriptor,
        PublicKeyCredentialType
    )
    from webauthn.helpers.cose import COSEAlgorithmIdentifier
    WEBAUTHN_AVAILABLE = True
except ImportError:
    WEBAUTHN_AVAILABLE = False
    logger.warning("WebAuthn library not available. MFA functionality will be limited.")

# Get client IP helper
def get_client_ip(request):
    """Get client IP address from request"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def get_ad_user_context(user):
    """Get Active Directory user context for templates"""
    try:
        ad_user_info = get_ad_user_info(user.username)
        if ad_user_info:
            return {
                'ad_email': ad_user_info.get('mail', ''),
                'ad_display_name': ad_user_info.get('displayName', ''),
            }
        else:
            return {
                'ad_email': user.email if hasattr(user, 'email') else '',
                'ad_display_name': user.get_full_name(),
            }
    except Exception as e:
        logger.error(f"Error retrieving AD user info for {user.username}: {str(e)}")
        return {
            'ad_email': user.email if hasattr(user, 'email') else '',
            'ad_display_name': user.get_full_name(),
        }

# Original views (keeping existing functionality)
@login_required
def home(request):
    """View for the home page (only accessible when logged in)"""
    saml_attributes = request.session.get('samlUserdata', {})
    # The attribute name for groups can vary. Common names are 'groups', 'memberOf', or a full URN.
    # We'll check for a few common ones here.
    group_attribute_keys = [
        'http://schemas.microsoft.com/ws/2008/06/identity/claims/groups',
        'groups',
        'memberOf'
    ]
    user_groups = []
    for key in group_attribute_keys:
        if key in saml_attributes:
            user_groups = saml_attributes.get(key, [])
            break

    # Get MFA status
    mfa_preference = getattr(request.user, 'mfa_preference', None)
    mfa_enabled = mfa_preference.mfa_enabled if mfa_preference else False
    webauthn_credentials = request.user.webauthn_credentials.filter(is_active=True).count()

    # Get recent activities (last 3 for home page)
    recent_activities = request.user.activity_logs.all()[:3]

    # Get current user info from Active Directory for consistent display
    ad_context = get_ad_user_context(request.user)

    context = {
        'saml_attributes': saml_attributes,
        'saml_attributes_json': json.dumps(saml_attributes),  # Add this line
        'user_groups': user_groups,
        'mfa_enabled': mfa_enabled,
        'webauthn_credentials_count': webauthn_credentials,
        'recent_activities': recent_activities,
        **ad_context,  # Include AD email and display name
    }
    return render(request, 'authentication/home.html', context)

def auth_choice(request):
    """Authentication method choice page"""
    if request.user.is_authenticated:
        return redirect('authentication:home')
    
    return render(request, 'authentication/auth_choice.html')

def standard_login(request):
    """Standard Django authentication login"""
    if request.user.is_authenticated:
        return redirect('authentication:home')
    
    # Handle form submission
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        remember_me = request.POST.get('rememberMe') == 'on'
        
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            # Check if user has MFA enabled
            mfa_preference = getattr(user, 'mfa_preference', None)
            if mfa_preference and mfa_preference.mfa_enabled:
                # Store user in session for MFA verification
                request.session['mfa_user_id'] = user.id
                request.session['mfa_remember_me'] = remember_me
                request.session['mfa_required'] = True
                
                return redirect('authentication:mfa_challenge')
            else:
                # Standard login without MFA
                login(request, user, backend='django.contrib.auth.backends.ModelBackend')
                
                # Log successful login
                ActivityLog.log_activity(
                    user=user,
                    activity_type='login',
                    description='User logged in successfully via standard authentication',
                    ip_address=get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    session_id=request.session.session_key,
                    details={'remember_me': remember_me, 'mfa_required': False, 'auth_method': 'standard'}
                )
            
            # Set session expiry based on remember me
            if not remember_me:
                # Session expires when browser closes
                request.session.set_expiry(0)
            
            return redirect('authentication:home')
        else:
            messages.error(request, "Invalid username or password.")
    
    return render(request, 'authentication/standard_login.html')

def login_view(request):
    """Main login view - handles both auth choice and direct login"""
    if request.user.is_authenticated:
        return redirect('authentication:home')
    
    # If this is a POST request, handle login directly
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        remember_me = request.POST.get('rememberMe') == 'on'
        
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            login(request, user)
            
            # Handle remember me functionality
            if remember_me:
                request.session.set_expiry(1209600)  # 2 weeks
            else:
                request.session.set_expiry(0)
            
            return redirect('authentication:home')
        else:
            messages.error(request, "Invalid username or password.")
            return render(request, 'authentication/login.html')
    
    # For GET requests, show the auth choice page
    return render(request, 'authentication/auth_choice.html')

def standard_register(request):
    """User registration for standard authentication"""
    if request.user.is_authenticated:
        return redirect('authentication:home')
    
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        email = request.POST.get('email', '').strip()
        password1 = request.POST.get('password1', '')
        password2 = request.POST.get('password2', '')
        first_name = request.POST.get('first_name', '').strip()
        last_name = request.POST.get('last_name', '').strip()
        
        # Validation
        errors = []
        
        if not username:
            errors.append('Username is required.')
        elif len(username) < 3:
            errors.append('Username must be at least 3 characters long.')
        elif User.objects.filter(username=username).exists():
            errors.append('Username already exists.')
        
        if not email:
            errors.append('Email is required.')
        elif User.objects.filter(email=email).exists():
            errors.append('Email already exists.')
        else:
            # Validate email format
            import re
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, email):
                errors.append('Please enter a valid email address.')
        
        if not password1:
            errors.append('Password is required.')
        elif len(password1) < 8:
            errors.append('Password must be at least 8 characters long.')
        elif password1 != password2:
            errors.append('Passwords do not match.')
        
        if not first_name:
            errors.append('First name is required.')
        
        if not last_name:
            errors.append('Last name is required.')
        
        if errors:
            for error in errors:
                messages.error(request, error)
        else:
            try:
                # Create user
                user = User.objects.create_user(
                    username=username,
                    email=email,
                    password=password1,
                    first_name=first_name,
                    last_name=last_name
                )
                
                # Log registration activity
                # Note: During registration, there might not be a session yet
                session_key = request.session.session_key or 'registration'
                ActivityLog.log_activity(
                    user=user,
                    activity_type='user_registered',
                    description='User registered via standard authentication',
                    ip_address=get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    session_id=session_key,
                    details={'auth_method': 'standard', 'email': email}
                )
                
                messages.success(request, 'Account created successfully! You can now log in.')
                return redirect('authentication:standard_login')
                
            except Exception as e:
                logger.error(f"Error creating user: {str(e)}")
                messages.error(request, 'An error occurred while creating your account. Please try again.')
    
    return render(request, 'authentication/standard_register.html')

def password_reset_request(request):
    """Password reset request"""
    if request.user.is_authenticated:
        return redirect('authentication:home')
    
    if request.method == 'POST':
        email = request.POST.get('email', '').strip()
        
        if not email:
            messages.error(request, 'Email address is required.')
        else:
            try:
                user = User.objects.get(email=email)
                
                # Generate reset token (simple implementation)
                import secrets
                import hashlib
                token = secrets.token_urlsafe(32)
                
                # Store token in session (in production, use database or cache)
                request.session[f'password_reset_token_{user.id}'] = token
                request.session[f'password_reset_user_{user.id}'] = user.id
                request.session[f'password_reset_expiry_{user.id}'] = str(timezone.now() + timedelta(hours=1))
                
                # Log password reset request
                # Note: During password reset request, there might not be a session yet
                session_key = request.session.session_key or 'password_reset_request'
                ActivityLog.log_activity(
                    user=user,
                    activity_type='password_reset_requested',
                    description='Password reset requested',
                    ip_address=get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    session_id=session_key,
                    details={'email': email, 'auth_method': 'standard'}
                )
                
                messages.success(request, f'Password reset instructions have been sent to {email}. Please check your email.')
                return redirect('authentication:standard_login')
                
            except User.DoesNotExist:
                messages.error(request, 'No account found with that email address.')
            except Exception as e:
                logger.error(f"Error processing password reset request: {str(e)}")
                messages.error(request, 'An error occurred. Please try again.')
    
    return render(request, 'authentication/password_reset_request.html')

def password_reset_confirm(request, user_id, token):
    """Password reset confirmation"""
    if request.user.is_authenticated:
        return redirect('authentication:home')
    
    # Verify token
    stored_token = request.session.get(f'password_reset_token_{user_id}')
    stored_user_id = request.session.get(f'password_reset_user_{user_id}')
    stored_expiry = request.session.get(f'password_reset_expiry_{user_id}')
    
    if not stored_token or not stored_user_id or not stored_expiry:
        messages.error(request, 'Invalid or expired password reset link.')
        return redirect('authentication:password_reset_request')
    
    # Check expiry
    try:
        expiry_time = timezone.datetime.fromisoformat(stored_expiry)
        if timezone.now() > expiry_time:
            messages.error(request, 'Password reset link has expired.')
            return redirect('authentication:password_reset_request')
    except:
        messages.error(request, 'Invalid password reset link.')
        return redirect('authentication:password_reset_request')
    
    if stored_token != token or int(stored_user_id) != int(user_id):
        messages.error(request, 'Invalid password reset link.')
        return redirect('authentication:password_reset_request')
    
    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        messages.error(request, 'User not found.')
        return redirect('authentication:password_reset_request')
    
    if request.method == 'POST':
        password1 = request.POST.get('password1', '')
        password2 = request.POST.get('password2', '')
        
        if not password1:
            messages.error(request, 'Password is required.')
        elif len(password1) < 8:
            messages.error(request, 'Password must be at least 8 characters long.')
        elif password1 != password2:
            messages.error(request, 'Passwords do not match.')
        else:
            try:
                # Update password
                user.set_password(password1)
                user.save()
                
                # Clear reset tokens
                for key in list(request.session.keys()):
                    if key.startswith(f'password_reset_{user_id}'):
                        del request.session[key]
                
                # Log password reset
                # Note: During password reset confirm, there might not be a session yet
                session_key = request.session.session_key or 'password_reset_confirm'
                ActivityLog.log_activity(
                    user=user,
                    activity_type='password_reset_completed',
                    description='Password reset completed',
                    ip_address=get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    session_id=session_key,
                    details={'auth_method': 'standard'}
                )
                
                messages.success(request, 'Password has been reset successfully. You can now log in.')
                return redirect('authentication:standard_login')
                
            except Exception as e:
                logger.error(f"Error resetting password: {str(e)}")
                messages.error(request, 'An error occurred while resetting your password. Please try again.')
    
    return render(request, 'authentication/password_reset_confirm.html', {'user': user})

# MFA Views
@login_required
def mfa_setup(request):
    """MFA setup page"""
    if not WEBAUTHN_AVAILABLE:
        messages.error(request, "MFA functionality is not available. Please contact your administrator.")
        return redirect('authentication:home')
    
    preference, created = UserMFAPreference.objects.get_or_create(user=request.user)
    credentials = request.user.webauthn_credentials.filter(is_active=True)
    
    # Get TOTP devices
    from .models import TOTPDevice
    totp_devices = request.user.totp_devices.filter(is_active=True)
    
    # Check if user has any active credentials (WebAuthn or TOTP)
    has_webauthn = credentials.exists()
    has_totp = totp_devices.filter(confirmed=True).exists()
    has_any_credentials = has_webauthn or has_totp
    
    # Check if we should auto-trigger backup codes generation
    auto_trigger_backup = request.GET.get('action') == 'backup_codes'
    
    # Get AD context for consistent email display
    ad_context = get_ad_user_context(request.user)
    
    context = {
        'mfa_enabled': preference.mfa_enabled,
        'credentials': credentials,
        'totp_devices': totp_devices,
        'backup_codes_generated': preference.backup_codes_generated,
        'webauthn_available': WEBAUTHN_AVAILABLE,
        'has_any_credentials': has_any_credentials,  # Add this for template logic
        'auto_trigger_backup': auto_trigger_backup,  # Add this for auto-triggering
        **ad_context,  # Include AD email and display name
    }
    return render(request, 'authentication/mfa_setup.html', context)

@login_required
@require_POST
def mfa_enable(request):
    """Enable MFA for user"""
    from .models import TOTPDevice
    
    preference, created = UserMFAPreference.objects.get_or_create(user=request.user)
    
    # Check if user has at least one active credential (WebAuthn or TOTP)
    has_webauthn = request.user.webauthn_credentials.filter(is_active=True).exists()
    has_totp = request.user.totp_devices.filter(is_active=True, confirmed=True).exists()
    
    if not has_webauthn and not has_totp:
        messages.error(request, "You must register at least one security key or authenticator app before enabling MFA.")
        return redirect('authentication:mfa_setup')
    
    preference.mfa_enabled = True
    preference.save()
    
    messages.success(request, "Multi-Factor Authentication has been enabled for your account.")
    return redirect('authentication:mfa_setup')

@login_required
@require_POST
def mfa_disable(request):
    """Disable MFA for user"""
    preference, created = UserMFAPreference.objects.get_or_create(user=request.user)
    preference.mfa_enabled = False
    preference.save()
    
    messages.warning(request, "Multi-Factor Authentication has been disabled for your account.")
    return redirect('authentication:mfa_setup')

@login_required
@require_POST
def mfa_toggle(request):
    """Toggle MFA status via AJAX"""
    try:
        from .models import TOTPDevice
        
        preference, created = UserMFAPreference.objects.get_or_create(user=request.user)
        
        if preference.mfa_enabled:
            # Disable MFA
            preference.mfa_enabled = False
            preference.save()
            
            # Log the activity
            ActivityLog.log_activity(
                user=request.user,
                activity_type='mfa_disabled',
                description='Multi-Factor Authentication was disabled',
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                session_id=request.session.session_key
            )
            
            return JsonResponse({
                'success': True,
                'mfa_enabled': False,
                'message': 'Multi-Factor Authentication has been disabled.'
            })
        else:
            # Enable MFA - check if user has credentials
            has_webauthn = request.user.webauthn_credentials.filter(is_active=True).exists()
            has_totp = request.user.totp_devices.filter(is_active=True, confirmed=True).exists()
            
            if not has_webauthn and not has_totp:
                return JsonResponse({
                    'success': False,
                    'error': 'You must register at least one security key or authenticator app before enabling MFA.',
                    'redirect_url': reverse('authentication:mfa_setup')
                }, status=400)
            
            preference.mfa_enabled = True
            preference.save()
            
            # Log the activity
            ActivityLog.log_activity(
                user=request.user,
                activity_type='mfa_enabled',
                description='Multi-Factor Authentication was enabled',
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                session_id=request.session.session_key
            )
            
            return JsonResponse({
                'success': True,
                'mfa_enabled': True,
                'message': 'Multi-Factor Authentication has been enabled.'
            })
            
    except Exception as e:
        logger.error(f"Error toggling MFA: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': 'An error occurred while updating MFA settings.'
        }, status=500)

@login_required
def mfa_register_begin(request):
    """Begin WebAuthn registration process"""
    if not WEBAUTHN_AVAILABLE:
        return JsonResponse({'error': 'WebAuthn not available'}, status=400)
    
    try:
        # Get WebAuthn settings
        rp_id = getattr(settings, 'WEBAUTHN_RP_ID', request.get_host().split(':')[0])
        rp_name = getattr(settings, 'WEBAUTHN_RP_NAME', 'SecureAuth')
        
        # Debug logging
        logger.info(f"WebAuthn registration - RP_ID: {rp_id}, Host: {request.get_host()}, Is_Secure: {request.is_secure()}")
        
        # Generate registration options
        registration_options = generate_registration_options(
            rp_id=rp_id,
            rp_name=rp_name,
            user_id=str(request.user.id).encode(),
            user_name=request.user.username,
            user_display_name=request.user.get_full_name() or request.user.username,
            exclude_credentials=[
                PublicKeyCredentialDescriptor(
                    id=base64.b64decode(cred.credential_id)
                ) for cred in request.user.webauthn_credentials.filter(is_active=True)
            ],
            authenticator_selection=AuthenticatorSelectionCriteria(
                authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM,
                user_verification=UserVerificationRequirement.PREFERRED
            ),
            attestation=AttestationConveyancePreference.DIRECT,
            supported_pub_key_algs=[
                COSEAlgorithmIdentifier.ECDSA_SHA_256,
                COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
                COSEAlgorithmIdentifier.EDDSA,
            ]
        )
        
        # Store challenge in session (base64 encoded for JSON serialization)
        request.session['registration_challenge'] = base64.b64encode(registration_options.challenge).decode()
        request.session['registration_user_id'] = base64.b64encode(registration_options.user.id).decode()
        
        # Convert to JSON-serializable format
        options_json = {
            'challenge': base64.b64encode(registration_options.challenge).decode(),
            'rp': {
                'name': registration_options.rp.name,
                'id': registration_options.rp.id,
            },
            'user': {
                'id': base64.b64encode(registration_options.user.id).decode(),
                'name': registration_options.user.name,
                'displayName': registration_options.user.display_name,
            },
            'pubKeyCredParams': [
                {'alg': param.alg.value, 'type': param.type} 
                for param in registration_options.pub_key_cred_params
            ],
            'timeout': registration_options.timeout,
            'excludeCredentials': [
                {
                    'id': base64.b64encode(cred.id).decode(),
                    'type': cred.type,
                    'transports': cred.transports or []
                } for cred in registration_options.exclude_credentials
            ] if registration_options.exclude_credentials else [],
            'authenticatorSelection': {
                'authenticatorAttachment': registration_options.authenticator_selection.authenticator_attachment.value if registration_options.authenticator_selection.authenticator_attachment else None,
                'userVerification': registration_options.authenticator_selection.user_verification.value,
                'requireResidentKey': registration_options.authenticator_selection.require_resident_key,
            },
            'attestation': registration_options.attestation.value,
        }
        
        return JsonResponse({'options': options_json})
        
    except Exception as e:
        logger.error(f"Error generating registration options: {str(e)}")
        return JsonResponse({'error': 'Failed to generate registration options'}, status=500)

@login_required
@require_POST
def mfa_register_complete(request):
    """Complete WebAuthn registration"""
    if not WEBAUTHN_AVAILABLE:
        return JsonResponse({'error': 'WebAuthn not available'}, status=400)
    
    try:
        # Log the request for debugging
        logger.info(f"WebAuthn registration completion - User: {request.user.username}")
        
        data = json.loads(request.body)
        credential = data.get('credential')
        device_name = data.get('deviceName', 'Security Key')
        
        if not credential:
            logger.error("No credential provided in request")
            return JsonResponse({'error': 'No credential provided'}, status=400)
        
        # Get stored challenge
        challenge_b64 = request.session.get('registration_challenge')
        registration_user_id = request.session.get('registration_user_id')
        
        if not challenge_b64:
            logger.error("No registration challenge found in session")
            return JsonResponse({'error': 'No registration challenge found'}, status=400)
        
        # Decode challenge from base64
        challenge = base64.b64decode(challenge_b64)
        
        # Get WebAuthn verification parameters
        expected_rp_id = getattr(settings, 'WEBAUTHN_RP_ID', request.get_host().split(':')[0])
        expected_origin = getattr(settings, 'WEBAUTHN_ORIGIN', f"https://{request.get_host()}" if request.is_secure() else f"http://{request.get_host()}")
        
        # Verify registration response
        try:
            verification = verify_registration_response(
                credential=credential,
                expected_challenge=challenge,
                expected_origin=expected_origin,
                expected_rp_id=expected_rp_id,
            )
            
            # If we get here, verification was successful (no exception raised)
            logger.info("WebAuthn registration verification successful")
            
            # Store credential in database
            webauthn_credential = WebAuthnCredential.objects.create(
                user=request.user,
                credential_id=base64.b64encode(verification.credential_id).decode(),
                public_key=base64.b64encode(verification.credential_public_key).decode(),
                device_name=device_name,
                aaguid=str(verification.aaguid) if verification.aaguid else '',
                sign_count=verification.sign_count,
                device_type='yubikey' if 'yubico' in str(verification.aaguid).lower() else 'security-key'
            )
            
            # Log successful registration
            MFAAttempt.objects.create(
                user=request.user,
                credential=webauthn_credential,
                attempt_type='registration',
                success=True,
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            
            # Log activity
            ActivityLog.log_activity(
                user=request.user,
                activity_type='device_registered',
                description=f'Security device "{device_name}" was registered',
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                session_id=request.session.session_key,
                details={'device_name': device_name, 'device_type': webauthn_credential.device_type}
            )
            
            # Clear session data
            del request.session['registration_challenge']
            if 'registration_user_id' in request.session:
                del request.session['registration_user_id']
            
            logger.info(f"WebAuthn registration completed successfully for user {request.user.username}")
            
            return JsonResponse({
                'success': True,
                'message': f'Successfully registered {device_name}',
                'credential_id': webauthn_credential.id
            })
            
        except Exception as verification_error:
            # WebAuthn verification failed
            logger.error(f"WebAuthn registration verification failed: {str(verification_error)}")
            
            # Log failed registration
            MFAAttempt.objects.create(
                user=request.user,
                attempt_type='registration',
                success=False,
                error_message=f'WebAuthn verification failed: {str(verification_error)}',
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            
            return JsonResponse({
                'error': f'Registration verification failed: {str(verification_error)}'
            }, status=400)
        
    except Exception as e:
        logger.error(f"Error completing registration: {str(e)}")
        logger.error(f"Exception type: {type(e).__name__}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        
        # Try to log failed attempt if possible
        try:
            MFAAttempt.objects.create(
                user=request.user,
                attempt_type='registration',
                success=False,
                error_message=str(e),
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
        except Exception as log_error:
            logger.error(f"Failed to log MFA attempt: {log_error}")
            
        return JsonResponse({'error': f'Registration failed: {str(e)}'}, status=500)

def mfa_challenge(request):
    """MFA challenge page"""
    if not request.session.get('mfa_required'):
        return redirect('authentication:login')
    
    user_id = request.session.get('mfa_user_id')
    if not user_id:
        return redirect('authentication:login')
    
    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return redirect('authentication:login')
    
    credentials = user.webauthn_credentials.filter(is_active=True)
    
    # Get TOTP devices
    from .models import TOTPDevice
    totp_devices = user.totp_devices.filter(is_active=True, confirmed=True)
    
    context = {
        'user': user,
        'credentials': credentials,
        'totp_devices': totp_devices,
        'webauthn_available': WEBAUTHN_AVAILABLE,
    }
    return render(request, 'authentication/mfa_challenge.html', context)

def mfa_authenticate_begin(request):
    """Begin WebAuthn authentication"""
    if not WEBAUTHN_AVAILABLE:
        logger.error("WebAuthn not available")
        return JsonResponse({'error': 'WebAuthn not available'}, status=400)
    
    if not request.session.get('mfa_required'):
        logger.error("MFA not required in session")
        return JsonResponse({'error': 'MFA not required'}, status=400)
    
    user_id = request.session.get('mfa_user_id')
    if not user_id:
        logger.error("No user ID in session for MFA")
        return JsonResponse({'error': 'No user for MFA'}, status=400)
    
    try:
        user = User.objects.get(id=user_id)
        credentials = user.webauthn_credentials.filter(is_active=True)
        
        if not credentials.exists():
            logger.error("No registered credentials for user")
            return JsonResponse({'error': 'No registered credentials'}, status=400)
        
        # Generate authentication options
        rp_id = getattr(settings, 'WEBAUTHN_RP_ID', request.get_host().split(':')[0])
        
        allow_credentials = []
        for cred in credentials:
            try:
                decoded_id = base64.b64decode(cred.credential_id)
                allow_credentials.append(
                    PublicKeyCredentialDescriptor(id=decoded_id)
                )
            except Exception as decode_error:
                logger.error(f"Failed to decode credential {cred.device_name}: {decode_error}")
        
        authentication_options = generate_authentication_options(
            rp_id=rp_id,
            allow_credentials=allow_credentials,
            user_verification=UserVerificationRequirement.PREFERRED,
        )
        
        # Store challenge in database (more secure than session for auth)
        # Clean up expired challenges
        MFAChallenge.objects.filter(user=user, expires_at__lt=timezone.now()).delete()
        
        # Clean up any existing challenges for this session (to avoid unique constraint violation)
        session_key = request.session.session_key or ''
        if session_key:
            existing_challenges = MFAChallenge.objects.filter(session_key=session_key)
            if existing_challenges.exists():
                existing_challenges.delete()
        
        # Also clean up any existing challenges for this user (as additional safety)
        user_challenges = MFAChallenge.objects.filter(user=user, challenge_type='webauthn')
        if user_challenges.exists():
            user_challenges.delete()
        
        mfa_challenge = MFAChallenge.objects.create(
            user=user,
            challenge=base64.b64encode(authentication_options.challenge).decode(),
            session_key=session_key,
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            challenge_type='webauthn',
            expires_at=timezone.now() + timedelta(minutes=5)
        )
        
        # Convert to JSON-serializable format
        try:
            options_json = {
                'challenge': base64.b64encode(authentication_options.challenge).decode(),
                'timeout': authentication_options.timeout,
                'rpId': authentication_options.rp_id,
                'allowCredentials': [
                    {
                        'id': base64.b64encode(cred.id).decode(),
                        'type': cred.type,
                        'transports': cred.transports or []
                    } for cred in authentication_options.allow_credentials
                ] if authentication_options.allow_credentials else [],
                'userVerification': authentication_options.user_verification.value,
            }
            
            logger.info(f"WebAuthn authentication options generated for user {user.username}")
            
            return JsonResponse({'options': options_json})
            
        except Exception as json_error:
            logger.error(f"JSON conversion failed: {json_error}")
            return JsonResponse({'error': f'JSON conversion failed: {str(json_error)}'}, status=500)
        
    except User.DoesNotExist:
        logger.error(f"User {user_id} does not exist")
        return JsonResponse({'error': 'User not found'}, status=400)
        
    except Exception as e:
        logger.error(f"Error generating authentication options: {str(e)}")
        return JsonResponse({'error': f'Failed to generate authentication options: {str(e)}'}, status=500)

@require_POST
def mfa_authenticate_complete(request):
    """Complete WebAuthn authentication"""
    import base64  # Import at function level to ensure availability
    
    if not WEBAUTHN_AVAILABLE:
        logger.error("WebAuthn not available")
        return JsonResponse({'error': 'WebAuthn not available'}, status=400)
    
    if not request.session.get('mfa_required'):
        logger.error("MFA not required in session")
        return JsonResponse({'error': 'MFA not required'}, status=400)
    
    user_id = request.session.get('mfa_user_id')
    if not user_id:
        logger.error("No user ID in session for MFA")
        return JsonResponse({'error': 'No user for MFA'}, status=400)
    
    try:
        data = json.loads(request.body)
        credential_response = data.get('credential')
        
        if not credential_response:
            logger.error("No credential provided")
            return JsonResponse({'error': 'No credential provided'}, status=400)
        
        user = User.objects.get(id=user_id)
        
        # Get the challenge
        challenge_obj = MFAChallenge.objects.filter(
            user=user,
            challenge_type='webauthn',
            expires_at__gt=timezone.now()
        ).first()
        
        if not challenge_obj:
            logger.error("No valid challenge found")
            return JsonResponse({'error': 'No valid challenge found'}, status=400)
        
        # Find the credential using various approaches
        credential_id_from_response = credential_response['id']
        
        # Get all active credentials for the user
        available_creds = WebAuthnCredential.objects.filter(user=user, is_active=True)
        
        # Function to normalize base64 strings for comparison
        def normalize_base64(b64_str):
            """Convert between URL-safe and standard base64, handle padding"""
            variants = []
            
            # Original string
            variants.append(b64_str)
            
            # URL-safe to standard conversion
            standard = b64_str.replace('-', '+').replace('_', '/')
            variants.append(standard)
            
            # Standard to URL-safe conversion  
            url_safe = b64_str.replace('+', '-').replace('/', '_')
            variants.append(url_safe)
            
            # Try adding padding if missing
            for variant in [b64_str, standard, url_safe]:
                # Add padding if needed
                missing_padding = len(variant) % 4
                if missing_padding:
                    padded = variant + '=' * (4 - missing_padding)
                    variants.append(padded)
            
            # Remove duplicates while preserving order
            seen = set()
            unique_variants = []
            for v in variants:
                if v not in seen:
                    seen.add(v)
                    unique_variants.append(v)
                    
            return unique_variants
        
        # Try to find the credential using various approaches
        webauthn_credential = None
        
        # Approach 1: Direct comparison with variants
        response_variants = normalize_base64(credential_id_from_response)
        
        for variant in response_variants:
            try:
                webauthn_credential = WebAuthnCredential.objects.get(
                    user=user,
                    credential_id=variant,
                    is_active=True
                )
                break
            except WebAuthnCredential.DoesNotExist:
                continue
        
        # Approach 2: If no exact match, try prefix matching (in case of truncation)
        if not webauthn_credential:
            for cred in available_creds:
                stored_variants = normalize_base64(cred.credential_id)
                for stored_variant in stored_variants:
                    for response_variant in response_variants:
                        # Check if either is a prefix of the other
                        if (response_variant.startswith(stored_variant[:len(response_variant)]) or 
                            stored_variant.startswith(response_variant)):
                            webauthn_credential = cred
                            break
                    if webauthn_credential:
                        break
                if webauthn_credential:
                    break
        
        # Approach 3: If still no match, try binary comparison after base64 decode
        if not webauthn_credential:
            try:
                # Try to decode the response credential ID
                response_decoded = None
                for variant in response_variants:
                    try:
                        response_decoded = base64.b64decode(variant)
                        break
                    except Exception:
                        continue
                
                if response_decoded:
                    # Compare with stored credentials
                    for cred in available_creds:
                        try:
                            stored_decoded = base64.b64decode(cred.credential_id)
                            if response_decoded == stored_decoded:
                                webauthn_credential = cred
                                break
                        except Exception:
                            continue
                            
            except Exception as e:
                logger.error(f"Binary comparison failed: {e}")
        
        if not webauthn_credential:
            logger.error(f"Credential not found for user {user.username}")
            return JsonResponse({'error': 'Credential not found'}, status=400)
        
        # Prepare verification parameters
        expected_origin = getattr(settings, 'WEBAUTHN_ORIGIN', f"https://{request.get_host()}" if request.is_secure() else f"http://{request.get_host()}")
        expected_rp_id = getattr(settings, 'WEBAUTHN_RP_ID', request.get_host().split(':')[0])
        
        # Decode the stored challenge
        try:
            expected_challenge_bytes = base64.b64decode(challenge_obj.challenge)
        except Exception as decode_error:
            logger.error(f"Failed to decode stored challenge: {decode_error}")
            return JsonResponse({'error': 'Invalid stored challenge'}, status=500)
        
        # Verify authentication response
        try:
            verification = verify_authentication_response(
                credential=credential_response,
                expected_challenge=expected_challenge_bytes,
                expected_origin=expected_origin,
                expected_rp_id=expected_rp_id,
                credential_public_key=base64.b64decode(webauthn_credential.public_key),
                credential_current_sign_count=webauthn_credential.sign_count,
            )
            
            # If we get here, verification was successful (no exception raised)
            logger.info(f"WebAuthn authentication successful for user {user.username}")
            
            # Update credential sign count
            webauthn_credential.sign_count = verification.new_sign_count
            webauthn_credential.update_last_used()
            
            # Log successful authentication
            MFAAttempt.objects.create(
                user=user,
                credential=webauthn_credential,
                attempt_type='webauthn',
                success=True,
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            
            # Log the user in
            login(request, user, backend='django.contrib.auth.backends.ModelBackend')
            
            # Log activity
            ActivityLog.log_activity(
                user=user,
                activity_type='login',
                description='User logged in successfully with MFA',
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                session_id=request.session.session_key,
                details={'remember_me': request.session.get('mfa_remember_me', False), 'mfa_required': True, 'device_name': webauthn_credential.device_name if webauthn_credential else 'Unknown'}
            )
            
            # Set session expiry based on remember me
            remember_me = request.session.get('mfa_remember_me', False)
            if not remember_me:
                request.session.set_expiry(0)
            
            # Clean up MFA session data
            del request.session['mfa_required']
            del request.session['mfa_user_id']
            if 'mfa_remember_me' in request.session:
                del request.session['mfa_remember_me']
            
            # Clean up challenge
            challenge_obj.delete()
            
            return JsonResponse({
                'success': True,
                'redirect': reverse('authentication:home')
            })
            
        except Exception as verification_error:
            # WebAuthn verification failed
            logger.error(f"WebAuthn authentication verification failed for user {user.username}: {str(verification_error)}")
            
            # Log failed authentication
            MFAAttempt.objects.create(
                user=user,
                credential=webauthn_credential,
                attempt_type='webauthn',
                success=False,
                error_message=f'WebAuthn verification failed: {str(verification_error)}',
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            
            return JsonResponse({
                'error': f'Authentication verification failed: {str(verification_error)}'
            }, status=400)
        
    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error: {str(e)}")
        return JsonResponse({'error': 'Invalid JSON data'}, status=400)
        
    except User.DoesNotExist:
        logger.error(f"User {user_id} does not exist")
        return JsonResponse({'error': 'User not found'}, status=400)
        
    except Exception as e:
        logger.error(f"Error completing authentication: {str(e)}")
        return JsonResponse({'error': f'Authentication failed: {str(e)}'}, status=500)

@login_required
def generate_backup_codes(request):
    """Generate backup codes for the user"""
    if request.method == 'POST':
        # Generate new backup codes (4 codes)
        codes = MFABackupCode.generate_codes_for_user(request.user, count=4)
        
        # Debug: Verify the preference was updated
        preference = UserMFAPreference.objects.get(user=request.user)
        logger.info(f"Backup codes generated for user {request.user.username}. backup_codes_generated: {preference.backup_codes_generated}")
        
        # Log activity
        ActivityLog.log_activity(
            user=request.user,
            activity_type='backup_codes_generated',
            description='New backup codes were generated',
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            session_id=request.session.session_key,
            details={'codes_count': len(codes)}
        )
        
        # Check if this is an AJAX request (from modal)
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or 'application/json' in request.headers.get('Accept', ''):
            return JsonResponse({
                'success': True,
                'codes': codes,  # codes is already a list of strings
                'message': 'Backup codes generated successfully'
            })
        
        # Traditional form submission
        messages.success(request, 
            "New backup codes have been generated. Please save them in a secure location. "
            "These codes can only be used once each."
        )
        
        context = {
            'backup_codes': codes,
            'show_codes': True
        }
        return render(request, 'authentication/backup_codes.html', context)
    
    return render(request, 'authentication/backup_codes.html')

@require_POST  
def mfa_backup_authenticate(request):
    """Authenticate using backup code"""
    if not request.session.get('mfa_required'):
        return JsonResponse({'error': 'MFA not required'}, status=400)
    
    user_id = request.session.get('mfa_user_id')  
    if not user_id:
        return JsonResponse({'error': 'No user for MFA'}, status=400)
    
    try:
        data = json.loads(request.body)
        backup_code = data.get('code', '').strip().upper()
        
        if not backup_code:
            return JsonResponse({'error': 'No backup code provided'}, status=400)
        
        user = User.objects.get(id=user_id)
        
        # Find unused backup code
        try:
            code_obj = MFABackupCode.objects.get(
                user=user,
                code=backup_code,
                used=False
            )
        except MFABackupCode.DoesNotExist:
            # Log failed attempt
            MFAAttempt.objects.create(
                user=user,
                attempt_type='backup',
                success=False,
                error_message='Invalid backup code',
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            return JsonResponse({'error': 'Invalid backup code'}, status=400)
        
        # Mark code as used
        code_obj.mark_as_used()
        
        # Log successful authentication
        MFAAttempt.objects.create(
            user=user,
            attempt_type='backup',
            success=True,
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        
        # Log activity
        ActivityLog.log_activity(
            user=user,
            activity_type='backup_code_used',
            description='Backup code was used for authentication',
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            session_id=request.session.session_key,
            details={'code_used': backup_code}
        )
        
        # Log the user in
        login(request, user, backend='django.contrib.auth.backends.ModelBackend')
        
        # Set session expiry based on remember me
        remember_me = request.session.get('mfa_remember_me', False)
        if not remember_me:
            request.session.set_expiry(0)
        
        # Clean up MFA session data
        del request.session['mfa_required']
        del request.session['mfa_user_id']
        if 'mfa_remember_me' in request.session:
            del request.session['mfa_remember_me']
        
        return JsonResponse({
            'success': True,
            'redirect': reverse('authentication:home'),
            'message': 'Successfully authenticated with backup code'
        })
        
    except Exception as e:
        logger.error(f"Error with backup code authentication: {str(e)}")
        return JsonResponse({'error': 'Authentication failed'}, status=500)

@login_required
@require_POST
def delete_credential(request, credential_id):
    """Delete a WebAuthn credential"""
    try:
        credential = WebAuthnCredential.objects.get(
            id=credential_id,
            user=request.user,
            is_active=True
        )
        
        device_name = credential.device_name
        credential.is_active = False
        credential.save()
        
        # Log activity
        ActivityLog.log_activity(
            user=request.user,
            activity_type='device_removed',
            description=f'Security device "{device_name}" was removed',
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            session_id=request.session.session_key,
            details={'device_name': device_name, 'device_type': credential.device_type}
        )
        
        messages.success(request, f"Security key '{device_name}' has been removed.")
        
    except WebAuthnCredential.DoesNotExist:
        messages.error(request, "Security key not found.")
    
    return redirect('authentication:mfa_setup')

# Keep all existing views below (SAML, logout, etc.)
def logout_view(request):
    """View for user logout - aggressive session and cache clearing with SAML SLO"""
    # Log logout activity if user is authenticated
    if request.user.is_authenticated:
        ActivityLog.log_activity(
            user=request.user,
            activity_type='logout',
            description='User logged out',
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            session_id=request.session.session_key
        )
    
    was_saml_authenticated = request.session.get('saml_authenticated', False)
    saml_name_id = request.session.get('saml_name_id', None)
    
    logger.info(f"Logout attempt - Session keys before clearing: {list(request.session.keys())}")
    logger.info(f"Was SAML authenticated: {was_saml_authenticated}")
    
    # If this was a SAML session, try to perform Single Logout
    if was_saml_authenticated and saml_name_id:
        try:
            # Try to initiate SAML Single Logout
            from django.urls import reverse
            
            # Force logout
            logout(request)
            
            # Clear all session data aggressively
            if hasattr(request, 'session'):
                # Get all keys before clearing
                all_keys = list(request.session.keys())
                
                # Clear every single key
                for key in all_keys:
                    del request.session[key]
                
                # Force session flush
                request.session.flush()
                
                # Create completely new session
                request.session.create()
            
            logger.info(f"Session keys after clearing: {list(request.session.keys())}")
            
            # Check if SAML SLS endpoint is available before redirecting
            try:
                from django.urls import reverse, NoReverseMatch
                # Try to reverse the SAML SLS URL
                sls_url = reverse('djangosaml2:saml2_sls')
                logger.info(f"SAML SLS URL found: {sls_url}")
                return redirect(sls_url)
            except (NoReverseMatch, ImportError) as e:
                logger.warning(f"SAML SLS not available ({e}), performing regular logout")
                # Fall through to regular logout
                
        except Exception as e:
            logger.error(f"Error during SAML logout process: {e}")
    
    # Regular logout process for non-SAML or fallback
    # Force logout
    logout(request)
    
    # Clear all session data aggressively
    if hasattr(request, 'session'):
        # Get all keys before clearing
        all_keys = list(request.session.keys())
        
        # Clear every single key
        for key in all_keys:
            del request.session[key]
        
        # Force session flush
        request.session.flush()
        
        # Create completely new session
        request.session.create()
    
    logger.info(f"Session keys after clearing: {list(request.session.keys())}")
    
    # Create response with cache clearing headers
    response = redirect('authentication:login')
    
    # Add headers to prevent caching and force fresh requests
    response['Cache-Control'] = 'no-cache, no-store, must-revalidate, private, max-age=0'
    response['Pragma'] = 'no-cache'
    response['Expires'] = '0'
    # Modified Clear-Site-Data to preserve localStorage (theme preference)
    response['Clear-Site-Data'] = '"cache", "cookies", "executionContexts"'
    
    # Clear any potential SAML cookies and other session cookies
    response.delete_cookie('sessionid')
    response.delete_cookie('csrftoken')
    
    if was_saml_authenticated:
        messages.info(request, "You have successfully logged out. Your SSO session has been completely cleared. Please close your browser to fully log out from ADFS.")
    else:
        messages.info(request, "You have successfully logged out.")
    
    return response

@require_http_methods(["GET"])
def adfs_login(request):
    """
    Redirect to SAML SSO authentication with aggressive session clearing
    """
    # Check if SAML is properly configured
    from django.conf import settings
    if not getattr(settings, 'SAML_READY', False) or not settings.SAML_CONFIG:
        messages.error(request, "SAML authentication is not configured. Please contact your administrator.")
        return redirect('authentication:login')
    
    # Log current session state for debugging
    logger.info(f"ADFS login attempt - Session keys before clearing: {list(request.session.keys())}")
    logger.info(f"User authenticated: {request.user.is_authenticated}")
    
    # Force logout any existing user
    if request.user.is_authenticated:
        logout(request)
    
    # Aggressive session clearing - remove ALL session data
    if hasattr(request, 'session'):
        # Clear all session keys
        for key in list(request.session.keys()):
            del request.session[key]
        
        # Force flush the session
        request.session.flush()
        
        # Create a new session
        request.session.create()
        
        # Explicitly clear any SAML-related cookies
        request.session['_force_new_saml_session'] = True
    
    logger.info(f"Session keys after clearing: {list(request.session.keys())}")
    
    # Force fresh authentication with additional parameters
    import urllib.parse
    params = {
        'forceAuthn': 'true',
        'isPassive': 'false',
        '_t': str(int(timezone.now().timestamp()))  # Cache buster
    }
    query_string = urllib.parse.urlencode(params)
    redirect_url = f'/saml2/login/?{query_string}'
    
    logger.info(f"Redirecting to: {redirect_url}")
    return redirect(redirect_url)

def saml_error_view(request):
    """
    Custom SAML error handler
    """
    error_details = {
        'message': 'SAML Authentication Error',
        'request_method': request.method,
        'user_authenticated': request.user.is_authenticated,
        'session_info': dict(request.session) if hasattr(request, 'session') else {},
        'get_params': dict(request.GET),
        'post_params': dict(request.POST) if request.method == 'POST' else {}
    }
    
    logger.error(f"SAML Error: {error_details}")
    
    # Show detailed error for debugging
    return HttpResponse(f"""
    <h1>SAML Authentication Debug</h1>
    <h2>Error Details:</h2>
    <pre>{json.dumps(error_details, indent=2)}</pre>
    <h2>Troubleshooting Steps:</h2>
    <ol>
        <li>Check ADFS Relying Party Trust configuration</li>
        <li>Verify Entity ID matches: https://192.168.1.46:8000/saml2/metadata/</li>
        <li>Check claim rules in ADFS</li>
        <li>Verify certificates are properly configured</li>
    </ol>
    <p><a href="/saml2/metadata/">View SP Metadata</a></p>
    """, content_type='text/html')

@csrf_exempt
def custom_saml_acs(request):
    """
    Custom SAML Assertion Consumer Service with visual processing indicator
    """
    if request.method == 'POST':
        saml_response = request.POST.get('SAMLResponse', '')
        relay_state = request.POST.get('RelayState', '/')
        
        # Check if this is the processing step (form resubmission)
        if request.POST.get('_processing') == 'true':
            # This is the actual processing step
            logger.info(f"Processing SAML Response: {saml_response[:100]}...")
            
            try:
                return process_saml_response(request, saml_response, relay_state)
            except Exception as e:
                logger.error(f"Error processing SAML response: {str(e)}")
                return show_saml_error(request, saml_response, str(e))
        else:
            # First time receiving from ADFS - show processing page with auto-submit form
            return show_saml_processing_page(request, saml_response, relay_state)
    
    return HttpResponse("Method not allowed", status=405)

def show_saml_processing_page(request, saml_response, relay_state):
    """
    Show a processing page with auto-submitting form
    """
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Processing SAML Authentication - SecureAuth</title>
        <meta name="description" content="Processing SAML authentication response">
        <meta name="robots" content="noindex, nofollow">
        <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><defs><linearGradient id='grad' x1='0%' y1='0%' x2='100%' y2='100%'><stop offset='0%' stop-color='%230066cc'/><stop offset='100%' stop-color='%233385d6'/></linearGradient></defs><rect width='100' height='100' rx='20' fill='url(%23grad)'/><path d='M50 25c-8.284 0-15 6.716-15 15v5h-5c-2.761 0-5 2.239-5 5v25c0 2.761 2.239 5 5 5h40c2.761 0 5-2.239 5-5V50c0-2.761-2.239-5-5-5h-5v-5c0-8.284-6.716-15-15-15zm0 6c5.523 0 10 4.477 10 10v5H40v-5c0-5.523 4.477-10 10-10z' fill='white'/></svg>">
        <link rel="stylesheet" href="/static/css/login.css?v=3">
        <link rel="stylesheet" href="/static/css/login-enhancements.css?v=2">
        <link rel="stylesheet" href="/static/css/background-enhancements.css?v=2">
        <link rel="stylesheet" href="/static/css/header-enhancements.css?v=2">
        <link rel="stylesheet" href="/static/css/home-enhancements.css?v=3">
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <style>
            :root {{
                /* SecureAuth Brand Colors */
                --primary-blue: #0066cc;
                --primary-blue-dark: #004499;
                --primary-blue-light: #3385d6;
                --secondary-blue: #4da6ff;
                --accent-blue: #80bfff;
                --success: #00a86b;
                --warning: #ff8c00;
                --error: #dc3545;
                --info: #17a2b8;
                
                /* Neutral Colors */
                --white: #ffffff;
                --gray-50: #f8fafc;
                --gray-100: #f1f5f9;
                --gray-200: #e2e8f0;
                --gray-300: #cbd5e1;
                --gray-400: #94a3b8;
                --gray-500: #64748b;
                --gray-600: #475569;
                --gray-700: #334155;
                --gray-800: #1e293b;
                --gray-900: #0f172a;
                
                /* Dark Mode Colors */
                --dark-bg: #0a0e1a;
                --dark-surface: #1a1f2e;
                --dark-surface-elevated: #252b3d;
                --dark-border: #2d3748;
                --dark-text-primary: #f7fafc;
                --dark-text-secondary: #a0aec0;
                
                /* Typography */
                --font-family-primary: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;
                
                /* Spacing Scale */
                --space-xs: 0.25rem;
                --space-sm: 0.5rem;
                --space-md: 1rem;
                --space-lg: 1.5rem;
                --space-xl: 2rem;
                --space-2xl: 3rem;
                --space-3xl: 4rem;
                
                /* Border Radius */
                --radius-sm: 0.375rem;
                --radius-md: 0.5rem;
                --radius-lg: 0.75rem;
                --radius-xl: 1rem;
                --radius-2xl: 1.5rem;
                
                /* Shadows */
                --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
                --shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
                --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
                --shadow-xl: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
                --shadow-2xl: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
            }}

            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}

            html {{
                font-size: 16px;
                scroll-behavior: smooth;
            }}

            body {{
                font-family: var(--font-family-primary);
                background: linear-gradient(135deg, var(--primary-blue) 0%, #1e3a8a 50%, var(--primary-blue-dark) 100%);
                min-height: 100vh;
                color: var(--gray-900);
                line-height: 1.6;
                -webkit-font-smoothing: antialiased;
                -moz-osx-font-smoothing: grayscale;
                text-rendering: optimizeLegibility;
                position: relative;
                overflow-x: hidden;
                transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            }}

            body.dark-mode {{
                background: linear-gradient(135deg, var(--dark-bg) 0%, #1a202c 50%, var(--gray-900) 100%);
                color: var(--dark-text-primary);
            }}

            /* Enhanced Background Elements */
            .background-wrapper {{
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                overflow: hidden;
                pointer-events: none;
                z-index: 0;
            }}

            .background-grid {{
                position: absolute;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                opacity: 0.03;
                background-image: 
                    linear-gradient(90deg, rgba(255, 255, 255, 0.15) 1px, transparent 1px),
                    linear-gradient(0deg, rgba(255, 255, 255, 0.15) 1px, transparent 1px);
                background-size: 50px 50px;
                animation: gridShimmer 8s ease-in-out infinite;
            }}

            @keyframes gridShimmer {{
                0%, 100% {{ opacity: 0.03; }}
                50% {{ opacity: 0.05; }}
            }}

            .background-overlay {{
                position: absolute;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: 
                    radial-gradient(circle at 20% 20%, rgba(0, 102, 204, 0.4) 0%, transparent 50%),
                    radial-gradient(circle at 80% 80%, rgba(0, 68, 153, 0.4) 0%, transparent 50%),
                    radial-gradient(circle at 50% 50%, rgba(77, 166, 255, 0.2) 0%, transparent 70%);
                opacity: 0.7;
                animation: backgroundPulse 15s ease-in-out infinite;
            }}

            @keyframes backgroundPulse {{
                0%, 100% {{ opacity: 0.7; }}
                50% {{ opacity: 0.5; }}
            }}

            .circuit-lines {{
                position: absolute;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                opacity: 0.07;
                background-image: url("data:image/svg+xml,%3Csvg width='100' height='100' viewBox='0 0 100 100' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M10 10 L90 10 M10 30 L30 30 L30 90 M70 30 L90 30 M50 10 L50 90 M70 50 L90 50 M10 70 L30 70 M70 70 L90 70 M10 90 L90 90' stroke='white' stroke-width='1.2' fill='none' /%3E%3Ccircle cx='30' cy='30' r='2' fill='white'/%3E%3Ccircle cx='70' cy='30' r='2' fill='white'/%3E%3Ccircle cx='30' cy='70' r='2' fill='white'/%3E%3Ccircle cx='70' cy='70' r='2' fill='white'/%3E%3C/svg%3E");
                background-size: 200px 200px;
                animation: circuitPulse 10s ease-in-out infinite;
            }}

            @keyframes circuitPulse {{
                0%, 100% {{ opacity: 0.07; }}
                50% {{ opacity: 0.04; }}
            }}

            .floating-elements {{
                position: absolute;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
            }}

            .floating-element {{
                position: absolute;
                width: 40px;
                height: 40px;
                border-radius: 50%;
                filter: blur(2px);
                animation: float 12s ease-in-out infinite;
                background: linear-gradient(135deg, rgba(255, 255, 255, 0.05) 0%, rgba(255, 255, 255, 0.02) 100%);
                backdrop-filter: blur(5px);
                border: 1px solid rgba(255, 255, 255, 0.05);
            }}

            .floating-element:nth-child(1) {{
                width: 80px;
                height: 80px;
                left: 10%;
                top: 10%;
                animation-delay: 0s;
            }}

            .floating-element:nth-child(2) {{
                width: 60px;
                height: 60px;
                left: 85%;
                top: 15%;
                animation-delay: 3s;
            }}

            .floating-element:nth-child(3) {{
                width: 70px;
                height: 70px;
                left: 70%;
                top: 70%;
                animation-delay: 6s;
            }}

            .floating-element:nth-child(4) {{
                width: 50px;
                height: 50px;
                left: 20%;
                top: 80%;
                animation-delay: 9s;
            }}

            @keyframes float {{
                0%, 100% {{ 
                    transform: translateY(0) translateX(0) rotate(0deg);
                    opacity: 0.6;
                }}
                50% {{ 
                    transform: translateY(-40px) translateX(20px) rotate(180deg);
                    opacity: 0.4;
                }}
            }}

            /* Header overrides to match other pages */
            .header {{
                display: flex !important;
                align-items: center !important;
                justify-content: space-between !important;
                padding: 1rem 2rem !important;
                background: rgba(0, 0, 0, 0.1) !important;
                backdrop-filter: blur(10px) !important;
                position: relative !important;
                z-index: 50 !important;
            }}

            /* Status indicator for system status */
            .status-indicator {{
                width: 8px;
                height: 8px;
                background: #10b981;
                border-radius: 50%;
                animation: pulse 2s infinite;
            }}

            /* Main Container */
            .processing-container {{
                max-width: 900px;
                margin: 0 auto;
                padding: 2rem 1rem;
                position: relative;
            }}

            @keyframes fadeInScale {{
                0% {{
                    opacity: 0;
                    transform: scale(0.9) translateY(20px);
                }}
                100% {{
                    opacity: 1;
                    transform: scale(1) translateY(0);
                }}
            }}

            /* Compact Header */
            .processing-header {{
                text-align: center;
                margin-bottom: 2rem;
                padding: 1.5rem 1.5rem 1rem;
                background: linear-gradient(135deg, rgba(255, 255, 255, 0.9), rgba(248, 250, 252, 0.95));
                border-radius: 16px;
                border: 1px solid rgba(0, 102, 204, 0.3);
                position: relative;
                overflow: hidden;
                box-shadow: 0 4px 15px rgba(0, 0, 0, 0.08);
            }}

            .processing-header::before {{
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                height: 3px;
                background: linear-gradient(135deg, #0066cc, #4285f4);
                border-radius: 16px 16px 0 0;
            }}

            body.dark-mode .processing-header {{
                background: linear-gradient(135deg, rgba(0, 102, 204, 0.1), rgba(66, 133, 244, 0.15));
                border-color: rgba(0, 102, 204, 0.2);
            }}

            .header-icon {{
                width: 50px;
                height: 50px;
                background: linear-gradient(135deg, #0066cc, #4285f4);
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
                color: white;
                font-size: 1.25rem;
                margin: 0 auto 1rem;
                box-shadow: 0 4px 15px rgba(0, 102, 204, 0.3);
                position: relative;
            }}

            .header-icon::after {{
                content: '';
                position: absolute;
                inset: -3px;
                background: linear-gradient(135deg, #0066cc, #4285f4);
                border-radius: 50%;
                z-index: -1;
                opacity: 0.3;
                animation: pulse 2s infinite;
            }}

            .processing-title {{
                font-size: 1.75rem;
                font-weight: 700;
                background: linear-gradient(135deg, #0066cc, #4285f4);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
                margin-bottom: 0.5rem;
                text-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            }}

            .processing-subtitle {{
                font-size: 0.95rem;
                color: var(--gray-600);
                max-width: 500px;
                margin: 0 auto;
                line-height: 1.5;
            }}

            body.dark-mode .processing-subtitle {{
                color: var(--dark-text-secondary);
            }}

            /* Compact Spinner */
            .spinner-container {{
                margin: 1rem 0;
            }}

            .spinner {{
                width: 48px;
                height: 48px;
                border: 3px solid var(--gray-200);
                border-top: 3px solid var(--primary-blue);
                border-radius: 50%;
                animation: spin 1s linear infinite;
                margin: 0 auto;
                position: relative;
            }}

            body.dark-mode .spinner {{
                border-color: var(--dark-border);
                border-top-color: var(--primary-blue-light);
            }}

            .spinner::after {{
                content: '';
                position: absolute;
                top: -3px;
                left: -3px;
                right: -3px;
                bottom: -3px;
                border: 2px solid transparent;
                border-top: 2px solid var(--primary-blue-light);
                border-radius: 50%;
                animation: spin 2s linear infinite reverse;
            }}

            @keyframes spin {{
                0% {{ transform: rotate(0deg); }}
                100% {{ transform: rotate(360deg); }}
            }}

            /* Compact Typography */
            .processing-title {{
                font-size: 1.4rem;
                font-weight: 700;
                margin-bottom: 0.5rem;
                color: var(--gray-900);
                letter-spacing: -0.025em;
            }}

            body.dark-mode .processing-title {{
                color: var(--dark-text-primary);
            }}

            .processing-message {{
                font-size: 0.9rem;
                color: var(--gray-600);
                margin-bottom: 1rem;
                line-height: 1.5;
                font-weight: 500;
            }}

            body.dark-mode .processing-message {{
                color: var(--dark-text-secondary);
            }}

            /* Processing Card */
            .processing-card {{
                background: rgba(255, 255, 255, 0.9);
                backdrop-filter: blur(20px);
                border-radius: 20px;
                padding: 2rem;
                margin-bottom: 2rem;
                border: 1px solid rgba(0, 102, 204, 0.1);
                box-shadow: 0 8px 30px rgba(0, 0, 0, 0.1);
                transition: all 0.3s ease;
                position: relative;
                overflow: hidden;
                animation: fadeIn 0.6s ease-out;
                text-align: center;
            }}

            .processing-card::before {{
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                height: 3px;
                background: linear-gradient(135deg, #0066cc, #4285f4);
            }}

            .processing-card:hover {{
                transform: translateY(-2px);
                box-shadow: 0 12px 40px rgba(0, 102, 204, 0.15);
            }}

            body.dark-mode .processing-card {{
                background: rgba(26, 32, 44, 0.9);
                border-color: rgba(0, 102, 204, 0.2);
            }}

            /* Spinner */
            .spinner {{
                width: 64px;
                height: 64px;
                border: 4px solid var(--gray-200);
                border-top: 4px solid var(--primary-blue);
                border-radius: 50%;
                animation: spin 1s linear infinite;
                margin: 2rem auto;
            }}

            body.dark-mode .spinner {{
                border-color: var(--dark-border);
                border-top-color: var(--primary-blue-light);
            }}

            @keyframes spin {{
                0% {{ transform: rotate(0deg); }}
                100% {{ transform: rotate(360deg); }}
            }}

            /* Status Message */
            .status-message {{
                background: rgba(0, 102, 204, 0.05);
                border: 1px solid rgba(0, 102, 204, 0.15);
                border-radius: 12px;
                padding: 1rem;
                margin: 1.5rem 0;
                color: var(--primary-blue);
                font-size: 0.9rem;
                font-weight: 500;
            }}

            body.dark-mode .status-message {{
                background: rgba(0, 102, 204, 0.1);
                border-color: rgba(0, 102, 204, 0.2);
                color: var(--primary-blue-light);
            }}

            .countdown {{
                font-size: 0.9rem;
                color: var(--gray-600);
                margin-top: 1rem;
                font-weight: 500;
            }}

            body.dark-mode .countdown {{
                color: var(--dark-text-secondary);
            }}

            .countdown-number {{
                color: var(--primary-blue);
                font-weight: 700;
            }}

            @keyframes pulse {{
                0%, 100% {{ 
                    opacity: 1; 
                    transform: scale(1);
                    box-shadow: 0 0 0 0 rgba(0, 102, 204, 0.7);
                }}
                50% {{ 
                    opacity: 0.8; 
                    transform: scale(1.05);
                    box-shadow: 0 0 0 20px rgba(0, 102, 204, 0);
                }}
            }}

            @keyframes fadeIn {{
                from {{ opacity: 0; transform: translateY(20px); }}
                to {{ opacity: 1; transform: translateY(0); }}
            }}

            /* Responsive Design */
            @media (max-width: 768px) {{
                .processing-container {{
                    padding: 1rem;
                }}
                
                .processing-header {{
                    padding: 1rem;
                    margin-bottom: 1.5rem;
                }}
                
                .processing-title {{
                    font-size: 1.5rem;
                }}
                
                .processing-subtitle {{
                    font-size: 0.875rem;
                }}

            .status-dot {{
                width: 8px;
                height: 8px;
                border-radius: 50%;
                background: var(--success);
                animation: pulse-dot 2s infinite;
            }}

            @keyframes pulse-dot {{
                0% {{ box-shadow: 0 0 0 0 rgba(0, 168, 107, 0.7); }}
                70% {{ box-shadow: 0 0 0 10px rgba(0, 168, 107, 0); }}
                100% {{ box-shadow: 0 0 0 0 rgba(0, 168, 107, 0); }}
            }}

            /* Responsive Design */
            @media (max-width: 640px) {{
                .processing-container {{
                    padding: var(--space-xl);
                    margin: var(--space-md);
                }}
                
                .processing-title {{
                    font-size: 1.5rem;
                }}
                
                .spinner {{
                    width: 48px;
                    height: 48px;
                }}
                
                .logo-icon {{
                    width: 40px;
                    height: 40px;
                }}
            }}
        </style>
    </head>
    <body>
        <!-- Enhanced Background Elements -->
        <div class="background-wrapper">
            <div class="background-grid"></div>
            <div class="background-overlay"></div>
            <div class="circuit-lines"></div>
            <div class="floating-elements">
                <div class="floating-element"></div>
                <div class="floating-element"></div>
                <div class="floating-element"></div>
                <div class="floating-element"></div>
                <div class="floating-element"></div>
                <div class="floating-element"></div>
            </div>
        </div>

        <!-- Header -->
        <header class="header">
            <div class="header-left">
                <a href="#" class="header-logo">
                    <div class="header-logo-icon">
                        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                            <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
                        </svg>
                    </div>
                    <div class="company-info">
                        <div class="company-name">SecureAuth</div>
                        <div class="company-tagline">Enterprise Access Portal</div>
                    </div>
                </a>
                <div class="system-status">
                    <div class="status-indicator"></div>
                    <span>Processing authentication</span>
                </div>
            </div>
            <div class="utility-controls">
                <button id="themeToggle" class="utility-btn" aria-label="Toggle dark mode">
                    <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path>
                    </svg>
                </button>
                <button id="helpBtn" class="utility-btn" aria-label="Get help">
                    <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <circle cx="12" cy="12" r="10"></circle>
                        <path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"></path>
                        <line x1="12" y1="17" x2="12.01" y2="17"></line>
                    </svg>
                </button>
            </div>
        </header>

        <!-- Main Content -->
        <div class="processing-container">
            <!-- Compact Header -->
            <div class="processing-header">
                <div class="header-icon">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="width: 24px; height: 24px;">
                        <rect x="4" y="11" width="16" height="10" rx="2" ry="2"></rect>
                        <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
                    </svg>
                </div>
                <h1 class="processing-title">Processing Authentication</h1>
                <p class="processing-subtitle">
                    Validating your SAML credentials and establishing secure session
                </p>
            </div>

            <!-- Processing Card -->
            <div class="processing-card">
                <!-- Spinner -->
                <div class="spinner"></div>
                
                <!-- Status Message -->
                <div class="status-message">
                    <strong>🔐 Authentication Progress:</strong><br>
                    SAML response validated • User attributes extracted • Creating secure session
                </div>
                
                <p class="countdown">
                    Redirecting in <span class="countdown-number" id="countdown">3</span> seconds...
                </p>
            </div>
            
            <!-- Hidden auto-submit form -->
            <form id="samlForm" method="POST" style="display: none;">
                <input type="hidden" name="SAMLResponse" value="{saml_response}">
                <input type="hidden" name="RelayState" value="{relay_state}">
                <input type="hidden" name="_processing" value="true">
            </form>
        </div>
        
        <script>
            // Theme Management (Match other pages)
            function initializeTheme() {{
                const savedTheme = localStorage.getItem('theme');
                const isDarkMode = savedTheme ? savedTheme === 'dark' : true;
                
                if (isDarkMode) {{
                    document.body.classList.add('dark-mode');
                    if (!savedTheme) {{
                        localStorage.setItem('theme', 'dark');
                    }}
                }}
                
                // Update theme toggle icon
                updateThemeIcon(isDarkMode);
            }}

            function updateThemeIcon(isDarkMode) {{
                const themeToggle = document.getElementById('themeToggle');
                if (themeToggle) {{
                    const icon = themeToggle.querySelector('svg');
                    if (isDarkMode) {{
                        icon.innerHTML = '<path d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"></path>';
                    }} else {{
                        icon.innerHTML = '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path>';
                    }}
                }}
            }}

            function toggleTheme() {{
                const isDarkMode = document.body.classList.toggle('dark-mode');
                localStorage.setItem('theme', isDarkMode ? 'dark' : 'light');
                updateThemeIcon(isDarkMode);
            }}

            // Initialize theme
            initializeTheme();

            // Theme toggle event listener
            document.getElementById('themeToggle')?.addEventListener('click', toggleTheme);

            // Countdown and form submission logic
            let countdown = 3;
            const countdownElement = document.getElementById('countdown');
            const countdownTextElement = document.getElementById('countdown-text');
            const statusIndicator = document.querySelector('.status-indicator span');
            
            const timer = setInterval(() => {{
                countdown--;
                countdownElement.textContent = countdown;
                
                // Update singular/plural text
                countdownTextElement.textContent = countdown === 1 ? 'second' : 'seconds';
                
                if (countdown <= 0) {{
                    clearInterval(timer);
                    countdownElement.textContent = '0';
                    countdownTextElement.textContent = 'seconds';
                    statusIndicator.textContent = 'Processing authentication...';
                    
                    // Add a subtle fade effect before submit
                    document.querySelector('.processing-container').style.opacity = '0.8';
                    document.getElementById('samlForm').submit();
                }}
            }}, 1000);
            
            // Also submit after 3 seconds as backup
            setTimeout(() => {{
                document.getElementById('samlForm').submit();
            }}, 3000);
        </script>
    </body>
    </html>
    """
    return HttpResponse(html_content, content_type='text/html')

def process_saml_response(request, saml_response, relay_state):
    """
    Process the actual SAML response
    """
    # Decode the SAML response (it's base64 encoded)
    decoded_response = base64.b64decode(saml_response).decode('utf-8')
    logger.info(f"Decoded SAML Response: {decoded_response[:500]}...")
    
    # Parse the XML to extract user information
    root = ET.fromstring(decoded_response)
    
    # Define namespaces for SAML
    namespaces = {
        'saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
        'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol'
    }
    
    # Extract user attributes
    attributes = {}
    for attr in root.findall('.//saml:Attribute', namespaces):
        attr_name = attr.get('Name', '')
        attr_values = [value.text for value in attr.findall('saml:AttributeValue', namespaces)]
        attributes[attr_name] = attr_values
        
    # Extract NameID
    name_id_element = root.find('.//saml:NameID', namespaces)
    name_id = name_id_element.text if name_id_element is not None else None
    
    # Try to extract NameID from Subject if not found in attributes
    if not name_id:
        subject_name_id = root.find('.//saml:Subject/saml:NameID', namespaces)
        name_id = subject_name_id.text if subject_name_id is not None else None
    
    logger.info(f"Extracted attributes: {attributes}")
    logger.info(f"NameID: {name_id}")
    
    # Create or get user based on email or name
    email = None
    username = None
    first_name = ''
    last_name = ''
    
    # Extract user info from attributes
    for attr_name, attr_values in attributes.items():
        if 'emailaddress' in attr_name.lower() and attr_values:
            email = attr_values[0]
        elif 'givenname' in attr_name.lower() and attr_values:
            first_name = attr_values[0]
        elif 'surname' in attr_name.lower() and attr_values:
            last_name = attr_values[0]
        elif 'name' in attr_name.lower() and attr_values:
            username = attr_values[0]
    
    # If no attributes were provided, use NameID or create a default user
    if not email and not username and name_id:
        # Try to extract domain/username from NameID if it looks like domain\username
        if '\\' in name_id:
            domain, user_part = name_id.split('\\', 1)
            username = user_part
            first_name = user_part.title()
        else:
            username = name_id
            first_name = name_id.title()
    
    # Use email as username if available, otherwise use NameID or extracted username
    if email:
        username = email
    elif not username and name_id:
        username = name_id
    elif not username:
        username = 'saml_user'
        
    logger.info(f"Creating/finding user: {username}")
    
    # Create or get the user
    user, created = User.objects.get_or_create(
        username=username,
        defaults={
            'email': email or '',
            'first_name': first_name,
            'last_name': last_name,
            'is_active': True,
        }
    )
    
    if not created:
        # Update user info
        user.email = email or user.email
        user.first_name = first_name or user.first_name
        user.last_name = last_name or user.last_name
        user.save()
        
    # Check if user has MFA enabled BEFORE logging them in
    mfa_preference = getattr(user, 'mfa_preference', None)
    if mfa_preference and mfa_preference.mfa_enabled:
        # Store user in session for MFA verification
        request.session['mfa_user_id'] = user.id
        request.session['mfa_remember_me'] = False  # SAML doesn't have remember me
        request.session['mfa_required'] = True
        
        # Store SAML session information for after MFA
        request.session['saml_authenticated'] = True
        request.session['saml_name_id'] = name_id
        request.session['saml_user_email'] = email
        request.session['saml_login_time'] = str(timezone.now()) if 'timezone' in globals() else 'unknown'
        request.session['authentication_method'] = 'saml'
        
        messages.info(request, f"Multi-Factor Authentication required for {user.first_name or user.username}")
        return redirect('authentication:mfa_challenge')
    else:
        # Standard SAML login without MFA
        login(request, user, backend='django.contrib.auth.backends.ModelBackend')
        
        # Store SAML session information for proper logout
        request.session['saml_authenticated'] = True
        request.session['saml_name_id'] = name_id
        request.session['saml_user_email'] = email
        request.session['saml_login_time'] = str(timezone.now()) if 'timezone' in globals() else 'unknown'
        
        # Mark this as a SAML session for logout purposes
        request.session['authentication_method'] = 'saml'
    
    messages.success(request, f"Successfully authenticated via SAML! Welcome {user.first_name or user.username}!")
    
    return redirect(relay_state or 'authentication:home')

def show_saml_error(request, saml_response, error_message):
    """
    Show SAML error page with debug information
    """
    try:
        decoded_response = base64.b64decode(saml_response).decode('utf-8')
    except:
        decoded_response = 'Failed to decode SAML response'
    
    return HttpResponse(f"""
        <h1>SAML Response Debug</h1>
        <h2>Error:</h2>
        <p>{error_message}</p>
        <h2>Raw SAML Response:</h2>
        <textarea rows="10" cols="100">{saml_response}</textarea>
        <h2>Decoded Response:</h2>
        <textarea rows="20" cols="100">{decoded_response}</textarea>
        <p><a href="/authentication/login/">Back to Login</a></p>
    """, content_type='text/html')

@login_required
def edit_profile(request):
    """View for editing user profile information"""
    if request.method == 'POST':
        # Debug CSRF token
        csrf_token_post = request.POST.get('csrfmiddlewaretoken', 'NOT_FOUND')
        csrf_token_cookie = request.META.get('CSRF_COOKIE', 'NOT_FOUND')
        session_key = request.session.session_key
        
        logger.info(f"CSRF token from POST: {csrf_token_post}")
        logger.info(f"CSRF token from cookies: {csrf_token_cookie}")
        logger.info(f"User session key: {session_key}")
        
        # Check if CSRF token is missing or invalid
        if not csrf_token_post or csrf_token_post == 'NOT_FOUND':
            logger.error("CSRF token missing from POST data")
            messages.error(request, 'Security token missing. Please refresh the page and try again.')
            return redirect('authentication:edit_profile')
        display_name = request.POST.get('display_name', '').strip()
        first_name = request.POST.get('first_name', '').strip()
        last_name = request.POST.get('last_name', '').strip()
        email = request.POST.get('email', '').strip()
        
        # Validate input
        if not display_name or not first_name or not last_name or not email:
            messages.error(request, 'Display name, first name, last name, and email are required.')
            return redirect('authentication:edit_profile')
        
        # Validate email format
        import re
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            messages.error(request, 'Please enter a valid email address.')
            return redirect('authentication:edit_profile')
        
        try:
            # Update Django user model
            user = request.user
            user.first_name = first_name
            user.last_name = last_name
            user.email = email
            user.save()
            
            # Update Active Directory with display name, individual names, and email
            success = update_ad_user_info(user.username, display_name, first_name, last_name, email)
            
            # Log the profile update activity
            ActivityLog.log_activity(
                user=request.user,
                activity_type='profile_updated',
                description=f'Profile updated: {first_name} {last_name} ({email})',
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                session_id=request.session.session_key,
                details={
                    'display_name': display_name,
                    'first_name': first_name,
                    'last_name': last_name,
                    'email': email,
                    'ad_update_success': success
                }
            )
            
            if success:
                messages.success(request, 'Profile updated successfully!')
            else:
                messages.warning(request, 'Profile updated locally, but there was an issue updating Active Directory.')
            
            return redirect('authentication:home')
            
        except Exception as e:
            logger.error(f"Error updating profile for user {request.user.username}: {str(e)}")
            messages.error(request, 'An error occurred while updating your profile.')
            return redirect('authentication:edit_profile')
    
    # GET request - retrieve data from AD and show the form
    try:
        # Get current user info from Active Directory
        ad_user_info = get_ad_user_info(request.user.username)
        
        # Use AD data if available, otherwise fall back to Django user data
        if ad_user_info:
            context = {
                'user': request.user,
                'ad_display_name': ad_user_info.get('displayName', ''),
                'ad_first_name': ad_user_info.get('givenName', ''),
                'ad_last_name': ad_user_info.get('sn', ''),
                'ad_username': ad_user_info.get('sAMAccountName', request.user.username),
                'ad_email': ad_user_info.get('mail', ''),
            }
        else:
            # Fallback to Django user data
            context = {
                'user': request.user,
                'ad_display_name': request.user.get_full_name(),
                'ad_first_name': request.user.first_name,
                'ad_last_name': request.user.last_name,
                'ad_username': request.user.username,
                'ad_email': request.user.email if hasattr(request.user, 'email') else '',
            }
            
    except Exception as e:
        logger.error(f"Error retrieving AD user info for {request.user.username}: {str(e)}")
        # Fallback to Django user data
        context = {
            'user': request.user,
            'ad_display_name': request.user.get_full_name(),
            'ad_first_name': request.user.first_name,
            'ad_last_name': request.user.last_name,
            'ad_username': request.user.username,
            'ad_email': request.user.email if hasattr(request.user, 'email') else '',
        }
    
    return render(request, 'authentication/edit_profile.html', context)

@login_required
def debug_csrf(request):
    """Debug view to check CSRF token status"""
    from django.middleware.csrf import get_token
    from django.template.loader import render_to_string
    
    csrf_token = get_token(request)
    session_key = request.session.session_key
    
    if request.method == 'POST':
        post_token = request.POST.get('csrfmiddlewaretoken', 'NOT_FOUND')
        cookie_token = request.META.get('CSRF_COOKIE', 'NOT_FOUND')
        tokens_match = post_token == cookie_token
        
        return HttpResponse(f"""
        <h2>CSRF Test - POST Successful!</h2>
        <p><strong>CSRF Token from POST:</strong> {post_token}</p>
        <p><strong>CSRF Token from Cookie:</strong> {cookie_token}</p>
        <p><strong>Tokens Match:</strong> {tokens_match}</p>
        <p><a href="/authentication/debug/csrf/">Test Again</a> | <a href="/authentication/profile/edit/">Back to Edit Profile</a></p>
        """, content_type='text/html')
    
    return HttpResponse(f"""
    <h2>CSRF Debug Information</h2>
    <p><strong>CSRF Token:</strong> {csrf_token}</p>
    <p><strong>Session Key:</strong> {session_key}</p>
    <p><strong>CSRF Cookie:</strong> {request.META.get('CSRF_COOKIE', 'NOT_FOUND')}</p>
    <p><strong>User:</strong> {request.user.username}</p>
    <p><strong>Is Authenticated:</strong> {request.user.is_authenticated}</p>
    
    <h3>Test CSRF Token</h3>
    <form method="post">
        <input type="hidden" name="csrfmiddlewaretoken" value="{csrf_token}">
        <button type="submit">Test CSRF Token</button>
    </form>
    
    <p><a href="/authentication/profile/edit/">Back to Edit Profile</a></p>
    """, content_type='text/html')

def get_ad_user_info(username):
    """Retrieve user information from Active Directory"""
    try:
        import ldap3
        from ldap3 import Server, Connection, ALL, NTLM, SIMPLE
        
        # AD connection settings
        AD_SERVER = getattr(settings, 'AD_SERVER', 'ldap://your-ad-server.com')
        AD_DOMAIN = getattr(settings, 'AD_DOMAIN', 'your-domain.com')
        AD_USERNAME = getattr(settings, 'AD_USERNAME', 'service-account@your-domain.com')
        AD_PASSWORD = getattr(settings, 'AD_PASSWORD', '')
        AD_SEARCH_BASE = getattr(settings, 'AD_SEARCH_BASE', 'DC=your-domain,DC=com')
        
        # Connect to AD with fallback authentication methods
        server = Server(AD_SERVER, get_info=ALL)
        
        # Try SIMPLE authentication first (more compatible)
        conn = None
        try:
            conn = Connection(
                server,
                user=f"{AD_USERNAME}",
                password=AD_PASSWORD,
                authentication=SIMPLE,
                auto_bind=True
            )
        except Exception as e:
            logger.warning(f"SIMPLE authentication failed: {str(e)}. Trying NTLM...")
            # Fallback to NTLM with MD4 disabled
            try:
                conn = Connection(
                    server,
                    user=f"{AD_DOMAIN}\\{AD_USERNAME}",
                    password=AD_PASSWORD,
                    authentication=NTLM,
                    auto_bind=True,
                    receive_timeout=30
                )
            except Exception as e2:
                logger.warning(f"NTLM authentication also failed: {str(e2)}. Trying with UPN format...")
                # Try with UPN format (user@domain.com)
                conn = Connection(
                    server,
                    user=f"{AD_USERNAME}",
                    password=AD_PASSWORD,
                    authentication=SIMPLE,
                    auto_bind=True
                )
        
        if not conn.bound:
            logger.error("Failed to bind to Active Directory")
            return None
        
        # Search for the user - try multiple search methods
        search_filters = [
            f"(&(objectClass=user)(sAMAccountName={username}))",  # Search by sAMAccountName
            f"(&(objectClass=user)(mail={username}))",  # Search by email
            f"(&(objectClass=user)(userPrincipalName={username}))",  # Search by UPN
            f"(&(objectClass=user)(cn={username}))",  # Search by common name
        ]
        
        user_entry = None
        search_method = None
        
        for i, search_filter in enumerate(search_filters):
            try:
                conn.search(
                    search_base=AD_SEARCH_BASE,
                    search_filter=search_filter,
                    attributes=['sAMAccountName', 'displayName', 'givenName', 'sn', 'cn', 'mail', 'userPrincipalName']
                )
                
                if conn.entries:
                    user_entry = conn.entries[0]
                    search_method = ['sAMAccountName', 'mail', 'userPrincipalName', 'cn'][i]
                    logger.info(f"Found user {username} using {search_method} search")
                    break
            except Exception as e:
                logger.warning(f"Search method {i+1} failed: {str(e)}")
                continue
        
        if not user_entry:
            logger.warning(f"User {username} not found in Active Directory using any search method")
            return None
        
        # Extract user information
        user_info = {
            'sAMAccountName': str(user_entry.sAMAccountName.value) if hasattr(user_entry, 'sAMAccountName') and user_entry.sAMAccountName.value else username,
            'displayName': str(user_entry.displayName.value) if hasattr(user_entry, 'displayName') and user_entry.displayName.value else '',
            'givenName': str(user_entry.givenName.value) if hasattr(user_entry, 'givenName') and user_entry.givenName.value else '',
            'sn': str(user_entry.sn.value) if hasattr(user_entry, 'sn') and user_entry.sn.value else '',
            'cn': str(user_entry.cn.value) if hasattr(user_entry, 'cn') and user_entry.cn.value else '',
            'mail': str(user_entry.mail.value) if hasattr(user_entry, 'mail') and user_entry.mail.value else '',
            'userPrincipalName': str(user_entry.userPrincipalName.value) if hasattr(user_entry, 'userPrincipalName') and user_entry.userPrincipalName.value else '',
        }
        
        logger.info(f"Successfully retrieved AD user info for {username}")
        return user_info
        
    except ImportError:
        logger.error("ldap3 library not available. Cannot retrieve from Active Directory.")
        return None
    except Exception as e:
        error_msg = str(e)
        if "MD4" in error_msg or "unsupported hash type" in error_msg:
            logger.error(f"Active Directory connection failed due to MD4 hash compatibility issue: {error_msg}")
            logger.info("This is likely due to an older AD server or incompatible cryptographic libraries. Consider updating your AD server or using a different authentication method.")
        else:
            logger.error(f"Error retrieving from Active Directory: {error_msg}")
        return None


def update_ad_user_info(username, display_name, first_name, last_name, email=None):
    """Update user information in Active Directory"""
    try:
        import ldap3
        from ldap3 import Server, Connection, ALL, NTLM, SIMPLE
        
        # AD connection settings
        AD_SERVER = getattr(settings, 'AD_SERVER', 'ldap://your-ad-server.com')
        AD_DOMAIN = getattr(settings, 'AD_DOMAIN', 'your-domain.com')
        AD_USERNAME = getattr(settings, 'AD_USERNAME', 'service-account@your-domain.com')
        AD_PASSWORD = getattr(settings, 'AD_PASSWORD', '')
        AD_SEARCH_BASE = getattr(settings, 'AD_SEARCH_BASE', 'DC=your-domain,DC=com')
        
        # Connect to AD with fallback authentication methods
        server = Server(AD_SERVER, get_info=ALL)
        
        # Try SIMPLE authentication first (more compatible)
        conn = None
        try:
            conn = Connection(
                server,
                user=f"{AD_USERNAME}",
                password=AD_PASSWORD,
                authentication=SIMPLE,
                auto_bind=True
            )
        except Exception as e:
            logger.warning(f"SIMPLE authentication failed: {str(e)}. Trying NTLM...")
            # Fallback to NTLM with MD4 disabled
            try:
                conn = Connection(
                    server,
                    user=f"{AD_DOMAIN}\\{AD_USERNAME}",
                    password=AD_PASSWORD,
                    authentication=NTLM,
                    auto_bind=True,
                    receive_timeout=30
                )
            except Exception as e2:
                logger.warning(f"NTLM authentication also failed: {str(e2)}. Trying with UPN format...")
                # Try with UPN format (user@domain.com)
                conn = Connection(
                    server,
                    user=f"{AD_USERNAME}",
                    password=AD_PASSWORD,
                    authentication=SIMPLE,
                    auto_bind=True
                )
        
        if not conn.bound:
            logger.error("Failed to bind to Active Directory")
            return False
        
        # Search for the user - try multiple search methods
        search_filters = [
            f"(&(objectClass=user)(sAMAccountName={username}))",  # Search by sAMAccountName
            f"(&(objectClass=user)(mail={username}))",  # Search by email
            f"(&(objectClass=user)(userPrincipalName={username}))",  # Search by UPN
            f"(&(objectClass=user)(cn={username}))",  # Search by common name
        ]
        
        user_entry = None
        search_method = None
        
        for i, search_filter in enumerate(search_filters):
            try:
                conn.search(
                    search_base=AD_SEARCH_BASE,
                    search_filter=search_filter,
                    attributes=['distinguishedName', 'displayName', 'cn', 'givenName', 'sn', 'sAMAccountName', 'mail', 'userPrincipalName']
                )
                
                if conn.entries:
                    user_entry = conn.entries[0]
                    search_method = ['sAMAccountName', 'mail', 'userPrincipalName', 'cn'][i]
                    logger.info(f"Found user {username} using {search_method} search for update")
                    break
            except Exception as e:
                logger.warning(f"Search method {i+1} failed: {str(e)}")
                continue
        
        if not user_entry:
            logger.error(f"User {username} not found in Active Directory using any search method")
            return False
        
        user_dn = user_entry.entry_dn
        
        # Update user attributes - use displayName, givenName, sn, and mail
        # Note: cn (Common Name) is part of RDN and cannot be modified directly
        changes = {
            'displayName': [(ldap3.MODIFY_REPLACE, [display_name])],
            'givenName': [(ldap3.MODIFY_REPLACE, [first_name])],
            'sn': [(ldap3.MODIFY_REPLACE, [last_name])]
        }
        
        # Add email update if provided
        if email:
            changes['mail'] = [(ldap3.MODIFY_REPLACE, [email])]
        
        success = conn.modify(user_dn, changes=changes)
        
        if success:
            email_info = f", mail={email}" if email else ""
            logger.info(f"Successfully updated AD user {username}: displayName={display_name}, givenName={first_name}, sn={last_name}{email_info}")
            return True
        else:
            logger.error(f"Failed to update AD user {username}: {conn.result}")
            return False
            
    except ImportError:
        logger.error("ldap3 library not available. Cannot update Active Directory.")
        return False
    except Exception as e:
        error_msg = str(e)
        if "MD4" in error_msg or "unsupported hash type" in error_msg:
            logger.error(f"Active Directory update failed due to MD4 hash compatibility issue: {error_msg}")
            logger.info("This is likely due to an older AD server or incompatible cryptographic libraries. Consider updating your AD server or using a different authentication method.")
        else:
            logger.error(f"Error updating Active Directory: {error_msg}")
        return False

@csrf_exempt
def saml_logout_view(request):
    """
    Handle SAML Single Logout (SLS) - clears all session data and redirects to IdP logout
    """
    try:
        # Clear all session data
        if hasattr(request, 'session'):
            request.session.flush()
        
        # Perform Django logout
        logout(request)
        
        # Try to redirect to SAML SLS endpoint if available
        from django.conf import settings
        if getattr(settings, 'SAML_READY', False) and settings.SAML_CONFIG:
            try:
                return redirect('/saml2/sls/')
            except Exception:
                # Fallback to local logout
                messages.info(request, "You have been logged out from SSO.")
                return redirect('authentication:login')
        else:
            # SAML not configured, just do local logout
            messages.info(request, "You have been logged out.")
            return redirect('authentication:login')
            
    except Exception as e:
        logger.error(f"Error during SAML logout: {str(e)}")
        # Force logout anyway
        logout(request)
        return redirect('authentication:login')

def clear_saml_session(request):
    """Clear SAML session data manually"""
    # Clear SAML-related session data
    saml_keys = ['saml_authenticated', 'saml_name_id', 'saml2_session', 'authentication_method']
    for key in saml_keys:
        if key in request.session:
            del request.session[key]
    
    request.session.save()
    
    return HttpResponse("SAML Session Cleared")

def is_ad_user(request):
    """Check if the current user is from Active Directory (SAML)"""
    # Check for SAML authentication indicators
    is_saml_authenticated = request.session.get('saml_authenticated', False)
    auth_method = request.session.get('authentication_method', '')
    
    # Also check if user has no password set (indicating AD user)
    has_password = request.user.has_usable_password() if request.user.is_authenticated else False
    
    return is_saml_authenticated or auth_method == 'saml' or not has_password

@login_required
def change_password(request):
    """View for changing user password"""
    # Check if user is from AD - restrict password changes for AD users
    if is_ad_user(request):
        # Log the detection for debugging
        logger.info(f"AD user detected: {request.user.username}, has_password: {request.user.has_usable_password()}, saml_authenticated: {request.session.get('saml_authenticated', False)}, auth_method: {request.session.get('authentication_method', '')}")
    
    # Continue to render the template - it will show appropriate content based on user type
    
    if request.method == 'POST':
        # Prevent AD users from processing password change requests
        if is_ad_user(request):
            return render(request, 'authentication/change_password.html')
        current_password = request.POST.get('current_password')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')
        
        # Validate input
        if not current_password or not new_password or not confirm_password:
            messages.error(request, 'All fields are required.')
            return redirect('authentication:change_password')
        
        # Check if new password matches confirmation
        if new_password != confirm_password:
            messages.error(request, 'New password and confirmation password do not match.')
            return redirect('authentication:change_password')
        
        # Validate current password
        if not request.user.check_password(current_password):
            messages.error(request, 'Current password is incorrect.')
            return redirect('authentication:change_password')
        
        # Validate new password strength
        if len(new_password) < 8:
            messages.error(request, 'New password must be at least 8 characters long.')
            return redirect('authentication:change_password')
        
        try:
            # Update password
            request.user.set_password(new_password)
            request.user.save()
            
            # Update session to prevent logout
            update_session_auth_hash(request, request.user)
            
            # Log the password change activity
            ActivityLog.log_activity(
                user=request.user,
                activity_type='password_changed',
                description='Password was changed successfully',
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                session_id=request.session.session_key,
                details={'password_changed_at': str(timezone.now())}
            )
            
            messages.success(request, 'Password changed successfully!')
            return redirect('authentication:home')
            
        except Exception as e:
            logger.error(f"Error changing password for user {request.user.username}: {str(e)}")
            messages.error(request, 'An error occurred while changing your password.')
            return redirect('authentication:change_password')
    
    # GET request - show the form
    return render(request, 'authentication/change_password.html')

@login_required
def view_all_activities(request):
    """View for displaying all recent activities"""
    # Get last 20 activities for better display
    activities = request.user.activity_logs.all()[:20]
    
    # Calculate additional stats
    total_activities = request.user.activity_logs.count()
    security_activities = request.user.activity_logs.filter(
        activity_type__in=['mfa_enabled', 'mfa_disabled', 'device_registered', 'device_removed', 
                          'backup_codes_generated', 'backup_code_used', 'password_changed']
    ).count()
    
    # Get recent activity types for filtering
    recent_types = request.user.activity_logs.values_list('activity_type', flat=True).distinct()[:10]
    
    context = {
        'activities': activities,
        'total_activities': total_activities,
        'security_activities': security_activities,
        'recent_types': recent_types,
    }
    return render(request, 'authentication/view_all_activities.html', context)
# TOTP (Authenticator App) views
@login_required
def totp_setup(request):
    """Setup TOTP authenticator app"""
    from .models import TOTPDevice
    
    # Check if user already has a TOTP device
    existing_device = TOTPDevice.objects.filter(user=request.user, is_active=True).first()
    if existing_device and existing_device.confirmed:
        messages.info(request, "You already have an authenticator app configured.")
        return redirect('authentication:mfa_setup')
    
    if request.method == 'POST':
        device_name = request.POST.get('device_name', 'Authenticator App')
        
        # Create new TOTP device
        device = TOTPDevice.create_for_user(request.user, device_name)
        
        # Generate QR code
        qr_code = device.generate_qr_code()
        
        # Return JSON response for modal
        return JsonResponse({
            'success': True,
            'device': {
                'id': device.id,
                'name': device.name,
                'user': request.user.username,
                'secret': device.secret
            },
            'qr_code': qr_code
        })
    
    # Get AD context for consistent email display
    ad_context = get_ad_user_context(request.user)
    
    return render(request, 'authentication/totp_setup.html', ad_context)

@login_required 
def totp_verify_setup(request):
    """Verify TOTP setup with a test code"""
    from .models import TOTPDevice
    
    if request.method == 'POST':
        device_id = request.POST.get('device_id')
        token = request.POST.get('token', '').strip()
        
        if not device_id:
            return JsonResponse({'error': 'No device ID provided'}, status=400)
        
        try:
            device = TOTPDevice.objects.get(id=device_id, user=request.user)
        except TOTPDevice.DoesNotExist:
            return JsonResponse({'error': 'TOTP device not found'}, status=400)
        
        if device.verify_token(token):
            # Confirm the device
            device.confirm_device()
            device.update_last_used()
            
            # Log activity
            ActivityLog.log_activity(
                user=request.user,
                activity_type='totp_setup',
                description=f'TOTP authenticator "{device.name}" was set up successfully',
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                session_id=request.session.session_key
            )
            
            return JsonResponse({
                'success': True,
                'message': f"Authenticator app '{device.name}' has been successfully configured!"
            })
        else:
            return JsonResponse({'error': 'Invalid verification code'}, status=400)
    
    # For GET requests (fallback to old behavior)
    device_id = request.session.get('totp_device_id')
    if not device_id:
        messages.error(request, "No TOTP setup session found.")
        return redirect('authentication:mfa_setup')
    
    try:
        device = TOTPDevice.objects.get(id=device_id, user=request.user)
    except TOTPDevice.DoesNotExist:
        messages.error(request, "TOTP device not found.")
        return redirect('authentication:mfa_setup')
    
    # Get AD context for consistent email display
    ad_context = get_ad_user_context(request.user)
    
    context = {
        'device': device,
        **ad_context,  # Include AD email and display name
    }
    return render(request, 'authentication/totp_verify_setup.html', context)

@login_required
@require_POST 
def totp_remove(request, device_id):
    """Remove a TOTP device"""
    from .models import TOTPDevice
    
    try:
        device = TOTPDevice.objects.get(id=device_id, user=request.user)
        device_name = device.name
        device.delete()
        
        # Log activity
        ActivityLog.log_activity(
            user=request.user,
            activity_type='totp_removed',
            description=f'TOTP authenticator "{device_name}" was removed',
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            session_id=request.session.session_key
        )
        
        messages.success(request, f"Authenticator app '{device_name}' has been removed.")
    except TOTPDevice.DoesNotExist:
        messages.error(request, "TOTP device not found.")
    
    return redirect('authentication:mfa_setup')

@login_required
def totp_challenge(request):
    """TOTP challenge page during login"""
    from .models import TOTPDevice
    
    # Check if user has TOTP devices
    totp_devices = TOTPDevice.objects.filter(user=request.user, is_active=True, confirmed=True)
    if not totp_devices.exists():
        messages.error(request, "No TOTP devices found.")
        return redirect('authentication:login')
    
    if request.method == 'POST':
        token = request.POST.get('token', '').strip()
        
        # Try to verify with any of the user's TOTP devices
        for device in totp_devices:
            if device.verify_token(token):
                device.update_last_used()
                
                # Log successful MFA attempt
                MFAAttempt.objects.create(
                    user=request.user,
                    totp_device=device,
                    attempt_type='totp',
                    success=True,
                    ip_address=get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', '')
                )
                
                # Mark user as fully authenticated
                request.session['mfa_verified'] = True
                request.session['mfa_method'] = 'totp'
                
                # Log activity
                ActivityLog.log_activity(
                    user=request.user,
                    activity_type='login',
                    description=f'Successful login with TOTP authenticator "{device.name}"',
                    ip_address=get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    session_id=request.session.session_key
                )
                
                return redirect('authentication:home')
        
        # If we get here, the token was invalid
        MFAAttempt.objects.create(
            user=request.user,
            attempt_type='totp',
            success=False,
            error_message='Invalid TOTP token',
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        
        messages.error(request, "Invalid verification code. Please try again.")
    
    context = {
        'totp_devices': totp_devices,
    }
    return render(request, 'authentication/totp_challenge.html', context)

@login_required
def totp_qr_code(request, device_id):
    """Generate QR code for TOTP device"""
    from .models import TOTPDevice
    from django.http import HttpResponse
    
    try:
        device = TOTPDevice.objects.get(id=device_id, user=request.user)
        qr_code = device.generate_qr_code()
        
        # Extract base64 data
        img_data = qr_code.split(',')[1]
        img_bytes = base64.b64decode(img_data)
        
        response = HttpResponse(img_bytes, content_type='image/png')
        response['Content-Disposition'] = f'inline; filename="totp-qr-{device.name}.png"'
        return response
        
    except TOTPDevice.DoesNotExist:
        messages.error(request, "TOTP device not found.")
        return redirect('authentication:mfa_setup')

@require_POST  
def mfa_totp_authenticate(request):
    """Authenticate using TOTP during MFA challenge"""
    if not request.session.get('mfa_required'):
        return JsonResponse({'error': 'MFA not required'}, status=400)
    
    user_id = request.session.get('mfa_user_id')  
    if not user_id:
        return JsonResponse({'error': 'No user for MFA'}, status=400)
    
    try:
        from .models import TOTPDevice
        
        data = json.loads(request.body)
        token = data.get('token', '').strip()
        
        if not token:
            return JsonResponse({'error': 'No TOTP token provided'}, status=400)
        
        user = User.objects.get(id=user_id)
        
        # Get user's confirmed TOTP devices
        totp_devices = user.totp_devices.filter(is_active=True, confirmed=True)
        
        if not totp_devices.exists():
            return JsonResponse({'error': 'No TOTP devices found'}, status=400)
        
        # Try to verify with any of the user's TOTP devices
        device_used = None
        for device in totp_devices:
            if device.verify_token(token):
                device.update_last_used()
                device_used = device
                break
        
        if device_used:
            # Log successful authentication
            MFAAttempt.objects.create(
                user=user,
                totp_device=device_used,
                attempt_type='totp',
                success=True,
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            
            # Log the user in
            login(request, user, backend='django.contrib.auth.backends.ModelBackend')
            
            # Log activity
            ActivityLog.log_activity(
                user=user,
                activity_type='login',
                description='User logged in successfully with TOTP authenticator',
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                session_id=request.session.session_key,
                details={'remember_me': request.session.get('mfa_remember_me', False), 'mfa_required': True, 'device_name': device_used.name}
            )
            
            # Set session expiry based on remember me
            remember_me = request.session.get('mfa_remember_me', False)
            if not remember_me:
                request.session.set_expiry(0)
            
            # Clean up MFA session data
            del request.session['mfa_required']
            del request.session['mfa_user_id']
            if 'mfa_remember_me' in request.session:
                del request.session['mfa_remember_me']
            
            return JsonResponse({
                'success': True,
                'redirect': reverse('authentication:home'),
                'message': 'Successfully authenticated with TOTP'
            })
        else:
            # Log failed authentication
            MFAAttempt.objects.create(
                user=user,
                attempt_type='totp',
                success=False,
                error_message='Invalid TOTP token',
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            
            return JsonResponse({'error': 'Invalid verification code'}, status=400)
        
    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error: {str(e)}")
        return JsonResponse({'error': 'Invalid JSON data'}, status=400)
        
    except User.DoesNotExist:
        logger.error(f"User {user_id} does not exist")
        return JsonResponse({'error': 'User not found'}, status=400)
        
    except Exception as e:
        logger.error(f"Error with TOTP authentication: {str(e)}")
        return JsonResponse({'error': 'Authentication failed'}, status=500)

# Document Management Views
from django.core.files.storage import default_storage
from django.core.paginator import Paginator
from django.db.models import Q
from .models import Document

@login_required
def documents_list(request):
    """Display user's documents with filtering and search"""
    # Get filter parameters
    category = request.GET.get('category', '')
    search = request.GET.get('search', '')
    sort_by = request.GET.get('sort', '-created_at')
    
    # Get user's documents
    documents = Document.objects.filter(user=request.user, is_private=True)
    
    # Apply filters
    if category:
        documents = documents.filter(category=category)
    
    if search:
        documents = documents.filter(
            Q(title__icontains=search) |
            Q(description__icontains=search) |
            Q(original_filename__icontains=search) |
            Q(tags__icontains=search)
        )
    
    # Apply sorting
    documents = documents.order_by(sort_by)
    
    # Pagination
    paginator = Paginator(documents, 12)  # 12 documents per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    # Get category choices for filter dropdown
    category_choices = Document.CATEGORY_CHOICES
    
    context = {
        'documents': page_obj,
        'category_choices': category_choices,
        'current_category': category,
        'current_search': search,
        'current_sort': sort_by,
        'total_documents': documents.count(),
    }
    
    return render(request, 'authentication/documents_list.html', context)

@login_required
def document_upload(request):
    """Handle document upload"""
    if request.method == 'POST':
        try:
            # Get form data
            title = request.POST.get('title', '').strip()
            description = request.POST.get('description', '').strip()
            category = request.POST.get('category', 'personal')
            tags = request.POST.get('tags', '').strip()
            file = request.FILES.get('file')
            
            # Validate required fields
            if not title:
                return JsonResponse({'error': 'Title is required'}, status=400)
            
            if not file:
                return JsonResponse({'error': 'File is required'}, status=400)
            
            # Check file size (max 50MB)
            max_size = 50 * 1024 * 1024  # 50MB
            if file.size > max_size:
                return JsonResponse({'error': 'File size too large. Maximum size is 50MB.'}, status=400)
            
            # Create document
            document = Document.objects.create(
                user=request.user,
                title=title,
                description=description,
                category=category,
                tags=tags,
                file=file
            )
            
            # Log activity
            ActivityLog.log_activity(
                user=request.user,
                activity_type='document_uploaded',
                description=f'Uploaded document: {title}',
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                session_id=request.session.session_key,
                details={
                    'document_id': document.id,
                    'file_name': document.original_filename,
                    'file_size': document.file_size,
                    'file_type': document.file_type,
                    'category': category
                }
            )
            
            return JsonResponse({
                'success': True,
                'message': 'Document uploaded successfully',
                'document': {
                    'id': document.id,
                    'title': document.title,
                    'file_size': document.get_file_size_display(),
                    'file_type': document.file_type,
                    'category': document.get_category_display(),
                    'created_at': document.created_at.strftime('%Y-%m-%d %H:%M')
                }
            })
            
        except Exception as e:
            logger.error(f"Error uploading document: {str(e)}")
            return JsonResponse({'error': 'Failed to upload document'}, status=500)
    
    # GET request - show upload form
    context = {
        'category_choices': Document.CATEGORY_CHOICES,
    }
    return render(request, 'authentication/document_upload.html', context)

@login_required
def document_detail(request, document_id):
    """View document details and download"""
    try:
        document = Document.objects.get(id=document_id, user=request.user, is_private=True)
        
        # Update last accessed
        document.update_last_accessed()
        
        # Log activity
        ActivityLog.log_activity(
            user=request.user,
            activity_type='document_accessed',
            description=f'Accessed document: {document.title}',
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            session_id=request.session.session_key,
            details={'document_id': document.id}
        )
        
        context = {
            'document': document,
        }
        return render(request, 'authentication/document_detail.html', context)
        
    except Document.DoesNotExist:
        messages.error(request, 'Document not found or access denied.')
        return redirect('authentication:documents_list')

@login_required
def document_download(request, document_id):
    """Download document file"""
    try:
        document = Document.objects.get(id=document_id, user=request.user, is_private=True)
        
        # Update last accessed
        document.update_last_accessed()
        
        # Log activity
        ActivityLog.log_activity(
            user=request.user,
            activity_type='document_downloaded',
            description=f'Downloaded document: {document.title}',
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            session_id=request.session.session_key,
            details={'document_id': document.id}
        )
        
        # Return file response
        response = HttpResponse(document.file.read(), content_type=document.file_type)
        response['Content-Disposition'] = f'attachment; filename="{document.original_filename}"'
        return response
        
    except Document.DoesNotExist:
        return HttpResponse('Document not found', status=404)

@login_required
@require_POST
def document_delete(request, document_id):
    """Delete document"""
    try:
        document = Document.objects.get(id=document_id, user=request.user, is_private=True)
        
        # Log activity before deletion
        ActivityLog.log_activity(
            user=request.user,
            activity_type='document_deleted',
            description=f'Deleted document: {document.title}',
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            session_id=request.session.session_key,
            details={'document_id': document.id, 'file_name': document.original_filename}
        )
        
        # Delete file from storage
        if document.file:
            document.file.delete(save=False)
        
        # Delete document record
        document.delete()
        
        return JsonResponse({
            'success': True,
            'message': 'Document deleted successfully'
        })
        
    except Document.DoesNotExist:
        return JsonResponse({'error': 'Document not found'}, status=404)
    except Exception as e:
        logger.error(f"Error deleting document: {str(e)}")
        return JsonResponse({'error': 'Failed to delete document'}, status=500)

@login_required
@require_POST
def document_update(request, document_id):
    """Update document metadata"""
    try:
        document = Document.objects.get(id=document_id, user=request.user, is_private=True)
        
        # Get form data
        title = request.POST.get('title', '').strip()
        description = request.POST.get('description', '').strip()
        category = request.POST.get('category', 'personal')
        tags = request.POST.get('tags', '').strip()
        
        # Validate required fields
        if not title:
            return JsonResponse({'error': 'Title is required'}, status=400)
        
        # Update document
        document.title = title
        document.description = description
        document.category = category
        document.tags = tags
        document.save()
        
        # Log activity
        ActivityLog.log_activity(
            user=request.user,
            activity_type='document_updated',
            description=f'Updated document: {title}',
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            session_id=request.session.session_key,
            details={'document_id': document.id}
        )
        
        return JsonResponse({
            'success': True,
            'message': 'Document updated successfully',
            'document': {
                'id': document.id,
                'title': document.title,
                'description': document.description,
                'category': document.get_category_display(),
                'tags': document.tags,
                'updated_at': document.updated_at.strftime('%Y-%m-%d %H:%M')
            }
        })
        
    except Document.DoesNotExist:
        return JsonResponse({'error': 'Document not found'}, status=404)
    except Exception as e:
        logger.error(f"Error updating document: {str(e)}")
        return JsonResponse({'error': 'Failed to update document'}, status=500)

@login_required
def user_database_view(request):
    """Display all users in the database in a table format"""
    # Only allow staff users to view this
    if not request.user.is_staff:
        messages.error(request, 'You do not have permission to view this page.')
        return redirect('authentication:home')
    
    # Get all users with their related data
    users = User.objects.all().order_by('id')
    
    # Get additional user data
    user_data = []
    for user in users:
        # Get MFA preference
        try:
            mfa_pref = user.mfa_preference
            mfa_enabled = mfa_pref.mfa_enabled
        except:
            mfa_enabled = False
        
        # Get TOTP devices count
        totp_devices = user.totp_devices.filter(is_active=True).count()
        
        # Get WebAuthn credentials count
        webauthn_creds = user.webauthn_credentials.filter(is_active=True).count()
        
        # Get last login
        last_login = user.last_login.strftime('%Y-%m-%d %H:%M:%S') if user.last_login else 'Never'
        
        # Get date joined
        date_joined = user.date_joined.strftime('%Y-%m-%d %H:%M:%S')
        
        user_data.append({
            'user': user,
            'mfa_enabled': mfa_enabled,
            'totp_devices': totp_devices,
            'webauthn_creds': webauthn_creds,
            'last_login': last_login,
            'date_joined': date_joined,
        })
    
    context = {
        'user_data': user_data,
        'total_users': users.count(),
    }
    
    return render(request, 'authentication/user_database.html', context)


@login_required
def calendar_view(request):
    """
    Calendar view that integrates with Google Calendar
    """
    try:
        # Get user email for Google Calendar integration
        user_email = None
        
        # Try to get email from SAML attributes first
        if hasattr(request, 'session') and 'saml_attributes' in request.session:
            saml_attributes = request.session['saml_attributes']
            email_keys = [
                'mail',
                'email', 
                'userPrincipalName',
                'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
                'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
                'http://schemas.microsoft.com/ws/2008/06/identity/claims/emailaddress',
                'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn',
            ]
            
            for key in email_keys:
                if key in saml_attributes and saml_attributes[key]:
                    user_email = saml_attributes[key]
                    if isinstance(user_email, list):
                        user_email = user_email[0]
                    break
        
        # Fallback to Django user email
        if not user_email:
            user_email = request.user.email
        
        # If still no email, use username with @gmail.com
        if not user_email:
            user_email = f"{request.user.username}@gmail.com"
        
        # Log activity
        ActivityLog.objects.create(
            user=request.user,
            activity_type='calendar_access',
            description='Accessed calendar application',
            ip_address=request.META.get('REMOTE_ADDR', ''),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        
        context = {
            'user_email': user_email,
            'user': request.user,
        }
        
        return render(request, 'authentication/calendar.html', context)
        
    except Exception as e:
        logger.error(f"Error in calendar view: {str(e)}")
        messages.error(request, 'Error loading calendar. Please try again.')
        return redirect('authentication:home')


@login_required
def google_calendar_redirect(request):
    """
    Redirect to Google Calendar with user's email
    """
    try:
        # Get user email
        user_email = None
        
        # Try to get email from SAML attributes first
        if hasattr(request, 'session') and 'saml_attributes' in request.session:
            saml_attributes = request.session['saml_attributes']
            email_keys = [
                'mail',
                'email', 
                'userPrincipalName',
                'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
                'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
                'http://schemas.microsoft.com/ws/2008/06/identity/claims/emailaddress',
                'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn',
            ]
            
            for key in email_keys:
                if key in saml_attributes and saml_attributes[key]:
                    user_email = saml_attributes[key]
                    if isinstance(user_email, list):
                        user_email = user_email[0]
                    break
        
        # Fallback to Django user email
        if not user_email:
            user_email = request.user.email
        
        # If still no email, use username with @gmail.com
        if not user_email:
            user_email = f"{request.user.username}@gmail.com"
        
        # Log activity
        ActivityLog.objects.create(
            user=request.user,
            activity_type='google_calendar_redirect',
            description='Redirected to Google Calendar',
            ip_address=request.META.get('REMOTE_ADDR', ''),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        
        # Redirect to Google Calendar
        google_calendar_url = "https://calendar.google.com/calendar/u/0/r"
        return redirect(google_calendar_url)
        
    except Exception as e:
        logger.error(f"Error redirecting to Google Calendar: {str(e)}")
        messages.error(request, 'Error opening Google Calendar. Please try again.')
        return redirect('authentication:home')


@login_required
def maps_view(request):
    """
    Maps view that integrates with Google Maps
    """
    try:
        # Get user email for Google Maps integration
        user_email = None
        
        # Try to get email from SAML attributes first
        if hasattr(request, 'session') and 'saml_attributes' in request.session:
            saml_attributes = request.session['saml_attributes']
            email_keys = [
                'mail',
                'email', 
                'userPrincipalName',
                'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
                'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
                'http://schemas.microsoft.com/ws/2008/06/identity/claims/emailaddress',
                'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn',
            ]
            
            for key in email_keys:
                if key in saml_attributes and saml_attributes[key]:
                    user_email = saml_attributes[key]
                    if isinstance(user_email, list):
                        user_email = user_email[0]
                    break
        
        # Fallback to Django user email
        if not user_email:
            user_email = request.user.email
        
        # If still no email, use username with @gmail.com
        if not user_email:
            user_email = f"{request.user.username}@gmail.com"
        
        # Log activity
        ActivityLog.objects.create(
            user=request.user,
            activity_type='maps_access',
            description='Accessed maps application',
            ip_address=request.META.get('REMOTE_ADDR', ''),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        
        context = {
            'user_email': user_email,
            'user': request.user,
        }
        
        return render(request, 'authentication/maps.html', context)
        
    except Exception as e:
        logger.error(f"Error in maps view: {str(e)}")
        messages.error(request, 'Error loading maps. Please try again.')
        return redirect('authentication:home')


@login_required
def google_maps_redirect(request):
    """
    Redirect to Google Maps with user's email
    """
    try:
        # Get user email
        user_email = None
        
        # Try to get email from SAML attributes first
        if hasattr(request, 'session') and 'saml_attributes' in request.session:
            saml_attributes = request.session['saml_attributes']
            email_keys = [
                'mail',
                'email', 
                'userPrincipalName',
                'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
                'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
                'http://schemas.microsoft.com/ws/2008/06/identity/claims/emailaddress',
                'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn',
            ]
            
            for key in email_keys:
                if key in saml_attributes and saml_attributes[key]:
                    user_email = saml_attributes[key]
                    if isinstance(user_email, list):
                        user_email = user_email[0]
                    break
        
        # Fallback to Django user email
        if not user_email:
            user_email = request.user.email
        
        # If still no email, use username with @gmail.com
        if not user_email:
            user_email = f"{request.user.username}@gmail.com"
        
        # Log activity
        ActivityLog.objects.create(
            user=request.user,
            activity_type='google_maps_redirect',
            description='Redirected to Google Maps',
            ip_address=request.META.get('REMOTE_ADDR', ''),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        
        # Redirect to Google Maps
        google_maps_url = "https://maps.google.com/"
        return redirect(google_maps_url)
        
    except Exception as e:
        logger.error(f"Error redirecting to Google Maps: {str(e)}")
        messages.error(request, 'Error opening Google Maps. Please try again.')
        return redirect('authentication:home')


@login_required
def meet_view(request):
    """
    Meet view that integrates with Google Meet
    """
    try:
        # Get user email for Google Meet integration
        user_email = None
        
        # Try to get email from SAML attributes first
        if hasattr(request, 'session') and 'saml_attributes' in request.session:
            saml_attributes = request.session['saml_attributes']
            email_keys = [
                'mail',
                'email', 
                'userPrincipalName',
                'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
                'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
                'http://schemas.microsoft.com/ws/2008/06/identity/claims/emailaddress',
                'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn',
            ]
            
            for key in email_keys:
                if key in saml_attributes and saml_attributes[key]:
                    user_email = saml_attributes[key]
                    if isinstance(user_email, list):
                        user_email = user_email[0]
                    break
        
        # Fallback to Django user email
        if not user_email:
            user_email = request.user.email
        
        # If still no email, use username with @gmail.com
        if not user_email:
            user_email = f"{request.user.username}@gmail.com"
        
        # Log activity
        ActivityLog.objects.create(
            user=request.user,
            activity_type='meet_access',
            description='Accessed meet application',
            ip_address=request.META.get('REMOTE_ADDR', ''),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        
        context = {
            'user_email': user_email,
            'user': request.user,
        }
        
        return render(request, 'authentication/meet.html', context)
        
    except Exception as e:
        logger.error(f"Error in meet view: {str(e)}")
        messages.error(request, 'Error loading meet. Please try again.')
        return redirect('authentication:home')


@login_required
def google_meet_redirect(request):
    """
    Redirect to Google Meet with user's email
    """
    try:
        # Get user email
        user_email = None
        
        # Try to get email from SAML attributes first
        if hasattr(request, 'session') and 'saml_attributes' in request.session:
            saml_attributes = request.session['saml_attributes']
            email_keys = [
                'mail',
                'email', 
                'userPrincipalName',
                'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
                'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
                'http://schemas.microsoft.com/ws/2008/06/identity/claims/emailaddress',
                'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn',
            ]
            
            for key in email_keys:
                if key in saml_attributes and saml_attributes[key]:
                    user_email = saml_attributes[key]
                    if isinstance(user_email, list):
                        user_email = user_email[0]
                    break
        
        # Fallback to Django user email
        if not user_email:
            user_email = request.user.email
        
        # If still no email, use username with @gmail.com
        if not user_email:
            user_email = f"{request.user.username}@gmail.com"
        
        # Log activity
        ActivityLog.objects.create(
            user=request.user,
            activity_type='google_meet_redirect',
            description='Redirected to Google Meet',
            ip_address=request.META.get('REMOTE_ADDR', ''),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        
        # Redirect to Google Meet
        google_meet_url = "https://meet.google.com/"
        return redirect(google_meet_url)
        
    except Exception as e:
        logger.error(f"Error redirecting to Google Meet: {str(e)}")
        messages.error(request, 'Error opening Google Meet. Please try again.')
        return redirect('authentication:home')


@login_required
def translate_view(request):
    """
    Translate view that integrates with Google Translate
    """
    try:
        # Get user email for Google Translate integration
        user_email = None
        
        # Try to get email from SAML attributes first
        if hasattr(request, 'session') and 'saml_attributes' in request.session:
            saml_attributes = request.session['saml_attributes']
            email_keys = [
                'mail',
                'email', 
                'userPrincipalName',
                'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
                'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
                'http://schemas.microsoft.com/ws/2008/06/identity/claims/emailaddress',
                'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn',
            ]
            
            for key in email_keys:
                if key in saml_attributes and saml_attributes[key]:
                    user_email = saml_attributes[key]
                    if isinstance(user_email, list):
                        user_email = user_email[0]
                    break
        
        # Fallback to Django user email
        if not user_email:
            user_email = request.user.email
        
        # If still no email, use username with @gmail.com
        if not user_email:
            user_email = f"{request.user.username}@gmail.com"
        
        # Log activity
        ActivityLog.objects.create(
            user=request.user,
            activity_type='translate_access',
            description='Accessed translate application',
            ip_address=request.META.get('REMOTE_ADDR', ''),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        
        context = {
            'user_email': user_email,
            'user': request.user,
        }
        
        return render(request, 'authentication/translate.html', context)
        
    except Exception as e:
        logger.error(f"Error in translate view: {str(e)}")
        messages.error(request, 'Error loading translate. Please try again.')
        return redirect('authentication:home')


@login_required
def google_translate_redirect(request):
    """
    Redirect to Google Translate with user's email
    """
    try:
        # Get user email
        user_email = None
        
        # Try to get email from SAML attributes first
        if hasattr(request, 'session') and 'saml_attributes' in request.session:
            saml_attributes = request.session['saml_attributes']
            email_keys = [
                'mail',
                'email', 
                'userPrincipalName',
                'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
                'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
                'http://schemas.microsoft.com/ws/2008/06/identity/claims/emailaddress',
                'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn',
            ]
            
            for key in email_keys:
                if key in saml_attributes and saml_attributes[key]:
                    user_email = saml_attributes[key]
                    if isinstance(user_email, list):
                        user_email = user_email[0]
                    break
        
        # Fallback to Django user email
        if not user_email:
            user_email = request.user.email
        
        # If still no email, use username with @gmail.com
        if not user_email:
            user_email = f"{request.user.username}@gmail.com"
        
        # Log activity
        ActivityLog.objects.create(
            user=request.user,
            activity_type='google_translate_redirect',
            description='Redirected to Google Translate',
            ip_address=request.META.get('REMOTE_ADDR', ''),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        
        # Redirect to Google Translate
        google_translate_url = "https://translate.google.com/"
        return redirect(google_translate_url)
        
    except Exception as e:
        logger.error(f"Error redirecting to Google Translate: {str(e)}")
        messages.error(request, 'Error opening Google Translate. Please try again.')
        return redirect('authentication:home')
