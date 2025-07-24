from django.shortcuts import render, redirect
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import HttpResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.models import User
import logging
import json
import base64
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)

@login_required
def home(request):
    """View for the home page (only accessible when logged in)"""
    return render(request, 'authentication/home.html')

def login_view(request):
    """View for user login - using our SecureAuth template"""
    if request.user.is_authenticated:
        return redirect('authentication:home')
    
    # Handle form submission
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        remember_me = request.POST.get('rememberMe') == 'on'
        
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            login(request, user, backend='django.contrib.auth.backends.ModelBackend')
            
            # Set session expiry based on remember me
            if not remember_me:
                # Session expires when browser closes
                request.session.set_expiry(0)
            
            return redirect('authentication:home')
        else:
            messages.error(request, "Invalid username or password.")
    
    return render(request, 'authentication/login.html')

def logout_view(request):
    """View for user logout"""
    logout(request)
    messages.info(request, "You have successfully logged out.")
    return redirect('authentication:login')

@require_http_methods(["GET"])
def adfs_login(request):
    """
    Redirect to SAML SSO authentication
    """
    return redirect('/saml2/login/')

@login_required
def sso_success(request):
    """
    Handle successful SSO authentication
    """
    if request.user.is_authenticated:
        messages.success(request, f"Welcome {request.user.first_name or request.user.username}! You have successfully authenticated via SSO.")
        return redirect('authentication:home')
    else:
        messages.error(request, "SSO authentication failed. Please try again.")
        return redirect('authentication:login')

def saml_debug_view(request):
    """
    Debug view to check SAML configuration
    """
    from django.conf import settings
    
    debug_info = {
        'SAML_CONFIG': {
            'entityid': settings.SAML_CONFIG.get('entityid'),
            'debug': settings.SAML_CONFIG.get('debug'),
            'metadata': 'configured' if settings.SAML_CONFIG.get('metadata') else 'not configured'
        },
        'request_info': {
            'user_authenticated': request.user.is_authenticated,
            'session_keys': list(request.session.keys()) if hasattr(request, 'session') else [],
            'request_method': request.method,
            'GET_params': dict(request.GET),
            'POST_params': dict(request.POST) if request.method == 'POST' else {}
        }
    }
    
    return HttpResponse(f"<pre>{json.dumps(debug_info, indent=2)}</pre>", content_type='text/html')

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
    <p><a href="/authentication/saml-debug/">View SAML Debug Info</a></p>
    """, content_type='text/html')

@csrf_exempt
def custom_saml_acs(request):
    """
    Custom SAML Assertion Consumer Service for debugging
    """
    if request.method == 'POST':
        saml_response = request.POST.get('SAMLResponse', '')
        relay_state = request.POST.get('RelayState', '/')
        
        logger.info(f"Received SAML Response: {saml_response[:100]}...")
        
        try:
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
                
            # Log the user in with explicit backend
            login(request, user, backend='django.contrib.auth.backends.ModelBackend')
            messages.success(request, f"Successfully authenticated via SAML! Welcome {user.first_name or user.username}!")
            
            return redirect(relay_state or 'authentication:home')
            
        except Exception as e:
            logger.error(f"Error processing SAML response: {str(e)}")
            return HttpResponse(f"""
                <h1>SAML Response Debug</h1>
                <h2>Error:</h2>
                <p>{str(e)}</p>
                <h2>Raw SAML Response:</h2>
                <textarea rows="10" cols="100">{saml_response}</textarea>
                <h2>Decoded Response:</h2>
                <textarea rows="20" cols="100">{decoded_response if 'decoded_response' in locals() else 'Failed to decode'}</textarea>
                <p><a href="/authentication/login/">Back to Login</a></p>
            """, content_type='text/html')
    
    return HttpResponse("Method not allowed", status=405)
