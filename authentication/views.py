from django.shortcuts import render, redirect
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import HttpResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.models import User
from django.utils import timezone
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
    """View for user logout - aggressive session and cache clearing with SAML SLO"""
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
            
            # Redirect to SAML Single Logout which should contact ADFS
            try:
                return redirect('/saml2/sls/')
            except Exception as e:
                logger.warning(f"SAML SLS redirect failed: {e}, falling back to regular logout")
                
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
    response['Clear-Site-Data'] = '"cache", "cookies", "storage", "executionContexts"'
    
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
            
            # Store SAML session information for proper logout
            request.session['saml_authenticated'] = True
            request.session['saml_name_id'] = name_id
            request.session['saml_user_email'] = email
            request.session['saml_login_time'] = str(timezone.now()) if 'timezone' in globals() else 'unknown'
            
            # Mark this as a SAML session for logout purposes
            request.session['authentication_method'] = 'saml'
            
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
        try:
            return redirect('/saml2/sls/')
        except Exception:
            # Fallback to local logout
            messages.info(request, "You have been logged out from SSO.")
            return redirect('authentication:login')
            
    except Exception as e:
        logger.error(f"Error during SAML logout: {str(e)}")
        # Force logout anyway
        logout(request)
        return redirect('authentication:login')




