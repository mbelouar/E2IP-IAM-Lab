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
        <title>Processing SAML Authentication...</title>
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
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
                display: flex;
                flex-direction: column;
                justify-content: center;
                align-items: center;
                color: var(--gray-900);
                line-height: 1.6;
                -webkit-font-smoothing: antialiased;
                -moz-osx-font-smoothing: grayscale;
                text-rendering: optimizeLegibility;
                position: relative;
                overflow-x: hidden;
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

            .floating-elements {{
                position: absolute;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
            }}

            /* Enhanced floating elements */
            .floating-element {{
                position: absolute;
                border-radius: 50%;
                filter: blur(2px);
                animation: float 12s ease-in-out infinite;
                background: linear-gradient(135deg, rgba(255, 255, 255, 0.05) 0%, rgba(255, 255, 255, 0.02) 100%);
                backdrop-filter: blur(5px);
                border: 1px solid rgba(255, 255, 255, 0.05);
            }}

            .floating-element:nth-child(1) {{
                width: 200px;
                height: 200px;
                left: 10%;
                top: 10%;
                animation-delay: 0s;
            }}

            .floating-element:nth-child(2) {{
                width: 150px;
                height: 150px;
                left: 85%;
                top: 15%;
                animation-delay: 3s;
            }}

            .floating-element:nth-child(3) {{
                width: 180px;
                height: 180px;
                left: 70%;
                top: 70%;
                animation-delay: 6s;
            }}

            .floating-element:nth-child(4) {{
                width: 120px;
                height: 120px;
                left: 20%;
                top: 80%;
                animation-delay: 9s;
            }}

            /* Add more floating elements */
            .floating-element:nth-child(5) {{
                width: 100px;
                height: 100px;
                left: 50%;
                top: 25%;
                animation-delay: 2s;
                animation-duration: 15s;
            }}

            .floating-element:nth-child(6) {{
                width: 80px;
                height: 80px;
                left: 30%;
                top: 50%;
                animation-delay: 7s;
                animation-duration: 18s;
            }}

            /* Enhanced animation */
            @keyframes float {{
                0% {{ 
                    transform: translateY(0) translateX(0) rotate(0deg);
                    opacity: 0.6;
                }}
                25% {{
                    transform: translateY(-30px) translateX(20px) rotate(90deg);
                    opacity: 0.8;
                }}
                50% {{ 
                    transform: translateY(-60px) translateX(0px) rotate(180deg);
                    opacity: 0.6;
                }}
                75% {{
                    transform: translateY(-30px) translateX(-20px) rotate(270deg);
                    opacity: 0.8;
                }}
                100% {{ 
                    transform: translateY(0) translateX(0) rotate(360deg);
                    opacity: 0.6;
                }}
            }}

            /* Enhanced circuit lines */
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

            /* Processing Container */
            .processing-container {{
                background: rgba(255, 255, 255, 0.95);
                backdrop-filter: blur(20px);
                padding: var(--space-3xl);
                border-radius: var(--radius-2xl);
                box-shadow: var(--shadow-2xl);
                text-align: center;
                max-width: 520px;
                width: 90%;
                position: relative;
                z-index: 10;
                border: 1px solid rgba(255, 255, 255, 0.2);
                animation: fadeInScale 0.6s cubic-bezier(0.16, 1, 0.3, 1);
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

            /* Logo Section */
            .logo-section {{
                margin-bottom: var(--space-xl);
            }}

            .logo-container {{
                display: flex;
                flex-direction: column;
                align-items: center;
                gap: var(--space-md);
            }}

            .logo-icon {{
                width: 48px;
                height: 48px;
                padding: var(--space-md);
                background: linear-gradient(135deg, var(--primary-blue), var(--primary-blue-light));
                color: white;
                border-radius: var(--radius-xl);
                box-shadow: var(--shadow-lg);
            }}

            .company-info {{
                text-align: center;
            }}

            .company-name {{
                font-size: 1.25rem;
                font-weight: 700;
                color: var(--primary-blue);
                margin-bottom: var(--space-xs);
            }}

            .company-tagline {{
                font-size: 0.875rem;
                color: var(--gray-600);
                font-weight: 500;
            }}

            /* Spinner */
            .spinner-container {{
                margin: var(--space-xl) 0;
            }}

            .spinner {{
                width: 64px;
                height: 64px;
                border: 4px solid var(--gray-200);
                border-top: 4px solid var(--primary-blue);
                border-radius: 50%;
                animation: spin 1s linear infinite;
                margin: 0 auto;
                position: relative;
            }}

            .spinner::after {{
                content: '';
                position: absolute;
                top: -4px;
                left: -4px;
                right: -4px;
                bottom: -4px;
                border: 2px solid transparent;
                border-top: 2px solid var(--primary-blue-light);
                border-radius: 50%;
                animation: spin 2s linear infinite reverse;
            }}

            @keyframes spin {{
                0% {{ transform: rotate(0deg); }}
                100% {{ transform: rotate(360deg); }}
            }}

            /* Typography */
            .processing-title {{
                font-size: 1.75rem;
                font-weight: 700;
                margin-bottom: var(--space-md);
                color: var(--gray-900);
                letter-spacing: -0.025em;
            }}

            .processing-message {{
                font-size: 1rem;
                color: var(--gray-600);
                margin-bottom: var(--space-xl);
                line-height: 1.6;
                font-weight: 500;
            }}

            .countdown {{
                font-size: 0.95rem;
                color: var(--gray-500);
                margin-top: var(--space-lg);
                font-weight: 500;
                display: flex;
                align-items: center;
                justify-content: center;
                gap: var(--space-sm);
            }}

            .countdown-number {{
                display: inline-flex;
                align-items: center;
                justify-content: center;
                width: 28px;
                height: 28px;
                background: var(--primary-blue);
                color: white;
                border-radius: 50%;
                font-weight: 600;
                font-size: 0.875rem;
                animation: pulse 1s ease-in-out infinite;
            }}

            @keyframes pulse {{
                0%, 100% {{ transform: scale(1); }}
                50% {{ transform: scale(1.1); }}
            }}

            /* Technical Info */
            .technical-info {{
                margin-top: var(--space-xl);
                padding: var(--space-lg);
                background: linear-gradient(to right, rgba(0, 102, 204, 0.05), rgba(51, 133, 214, 0.05));
                border-radius: var(--radius-lg);
                font-size: 0.875rem;
                color: var(--gray-600);
                border-left: 3px solid var(--primary-blue-light);
                text-align: left;
            }}

            .technical-info strong {{
                color: var(--gray-800);
                font-weight: 600;
                display: block;
                margin-bottom: var(--space-sm);
            }}

            .technical-info ul {{
                list-style: none;
                margin: 0;
                padding: 0;
            }}

            .technical-info li {{
                display: flex;
                align-items: center;
                margin-bottom: var(--space-sm);
                padding-left: var(--space-md);
                position: relative;
            }}

            .technical-info li::before {{
                content: '✓';
                position: absolute;
                left: 0;
                color: var(--success);
                font-weight: 600;
                font-size: 0.75rem;
            }}

            .technical-info li:last-child {{
                margin-bottom: 0;
            }}

            /* Status indicator */
            .status-indicator {{
                display: flex;
                align-items: center;
                justify-content: center;
                gap: var(--space-sm);
                margin-top: var(--space-lg);
                padding: var(--space-md);
                background: rgba(0, 168, 107, 0.1);
                border-radius: var(--radius-lg);
                color: var(--success);
                font-size: 0.875rem;
                font-weight: 600;
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

        <div class="processing-container">
            <!-- Logo Section -->
            <div class="logo-section">
                <div class="logo-container">
                    <div class="logo-icon">
                        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                            <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
                        </svg>
                    </div>
                    <div class="company-info">
                        <div class="company-name">SecureAuth</div>
                        <div class="company-tagline">Enterprise Access Portal</div>
                    </div>
                </div>
            </div>

            <!-- Spinner -->
            <div class="spinner-container">
                <div class="spinner"></div>
            </div>

            <h1 class="processing-title">Processing SAML Authentication</h1>
            <p class="processing-message">
                Successfully received authentication response from ADFS.<br>
                Processing your credentials and creating your session...
            </p>
            
            <div class="technical-info">
                <strong>Authentication Progress:</strong>
                <ul>
                    <li>SAML Response received from ADFS</li>
                    <li>Validating digital signatures</li>
                    <li>Extracting user attributes</li>
                    <li>Creating secure session</li>
                </ul>
            </div>

            <div class="status-indicator">
                <div class="status-dot"></div>
                <span>Authentication in progress</span>
            </div>
            
            <p class="countdown">
                This page will automatically continue in 
                <span class="countdown-number" id="countdown">3</span> 
                seconds...
            </p>
            
            <!-- Hidden auto-submit form -->
            <form id="samlForm" method="POST" style="display: none;">
                <input type="hidden" name="SAMLResponse" value="{saml_response}">
                <input type="hidden" name="RelayState" value="{relay_state}">
                <input type="hidden" name="_processing" value="true">
            </form>
        </div>
        
        <script>
            let countdown = 3;
            const countdownElement = document.getElementById('countdown');
            const statusIndicator = document.querySelector('.status-indicator span');
            
            const timer = setInterval(() => {{
                countdown--;
                countdownElement.textContent = countdown;
                
                if (countdown <= 0) {{
                    clearInterval(timer);
                    countdownElement.textContent = '0';
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
