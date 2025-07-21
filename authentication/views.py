from django.shortcuts import render, redirect
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import HttpResponse
from django.views.decorators.http import require_http_methods

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
            login(request, user)
            
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
    Placeholder for ADFS authentication
    This function will be expanded when implementing ADFS SSO
    """
    # This is just a placeholder - in a real implementation this would:
    # 1. Redirect to ADFS server for authentication
    # 2. Handle the response from ADFS
    # 3. Create or authenticate the user based on ADFS claims
    # 4. Log the user in
    
    # For demonstration purposes, we're simulating a successful SSO login
    # In a real implementation, this would be replaced with actual ADFS/SAML integration
    
    # Auto-login a dummy user to simulate SSO authentication
    # In real implementation, this would be handled by the SSO provider
    user = authenticate(request, username='admin', password='admin')
    if user is not None:
        login(request, user)
        messages.success(request, "Successfully authenticated via SSO.")
        return redirect('authentication:home')
    else:
        messages.error(request, "SSO authentication failed. Please try again or contact support.")
        return redirect('authentication:login')
