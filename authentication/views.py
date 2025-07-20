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
    """View for user login - simplified to only show ADFS login option"""
    if request.user.is_authenticated:
        return redirect('home')
    
    # Simply render the login page with ADFS button only
    return render(request, 'authentication/login.html')

def logout_view(request):
    """View for user logout"""
    logout(request)
    messages.info(request, "You have successfully logged out.")
    return redirect('login')

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
    
    messages.info(request, "ADFS authentication is not yet implemented.")
    return redirect('login')
