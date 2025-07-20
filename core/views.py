from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.conf import settings
from django.contrib.auth import logout
from django.urls import reverse

@login_required
def dashboard(request):
    """
    Dashboard view that requires authentication.
    Displays user information including name, email, and AD groups.
    """
    user = request.user
    
    # Get user attributes from session if they exist
    session_attrs = {}
    if hasattr(request, 'session') and 'saml_attributes' in request.session:
        session_attrs = request.session['saml_attributes']
    
    # Get AD groups if available in the SAML attributes
    groups = []
    if 'groups' in session_attrs:
        groups = session_attrs['groups']
    
    context = {
        'user': user,
        'email': user.email,
        'username': user.username,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'groups': groups,
        'attributes': session_attrs,
    }
    
    return render(request, 'core/dashboard.html', context)

def index(request):
    """
    Landing page view.
    If user is authenticated, redirect to dashboard.
    Otherwise, show login button that redirects to ADFS.
    """
    if request.user.is_authenticated:
        return redirect('dashboard')
    
    return render(request, 'core/index.html')

def logout_view(request):
    """
    Custom logout view that logs the user out
    and redirects to the SAML2 logout endpoint.
    """
    logout(request)
    return redirect('index')
