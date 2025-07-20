from django.shortcuts import render, redirect
from django.contrib.auth.forms import AuthenticationForm
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
    """View for user login"""
    if request.user.is_authenticated:
        return redirect('home')
    
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                messages.info(request, f"You are now logged in as {username}.")
                return redirect('home')
            else:
                messages.error(request, "Invalid username or password.")
        else:
            messages.error(request, "Invalid username or password.")
    else:
        form = AuthenticationForm()
    
    return render(request, 'authentication/login.html', {'form': form})

def register_view(request):
    """View for user registration"""
    if request.user.is_authenticated:
        return redirect('home')
        
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            messages.success(request, "Registration successful.")
            return redirect('home')
        messages.error(request, "Unsuccessful registration. Invalid information.")
    else:
        form = UserCreationForm()
    
    return render(request, 'authentication/register.html', {'form': form})

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
