from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('login/', views.login_view, name='login'),
    # We're keeping the register path temporarily to avoid errors, but it won't be linked in the UI
    path('register/', views.register_view, name='register'),
    path('logout/', views.logout_view, name='logout'),
    path('adfs-login/', views.adfs_login, name='adfs_login'),
]
