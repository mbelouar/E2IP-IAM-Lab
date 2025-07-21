from django.urls import path
from . import views

app_name = 'authentication'

urlpatterns = [
    path('', views.home, name='home'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('adfs-login/', views.adfs_login, name='adfs_login'),
]
