from django.urls import path
from . import views

app_name = 'authentication'

urlpatterns = [
    path('', views.home, name='home'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('adfs-login/', views.adfs_login, name='adfs_login'),
    path('saml-debug/', views.saml_debug_view, name='saml_debug'),
    path('saml-error/', views.saml_error_view, name='saml_error'),
    path('custom-saml-acs/', views.custom_saml_acs, name='custom_saml_acs'),
]
