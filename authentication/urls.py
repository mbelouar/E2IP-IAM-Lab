from django.urls import path
from . import views

app_name = 'authentication'

urlpatterns = [
    # Basic authentication
    path('', views.login_view, name='login'),
    path('login/', views.login_view, name='login'),
    path('home/', views.home, name='home'),
    path('logout/', views.logout_view, name='logout'),
    
    # SAML authentication
    path('adfs-login/', views.adfs_login, name='adfs_login'),
    path('saml-error/', views.saml_error_view, name='saml_error'),
    path('saml-acs/', views.custom_saml_acs, name='saml_acs'),
    path('custom-saml-acs/', views.custom_saml_acs, name='custom_saml_acs'),  # Backward compatibility
    path('saml-logout/', views.saml_logout_view, name='saml_logout'),
    
    # MFA Setup and Management
    path('mfa/setup/', views.mfa_setup, name='mfa_setup'),
    path('mfa/enable/', views.mfa_enable, name='mfa_enable'),
    path('mfa/disable/', views.mfa_disable, name='mfa_disable'),
    path('mfa/toggle/', views.mfa_toggle, name='mfa_toggle'),
    path('mfa/register/begin/', views.mfa_register_begin, name='mfa_register_begin'),
    path('mfa/register/complete/', views.mfa_register_complete, name='mfa_register_complete'),
    path('mfa/challenge/', views.mfa_challenge, name='mfa_challenge'),
    path('mfa/authenticate/begin/', views.mfa_authenticate_begin, name='mfa_authenticate_begin'),
    path('mfa/authenticate/complete/', views.mfa_authenticate_complete, name='mfa_authenticate_complete'),
    path('mfa/backup-codes/', views.generate_backup_codes, name='generate_backup_codes'),
    path('mfa/backup-authenticate/', views.mfa_backup_authenticate, name='mfa_backup_authenticate'),
    path('mfa/delete-credential/<int:credential_id>/', views.delete_credential, name='delete_credential'),
    
    # Profile Management
    path('profile/edit/', views.edit_profile, name='edit_profile'),
    path('profile/change-password/', views.change_password, name='change_password'),
    path('activities/', views.view_all_activities, name='view_all_activities'),
]
