from django.urls import path
from . import views

app_name = 'authentication'

urlpatterns = [
    # Authentication choice and basic authentication
    path('', views.auth_choice, name='auth_choice'),
    path('login/', views.login_view, name='login'),
    path('home/', views.home, name='home'),
    path('logout/', views.logout_view, name='logout'),
    
    # Standard Authentication
    path('standard/login/', views.standard_login, name='standard_login'),
    path('standard/register/', views.standard_register, name='standard_register'),
    path('standard/password-reset/', views.password_reset_request, name='password_reset_request'),
    path('standard/password-reset/<int:user_id>/<str:token>/', views.password_reset_confirm, name='password_reset_confirm'),
    
    # SAML authentication
    path('adfs-login/', views.adfs_login, name='adfs_login'),
    path('saml-error/', views.saml_error_view, name='saml_error'),
    path('saml-acs/', views.custom_saml_acs, name='saml_acs'),
    path('custom-saml-acs/', views.custom_saml_acs, name='custom_saml_acs'),  # Backward compatibility
    path('saml-logout/', views.saml_logout_view, name='saml_logout'),
    path('clear-saml-session/', views.clear_saml_session, name='clear_saml_session'),
    
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
    path('mfa/totp-authenticate/', views.mfa_totp_authenticate, name='mfa_totp_authenticate'),
    path('mfa/delete-credential/<int:credential_id>/', views.delete_credential, name='delete_credential'),
    
    # TOTP (Authenticator App) Management
    path('mfa/totp/setup/', views.totp_setup, name='totp_setup'),
    path('mfa/totp/verify/', views.totp_verify_setup, name='totp_verify_setup'),
    path('mfa/totp/remove/<int:device_id>/', views.totp_remove, name='totp_remove'),
    path('mfa/totp/challenge/', views.totp_challenge, name='totp_challenge'),
    path('mfa/totp/qr/<int:device_id>/', views.totp_qr_code, name='totp_qr_code'),
    
    # Profile Management
    path('profile/edit/', views.edit_profile, name='edit_profile'),
    path('profile/change-password/', views.change_password, name='change_password'),
    path('debug/csrf/', views.debug_csrf, name='debug_csrf'),
    path('activities/', views.view_all_activities, name='view_all_activities'),
    
    # Document Management
    path('documents/', views.documents_list, name='documents_list'),
    path('documents/upload/', views.document_upload, name='document_upload'),
    path('documents/<int:document_id>/', views.document_detail, name='document_detail'),
    path('documents/<int:document_id>/download/', views.document_download, name='document_download'),
    path('documents/<int:document_id>/delete/', views.document_delete, name='document_delete'),
    path('documents/<int:document_id>/update/', views.document_update, name='document_update'),
    
    # Admin/Database Views
    path('admin/users/', views.user_database_view, name='user_database'),
    
    # Calendar Integration
    path('calendar/', views.calendar_view, name='calendar'),
    path('calendar/google/', views.google_calendar_redirect, name='google_calendar_redirect'),
    
    # Maps Integration
    path('maps/', views.maps_view, name='maps'),
    path('maps/google/', views.google_maps_redirect, name='google_maps_redirect'),
    
    # Meet Integration
    path('meet/', views.meet_view, name='meet'),
    path('meet/google/', views.google_meet_redirect, name='google_meet_redirect'),
    
    # Translate Integration
    path('translate/', views.translate_view, name='translate'),
    path('translate/google/', views.google_translate_redirect, name='google_translate_redirect'),
    
    # Google Drive Integration
    path('drive/google/', views.google_drive_redirect, name='google_drive_redirect'),
]
