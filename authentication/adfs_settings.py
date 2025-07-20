"""
ADFS Configuration settings for future integration.
This file contains placeholder settings that will need to be updated
when implementing ADFS Single Sign-On.
"""

# ADFS server settings
ADFS_SERVER = 'https://adfs.example.com'
ADFS_CLIENT_ID = 'your-client-id'  # Also known as Relying Party Identifier

# ADFS endpoints - these are standard endpoints for ADFS
ADFS_AUTHORIZE_ENDPOINT = '/adfs/oauth2/authorize'
ADFS_TOKEN_ENDPOINT = '/adfs/oauth2/token'

# ADFS claim settings
ADFS_USERNAME_CLAIM = 'upn'  # UserPrincipalName is commonly used
ADFS_EMAIL_CLAIM = 'email'
ADFS_FIRST_NAME_CLAIM = 'given_name'
ADFS_LAST_NAME_CLAIM = 'family_name'

# Application callback URL - this needs to be registered with ADFS
ADFS_REDIRECT_URI = 'https://your-app.example.com/auth/adfs/callback'

# SSL/TLS verification setting - in production this should always be True
ADFS_VERIFY_SSL = True

"""
Implementation Notes:

To implement ADFS authentication, you will need to:

1. Register your application with ADFS as a Relying Party Trust
2. Configure claims rules to send the necessary user information
3. Set up the OAuth 2.0 endpoints
4. Implement token handling and validation
5. Map ADFS claims to your user model
6. Set up appropriate error handling and logging

Required Python packages for implementation:
- requests
- python-jose (for JWT validation)
- pyOpenSSL (for certificate handling)
"""
