# ADFS Authentication with Django

This project demonstrates how to implement SAML 2.0 authentication with ADFS (Active Directory Federation Services) in a Django application. The application delegates authentication to ADFS, supports SSO and MFA, and manages user sessions locally after successful authentication.

## Features

- SAML 2.0 integration with ADFS
- Single Sign-On (SSO) with ADFS portal
- MFA support (managed by ADFS)
- Automatic user provisioning from ADFS claims
- User dashboard showing authenticated user information
- Security best practices implementation

## Requirements

- Python 3.8+
- Django 5.2+
- djangosaml2 1.11+
- pysaml2 7.5+
- xmlsec binary installed on your system

## Setup Instructions

### 1. Install Requirements

```bash
pip install -r requirements.txt
```

### 2. Configure Environment Variables

Create a `.env` file in the project root with the following variables:

```
SECRET_KEY=your_django_secret_key
DEBUG=True  # Set to False in production
ALLOWED_HOSTS=localhost,127.0.0.1,your-domain.com

# SAML Configuration
SAML_ENTITY_ID=https://your-domain.com/saml2/metadata/
SAML_IDP_ENTITY_ID=https://adfs.your-company.com/adfs/services/trust
SAML_IDP_URL=https://adfs.your-company.com/adfs/ls/
SAML_IDP_METADATA_URL=https://adfs.your-company.com/federationmetadata/2007-06/federationmetadata.xml
```

### 3. Download ADFS Metadata

Run the metadata download script:

```bash
python download_metadata.py
```

### 4. Create Database

```bash
python manage.py migrate
```

### 5. Run Development Server with HTTPS

For development, you can use Django's runserver with SSL:

```bash
python manage.py runserver_plus --cert-file saml/certs/sp.crt --key-file saml/certs/sp.key
```

For production, use a proper WSGI server behind a reverse proxy with HTTPS.

### 6. Access the Application

Visit `https://localhost:8000/` in your browser to access the application.

## ADFS Configuration

1. Register your SP in ADFS:

   - Identifier (Entity ID): https://your-domain.com/saml2/metadata/
   - Reply URL (ACS URL): https://your-domain.com/saml2/acs/
   - Logout URL: https://your-domain.com/saml2/ls/

2. Configure Claim Rules:
   - Email address
   - First name
   - Last name
   - Group memberships

## Security Considerations

- Always use HTTPS in production
- Configure proper attribute mappings
- Use CSRF protection (enabled by default)
- Implement proper session handling
- Ensure secure logout functionality

## License

MIT
