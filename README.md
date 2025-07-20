# ADFS Authentication with Django

This project demonstrates how to implement SAML 2.0 authentication with ADFS (Active Directory Federation Services) in a Django application. The application delegates authentication to ADFS, supports SSO and MFA, and manages user sessions locally after successful authentication.

## Overview

The `auth_app` Django application provides a secure authentication system that delegates user authentication to an existing ADFS infrastructure. When a user attempts to access a protected resource, they are redirected to the ADFS login portal where authentication occurs. After successful authentication, ADFS sends SAML assertions back to our application, which then creates a local session for the user.

### Key Components

1. **SAML Integration**: Uses djangosaml2 to establish trust between our application and ADFS
2. **User Management**: Auto-provisions users based on ADFS claims
3. **Session Handling**: Securely manages user sessions after authentication
4. **Dashboard**: Displays authenticated user information including AD group memberships

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

You can set up the application either manually or using the automated setup script.

### Option 1: Automated Setup

For a quick start, use the provided setup script:

```bash
# Create and activate a Python virtual environment
python3 -m venv env
source env/bin/activate

# Run the setup script
./setup.py
```

The setup script will:

- Install required packages
- Generate SAML certificates if needed
- Download ADFS metadata
- Create database tables
- Create a test admin user
- Collect static files
- Test the SAML configuration

### Option 2: Manual Setup

#### 1. Install Requirements

```bash
# Create and activate a Python virtual environment
python3 -m venv env
source env/bin/activate

# Install required packages
pip install -r requirements.txt
```

#### 2. Configure Environment Variables

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

#### 3. Generate SAML Certificates

```bash
# Create the certificates directory
mkdir -p saml/certs

# Generate self-signed certificates
openssl req -new -x509 -days 3650 -nodes \
  -out saml/certs/sp.crt -keyout saml/certs/sp.key \
  -subj "/CN=auth_app.example.com"
```

#### 4. Download ADFS Metadata

Run the metadata download script:

```bash
python download_metadata.py
```

#### 5. Create Database

```bash
python manage.py migrate
```

#### 6. Create a Test User (Optional)

```bash
python manage.py create_test_admin
```

#### 7. Collect Static Files

```bash
python manage.py collectstatic
```

### Running the Application

#### Development Mode

For development, you can use Django's built-in server:

```bash
python manage.py runserver
```

#### Production Mode

For production, use Gunicorn with a proper HTTPS reverse proxy:

```bash
gunicorn auth_app.wsgi:application --bind 0.0.0.0:8000
```

#### Using Docker

To run the application with Docker:

```bash
docker-compose up -d
```

This will start both the Django application and an HTTPS proxy for secure access.

### Access the Application

Visit `http://localhost:8000/` in development mode or `https://auth_app.example.com/` when using Docker or in production.

You will see a login page where you can authenticate through ADFS.

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

## Project Structure

```
auth_app/                   # Main Django project folder
├── settings.py             # Django settings including SAML configuration
├── urls.py                 # Main URL routing
└── wsgi.py                 # WSGI application entry point

core/                       # Django app for main functionality
├── templates/
│   └── core/
│       ├── index.html      # Landing page with login button
│       └── dashboard.html  # User dashboard showing SAML attributes
├── urls.py                 # App-level URL routing
└── views.py                # View functions for dashboard and auth redirects

saml/                       # SAML configuration directory
├── attribute-maps/
│   └── adfs_map.py         # SAML attribute mapping definitions
├── certs/
│   ├── sp.crt              # Service Provider certificate
│   └── sp.key              # Service Provider private key
├── metadata/
│   └── adfs_metadata.xml   # IdP metadata from ADFS
└── saml_settings.py        # SAML configuration for djangosaml2

download_metadata.py        # Utility script to fetch ADFS metadata
.env                        # Environment variables for configuration
requirements.txt            # Project dependencies
```

## Authentication Flow

1. User navigates to the application
2. User clicks "Login with ADFS" button
3. User is redirected to ADFS portal
4. ADFS authenticates the user (with MFA if configured)
5. ADFS sends SAML assertions back to our application
6. Our application validates the SAML response
7. A Django user is created/updated based on SAML attributes
8. User is redirected to the dashboard

## License

MIT
