# Enterprise Authentication Portal with Google Integrations

A comprehensive enterprise authentication and productivity portal built with Django, featuring ADFS/SAML integration, Multi-Factor Authentication (MFA), document management, and seamless Google Workspace integrations.

## 🚀 Features

### 🔐 Enterprise Authentication

- **ADFS/SAML Integration**: Complete Single Sign-On (SSO) with Active Directory Federation Services
- **Standard Authentication**: Username/password authentication with password reset
- **Multi-Factor Authentication (MFA)**:
  - WebAuthn/FIDO2 support for YubiKey and security keys
  - TOTP authenticator apps (Google Authenticator, Authy, etc.)
  - Backup codes for account recovery
- **Session Management**: Secure session handling with logout capabilities

### 🛡️ Security Features

- **CSRF Protection**: Django's built-in CSRF protection
- **Activity Logging**: Comprehensive audit trail for all user actions
- **IP Tracking**: Monitor user access patterns and locations
- **Password Security**: Secure password reset with token-based validation
- **MFA Enforcement**: Optional MFA requirements for enhanced security

### 📁 Document Management

- **Private Document Storage**: Secure file upload and storage
- **Multiple File Types**: Support for PDF, Word, Excel, PowerPoint, images, and more
- **Document Organization**: Categories, tags, and search functionality
- **File Security**: Private user-specific storage with access controls
- **Document Actions**: Upload, download, update, and delete documents

### 🌐 Google Workspace Integrations

- **Google Calendar**: Embedded calendar view with full functionality
- **Google Maps**: Interactive maps with navigation and location services
- **Google Meet**: Video conferencing with meeting management
- **Google Translate**: Multi-language translation with 100+ language support
- **Google Drive**: Document storage and collaboration

### 👤 User Management

- **Profile Management**: Edit user profiles and personal information
- **User Database**: Admin view of all registered users
- **Activity Monitoring**: Track user activities and system usage
- **Password Management**: Change passwords with security validation

### 🎨 Modern UI/UX

- **Responsive Design**: Works seamlessly on desktop, tablet, and mobile
- **Dark Mode Support**: Consistent theming across all applications
- **Interactive Elements**: Smooth animations and transitions
- **Intuitive Navigation**: Easy-to-use interface with clear app organization
- **Real-time Notifications**: Auto-dismissing alerts and status messages

## 🏗️ Project Structure

```
E2IP-IAM-Lab/
├── auth_project/               # Main Django project
│   ├── settings.py            # Django configuration
│   ├── urls.py               # Main URL routing
│   └── wsgi.py               # WSGI configuration
├── authentication/            # Core authentication app
│   ├── models.py             # Database models (MFA, Documents, Activity)
│   ├── views.py              # View functions (60+ endpoints)
│   ├── urls.py               # App URL patterns
│   └── admin.py              # Django admin configuration
├── templates/authentication/  # HTML templates
│   ├── home.html             # Main dashboard
│   ├── login.html            # ADFS login page
│   ├── standard_login.html   # Standard authentication
│   ├── mfa_*.html            # MFA setup and challenge pages
│   ├── documents_*.html      # Document management pages
│   ├── calendar.html         # Google Calendar integration
│   ├── maps.html             # Google Maps integration
│   ├── meet.html             # Google Meet integration
│   └── translate.html        # Google Translate integration
├── static/                   # Static assets
│   ├── css/                  # Stylesheets
│   └── js/                   # JavaScript files
├── documents/                # User document storage
├── saml_metadata/            # SAML configuration files
├── docker/                   # Docker configuration
└── requirements.txt          # Python dependencies
```

## 🚀 Getting Started

### Prerequisites

- Python 3.9+
- Docker and Docker Compose (recommended)
- Make (optional, for using Makefile commands)

### Docker Installation (Recommended)

1. **Clone the repository**

   ```bash
   git clone <repository-url>
   cd E2IP-IAM-Lab
   ```

2. **Create environment file**

   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. **Build and run with Docker**

   ```bash
   cd docker
   docker-compose up --build
   ```

   Or use Make from project root:

   ```bash
   make rebuild
   ```

4. **Access the application**
   - Main Portal: http://192.168.64.1:8000/
   - Admin Panel: http://192.168.64.1:8000/admin/

### Manual Installation

1. **Clone and setup virtual environment**

   ```bash
   git clone <repository-url>
   cd E2IP-IAM-Lab
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```

3. **Configure database and run migrations**

   ```bash
   python manage.py migrate
   python manage.py createsuperuser
   ```

4. **Start development server**
   ```bash
   python manage.py runserver
   ```

## 📖 Usage Guide

### Authentication Options

1. **ADFS/SAML Login**: `/login/` - Enterprise SSO integration
2. **Standard Login**: `/standard/login/` - Username/password authentication
3. **Registration**: `/standard/register/` - Create new user accounts

### Main Applications

#### 🏠 Dashboard (`/home/`)

- Overview of all available applications
- Quick access to recent activities
- User profile information
- System status and notifications

#### 📅 Calendar (`/calendar/`)

- Embedded Google Calendar view
- Direct access to Google Calendar
- Meeting scheduling and management
- Event creation and editing

#### 🗺️ Maps (`/maps/`)

- Interactive Google Maps integration
- Navigation and location services
- Search for places and businesses
- Route planning and traffic updates

#### 🎥 Meet (`/meet/`)

- Google Meet video conferencing
- Instant meeting creation
- Meeting code joining
- Screen sharing and recording

#### 🌍 Translate (`/translate/`)

- Google Translate integration
- Text, document, and website translation
- Support for 100+ languages
- Image translation with OCR

#### 📁 Documents (`/documents/`)

- Private document storage
- File upload and organization
- Document sharing and collaboration
- Search and categorization

### Multi-Factor Authentication

#### Setup MFA (`/mfa/setup/`)

1. **WebAuthn/FIDO2**: Register security keys (YubiKey, etc.)
2. **TOTP Apps**: Setup authenticator apps (Google Authenticator, Authy)
3. **Backup Codes**: Generate recovery codes for account access

#### MFA Challenge (`/mfa/challenge/`)

- Authenticate using registered devices
- TOTP code verification
- Backup code usage
- Security key authentication

## 🔧 Configuration

### ADFS/SAML Setup

1. **Configure ADFS Server**:

   - Register application as Relying Party Trust
   - Set up claim rules for user attributes
   - Configure redirect URIs

2. **Update SAML Settings**:
   - Modify `saml_metadata/adfs_metadata.xml`
   - Update `auth_project/settings.py` with ADFS configuration
   - Configure user attribute mapping

### Google Integrations

The portal integrates with Google services using embedded iframes and redirects. No additional API keys are required for basic functionality.

### Environment Variables

Create a `.env` file with:

```env
DEBUG=True
SECRET_KEY=your_secret_key_here
DATABASE_URL=sqlite:///db.sqlite3
```

## 🛠️ Development

### Available Make Commands

```bash
make build        # Build Docker image
make run          # Run container
make stop         # Stop container
make rebuild      # Clean restart
make logs         # View container logs
make clean        # Remove containers and images
make bash         # Access container shell
```

### Database Models

- **UserMFAPreference**: MFA settings and preferences
- **WebAuthnCredential**: FIDO2/WebAuthn security keys
- **TOTPDevice**: Authenticator app devices
- **MFABackupCode**: Recovery codes
- **ActivityLog**: User activity tracking
- **Document**: File storage and management

### Key Dependencies

- **Django 4.2+**: Web framework
- **djangosaml2**: SAML authentication
- **webauthn**: FIDO2/WebAuthn support
- **pyotp**: TOTP authenticator support
- **google-api-python-client**: Google integrations
- **ldap3**: Active Directory integration

## 🔒 Security Features

### Authentication Security

- CSRF protection on all forms
- Secure session management
- Password hashing with Django's built-in system
- MFA enforcement for sensitive operations

### Data Protection

- Private document storage per user
- Encrypted MFA credentials
- Secure token generation for password resets
- IP address and user agent tracking

### Audit and Monitoring

- Comprehensive activity logging
- Failed authentication attempt tracking
- MFA usage monitoring
- Document access logging

## 🚀 Deployment

### Production Considerations

1. **Database**: Use PostgreSQL or MySQL for production
2. **Static Files**: Configure proper static file serving
3. **SSL/TLS**: Enable HTTPS for all communications
4. **SAML Certificates**: Use proper SSL certificates for SAML
5. **Environment Variables**: Secure configuration management

### Docker Production

```bash
# Build production image
docker build -f docker/Dockerfile.linux -t enterprise-portal .

# Run with production settings
docker run -d -p 8000:8000 \
  -e DEBUG=False \
  -e SECRET_KEY=your_production_secret \
  enterprise-portal
```

## 📚 Documentation

- [Calendar Integration](CALENDAR_INTEGRATION.md)
- [Maps Integration](MAPS_INTEGRATION.md)
- [Meet Integration](MEET_INTEGRATION.md)
- [Translate Integration](TRANSLATE_INTEGRATION.md)
- [ADFS Setup Guide](ADFS_SETUP_GUIDE.md)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For technical support or questions:

1. Check the activity logs for error details
2. Review the integration documentation
3. Verify configuration settings
4. Contact the system administrator

## 🔮 Future Enhancements

- **Advanced Analytics**: User behavior and system usage analytics
- **Custom Integrations**: Additional third-party service integrations
- **Mobile App**: Native mobile application
- **API Development**: RESTful API for external integrations
- **Advanced MFA**: Biometric authentication support
- **Workflow Automation**: Automated business processes
- **Advanced Document Features**: Version control and collaboration
- **Real-time Notifications**: WebSocket-based notifications
