# Django Authentication System with ADFS Integration

A streamlined authentication system built with Django, focusing exclusively on ADFS (Active Directory Federation Services) Single Sign-On integration for enterprise authentication.

## Features

- **Enterprise Authentication**

  - Dedicated ADFS Single Sign-On integration
  - Logout capability
  - Protected routes requiring authentication

- **Modern UI/UX**

  - Clean, responsive design with red and white color scheme
  - CSS animations and transitions
  - Interactive elements with JavaScript
  - Auto-dismissing notifications

- **Security Features**
  - CSRF protection
  - Enterprise-grade authentication via ADFS
  - Django's built-in security features

## Project Structure

```
auth_project/               # Main Django project directory
authentication/             # Django app for authentication features
static/
  ├── css/                  # Stylesheet files
  │   ├── background-enhancements.css
  │   ├── header-enhancements.css
  │   ├── login-enhancements.css
  │   └── login.css
  └── js/                   # JavaScript files
      ├── login-enhancements.js
      └── login.js
templates/
  └── authentication/       # Authentication-specific templates
      ├── home.html         # Dashboard/home page (protected)
      └── login.html        # ADFS login page
Dockerfile                  # Docker configuration
docker-compose.yaml         # Docker Compose configuration
Makefile                    # Utility commands for Docker operations
requirements.txt            # Python dependencies
```

## Getting Started

### Prerequisites

- Docker and Docker Compose
- Make (optional, for using the provided Makefile)

### Docker Installation (Recommended)

1. Clone the repository

   ```
   git clone <repository-url>
   cd E2IP-IAM-Lab
   ```

2. Create a `.env` file with basic settings

   ```
   DEBUG=True
   SECRET_KEY=your_secret_key_here
   ```

3. Build and run with Docker

   ```
   make rebuild
   ```

   Or with Docker Compose directly:

   ```
   docker-compose up --build
   ```

4. Access the application at http://localhost:8000/

### Manual Installation (Alternative)

1. Clone the repository

   ```
   git clone <repository-url>
   cd E2IP-IAM-Lab
   ```

2. Create and activate a virtual environment

   ```
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies

   ```
   pip install -r requirements.txt
   ```

4. Run migrations

   ```
   python manage.py migrate
   ```

5. Create a superuser (for admin access)

   ```
   python manage.py createsuperuser
   ```

6. Start the development server

   ```
   python manage.py runserver
   ```

7. Access the application at http://127.0.0.1:8000/

## Usage

- **ADFS Login**: Visit http://127.0.0.1:8000/login/
- **Dashboard**: After login, access http://127.0.0.1:8000/
- **Admin Panel**: Visit http://127.0.0.1:8000/admin/

## ADFS Integration (Planned)

This project is now focused exclusively on integrating with Active Directory Federation Services (ADFS) for enterprise Single Sign-On capabilities:

### What is prepared:

- Dedicated UI for ADFS login
- Route structure for ADFS authentication flow
- Configuration file with settings to be updated
- View function placeholder for handling ADFS authentication

### Implementation steps (to be completed):

1. **ADFS Server Configuration:**

   - Register the application as a Relying Party Trust in ADFS
   - Configure claim rules for username, email, and other required user attributes
   - Set up the proper redirect URIs

2. **Application Configuration:**

   - Update `adfs_settings.py` with your ADFS server information
   - Implement token validation and user creation/authentication logic
   - Set up proper error handling and logging

3. **Testing and Security:**
   - Test the authentication flow in a development environment
   - Implement security best practices for token handling
   - Validate SSL/TLS certificates

## Extending the Project

Some ideas for extending this project:

1. Complete the ADFS integration using OAuth 2.0 or SAML protocols
2. Implement Multi-Factor Authentication (MFA)
3. Create user profiles with additional information
4. Implement audit logging for authentication events
5. Add role-based access control

## Docker Development Environment

The project is configured for Docker-based development with the following features:

### Docker Setup

- **Dockerfile**: Defines a Python 3.9 environment for running the Django application
- **docker-compose.yaml**: Configures the service with proper volume mounts for development
- **Makefile**: Provides convenient commands for Docker operations

### Makefile Commands

```
make build        # Build the Docker image
make run          # Run the container
make stop         # Stop and remove the container
make rebuild      # Stop, build, and run (clean restart)
make logs         # Show container logs
make clean        # Remove container, image, and volumes
make bash         # Get a shell in the container
```

### Static Files Configuration

Static files are configured for development mode using Django's built-in static file serving:

- Static files are stored in the `static/` directory
- The project uses `STATIC_URL = '/static/'` without `STATIC_ROOT`
- Static files are mounted directly into the Docker container with a dedicated volume
- Templates use the `{% static %}` template tag to reference static files

## Technologies Used

- **Backend**: Django 4.2.x, Python 3.9
- **Frontend**: HTML5, CSS3, JavaScript
- **Database**: SQLite (default)
- **Authentication**: Django's authentication system with ADFS integration
- **Containerization**: Docker, Docker Compose
- **Development Workflow**: Make

## License

This project is licensed under the MIT License - see the LICENSE file for details.
