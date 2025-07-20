# Django Authentication System with ADFS Integration

A comprehensive authentication system built with Django, featuring login functionality and a preparation for ADFS (Active Directory Federation Services) Single Sign-On integration.

## Features

- **User Authentication**

  - Login functionality with Django's built-in authentication
  - Preparation for ADFS Single Sign-On integration
  - Logout capability
  - Protected routes requiring authentication

- **Modern UI/UX**

  - Clean, responsive design
  - CSS animations and transitions
  - Interactive elements with JavaScript
  - Form validation with visual feedback
  - Password visibility toggle
  - Auto-dismissing notifications

- **Security Features**
  - CSRF protection
  - Password hashing and validation
  - Django's built-in security features

## Project Structure

```
auth_project/               # Main Django project directory
authentication/             # Django app for authentication features
static/
  ├── css/                  # Stylesheet files
  │   └── styles.css        # Main CSS file
  └── js/                   # JavaScript files
      └── script.js         # Main JS file
templates/
  ├── base.html             # Base template with common elements
  └── authentication/       # Authentication-specific templates
      ├── home.html         # Dashboard/home page (protected)
      ├── login.html        # Login page
      └── register.html     # Registration page
```

## Getting Started

### Prerequisites

- Python 3.x
- Django 5.x

### Installation

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
   pip install django
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

- **Login**: Visit http://127.0.0.1:8000/login/
- **Dashboard**: After login, access http://127.0.0.1:8000/
- **Admin Panel**: Visit http://127.0.0.1:8000/admin/

## ADFS Integration (Planned)

This project includes preparations for integrating with Active Directory Federation Services (ADFS) for enterprise Single Sign-On capabilities:

### What is prepared:

- Placeholder UI elements for ADFS login
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
2. Implement password reset functionality
3. Add Multi-Factor Authentication (MFA)
4. Create user profiles with additional information
5. Implement audit logging for authentication events
6. Add role-based access control

## Technologies Used

- **Backend**: Django 5.x, Python 3.x
- **Frontend**: HTML5, CSS3, JavaScript
- **Database**: SQLite (default)
- **Authentication**: Django's authentication system

## License

This project is licensed under the MIT License - see the LICENSE file for details.
