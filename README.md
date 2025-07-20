# Django Authentication System

A comprehensive authentication system built with Django, featuring user registration, login, and a personalized dashboard.

## Features

- **User Authentication**

  - Login functionality with Django's built-in authentication
  - User registration with form validation
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
- **Register**: Visit http://127.0.0.1:8000/register/
- **Dashboard**: After login, access http://127.0.0.1:8000/
- **Admin Panel**: Visit http://127.0.0.1:8000/admin/

## Extending the Project

Some ideas for extending this project:

1. Add email verification for new user registrations
2. Implement password reset functionality
3. Add social authentication (Google, Facebook, etc.)
4. Create user profiles with additional information
5. Implement two-factor authentication
6. Add role-based access control

## Technologies Used

- **Backend**: Django 5.x, Python 3.x
- **Frontend**: HTML5, CSS3, JavaScript
- **Database**: SQLite (default)
- **Authentication**: Django's authentication system

## License

This project is licensed under the MIT License - see the LICENSE file for details.
