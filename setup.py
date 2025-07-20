#!/usr/bin/env python
"""
Setup script for the ADFS Authentication Demo.

This script performs the following tasks:
1. Checks environment and requirements
2. Downloads ADFS metadata
3. Generates SAML certificates if needed
4. Creates database tables
5. Creates a test admin user
"""

import os
import sys
import subprocess
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

def check_requirements():
    """Check if all required packages are installed."""
    print("Checking requirements...")
    try:
        # Use subprocess to run pip check
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✅ All requirements installed")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Error checking requirements: {e}")
        return False

def setup_database():
    """Set up the database."""
    print("Setting up database...")
    try:
        # Run Django migrations
        os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'auth_app.settings')
        import django
        django.setup()
        
        from django.core.management import call_command
        call_command('migrate')
        print("✅ Database migrations applied")
        
        # Create a test admin user
        call_command('create_test_admin')
        
        return True
    except Exception as e:
        print(f"❌ Error setting up database: {e}")
        return False

def download_saml_metadata():
    """Download SAML metadata from ADFS."""
    print("Downloading SAML metadata...")
    try:
        # Use our download_metadata script
        result = subprocess.run([sys.executable, "download_metadata.py"], 
                              check=True, capture_output=True, text=True)
        print(result.stdout)
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Error downloading metadata: {e}")
        print(e.stdout)
        print(e.stderr)
        return False
        
def check_saml_certificates():
    """Check if SAML certificates exist, generate if needed."""
    print("Checking SAML certificates...")
    cert_path = os.path.join(BASE_DIR, "saml", "certs", "sp.crt")
    key_path = os.path.join(BASE_DIR, "saml", "certs", "sp.key")
    
    if os.path.exists(cert_path) and os.path.exists(key_path):
        print("✅ SAML certificates already exist")
        return True
        
    print("Generating self-signed certificates...")
    try:
        # Create directory if it doesn't exist
        os.makedirs(os.path.join(BASE_DIR, "saml", "certs"), exist_ok=True)
        
        # Generate certificates
        result = subprocess.run([
            "openssl", "req", "-new", "-x509", "-days", "3650", "-nodes",
            "-out", cert_path, "-keyout", key_path,
            "-subj", "/CN=auth_app.example.com"
        ], check=True, capture_output=True, text=True)
        
        print("✅ SAML certificates generated")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Error generating certificates: {e}")
        print(e.stdout)
        print(e.stderr)
        return False
        
def collect_static_files():
    """Collect static files."""
    print("Collecting static files...")
    try:
        os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'auth_app.settings')
        import django
        django.setup()
        
        from django.core.management import call_command
        call_command('collectstatic', '--noinput')
        print("✅ Static files collected")
        return True
    except Exception as e:
        print(f"❌ Error collecting static files: {e}")
        return False
        
def test_saml_config():
    """Test SAML configuration."""
    print("Testing SAML configuration...")
    try:
        result = subprocess.run([sys.executable, "test_saml_config.py"], 
                              check=True, capture_output=True, text=True)
        print(result.stdout)
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Error testing SAML configuration: {e}")
        print(e.stdout)
        print(e.stderr)
        return False

def main():
    """Main setup function."""
    print("=" * 80)
    print("ADFS Authentication Demo - Setup Script")
    print("=" * 80)
    
    success = True
    
    # Step 1: Check requirements
    if not check_requirements():
        print("⚠️ Warning: Some requirements may be missing")
    
    # Step 2: Check SAML certificates
    if not check_saml_certificates():
        print("❌ Failed to set up SAML certificates")
        success = False
    
    # Step 3: Download SAML metadata
    if not download_saml_metadata():
        print("❌ Failed to download SAML metadata")
        success = False
    
    # Step 4: Set up database
    if not setup_database():
        print("❌ Failed to set up database")
        success = False
    
    # Step 5: Collect static files
    if not collect_static_files():
        print("⚠️ Warning: Failed to collect static files")
    
    # Step 6: Test SAML configuration
    if not test_saml_config():
        print("⚠️ Warning: SAML configuration test failed")
    
    if success:
        print("\n✅ Setup completed successfully!")
        print("\nYou can now run the development server with:")
        print("python manage.py runserver")
        print("\nOr in a production environment using gunicorn:")
        print("gunicorn auth_app.wsgi:application --bind 0.0.0.0:8000")
        print("\nLogin credentials for the test admin user:")
        print("Username: admin")
        print("Password: admin123")
        print("\nIMPORTANT: Don't use these credentials in production!")
    else:
        print("\n❌ Setup completed with errors. Please check the logs above.")
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())
