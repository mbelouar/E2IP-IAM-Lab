from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth.models import User
from django.contrib.messages import get_messages


class AuthenticationViewsTest(TestCase):
    """Test cases for authentication views"""
    
    def setUp(self):
        """Set up test client and test user"""
        self.client = Client()
        self.test_user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
    
    def test_login_page_loads(self):
        """Test that login page loads correctly"""
        response = self.client.get(reverse('authentication:login'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'SecureAuth')
    
    def test_home_requires_login(self):
        """Test that home page requires authentication"""
        response = self.client.get(reverse('authentication:home'))
        # Should redirect to login
        self.assertEqual(response.status_code, 302)
    
    def test_successful_login(self):
        """Test successful login flow"""
        response = self.client.post(reverse('authentication:login'), {
            'username': 'testuser',
            'password': 'testpass123'
        })
        # Should redirect to home after successful login
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('authentication:home'))
    
    def test_invalid_login(self):
        """Test login with invalid credentials"""
        response = self.client.post(reverse('authentication:login'), {
            'username': 'testuser',
            'password': 'wrongpassword'
        })
        # Should stay on login page
        self.assertEqual(response.status_code, 200)
        # Should show error message
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('Invalid username or password' in str(message) for message in messages))
    
    def test_logout_functionality(self):
        """Test logout functionality"""
        # First login
        self.client.login(username='testuser', password='testpass123')
        
        # Then logout
        response = self.client.get(reverse('authentication:logout'))
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('authentication:login'))
    
    def test_adfs_login_redirect(self):
        """Test ADFS login redirect"""
        import os
        if os.getenv('CI'):
            self.skipTest("SAML not available in CI environment")
            
        response = self.client.get(reverse('authentication:adfs_login'))
        self.assertEqual(response.status_code, 302)
        # Should redirect to SAML login endpoint with forceAuthn parameter
        self.assertTrue('/saml2/login/' in response.url)
        self.assertTrue('forceAuthn=true' in response.url)
    
    def test_saml_session_clearing(self):
        """Test SAML session data is cleared on logout"""
        import os
        if os.getenv('CI'):
            self.skipTest("SAML not available in CI environment")
            
        # Simulate SAML login by setting session data
        session = self.client.session
        session['saml_authenticated'] = True
        session['saml_name_id'] = 'test@example.com'
        session['authentication_method'] = 'saml'
        session.save()
        
        # Login user
        self.client.login(username='testuser', password='testpass123')
        
        # Logout
        response = self.client.get(reverse('authentication:logout'))
        self.assertEqual(response.status_code, 302)
        
        # Check that session is cleared
        session = self.client.session
        self.assertNotIn('saml_authenticated', session)
        self.assertNotIn('saml_name_id', session)
        self.assertNotIn('authentication_method', session)
    
    def test_clear_saml_session_view(self):
        """Test manual SAML session clearing view"""
        import os
        if os.getenv('CI'):
            self.skipTest("SAML not available in CI environment")
            
        # Set some SAML session data
        session = self.client.session
        session['saml_authenticated'] = True
        session['saml2_session'] = 'test_session'
        session.save()
        
        # Call clear session view
        response = self.client.get(reverse('authentication:clear_saml_session'))
        self.assertEqual(response.status_code, 200)
        self.assertIn('SAML Session Cleared', response.content.decode())


class ConfigurationTest(TestCase):
    """Test Django configuration and setup"""
    
    def test_django_settings_loaded(self):
        """Test that Django settings are loaded correctly"""
        from django.conf import settings
        self.assertTrue(hasattr(settings, 'INSTALLED_APPS'))
        self.assertIn('authentication', settings.INSTALLED_APPS)
        
        # Only check for SAML if not in CI
        import os
        if not os.getenv('CI'):
            self.assertIn('djangosaml2', settings.INSTALLED_APPS)
    
    def test_saml_config_exists(self):
        """Test that SAML configuration exists"""
        import os
        if os.getenv('CI'):
            self.skipTest("SAML not available in CI environment")
            
        from django.conf import settings
        self.assertTrue(hasattr(settings, 'SAML_CONFIG'))
        self.assertIsInstance(settings.SAML_CONFIG, dict)
