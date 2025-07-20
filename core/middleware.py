from django.utils.deprecation import MiddlewareMixin
from django.conf import settings
import time
import logging

logger = logging.getLogger(__name__)

class SecurityHeadersMiddleware(MiddlewareMixin):
    """
    Middleware to add security headers to all responses.
    """
    
    def process_response(self, request, response):
        # Add security headers
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-XSS-Protection'] = '1; mode=block'
        response['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
        response['Cache-Control'] = 'no-store, max-age=0'
        
        return response


class SAMLAttributeMiddleware(MiddlewareMixin):
    """
    Middleware to process and enhance SAML attributes.
    Stores additional useful information in the session.
    """
    
    def process_request(self, request):
        # Only process for authenticated users
        if not request.user.is_authenticated:
            return None
            
        # Check if we have SAML attributes in the session
        if hasattr(request, 'session') and 'saml_attributes' in request.session:
            saml_attributes = request.session['saml_attributes']
            
            # Process group memberships for easy access
            if 'groups' in saml_attributes:
                groups = saml_attributes['groups']
                
                # Extract group names from full DN if needed
                clean_groups = []
                for group in groups:
                    # Handle different group formats
                    if isinstance(group, str):
                        # Extract CN=GroupName from DN
                        if group.startswith('CN='):
                            clean_name = group.split(',')[0].replace('CN=', '')
                            clean_groups.append(clean_name)
                        else:
                            clean_groups.append(group)
                    else:
                        clean_groups.append(str(group))
                
                # Store cleaned group names for easy access
                request.session['clean_groups'] = clean_groups
                
            # Add authentication timestamp if not present
            if 'auth_timestamp' not in request.session:
                request.session['auth_timestamp'] = time.time()
                logger.info(f"User {request.user.username} authenticated via SAML")
                
        return None


class SessionExpiryMiddleware(MiddlewareMixin):
    """
    Middleware to handle custom session expiry policy.
    Enforces absolute timeout in addition to idle timeout.
    """
    
    def process_request(self, request):
        if not request.user.is_authenticated:
            return None
            
        # Get the current timestamp
        now = time.time()
        
        # Check for absolute timeout (e.g., 12 hours)
        auth_timestamp = request.session.get('auth_timestamp')
        absolute_timeout = getattr(settings, 'SAML_ABSOLUTE_SESSION_TIMEOUT', 12 * 60 * 60)
        
        if auth_timestamp and now - auth_timestamp > absolute_timeout:
            logger.info(f"User {request.user.username} session expired due to absolute timeout")
            request.session.flush()
            
        # Update last activity timestamp
        request.session['last_activity'] = now
        
        return None
