#!/usr/bin/env python
"""
Script to download ADFS metadata XML and save it locally.
This script would typically be run as part of deployment
or initial setup of the application.
"""

import os
import sys
import requests
from pathlib import Path

# Get the base directory of the project
BASE_DIR = Path(__file__).resolve().parent

# Check if ADFS metadata URL is provided
ADFS_METADATA_URL = os.environ.get(
    'SAML_IDP_METADATA_URL', 
    'https://adfs.example.com/federationmetadata/2007-06/federationmetadata.xml'
)

# Define where to save the metadata
METADATA_FILE = os.path.join(BASE_DIR, 'saml', 'metadata', 'adfs_metadata.xml')

def download_metadata():
    """Download the ADFS metadata and save it locally."""
    print(f"Downloading ADFS metadata from: {ADFS_METADATA_URL}")
    
    try:
        # Make sure the directory exists
        os.makedirs(os.path.dirname(METADATA_FILE), exist_ok=True)
        
        # For development, we'll simulate the content since the actual URL won't work
        if 'example.com' in ADFS_METADATA_URL:
            print("Using sample metadata for development")
            with open(METADATA_FILE, 'w') as f:
                f.write("""<?xml version="1.0" encoding="utf-8"?>
<EntityDescriptor entityID="https://adfs.example.com/adfs/services/trust" 
                  xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
  <IDPSSODescriptor WantAuthnRequestsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>MIICmTCCAYECBEjlTVkwDQYJKoZIhvcNAQEEBQAwPDELMAkGA1UEBhMCVVMxDDAKBgNVBAoT
A1NVTjEMMAoGA1UECxMDSlNXUzERMA8GA1UEAxMIVGVzdCBDQTAeFw0wNTA2MjgxMjMxMjBa
Fw0xNTA2MjYxMjMxMjBaMDwxCzAJBgNVBAYTAlVTMQwwCgYDVQQKEwNTVU4xDDAKBgNVBAsT
A0pTVzETMBEGA1UEAxMKVGVzdCBDZXJ0MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC/
EmflFBTQK8f0kQWQQSMzp4uMXcvQh8H+2Par7Qyy4HiNklq4HEVLo4c5Vuv0vaIiTUFRXGP8
+u3J0Y7/6inMDZxU4BepfJhjs4WC0YlJNkuVjZfCTUTMGc7LW+pRXEGxzXJI3igd4D7oNO+z
sIhPdmfJhx2au/VhWOqpUHNpnwIDAQABMA0GCSqGSIb3DQEBBAUAA4IBAQCJJ9rvgBaa1Uth
N4hSZ6fbPKjXYfKw/9rJPuJpJAQr3RFEoKp6QWPCZk06eFQJXx3zzgYQEQ/J1BHyus8xFCEJ
4SmZOIUnYl4IYZ2Xd6STXyBCIqhdffx+X9KjUzqUBGLlU5Ucry7+B87JKfwzLKobiRi2FkGS
A9BVoNYNlVANGXXwwGKEHmwKRBlBVCTUbx8iUCxKRQnZJFLEWUizhOJ4FnI4tJBbotmDKxrQ
kp1aG6rSQi87OzQOR4nqRnNfxQ8mbAXKLgCIZJGX3sjG7XqOLkh0NZ4I1csSRkLfYTIXKRZT
cXlpCppQT7LUYyVwLCkGK8qU42DP4S3cs2wTTQzn</X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <KeyDescriptor use="encryption">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>MIICmTCCAYECBEjlTVkwDQYJKoZIhvcNAQEEBQAwPDELMAkGA1UEBhMCVVMxDDAKBgNVBAoT
A1NVTjEMMAoGA1UECxMDSlNXUzERMA8GA1UEAxMIVGVzdCBDQTAeFw0wNTA2MjgxMjMxMjBa
Fw0xNTA2MjYxMjMxMjBaMDwxCzAJBgNVBAYTAlVTMQwwCgYDVQQKEwNTVU4xDDAKBgNVBAsT
A0pTVzETMBEGA1UEAxMKVGVzdCBDZXJ0MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC/
EmflFBTQK8f0kQWQQSMzp4uMXcvQh8H+2Par7Qyy4HiNklq4HEVLo4c5Vuv0vaIiTUFRXGP8
+u3J0Y7/6inMDZxU4BepfJhjs4WC0YlJNkuVjZfCTUTMGc7LW+pRXEGxzXJI3igd4D7oNO+z
sIhPdmfJhx2au/VhWOqpUHNpnwIDAQABMA0GCSqGSIb3DQEBBAUAA4IBAQCJJ9rvgBaa1Uth
N4hSZ6fbPKjXYfKw/9rJPuJpJAQr3RFEoKp6QWPCZk06eFQJXx3zzgYQEQ/J1BHyus8xFCEJ
4SmZOIUnYl4IYZ2Xd6STXyBCIqhdffx+X9KjUzqUBGLlU5Ucry7+B87JKfwzLKobiRi2FkGS
A9BVoNYNlVANGXXwwGKEHmwKRBlBVCTUbx8iUCxKRQnZJFLEWUizhOJ4FnI4tJBbotmDKxrQ
kp1aG6rSQi87OzQOR4nqRnNfxQ8mbAXKLgCIZJGX3sjG7XqOLkh0NZ4I1csSRkLfYTIXKRZT
cXlpCppQT7LUYyVwLCkGK8qU42DP4S3cs2wTTQzn</X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" 
                         Location="https://adfs.example.com/adfs/ls/" />
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" 
                         Location="https://adfs.example.com/adfs/ls/" />
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" 
                         Location="https://adfs.example.com/adfs/ls/" />
  </IDPSSODescriptor>
</EntityDescriptor>""")
        else:
            # Download the actual metadata
            response = requests.get(ADFS_METADATA_URL, timeout=10)
            response.raise_for_status()
            
            with open(METADATA_FILE, 'wb') as f:
                f.write(response.content)
        
        print(f"Metadata saved to: {METADATA_FILE}")
        return True
    except Exception as e:
        print(f"Error downloading metadata: {e}")
        return False

if __name__ == "__main__":
    success = download_metadata()
    sys.exit(0 if success else 1)
