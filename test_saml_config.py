#!/usr/bin/env python
"""
Test script to verify SAML configuration is working correctly.
"""
import os
import sys
import xml.dom.minidom
from pathlib import Path

# Add the project path to the sys.path
BASE_DIR = Path(__file__).resolve().parent
sys.path.append(str(BASE_DIR))

# Initialize Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'auth_app.settings')
import django
django.setup()

# Import SAML settings after Django is initialized
from saml.saml_settings import SAML_CONFIG
from saml2.config import SPConfig
from saml2.metadata import entity_descriptor

def test_saml_config():
    """Test the SAML configuration by generating metadata."""
    print("Testing SAML configuration...")
    
    # Check if configuration can be loaded
    try:
        conf = SPConfig()
        conf.load(SAML_CONFIG)
        print("✅ SAML configuration loaded successfully")
    except Exception as e:
        print(f"❌ Error loading SAML configuration: {e}")
        return False
    
    # Check certificate paths
    cert_file = SAML_CONFIG.get('cert_file')
    key_file = SAML_CONFIG.get('key_file')
    
    if cert_file and not os.path.exists(cert_file):
        print(f"❌ Certificate file not found: {cert_file}")
    else:
        print(f"✅ Certificate file exists: {cert_file}")
    
    if key_file and not os.path.exists(key_file):
        print(f"❌ Key file not found: {key_file}")
    else:
        print(f"✅ Key file exists: {key_file}")
    
    # Check IdP metadata
    metadata_files = SAML_CONFIG.get('metadata', {}).get('local', [])
    for metadata_file in metadata_files:
        if not os.path.exists(metadata_file):
            print(f"❌ IdP metadata file not found: {metadata_file}")
        else:
            print(f"✅ IdP metadata file exists: {metadata_file}")
    
    # Generate metadata XML
    try:
        metadata = entity_descriptor(conf)
        pretty_metadata = xml.dom.minidom.parseString(str(metadata)).toprettyxml()
        print("\nGenerated SP Metadata (sample):")
        print("=" * 80)
        # Print first 20 lines
        for line in pretty_metadata.split("\n")[:20]:
            print(line)
        print("..." if len(pretty_metadata.split("\n")) > 20 else "")
        print("=" * 80)
        print(f"Total metadata length: {len(pretty_metadata.split(chr(10)))} lines")
        
        return True
    except Exception as e:
        print(f"❌ Error generating metadata: {e}")
        return False

if __name__ == "__main__":
    success = test_saml_config()
    sys.exit(0 if success else 1)
