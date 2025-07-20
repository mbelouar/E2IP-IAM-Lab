from pathlib import Path
import os
import saml2
from saml2.saml import NAMEID_FORMAT_EMAILADDRESS, NAMEID_FORMAT_UNSPECIFIED
from saml2.sigver import get_xmlsec_binary

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Metadata is stored locally
SAML_CONFIG_DIR = os.path.join(BASE_DIR, 'saml')
SAML_METADATA_DIR = os.path.join(SAML_CONFIG_DIR, 'metadata')

# Make sure the metadata directory exists
os.makedirs(SAML_METADATA_DIR, exist_ok=True)

# ADFS Configuration - these should be loaded from environment variables in production
SAML_ENTITY_ID = os.environ.get('SAML_ENTITY_ID', 'https://auth_app.example.com/saml2/metadata/')
SAML_IDP_ENTITY_ID = os.environ.get('SAML_IDP_ENTITY_ID', 'https://adfs.example.com/adfs/services/trust')
SAML_IDP_URL = os.environ.get('SAML_IDP_URL', 'https://adfs.example.com/adfs/ls/')
SAML_IDP_METADATA_URL = os.environ.get('SAML_IDP_METADATA_URL', 'https://adfs.example.com/federationmetadata/2007-06/federationmetadata.xml')

# Basic SAML configuration
SAML_CONFIG = {
    # full path to the xmlsec1 binary programm
    'xmlsec_binary': get_xmlsec_binary(),

    # your entity id, usually your subdomain plus the url to the metadata view
    'entityid': SAML_ENTITY_ID,

    # directory with attribute mapping
    'attribute_map_dir': os.path.join(SAML_CONFIG_DIR, 'attribute-maps'),

    # this block states what services we provide
    'service': {
        # we are just a lonely SP
        'sp': {
            'name': 'Django SAML2 SP',
            'name_id_format': NAMEID_FORMAT_EMAILADDRESS,
            'endpoints': {
                # url and binding to the assertion consumer service view
                'assertion_consumer_service': [
                    ('https://auth_app.example.com/saml2/acs/',
                     saml2.BINDING_HTTP_POST),
                ],
                # url and binding to the single logout service view
                'single_logout_service': [
                    ('https://auth_app.example.com/saml2/ls/',
                     saml2.BINDING_HTTP_REDIRECT),
                ],
            },
            # Auto provision users
            'auto_create_user': True,

            # Certificates for encryption/signing
            'key_file': os.path.join(SAML_CONFIG_DIR, 'certs', 'sp.key'),
            'cert_file': os.path.join(SAML_CONFIG_DIR, 'certs', 'sp.crt'),

            # ADFS requires encryption
            'encryption_keypairs': [{
                'key_file': os.path.join(SAML_CONFIG_DIR, 'certs', 'sp.key'),
                'cert_file': os.path.join(SAML_CONFIG_DIR, 'certs', 'sp.crt'),
            }],

            # Enable encryption for SAML assertions
            'want_assertions_encrypted': True,

            # Required to support ADFS
            'want_response_signed': False,
            'authn_requests_signed': True,
            'logout_requests_signed': True,
            'want_assertions_signed': True,
            'only_use_keys_in_metadata': False,

            # Mappings to extract attributes from SAML assertions
            'attribute_consuming_service': {
                'required': ['mail'],
                'name': 'Django SAML2 SP',
                'attribute': [
                    {
                        'name': 'mail',
                        'name_format': saml2.saml.NAME_FORMAT_URI,
                        'friendly_name': 'email',
                    },
                    {
                        'name': 'givenName',
                        'name_format': saml2.saml.NAME_FORMAT_URI,
                        'friendly_name': 'first_name',
                    },
                    {
                        'name': 'sn',
                        'name_format': saml2.saml.NAME_FORMAT_URI,
                        'friendly_name': 'last_name',
                    },
                ]
            }
        },
    },

    # where the remote metadata is stored
    'metadata': {
        'local': [os.path.join(SAML_METADATA_DIR, 'adfs_metadata.xml')],
    },

    # set to 1 to output debugging information
    'debug': 1,

    # certificate
    'key_file': os.path.join(SAML_CONFIG_DIR, 'certs', 'sp.key'),  # private part
    'cert_file': os.path.join(SAML_CONFIG_DIR, 'certs', 'sp.crt'),  # public part

    # own metadata settings
    'contact_person': [
        {
            'given_name': 'Technical',
            'sur_name': 'Support',
            'company': 'Your Company',
            'email_address': 'technical@example.com',
            'contact_type': 'technical'
        },
    ],

    # you can set multilanguage information here
    'organization': {
        'name': [('Your Company', 'en')],
        'display_name': [('Your Company', 'en')],
        'url': [('https://auth_app.example.com', 'en')],
    },
    'valid_for': 24,  # how long is our metadata valid
}
