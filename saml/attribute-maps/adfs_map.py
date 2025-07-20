MAP = {
    "identifier": "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
    "fro": {
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": "mail",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname": "givenName",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname": "sn",
        "http://schemas.microsoft.com/ws/2008/06/identity/claims/role": "role",
        "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups": "groups",
    },
    "to": {
        "mail": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
        "givenName": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
        "sn": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
        "role": "http://schemas.microsoft.com/ws/2008/06/identity/claims/role",
        "groups": "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups",
    }
}
