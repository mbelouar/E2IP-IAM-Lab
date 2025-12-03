#!/bin/bash

echo "=========================================="
echo "Generating SSL Certificate for SecureAuth"
echo "=========================================="
echo ""

# Create ssl directory if it doesn't exist
mkdir -p ssl

# Check if certificates already exist
if [ -f "ssl/cert.pem" ] && [ -f "ssl/key.pem" ]; then
    echo "SSL certificates already exist in ssl/ directory"
    echo ""
    read -p "Do you want to regenerate them? (y/n): " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Using existing certificates."
        exit 0
    fi
fi

echo "Generating new SSL certificate..."
echo ""

# Generate SSL certificate
openssl req -x509 -newkey rsa:4096 \
    -keyout ssl/key.pem \
    -out ssl/cert.pem \
    -days 365 \
    -nodes \
    -subj "/C=US/ST=State/L=City/O=SecureAuth/OU=IT/CN=secureauth.local" \
    -addext "subjectAltName=DNS:secureauth.local,DNS:*.secureauth.local,IP:192.168.64.1"

if [ $? -eq 0 ]; then
    echo ""
    echo "✓ SSL certificates generated successfully!"
    echo ""
    echo "Certificate files created:"
    echo "  - ssl/cert.pem (Certificate)"
    echo "  - ssl/key.pem (Private Key)"
    echo ""
    echo "Certificate details:"
    openssl x509 -in ssl/cert.pem -noout -subject -dates
    echo ""
    echo "You can now run the server with SSL:"
    echo "  make runserver-ssl"
    echo ""
    echo "Access the portal at:"
    echo "  https://secureauth.local:8000/"
    echo ""
else
    echo ""
    echo "✗ Error generating SSL certificates"
    exit 1
fi

