#!/bin/bash

echo "=========================================="
echo "SecureAuth Portal - HTTPS Setup Script"
echo "=========================================="
echo ""

# Check if running as sudo
if [ "$EUID" -ne 0 ]; then 
    echo "Please run with sudo:"
    echo "sudo bash setup_secureauth.sh"
    exit 1
fi

echo "1. Adding secureauth.local to /etc/hosts..."
if grep -q "secureauth.local" /etc/hosts; then
    echo "   ✓ secureauth.local already in hosts file"
else
    echo "192.168.64.1    secureauth.local" >> /etc/hosts
    echo "   ✓ Added secureauth.local to hosts file"
fi

echo ""
echo "2. Adding adfs.my-lab.local to /etc/hosts..."
if grep -q "adfs.my-lab.local" /etc/hosts; then
    echo "   ✓ adfs.my-lab.local already in hosts file"
else
    echo "192.168.64.3    adfs.my-lab.local" >> /etc/hosts
    echo "   ✓ Added adfs.my-lab.local to hosts file"
fi

echo ""
echo "3. Testing DNS resolution..."
if ping -c 1 secureauth.local > /dev/null 2>&1; then
    echo "   ✓ secureauth.local resolves correctly"
else
    echo "   ✗ Warning: secureauth.local not resolving"
fi

if ping -c 1 adfs.my-lab.local > /dev/null 2>&1; then
    echo "   ✓ adfs.my-lab.local resolves correctly"
else
    echo "   ✗ Warning: adfs.my-lab.local not resolving"
fi

echo ""
echo "=========================================="
echo "Setup Complete!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "1. Generate SSL certificates: bash generate_ssl_cert.sh"
echo "2. Run server with SSL: make runserver-ssl"
echo "3. Access portal at: https://secureauth.local:8000/"
echo ""

