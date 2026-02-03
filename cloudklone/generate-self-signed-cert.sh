#!/bin/bash

# CloudKlone - Self-Signed Certificate Generator
# For development/homelab use only

set -e

echo "🔐 Generating Self-Signed SSL Certificate for CloudKlone"
echo ""

# Create certs directory
mkdir -p ./certs

# Get hostname or use default
read -p "Enter hostname [localhost]: " HOSTNAME
HOSTNAME=${HOSTNAME:-localhost}

echo ""
echo "Generating certificate for: $HOSTNAME"
echo ""

# Generate private key
openssl genrsa -out ./certs/privkey.pem 2048

# Generate certificate signing request
openssl req -new -key ./certs/privkey.pem -out ./certs/cert.csr \
  -subj "/C=US/ST=State/L=City/O=CloudKlone/CN=$HOSTNAME"

# Generate self-signed certificate (valid for 365 days)
openssl x509 -req -days 365 -in ./certs/cert.csr \
  -signkey ./certs/privkey.pem -out ./certs/fullchain.pem

# Create combined cert for some applications
cat ./certs/fullchain.pem ./certs/privkey.pem > ./certs/combined.pem

# Set permissions
chmod 600 ./certs/privkey.pem
chmod 644 ./certs/fullchain.pem

echo ""
echo "✅ Certificate generated successfully!"
echo ""
echo "Files created:"
echo "  - ./certs/privkey.pem (private key)"
echo "  - ./certs/fullchain.pem (certificate)"
echo "  - ./certs/combined.pem (combined for nginx)"
echo ""
echo "⚠️  WARNING: This is a self-signed certificate!"
echo "Browsers will show security warnings."
echo "For production use, use Let's Encrypt with Traefik."
echo ""
