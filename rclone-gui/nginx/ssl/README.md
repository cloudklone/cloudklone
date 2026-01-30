# SSL Certificate Setup

Place your SSL certificates in this directory:

- `cert.pem` - Your SSL certificate
- `key.pem` - Your private key

## Self-Signed Certificate (for testing)

To generate a self-signed certificate for testing:

```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout nginx/ssl/key.pem \
  -out nginx/ssl/cert.pem \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
```

## Let's Encrypt (for production)

For production, use Let's Encrypt with certbot:

```bash
# Install certbot
sudo apt-get update
sudo apt-get install certbot

# Generate certificate
sudo certbot certonly --standalone -d your-domain.com

# Copy certificates
sudo cp /etc/letsencrypt/live/your-domain.com/fullchain.pem nginx/ssl/cert.pem
sudo cp /etc/letsencrypt/live/your-domain.com/privkey.pem nginx/ssl/key.pem
```

## Note

- If no certificates are present, the application will run on HTTP only (port 80)
- When certificates are loaded, HTTP traffic will automatically redirect to HTTPS (port 443)
