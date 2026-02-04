# CloudKlone - HTTPS Setup Guide 🔒

## 🎯 Choose Your HTTPS Option

CloudKlone supports **3 HTTPS options** depending on your needs:

| Option | Best For | Difficulty | Certificate Type | Cost |
|--------|----------|------------|------------------|------|
| **Option 1: Self-Signed** | Development, Homelab | Easy | Self-Signed | Free |
| **Option 2: Let's Encrypt + Traefik** | Production | Medium | Valid SSL | Free |
| **Option 3: Custom nginx/Caddy** | Advanced Users | Hard | Your Choice | Varies |

---

## 📦 What's Included

Your CloudKlone package includes:

```
cloudklone/
├── docker-compose.yml              # Default HTTP (port 80)
├── docker-compose.https.yml        # Traefik + Let's Encrypt
├── .env.https.example              # HTTPS configuration template
├── generate-self-signed-cert.sh    # Self-signed cert generator
└── HTTPS-SETUP-GUIDE.md           # This file
```

---

## 🟢 Option 1: Self-Signed Certificate (Quick Start)

**Best for:** Testing, homelab, internal networks, development

### ✅ Pros
- ✅ Works immediately (no domain needed)
- ✅ Free and simple
- ✅ Good for local/internal use
- ✅ No external dependencies

### ⚠️ Cons
- ❌ Browser security warnings
- ❌ "Not Secure" messages
- ❌ Manual trust required
- ❌ Not suitable for public internet

### 📝 Setup Steps

**1. Generate Certificate**
```bash
cd ~/cloudklone
./generate-self-signed-cert.sh

# When prompted, enter hostname (or press Enter for 'localhost')
# Enter hostname [localhost]: cloudklone.local
```

**2. Update nginx Configuration**

Create `nginx-https.conf`:
```nginx
server {
    listen 443 ssl http2;
    server_name localhost;

    ssl_certificate /etc/nginx/certs/fullchain.pem;
    ssl_certificate_key /etc/nginx/certs/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    location / {
        proxy_pass http://cloudklone-app:3001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name localhost;
    return 301 https://$host$request_uri;
}
```

**3. Add nginx to docker-compose.yml**
```yaml
  nginx:
    container_name: cloudklone-nginx
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx-https.conf:/etc/nginx/conf.d/default.conf:ro
      - ./certs:/etc/nginx/certs:ro
    networks:
      - cloudklone-network
    depends_on:
      - app
    restart: unless-stopped

  app:
    # Remove ports section - nginx handles this
    # ports:
    #   - "0.0.0.0:80:3001"
```

**4. Deploy**
```bash
sudo docker-compose down
sudo docker-compose up -d
```

**5. Access**
```
https://localhost
```

**Accept the security warning** (it's expected for self-signed certs).

### 🔧 Trust Self-Signed Certificate (Optional)

**Chrome/Edge (Windows):**
1. Visit `https://localhost`
2. Click "Advanced" → "Proceed to localhost"
3. Or: Import `fullchain.pem` to Trusted Root Certificates

**Chrome/Edge (Linux):**
```bash
sudo cp ./certs/fullchain.pem /usr/local/share/ca-certificates/cloudklone.crt
sudo update-ca-certificates
```

**Firefox:**
1. Visit `https://localhost`
2. Click "Advanced" → "Accept the Risk and Continue"
3. Or: Settings → Privacy & Security → Certificates → View Certificates → Import

**macOS:**
```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ./certs/fullchain.pem
```

---

## 🟦 Option 2: Let's Encrypt + Traefik (Recommended for Production)

**Best for:** Production deployments, public internet, real domain names

### ✅ Pros
- ✅ **Valid SSL certificate** (no browser warnings!)
- ✅ Automatic certificate generation
- ✅ Automatic renewal (every 90 days)
- ✅ Free from Let's Encrypt
- ✅ Production-grade security

### ⚠️ Requirements
- ✅ **Domain name** (e.g., `cloudklone.yourdomain.com`)
- ✅ **DNS pointing to your server** (A record)
- ✅ **Port 80 and 443 open** on firewall
- ✅ **Public internet access** (Let's Encrypt verification)

### 📝 Setup Steps

**1. Set Up Domain**

Point your domain to your server:
```
A Record: cloudklone.yourdomain.com → YOUR_SERVER_IP
```

Verify DNS:
```bash
dig +short cloudklone.yourdomain.com
# Should return your server's IP
```

**2. Configure Environment**
```bash
cd ~/cloudklone
cp .env.https.example .env.https
nano .env.https
```

Update with your details:
```bash
DOMAIN=cloudklone.yourdomain.com
ACME_EMAIL=admin@yourdomain.com
```

**3. Use HTTPS docker-compose**
```bash
# Backup existing setup
sudo docker-compose down

# Deploy with Traefik
sudo docker-compose -f docker-compose.https.yml --env-file .env.https up -d
```

**4. Monitor Certificate Generation**
```bash
# Watch Traefik logs
sudo docker-compose -f docker-compose.https.yml logs -f traefik

# Look for:
# "Domains obtained for cloudklone.yourdomain.com"
```

**5. Verify HTTPS**

Visit: `https://cloudklone.yourdomain.com`

✅ **Should see:**
- Green padlock in browser
- Valid certificate
- No warnings!

### 🎯 Traefik Dashboard

Traefik provides a dashboard at: `http://YOUR_IP:8080`

**View:**
- Active routers
- Certificate status
- Backend health

**⚠️ Production:** Remove port 8080 exposure by commenting it out in `docker-compose.https.yml`

### 🔄 Certificate Renewal

**Automatic!** Traefik renews certificates automatically 30 days before expiry.

**Check certificate expiry:**
```bash
echo | openssl s_client -servername cloudklone.yourdomain.com -connect cloudklone.yourdomain.com:443 2>/dev/null | openssl x509 -noout -dates
```

### 🛠️ Troubleshooting

**Certificate not generating:**

1. **Check DNS:**
   ```bash
   dig +short cloudklone.yourdomain.com
   # Must return your server IP
   ```

2. **Check port 80 accessibility:**
   ```bash
   curl -I http://cloudklone.yourdomain.com
   # Should connect (even if redirects)
   ```

3. **Check Traefik logs:**
   ```bash
   sudo docker-compose -f docker-compose.https.yml logs traefik | grep -i error
   ```

4. **Common issues:**
   - DNS not propagated yet (wait 10-60 minutes)
   - Firewall blocking port 80/443
   - Domain not pointing to server
   - Rate limited by Let's Encrypt (5 certs/week per domain)

**Let's Encrypt Staging:**

For testing, use staging server (avoids rate limits):

In `docker-compose.https.yml`, add:
```yaml
- "--certificatesresolvers.letsencrypt.acme.caserver=https://acme-staging-v02.api.letsencrypt.org/directory"
```

⚠️ Staging certs are not trusted by browsers (for testing only).

---

## 🟣 Option 3: Custom Reverse Proxy (Advanced)

**Best for:** Existing infrastructure, custom requirements, advanced users

### Bring Your Own Reverse Proxy

If you already have nginx, Apache, Caddy, or another reverse proxy:

**CloudKlone backend listens on:** `http://localhost:3001`

**Proxy configuration example (nginx):**

```nginx
server {
    listen 443 ssl http2;
    server_name cloudklone.yourdomain.com;

    ssl_certificate /path/to/your/fullchain.pem;
    ssl_certificate_key /path/to/your/privkey.pem;

    location / {
        proxy_pass http://localhost:3001;
        proxy_http_version 1.1;
        
        # WebSocket support (for live updates)
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        
        # Headers
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        proxy_cache_bypass $http_upgrade;
    }

    # WebSocket endpoint
    location /ws {
        proxy_pass http://localhost:3001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host $host;
    }
}
```

**Caddy configuration:**

```caddy
cloudklone.yourdomain.com {
    reverse_proxy localhost:3001
}
```

**Apache configuration:**

```apache
<VirtualHost *:443>
    ServerName cloudklone.yourdomain.com
    
    SSLEngine on
    SSLCertificateFile /path/to/fullchain.pem
    SSLCertificateKeyFile /path/to/privkey.pem
    
    ProxyPreserveHost On
    ProxyPass / http://localhost:3001/
    ProxyPassReverse / http://localhost:3001/
    
    # WebSocket support
    RewriteEngine On
    RewriteCond %{HTTP:Upgrade} =websocket [NC]
    RewriteRule /(.*)           ws://localhost:3001/$1 [P,L]
</VirtualHost>
```

---

## 🔒 Security Best Practices

### SSL/TLS Configuration

**Minimum TLS version:** TLSv1.2 (TLSv1.3 preferred)

**Strong cipher suites:**
```
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305
```

**Disable weak ciphers:**
- RC4
- 3DES
- MD5
- SSLv2/SSLv3

### Security Headers

Add to your reverse proxy:

```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
```

### Firewall Rules

**Allow:**
- Port 443 (HTTPS)
- Port 80 (HTTP, for Let's Encrypt validation and redirects)

**Block:**
- Direct access to port 3001 (CloudKlone backend)
- Port 8080 (Traefik dashboard in production)

```bash
# UFW example
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw deny 3001/tcp
sudo ufw enable
```

---

## 📊 Comparison Matrix

| Feature | Self-Signed | Let's Encrypt + Traefik | Custom Proxy |
|---------|-------------|-------------------------|--------------|
| **Setup Time** | 5 minutes | 15 minutes | Varies |
| **Certificate Validity** | Browser warning | ✅ Trusted | Depends |
| **Auto Renewal** | ❌ Manual | ✅ Automatic | Depends |
| **Domain Required** | ❌ No | ✅ Yes | ✅ Yes |
| **Public Internet** | ❌ No | ✅ Yes | Depends |
| **Cost** | Free | Free | Varies |
| **Production Ready** | ❌ No | ✅ Yes | ✅ Yes |

---

## 🧪 Testing HTTPS

### Test SSL Configuration

**1. SSL Labs Test:**
```
https://www.ssllabs.com/ssltest/
```
Enter your domain, should get **A or A+** rating.

**2. Command Line:**
```bash
# Test TLS versions
openssl s_client -connect cloudklone.yourdomain.com:443 -tls1_2
openssl s_client -connect cloudklone.yourdomain.com:443 -tls1_3

# Check certificate
echo | openssl s_client -servername cloudklone.yourdomain.com -connect cloudklone.yourdomain.com:443 2>/dev/null | openssl x509 -noout -text
```

**3. Browser Test:**
- Click padlock icon
- View certificate details
- Verify: Valid, correct domain, not expired

### Test WebSocket over HTTPS

WebSockets (for live transfer updates) should work over HTTPS:

```javascript
// In browser console
const ws = new WebSocket('wss://cloudklone.yourdomain.com/ws');
ws.onopen = () => console.log('✅ WebSocket connected!');
ws.onerror = (e) => console.error('❌ WebSocket error:', e);
```

---

## 🔄 Switching Between Options

### HTTP → HTTPS (Traefik)
```bash
sudo docker-compose down
sudo docker-compose -f docker-compose.https.yml --env-file .env.https up -d
```

### HTTPS (Traefik) → HTTP
```bash
sudo docker-compose -f docker-compose.https.yml down
sudo docker-compose up -d
```

### Keep Data Safe
All methods use the same volumes:
- `postgres_data` (database)
- `rclone_config` (remote configurations)

**Switching HTTPS methods does not affect your data!**

---

## 🎯 Recommended Setup by Use Case

### 🏠 Homelab / Internal Network
```
✅ Option 1: Self-Signed
- Use: https://cloudklone.local
- No domain needed
- Accept browser warning once
```

### 🌐 Production / Public Internet
```
✅ Option 2: Let's Encrypt + Traefik
- Use: https://cloudklone.yourdomain.com
- Valid certificate
- Automatic renewal
```

### 🏢 Enterprise / Existing Infrastructure
```
✅ Option 3: Custom Proxy
- Integrate with existing setup
- Use corporate certificates
- Follow company policies
```

---

## 📝 Quick Start Commands

**Self-Signed:**
```bash
cd ~/cloudklone
./generate-self-signed-cert.sh
# Add nginx to docker-compose.yml
sudo docker-compose up -d
```

**Let's Encrypt:**
```bash
cd ~/cloudklone
cp .env.https.example .env.https
nano .env.https  # Set DOMAIN and ACME_EMAIL
sudo docker-compose -f docker-compose.https.yml --env-file .env.https up -d
```

**Custom:**
```bash
# Configure your reverse proxy to point to localhost:3001
# Start CloudKlone normally
sudo docker-compose up -d
```

---

## 🎉 You're Secure!

Choose the option that fits your needs:
- 🟢 Quick homelab? → Self-signed
- 🟦 Production deployment? → Let's Encrypt + Traefik
- 🟣 Existing infrastructure? → Custom proxy

**All options provide encrypted HTTPS connections!** 🔒

---

## 📚 Additional Resources

- **Let's Encrypt:** https://letsencrypt.org/
- **Traefik Docs:** https://doc.traefik.io/traefik/
- **SSL Labs Test:** https://www.ssllabs.com/ssltest/
- **Mozilla SSL Config:** https://ssl-config.mozilla.org/

Need help? Check the troubleshooting section or your CloudKlone logs! 🚀
