# CloudKlone HTTPS - Quick Reference 🔒

## 🎯 Three Options

| Option | Command | Time | Certificate |
|--------|---------|------|-------------|
| **Self-Signed** | `./setup-https.sh` → 1 | 5 min | Browser warning |
| **Let's Encrypt** | `./setup-https.sh` → 2 | 15 min | ✅ Valid SSL |
| **Custom Proxy** | Manual setup | Varies | Your choice |

---

## 🟢 Option 1: Self-Signed (Homelab)

**One command:**
```bash
./setup-https.sh
# Choose option 1
```

**What you get:**
- ✅ HTTPS enabled immediately
- ✅ No domain required
- ⚠️ Browser security warning (expected)

**Good for:** Homelab, testing, internal networks

---

## 🟦 Option 2: Let's Encrypt (Production) ⭐ RECOMMENDED

**Prerequisites:**
1. Domain name (e.g., `cloudklone.yourdomain.com`)
2. DNS A record pointing to your server
3. Ports 80 & 443 open

**One command:**
```bash
./setup-https.sh
# Choose option 2
# Enter: cloudklone.yourdomain.com
# Enter: your@email.com
# Type: y (to deploy)
```

**What you get:**
- ✅ Valid SSL certificate
- ✅ No browser warnings
- ✅ Automatic renewal
- ✅ Production-ready

**Good for:** Production, public internet, real deployments

---

## 🟣 Option 3: Custom Proxy (Advanced)

**For existing infrastructure:**

Point your nginx/Caddy/Apache to:
```
http://localhost:3001
```

**nginx example:**
```nginx
server {
    listen 443 ssl;
    server_name cloudklone.yourdomain.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location / {
        proxy_pass http://localhost:3001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

**Good for:** Enterprise, existing setups, custom requirements

---

## 📊 Which Option to Choose?

### Use Self-Signed if:
- ✅ Testing/development
- ✅ Homelab/internal network
- ✅ Don't have a domain
- ✅ Don't care about browser warnings

### Use Let's Encrypt if:
- ✅ Production deployment
- ✅ Have a domain name
- ✅ Need valid certificate
- ✅ Public internet access

### Use Custom Proxy if:
- ✅ Have existing reverse proxy
- ✅ Corporate environment
- ✅ Specific requirements
- ✅ Advanced configuration needed

---

## 🚀 Quick Deploy Commands

### Self-Signed
```bash
cd ~/cloudklone
./setup-https.sh
# Choose 1
```

### Let's Encrypt
```bash
cd ~/cloudklone
./setup-https.sh
# Choose 2
# Follow prompts
```

### Manual Let's Encrypt
```bash
cd ~/cloudklone
cp .env.https.example .env.https
nano .env.https  # Set DOMAIN and ACME_EMAIL
sudo docker-compose -f docker-compose.https.yml --env-file .env.https up -d
```

---

## 🔍 Verify HTTPS Working

### Self-Signed
```bash
# Visit https://localhost
# Accept security warning
# ✅ You're using HTTPS!
```

### Let's Encrypt
```bash
# Visit https://cloudklone.yourdomain.com
# Check for green padlock
# ✅ Valid certificate!
```

### Test from command line
```bash
curl -I https://cloudklone.yourdomain.com
# Should return: HTTP/2 200
```

---

## 🛠️ Troubleshooting

### Self-Signed: Browser won't accept certificate
**Solution:** This is expected. Click "Advanced" → "Proceed anyway"

### Let's Encrypt: Certificate not generating
**Check:**
```bash
# 1. DNS resolves
dig +short cloudklone.yourdomain.com

# 2. Port 80 reachable
curl -I http://cloudklone.yourdomain.com

# 3. Traefik logs
sudo docker-compose -f docker-compose.https.yml logs traefik
```

### Can't access on port 443
**Check:**
```bash
# Firewall
sudo ufw status
sudo ufw allow 443/tcp

# Container running
sudo docker-compose ps
```

---

## 📁 Files Included

```
cloudklone/
├── setup-https.sh                 # Interactive setup
├── generate-self-signed-cert.sh   # Self-signed cert generator
├── docker-compose.https.yml       # Traefik configuration
├── .env.https.example            # HTTPS config template
└── HTTPS-SETUP-GUIDE.md          # Full documentation
```

---

## 🔄 Switching Methods

### Currently on HTTP, want HTTPS?
```bash
sudo docker-compose down
sudo docker-compose -f docker-compose.https.yml --env-file .env.https up -d
```

### Currently on HTTPS, want HTTP?
```bash
sudo docker-compose -f docker-compose.https.yml down
sudo docker-compose up -d
```

**Your data is safe!** Volumes are preserved when switching.

---

## ⚡ One-Line Quick Start

**Homelab (Self-Signed):**
```bash
cd ~/cloudklone && ./setup-https.sh
```

**Production (Let's Encrypt):**
```bash
cd ~/cloudklone && ./setup-https.sh
# Enter your domain when prompted
```

---

## 📖 Need More Help?

See full guide: `HTTPS-SETUP-GUIDE.md`

Covers:
- Detailed setup instructions
- Security best practices
- Advanced configurations
- Troubleshooting guide
- Custom reverse proxy examples

---

## 🎉 That's It!

Three options, choose what fits your needs:
- 🟢 Quick & easy? → Self-signed
- 🟦 Production? → Let's Encrypt
- 🟣 Custom setup? → Your proxy

**All provide encrypted HTTPS!** 🔒
