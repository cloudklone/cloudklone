# CloudKlone - Self-Hosted Rclone GUI

Transfer files between cloud storage providers with a beautiful web interface.

## ⚡ Quick Start (Zero Configuration Required)

```bash
# 1. Extract
tar -xzf cloudklone-v4-final.tar.gz
cd cloudklone

# 2. Deploy
docker-compose up -d

# 3. Access
# Open browser to http://localhost
# Login: admin / admin
# ⚠️ IMPORTANT: Change the default password immediately after first login!
```

**⚠️ SECURITY WARNING:** The default credentials (`admin / admin`) are **INSECURE**. Change them immediately after first login:
1. Log in with `admin / admin`
2. Go to **Settings** → **Account**
3. Click **Change Password**
4. Use a strong, unique password

Never use default credentials in production!

**That's it!** No manual key generation, no .env editing, no configuration files.

---

## 🔒 HTTPS Support

CloudKlone includes **3 HTTPS options** for secure access:

### 🟢 Quick Start: Self-Signed (Development/Homelab)
```bash
./setup-https.sh
# Choose option 1
```
Works immediately, no domain needed. Browser will show security warning (expected).

### 🟦 Production: Let's Encrypt + Traefik (Recommended)
```bash
./setup-https.sh
# Choose option 2, enter your domain
```
Valid SSL certificate, automatic renewal. **Requires domain name.**

### 🟣 Advanced: Custom Reverse Proxy
Use your existing nginx/Caddy/Apache setup. CloudKlone runs on `http://localhost:3001`.

**📖 Full guide:** See `HTTPS-SETUP-GUIDE.md` for detailed instructions.

---

## 🔐 What Happens Automatically

On first run, CloudKlone automatically:
- ✅ Generates secure encryption keys (ENCRYPTION_KEY + JWT_SECRET)
- ✅ Saves them to persistent storage (`/app/.env`)
- ✅ Creates database tables
- ✅ Creates default admin user (admin/admin)
- ✅ Initializes all services

**Your keys persist forever** - stored in the `backend` volume, never regenerated.

---

## 🔄 Upgrading (Keeps All Data)

```bash
cd ~/cloudklone
docker-compose down

cd ~ && tar -xzf cloudklone-v5.tar.gz
cd cloudklone
docker-compose up -d
```

Your encryption keys, remotes, users, and transfers are preserved!

---

## 📊 Supported Providers

Amazon S3 • Backblaze B2 • Cloudflare R2 • Wasabi • Google Cloud Storage • Azure • Dropbox • Google Drive • SFTP • FTP • and 40+ more

---

## ✨ Features

- **Transfer Management**: Copy/sync, scheduling, real-time progress, history
- **User Management**: Groups, roles, password reset
- **Security**: AES-256 encryption, bcrypt passwords, JWT auth
- **Notifications**: Email alerts, daily reports
- **Smart**: Auto-obscures SFTP passwords, validates remotes, same-bucket transfers

---

## 🛠️ Optional: Custom Configuration

### Change Port
```yaml
# docker-compose.yml
ports:
  - "8080:3001"  # Change 80 to your port
```

### Secure PostgreSQL
```yaml
# docker-compose.yml
environment:
  POSTGRES_PASSWORD: your_secure_password
  DATABASE_URL: postgresql://cloudklone:your_secure_password@postgres:5432/cloudklone
```

### Manual Key Override
Only if you have existing keys to restore:
```bash
cd cloudklone/backend
cat > .env << EOF
ENCRYPTION_KEY=your-existing-key-here
JWT_SECRET=your-existing-key-here
EOF
```

---

## 📝 Useful Commands

```bash
# View logs
docker-compose logs -f

# Restart
docker-compose restart

# Stop
docker-compose down

# Backup database
docker-compose exec postgres pg_dump -U cloudklone cloudklone > backup.sql

# Backup encryption keys
docker cp $(docker-compose ps -q app):/app/.env ./keys-backup.env
```

---

## 🐛 Quick Fixes

**"Server error" creating transfer?**
```bash
docker-compose down && docker-compose up -d --build
```

**SFTP "base64 decode error"?**  
Delete the old SFTP remote and re-add it (passwords now auto-obscured)

**Transfer stuck?**  
Admin tab → Cancel All Stuck Transfers

**Can't see Admin tab?**  
Log in as `admin` (only admins see it)

---

## 📚 Full Documentation

- [SECURITY.md](SECURITY.md) - Encryption, authentication, best practices
- [ADMIN-GUIDE.md](ADMIN-GUIDE.md) - User/group management
- [B2-SETUP.md](B2-SETUP.md) - Backblaze B2 configuration
- [DEPLOY-V4.md](DEPLOY-V4.md) - Detailed deployment guide

---

## 🎯 Example Workflows

**Nightly Backup:**
```
Source: prod-db:backups
Destination: b2:archive
Schedule: Daily at 2:00 AM
```

**Cloud Migration:**
```
Source: old-s3:data
Destination: new-r2:data
Operation: Copy (test) or Sync
```

**Same-Bucket Reorganization:**
```
Source: my-bucket:old-structure
Destination: my-bucket:new-structure
(Server-side copy = instant!)
```

---

## ⚡ Zero Configuration Promise

**You will NEVER need to:**
- ❌ Generate encryption keys manually
- ❌ Edit .env files
- ❌ Run database migrations
- ❌ Configure rclone manually
- ❌ Set up JWT secrets

**Just extract and run `docker-compose up -d`**

---

**Built with Rclone, Node.js, PostgreSQL, and Docker** • MIT License • Contributions welcome!
