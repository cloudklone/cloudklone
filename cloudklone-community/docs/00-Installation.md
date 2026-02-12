# Installation Guide

This guide covers installing and configuring CloudKlone for the first time.

## Prerequisites

### System Requirements

**Minimum:**
- 2 CPU cores
- 4 GB RAM
- 20 GB disk space
- Ubuntu 20.04+ or similar Linux distribution

**Recommended:**
- 4 CPU cores
- 8 GB RAM
- 50 GB disk space
- Ubuntu 22.04 LTS or 24.04 LTS

### Required Software

**Docker and Docker Compose:**
```bash
# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Install Docker Compose
sudo apt-get update
sudo apt-get install docker-compose-plugin

# Verify installation
docker --version
docker compose version
```

**Alternative (older systems):**
```bash
# Docker Compose standalone
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

## Installation Steps

### Step 1: Download CloudKlone

Extract the CloudKlone package:

```bash
# Create installation directory
sudo mkdir -p /opt/cloudklone
cd /opt/cloudklone

# Extract package
tar -xzf cloudklone-v8.tar.gz
cd cloudklone
```

### Step 2: Review Configuration

Check the `docker-compose.yml` file:

```yaml
services:
  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: cloudklone
      POSTGRES_USER: cloudklone
      POSTGRES_PASSWORD: changeme  # Change this!
    volumes:
      - postgres_data:/var/lib/postgresql/data
    restart: unless-stopped

  app:
    build: ./backend
    ports:
      - "3001:3001"
    environment:
      - DB_HOST=postgres
      - DB_PORT=5432
      - DB_NAME=cloudklone
      - DB_USER=cloudklone
      - DB_PASSWORD=changeme  # Must match above
      - JWT_SECRET=your-secure-random-string  # Change this!
      - EDITION=community  # Options: community, professional, enterprise
    volumes:
      - rclone_config:/root/.config/rclone
    depends_on:
      - postgres
    restart: unless-stopped

volumes:
  postgres_data:
  rclone_config:
```

### Step 3: Configure Security

**Required: Change default passwords and secrets**

Edit `docker-compose.yml`:

```bash
# Generate secure random string for JWT_SECRET
openssl rand -base64 32

# Update docker-compose.yml with:
# 1. New POSTGRES_PASSWORD (both places)
# 2. New JWT_SECRET
# 3. Your preferred EDITION
```

**Example secure configuration:**
```yaml
environment:
  POSTGRES_PASSWORD: k8mP9xL2nQ7wR4sT6vY1zA3bC5dF8gH0
  DB_PASSWORD: k8mP9xL2nQ7wR4sT6vY1zA3bC5dF8gH0
  JWT_SECRET: vR2xK9mN5pL8qW3sT7yU1zA4bC6dF0gH2jM5nP8qR1sT
```

### Step 4: Start CloudKlone

```bash
# Build and start containers
sudo docker-compose up -d

# Check status
sudo docker-compose ps

# View logs
sudo docker-compose logs -f
```

**Expected output:**
```
[OK] Database initialized successfully
[OK] Edition: COMMUNITY
[OK] HTTP server listening on 0.0.0.0:3001
```

### Step 5: Verify Installation

**Check containers are running:**
```bash
sudo docker-compose ps
```

Expected output:
```
NAME                STATUS              PORTS
cloudklone-app      Up 2 minutes        0.0.0.0:3001->3001/tcp
cloudklone-postgres Up 2 minutes        5432/tcp
```

**Test web interface:**
```bash
curl http://localhost:3001
```

Should return HTML content.

**Check database:**
```bash
sudo docker-compose exec postgres psql -U cloudklone -d cloudklone -c "\dt"
```

Should list tables: users, remotes, transfers, etc.

### Step 6: Create First Admin User

**Access database:**
```bash
sudo docker-compose exec postgres psql -U cloudklone -d cloudklone
```

**Create admin user:**
```sql
INSERT INTO users (username, password, email, role) 
VALUES (
  'admin',
  '$2b$10$rKZWQVCqJU5JxGPw3Lh0ku6YVvXKZJ4YF8LXJBhKkGvO2hPJN6sGS',  -- Password: admin123
  'admin@example.com',
  'admin'
);
```

**Exit database:**
```
\q
```

**Important:** Change the default password immediately after first login.

## Initial Configuration

### Access Web Interface

Open browser to:
```
http://your-server-ip:3001
```

Or for local testing:
```
http://localhost:3001
```

### First Login

**Credentials:**
- Username: `admin`
- Password: `admin123`

**Immediate actions:**
1. Login with default credentials
2. Go to Admin tab
3. Change admin password
4. Add additional users if needed

### System Settings

Configure in Admin panel:

**Timezone:**
```
Settings tab → System Settings → Timezone
Select your timezone (e.g., America/New_York)
Save Settings
```

**SMTP (for email notifications):**
```
Settings tab → System Settings → SMTP Configuration
SMTP Host: smtp.gmail.com
SMTP Port: 587
Username: your-email@gmail.com
Password: your-app-password
From Email: noreply@yourcompany.com
Save Settings
```

**Test SMTP:**
```
Settings tab → Send Test Email
Check inbox for test message
```

## Reverse Proxy Setup (Recommended)

### Using Nginx

**Install Nginx:**
```bash
sudo apt-get update
sudo apt-get install nginx
```

**Create configuration:**
```bash
sudo nano /etc/nginx/sites-available/cloudklone
```

**Basic configuration:**
```nginx
server {
    listen 80;
    server_name cloudklone.example.com;

    location / {
        proxy_pass http://localhost:3001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

**Enable site:**
```bash
sudo ln -s /etc/nginx/sites-available/cloudklone /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### SSL/TLS with Let's Encrypt

**Install Certbot:**
```bash
sudo apt-get install certbot python3-certbot-nginx
```

**Obtain certificate:**
```bash
sudo certbot --nginx -d cloudklone.example.com
```

**Auto-renewal:**
```bash
sudo systemctl status certbot.timer
```

**Update Nginx config for HTTPS:**
```nginx
server {
    listen 443 ssl http2;
    server_name cloudklone.example.com;

    ssl_certificate /etc/letsencrypt/live/cloudklone.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/cloudklone.example.com/privkey.pem;

    location / {
        proxy_pass http://localhost:3001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

server {
    listen 80;
    server_name cloudklone.example.com;
    return 301 https://$server_name$request_uri;
}
```

## Firewall Configuration

**Allow necessary ports:**
```bash
# If using UFW
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 3001/tcp  # Only if accessing directly
sudo ufw enable

# If using firewalld
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --reload
```

## Backup Configuration

### Database Backup

**Manual backup:**
```bash
sudo docker-compose exec postgres pg_dump -U cloudklone cloudklone > backup.sql
```

**Automated daily backup:**
```bash
# Create backup script
sudo nano /opt/cloudklone/backup.sh
```

**Backup script:**
```bash
#!/bin/bash
BACKUP_DIR="/opt/cloudklone/backups"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR
docker-compose -f /opt/cloudklone/cloudklone/docker-compose.yml exec -T postgres \
  pg_dump -U cloudklone cloudklone > $BACKUP_DIR/cloudklone_$DATE.sql

# Keep only last 30 days
find $BACKUP_DIR -name "cloudklone_*.sql" -mtime +30 -delete
```

**Make executable and schedule:**
```bash
sudo chmod +x /opt/cloudklone/backup.sh
sudo crontab -e
```

**Add to crontab:**
```
0 2 * * * /opt/cloudklone/backup.sh
```

### Configuration Backup

**Backup rclone configs and docker-compose:**
```bash
sudo tar -czf cloudklone-config-backup.tar.gz \
  /opt/cloudklone/cloudklone/docker-compose.yml \
  /var/lib/docker/volumes/cloudklone_rclone_config
```

## Upgrading

### Backup Before Upgrade

```bash
# Backup database
sudo docker-compose exec postgres pg_dump -U cloudklone cloudklone > pre-upgrade-backup.sql

# Backup configuration
sudo cp docker-compose.yml docker-compose.yml.backup
```

### Upgrade Process

```bash
# Stop containers
sudo docker-compose down

# Extract new version
tar -xzf cloudklone-v9.tar.gz
cd cloudklone

# Merge any custom configuration from backup
# Review docker-compose.yml for changes

# Start new version
sudo docker-compose up -d

# Check logs
sudo docker-compose logs -f
```

## Troubleshooting Installation

### Container Won't Start

**Check logs:**
```bash
sudo docker-compose logs app
sudo docker-compose logs postgres
```

**Common issues:**

**Port already in use:**
```bash
# Check what's using port 3001
sudo netstat -tulpn | grep 3001

# Change port in docker-compose.yml
ports:
  - "3002:3001"  # Use different external port
```

**Database connection failed:**
```bash
# Verify postgres is running
sudo docker-compose ps postgres

# Check database logs
sudo docker-compose logs postgres

# Ensure DB_PASSWORD matches POSTGRES_PASSWORD
```

### Cannot Access Web Interface

**Check container is running:**
```bash
sudo docker-compose ps
```

**Test locally:**
```bash
curl http://localhost:3001
```

**Check firewall:**
```bash
sudo ufw status
```

**Verify port binding:**
```bash
sudo netstat -tulpn | grep 3001
```

### Database Migration Failed

**Check migration logs:**
```bash
sudo docker-compose logs app | grep -i migration
```

**Manual database check:**
```bash
sudo docker-compose exec postgres psql -U cloudklone -d cloudklone
\dt  # List tables
\q   # Exit
```

**Reset database (caution - loses all data):**
```bash
sudo docker-compose down -v  # Removes volumes
sudo docker-compose up -d
```

### Permission Issues

**Fix docker permissions:**
```bash
sudo usermod -aG docker $USER
newgrp docker
```

**Fix file permissions:**
```bash
sudo chown -R 1000:1000 /opt/cloudklone
```

## Monitoring

### Check Container Health

```bash
# Status
sudo docker-compose ps

# Resource usage
sudo docker stats

# Logs (live)
sudo docker-compose logs -f

# Logs (specific service)
sudo docker-compose logs -f app
```

### Check Disk Usage

```bash
# Docker volumes
sudo docker system df

# Postgres data
sudo du -sh /var/lib/docker/volumes/cloudklone_postgres_data
```

### Performance Monitoring

**Install monitoring tools:**
```bash
sudo apt-get install htop iotop
```

**Monitor resources:**
```bash
htop  # CPU and memory
iotop  # Disk I/O
```

## Security Hardening

### Change Default Credentials

**Update docker-compose.yml:**
- POSTGRES_PASSWORD
- DB_PASSWORD
- JWT_SECRET

**Restart after changes:**
```bash
sudo docker-compose down
sudo docker-compose up -d
```

### Restrict Network Access

**Bind to localhost only:**
```yaml
ports:
  - "127.0.0.1:3001:3001"  # Only accessible locally
```

**Use reverse proxy for external access.**

### Regular Updates

**Update base system:**
```bash
sudo apt-get update
sudo apt-get upgrade
```

**Update Docker images:**
```bash
sudo docker-compose pull
sudo docker-compose up -d
```

### Enable Audit Logging

Available in Professional and Enterprise editions.

## Uninstallation

### Stop and Remove Containers

```bash
cd /opt/cloudklone/cloudklone
sudo docker-compose down
```

### Remove Volumes (Optional)

**Warning: This deletes all data**

```bash
sudo docker-compose down -v
```

### Remove Files

```bash
sudo rm -rf /opt/cloudklone
```

### Remove Docker Images

```bash
sudo docker image prune -a
```

## Quick Reference

### Common Commands

**Start CloudKlone:**
```bash
sudo docker-compose up -d
```

**Stop CloudKlone:**
```bash
sudo docker-compose down
```

**Restart CloudKlone:**
```bash
sudo docker-compose restart
```

**View logs:**
```bash
sudo docker-compose logs -f
```

**Update containers:**
```bash
sudo docker-compose pull
sudo docker-compose up -d
```

**Backup database:**
```bash
sudo docker-compose exec postgres pg_dump -U cloudklone cloudklone > backup.sql
```

**Restore database:**
```bash
cat backup.sql | sudo docker-compose exec -T postgres psql -U cloudklone cloudklone
```

## Support

### Documentation

- User guides: See `docs/` directory
- API documentation: Contact support
- Configuration reference: Check `docker-compose.yml`

### Getting Help

**Before contacting support:**
1. Check logs: `sudo docker-compose logs`
2. Verify configuration
3. Review this installation guide
4. Check troubleshooting section

**Include when requesting help:**
- CloudKlone version
- Operating system and version
- Docker and Docker Compose versions
- Relevant logs
- Steps to reproduce issue

## Next Steps

After installation:

1. Review [Getting Started](01-Getting-Started.md) guide
2. Configure first remote connection
3. Test with small transfer
4. Set up email notifications
5. Create additional user accounts
6. Schedule regular backups

## Production Checklist

Before deploying to production:

- [ ] Changed all default passwords
- [ ] Configured SSL/TLS
- [ ] Set up reverse proxy
- [ ] Configured firewall
- [ ] Set up automated backups
- [ ] Configured email (SMTP)
- [ ] Created admin users
- [ ] Tested basic transfer
- [ ] Documented custom configuration
- [ ] Set up monitoring
- [ ] Planned upgrade process
- [ ] Tested backup restoration

---

CloudKlone is now installed and ready to use. Proceed to the Getting Started guide for user instructions.
