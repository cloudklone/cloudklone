# CloudKlone v7 - Deployment Guide

## Overview

CloudKlone v7 is an enterprise-grade data transfer orchestration platform for managing cloud-to-cloud, cloud-to-endpoint, and cross-cloud data operations at scale. The platform provides centralized control, comprehensive audit trails, role-based access control, and automated scheduling for multi-cloud data transfer workflows.

**Key Capabilities:**
- Centralized multi-cloud transfer orchestration
- Enterprise security (HTTPS, SSH host key verification, encrypted credentials)
- Role-based access control with four permission tiers
- Comprehensive audit logging for compliance
- Automated scheduling and retry logic
- Real-time monitoring and alerting
- Webhook integrations for operational workflows

## Prerequisites

- Docker and Docker Compose installed
- Port 80 and 443 available
- Linux-based host system (Ubuntu 20.04+ recommended)

## Quick Start

### 1. Extract and Deploy

```bash
tar -xzf cloudklone-v7-security-https.tar.gz
cd cloudklone
sudo docker-compose up -d
```

### 2. Monitor Startup

```bash
sudo docker-compose logs -f app
```

Wait for these messages:
- `[OK] Self-signed SSL certificate generated successfully`
- `[OK] HTTPS server listening on 0.0.0.0:443`
- `[OK] Default admin user created (admin / admin)`

### 3. First Access

Navigate to: `https://localhost` or `https://your-server-ip`

**Browser Security Warning:** You will see a security warning because CloudKlone uses a self-signed certificate. This is expected behavior.

- **Chrome:** Click "Advanced" then "Proceed to localhost (unsafe)"
- **Firefox:** Click "Advanced" then "Accept the Risk and Continue"
- **Safari:** Click "Show Details" then "visit this website"

### 4. Initial Login

**Default Credentials:**
- Username: `admin`
- Password: `admin`

**Important:** You will be immediately prompted to change this password. You cannot access the application until you set a new password (minimum 6 characters).

## Architecture

### Control Plane Design

CloudKlone implements a three-tier architecture separating control plane operations from data plane execution:

**Control Plane:**
- **Management Console:** Web-based administrative interface for operations
- **API Layer:** RESTful API with JWT authentication and WebSocket for real-time updates
- **Orchestration Engine:** Transfer scheduling, queuing, and execution management
- **Metadata Store:** PostgreSQL database for configuration, audit logs, and state management

**Data Plane:**
- **Transfer Execution Engine:** Rclone runtime for actual data movement
- **Credential Vault:** Encrypted storage for cloud provider credentials
- **Transfer Monitoring:** Real-time progress tracking and statistics collection

This separation ensures the control plane remains responsive even during large data transfers, and allows horizontal scaling of data plane workers in future versions.

### Ports

- **80:** HTTP (automatically redirects to HTTPS)
- **443:** HTTPS (primary access point)

### Volumes

- `postgres_data` - Database persistence
- `rclone_config` - Rclone configuration files
- `ssl_certs` - SSL certificates (auto-generated)
- `ssh_keys` - SSH known_hosts files for SFTP

## Configuration

### Environment Variables

Edit `docker-compose.yml` to configure:

```yaml
environment:
  DATABASE_URL: postgresql://cloudklone_user:changeme123@postgres:5432/cloudklone
  HTTP_PORT: 3001
  HTTPS_PORT: 3443
```

### Database Password

Default PostgreSQL password is `changeme123`. To change:

```yaml
services:
  postgres:
    environment:
      POSTGRES_PASSWORD: your-secure-password
  app:
    environment:
      DATABASE_URL: postgresql://cloudklone_user:your-secure-password@postgres:5432/cloudklone
```

After changing, recreate containers:
```bash
sudo docker-compose down
sudo docker-compose up -d
```

## Features

### Supported Cloud Providers

- Amazon S3
- Cloudflare R2
- Backblaze B2
- Google Cloud Storage
- Azure Blob Storage
- Wasabi
- Dropbox
- SFTP

### Transfer Operations

- **Copy:** Copy files from source to destination (keeps source)
- **Sync:** Make destination identical to source (deletes extra files)

### Scheduling

- **One-time:** Schedule transfer for specific date/time
- **Recurring:** Daily, weekly, monthly automatic transfers

### Notifications

- **Email:** SMTP notifications for success/failure
- **Webhooks:** Slack, Microsoft Teams, Discord integrations

### Security Features

- **HTTPS by default** with auto-generated certificate
- **SSH host key verification** for SFTP connections
- **Forced password change** on first admin login
- **Role-based access control** (Admin, Power User, Operator, Viewer)
- **Audit logging** for all user actions
- **Encrypted credentials** in database

## Common Tasks

### Adding Cloud Remotes

1. Navigate to **Remotes** tab
2. Click **Add Remote**
3. Select provider type
4. Enter credentials
5. Click **Test Connection**
6. Click **Save**

For SFTP remotes, host keys are automatically scanned and verified.

### Creating Transfers

1. Navigate to **Transfers** tab
2. Click **New Transfer**
3. Select source remote and path
4. Select destination remote and path
5. Choose operation (Copy or Sync)
6. Optionally configure schedule
7. Click **Start Transfer**

### Managing Users

1. Navigate to **Admin** tab (admin users only)
2. Click **Create User**
3. Enter username, email, password
4. Assign to group (optional)
5. Set admin privileges (if needed)
6. Click **Create**

### Viewing SSH Host Keys

1. Navigate to **Admin** tab
2. Scroll to **SSH Host Keys** section
3. View all SFTP remotes with their host keys
4. Click **Rescan** to update a host key
5. Click **Clear** to remove a host key

## Troubleshooting

### Cannot Access Management Console

**Symptoms:** Browser cannot connect, timeout errors

**Solutions:**
1. Check containers are running: `sudo docker-compose ps`
2. Check logs: `sudo docker-compose logs app`
3. Verify ports not in use: `sudo netstat -tlnp | grep -E ':(80|443)'`
4. Check firewall: `sudo ufw status`

### Database Connection Failed

**Symptoms:** "Failed to initialize database" in logs

**Solutions:**
1. Check database is healthy: `sudo docker-compose ps postgres`
2. Wait for database startup (can take 30-60 seconds)
3. Check database logs: `sudo docker-compose logs postgres`
4. Verify credentials match in docker-compose.yml

### SSL Certificate Errors

**Symptoms:** "Failed to generate SSL certificate" in logs

**Solutions:**
1. Verify OpenSSL installed: `sudo docker exec cloudklone-app openssl version`
2. Check /app/certs permissions: `sudo docker exec cloudklone-app ls -la /app/certs`
3. Remove and recreate cert volume:
   ```bash
   sudo docker-compose down
   sudo docker volume rm cloudklone_ssl_certs
   sudo docker-compose up -d
   ```

### SFTP Host Key Scan Fails

**Symptoms:** "Failed to scan SSH host key" when creating SFTP remote

**Causes:**
- Host not reachable
- SSH server not running
- Firewall blocking port 22
- Incorrect hostname or port

**Solutions:**
1. Test connectivity: `ping hostname`
2. Test SSH port: `telnet hostname 22`
3. Verify SSH server running on remote host
4. Check firewall rules on both sides
5. Verify hostname is correct (not IP that changed)

### Transfer Stuck in "Running" State

**Symptoms:** Transfer shows "running" but no progress for 10+ minutes

**Solutions:**
1. Navigate to **Admin** tab
2. Scroll to **System Tools**
3. Click **Cancel All Stuck Transfers**
4. Alternatively, restart app: `sudo docker-compose restart app`

### Password Change Not Working

**Symptoms:** Cannot change password, modal won't close

**Solutions:**
1. Ensure all fields filled
2. New password must be minimum 6 characters
3. Passwords must match
4. New password must differ from current
5. Check browser console (F12) for errors
6. Hard refresh: Ctrl+F5 (Windows/Linux) or Cmd+Shift+R (Mac)

### Webhook Notifications Not Sending

**Symptoms:** No messages in Slack/Teams/Discord

**Solutions:**
1. Navigate to **Settings** tab
2. Verify webhook URL is correct
3. Verify webhook type matches platform (Slack/Teams/Discord)
4. Click **Test Webhook** to verify
5. Check platform webhook settings (not disabled/deleted)
6. Check CloudKlone logs: `sudo docker-compose logs app | grep webhook`

## Maintenance

### Viewing Logs

```bash
# All logs
sudo docker-compose logs -f

# App only
sudo docker-compose logs -f app

# Database only
sudo docker-compose logs -f postgres

# Last 100 lines
sudo docker-compose logs --tail=100 app
```

### Backing Up Database

```bash
# Create backup
sudo docker exec cloudklone-database pg_dump -U cloudklone_user cloudklone > backup.sql

# Restore backup
sudo docker exec -i cloudklone-database psql -U cloudklone_user cloudklone < backup.sql
```

### Updating CloudKlone

```bash
# Stop services
sudo docker-compose down

# Backup database (recommended)
sudo docker exec cloudklone-database pg_dump -U cloudklone_user cloudklone > backup-$(date +%Y%m%d).sql

# Extract new version
tar -xzf cloudklone-v8-new.tar.gz
cd cloudklone

# Start new version
sudo docker-compose up -d

# Check logs
sudo docker-compose logs -f app
```

### Cleaning Up

```bash
# Stop and remove containers (keeps volumes/data)
sudo docker-compose down

# Remove containers and volumes (deletes all data)
sudo docker-compose down -v

# Remove old images
sudo docker image prune -a
```

## Production Recommendations

### Use Real SSL Certificate

**Option 1: Let's Encrypt with Reverse Proxy**

Deploy Caddy or Traefik in front of CloudKlone to handle automatic SSL certificates.

**Option 2: Provide Your Own Certificate**

```bash
# Copy certificate files
sudo docker cp your-cert.pem cloudklone-app:/app/certs/cert.pem
sudo docker cp your-key.pem cloudklone-app:/app/certs/key.pem

# Restart app
sudo docker-compose restart app
```

### Enable Firewall

```bash
# Allow only necessary ports
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

### Regular Backups

Set up automated daily backups:

```bash
# Create backup script
cat > /usr/local/bin/cloudklone-backup.sh << 'EOF'
#!/bin/bash
BACKUP_DIR=/var/backups/cloudklone
mkdir -p $BACKUP_DIR
DATE=$(date +%Y%m%d)
docker exec cloudklone-database pg_dump -U cloudklone_user cloudklone | gzip > $BACKUP_DIR/backup-$DATE.sql.gz
find $BACKUP_DIR -name "backup-*.sql.gz" -mtime +30 -delete
EOF

chmod +x /usr/local/bin/cloudklone-backup.sh

# Add to crontab (daily at 2 AM)
echo "0 2 * * * /usr/local/bin/cloudklone-backup.sh" | sudo crontab -
```

### Monitor Disk Space

CloudKlone itself uses minimal disk space, but transfer logs can accumulate:

```bash
# Check disk usage
sudo docker exec cloudklone-database du -sh /var/lib/postgresql/data

# Clean old audit logs (older than 90 days)
sudo docker exec -i cloudklone-database psql -U cloudklone_user cloudklone << EOF
DELETE FROM audit_logs WHERE timestamp < NOW() - INTERVAL '90 days';
EOF
```

### Set Strong Database Password

Never use default password in production. Generate secure password:

```bash
openssl rand -base64 32
```

Update in docker-compose.yml and restart services.

## Security Considerations

### Network Security

- Deploy behind firewall
- Use VPN for remote access if not public-facing
- Enable fail2ban to prevent brute force attacks
- Keep host system updated

### Application Security

- Change default admin password immediately
- Create separate user accounts (don't share admin)
- Use role-based access control
- Review audit logs regularly
- Enable webhook/email notifications for monitoring

### Data Security

- Database credentials stored encrypted
- SFTP passwords obscured with rclone
- SSL/TLS for all connections
- SSH host key verification for SFTP

## Support

### Log Collection

When reporting issues, include:

```bash
# System info
uname -a
docker --version
docker-compose --version

# Container status
sudo docker-compose ps

# Recent logs
sudo docker-compose logs --tail=200 app > cloudklone-logs.txt
```

### Common Issues Database

| Issue | Solution |
|-------|----------|
| Containers won't start | Check logs, verify ports available |
| Database connection timeout | Wait 60s, database startup can be slow |
| Browser security warning | Expected with self-signed cert, click "Proceed" |
| Can't change admin password | Hard refresh browser (Ctrl+F5) |
| Transfer fails immediately | Check remote credentials, test connection |
| SFTP host key error | Rescan host key from Admin panel |
| Out of disk space | Clean old audit logs, check Docker volumes |

## Architecture Details

### Database Schema

**Main Tables:**
- `users` - User accounts and authentication
- `groups` - User groups for RBAC
- `remotes` - Cloud storage configurations
- `transfers` - Transfer history and active jobs
- `audit_logs` - All user actions logged
- `notification_settings` - Email/webhook configuration

**Security:**
- All passwords stored as bcrypt hashes
- Cloud credentials encrypted with AES-256
- JWT tokens for API authentication (24h expiry)

### File Locations

**Inside Containers:**
- App code: `/app`
- SSL certs: `/app/certs`
- Rclone configs: `/root/.config/rclone`
- SSH known_hosts: `/root/.ssh`

**Docker Volumes:**
- `postgres_data` - PostgreSQL data directory
- `rclone_config` - User rclone configurations
- `ssl_certs` - SSL certificate files
- `ssh_keys` - SSH host keys

### API Endpoints

All endpoints require JWT authentication except `/api/auth/login`.

**Authentication:**
- POST `/api/auth/login` - User login
- POST `/api/auth/change-password` - Change password
- GET `/api/auth/permissions` - Get user permissions

**Remotes:**
- GET `/api/remotes` - List remotes
- POST `/api/remotes` - Create remote
- POST `/api/remotes/:id/test` - Test connection

**Transfers:**
- GET `/api/transfers` - List active transfers
- POST `/api/transfers` - Create transfer
- GET `/api/transfers/history` - Transfer history
- GET `/api/transfers/scheduled` - Scheduled jobs

**Admin:**
- GET `/api/users` - List users (admin only)
- POST `/api/users` - Create user (admin only)
- GET `/api/admin/ssh-host-keys` - List SSH keys (admin only)
- POST `/api/admin/ssh-host-keys/:id/rescan` - Rescan key (admin only)

## Version History

**v7 (Current):**
- HTTPS by default with auto-generated certificate
- SSH host key management for SFTP
- Forced password change on first login
- Auto-retry logic with credential error detection
- Webhook notifications (Slack, Teams, Discord)
- Universal scheduled job visibility
- Complete audit logging

## License

CloudKlone is provided as-is for self-hosting purposes. Use responsibly.
