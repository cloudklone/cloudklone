# CloudKlone - Enterprise Data Transfer Orchestration Platform

CloudKlone is a self-hosted data transfer control plane that orchestrates secure, scalable file transfers between cloud storage providers and endpoints. Built for enterprise operations, CloudKlone provides centralized management, role-based access control, comprehensive audit logging, and automated scheduling capabilities.

## Quick Start

```bash
# Extract
tar -xzf cloudklone-v7-security-https.tar.gz
cd cloudklone

# Deploy
sudo docker-compose up -d

# Access
# Open browser to https://localhost
# Login: admin / admin
```

**IMPORTANT:** On first login, you will be required to change the default password before accessing the application.

---

## Enterprise-Grade Capabilities

CloudKlone is not simply an rclone wrapper - it is a complete data transfer control plane designed for enterprise operations:

**What Rclone Provides:**
- Command-line data transfer execution
- Support for 40+ storage providers
- Efficient file synchronization algorithms

**What CloudKlone Adds:**
- **Centralized Orchestration:** Manage all transfers from a single control plane
- **Multi-User Architecture:** Role-based access control with four permission tiers
- **Audit Compliance:** Comprehensive logging of all user actions and transfer operations
- **Enterprise Security:** HTTPS by default, SSH host key verification, credential encryption
- **Operational Intelligence:** Real-time monitoring, automated alerting, transfer history
- **Workflow Automation:** Scheduled transfers with automatic retry and failure handling
- **Team Collaboration:** Shared remotes, group-based permissions, transfer ownership
- **Integration Ready:** Webhook notifications for Slack, Teams, Discord
- **Zero Downtime:** Persistent configuration, automatic key management, health monitoring

CloudKlone transforms rclone from a CLI tool into an enterprise data transfer platform with centralized control, security, and operational visibility.

---

## HTTPS Access

CloudKlone v7 enables HTTPS by default with an auto-generated self-signed certificate.

**First Access:**
1. Navigate to `https://localhost` or `https://your-server-ip`
2. Browser will show security warning (expected with self-signed certificates)
3. Click "Advanced" then "Proceed" to continue
4. Login with default credentials and set new password

**For Production:** Replace self-signed certificate with valid SSL certificate from Let's Encrypt or your certificate authority. See DEPLOYMENT-GUIDE.md for instructions.

---

## Security Features

**Authentication:**
- Forced password change on first admin login
- Bcrypt password hashing (10 rounds)
- JWT token-based authentication (24h expiry)
- Session management

**Data Protection:**
- AES-256 encryption for stored credentials
- HTTPS by default (port 443)
- SSH host key verification for SFTP
- Audit logging for all user actions

**Access Control:**
- Role-based permissions (Admin, Power User, Operator, Viewer)
- Group-based access management
- Per-remote ownership and sharing

---

## Supported Providers

**S3-Compatible:**
- Amazon S3
- Cloudflare R2
- Backblaze B2
- Wasabi
- MinIO
- DigitalOcean Spaces

**Cloud Storage:**
- Google Cloud Storage
- Azure Blob Storage
- Dropbox
- Google Drive

**File Transfer:**
- SFTP (with host key verification)
- FTP/FTPS
- Local filesystem

---

## Core Features

**Transfer Management:**
- Copy and Sync operations
- Real-time progress monitoring
- Transfer history and audit logs
- Automatic retry on failure (3 attempts)
- Scheduled transfers (one-time and recurring)

**User Management:**
- Multi-user support
- Group-based permissions
- Admin panel for user creation/editing
- Role assignment and access control

**Notifications:**
- Email alerts (SMTP)
- Webhook integrations (Slack, Microsoft Teams, Discord)
- Success/failure notifications
- Daily summary reports

**Security:**
- SSH host key management for SFTP
- Credential encryption in database
- Auto-obscured SFTP passwords
- Comprehensive audit logging

---

## System Requirements

- Docker and Docker Compose
- 2GB RAM minimum (4GB recommended)
- Port 80 and 443 available
- Linux host (Ubuntu 20.04+ recommended)
- 20GB+ disk space for database and logs

---

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

Change default PostgreSQL password in production:

```yaml
services:
  postgres:
    environment:
      POSTGRES_PASSWORD: your-secure-password
  app:
    environment:
      DATABASE_URL: postgresql://cloudklone_user:your-secure-password@postgres:5432/cloudklone
```

After changing, restart containers:
```bash
sudo docker-compose down
sudo docker-compose up -d
```

---

## Common Tasks

### View Logs
```bash
sudo docker-compose logs -f app
```

### Restart Service
```bash
sudo docker-compose restart app
```

### Backup Database
```bash
sudo docker exec cloudklone-database pg_dump -U cloudklone_user cloudklone > backup.sql
```

### Restore Database
```bash
sudo docker exec -i cloudklone-database psql -U cloudklone_user cloudklone < backup.sql
```

### Update CloudKlone
```bash
sudo docker-compose down
tar -xzf cloudklone-v8-new.tar.gz
cd cloudklone
sudo docker-compose up -d
```

---

## Architecture

**Control Plane Components:**
- Management Console: Web-based administrative interface
- API Layer: RESTful API with WebSocket for real-time updates
- Orchestration Engine: Transfer scheduling and execution management
- Data Plane: Rclone execution layer for actual data transfer operations

**Ports:**
- 80 (HTTP) - Redirects to HTTPS
- 443 (HTTPS) - Primary access

**Volumes:**
- `postgres_data` - Database files
- `rclone_config` - Rclone configurations
- `ssl_certs` - SSL certificates
- `ssh_keys` - SSH known_hosts files

---

## Troubleshooting

**Cannot connect to management console:**
- Check containers running: `sudo docker-compose ps`
- Check logs: `sudo docker-compose logs app`
- Verify ports available: `sudo netstat -tlnp | grep -E ':(80|443)'`

**Database connection failed:**
- Wait 60 seconds for database initialization
- Check database health: `sudo docker-compose ps postgres`
- Review database logs: `sudo docker-compose logs postgres`

**SSL certificate error:**
- Verify OpenSSL installed: `sudo docker exec cloudklone-app openssl version`
- Recreate certificate volume: `sudo docker volume rm cloudklone_ssl_certs`

**Transfer stuck in running state:**
- Admin tab > System Tools > Cancel All Stuck Transfers
- Or restart app: `sudo docker-compose restart app`

For complete troubleshooting guide, see DEPLOYMENT-GUIDE.md

---

## Documentation

- **DEPLOYMENT-GUIDE.md** - Complete deployment and configuration reference
- **FEATURES.md** - Detailed feature documentation

---

## License

CloudKlone is provided as-is for self-hosting purposes.

Built with Rclone, Node.js, PostgreSQL, and Docker.
