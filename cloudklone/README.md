# CloudKlone - Cloud Storage Management Platform

**Streamlined cloud-to-cloud transfers powered by Rclone**

![CloudKlone](backend/logo.png)

## ✨ Features

- 🎨 **Modern Dark UI** - Sleek, professional interface
- ☁️ **Multi-Cloud Support** - S3, R2, B2, GCS, Azure, Dropbox, Google Drive, SFTP, and more
- ⚡ **Real-Time Monitoring** - Live transfer progress with exact MB/GB amounts
- 🔄 **Copy & Sync Operations** - Standard Rclone functionality
- 🌐 **Cloud-to-Cloud Transfers** - Data streams through server (middleware mode)
- 👥 **User Management** - Multi-user support with admin controls
- 🔐 **Secure** - JWT authentication, encrypted passwords

## 🚀 Quick Start

```bash
# Extract
tar -xzf cloudklone.tar.gz
cd cloudklone

# Start
sudo docker-compose up -d

# Access at http://localhost
# Login: admin / admin (change immediately!)
```

## 📋 Requirements

- Docker & Docker Compose
- 1GB RAM minimum
- 2GB disk space

## 🎯 What's New in CloudKlone

### Branding
- Custom CloudKlone logo and branding throughout
- Professional dark theme interface

### Enhanced Transfer Display
- Shows exact transfer amounts (e.g., "245.5 MiB / 1.2 GiB")
- Real-time speed monitoring
- Accurate ETA calculations
- Percentage progress bars

### Quick Deploy
- Single-file HTML application
- Fast Docker build (1-2 minutes)
- No complex build process

## 📊 Architecture

```
cloudklone/
├── docker-compose.yml      # Container orchestration
└── backend/
    ├── index.js            # Node.js API + WebSocket server
    ├── index.html          # Single-page application
    ├── package.json        # Dependencies
    └── logo.png            # CloudKlone logo
```

## 🔧 Configuration

### Environment Variables

Edit `docker-compose.yml` to customize:

```yaml
environment:
  POSTGRES_PASSWORD: your-secure-password
  JWT_SECRET: your-secure-jwt-secret
  PORT: 3001
```

### Ports

- `80` - Web interface (HTTP)
- `3001` - Backend API (internal)
- `5432` - PostgreSQL (internal)

## 📖 Usage

### Adding a Remote

1. Navigate to **Remotes** tab
2. Click **Add Remote**
3. Select provider (S3, B2, GCS, etc.)
4. Enter credentials
5. Click **Test** to verify connection

### Creating a Transfer

1. Navigate to **Transfers** tab
2. Click **New Transfer**
3. Select operation:
   - **Copy** - Duplicates files (preserves source)
   - **Sync** - Mirrors to destination
4. Choose source remote and path
5. Choose destination remote and path
6. Click **Start Transfer**
7. Monitor real-time progress with exact MB amounts

### Managing Users (Admin Only)

1. Navigate to **Users** tab
2. Click **Add User**
3. Set username, email, password
4. Optionally grant admin privileges

## 🛠️ Management Commands

```bash
# View logs
sudo docker-compose logs -f

# Restart
sudo docker-compose restart

# Stop
sudo docker-compose down

# Update
sudo docker-compose pull
sudo docker-compose up -d

# Backup database
sudo docker-compose exec postgres pg_dump -U rclone_admin rclone_gui > backup.sql

# Restore database
sudo docker-compose exec -T postgres psql -U rclone_admin rclone_gui < backup.sql
```

## 🔒 Security Best Practices

1. **Change default password** immediately after first login
2. **Use strong passwords** for database and JWT secret
3. **Enable HTTPS** with proper SSL certificates for production
4. **Restrict access** with firewall rules
5. **Regular backups** of PostgreSQL database
6. **Update regularly** to get latest security patches

## 🎨 Supported Cloud Providers

| Provider | Type | Status |
|----------|------|--------|
| Amazon S3 | s3 | ✅ Full Support |
| Cloudflare R2 | s3 | ✅ Full Support |
| Backblaze B2 | b2 | ✅ Full Support |
| Google Cloud Storage | google cloud storage | ✅ Full Support |
| Azure Blob Storage | azureblob | ✅ Full Support |
| Dropbox | dropbox | ✅ Full Support |
| Google Drive | drive | ✅ Full Support |
| SFTP | sftp | ✅ Full Support |
| Local Filesystem | local | ✅ Full Support |

## 🐛 Troubleshooting

### Can't access on port 80

```bash
# Check if containers are running
sudo docker-compose ps

# Check logs
sudo docker-compose logs app

# Verify port is not in use
sudo netstat -tlnp | grep :80
```

### Database connection errors

```bash
# Remove stale database volume
sudo docker-compose down
sudo docker volume rm cloudklone_postgres_data
sudo docker-compose up -d
```

### Transfer not starting

```bash
# Check rclone is installed
sudo docker-compose exec app rclone version

# Test remote connection
# Use "Test" button in Remotes page

# Check backend logs
sudo docker-compose logs app | grep rclone
```

## 📈 Performance

- **Transfer Speed** - Limited by your server's network bandwidth
- **Concurrent Transfers** - Multiple transfers supported
- **Memory Usage** - ~150-200MB per container
- **CPU Usage** - Low (rclone handles transfers efficiently)

## 🔄 Upgrading

To upgrade to a new version:

```bash
# Backup first
sudo docker-compose exec postgres pg_dump -U rclone_admin rclone_gui > backup.sql

# Stop current version
sudo docker-compose down

# Extract new version
tar -xzf cloudklone-new.tar.gz

# Copy old data
sudo cp -r old-cloudklone/backend/. cloudklone/backend/

# Start new version
cd cloudklone
sudo docker-compose up -d
```

## 🤝 Support

For issues and questions:
- Check logs: `sudo docker-compose logs -f`
- Verify all containers are healthy: `sudo docker-compose ps`
- Ensure database is accessible: `sudo docker-compose exec postgres pg_isready`

## 📝 License

MIT License - See LICENSE file for details

## 🙏 Credits

- Powered by [Rclone](https://rclone.org/) - The amazing cloud storage CLI tool
- Built with Node.js, Express, PostgreSQL, and WebSocket
- Logo designed for CloudKlone

---

**CloudKlone** - Simplifying cloud storage management, one transfer at a time.
