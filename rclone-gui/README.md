# Rclone GUI - Self-Hosted Cloud Storage Manager

A sleek, modern web interface for managing Rclone cloud storage transfers. Built with React and Node.js, designed for self-hosting via Docker.

![Rclone GUI](https://via.placeholder.com/800x400/0a0a0a/3b82f6?text=Rclone+GUI)

## Features

- **🎨 Modern Dark UI** - Sleek, technical design inspired by Cloudflare, Tailscale, and n8n
- **☁️ Multi-Cloud Support** - Works with S3, B2, GCS, Azure, Dropbox, Google Drive, SFTP, and more
- **⚡ Real-Time Monitoring** - Live transfer progress with WebSocket updates
- **🔄 Copy & Sync Operations** - Standard Rclone copy and sync functionality
- **🌐 Cloud-to-Cloud Transfers** - Data passes through server as middleware (no local storage)
- **👥 User Management** - Multi-user support with admin controls
- **🔐 Secure Authentication** - JWT-based authentication system
- **🐳 Docker Ready** - Complete Docker Compose setup included
- **🔒 HTTPS Support** - Optional SSL/TLS certificate support

## Infrastructure

### Requirements

- Docker & Docker Compose
- (Optional) SSL certificates for HTTPS

### Architecture

- **Frontend**: React with modern CSS (dark mode only)
- **Backend**: Node.js + Express + WebSocket
- **Database**: PostgreSQL
- **Reverse Proxy**: Nginx
- **Transfer Engine**: Rclone

## Quick Start

### 1. Clone or Download

```bash
# If you have the files locally, navigate to the directory
cd rclone-gui
```

### 2. Configure Environment

```bash
# Copy example environment file
cp .env.example .env

# Edit .env and set secure passwords
nano .env
```

**Important**: Change the default values in `.env`:
```env
DB_PASSWORD=your_secure_database_password_here
JWT_SECRET=your_super_secret_jwt_key_minimum_32_characters
```

### 3. (Optional) Setup SSL Certificates

For HTTPS support, place your certificates in `nginx/ssl/`:

```bash
# Using self-signed certificate (for testing)
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout nginx/ssl/key.pem \
  -out nginx/ssl/cert.pem \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"

# OR using Let's Encrypt (for production)
sudo certbot certonly --standalone -d your-domain.com
sudo cp /etc/letsencrypt/live/your-domain.com/fullchain.pem nginx/ssl/cert.pem
sudo cp /etc/letsencrypt/live/your-domain.com/privkey.pem nginx/ssl/key.pem
```

### 4. Start the Application

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Check status
docker-compose ps
```

### 5. Access the Application

- **HTTP**: http://localhost
- **HTTPS**: https://localhost (if certificates are configured)

**Default Login Credentials**:
- Username: `admin`
- Password: `admin`

**⚠️ Important**: Change the default password immediately after first login!

## Usage Guide

### Adding a Remote

1. Navigate to **Remotes** in the sidebar
2. Click **Add Remote**
3. Select your cloud provider (S3, B2, GCS, etc.)
4. Fill in the configuration details
5. Click **Test** to verify the connection
6. Save the remote

### Creating a Transfer

1. Navigate to **Transfers**
2. Click **New Transfer**
3. Select operation type:
   - **Copy**: Preserve source files (duplicate)
   - **Sync**: Mirror to destination (make identical)
4. Choose source remote and path
5. Choose destination remote and path
6. Click **Start Transfer**
7. Monitor real-time progress

### Managing Users (Admin Only)

1. Navigate to **Users**
2. Click **Add User**
3. Enter username, email, and password
4. Optionally grant admin privileges
5. Click **Create User**

### Changing Password

1. Navigate to **Settings**
2. Enter current password
3. Enter and confirm new password
4. Click **Update Password**

## Supported Cloud Providers

| Provider | Type | Features |
|----------|------|----------|
| Amazon S3 | `s3` | Full support, multiple providers (AWS, R2, Wasabi) |
| Backblaze B2 | `b2` | Full support |
| Google Cloud Storage | `google cloud storage` | Full support |
| Azure Blob Storage | `azureblob` | Full support |
| Dropbox | `dropbox` | Full support |
| Google Drive | `drive` | Full support |
| SFTP | `sftp` | Full support |
| Local Filesystem | `local` | Full support |

## Docker Management

```bash
# Stop all services
docker-compose down

# Stop and remove all data (WARNING: DELETES EVERYTHING)
docker-compose down -v

# Restart a specific service
docker-compose restart backend

# View logs for a specific service
docker-compose logs -f frontend

# Update containers
docker-compose pull
docker-compose up -d

# Backup database
docker-compose exec postgres pg_dump -U rclone_admin rclone_gui > backup.sql

# Restore database
docker-compose exec -T postgres psql -U rclone_admin rclone_gui < backup.sql
```

## Security Recommendations

1. **Change Default Password**: Immediately after first login
2. **Use Strong Passwords**: For database and JWT secret
3. **Enable HTTPS**: Use proper SSL certificates in production
4. **Firewall Rules**: Restrict access to ports 80/443
5. **Regular Updates**: Keep Docker images updated
6. **Backup Data**: Regularly backup the PostgreSQL database
7. **Secure Credentials**: Never commit `.env` file to version control

## Troubleshooting

### Cannot Connect to Backend

```bash
# Check if backend is running
docker-compose ps backend

# View backend logs
docker-compose logs backend

# Restart backend
docker-compose restart backend
```

### Database Connection Errors

```bash
# Check if PostgreSQL is running
docker-compose ps postgres

# View database logs
docker-compose logs postgres

# Recreate database (WARNING: DELETES DATA)
docker-compose down
docker volume rm rclone-gui_postgres_data
docker-compose up -d
```

### WebSocket Connection Issues

- Ensure you're using the same protocol (HTTP/HTTPS) for WebSocket
- Check browser console for WebSocket errors
- Verify Nginx configuration is correct

### Transfer Not Starting

- Verify remote configuration is correct
- Test remote connection using the **Test** button
- Check backend logs for Rclone errors
- Ensure source and destination paths are valid

## Development

### Local Development Setup

```bash
# Backend
cd backend
npm install
npm run dev

# Frontend
cd frontend
npm install
npm start

# Database (using Docker)
docker run -d \
  -p 5432:5432 \
  -e POSTGRES_DB=rclone_gui \
  -e POSTGRES_USER=rclone_admin \
  -e POSTGRES_PASSWORD=changeme123 \
  postgres:16-alpine
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DB_PASSWORD` | PostgreSQL password | `changeme123` |
| `JWT_SECRET` | JWT signing secret | (required) |
| `NODE_ENV` | Environment mode | `production` |

## Architecture Details

### Data Flow

1. User creates transfer via React frontend
2. Frontend sends request to Express backend
3. Backend stores transfer in PostgreSQL
4. Backend spawns Rclone process
5. Rclone streams data cloud-to-cloud
6. Progress updates sent via WebSocket
7. Frontend displays real-time progress

### Cloud-to-Cloud Transfers

Rclone handles cloud-to-cloud transfers efficiently:
- Data streams through server memory
- No disk storage required
- Supports large files
- Automatic retry on failures

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

MIT License - see LICENSE file for details

## Support

For issues and questions:
- Rclone Documentation: https://rclone.org/docs/
- GitHub Issues: [Your Repository URL]

## Acknowledgments

- [Rclone](https://rclone.org/) - The amazing cloud storage CLI
- Design inspiration: Cloudflare, Tailscale, n8n
- Icons: Hand-crafted SVGs

---

**Built with ❤️ for the self-hosting community**
