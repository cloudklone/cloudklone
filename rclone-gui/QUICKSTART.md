# Quick Setup Guide

## Prerequisites
- Docker installed
- Docker Compose installed

## Installation Steps

### 1. Configure Environment
```bash
cd rclone-gui
cp .env.example .env
nano .env
```

Set secure values:
- `DB_PASSWORD` - Choose a strong database password
- `JWT_SECRET` - Generate a secure 32+ character secret

### 2. (Optional) Setup SSL for HTTPS

#### For Testing (Self-Signed Certificate):
```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout nginx/ssl/key.pem \
  -out nginx/ssl/cert.pem \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
```

#### For Production (Let's Encrypt):
```bash
sudo certbot certonly --standalone -d your-domain.com
sudo cp /etc/letsencrypt/live/your-domain.com/fullchain.pem nginx/ssl/cert.pem
sudo cp /etc/letsencrypt/live/your-domain.com/privkey.pem nginx/ssl/key.pem
```

### 3. Start the Application
```bash
docker-compose up -d
```

### 4. Access the Application
- Without SSL: http://localhost
- With SSL: https://localhost

### 5. Login
- Username: `admin`
- Password: `admin`

**⚠️ IMPORTANT**: Change the default password immediately!

## Common Commands

```bash
# View logs
docker-compose logs -f

# Stop application
docker-compose down

# Restart services
docker-compose restart

# Update containers
docker-compose pull && docker-compose up -d
```

## Project Structure

```
rclone-gui/
├── docker-compose.yml          # Main orchestration file
├── .env.example                # Environment template
├── README.md                   # Full documentation
├── backend/                    # Node.js API server
│   ├── Dockerfile
│   ├── package.json
│   └── src/
│       └── index.js           # Main backend application
├── frontend/                   # React web interface
│   ├── Dockerfile
│   ├── package.json
│   ├── public/
│   └── src/
│       ├── App.js
│       ├── components/
│       └── index.js
└── nginx/                      # Reverse proxy
    ├── nginx.conf
    └── ssl/                    # Place SSL certificates here
```

## Next Steps

1. Add your first remote (Remotes → Add Remote)
2. Create a transfer (Transfers → New Transfer)
3. Add additional users if needed (Users → Add User)
4. Update your password (Settings)

For detailed documentation, see README.md
