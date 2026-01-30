# Troubleshooting Guide

## Build Issues

### Error: "sh: syntax error: unexpected"

**Problem**: Rclone install script failing during Docker build.

**Solution**: The Dockerfile has been updated to use Alpine's package manager instead of the install script.

```dockerfile
# Old (broken):
RUN curl https://rclone.org/install.sh | sh

# New (works):
RUN apk add --no-cache rclone
```

If you see this error, update your `backend/Dockerfile` to use `apk add rclone`.

### Error: "npm ci can only install with existing package-lock.json"

**Problem**: Missing package-lock.json files.

**Solution**: The Dockerfile has been updated to use `npm install` instead of `npm ci`.

```dockerfile
# Old:
RUN npm ci

# New:
RUN npm install
```

### Error: "version is obsolete"

**Problem**: Docker Compose warns about obsolete version field.

**Solution**: Remove the `version: '3.8'` line from docker-compose.yml (it's been removed in the fixed version).

## Runtime Issues

### Cannot Access Application

**Check services are running:**
```bash
docker-compose ps

# All services should show "Up" status
```

**Check logs:**
```bash
# All services
docker-compose logs

# Specific service
docker-compose logs backend
docker-compose logs frontend
docker-compose logs postgres
```

### Database Connection Failed

**Verify PostgreSQL is healthy:**
```bash
docker-compose ps postgres

# Should show "healthy" status
```

**Check database logs:**
```bash
docker-compose logs postgres
```

**Restart database:**
```bash
docker-compose restart postgres

# Wait 10 seconds for health check
sleep 10

# Check status
docker-compose ps postgres
```

### Backend Won't Start

**Check backend logs:**
```bash
docker-compose logs backend
```

**Common issues:**

1. **Database not ready** - Wait for postgres to be healthy
2. **Port conflict** - Check if port 3001 is already in use
3. **Environment variables** - Verify .env file exists

**Fix:**
```bash
# Stop all services
docker-compose down

# Start database first
docker-compose up -d postgres

# Wait for healthy status
docker-compose ps postgres

# Start backend
docker-compose up -d backend

# Start frontend
docker-compose up -d frontend

# Start nginx
docker-compose up -d nginx
```

### Frontend Shows Blank Page

**Check frontend logs:**
```bash
docker-compose logs frontend
```

**Check if built correctly:**
```bash
# Rebuild frontend
docker-compose up -d --build frontend
```

**Check Nginx logs:**
```bash
docker-compose logs nginx
```

### WebSocket Connection Failed

**Symptoms:**
- Transfer progress not updating in real-time
- Console shows WebSocket errors

**Solutions:**

1. **Check backend is running:**
```bash
docker-compose ps backend
```

2. **Verify WebSocket endpoint:**
   - HTTP: ws://localhost/ws
   - HTTPS: wss://localhost/ws

3. **Check Nginx configuration:**
```bash
# View nginx config
cat nginx/nginx.conf

# Look for WebSocket upgrade headers
```

4. **Browser blocking mixed content:**
   - If using HTTPS, WebSocket must be WSS
   - Check browser console for errors

### Transfers Not Starting

**Check rclone is installed:**
```bash
docker-compose exec backend rclone version
```

**Check backend logs:**
```bash
docker-compose logs backend | grep rclone
```

**Verify remote configuration:**
1. Go to Remotes page
2. Click "Test" on the remote
3. Check for error messages

**Check rclone config files:**
```bash
# List config files
docker-compose exec backend ls -la /root/.config/rclone/

# View a config file
docker-compose exec backend cat /root/.config/rclone/user_1.conf
```

### SSL/HTTPS Issues

**Certificate not found:**
```bash
# Check if certificates exist
ls -la nginx/ssl/

# Should see cert.pem and key.pem
```

**Generate self-signed certificate:**
```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout nginx/ssl/key.pem \
  -out nginx/ssl/cert.pem \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
```

**Restart nginx after adding certificates:**
```bash
docker-compose restart nginx
```

**Browser shows "Not Secure":**
- This is normal for self-signed certificates
- Click "Advanced" → "Proceed to localhost"
- For production, use Let's Encrypt

## Permission Issues

### Error: "Permission denied"

**Docker volume permissions:**
```bash
# Check volume ownership
docker-compose exec backend ls -la /root/.config/rclone/

# Fix permissions if needed
docker-compose exec backend chown -R node:node /root/.config/rclone/
```

**File upload issues:**
```bash
# Check cache directory
docker-compose exec backend ls -la /app/cache/

# Fix if needed
docker-compose exec backend chown -R node:node /app/cache/
```

## Performance Issues

### Slow Transfers

**Check server resources:**
```bash
# CPU and memory usage
docker stats

# Network usage
docker-compose exec backend ifconfig
```

**Optimize rclone:**
- Transfers use default rclone settings
- For faster transfers, modify backend/src/index.js:
```javascript
const args = [
  command,
  source,
  dest,
  '--config', configFile,
  '--transfers', '4',        // Add: parallel transfers
  '--checkers', '8',         // Add: parallel file checks
  '--buffer-size', '64M',    // Add: larger buffer
];
```

### High Memory Usage

**Check Docker stats:**
```bash
docker stats
```

**Set memory limits in docker-compose.yml:**
```yaml
backend:
  deploy:
    resources:
      limits:
        memory: 2G
```

## Data Issues

### Lost All Data

**Check volumes:**
```bash
# List volumes
docker volume ls

# Should see:
# rclone-gui_postgres_data
# rclone-gui_rclone_config
# rclone-gui_transfer_cache
```

**Backup database:**
```bash
docker-compose exec postgres pg_dump -U rclone_admin rclone_gui > backup.sql
```

**Restore database:**
```bash
docker-compose exec -T postgres psql -U rclone_admin rclone_gui < backup.sql
```

### Reset Everything (DANGER!)

**Complete reset (deletes all data):**
```bash
# Stop and remove everything
docker-compose down -v

# Remove all volumes
docker volume prune

# Start fresh
docker-compose up -d
```

## Useful Commands

### Restart Individual Service
```bash
docker-compose restart backend
docker-compose restart frontend
docker-compose restart nginx
docker-compose restart postgres
```

### View Real-Time Logs
```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f backend
```

### Execute Commands in Container
```bash
# Backend shell
docker-compose exec backend sh

# PostgreSQL shell
docker-compose exec postgres psql -U rclone_admin rclone_gui

# Check rclone
docker-compose exec backend rclone version
```

### Rebuild Containers
```bash
# Rebuild all
docker-compose build

# Rebuild specific service
docker-compose build backend

# Rebuild and restart
docker-compose up -d --build
```

### Check Container Health
```bash
# Quick status
docker-compose ps

# Detailed inspection
docker-compose exec backend wget -O- http://localhost:3001/api/providers
```

## Still Having Issues?

1. **Check Docker version:**
```bash
docker --version
docker-compose --version
```

2. **Clean Docker cache:**
```bash
docker system prune -a
```

3. **Check system resources:**
```bash
df -h  # Disk space
free -h  # Memory
```

4. **Enable debug logging:**
```bash
# Edit docker-compose.yml
# Add to backend service:
environment:
  - DEBUG=*
```

5. **Create GitHub issue** with:
   - Error messages
   - Output of `docker-compose logs`
   - Docker version
   - Operating system
