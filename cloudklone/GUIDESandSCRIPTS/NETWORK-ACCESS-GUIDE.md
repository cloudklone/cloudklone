# CloudKlone Network Access Guide

## 🌐 Making CloudKlone Accessible from Other Devices

CloudKlone should support **unlimited simultaneous connections**. If you can only access it from your laptop, it's a **firewall or network configuration issue**.

---

## 🔍 Quick Diagnosis

Run this diagnostic script on your server:

```bash
#!/bin/bash
echo "=== CloudKlone Network Diagnostic ==="
echo ""

echo "1. Docker Status:"
sudo docker ps | grep cloudklone

echo ""
echo "2. Port Binding:"
sudo ss -tulpn | grep :80

echo ""
echo "3. Server IP Addresses:"
ip addr show | grep "inet " | grep -v 127.0.0.1

echo ""
echo "4. Firewall Status:"
if command -v firewall-cmd &> /dev/null; then
    echo "Using firewalld:"
    sudo firewall-cmd --list-all
elif command -v ufw &> /dev/null; then
    echo "Using UFW:"
    sudo ufw status
else
    echo "No firewall detected"
fi

echo ""
echo "5. SELinux Status (if applicable):"
if command -v getenforce &> /dev/null; then
    getenforce
else
    echo "SELinux not present"
fi
```

Save as `diagnose.sh`, run:
```bash
chmod +x diagnose.sh
./diagnose.sh
```

---

## 🎯 Common Issues & Solutions

### Issue 1: Firewall Blocking Port 80 (Most Common!)

#### For Fedora/RHEL/CentOS (firewalld):
```bash
# Check what's open
sudo firewall-cmd --list-all

# Open HTTP service (includes port 80)
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --reload

# Verify
sudo firewall-cmd --list-services
# Should include "http"

# Alternative: Open port 80 directly
sudo firewall-cmd --permanent --add-port=80/tcp
sudo firewall-cmd --reload
```

#### For Ubuntu/Debian (UFW):
```bash
# Check status
sudo ufw status

# Allow port 80
sudo ufw allow 80/tcp
sudo ufw reload

# Verify
sudo ufw status numbered
# Should show: 80/tcp ALLOW IN
```

---

### Issue 2: SELinux Blocking Connections (Fedora/RHEL)

```bash
# Check if SELinux is enabled
getenforce
# If returns "Enforcing", SELinux is active

# Allow HTTP connections
sudo setsebool -P httpd_can_network_connect 1

# Test by temporarily disabling SELinux
sudo setenforce 0
# Try accessing CloudKlone from another device
# If it works now, SELinux was the issue

# Re-enable SELinux
sudo setenforce 1
```

---

### Issue 3: Docker Binding to Localhost Only

**Check binding:**
```bash
sudo ss -tulpn | grep :80
```

**Expected output:**
```
tcp   LISTEN 0.0.0.0:80    0.0.0.0:*
                └─ Good! Listening on all interfaces
```

**Bad output:**
```
tcp   LISTEN 127.0.0.1:80  0.0.0.0:*
                └─ Bad! Only localhost
```

**Fix (already in updated package):**
```yaml
# docker-compose.yml
ports:
  - "0.0.0.0:80:3001"  # Explicitly bind to all interfaces
```

Then redeploy:
```bash
cd ~/cloudklone
sudo docker-compose down
sudo docker-compose up -d
```

---

### Issue 4: Wrong IP Address

#### Find Your Server's IP:

```bash
# Method 1: All interfaces
ip addr show

# Method 2: Just the useful ones
ip addr show | grep "inet " | grep -v 127.0.0.1 | awk '{print $2}'

# Method 3: External IP (if cloud server)
curl ifconfig.me
```

**Example output:**
```
inet 192.168.1.100/24 brd 192.168.1.255 scope global enp0s3
     └─ Your local network IP

inet 10.0.0.13/24 brd 10.0.0.255 scope global eth0
     └─ Your actual server IP
```

#### Access From Other Devices:

**Correct:**
```
http://192.168.1.100    ← Replace with YOUR server IP
http://10.0.0.13        ← Or your actual network IP
```

**Wrong:**
```
❌ http://localhost      ← Only works on the server
❌ http://127.0.0.1      ← Only works on the server
❌ http://10.0.0.13      ← Only correct if that's YOUR server IP
```

---

## 🚀 Complete Fix Procedure

### Step 1: Deploy Updated Version
```bash
cd ~/cloudklone
sudo docker-compose down

cd ~ && tar -xzf cloudklone-v4-final.tar.gz
cd cloudklone

# Updated docker-compose with explicit binding
sudo docker-compose up -d
```

### Step 2: Open Firewall

**Fedora/RHEL/CentOS:**
```bash
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --reload
```

**Ubuntu/Debian:**
```bash
sudo ufw allow 80/tcp
sudo ufw reload
```

### Step 3: Fix SELinux (if applicable)
```bash
sudo setsebool -P httpd_can_network_connect 1
```

### Step 4: Test Connection

**From server:**
```bash
curl -I http://localhost
# Should return: HTTP/1.1 200 OK
```

**From another device:**
```bash
# Replace with YOUR server IP
curl -I http://192.168.1.100
# Should return: HTTP/1.1 200 OK
```

---

## 🧪 Systematic Testing

### Test 1: Local Access
```bash
# On the server
curl http://localhost
```
✅ **Works?** → Docker is running correctly
❌ **Fails?** → Docker issue, check `sudo docker ps`

### Test 2: Local IP Access
```bash
# On the server, using its own IP
curl http://192.168.1.100  # Replace with your IP
```
✅ **Works?** → Docker binding is correct
❌ **Fails?** → Docker binding issue, use `0.0.0.0:80:3001`

### Test 3: Remote Access
```bash
# From another device on same network
curl http://192.168.1.100  # Replace with server IP
```
✅ **Works?** → Everything is working!
❌ **Fails?** → Firewall/SELinux blocking

### Test 4: Browser Access
```
http://192.168.1.100
```
✅ **Works?** → Perfect!
❌ **"Connection refused"?** → Firewall issue
❌ **"This site can't be reached"?** → Wrong IP or network issue

---

## 🔒 Security Note

**Opening port 80 to all interfaces** means anyone on your network can access CloudKlone. For production use:

### Option 1: Restrict to Specific IPs
```yaml
# docker-compose.yml
ports:
  - "192.168.1.0/24:80:3001"  # Only your subnet
```

### Option 2: Use Reverse Proxy with SSL
```bash
# Install nginx
sudo dnf install nginx  # Fedora/RHEL
sudo apt install nginx  # Ubuntu/Debian

# Configure nginx with SSL
# Then bind CloudKlone to localhost only
ports:
  - "127.0.0.1:80:3001"
```

### Option 3: VPN Access Only
- Keep CloudKlone on localhost
- Access via VPN (WireGuard, Tailscale, etc.)

---

## 📊 Network Architecture

### Current Setup:
```
[Your Laptop] ----X----> [Server:80 CloudKlone]
                         └─ Firewall blocking?
```

### After Fix:
```
[Your Laptop] ---------> [Server:80 CloudKlone]
[Phone]       ---------> [Server:80 CloudKlone]
[Tablet]      ---------> [Server:80 CloudKlone]
              └─ All can connect simultaneously
```

### Multiple Users:
```
User 1 [Laptop]  ----\
User 2 [Phone]   -----+----> [CloudKlone Server]
User 3 [Desktop] ----/       └─ Handles all connections
```

CloudKlone uses:
- **JWT tokens** for authentication
- **WebSocket** for real-time updates
- **PostgreSQL** for data storage
- **Node.js** Express server

There's **no connection limit** - it supports unlimited simultaneous users!

---

## 🐛 Advanced Troubleshooting

### Check Docker Logs
```bash
sudo docker-compose logs -f app
# Look for binding errors
```

### Check Network Routes
```bash
# Is your device on the same network?
ip route show
```

### Test with Specific Interface
```bash
# If server has multiple IPs, test each
curl http://192.168.1.100  # LAN IP
curl http://10.0.0.13      # VPN IP?
```

### Temporarily Disable Firewall (Testing Only!)
```bash
# Fedora/RHEL
sudo systemctl stop firewalld
# Try accessing
sudo systemctl start firewalld

# Ubuntu/Debian
sudo ufw disable
# Try accessing
sudo ufw enable
```

---

## ✅ Verification Checklist

- [ ] Docker container running: `sudo docker ps | grep cloudklone`
- [ ] Binding to 0.0.0.0:80: `sudo ss -tulpn | grep :80`
- [ ] Firewall allows HTTP: `sudo firewall-cmd --list-services`
- [ ] SELinux allows connections: `sudo getsebool httpd_can_network_connect`
- [ ] Can access locally: `curl http://localhost`
- [ ] Can access via IP: `curl http://YOUR_IP`
- [ ] Browser works from other device: `http://YOUR_IP`

---

## 🎉 Success!

After fixing, you should be able to access CloudKlone from:
- ✅ Your laptop
- ✅ Your phone
- ✅ Your tablet
- ✅ Other computers on the network
- ✅ All simultaneously!

Each user:
1. Navigates to `http://YOUR_SERVER_IP`
2. Logs in with their own credentials
3. Gets their own session and view
4. Can work independently

**No connection limits!** 🚀
