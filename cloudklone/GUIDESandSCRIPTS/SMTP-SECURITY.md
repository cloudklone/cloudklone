# SMTP Configuration Security

## ✅ What's Encrypted NOW

After this update, **SMTP passwords are encrypted** using AES-256-CBC encryption:

### Storage (Database):
```sql
smtp_pass = 'iv:encrypted_data'  -- AES-256 encrypted with your ENCRYPTION_KEY
```

### Transmission (API):
```javascript
POST /api/notifications/settings
{
  "smtp_pass": "my-plain-password"  // ← Sent over HTTPS
}
// Server encrypts immediately before storing
```

### Usage (Sending Email):
```javascript
// Retrieved from database (encrypted)
const encrypted = settings.smtp_pass;

// Decrypted in memory only when needed
const decrypted = decrypt(encrypted);

// Used to authenticate with SMTP server
auth: { pass: decrypted }

// Immediately discarded after use
```

---

## 🔒 Encryption Details

### What Gets Encrypted:
1. **Remote credentials** (S3 keys, B2 tokens, SFTP passwords)
2. **SMTP passwords** ← NEW!
3. **User passwords** (bcrypt hash, not AES)

### Encryption Method:
- **Algorithm:** AES-256-CBC
- **Key:** Your auto-generated `ENCRYPTION_KEY` (64-char hex)
- **IV:** Random 16-byte initialization vector per encryption
- **Format:** `iv:encrypted_data` (both in hex)

### Example:
```
Plain: mypassword123
Encrypted: a1b2c3d4e5f6...789:9f8e7d6c5b4a...321
         └─ Random IV ─┘ └─ Encrypted data ──┘
```

---

## 🚨 Security Checklist

### ✅ What's Secure:

| Data | Storage | Transmission | At Rest |
|------|---------|--------------|---------|
| User passwords | bcrypt hash | HTTPS | ✅ Hashed |
| Remote API keys | AES-256 | HTTPS | ✅ Encrypted |
| SFTP passwords | rclone obscured + AES-256 | HTTPS | ✅ Encrypted |
| SMTP passwords | AES-256 | HTTPS | ✅ Encrypted |
| JWT tokens | Signed | HTTPS | ✅ Signed |

### ⚠️ Not Encrypted (By Design):

| Data | Why Not Encrypted |
|------|-------------------|
| Email addresses | Need to display to user |
| SMTP hostnames | Need to display/validate |
| SMTP usernames | Need to display to user |
| Remote names | User-facing labels |
| Transfer history | Need for reporting/filtering |

---

## 🔐 Security Architecture

### Layer 1: Transport (HTTPS)
```
User Browser ←→ [TLS/HTTPS] ←→ CloudKlone Server
```
**Recommendation:** Use reverse proxy (nginx/Caddy) with SSL certificate

### Layer 2: Application (JWT)
```
Login → JWT token (24hr expiry) → All API calls require token
```

### Layer 3: Database (Encryption at Rest)
```
Sensitive data → encrypt() → Database
Database → decrypt() → Used in memory → Discarded
```

### Layer 4: System (Environment)
```
ENCRYPTION_KEY stored in:
- /app/.env (inside container)
- Docker volume (persistent)
- Never exposed via API
```

---

## 🔑 ENCRYPTION_KEY Importance

**Your ENCRYPTION_KEY is CRITICAL:**
- If lost: All encrypted data is unrecoverable
- If leaked: All encrypted data can be decrypted
- If changed: All existing encrypted data becomes unreadable

**Backup your key:**
```bash
# From inside container
docker cp cloudklone-app:/app/.env ./encryption-key-backup.txt

# Store securely!
```

---

## 🎯 What Happens When You Save SMTP Settings

### Step 1: Client Side (Browser)
```javascript
{
  smtp_pass: "my-actual-password"  // Plain text in memory
}
// Sent over HTTPS to server
```

### Step 2: Server Side (Backend)
```javascript
// Received
const { smtp_pass } = req.body;  // "my-actual-password"

// Encrypted immediately
const encrypted = encrypt(smtp_pass);
// Result: "a1b2c3...789:9f8e7d...321"

// Stored encrypted
await pool.query(
  'INSERT INTO notification_settings ... VALUES ($1)',
  [encrypted]  // Encrypted value stored
);
```

### Step 3: Database
```sql
-- What's actually stored:
smtp_pass = 'a1b2c3d4e5f6...789:9f8e7d6c5b4a...321'
--          └─── Encrypted! ───┘
```

### Step 4: When Sending Email
```javascript
// Retrieved (still encrypted)
const settings = await pool.query('SELECT ...');
// settings.smtp_pass = "a1b2c3...789:9f8e7d...321"

// Decrypted ONLY when needed
const decrypted = decrypt(settings.smtp_pass);
// decrypted = "my-actual-password"

// Used immediately
nodemailer.createTransport({
  auth: { pass: decrypted }
});

// Decrypted value discarded after use
```

---

## 🛡️ Additional Security Measures

### Already Implemented:
- ✅ Password hashing (bcrypt, cost factor 10)
- ✅ JWT token expiry (24 hours)
- ✅ SQL injection protection (parameterized queries)
- ✅ Encryption key auto-generation
- ✅ Encrypted credential storage
- ✅ SMTP password encryption

### Recommended for Production:
- ⚠️ HTTPS/TLS (use reverse proxy)
- ⚠️ Rate limiting (basic implemented, upgrade for production)
- ⚠️ Regular encryption key backups
- ⚠️ Firewall rules (only ports 80/443)
- ⚠️ Database password change
- ⚠️ Regular security updates

### Not Implemented (Future):
- ❌ 2FA/MFA
- ❌ Audit logging
- ❌ IP allowlisting
- ❌ Encryption key rotation
- ❌ Hardware security module (HSM)

---

## 📊 Threat Model

### Protected Against:
| Threat | Protection |
|--------|-----------|
| Database breach | ✅ Passwords encrypted |
| SQL injection | ✅ Parameterized queries |
| Password cracking | ✅ bcrypt with salt |
| Token theft | ✅ 24hr expiry |
| Credential exposure | ✅ Never logged/displayed |

### Not Protected Against:
| Threat | Mitigation |
|--------|------------|
| Man-in-the-middle | Use HTTPS reverse proxy |
| Stolen ENCRYPTION_KEY | Keep key secure, backup safely |
| Compromised server | Standard OS security practices |
| Brute force login | Add rate limiting |

---

## 🔍 How to Verify Encryption

### Check Database:
```bash
# Connect to database
sudo docker exec -it cloudklone-database psql -U rclone_admin rclone_gui

# View encrypted passwords
SELECT id, user_id, length(smtp_pass), 
       substring(smtp_pass, 1, 20) || '...' as encrypted_preview
FROM notification_settings;

# Should show:
# length | encrypted_preview
# -------+----------------------
#    129 | a1b2c3d4e5f6789012...
```

### Check Code:
```bash
# Verify encryption is used
sudo docker exec cloudklone-app grep -n "encrypt(smtp_pass)" index.js

# Should show line number where encryption happens
```

### Test Flow:
1. Save SMTP settings with password "test123"
2. Check database - should NOT see "test123"
3. Send test email - should work (decrypted)
4. Verify encrypted value persists in database

---

## 🚀 Migration Steps

If you saved SMTP settings BEFORE this update, they're stored in **plain text**. After deploying this update:

```bash
# 1. Deploy new version
sudo docker-compose down
cd ~ && tar -xzf cloudklone-v4-final.tar.gz
cd cloudklone
sudo docker-compose up -d

# 2. Re-enter your SMTP password in Settings
# (This will encrypt it)

# 3. Verify encryption
sudo docker exec -it cloudklone-database psql -U rclone_admin rclone_gui
SELECT length(smtp_pass) FROM notification_settings WHERE user_id = 1;
# Should show ~100-150 chars (encrypted), not 10-20 (plain text)
```

---

## 🎉 Summary

**Question:** Is SMTP configuration encrypted when it verifies?

**Answer:** **YES, NOW IT IS!** 

- SMTP passwords are encrypted with AES-256 before storage
- Decrypted only in memory when sending emails
- Never exposed via API or logs
- Protected by your auto-generated ENCRYPTION_KEY

**Your SMTP credentials are now as secure as your remote credentials!** 🔒✨
