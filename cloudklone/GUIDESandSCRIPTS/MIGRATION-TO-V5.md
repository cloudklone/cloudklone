# CloudKlone v5 - RBAC Migration Guide

## 🚀 What's New

**4 Role-Based Access Control:**
- Read-Only, Operator, Power User, Admin

**Audit Logging:**
- All actions logged with full transparency

---

## 📋 Quick Migration

```bash
# 1. Backup
cd ~/cloudklone
sudo docker-compose exec postgres pg_dump -U rclone_admin rclone_gui > ~/backup.sql

# 2. Deploy
sudo docker-compose down
cd ~ && tar -xzf cloudklone-v5-rbac-backend.tar.gz
cd cloudklone

# 3. Migrate database
sudo docker-compose up -d postgres && sleep 10

sudo docker-compose exec -T postgres psql -U rclone_admin rclone_gui << 'EOF'
ALTER TABLE groups ADD COLUMN IF NOT EXISTS permissions JSONB DEFAULT '{"role": "operator", "can_create_copy": true, "can_create_sync": false}';

CREATE TABLE IF NOT EXISTS audit_logs (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id),
  username VARCHAR(255),
  action VARCHAR(100),
  resource_type VARCHAR(50),
  resource_id INTEGER,
  resource_name VARCHAR(255),
  details JSONB,
  ip_address VARCHAR(45),
  user_agent TEXT,
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp DESC);
EOF

# 4. Start
sudo docker-compose up -d
```

**Done!** Backend RBAC is now active.

Default role for all users: **Operator** (copy only, no sync, no delete)

Frontend UI updates coming in Phase 3.
