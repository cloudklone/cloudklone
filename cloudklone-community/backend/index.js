const express = require('express');
const http = require('http');
const https = require('https');
const WebSocket = require('ws');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { spawn } = require('child_process');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs').promises;
const fsSync = require('fs');
const nodemailer = require('nodemailer');
const cron = require('node-cron');
const crypto = require('crypto');
const editionManager = require('./edition');

// Auto-generate and persist encryption keys if not set
const ENV_FILE = '/app/.env';
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || loadOrGenerateKey('ENCRYPTION_KEY');
const JWT_SECRET = process.env.JWT_SECRET || loadOrGenerateKey('JWT_SECRET');
const IV_LENGTH = 16;

function loadOrGenerateKey(keyName) {
  try {
    // Try to read from persistent .env file
    const envContent = require('fs').readFileSync(ENV_FILE, 'utf8');
    const match = envContent.match(new RegExp(`${keyName}=(.+)`));
    if (match) {
      console.log(`[OK] Loaded ${keyName} from ${ENV_FILE}`);
      return match[1].trim();
    }
  } catch (err) {
    // File doesn't exist or can't be read
  }
  
  // Generate new key
  const newKey = crypto.randomBytes(32).toString('hex');
  console.log(`⚠ Generated new ${keyName} - saving to ${ENV_FILE}`);
  
  // Persist to file
  try {
    let envContent = '';
    try {
      envContent = require('fs').readFileSync(ENV_FILE, 'utf8');
    } catch (e) {
      // File doesn't exist yet, create header
      envContent = `# CloudKlone Configuration - Generated ${new Date().toISOString()}\n# DO NOT DELETE OR MODIFY THESE KEYS!\n\n`;
    }
    
    // Add or update the key
    if (envContent.includes(`${keyName}=`)) {
      envContent = envContent.replace(new RegExp(`${keyName}=.+`), `${keyName}=${newKey}`);
    } else {
      envContent += `${keyName}=${newKey}\n`;
    }
    
    require('fs').writeFileSync(ENV_FILE, envContent);
    console.log(`[OK] Saved ${keyName} to ${ENV_FILE}`);
  } catch (err) {
    console.error(`⚠ Failed to save ${keyName} to file:`, err.message);
    console.error(`⚠ Key will be regenerated on next restart!`);
  }
  
  return newKey;
}

// Encryption for sensitive data at rest
function encrypt(text) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY.substring(0, 64), 'hex'), iv);
  let encrypted = cipher.update(text);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text) {
  const parts = text.split(':');
  const iv = Buffer.from(parts.shift(), 'hex');
  const encryptedText = Buffer.from(parts.join(':'), 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY.substring(0, 64), 'hex'), iv);
  let decrypted = decipher.update(encryptedText);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted.toString();
}

// Obscure password for rclone (rclone's own obscure format)
function obscurePassword(password) {
  return new Promise((resolve, reject) => {
    const rclone = spawn('rclone', ['obscure', password]);
    let output = '';
    rclone.stdout.on('data', (data) => { output += data.toString(); });
    rclone.on('close', (code) => {
      if (code === 0) resolve(output.trim());
      else reject(new Error('Failed to obscure password'));
    });
  });
}

// Scan SSH host keys for SFTP remotes
function scanSSHHostKey(host, port = 22) {
  return new Promise((resolve, reject) => {
    const sshKeyscan = spawn('ssh-keyscan', ['-p', port.toString(), '-t', 'rsa,ecdsa,ed25519', host]);
    let output = '';
    let errorOutput = '';
    
    sshKeyscan.stdout.on('data', (data) => { output += data.toString(); });
    sshKeyscan.stderr.on('data', (data) => { errorOutput += data.toString(); });
    
    const timeout = setTimeout(() => {
      sshKeyscan.kill();
      reject(new Error('SSH host key scan timed out after 10 seconds'));
    }, 10000);
    
    sshKeyscan.on('close', (code) => {
      clearTimeout(timeout);
      if (code === 0 && output.trim()) {
        // Filter out comments and empty lines
        const hostKeys = output.split('\n')
          .filter(line => line.trim() && !line.startsWith('#'))
          .join('\n');
        resolve(hostKeys);
      } else {
        reject(new Error(`Failed to scan SSH host key: ${errorOutput || 'No keys found'}`));
      }
    });
  });
}

// Generate self-signed certificate if it doesn't exist
async function ensureSSLCertificate() {
  const certDir = '/app/certs';
  const certPath = path.join(certDir, 'cert.pem');
  const keyPath = path.join(certDir, 'key.pem');
  
  try {
    await fs.mkdir(certDir, { recursive: true });
    
    // Check if certificates exist
    try {
      await fs.access(certPath);
      await fs.access(keyPath);
      console.log('[OK] SSL certificates found');
      return { certPath, keyPath };
    } catch {
      // Certificates don't exist, generate them
      console.log('[WARNING]  No SSL certificates found, generating self-signed certificate...');
      
      return new Promise((resolve, reject) => {
        const openssl = spawn('openssl', [
          'req', '-x509', '-newkey', 'rsa:4096', '-nodes',
          '-keyout', keyPath,
          '-out', certPath,
          '-days', '365',
          '-subj', '/CN=cloudklone/O=CloudKlone/C=US'
        ]);
        
        let errorOutput = '';
        openssl.stderr.on('data', (data) => { errorOutput += data.toString(); });
        
        openssl.on('close', (code) => {
          if (code === 0) {
            console.log('[OK] Self-signed SSL certificate generated successfully');
            console.log('[WARNING]  IMPORTANT: Browser will show security warning (this is expected)');
            console.log('   To proceed: Click "Advanced" → "Proceed to localhost (unsafe)"');
            resolve({ certPath, keyPath });
          } else {
            console.error('Failed to generate SSL certificate:', errorOutput);
            reject(new Error('Failed to generate SSL certificate'));
          }
        });
      });
    }
  } catch (err) {
    console.error('SSL certificate error:', err);
    throw err;
  }
}

const app = express();

// HTTP to HTTPS redirect middleware (must be first)
app.use((req, res, next) => {
  if (req.secure || req.headers['x-forwarded-proto'] === 'https') {
    return next();
  }
  // Redirect HTTP to HTTPS
  res.redirect(301, `https://${req.headers.host}${req.url}`);
});

const server = http.createServer(app);

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

app.use(cors());
app.use(express.json());

// Serve index.html for all non-API routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Serve logo
app.get('/logo.png', (req, res) => {
  res.sendFile(path.join(__dirname, 'logo.png'));
});

// ==================== RBAC & AUDIT HELPERS ====================

// Role permission definitions
const ROLE_PERMISSIONS = {
  'read_only': {
    role: 'read_only',
    can_create_copy: false,
    can_create_sync: false,
    can_edit_transfers: false,
    can_delete_own_transfers: false,
    can_delete_any_transfers: false,
    can_manage_remotes: false,
    can_manage_settings: false,
    can_manage_users: false
  },
  'operator': {
    role: 'operator',
    can_create_copy: true,
    can_create_sync: false,
    can_edit_transfers: false,
    can_delete_own_transfers: false,
    can_delete_any_transfers: false,
    can_manage_remotes: false,
    can_manage_settings: false,
    can_manage_users: false
  },
  'power_user': {
    role: 'power_user',
    can_create_copy: true,
    can_create_sync: true,
    can_edit_transfers: false,
    can_delete_own_transfers: true,
    can_delete_any_transfers: false,
    can_manage_remotes: true,
    can_manage_settings: false,
    can_manage_users: false
  },
  'admin': {
    role: 'admin',
    can_create_copy: true,
    can_create_sync: true,
    can_edit_transfers: true,
    can_delete_own_transfers: true,
    can_delete_any_transfers: true,
    can_manage_remotes: true,
    can_manage_settings: true,
    can_manage_users: true
  }
};

// Get user's permissions from their group
async function getUserPermissions(userId) {
  try {
    const result = await pool.query(`
      SELECT g.permissions, u.is_admin, u.group_id
      FROM users u
      LEFT JOIN groups g ON u.group_id = g.id
      WHERE u.id = $1
    `, [userId]);
    
    if (!result.rows[0]) return null;
    
    const user = result.rows[0];
    
    // Admins have all permissions
    if (user.is_admin) {
      return ROLE_PERMISSIONS.admin;
    }
    
    // If user has group with permissions, use those
    if (user.group_id && user.permissions) {
      return user.permissions;
    }
    
    // Default to operator permissions
    return ROLE_PERMISSIONS.operator;
  } catch (error) {
    console.error('Get user permissions error:', error);
    return ROLE_PERMISSIONS.operator; // Safe default
  }
}

// Log audit event
async function logAudit({ user_id, username, action, resource_type, resource_id, resource_name, details, ip_address, user_agent }) {
  try {
    await pool.query(`
      INSERT INTO audit_logs 
      (user_id, username, action, resource_type, resource_id, resource_name, details, ip_address, user_agent)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
    `, [user_id, username, action, resource_type, resource_id, resource_name, JSON.stringify(details || {}), ip_address, user_agent]);
  } catch (error) {
    console.error('Audit log error:', error);
  }
}

// Middleware: Check if user has specific permission
function requirePermission(permission) {
  return async (req, res, next) => {
    try {
      const permissions = await getUserPermissions(req.user.id);
      
      if (!permissions || !permissions[permission]) {
        await logAudit({
          user_id: req.user.id,
          username: req.user.username,
          action: 'permission_denied',
          resource_type: permission,
          resource_id: null,
          resource_name: req.path,
          details: { permission, reason: 'insufficient_permissions' },
          ip_address: req.ip,
          user_agent: req.get('user-agent')
        });
        return res.status(403).json({ error: 'Insufficient permissions', required: permission });
      }
      
      next();
    } catch (error) {
      console.error('Permission check error:', error);
      res.status(500).json({ error: 'Server error' });
    }
  };
}

// Middleware: Check operation type (copy vs sync)
async function validateTransferOperation(req, res, next) {
  try {
    const { operation } = req.body;
    const permissions = await getUserPermissions(req.user.id);
    
    // Guard against null permissions
    if (!permissions) {
      await logAudit({
        user_id: req.user.id,
        username: req.user.username,
        action: 'permission_lookup_failed',
        resource_type: 'transfer',
        resource_id: null,
        resource_name: operation,
        details: { operation, reason: 'permissions_null' },
        ip_address: req.ip,
        user_agent: req.get('user-agent')
      });
      return res.status(403).json({ 
        error: 'Unable to verify permissions. Please contact an administrator.',
        allowedOperations: []
      });
    }
    
    if (operation === 'sync' && !permissions.can_create_sync) {
      await logAudit({
        user_id: req.user.id,
        username: req.user.username,
        action: 'operation_denied',
        resource_type: 'transfer',
        resource_id: null,
        resource_name: 'sync',
        details: { operation, reason: 'sync_not_permitted' },
        ip_address: req.ip,
        user_agent: req.get('user-agent')
      });
      return res.status(403).json({ 
        error: 'Sync operations not permitted for your role. Only copy operations are allowed.',
        allowedOperations: permissions.can_create_copy ? ['copy'] : []
      });
    }
    
    if (operation === 'copy' && !permissions.can_create_copy) {
      await logAudit({
        user_id: req.user.id,
        username: req.user.username,
        action: 'operation_denied',
        resource_type: 'transfer',
        resource_id: null,
        resource_name: 'copy',
        details: { operation, reason: 'copy_not_permitted' },
        ip_address: req.ip,
        user_agent: req.get('user-agent')
      });
      return res.status(403).json({ 
        error: 'You do not have permission to create transfers.',
        allowedOperations: []
      });
    }
    
    next();
  } catch (error) {
    console.error('Operation validation error:', error);
    res.status(500).json({ error: 'Server error' });
  }
}

// Middleware: Check ownership for delete
async function checkTransferOwnership(req, res, next) {
  try {
    const permissions = await getUserPermissions(req.user.id);
    
    // Guard against null permissions
    if (!permissions) {
      await logAudit({
        user_id: req.user.id,
        username: req.user.username,
        action: 'permission_lookup_failed',
        resource_type: 'transfer',
        resource_id: req.params.id,
        resource_name: 'delete',
        details: { reason: 'permissions_null' },
        ip_address: req.ip,
        user_agent: req.get('user-agent')
      });
      return res.status(403).json({ 
        error: 'Unable to verify permissions. Please contact an administrator.'
      });
    }
    
    // Admins can delete any transfer
    if (permissions.can_delete_any_transfers) {
      return next();
    }
    
    // Power users can delete own transfers
    if (permissions.can_delete_own_transfers) {
      const transfer = await pool.query(
        'SELECT user_id FROM transfers WHERE id = $1',
        [req.params.id]
      );
      
      if (!transfer.rows[0]) {
        return res.status(404).json({ error: 'Transfer not found' });
      }
      
      if (transfer.rows[0].user_id !== req.user.id) {
        await logAudit({
          user_id: req.user.id,
          username: req.user.username,
          action: 'permission_denied',
          resource_type: 'transfer',
          resource_id: req.params.id,
          resource_name: 'delete',
          details: { reason: 'not_owner' },
          ip_address: req.ip,
          user_agent: req.get('user-agent')
        });
        return res.status(403).json({ error: 'You can only delete your own transfers' });
      }
      
      return next();
    }
    
    // No delete permission
    await logAudit({
      user_id: req.user.id,
      username: req.user.username,
      action: 'permission_denied',
      resource_type: 'transfer',
      resource_id: req.params.id,
      resource_name: 'delete',
      details: { reason: 'insufficient_permissions' },
      ip_address: req.ip,
      user_agent: req.get('user-agent')
    });
    return res.status(403).json({ error: 'You do not have permission to delete transfers' });
  } catch (error) {
    console.error('Ownership check error:', error);
    res.status(500).json({ error: 'Server error' });
  }
}

// Middleware: Admin only
function requireAdmin(req, res, next) {
  if (!req.user.isAdmin) {
    logAudit({
      user_id: req.user.id,
      username: req.user.username,
      action: 'permission_denied',
      resource_type: 'admin_action',
      resource_id: null,
      resource_name: req.path,
      details: { reason: 'not_admin' },
      ip_address: req.ip,
      user_agent: req.get('user-agent')
    });
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
}

// ==================== AUTH ROUTES ====================

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const result = await pool.query(
      'SELECT id, username, email, password_hash, is_admin, password_changed, enabled FROM users WHERE username = $1',
      [username]
    );
    if (result.rows.length === 0) {
      await logAudit({
        user_id: null,
        username: username,
        action: 'login_failed',
        resource_type: 'auth',
        details: { reason: 'user_not_found' },
        ip_address: req.ip,
        user_agent: req.get('user-agent')
      });
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const user = result.rows[0];
    
    // Check if user is enabled (default to true if column doesn't exist yet)
    if (user.enabled === false) {
      await logAudit({
        user_id: user.id,
        username: user.username,
        action: 'login_failed',
        resource_type: 'auth',
        details: { reason: 'user_disabled' },
        ip_address: req.ip,
        user_agent: req.get('user-agent')
      });
      return res.status(403).json({ error: 'User account has been disabled. Please contact an administrator.' });
    }
    
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      await logAudit({
        user_id: user.id,
        username: user.username,
        action: 'login_failed',
        resource_type: 'auth',
        details: { reason: 'invalid_password' },
        ip_address: req.ip,
        user_agent: req.get('user-agent')
      });
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Successful login
    await logAudit({
      user_id: user.id,
      username: user.username,
      action: 'login_success',
      resource_type: 'auth',
      details: { admin: user.is_admin },
      ip_address: req.ip,
      user_agent: req.get('user-agent')
    });
    
    const token = jwt.sign(
      { id: user.id, username: user.username, isAdmin: user.is_admin },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    res.json({
      token,
      user: { 
        id: user.id, 
        username: user.username, 
        email: user.email, 
        isAdmin: user.is_admin,
        passwordChanged: user.password_changed
      },
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get current user's permissions
app.get('/api/auth/permissions', authenticateToken, async (req, res) => {
  try {
    const permissions = await getUserPermissions(req.user.id);
    res.json({ permissions });
  } catch (error) {
    console.error('Get permissions error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Force password change (for first-time login)
app.post('/api/auth/change-password', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Current and new password are required' });
    }
    
    if (newPassword.length < 6) {
      return res.status(400).json({ error: 'New password must be at least 6 characters' });
    }
    
    // Get user with current password
    const result = await pool.query(
      'SELECT id, password_hash FROM users WHERE id = $1',
      [req.user.id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const user = result.rows[0];
    
    // Verify current password
    const validPassword = await bcrypt.compare(currentPassword, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }
    
    // Hash new password
    const newHash = await bcrypt.hash(newPassword, 10);
    
    // Update password and mark as changed
    await pool.query(
      'UPDATE users SET password_hash = $1, password_changed = true WHERE id = $2',
      [newHash, req.user.id]
    );
    
    // Log audit event
    await logAudit({
      user_id: req.user.id,
      username: req.user.username,
      action: 'password_changed',
      resource_type: 'auth',
      details: { forced_change: true },
      ip_address: req.ip,
      user_agent: req.get('user-agent')
    });
    
    res.json({ success: true, message: 'Password changed successfully' });
  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/register', authenticateToken, async (req, res) => {
  try {
    if (!req.user.isAdmin) return res.status(403).json({ error: 'Admin access required' });
    
    // Check edition user limit
    const canCreate = await editionManager.canCreateUser();
    if (!canCreate) {
      const userCount = await editionManager.getUserCount();
      const maxUsers = editionManager.getMaxUsers();
      return res.status(403).json({ 
        error: `User limit reached (${userCount}/${maxUsers})`,
        edition: editionManager.edition,
        upgrade: editionManager.isCommunity() ? 'professional' : null
      });
    }
    
    const { username, email, password, isAdmin = false } = req.body;
    if (!username || !email || !password) return res.status(400).json({ error: 'Missing required fields' });
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (username, email, password_hash, is_admin) VALUES ($1, $2, $3, $4) RETURNING id, username, email, is_admin',
      [username, email, hash, isAdmin]
    );
    
    // Log audit event
    await logAudit({
      user_id: req.user.id,
      username: req.user.username,
      action: 'user_created',
      resource_type: 'user',
      resource_id: result.rows[0].id,
      resource_name: username,
      details: { email, is_admin: isAdmin },
      ip_address: req.ip,
      user_agent: req.get('user-agent')
    });
    
    res.status(201).json({ user: result.rows[0] });
  } catch (error) {
    if (error.code === '23505') return res.status(400).json({ error: 'Username or email already exists' });
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== EDITION INFO ====================

app.get('/api/edition', authenticateToken, (req, res) => {
  res.json(editionManager.getEditionInfo());
});

// ==================== USER ROUTES ====================

app.get('/api/users', authenticateToken, async (req, res) => {
  try {
    if (!req.user.isAdmin) return res.status(403).json({ error: 'Admin access required' });
    const result = await pool.query('SELECT id, username, email, is_admin, group_id, created_at FROM users ORDER BY created_at DESC');
    res.json({ users: result.rows });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/users/:id', authenticateToken, async (req, res) => {
  try {
    if (!req.user.isAdmin) return res.status(403).json({ error: 'Admin access required' });
    if (parseInt(req.params.id) === req.user.id) return res.status(400).json({ error: 'Cannot delete your own account' });
    
    // Get user details before deletion
    const userResult = await pool.query('SELECT username, email, is_admin FROM users WHERE id = $1', [req.params.id]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const deletedUser = userResult.rows[0];
    
    // If deleting an admin, check if there's at least one other enabled admin
    if (deletedUser.is_admin) {
      const adminCount = await pool.query(
        'SELECT COUNT(*) as count FROM users WHERE is_admin = true AND enabled = true AND id != $1',
        [req.params.id]
      );
      
      const activeAdmins = parseInt(adminCount.rows[0].count);
      if (activeAdmins === 0) {
        return res.status(400).json({ 
          error: 'Cannot delete the last admin user',
          message: 'At least one admin user must remain in the system'
        });
      }
    }
    
    await pool.query('DELETE FROM users WHERE id = $1', [req.params.id]);
    
    // Log audit event
    await logAudit({
      user_id: req.user.id,
      username: req.user.username,
      action: 'user_deleted',
      resource_type: 'user',
      resource_id: parseInt(req.params.id),
      resource_name: deletedUser?.username,
      details: { deleted_user_email: deletedUser?.email },
      ip_address: req.ip,
      user_agent: req.get('user-agent')
    });
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Enable/disable user
app.put('/api/users/:id/status', authenticateToken, async (req, res) => {
  try {
    if (!req.user.isAdmin) return res.status(403).json({ error: 'Admin access required' });
    
    const userId = parseInt(req.params.id);
    const { enabled } = req.body;
    
    // Cannot disable your own account
    if (userId === req.user.id) {
      return res.status(400).json({ error: 'Cannot disable your own account' });
    }
    
    // Get user details
    const userResult = await pool.query('SELECT is_admin, username, enabled FROM users WHERE id = $1', [userId]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const targetUser = userResult.rows[0];
    
    // If disabling an admin, check if there's at least one other enabled admin
    if (targetUser.is_admin && enabled === false) {
      const adminCount = await pool.query(
        'SELECT COUNT(*) as count FROM users WHERE is_admin = true AND enabled = true AND id != $1',
        [userId]
      );
      
      const activeAdmins = parseInt(adminCount.rows[0].count);
      if (activeAdmins === 0) {
        return res.status(400).json({ 
          error: 'Cannot disable the last admin user',
          message: 'At least one admin user must remain enabled'
        });
      }
    }
    
    // Add enabled column if it doesn't exist
    await pool.query(`
      DO $$ 
      BEGIN 
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                       WHERE table_name='users' AND column_name='enabled') THEN
          ALTER TABLE users ADD COLUMN enabled BOOLEAN DEFAULT true;
        END IF;
      END $$;
    `);
    
    // Update user status
    await pool.query('UPDATE users SET enabled = $1 WHERE id = $2', [enabled, userId]);
    
    // Log audit event
    await logAudit({
      user_id: req.user.id,
      username: req.user.username,
      action: enabled ? 'user_enabled' : 'user_disabled',
      resource_type: 'user',
      resource_id: userId,
      resource_name: targetUser.username,
      details: { is_admin: targetUser.is_admin },
      ip_address: req.ip,
      user_agent: req.get('user-agent')
    });
    
    res.json({ success: true, enabled });
  } catch (error) {
    console.error('User status update error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/users/:id/password', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { currentPassword, newPassword } = req.body;
    if (parseInt(id) !== req.user.id && !req.user.isAdmin) return res.status(403).json({ error: 'Access denied' });
    if (parseInt(id) === req.user.id) {
      const result = await pool.query('SELECT password_hash FROM users WHERE id = $1', [id]);
      const valid = await bcrypt.compare(currentPassword, result.rows[0].password_hash);
      if (!valid) return res.status(401).json({ error: 'Current password is incorrect' });
    }
    const hash = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hash, id]);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Password reset request
app.post('/api/auth/reset-request', async (req, res) => {
  try {
    const { email } = req.body;
    const result = await pool.query('SELECT id, username, email FROM users WHERE email = $1', [email]);
    
    if (result.rows.length === 0) {
      // Don't reveal if email exists
      return res.json({ message: 'If that email exists, a reset link has been sent' });
    }
    
    const user = result.rows[0];
    const resetToken = crypto.randomBytes(32).toString('hex');
    const expires = new Date(Date.now() + 3600000); // 1 hour
    
    await pool.query(
      'UPDATE users SET reset_token = $1, reset_token_expires = $2 WHERE id = $3',
      [resetToken, expires, user.id]
    );
    
    // Get notification settings
    const settings = await pool.query(
      'SELECT * FROM notification_settings WHERE user_id = $1 AND email_enabled = true',
      [user.id]
    );
    
    if (settings.rows.length > 0) {
      const resetUrl = `${req.headers.origin}/reset-password?token=${resetToken}`;
      await sendEmail(settings.rows[0], {
        subject: 'CloudKlone Password Reset',
        text: `Reset your password: ${resetUrl}\n\nThis link expires in 1 hour.`
      });
    }
    
    res.json({ message: 'If that email exists, a reset link has been sent' });
  } catch (error) {
    console.error('Password reset request error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Password reset confirmation
app.post('/api/auth/reset-confirm', async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    
    const result = await pool.query(
      'SELECT id FROM users WHERE reset_token = $1 AND reset_token_expires > NOW()',
      [token]
    );
    
    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid or expired reset token' });
    }
    
    const hash = await bcrypt.hash(newPassword, 10);
    await pool.query(
      'UPDATE users SET password_hash = $1, reset_token = NULL, reset_token_expires = NULL WHERE id = $2',
      [hash, result.rows[0].id]
    );
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== GROUP ROUTES ====================

app.get('/api/groups', authenticateToken, async (req, res) => {
  try {
    if (!req.user.isAdmin) return res.status(403).json({ error: 'Admin access required' });
    const result = await pool.query('SELECT * FROM groups ORDER BY name');
    res.json({ groups: result.rows });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/groups', authenticateToken, async (req, res) => {
  try {
    if (!req.user.isAdmin) return res.status(403).json({ error: 'Admin access required' });
    const { name, description, permissions } = req.body;
    
    // If permissions provided, use them; otherwise use default operator permissions
    const groupPermissions = permissions || {
      role: 'operator',
      can_create_copy: true,
      can_create_sync: false,
      can_edit_transfers: false,
      can_delete_own_transfers: false,
      can_delete_any_transfers: false,
      can_manage_remotes: false,
      can_manage_settings: false,
      can_manage_users: false
    };
    
    const result = await pool.query(
      'INSERT INTO groups (name, description, permissions) VALUES ($1, $2, $3) RETURNING *',
      [name, description, JSON.stringify(groupPermissions)]
    );
    
    // Log audit event
    await logAudit({
      user_id: req.user.id,
      username: req.user.username,
      action: 'group_created',
      resource_type: 'group',
      resource_id: result.rows[0].id,
      resource_name: name,
      details: { role: groupPermissions.role },
      ip_address: req.ip,
      user_agent: req.get('user-agent')
    });
    
    res.status(201).json({ group: result.rows[0] });
  } catch (error) {
    if (error.code === '23505') return res.status(400).json({ error: 'Group name already exists' });
    console.error('Create group error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/groups/:id', authenticateToken, async (req, res) => {
  try {
    if (!req.user.isAdmin) return res.status(403).json({ error: 'Admin access required' });
    
    // Get group details before deletion
    const groupResult = await pool.query('SELECT name FROM groups WHERE id = $1', [req.params.id]);
    const deletedGroup = groupResult.rows[0];
    
    await pool.query('DELETE FROM groups WHERE id = $1', [req.params.id]);
    
    // Log audit event
    await logAudit({
      user_id: req.user.id,
      username: req.user.username,
      action: 'group_deleted',
      resource_type: 'group',
      resource_id: parseInt(req.params.id),
      resource_name: deletedGroup?.name,
      details: {},
      ip_address: req.ip,
      user_agent: req.get('user-agent')
    });
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== AUDIT LOGS ROUTES ====================

// Get audit logs
app.get('/api/audit-logs', authenticateToken, async (req, res) => {
  try {
    // Check if audit logs are available in this edition
    if (!editionManager.hasAuditLogs()) {
      return res.status(403).json({ 
        error: 'Audit logs are not available in Community edition',
        edition: editionManager.edition,
        upgrade: 'professional'
      });
    }
    
    const { limit = 100, offset = 0, user_id, action, resource_type } = req.query;
    
    let query = 'SELECT * FROM audit_logs WHERE 1=1';
    const params = [];
    let paramIndex = 1;
    
    // Non-admins can only see their own logs (optional: remove this for full transparency)
    // if (!req.user.isAdmin) {
    //   query += ` AND user_id = $${paramIndex++}`;
    //   params.push(req.user.id);
    // }
    
    // Filters
    if (user_id) {
      query += ` AND user_id = $${paramIndex++}`;
      params.push(user_id);
    }
    
    if (action) {
      query += ` AND action = $${paramIndex++}`;
      params.push(action);
    }
    
    if (resource_type) {
      query += ` AND resource_type = $${paramIndex++}`;
      params.push(resource_type);
    }
    
    query += ` ORDER BY timestamp DESC LIMIT $${paramIndex++} OFFSET $${paramIndex++}`;
    params.push(limit, offset);
    
    const result = await pool.query(query, params);
    
    // Get total count
    const countQuery = 'SELECT COUNT(*) FROM audit_logs';
    const countResult = await pool.query(countQuery);
    
    res.json({ 
      logs: result.rows,
      total: parseInt(countResult.rows[0].count)
    });
  } catch (error) {
    console.error('Audit logs error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Export audit logs as CSV
app.get('/api/audit-logs/export', authenticateToken, async (req, res) => {
  try {
    if (!editionManager.hasAuditLogs()) {
      return res.status(403).json({ 
        error: 'Audit logs are not available in Community edition',
        edition: editionManager.edition,
        upgrade: 'professional'
      });
    }
    
    if (!req.user.isAdmin) {
      return res.status(403).json({ error: 'Admin access required' });
    }
    
    const { user_id, action, resource_type, start_date, end_date } = req.query;
    
    let query = 'SELECT * FROM audit_logs WHERE 1=1';
    const params = [];
    let paramIndex = 1;
    
    // Filters
    if (user_id) {
      query += ` AND user_id = $${paramIndex++}`;
      params.push(user_id);
    }
    
    if (action) {
      query += ` AND action = $${paramIndex++}`;
      params.push(action);
    }
    
    if (resource_type) {
      query += ` AND resource_type = $${paramIndex++}`;
      params.push(resource_type);
    }
    
    if (start_date) {
      query += ` AND timestamp >= $${paramIndex++}`;
      params.push(start_date);
    }
    
    if (end_date) {
      query += ` AND timestamp <= $${paramIndex++}`;
      params.push(end_date);
    }
    
    query += ' ORDER BY timestamp DESC';
    
    const result = await pool.query(query, params);
    
    // Convert to CSV
    const csv = convertLogsToCSV(result.rows);
    
    // Set headers for download
    const filename = `audit-logs-${new Date().toISOString().split('T')[0]}.csv`;
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(csv);
    
  } catch (error) {
    console.error('Export logs error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

function convertLogsToCSV(logs) {
  if (logs.length === 0) {
    return 'No logs to export';
  }
  
  // CSV header
  const headers = ['Timestamp', 'User', 'Action', 'Resource Type', 'Resource Name', 'IP Address', 'Details'];
  let csv = headers.join(',') + '\n';
  
  // CSV rows
  logs.forEach(log => {
    const row = [
      `"${new Date(log.timestamp).toISOString()}"`,
      `"${log.username || ''}"`,
      `"${log.action || ''}"`,
      `"${log.resource_type || ''}"`,
      `"${log.resource_name || ''}"`,
      `"${log.ip_address || ''}"`,
      `"${JSON.stringify(log.details || {}).replace(/"/g, '""')}"` // Escape quotes
    ];
    csv += row.join(',') + '\n';
  });
  
  return csv;
}

// Get scheduled log report settings
app.get('/api/admin/log-report-schedule', authenticateToken, async (req, res) => {
  try {
    if (!req.user.isAdmin) {
      return res.status(403).json({ error: 'Admin access required' });
    }
    
    const result = await pool.query(
      "SELECT value FROM system_settings WHERE key = 'log_report_schedule'"
    );
    
    if (result.rows.length === 0) {
      return res.json({ 
        enabled: false,
        frequency: 'weekly',
        day_of_week: 1, // Monday
        time: '08:00',
        email: ''
      });
    }
    
    res.json(JSON.parse(result.rows[0].value));
  } catch (error) {
    console.error('Get log report schedule error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update scheduled log report settings
app.post('/api/admin/log-report-schedule', authenticateToken, async (req, res) => {
  try {
    if (!req.user.isAdmin) {
      return res.status(403).json({ error: 'Admin access required' });
    }
    
    const { enabled, frequency, day_of_week, time, email } = req.body;
    
    const settings = {
      enabled: enabled || false,
      frequency: frequency || 'weekly', // daily, weekly, monthly
      day_of_week: day_of_week || 1, // 0=Sunday, 1=Monday, etc
      time: time || '08:00',
      email: email || ''
    };
    
    await pool.query(
      `INSERT INTO system_settings (key, value, updated_at)
       VALUES ('log_report_schedule', $1, CURRENT_TIMESTAMP)
       ON CONFLICT (key) 
       DO UPDATE SET value = $1, updated_at = CURRENT_TIMESTAMP`,
      [JSON.stringify(settings)]
    );
    
    // Log audit event
    await logAudit({
      user_id: req.user.id,
      username: req.user.username,
      action: 'log_report_schedule_updated',
      resource_type: 'settings',
      details: settings,
      ip_address: req.ip,
      user_agent: req.get('user-agent')
    });
    
    res.json({ success: true, settings });
  } catch (error) {
    console.error('Update log report schedule error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update user's group
app.put('/api/users/:id/group', authenticateToken, async (req, res) => {
  try {
    if (!req.user.isAdmin) return res.status(403).json({ error: 'Admin access required' });
    const { groupId } = req.body;
    await pool.query('UPDATE users SET group_id = $1 WHERE id = $2', [groupId, req.params.id]);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Update user (admin only)
app.put('/api/users/:id', authenticateToken, async (req, res) => {
  try {
    if (!req.user.isAdmin) return res.status(403).json({ error: 'Admin access required' });
    
    const { email, groupId, isAdmin, password } = req.body;
    const userId = req.params.id;
    
    console.log('Update user request:', { userId, email, groupId, isAdmin, hasPassword: !!password });
    
    // Build update query dynamically
    const updates = [];
    const values = [];
    let paramIndex = 1;
    
    if (email !== undefined) {
      updates.push(`email = $${paramIndex++}`);
      values.push(email);
    }
    
    if (groupId !== undefined) {
      updates.push(`group_id = $${paramIndex++}`);
      values.push(groupId);
    }
    
    if (isAdmin !== undefined) {
      updates.push(`is_admin = $${paramIndex++}`);
      values.push(isAdmin);
    }
    
    if (password) {
      const hashedPassword = await bcrypt.hash(password, 10);
      updates.push(`password_hash = $${paramIndex++}`);
      values.push(hashedPassword);
    }
    
    if (updates.length === 0) {
      console.log('No updates provided');
      return res.status(400).json({ error: 'No updates provided' });
    }
    
    values.push(userId);
    const query = `UPDATE users SET ${updates.join(', ')} WHERE id = $${paramIndex} RETURNING id, username, email, is_admin, group_id`;
    
    console.log('Executing query:', query);
    console.log('With values:', values);
    
    const result = await pool.query(query, values);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Log audit event
    await logAudit({
      user_id: req.user.id,
      username: req.user.username,
      action: 'user_updated',
      resource_type: 'user',
      resource_id: parseInt(userId),
      resource_name: result.rows[0].username,
      details: {
        email_changed: email !== undefined,
        group_changed: groupId !== undefined,
        admin_status_changed: isAdmin !== undefined,
        password_changed: !!password
      },
      ip_address: req.ip,
      user_agent: req.get('user-agent')
    });
    
    console.log('User updated successfully:', result.rows[0]);
    res.json({ user: result.rows[0] });
  } catch (error) {
    console.error('Update user error:', error);
    console.error('Error stack:', error.stack);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// ==================== REMOTE ROUTES ====================

app.get('/api/remotes', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, name, type, config, created_at FROM remotes WHERE user_id = $1 ORDER BY created_at DESC',
      [req.user.id]
    );
    res.json({ remotes: result.rows });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/remotes', authenticateToken, requirePermission('can_manage_remotes'), async (req, res) => {
  try {
    const { name, type, config } = req.body;
    if (!name || !type || !config) return res.status(400).json({ error: 'Missing required fields' });
    
    // Add SFTP-specific config and obscure password
    let sshHostKey = null;
    if (type === 'sftp') {
      config.skip_links = 'true';
      config.set_modtime = 'false';
      config.key_use_agent = 'false';
      
      // Scan SSH host key
      try {
        const host = config.host;
        const port = config.port || 22;
        console.log(`Scanning SSH host key for ${host}:${port}...`);
        sshHostKey = await scanSSHHostKey(host, port);
        console.log(`[OK] SSH host key obtained for ${host}`);
      } catch (err) {
        console.error('Failed to scan SSH host key:', err);
        return res.status(400).json({ 
          error: `Failed to scan SSH host key: ${err.message}. Please check the hostname and port are correct.` 
        });
      }
      
      // Obscure the password using rclone obscure
      if (config.pass) {
        try {
          config.pass = await obscurePassword(config.pass);
        } catch (err) {
          console.error('Failed to obscure SFTP password:', err);
          return res.status(500).json({ error: 'Failed to encrypt password' });
        }
      }
    }
    
    // Add SMB-specific config and obscure password
    if (type === 'smb') {
      // Obscure the password using rclone obscure
      if (config.pass) {
        try {
          config.pass = await obscurePassword(config.pass);
        } catch (err) {
          console.error('Failed to obscure SMB password:', err);
          return res.status(500).json({ error: 'Failed to encrypt password' });
        }
      }
    }
    
    // Validate endpoint for S3-compatible services
    if (type === 's3' && config.endpoint) {
      try {
        new URL(config.endpoint);
      } catch (e) {
        return res.status(400).json({ error: 'Invalid endpoint URL format' });
      }
    }
    
    // Extract test_bucket for R2 (used for testing only, not saved)
    const testBucket = config.test_bucket || '';
    delete config.test_bucket; // Remove from config before saving
    
    // Encrypt sensitive fields in config
    const encryptedConfig = encrypt(JSON.stringify(config));
    
    // Create temporary rclone config to test
    const tempConfigPath = `/tmp/rclone_test_${Date.now()}.conf`;
    let configContent = `[${name}]\ntype = ${type}\n`;
    for (const [key, value] of Object.entries(config)) {
      configContent += `${key} = ${value}\n`;
    }
    await fs.writeFile(tempConfigPath, configContent);
    
    // Build test args - use bucket if provided for R2
    let testPath = `${name}:`;
    if (testBucket && config.endpoint && config.endpoint.includes('r2.cloudflarestorage.com')) {
      testPath = `${name}:${testBucket}`;
    }
    
    const testArgs = ['lsd', testPath, '--config', tempConfigPath, '--max-depth', '1'];
    if (type === 'sftp') {
      testArgs.push('--sftp-skip-links');
    }
    
    // Test the remote connection
    const testResult = await new Promise((resolve) => {
      const rclone = spawn('rclone', testArgs);
      let output = '';
      let errorOutput = '';
      
      rclone.stdout.on('data', (data) => { output += data.toString(); });
      rclone.stderr.on('data', (data) => { errorOutput += data.toString(); });
      
      rclone.on('close', (code) => {
        fs.unlink(tempConfigPath).catch(() => {});
        
        let endpointInfo = '';
        if (code === 0) {
          const lines = output.split('\n').filter(l => l.trim());
          
          // Different message for bucket-specific test
          if (testBucket) {
            endpointInfo = `[SUCCESS] Connected successfully to bucket '${testBucket}'. Found ${lines.length} items.`;
          } else {
            endpointInfo = `[SUCCESS] Connected successfully. Found ${lines.length} items at root.`;
          }
          
          // Detect endpoint/region info
          if (type === 's3') {
            if (config.endpoint && config.endpoint.includes('r2.cloudflarestorage.com')) {
              endpointInfo += ' (Cloudflare R2)';
            } else if (config.endpoint && config.endpoint.includes('s3.wasabisys.com')) {
              endpointInfo += ' (Wasabi)';
            } else if (config.region) {
              endpointInfo += ` (Region: ${config.region})`;
            }
          } else if (type === 'sftp') {
            endpointInfo += ` (${config.host})`;
          }
        }
        
        resolve({ success: code === 0, error: errorOutput, endpointInfo });
      });
      
      setTimeout(() => {
        rclone.kill();
        fs.unlink(tempConfigPath).catch(() => {});
        resolve({ success: false, error: 'Connection timeout (15s)' });
      }, 15000);
    });
    
    if (!testResult.success) {
      return res.status(400).json({ 
        error: 'Remote connection failed. Please check your credentials and endpoint.', 
        details: testResult.error 
      });
    }
    
    const result = await pool.query(
      'INSERT INTO remotes (user_id, name, type, config, encrypted_config, ssh_host_key) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
      [req.user.id, name, type, config, encryptedConfig, sshHostKey]
    );
    await updateRcloneConfig(req.user.id);
    
    // Log audit event
    await logAudit({
      user_id: req.user.id,
      username: req.user.username,
      action: 'remote_created',
      resource_type: 'remote',
      resource_id: result.rows[0].id,
      resource_name: name,
      details: { type },
      ip_address: req.ip,
      user_agent: req.get('user-agent')
    });
    
    res.status(201).json({ 
      remote: result.rows[0],
      message: testResult.endpointInfo 
    });
  } catch (error) {
    if (error.code === '23505') return res.status(400).json({ error: 'Remote name already exists' });
    console.error('Create remote error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/remotes/:id', authenticateToken, requirePermission('can_manage_remotes'), async (req, res) => {
  try {
    const { name, type, config } = req.body;
    const result = await pool.query(
      'UPDATE remotes SET name = $1, type = $2, config = $3 WHERE id = $4 AND user_id = $5 RETURNING *',
      [name, type, config, req.params.id, req.user.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Remote not found' });
    await updateRcloneConfig(req.user.id);
    
    // Log audit event
    await logAudit({
      user_id: req.user.id,
      username: req.user.username,
      action: 'remote_updated',
      resource_type: 'remote',
      resource_id: parseInt(req.params.id),
      resource_name: name,
      details: { type },
      ip_address: req.ip,
      user_agent: req.get('user-agent')
    });
    
    res.json({ remote: result.rows[0] });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/remotes/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    // Get remote name before deleting
    const remote = await pool.query('SELECT name FROM remotes WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]);
    
    await pool.query('DELETE FROM remotes WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]);
    await updateRcloneConfig(req.user.id);
    
    // Log audit event
    if (remote.rows.length > 0) {
      await logAudit({
        user_id: req.user.id,
        username: req.user.username,
        action: 'remote_deleted',
        resource_type: 'remote',
        resource_id: parseInt(req.params.id),
        resource_name: remote.rows[0].name,
        details: {},
        ip_address: req.ip,
        user_agent: req.get('user-agent')
      });
    }
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/remotes/:id/test', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT name, type, config FROM remotes WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Remote not found' });
    
    const remote = result.rows[0];
    const remoteName = remote.name;
    const configFile = `/root/.config/rclone/user_${req.user.id}.conf`;
    
    // Build test args
    const testArgs = ['lsd', `${remoteName}:`, '--config', configFile, '--max-depth', '1'];
    
    // Add S3-specific flags for R2 (no bucket check)
    const isR2 = remote.type === 's3' && remote.config.endpoint && remote.config.endpoint.includes('r2.cloudflarestorage.com');
    if (isR2) {
      testArgs.push('--s3-no-check-bucket');
    }
    
    // Add SFTP-specific flags
    if (remote.type === 'sftp') {
      testArgs.push('--sftp-skip-links');
    }
    
    const rclone = spawn('rclone', testArgs);
    let output = '';
    let errorOutput = '';
    
    rclone.stdout.on('data', (data) => { output += data.toString(); });
    rclone.stderr.on('data', (data) => { errorOutput += data.toString(); });
    
    rclone.on('close', (code) => {
      if (code === 0) {
        const lines = output.split('\n').filter(l => l.trim());
        let message = `[SUCCESS] Connection successful. Found ${lines.length} items.`;
        
        // Add provider-specific info
        if (isR2) {
          message += ' (Cloudflare R2)';
        } else if (remote.type === 'sftp') {
          message += ` (${remote.config.host})`;
        }
        
        res.json({ success: true, message });
      } else {
        // For R2 bucket-specific tokens, provide helpful error
        if (isR2 && errorOutput.includes('AccessDenied')) {
          res.status(400).json({ 
            success: false, 
            error: 'Cannot list all buckets with this token. This is expected with bucket-specific tokens. Your remote will still work for transfers - just specify the bucket name in paths (e.g., remote:bucket-name/path).' 
          });
        } else {
          res.status(400).json({ success: false, error: errorOutput || 'Connection failed' });
        }
      }
    });
    
    // Timeout after 15 seconds
    setTimeout(() => {
      rclone.kill();
      res.status(408).json({ success: false, error: 'Connection timeout (15s)' });
    }, 15000);
    
  } catch (error) {
    console.error('Test remote error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== SSH HOST KEYS MANAGEMENT ====================

// Get all SSH host keys (admin only)

// System Settings (Admin only)
app.get('/api/system/settings', authenticateToken, async (req, res) => {
  try {
    if (!req.user.isAdmin) {
      return res.status(403).json({ error: 'Admin access required' });
    }
    
    const result = await pool.query('SELECT * FROM system_settings');
    const settings = {};
    result.rows.forEach(row => {
      settings[row.setting_key] = row.setting_value;
    });
    
    res.json({ settings });
  } catch (error) {
    console.error('Get system settings error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/system/settings', authenticateToken, async (req, res) => {
  try {
    if (!req.user.isAdmin) {
      return res.status(403).json({ error: 'Admin access required' });
    }
    
    const { timezone } = req.body;
    
    if (timezone) {
      await pool.query(`
        INSERT INTO system_settings (setting_key, setting_value, updated_at)
        VALUES ('timezone', $1, CURRENT_TIMESTAMP)
        ON CONFLICT (setting_key) 
        DO UPDATE SET setting_value = $1, updated_at = CURRENT_TIMESTAMP
      `, [timezone]);
    }
    
    // Log audit event
    await logAudit({
      user_id: req.user.id,
      username: req.user.username,
      action: 'system_settings_updated',
      resource_type: 'settings',
      resource_id: null,
      resource_name: 'System Settings',
      details: { timezone },
      ip_address: req.ip,
      user_agent: req.get('user-agent')
    });
    
    res.json({ success: true });
  } catch (error) {
    console.error('Save system settings error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/admin/ssh-host-keys', authenticateToken, async (req, res) => {
  try {
    if (!req.user.isAdmin) {
      return res.status(403).json({ error: 'Admin access required' });
    }
    
    const result = await pool.query(`
      SELECT r.id, r.name, r.type, r.ssh_host_key, r.created_at, 
             u.username as owner, r.config->>'host' as host, r.config->>'port' as port, r.config->>'user' as username
      FROM remotes r
      JOIN users u ON r.user_id = u.id
      WHERE r.type = 'sftp' AND r.ssh_host_key IS NOT NULL
      ORDER BY r.created_at DESC
    `);
    
    console.log(`[INFO] Found ${result.rows.length} SFTP remotes with host keys`);
    res.json({ hostKeys: result.rows });
  } catch (error) {
    console.error('Get SSH host keys error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Rescan SSH host key for a specific remote (admin only)
app.post('/api/admin/ssh-host-keys/:id/rescan', authenticateToken, async (req, res) => {
  try {
    if (!req.user.isAdmin) {
      return res.status(403).json({ error: 'Admin access required' });
    }
    
    // Get remote details
    const remoteResult = await pool.query(
      'SELECT * FROM remotes WHERE id = $1 AND type = $2',
      [req.params.id, 'sftp']
    );
    
    if (remoteResult.rows.length === 0) {
      return res.status(404).json({ error: 'SFTP remote not found' });
    }
    
    const remote = remoteResult.rows[0];
    const host = remote.config.host;
    const port = remote.config.port || 22;
    
    // Scan new host key
    let newHostKey;
    try {
      newHostKey = await scanSSHHostKey(host, port);
    } catch (err) {
      return res.status(400).json({ error: `Failed to scan host key: ${err.message}` });
    }
    
    // Update in database
    await pool.query(
      'UPDATE remotes SET ssh_host_key = $1 WHERE id = $2',
      [newHostKey, req.params.id]
    );
    
    // Update rclone config
    await updateRcloneConfig(remote.user_id);
    
    // Log audit event
    await logAudit({
      user_id: req.user.id,
      username: req.user.username,
      action: 'ssh_host_key_rescanned',
      resource_type: 'remote',
      resource_id: remote.id,
      resource_name: remote.name,
      details: { host, port },
      ip_address: req.ip,
      user_agent: req.get('user-agent')
    });
    
    res.json({ success: true, hostKey: newHostKey });
  } catch (error) {
    console.error('Rescan SSH host key error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Clear/delete SSH host key for a specific remote (admin only)
app.delete('/api/admin/ssh-host-keys/:id', authenticateToken, async (req, res) => {
  try {
    if (!req.user.isAdmin) {
      return res.status(403).json({ error: 'Admin access required' });
    }
    
    // Get remote details
    const remoteResult = await pool.query(
      'SELECT * FROM remotes WHERE id = $1 AND type = $2',
      [req.params.id, 'sftp']
    );
    
    if (remoteResult.rows.length === 0) {
      return res.status(404).json({ error: 'SFTP remote not found' });
    }
    
    const remote = remoteResult.rows[0];
    
    // Clear host key
    await pool.query(
      'UPDATE remotes SET ssh_host_key = NULL WHERE id = $1',
      [req.params.id]
    );
    
    // Update rclone config
    await updateRcloneConfig(remote.user_id);
    
    // Log audit event
    await logAudit({
      user_id: req.user.id,
      username: req.user.username,
      action: 'ssh_host_key_cleared',
      resource_type: 'remote',
      resource_id: remote.id,
      resource_name: remote.name,
      details: { host: remote.config.host },
      ip_address: req.ip,
      user_agent: req.get('user-agent')
    });
    
    res.json({ success: true });
  } catch (error) {
    console.error('Clear SSH host key error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Admin Shell endpoint
app.post('/api/admin/shell', authenticateToken, async (req, res) => {
  try {
    if (!req.user.isAdmin) {
      return res.status(403).json({ error: 'Admin access required' });
    }
    
    const { command } = req.body;
    
    if (!command || typeof command !== 'string') {
      return res.status(400).json({ error: 'Command is required' });
    }
    
    // Security: Only allow rclone commands
    const trimmedCommand = command.trim();
    if (!trimmedCommand.startsWith('rclone ')) {
      return res.status(403).json({ error: 'Only rclone commands are allowed. Example: rclone version' });
    }
    
    // Parse command and args
    const parts = trimmedCommand.split(/\s+/);
    const cmd = parts[0]; // 'rclone'
    const args = parts.slice(1);
    
    // Add user's config file if not already specified
    const configFile = `/root/.config/rclone/user_${req.user.id}.conf`;
    if (!args.includes('--config')) {
      args.push('--config', configFile);
    }
    
    console.log(`[SHELL] User ${req.user.username} executing: rclone ${args.join(' ')}`);
    
    // Execute command
    const result = await new Promise((resolve) => {
      const proc = spawn('rclone', args);
      let stdout = '';
      let stderr = '';
      
      proc.stdout.on('data', (data) => {
        stdout += data.toString();
      });
      
      proc.stderr.on('data', (data) => {
        stderr += data.toString();
      });
      
      proc.on('close', (code) => {
        resolve({
          stdout,
          stderr,
          exit_code: code
        });
      });
      
      // Timeout after 60 seconds
      setTimeout(() => {
        proc.kill('SIGTERM');
        resolve({
          stdout,
          stderr: stderr + '\n[TIMEOUT] Command terminated after 60 seconds',
          exit_code: -1
        });
      }, 60000);
    });
    
    // Log to audit trail
    await logAudit({
      user_id: req.user.id,
      username: req.user.username,
      action: 'shell_command_executed',
      resource_type: 'system',
      resource_id: null,
      resource_name: 'admin_shell',
      details: { command: trimmedCommand, exit_code: result.exit_code },
      ip_address: req.ip,
      user_agent: req.get('user-agent')
    });
    
    // Return output
    const output = result.stdout + result.stderr;
    res.json({
      output: output || '(no output)',
      exit_code: result.exit_code
    });
    
  } catch (error) {
    console.error('Shell command error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});


// ==================== ENTERPRISE V7: BRANDING & COMPLIANCE ====================

// Get branding settings
app.get('/api/enterprise/branding', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM branding_settings LIMIT 1');
    const branding = result.rows[0] || {
      company_name: 'CloudKlone',
      primary_color: '#1a73e8',
      secondary_color: '#34a853',
      accent_color: '#ff6b00'
    };
    res.json(branding);
  } catch (error) {
    console.error('Get branding error:', error);
    res.status(500).json({ error: 'Failed to get branding settings' });
  }
});

// Update branding settings (Admin only)
app.put('/api/enterprise/branding', authenticateToken, async (req, res) => {
  try {
    if (!req.user.isAdmin) {
      return res.status(403).json({ error: 'Admin access required' });
    }
    
    const {
      company_name,
      logo_url,
      favicon_url,
      primary_color,
      secondary_color,
      accent_color,
      login_background_url,
      custom_css,
      footer_text,
      support_email,
      support_url
    } = req.body;
    
    // Check if branding exists
    const check = await pool.query('SELECT id FROM branding_settings LIMIT 1');
    
    if (check.rows.length === 0) {
      // Insert new
      await pool.query(`
        INSERT INTO branding_settings (
          company_name, logo_url, favicon_url, primary_color, secondary_color,
          accent_color, login_background_url, custom_css, footer_text,
          support_email, support_url, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, CURRENT_TIMESTAMP)
      `, [company_name, logo_url, favicon_url, primary_color, secondary_color, 
          accent_color, login_background_url, custom_css, footer_text,
          support_email, support_url]);
    } else {
      // Update existing
      await pool.query(`
        UPDATE branding_settings SET
          company_name = COALESCE($1, company_name),
          logo_url = COALESCE($2, logo_url),
          favicon_url = COALESCE($3, favicon_url),
          primary_color = COALESCE($4, primary_color),
          secondary_color = COALESCE($5, secondary_color),
          accent_color = COALESCE($6, accent_color),
          login_background_url = COALESCE($7, login_background_url),
          custom_css = COALESCE($8, custom_css),
          footer_text = COALESCE($9, footer_text),
          support_email = COALESCE($10, support_email),
          support_url = COALESCE($11, support_url),
          updated_at = CURRENT_TIMESTAMP
        WHERE id = $12
      `, [company_name, logo_url, favicon_url, primary_color, secondary_color,
          accent_color, login_background_url, custom_css, footer_text,
          support_email, support_url, check.rows[0].id]);
    }
    
    // Log the change
    await logAudit({
      user_id: req.user.id,
      username: req.user.username,
      action: 'branding_updated',
      resource_type: 'settings',
      resource_name: 'branding',
      details: { company_name, updated_fields: Object.keys(req.body) },
      ip_address: req.ip
    });
    
    res.json({ success: true, message: 'Branding updated successfully' });
  } catch (error) {
    console.error('Update branding error:', error);
    res.status(500).json({ error: 'Failed to update branding settings' });
  }
});

// Get compliance settings
app.get('/api/enterprise/compliance/settings', authenticateToken, async (req, res) => {
  try {
    if (!req.user.isAdmin) {
      return res.status(403).json({ error: 'Admin access required' });
    }
    
    const result = await pool.query('SELECT * FROM compliance_settings LIMIT 1');
    const settings = result.rows[0] || {
      data_retention_days: 90,
      log_retention_days: 365,
      auto_delete_enabled: false,
      gdpr_enabled: true,
      soc2_enabled: true
    };
    res.json(settings);
  } catch (error) {
    console.error('Get compliance settings error:', error);
    res.status(500).json({ error: 'Failed to get compliance settings' });
  }
});

// Update compliance settings
app.put('/api/enterprise/compliance/settings', authenticateToken, async (req, res) => {
  try {
    if (!req.user.isAdmin) {
      return res.status(403).json({ error: 'Admin access required' });
    }
    
    const {
      data_retention_days,
      log_retention_days,
      auto_delete_enabled,
      gdpr_enabled,
      soc2_enabled,
      cookie_consent_enabled,
      privacy_policy_url,
      terms_url,
      dpo_name,
      dpo_email
    } = req.body;
    
    // Check if settings exist
    const check = await pool.query('SELECT id FROM compliance_settings LIMIT 1');
    
    if (check.rows.length === 0) {
      // Insert new
      await pool.query(`
        INSERT INTO compliance_settings (
          data_retention_days, log_retention_days, auto_delete_enabled,
          gdpr_enabled, soc2_enabled, cookie_consent_enabled,
          privacy_policy_url, terms_url, dpo_name, dpo_email, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, CURRENT_TIMESTAMP)
      `, [data_retention_days, log_retention_days, auto_delete_enabled,
          gdpr_enabled, soc2_enabled, cookie_consent_enabled,
          privacy_policy_url, terms_url, dpo_name, dpo_email]);
    } else {
      // Update existing
      await pool.query(`
        UPDATE compliance_settings SET
          data_retention_days = COALESCE($1, data_retention_days),
          log_retention_days = COALESCE($2, log_retention_days),
          auto_delete_enabled = COALESCE($3, auto_delete_enabled),
          gdpr_enabled = COALESCE($4, gdpr_enabled),
          soc2_enabled = COALESCE($5, soc2_enabled),
          cookie_consent_enabled = COALESCE($6, cookie_consent_enabled),
          privacy_policy_url = COALESCE($7, privacy_policy_url),
          terms_url = COALESCE($8, terms_url),
          dpo_name = COALESCE($9, dpo_name),
          dpo_email = COALESCE($10, dpo_email),
          updated_at = CURRENT_TIMESTAMP
        WHERE id = $11
      `, [data_retention_days, log_retention_days, auto_delete_enabled,
          gdpr_enabled, soc2_enabled, cookie_consent_enabled,
          privacy_policy_url, terms_url, dpo_name, dpo_email, check.rows[0].id]);
    }
    
    // Log compliance event
    await pool.query(`
      INSERT INTO compliance_events (event_type, event_category, user_id, details, ip_address)
      VALUES ($1, $2, $3, $4, $5)
    `, ['compliance_settings_updated', 'policy_change', req.user.id, 
        JSON.stringify({ updated_fields: Object.keys(req.body) }), req.ip]);
    
    res.json({ success: true, message: 'Compliance settings updated successfully' });
  } catch (error) {
    console.error('Update compliance settings error:', error);
    res.status(500).json({ error: 'Failed to update compliance settings' });
  }
});

// Get compliance dashboard data
app.get('/api/enterprise/compliance/dashboard', authenticateToken, async (req, res) => {
  try {
    if (!req.user.isAdmin) {
      return res.status(403).json({ error: 'Admin access required' });
    }
    
    // Get settings
    const settingsResult = await pool.query('SELECT * FROM compliance_settings LIMIT 1');
    const settings = settingsResult.rows[0];
    
    // Get stats
    const userCount = await pool.query('SELECT COUNT(*) as count FROM users');
    const transferCount = await pool.query('SELECT COUNT(*) as count FROM transfers');
    const logCount = await pool.query('SELECT COUNT(*) as count FROM audit_logs');
    
    // Get pending GDPR requests
    const pendingRequests = await pool.query(`
      SELECT COUNT(*) as count FROM gdpr_requests 
      WHERE status = 'pending'
    `);
    
    // Get recent compliance events
    const recentEvents = await pool.query(`
      SELECT ce.*, u.username 
      FROM compliance_events ce
      LEFT JOIN users u ON ce.user_id = u.id
      ORDER BY ce.created_at DESC
      LIMIT 10
    `);
    
    // Calculate data age stats
    const oldTransfers = await pool.query(`
      SELECT COUNT(*) as count FROM transfers 
      WHERE created_at < NOW() - INTERVAL '${settings?.data_retention_days || 90} days'
    `);
    
    const oldLogs = await pool.query(`
      SELECT COUNT(*) as count FROM audit_logs 
      WHERE timestamp < NOW() - INTERVAL '${settings?.log_retention_days || 365} days'
    `);
    
    res.json({
      settings,
      stats: {
        total_users: parseInt(userCount.rows[0].count),
        total_transfers: parseInt(transferCount.rows[0].count),
        total_logs: parseInt(logCount.rows[0].count),
        pending_gdpr_requests: parseInt(pendingRequests.rows[0].count),
        old_transfers: parseInt(oldTransfers.rows[0].count),
        old_logs: parseInt(oldLogs.rows[0].count)
      },
      recent_events: recentEvents.rows
    });
  } catch (error) {
    console.error('Get compliance dashboard error:', error);
    res.status(500).json({ error: 'Failed to get compliance dashboard data' });
  }
});

// Request GDPR data export
app.post('/api/enterprise/compliance/gdpr/export', authenticateToken, async (req, res) => {
  try {
    // Create GDPR export request
    await pool.query(`
      INSERT INTO gdpr_requests (user_id, request_type, status, requester_ip)
      VALUES ($1, 'export', 'pending', $2)
    `, [req.user.id, req.ip]);
    
    // Log compliance event
    await pool.query(`
      INSERT INTO compliance_events (event_type, event_category, user_id, details, ip_address)
      VALUES ($1, $2, $3, $4, $5)
    `, ['gdpr_export_requested', 'data_export', req.user.id, 
        JSON.stringify({ request_type: 'export' }), req.ip]);
    
    res.json({ 
      success: true, 
      message: 'Data export request submitted. You will be notified when ready.' 
    });
  } catch (error) {
    console.error('GDPR export request error:', error);
    res.status(500).json({ error: 'Failed to submit export request' });
  }
});

// Request GDPR data deletion (Right to be forgotten)
app.post('/api/enterprise/compliance/gdpr/delete', authenticateToken, async (req, res) => {
  try {
    // Create GDPR deletion request
    await pool.query(`
      INSERT INTO gdpr_requests (user_id, request_type, status, requester_ip, notes)
      VALUES ($1, 'deletion', 'pending', $2, $3)
    `, [req.user.id, req.ip, req.body.reason || 'User requested account deletion']);
    
    // Log compliance event
    await pool.query(`
      INSERT INTO compliance_events (event_type, event_category, user_id, details, ip_address)
      VALUES ($1, $2, $3, $4, $5)
    `, ['gdpr_deletion_requested', 'data_deletion', req.user.id, 
        JSON.stringify({ request_type: 'deletion', reason: req.body.reason }), req.ip]);
    
    res.json({ 
      success: true, 
      message: 'Deletion request submitted. An administrator will review your request.' 
    });
  } catch (error) {
    console.error('GDPR deletion request error:', error);
    res.status(500).json({ error: 'Failed to submit deletion request' });
  }
});

// Get GDPR requests (Admin)
app.get('/api/enterprise/compliance/gdpr/requests', authenticateToken, async (req, res) => {
  try {
    if (!req.user.isAdmin) {
      return res.status(403).json({ error: 'Admin access required' });
    }
    
    const result = await pool.query(`
      SELECT gr.*, u.username, u.email
      FROM gdpr_requests gr
      JOIN users u ON gr.user_id = u.id
      ORDER BY gr.requested_at DESC
    `);
    
    res.json({ requests: result.rows });
  } catch (error) {
    console.error('Get GDPR requests error:', error);
    res.status(500).json({ error: 'Failed to get GDPR requests' });
  }
});

// Process GDPR export request (Admin)
app.post('/api/enterprise/compliance/gdpr/requests/:id/process', authenticateToken, async (req, res) => {
  try {
    if (!req.user.isAdmin) {
      return res.status(403).json({ error: 'Admin access required' });
    }
    
    const requestId = req.params.id;
    
    // Get request details
    const requestResult = await pool.query(`
      SELECT gr.*, u.username, u.email
      FROM gdpr_requests gr
      JOIN users u ON gr.user_id = u.id
      WHERE gr.id = $1
    `, [requestId]);
    
    if (requestResult.rows.length === 0) {
      return res.status(404).json({ error: 'Request not found' });
    }
    
    const request = requestResult.rows[0];
    
    if (request.request_type === 'export') {
      // Update status to processing
      await pool.query(`
        UPDATE gdpr_requests 
        SET status = 'processing'
        WHERE id = $1
      `, [requestId]);
      
      // Gather user data
      const userData = {
        user: {
          id: request.user_id,
          username: request.username,
          email: request.email
        },
        transfers: [],
        remotes: [],
        audit_logs: []
      };
      
      // Get user's transfers
      const transfers = await pool.query(`
        SELECT * FROM transfers WHERE created_by = $1
      `, [request.user_id]);
      userData.transfers = transfers.rows;
      
      // Get user's remotes
      const remotes = await pool.query(`
        SELECT id, name, type, created_at FROM remotes WHERE user_id = $1
      `, [request.user_id]);
      userData.remotes = remotes.rows;
      
      // Get user's audit logs
      const logs = await pool.query(`
        SELECT * FROM audit_logs WHERE user_id = $1
      `, [request.user_id]);
      userData.audit_logs = logs.rows;
      
      // Save to file
      const exportPath = `/tmp/gdpr_export_${request.user_id}_${Date.now()}.json`;
      await fs.writeFile(exportPath, JSON.stringify(userData, null, 2));
      
      // Update request as completed
      await pool.query(`
        UPDATE gdpr_requests 
        SET status = 'completed', completed_at = CURRENT_TIMESTAMP, export_file_path = $2
        WHERE id = $1
      `, [requestId, exportPath]);
      
      // Log event
      await pool.query(`
        INSERT INTO compliance_events (event_type, event_category, user_id, details, ip_address)
        VALUES ($1, $2, $3, $4, $5)
      `, ['gdpr_export_completed', 'data_export', request.user_id, 
          JSON.stringify({ request_id: requestId, admin_id: req.user.id }), req.ip]);
      
      res.json({ success: true, message: 'Export completed', export_path: exportPath });
      
    } else if (request.request_type === 'deletion') {
      // Update status to processing
      await pool.query(`
        UPDATE gdpr_requests 
        SET status = 'processing'
        WHERE id = $1
      `, [requestId]);
      
      // Delete user data
      await pool.query('DELETE FROM transfers WHERE created_by = $1', [request.user_id]);
      await pool.query('DELETE FROM remotes WHERE user_id = $1', [request.user_id]);
      await pool.query('DELETE FROM audit_logs WHERE user_id = $1', [request.user_id]);
      await pool.query('DELETE FROM users WHERE id = $1', [request.user_id]);
      
      // Mark request as completed
      await pool.query(`
        UPDATE gdpr_requests 
        SET status = 'completed', completed_at = CURRENT_TIMESTAMP
        WHERE id = $1
      `, [requestId]);
      
      // Log event (with NULL user_id since user is deleted)
      await pool.query(`
        INSERT INTO compliance_events (event_type, event_category, user_id, details, ip_address)
        VALUES ($1, $2, $3, $4, $5)
      `, ['gdpr_deletion_completed', 'data_deletion', null, 
          JSON.stringify({ request_id: requestId, deleted_user_id: request.user_id, admin_id: req.user.id }), req.ip]);
      
      res.json({ success: true, message: 'User data deleted successfully' });
    }
  } catch (error) {
    console.error('Process GDPR request error:', error);
    res.status(500).json({ error: 'Failed to process GDPR request' });
  }
});

// Generate compliance report (SOC 2 / GDPR)
app.get('/api/enterprise/compliance/report', authenticateToken, async (req, res) => {
  try {
    if (!req.user.isAdmin) {
      return res.status(403).json({ error: 'Admin access required' });
    }
    
    const reportType = req.query.type || 'full'; // 'full', 'soc2', 'gdpr'
    const format = req.query.format || 'json'; // 'json' or 'csv'
    
    // Get compliance settings
    const settingsResult = await pool.query('SELECT * FROM compliance_settings LIMIT 1');
    const settings = settingsResult.rows[0];
    
    // Get data processing records
    const dprResult = await pool.query('SELECT * FROM data_processing_records');
    
    // Get compliance events
    const eventsResult = await pool.query(`
      SELECT ce.*, u.username
      FROM compliance_events ce
      LEFT JOIN users u ON ce.user_id = u.id
      ORDER BY ce.created_at DESC
      LIMIT 1000
    `);
    
    // Get GDPR requests
    const gdprResult = await pool.query(`
      SELECT gr.*, u.username, u.email
      FROM gdpr_requests gr
      LEFT JOIN users u ON gr.user_id = u.id
      ORDER BY gr.requested_at DESC
    `);
    
    // Get audit log stats
    const logStats = await pool.query(`
      SELECT 
        COUNT(*) as total_logs,
        COUNT(DISTINCT user_id) as unique_users,
        MIN(timestamp) as oldest_log,
        MAX(timestamp) as newest_log
      FROM audit_logs
    `);
    
    const report = {
      generated_at: new Date().toISOString(),
      report_type: reportType,
      compliance_settings: settings,
      data_processing_records: dprResult.rows,
      compliance_events: eventsResult.rows,
      gdpr_requests: gdprResult.rows,
      audit_log_stats: logStats.rows[0],
      summary: {
        total_users: 0,
        total_transfers: 0,
        total_remotes: 0,
        gdpr_export_requests: gdprResult.rows.filter(r => r.request_type === 'export').length,
        gdpr_deletion_requests: gdprResult.rows.filter(r => r.request_type === 'deletion').length,
        pending_requests: gdprResult.rows.filter(r => r.status === 'pending').length
      }
    };
    
    // Get user/transfer/remote counts
    const userCount = await pool.query('SELECT COUNT(*) as count FROM users');
    const transferCount = await pool.query('SELECT COUNT(*) as count FROM transfers');
    const remoteCount = await pool.query('SELECT COUNT(*) as count FROM remotes');
    
    report.summary.total_users = parseInt(userCount.rows[0].count);
    report.summary.total_transfers = parseInt(transferCount.rows[0].count);
    report.summary.total_remotes = parseInt(remoteCount.rows[0].count);
    
    if (format === 'json') {
      res.json(report);
    } else if (format === 'csv') {
      // Convert to CSV format
      let csv = 'Compliance Report - Generated ' + new Date().toISOString() + '\n\n';
      
      csv += 'SUMMARY\n';
      csv += 'Total Users,' + report.summary.total_users + '\n';
      csv += 'Total Transfers,' + report.summary.total_transfers + '\n';
      csv += 'GDPR Export Requests,' + report.summary.gdpr_export_requests + '\n';
      csv += 'GDPR Deletion Requests,' + report.summary.gdpr_deletion_requests + '\n';
      csv += 'Pending Requests,' + report.summary.pending_requests + '\n\n';
      
      csv += 'COMPLIANCE EVENTS\n';
      csv += 'Timestamp,Event Type,Category,Username,Details\n';
      report.compliance_events.forEach(event => {
        csv += `"${event.created_at}","${event.event_type}","${event.event_category}","${event.username || ''}","${JSON.stringify(event.details || {})}"\n`;
      });
      
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename="compliance-report-${Date.now()}.csv"`);
      res.send(csv);
    }
  } catch (error) {
    console.error('Generate compliance report error:', error);
    res.status(500).json({ error: 'Failed to generate compliance report' });
  }
});


// ==================== ENTERPRISE V8: AI ASSISTANT ====================

// Get AI settings
app.get('/api/enterprise/ai/settings', authenticateToken, async (req, res) => {
  try {
    if (!req.user.isAdmin) {
      return res.status(403).json({ error: 'Admin access required' });
    }
    
    const result = await pool.query('SELECT * FROM ai_settings LIMIT 1');
    const settings = result.rows[0] || {
      claude_enabled: false,
      chatgpt_enabled: false,
      ai_context_depth: 'standard'
    };
    
    // Don't send API keys to frontend
    if (settings.claude_api_key) settings.claude_api_key = '***HIDDEN***';
    if (settings.chatgpt_api_key) settings.chatgpt_api_key = '***HIDDEN***';
    
    res.json(settings);
  } catch (error) {
    console.error('Get AI settings error:', error);
    res.status(500).json({ error: 'Failed to get AI settings' });
  }
});

// Update AI settings
app.put('/api/enterprise/ai/settings', authenticateToken, async (req, res) => {
  try {
    if (!req.user.isAdmin) {
      return res.status(403).json({ error: 'Admin access required' });
    }
    
    const {
      claude_enabled,
      claude_api_key,
      chatgpt_enabled,
      chatgpt_api_key,
      ai_context_depth
    } = req.body;
    
    // Check if settings exist
    const check = await pool.query('SELECT id FROM ai_settings LIMIT 1');
    
    const updateFields = [];
    const updateValues = [];
    let paramCount = 1;
    
    if (claude_enabled !== undefined) {
      updateFields.push(`claude_enabled = $${paramCount++}`);
      updateValues.push(claude_enabled);
    }
    if (claude_api_key && claude_api_key !== '***HIDDEN***') {
      updateFields.push(`claude_api_key = $${paramCount++}`);
      updateValues.push(claude_api_key);
    }
    if (chatgpt_enabled !== undefined) {
      updateFields.push(`chatgpt_enabled = $${paramCount++}`);
      updateValues.push(chatgpt_enabled);
    }
    if (chatgpt_api_key && chatgpt_api_key !== '***HIDDEN***') {
      updateFields.push(`chatgpt_api_key = $${paramCount++}`);
      updateValues.push(chatgpt_api_key);
    }
    if (ai_context_depth) {
      updateFields.push(`ai_context_depth = $${paramCount++}`);
      updateValues.push(ai_context_depth);
    }
    
    if (check.rows.length === 0) {
      // Insert new
      await pool.query(`
        INSERT INTO ai_settings (
          claude_enabled, claude_api_key, chatgpt_enabled, chatgpt_api_key,
          ai_context_depth, updated_at
        ) VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP)
      `, [
        claude_enabled || false,
        claude_api_key || null,
        chatgpt_enabled || false,
        chatgpt_api_key || null,
        ai_context_depth || 'standard'
      ]);
    } else {
      // Update existing
      if (updateFields.length > 0) {
        updateFields.push('updated_at = CURRENT_TIMESTAMP');
        updateValues.push(check.rows[0].id);
        
        await pool.query(`
          UPDATE ai_settings SET ${updateFields.join(', ')}
          WHERE id = $${paramCount}
        `, updateValues);
      }
    }
    
    // Log the change
    await logAudit({
      user_id: req.user.id,
      username: req.user.username,
      action: 'ai_settings_updated',
      resource_type: 'settings',
      resource_name: 'ai_assistant',
      details: { updated_fields: Object.keys(req.body).filter(k => !k.includes('api_key')) },
      ip_address: req.ip
    });
    
    res.json({ success: true, message: 'AI settings updated successfully' });
  } catch (error) {
    console.error('Update AI settings error:', error);
    res.status(500).json({ error: 'Failed to update AI settings' });
  }
});

// Gather context about user's CloudKlone setup
async function gatherAIContext(userId, depth = 'standard') {
  const context = {
    timestamp: new Date().toISOString(),
    depth: depth
  };
  
  try {
    // User info
    const userResult = await pool.query('SELECT username, email, is_admin FROM users WHERE id = $1', [userId]);
    context.user = userResult.rows[0];
    
    // Remotes summary
    const remotesResult = await pool.query(`
      SELECT type, COUNT(*) as count 
      FROM remotes 
      WHERE user_id = $1 OR user_id IN (SELECT id FROM users WHERE is_admin = true)
      GROUP BY type
    `, [userId]);
    context.remotes = {
      total: remotesResult.rows.reduce((sum, r) => sum + parseInt(r.count), 0),
      by_type: remotesResult.rows
    };
    
    // Transfers summary
    const transfersResult = await pool.query(`
      SELECT status, COUNT(*) as count
      FROM transfers
      WHERE created_by = $1
      GROUP BY status
    `, [userId]);
    context.transfers = {
      total: transfersResult.rows.reduce((sum, r) => sum + parseInt(r.count), 0),
      by_status: transfersResult.rows
    };
    
    if (depth === 'comprehensive') {
      // Recent transfers
      const recentTransfers = await pool.query(`
        SELECT id, source_remote, destination_remote, source_path, destination_path, status, created_at
        FROM transfers
        WHERE created_by = $1
        ORDER BY created_at DESC
        LIMIT 10
      `, [userId]);
      context.recent_transfers = recentTransfers.rows;
      
      // Recent errors
      const recentErrors = await pool.query(`
        SELECT action, resource_type, details, timestamp
        FROM audit_logs
        WHERE user_id = $1 AND action LIKE '%fail%'
        ORDER BY timestamp DESC
        LIMIT 5
      `, [userId]);
      context.recent_errors = recentErrors.rows;
    }
    
    // System info
    if (context.user.is_admin && depth === 'comprehensive') {
      const allUsers = await pool.query('SELECT COUNT(*) as count FROM users');
      const allTransfers = await pool.query('SELECT COUNT(*) as count FROM transfers');
      context.system = {
        total_users: parseInt(allUsers.rows[0].count),
        total_transfers: parseInt(allTransfers.rows[0].count)
      };
    }
    
  } catch (error) {
    console.error('Gather AI context error:', error);
    context.error = 'Failed to gather some context';
  }
  
  return context;
}

// Query Claude API
async function queryClaude(apiKey, prompt, context) {
  const startTime = Date.now();
  
  try {
    const systemPrompt = `You are CloudKlone AI Assistant. Here's the user's current setup:\n\n${JSON.stringify(context, null, 2)}`;
    
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-3-sonnet-20240229',
        max_tokens: 1024,
        system: systemPrompt,
        messages: [
          { role: 'user', content: prompt }
        ]
      })
    });
    
    if (!response.ok) {
      throw new Error(`Claude API error: ${response.statusText}`);
    }
    
    const data = await response.json();
    const responseTime = Date.now() - startTime;
    
    return {
      response: data.content[0].text,
      model: 'claude-3-sonnet',
      tokens: data.usage.input_tokens + data.usage.output_tokens,
      response_time_ms: responseTime
    };
    
  } catch (error) {
    console.error('Claude query error:', error);
    throw error;
  }
}

// Query ChatGPT API
async function queryChatGPT(apiKey, prompt, context) {
  const startTime = Date.now();
  
  try {
    const systemPrompt = `You are CloudKlone AI Assistant. Here's the user's current setup:\n\n${JSON.stringify(context, null, 2)}`;
    
    const response = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`
      },
      body: JSON.stringify({
        model: 'gpt-4',
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: prompt }
        ],
        max_tokens: 1024
      })
    });
    
    if (!response.ok) {
      throw new Error(`ChatGPT API error: ${response.statusText}`);
    }
    
    const data = await response.json();
    const responseTime = Date.now() - startTime;
    
    return {
      response: data.choices[0].message.content,
      model: 'gpt-4',
      tokens: data.usage.total_tokens,
      response_time_ms: responseTime
    };
    
  } catch (error) {
    console.error('ChatGPT query error:', error);
    throw error;
  }
}

// AI Assistant query endpoint
app.post('/api/enterprise/ai/query', authenticateToken, async (req, res) => {
  try {
    const { query, provider } = req.body; // provider: 'claude', 'chatgpt', or 'auto'
    
    if (!query) {
      return res.status(400).json({ error: 'Query is required' });
    }
    
    // Get AI settings
    const settingsResult = await pool.query('SELECT * FROM ai_settings LIMIT 1');
    if (settingsResult.rows.length === 0) {
      return res.status(400).json({ error: 'AI not configured. Please configure in AI Assistant settings.' });
    }
    
    const settings = settingsResult.rows[0];
    
    // Determine which provider to use
    let useProvider = provider || 'auto';
    if (useProvider === 'auto') {
      // Priority: Claude > ChatGPT
      if (settings.claude_enabled && settings.claude_api_key) {
        useProvider = 'claude';
      } else if (settings.chatgpt_enabled && settings.chatgpt_api_key) {
        useProvider = 'chatgpt';
      } else {
        return res.status(400).json({ error: 'No AI provider enabled. Please enable Claude or ChatGPT in settings.' });
      }
    }
    
    // Gather context
    const context = await gatherAIContext(req.user.id, settings.ai_context_depth);
    
    // Query AI
    let result;
    try {
      if (useProvider === 'claude') {
        if (!settings.claude_enabled || !settings.claude_api_key) {
          return res.status(400).json({ error: 'Claude is not configured' });
        }
        result = await queryClaude(settings.claude_api_key, query, context);
      } else if (useProvider === 'chatgpt') {
        if (!settings.chatgpt_enabled || !settings.chatgpt_api_key) {
          return res.status(400).json({ error: 'ChatGPT is not configured' });
        }
        result = await queryChatGPT(settings.chatgpt_api_key, query, context);
      } else {
        return res.status(400).json({ error: 'Invalid provider. Use "claude" or "chatgpt".' });
      }
    } catch (aiError) {
      console.error('AI query error:', aiError);
      return res.status(500).json({ 
        error: 'AI query failed', 
        details: aiError.message,
        suggestion: 'Check your API key and network connection'
      });
    }
    
    // Save conversation
    await pool.query(`
      INSERT INTO ai_conversations (user_id, provider, query, response, context_used, model_used, tokens_used, response_time_ms)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
    `, [
      req.user.id,
      useProvider,
      query,
      result.response,
      JSON.stringify(context),
      result.model,
      result.tokens,
      result.response_time_ms
    ]);
    
    // Log the query
    await logAudit({
      user_id: req.user.id,
      username: req.user.username,
      action: 'ai_query',
      resource_type: 'ai_assistant',
      resource_name: useProvider,
      details: { query_length: query.length, response_time_ms: result.response_time_ms },
      ip_address: req.ip
    });
    
    res.json({
      response: result.response,
      provider: useProvider,
      model: result.model,
      tokens_used: result.tokens,
      response_time_ms: result.response_time_ms
    });
    
  } catch (error) {
    console.error('AI query error:', error);
    res.status(500).json({ error: 'Failed to process AI query' });
  }
});

// Get AI conversation history
app.get('/api/enterprise/ai/history', authenticateToken, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 20;
    
    const result = await pool.query(`
      SELECT id, provider, query, response, model_used, tokens_used, response_time_ms, created_at
      FROM ai_conversations
      WHERE user_id = $1
      ORDER BY created_at DESC
      LIMIT $2
    `, [req.user.id, limit]);
    
    res.json({ conversations: result.rows });
  } catch (error) {
    console.error('Get AI history error:', error);
    res.status(500).json({ error: 'Failed to get AI history' });
  }
});

// External AI connector endpoint (for Claude/ChatGPT to query CloudKlone data)
app.post('/api/enterprise/ai/connector', authenticateToken, async (req, res) => {
  try {
    const { data_type } = req.body; // 'summary', 'remotes', 'transfers', 'errors'
    
    const context = await gatherAIContext(req.user.id, 'comprehensive');
    
    let response = {};
    if (data_type === 'summary' || !data_type) {
      response = context;
    } else if (data_type === 'remotes') {
      const remotes = await pool.query(`
        SELECT id, name, type, created_at
        FROM remotes
        WHERE user_id = $1 OR user_id IN (SELECT id FROM users WHERE is_admin = true)
      `, [req.user.id]);
      response = { remotes: remotes.rows };
    } else if (data_type === 'transfers') {
      const transfers = await pool.query(`
        SELECT id, source_remote, destination_remote, source_path, destination_path, status, created_at
        FROM transfers
        WHERE created_by = $1
        ORDER BY created_at DESC
        LIMIT 50
      `, [req.user.id]);
      response = { transfers: transfers.rows };
    } else if (data_type === 'errors') {
      const errors = await pool.query(`
        SELECT action, resource_type, resource_name, details, timestamp
        FROM audit_logs
        WHERE user_id = $1 AND (action LIKE '%fail%' OR action LIKE '%error%')
        ORDER BY timestamp DESC
        LIMIT 20
      `, [req.user.id]);
      response = { errors: errors.rows };
    }
    
    res.json(response);
    
  } catch (error) {
    console.error('AI connector error:', error);
    res.status(500).json({ error: 'Failed to fetch data for AI connector' });
  }
});

// ==================== TRANSFER ROUTES ====================

app.get('/api/transfers', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM transfers WHERE user_id = $1 ORDER BY created_at DESC LIMIT 100',
      [req.user.id]
    );
    res.json({ transfers: result.rows });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/transfers/history', authenticateToken, async (req, res) => {
  try {
    const { status, limit = 50, offset = 0 } = req.query;
    
    let query = 'SELECT * FROM transfers WHERE user_id = $1';
    const params = [req.user.id];
    
    // Apply history retention limit for Community edition
    const retentionDays = editionManager.getHistoryRetentionDays();
    if (retentionDays !== null) {
      query += ` AND created_at > NOW() - INTERVAL '${retentionDays} days'`;
    }
    
    if (status) {
      query += ' AND status = $2';
      params.push(status);
    }
    
    query += ' ORDER BY created_at DESC LIMIT $' + (params.length + 1) + ' OFFSET $' + (params.length + 2);
    params.push(limit, offset);
    
    const result = await pool.query(query, params);
    
    // Get statistics
    const stats = await pool.query(`
      SELECT 
        COUNT(*) FILTER (WHERE status = 'completed') as completed,
        COUNT(*) FILTER (WHERE status = 'failed') as failed,
        COUNT(*) FILTER (WHERE status = 'running') as running,
        COUNT(*) as total
      FROM transfers WHERE user_id = $1
    `, [req.user.id]);
    
    res.json({ 
      transfers: result.rows,
      statistics: stats.rows[0]
    });
  } catch (error) {
    console.error('Transfer history error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get scheduled transfers
app.get('/api/transfers/scheduled', authenticateToken, async (req, res) => {
  try {
    const { filter } = req.query;
    
    // All users can see all scheduled transfers
    let query = 'SELECT * FROM transfers WHERE status = $1';
    const params = ['scheduled'];
    
    // Build filter based on next param index
    const nextParam = params.length + 1;
    
    if (filter === 'recurring') {
      query += ` AND schedule_type = $${nextParam}`;
      params.push('recurring');
    } else if (filter === 'once') {
      query += ` AND schedule_type = $${nextParam}`;
      params.push('once');
    } else if (filter === 'active') {
      query += ` AND enabled = $${nextParam}`;
      params.push(true);
    } else if (filter === 'disabled') {
      query += ` AND enabled = $${nextParam}`;
      params.push(false);
    }
    
    query += ' ORDER BY next_run ASC NULLS LAST';
    
    const result = await pool.query(query, params);
    
    // Get statistics - all users see all scheduled transfers
    const statsQuery = `
      SELECT 
        COUNT(*) as total,
        COUNT(*) FILTER (WHERE enabled = true) as active,
        COUNT(*) FILTER (WHERE enabled = false) as disabled,
        COUNT(*) FILTER (WHERE schedule_type = 'recurring') as recurring
      FROM transfers 
      WHERE status = 'scheduled'
    `;
    
    const stats = await pool.query(statsQuery);
    
    res.json({ 
      transfers: result.rows,
      statistics: stats.rows[0]
    });
  } catch (error) {
    console.error('Scheduled transfers error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get today's statistics (data transferred, average speed, counts)
app.get('/api/transfers/today-stats', authenticateToken, async (req, res) => {
  try {
    // Get today's date range
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const tomorrow = new Date(today);
    tomorrow.setDate(tomorrow.getDate() + 1);
    
    // Get counts for today
    const countsQuery = `
      SELECT 
        COUNT(*) FILTER (WHERE status = 'running') as active,
        COUNT(*) FILTER (WHERE status = 'completed' AND completed_at >= $1 AND completed_at < $2) as completed,
        COUNT(*) FILTER (WHERE status = 'failed' AND completed_at >= $1 AND completed_at < $2) as failed
      FROM transfers
      WHERE user_id = $3 OR $4 = true
    `;
    
    const counts = await pool.query(countsQuery, [today, tomorrow, req.user.id, req.user.isAdmin]);
    
    // Calculate total data transferred and average speed for completed transfers today
    const dataQuery = `
      SELECT 
        transfer_id,
        progress,
        EXTRACT(EPOCH FROM (completed_at - created_at)) as elapsed_seconds
      FROM transfers
      WHERE status = 'completed'
        AND completed_at >= $1 
        AND completed_at < $2
        AND (user_id = $3 OR $4 = true)
        AND progress IS NOT NULL
        AND completed_at IS NOT NULL
        AND created_at IS NOT NULL
    `;
    
    const dataResult = await pool.query(dataQuery, [today, tomorrow, req.user.id, req.user.isAdmin]);
    
    let totalBytes = 0;
    let totalSpeed = 0;
    let speedCount = 0;
    
    // Parse progress data to extract transferred bytes and calculate speed
    dataResult.rows.forEach(row => {
      if (row.progress && row.progress.transferred && row.elapsed_seconds && row.elapsed_seconds > 0) {
        // Try to parse transferred amount
        const transferred = row.progress.transferred;
        
        // Handle different formats: "123 MB", "1.5 GiB / 2 GiB, 75%", etc.
        if (typeof transferred === 'string') {
          // Extract first number with unit
          const match = transferred.match(/([\d.]+)\s*(B|KB|MB|GB|TB|KiB|MiB|GiB|TiB)/i);
          if (match) {
            const value = parseFloat(match[1]);
            const unit = match[2].toUpperCase();
            
            // Convert to bytes
            const multipliers = {
              'B': 1,
              'KB': 1000, 'KIB': 1024,
              'MB': 1000000, 'MIB': 1048576,
              'GB': 1000000000, 'GIB': 1073741824,
              'TB': 1000000000000, 'TIB': 1099511627776
            };
            
            const bytes = value * (multipliers[unit] || 1);
            totalBytes += bytes;
            
            // Calculate speed from bytes and elapsed time
            const speedBytesPerSec = bytes / row.elapsed_seconds;
            totalSpeed += speedBytesPerSec;
            speedCount++;
          }
        }
      }
    });
    
    const avgSpeed = speedCount > 0 ? totalSpeed / speedCount : 0;
    
    res.json({
      active: parseInt(counts.rows[0].active) || 0,
      completed: parseInt(counts.rows[0].completed) || 0,
      failed: parseInt(counts.rows[0].failed) || 0,
      totalBytes: totalBytes,
      avgSpeedBytesPerSec: avgSpeed
    });
  } catch (error) {
    console.error('Today stats error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Toggle scheduled transfer enabled/disabled
app.put('/api/transfers/:id/toggle', authenticateToken, async (req, res) => {
  try {
    const { enabled } = req.body;
    
    // Check ownership or admin
    const transfer = await pool.query(
      'SELECT user_id FROM transfers WHERE id = $1',
      [req.params.id]
    );
    
    if (!transfer.rows[0]) {
      return res.status(404).json({ error: 'Transfer not found' });
    }
    
    if (!req.user.isAdmin && transfer.rows[0].user_id !== req.user.id) {
      return res.status(403).json({ error: 'You can only modify your own transfers' });
    }
    
    const result = await pool.query(
      'UPDATE transfers SET enabled = $1 WHERE id = $2 RETURNING *',
      [enabled, req.params.id]
    );
    res.json({ transfer: result.rows[0] });
  } catch (error) {
    console.error('Toggle transfer error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/transfers', authenticateToken, validateTransferOperation, async (req, res) => {
  try {
    const { sourceRemote, sourcePath, destRemote, destPath, operation, schedule, encryption } = req.body;
    if (!sourceRemote || !sourcePath || !destRemote || !destPath || !operation)
      return res.status(400).json({ error: 'Missing required fields' });
    
    const transferId = uuidv4();
    
    // Handle scheduling
    let scheduledFor = null;
    let scheduleType = null;
    let scheduleInterval = null;
    let scheduleTime = null;
    let nextRun = null;
    
    if (schedule && schedule.enabled) {
      scheduleType = schedule.type; // 'once', 'recurring'
      
      if (schedule.type === 'once') {
        scheduledFor = new Date(schedule.datetime);
        nextRun = scheduledFor;
      } else if (schedule.type === 'recurring') {
        scheduleInterval = schedule.interval; // 'hourly', 'daily', 'weekly', 'monthly'
        scheduleTime = schedule.time; // Store the time like "14:00"
        const timezoneOffset = schedule.timezoneOffset || 0;
        nextRun = calculateNextRun(scheduleInterval, schedule.time, timezoneOffset);
      }
    }
    
    
    const result = await pool.query(
      `INSERT INTO transfers 
       (user_id, transfer_id, source_remote, source_path, dest_remote, dest_path, operation, status, scheduled_for, schedule_type, schedule_interval, schedule_time, next_run, enabled) 
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) 
       RETURNING *`,
      [
        req.user.id, transferId, sourceRemote, sourcePath, destRemote, destPath, operation,
        schedule && schedule.enabled ? 'scheduled' : 'queued',
        scheduledFor, scheduleType, scheduleInterval, scheduleTime, nextRun, true
      ]
    );
    
    // Log audit event
    await logAudit({
      user_id: req.user.id,
      username: req.user.username,
      action: 'transfer_created',
      resource_type: 'transfer',
      resource_id: result.rows[0].id,
      resource_name: `${sourceRemote}:${sourcePath} → ${destRemote}:${destPath}`,
      details: { operation, scheduled: schedule && schedule.enabled },
      ip_address: req.ip,
      user_agent: req.get('user-agent')
    });
    
    // If not scheduled, start immediately
    if (!schedule || !schedule.enabled) {
      await startTransfer(result.rows[0], req.user.id);
    }
    
    res.status(201).json({ transfer: result.rows[0] });
  } catch (error) {
    console.error('Create transfer error:', error);
    console.error('Error stack:', error.stack);
    res.status(500).json({ 
      error: 'Failed to create transfer', 
      details: error.message,
      hint: error.code === '42703' ? 'Database schema outdated - rebuild container' : null
    });
  }
});

// Update scheduled transfer
app.put('/api/transfers/:id/schedule', authenticateToken, async (req, res) => {
  try {
    const { schedule } = req.body;
    
    if (!schedule || !schedule.enabled) {
      return res.status(400).json({ error: 'Schedule information required' });
    }
    
    // Get transfer and check ownership
    const transferCheck = await pool.query(
      'SELECT * FROM transfers WHERE id = $1',
      [req.params.id]
    );
    
    if (transferCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Transfer not found' });
    }
    
    const transfer = transferCheck.rows[0];
    
    // Check if user owns this transfer or is admin
    if (transfer.user_id !== req.user.id && !req.user.isAdmin) {
      return res.status(403).json({ error: 'Permission denied' });
    }
    
    // Calculate new schedule
    let scheduledFor = null;
    let scheduleType = schedule.type;
    let scheduleInterval = null;
    let scheduleTime = null;
    let nextRun = null;
    
    if (schedule.type === 'once') {
      scheduledFor = new Date(schedule.datetime);
      nextRun = scheduledFor;
    } else if (schedule.type === 'recurring') {
      scheduleInterval = schedule.interval;
      scheduleTime = schedule.time;
      const timezoneOffset = schedule.timezoneOffset || 0;
      nextRun = calculateNextRun(scheduleInterval, schedule.time, timezoneOffset);
    }
    
    // Update transfer
    const result = await pool.query(
      `UPDATE transfers 
       SET scheduled_for = $1, 
           schedule_type = $2, 
           schedule_interval = $3, 
           schedule_time = $4,
           next_run = $5,
           status = 'scheduled'
       WHERE id = $6 
       RETURNING *`,
      [scheduledFor, scheduleType, scheduleInterval, scheduleTime, nextRun, req.params.id]
    );
    
    // Log audit event
    await logAudit({
      user_id: req.user.id,
      username: req.user.username,
      action: 'schedule_updated',
      resource_type: 'transfer',
      resource_id: req.params.id,
      resource_name: `${transfer.source_remote}:${transfer.source_path} → ${transfer.dest_remote}:${transfer.dest_path}`,
      details: { schedule_type: scheduleType, schedule_interval: scheduleInterval, next_run: nextRun },
      ip_address: req.ip,
      user_agent: req.get('user-agent')
    });
    
    res.json({ transfer: result.rows[0] });
  } catch (error) {
    console.error('Update schedule error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/transfers/:id', authenticateToken, async (req, res) => {
  try {
    // Get transfer details and check ownership
    const transferCheck = await pool.query(
      'SELECT * FROM transfers WHERE transfer_id = $1',
      [req.params.id]
    );
    
    if (transferCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Transfer not found' });
    }
    
    const transfer = transferCheck.rows[0];
    const permissions = await getUserPermissions(req.user.id);
    
    // Check if user can delete this transfer
    const isOwner = transfer.user_id === req.user.id;
    const canDelete = permissions.can_delete_any_transfers || 
                      (isOwner && permissions.can_delete_own_transfers);
    
    if (!canDelete) {
      await logAudit({
        user_id: req.user.id,
        username: req.user.username,
        action: 'transfer_delete_denied',
        resource_type: 'transfer',
        resource_id: transfer.id,
        details: { reason: 'no_delete_permission', is_owner: isOwner },
        ip_address: req.ip
      });
      return res.status(403).json({ error: 'You do not have permission to delete transfers' });
    }
    
    // Check if transfer is running
    const activeTransfer = activeTransfers.get(req.params.id);
    if (activeTransfer && activeTransfer.process) {
      console.log(`Killing running transfer: ${req.params.id}`);
      activeTransfer.process.kill('SIGTERM');
      activeTransfers.delete(req.params.id);
      
      // Update database status
      await pool.query(
        'UPDATE transfers SET status = $1, error = $2 WHERE transfer_id = $3',
        ['cancelled', 'Transfer cancelled by user', req.params.id]
      );
    } else {
      // Just delete from database
      await pool.query('DELETE FROM transfers WHERE transfer_id = $1', [req.params.id]);
    }
    
    // Log audit event
    await logAudit({
      user_id: req.user.id,
      username: req.user.username,
      action: 'transfer_deleted',
      resource_type: 'transfer',
      resource_id: transfer.id,
      resource_name: `${transfer.source_remote}:${transfer.source_path} → ${transfer.dest_remote}:${transfer.dest_path}`,
      details: { was_running: !!activeTransfer },
      ip_address: req.ip
    });
    
    res.json({ success: true });
  } catch (error) {
    console.error('Delete transfer error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Cancel all stuck transfers (admin only)
app.post('/api/transfers/cancel-all-stuck', authenticateToken, async (req, res) => {
  try {
    if (!req.user.isAdmin) return res.status(403).json({ error: 'Admin access required' });
    
    // Update all transfers stuck in "running" state with no recent progress
    const result = await pool.query(`
      UPDATE transfers 
      SET status = 'failed', error = 'Transfer timed out or was stuck'
      WHERE status = 'running' 
        AND (progress IS NULL OR progress->>'percentage' IS NULL OR (progress->>'percentage')::int = 0)
        AND created_at < NOW() - INTERVAL '10 minutes'
      RETURNING transfer_id
    `);
    
    // Kill any active transfer processes
    for (const row of result.rows) {
      const transfer = activeTransfers.get(row.transfer_id);
      if (transfer && transfer.process) {
        transfer.process.kill('SIGTERM');
        activeTransfers.delete(row.transfer_id);
      }
    }
    
    res.json({ success: true, count: result.rows.length });
  } catch (error) {
    console.error('Cancel stuck transfers error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== TESTS & QUERIES ====================

// Dry-run test endpoint
app.post('/api/tests/dry-run', authenticateToken, async (req, res) => {
  try {
    const { operation, sourceRemote, sourcePath, destRemote, destPath } = req.body;
    
    if (!sourceRemote || !destRemote || !operation) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    
    const configFile = `/root/.config/rclone/user_${req.user.id}.conf`;
    const command = operation === 'copy' ? 'copy' : 'sync';
    
    // Build rclone args with --dry-run
    const args = [
      command,
      `${sourceRemote}:${sourcePath || ''}`,
      `${destRemote}:${destPath || ''}`,
      '--config', configFile,
      '--dry-run',        // DRY-RUN FLAG - no actual transfers
      '--stats', '0',     // No stats for dry-run
      '-vv'               // Verbose output to see what would happen
    ];
    
    console.log(`[DRY-RUN] User ${req.user.username}: ${command} ${sourceRemote}:${sourcePath || ''} → ${destRemote}:${destPath || ''}`);
    
    // Execute dry-run
    const result = await new Promise((resolve) => {
      const rclone = spawn('rclone', args);
      let output = '';
      let errorOutput = '';
      
      rclone.stdout.on('data', (data) => {
        output += data.toString();
      });
      
      rclone.stderr.on('data', (data) => {
        errorOutput += data.toString();
      });
      
      rclone.on('close', (code) => {
        const fullOutput = output + errorOutput;
        resolve({
          success: code === 0,
          output: fullOutput || 'Dry-run completed. No files would be transferred.',
          code
        });
      });
      
      // Timeout after 60 seconds
      setTimeout(() => {
        rclone.kill('SIGTERM');
        resolve({
          success: false,
          output: 'Dry-run timed out after 60 seconds',
          code: -1
        });
      }, 60000);
    });
    
    if (result.success) {
      res.json({ output: result.output });
    } else {
      res.status(400).json({ error: result.output });
    }
  } catch (error) {
    console.error('Dry-run error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Query endpoint (read-only commands)
app.post('/api/tests/query', authenticateToken, async (req, res) => {
  try {
    const { remote, path, command, filename } = req.body;
    
    if (!remote || !command) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    
    // Whitelist of allowed read-only commands
    const allowedCommands = ['lsd', 'ls', 'lsl', 'lsf', 'size', 'about', 'tree', 'cat'];
    
    if (!allowedCommands.includes(command)) {
      return res.status(403).json({ error: 'Command not allowed. Only read-only commands are permitted.' });
    }
    
    const configFile = `/root/.config/rclone/user_${req.user.id}.conf`;
    let remotePath = `${remote}:${path || ''}`;
    
    // For cat command, append filename
    if (command === 'cat' && filename) {
      remotePath = `${remote}:${path ? path + '/' : ''}${filename}`;
    }
    
    // Build rclone args
    const args = [command, remotePath, '--config', configFile];
    
    // Add specific flags for certain commands
    if (command === 'tree') {
      args.push('--max-depth', '5'); // Limit depth for performance
    }
    
    // For cat command, limit to first 1MB for safety (prevents browser crashes)
    if (command === 'cat') {
      args.push('--max-size', '1M');
    }
    
    console.log(`[QUERY] User ${req.user.username}: rclone ${command} ${remotePath}`);
    
    // Execute query
    const MAX_OUTPUT_SIZE = 1024 * 1024; // 1MB max output
    const result = await new Promise((resolve) => {
      const rclone = spawn('rclone', args);
      let output = '';
      let errorOutput = '';
      let outputTruncated = false;
      
      rclone.stdout.on('data', (data) => {
        if (output.length < MAX_OUTPUT_SIZE) {
          const chunk = data.toString();
          if (output.length + chunk.length > MAX_OUTPUT_SIZE) {
            // Truncate to exactly MAX_OUTPUT_SIZE
            output += chunk.substring(0, MAX_OUTPUT_SIZE - output.length);
            outputTruncated = true;
            rclone.kill('SIGTERM'); // Stop reading more data
          } else {
            output += chunk;
          }
        }
      });
      
      rclone.stderr.on('data', (data) => {
        if (errorOutput.length < MAX_OUTPUT_SIZE) {
          errorOutput += data.toString();
        }
      });
      
      rclone.on('close', (code) => {
        let finalOutput = output || errorOutput || 'Query completed with no output';
        if (outputTruncated) {
          finalOutput += '\n\n[OUTPUT TRUNCATED - File too large. Only first 1MB shown. Use rclone directly for full file.]';
        }
        resolve({
          success: code === 0 || outputTruncated,
          output: finalOutput,
          code,
          truncated: outputTruncated
        });
      });
      
      // Timeout after 30 seconds
      setTimeout(() => {
        rclone.kill('SIGTERM');
        resolve({
          success: false,
          output: 'Query timed out after 30 seconds',
          code: -1
        });
      }, 30000);
    });
    
    if (result.success) {
      res.json({ output: result.output });
    } else {
      res.status(400).json({ error: result.output });
    }
  } catch (error) {
    console.error('Query error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== DECRYPTION ====================

// Decrypt files endpoint

// ==================== NOTIFICATION SETTINGS ====================

app.get('/api/notifications/settings', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM notification_settings WHERE user_id = $1',
      [req.user.id]
    );
    
    if (result.rows[0]) {
      const settings = { ...result.rows[0] };
      // Don't send encrypted password to client
      // Just indicate if password is set
      settings.smtp_pass = settings.smtp_pass ? '••••••••' : '';
      res.json({ settings });
    } else {
      res.json({ settings: null });
    }
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/notifications/settings', authenticateToken, requirePermission('can_manage_settings'), async (req, res) => {
  try {
    const { 
      email_enabled, email_address, from_email, smtp_host, smtp_port, smtp_user, smtp_pass,
      webhook_enabled, webhook_url, webhook_type,
      notify_on_failure, notify_on_success, daily_report,
      webhook_notify_on_failure, webhook_notify_on_success, webhook_daily_report
    } = req.body;
    
    // Encrypt SMTP password if provided
    const encryptedPass = smtp_pass ? encrypt(smtp_pass) : null;
    
    const result = await pool.query(`
      INSERT INTO notification_settings 
      (user_id, email_enabled, email_address, from_email, smtp_host, smtp_port, smtp_user, smtp_pass, 
       webhook_enabled, webhook_url, webhook_type,
       notify_on_failure, notify_on_success, daily_report,
       webhook_notify_on_failure, webhook_notify_on_success, webhook_daily_report)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
      ON CONFLICT (user_id) 
      DO UPDATE SET 
        email_enabled = $2,
        email_address = $3,
        from_email = $4,
        smtp_host = $5,
        smtp_port = $6,
        smtp_user = $7,
        smtp_pass = CASE WHEN $8 IS NOT NULL THEN $8 ELSE notification_settings.smtp_pass END,
        webhook_enabled = $9,
        webhook_url = $10,
        webhook_type = $11,
        notify_on_failure = $12,
        notify_on_success = $13,
        daily_report = $14,
        webhook_notify_on_failure = $15,
        webhook_notify_on_success = $16,
        webhook_daily_report = $17,
        updated_at = CURRENT_TIMESTAMP
      RETURNING *
    `, [req.user.id, email_enabled, email_address, from_email, smtp_host, smtp_port, smtp_user, encryptedPass,
        webhook_enabled, webhook_url, webhook_type,
        notify_on_failure, notify_on_success, daily_report,
        webhook_notify_on_failure, webhook_notify_on_success, webhook_daily_report]);
    
    // Log audit event
    await logAudit({
      user_id: req.user.id,
      username: req.user.username,
      action: 'notifications_configured',
      resource_type: 'settings',
      resource_id: null,
      resource_name: 'Notifications',
      details: { smtp_host, smtp_port, email_enabled, webhook_enabled, webhook_type },
      ip_address: req.ip,
      user_agent: req.get('user-agent')
    });
    
    // Don't return encrypted password to client
    const settings = { ...result.rows[0] };
    delete settings.smtp_pass;
    
    res.json({ settings });
  } catch (error) {
    console.error('Save notification settings error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/notifications/test', authenticateToken, async (req, res) => {
  try {
    const settings = await pool.query(
      'SELECT * FROM notification_settings WHERE user_id = $1',
      [req.user.id]
    );
    
    if (!settings.rows[0] || !settings.rows[0].email_enabled) {
      return res.status(400).json({ error: 'Email notifications not configured' });
    }
    
    await sendEmail(settings.rows[0], {
      subject: 'CloudKlone Test Notification',
      text: 'This is a test email from CloudKlone. If you received this, your email notifications are working correctly!'
    });
    
    res.json({ success: true, message: 'Test email sent successfully' });
  } catch (error) {
    console.error('Test email error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/notifications/test-webhook', authenticateToken, async (req, res) => {
  try {
    const { webhook_url, webhook_type } = req.body;
    
    if (!webhook_url) {
      return res.status(400).json({ error: 'Webhook URL is required' });
    }
    
    const payload = {
      status: 'completed successfully',
      success: true,
      source: 'test-remote:test/source/path',
      destination: 'test-remote:test/dest/path',
      operation: 'copy',
      transfer_id: 'test-transfer-' + Date.now(),
      timestamp: new Date().toISOString()
    };
    
    await sendWebhook({ webhook_url, webhook_type }, payload);
    
    res.json({ success: true, message: 'Test webhook sent successfully' });
  } catch (error) {
    console.error('Test webhook error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ==================== PROVIDER METADATA ====================

app.get('/api/providers', (req, res) => {
  res.json({
    providers: [
      { id: 's3', name: 'Amazon S3', type: 's3', fields: [
        { name: 'provider', label: 'Provider', type: 'select', options: ['AWS', 'Wasabi', 'Other'], required: true },
        { name: 'access_key_id', label: 'Access Key ID', type: 'text', required: true },
        { name: 'secret_access_key', label: 'Secret Access Key', type: 'password', required: true },
        { name: 'region', label: 'Region', type: 'text', placeholder: 'us-east-1', required: false },
        { name: 'endpoint', label: 'Endpoint URL', type: 'text', placeholder: 'https://...', required: false },
      ]},
      { id: 'r2', name: 'Cloudflare R2', type: 's3', fields: [
        { name: 'provider', label: 'Provider', type: 'hidden', default: 'Cloudflare', required: true },
        { name: 'access_key_id', label: 'Access Key ID', type: 'text', required: true },
        { name: 'secret_access_key', label: 'Secret Access Key', type: 'password', required: true },
        { name: 'endpoint', label: 'Account Endpoint', type: 'text', placeholder: 'https://<account-id>.r2.cloudflarestorage.com', required: true },
        { name: 'test_bucket', label: 'Bucket Name (for testing)', type: 'text', placeholder: 'my-bucket (leave blank if token has Admin access)', required: false },
        { name: 'region', label: 'Region', type: 'hidden', default: 'auto', required: false },
        { name: 'acl', label: 'ACL', type: 'hidden', default: 'private', required: false },
      ]},
      { id: 'b2', name: 'Backblaze B2 (Native API)', type: 'b2', fields: [
        { name: 'account', label: 'Account ID or Application Key ID', type: 'text', required: true },
        { name: 'key', label: 'Application Key', type: 'password', required: true },
        { name: 'hard_delete', label: 'Hard Delete', type: 'select', options: ['false', 'true'], default: 'false', required: false },
      ]},
      { id: 'b2-s3', name: 'Backblaze B2 (S3-Compatible)', type: 's3', fields: [
        { name: 'provider', label: 'Provider', type: 'select', options: ['Other'], required: true },
        { name: 'access_key_id', label: 'Application Key ID (starts with 001...)', type: 'text', required: true },
        { name: 'secret_access_key', label: 'Application Key', type: 'password', required: true },
        { name: 'endpoint', label: 'Endpoint URL', type: 'text', placeholder: 'https://s3.us-west-004.backblazeb2.com', required: true },
        { name: 'region', label: 'Region', type: 'text', placeholder: 'us-west-004', required: false },
      ]},
      { id: 'gcs', name: 'Google Cloud Storage', type: 'google cloud storage', fields: [
        { name: 'project_number', label: 'Project Number', type: 'text', required: true },
        { name: 'service_account_file', label: 'Service Account JSON', type: 'textarea', required: true },
      ]},
      { id: 'azure', name: 'Azure Blob Storage', type: 'azureblob', fields: [
        { name: 'account', label: 'Storage Account', type: 'text', required: true },
        { name: 'key', label: 'Storage Account Key', type: 'password', required: true },
      ]},
      { id: 'dropbox', name: 'Dropbox', type: 'dropbox', fields: [
        { name: 'token', label: 'Access Token', type: 'password', required: true },
      ]},
      { id: 'gdrive', name: 'Google Drive', type: 'drive', fields: [
        { name: 'scope', label: 'Scope', type: 'select', options: ['drive', 'drive.readonly', 'drive.file', 'drive.appfolder', 'drive.metadata.readonly'], default: 'drive', required: true },
        { name: 'client_id', label: 'Client ID (optional - leave blank to use rclone default)', type: 'text', placeholder: 'xxxxx.apps.googleusercontent.com', required: false },
        { name: 'client_secret', label: 'Client Secret (optional - only if using custom Client ID)', type: 'password', placeholder: 'GOCSPX-...', required: false },
        { name: 'token', label: 'OAuth Token JSON', type: 'textarea', placeholder: '{"access_token":"ya29...","token_type":"Bearer","refresh_token":"1//...","expiry":"2026-02-12T..."}', required: true, help: 'Run "rclone config" locally to get this token. See Help below for detailed instructions.' },
        { name: 'root_folder_id', label: 'Root Folder ID (optional)', type: 'text', placeholder: 'Leave blank for entire drive', required: false },
        { name: 'team_drive', label: 'Team Drive ID (optional)', type: 'text', placeholder: 'For shared drives', required: false },
      ]},
      { id: 'sftp', name: 'SFTP', type: 'sftp', fields: [
        { name: 'host', label: 'Host', type: 'text', placeholder: 'example.com', required: true },
        { name: 'user', label: 'Username', type: 'text', required: true },
        { name: 'pass', label: 'Password', type: 'password', required: false },
        { name: 'port', label: 'Port', type: 'number', default: '22', required: false },
      ]},
      { id: 'smb', name: 'SMB/CIFS (Samba)', type: 'smb', fields: [
        { name: 'host', label: 'Server', type: 'text', placeholder: 'server.local or IP address', required: true },
        { name: 'user', label: 'Username', type: 'text', required: true },
        { name: 'pass', label: 'Password', type: 'password', required: true },
        { name: 'share', label: 'Share Name', type: 'text', placeholder: 'share (optional - leave blank for root)', required: false },
        { name: 'domain', label: 'Domain', type: 'text', placeholder: 'WORKGROUP (optional)', required: false },
        { name: 'port', label: 'Port', type: 'number', default: '445', required: false },
      ]},
      { id: 'nfs', name: 'NFS (Network File System)', type: 'http', fields: [
        { name: 'url', label: 'NFS URL', type: 'text', placeholder: 'http://nfs-server/export/path', required: true },
      ]},
      { id: 'local', name: 'Local Filesystem', type: 'local', fields: [] },
    ],
  });
});

// ==================== MIDDLEWARE & HELPERS ====================

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access token required' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
}

const activeTransfers = new Map();
let wss; // WebSocket server - assigned when HTTPS server starts

function broadcast(data) {
  if (!wss || !wss.clients) return; // Safety check - wss not initialized yet
  wss.clients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN) client.send(JSON.stringify(data));
  });
}

async function updateRcloneConfig(userId) {
  const result = await pool.query('SELECT name, type, config, ssh_host_key FROM remotes WHERE user_id = $1', [userId]);
  const configPath = `/root/.config/rclone/user_${userId}.conf`;
  const knownHostsPath = `/root/.ssh/known_hosts_user_${userId}`;
  
  await fs.mkdir(path.dirname(configPath), { recursive: true });
  await fs.mkdir('/root/.ssh', { recursive: true });
  
  let content = '';
  let knownHostsContent = '';
  
  for (const remote of result.rows) {
    content += `[${remote.name}]\ntype = ${remote.type}\n`;
    for (const [key, value] of Object.entries(remote.config)) {
      content += `${key} = ${value}\n`;
    }
    
    // Add known_hosts file reference for SFTP
    if (remote.type === 'sftp') {
      content += `known_hosts_file = ${knownHostsPath}\n`;
      
      // Add host key to known_hosts
      if (remote.ssh_host_key) {
        knownHostsContent += remote.ssh_host_key + '\n';
      }
    }
    
    content += '\n';
  }
  
  await fs.writeFile(configPath, content);
  
  // Write known_hosts file if we have any SSH keys
  if (knownHostsContent) {
    await fs.writeFile(knownHostsPath, knownHostsContent);
    await fs.chmod(knownHostsPath, 0o600); // Set proper permissions
  }
}


async function sendEmail(settings, {subject, text, html}) {
  // Decrypt SMTP password
  const decryptedPass = settings.smtp_pass ? decrypt(settings.smtp_pass) : '';
  
  const transporter = nodemailer.createTransport({
    host: settings.smtp_host,
    port: settings.smtp_port,
    secure: settings.smtp_port == 465,
    auth: {
      user: settings.smtp_user,
      pass: decryptedPass,
    },
  });
  
  await transporter.sendMail({
    from: settings.from_email || settings.smtp_user,
    to: settings.email_address,
    subject,
    text,
    html
  });
}

async function sendWebhook(settings, payload) {
  try {
    const { webhook_url, webhook_type } = settings;
    
    // Format payload based on webhook type
    let body;
    switch (webhook_type) {
      case 'slack':
        body = JSON.stringify({
          text: `*CloudKlone Transfer ${payload.status}*`,
          blocks: [
            {
              type: "header",
              text: {
                type: "plain_text",
                text: `Transfer ${payload.status}`,
                emoji: true
              }
            },
            {
              type: "section",
              fields: [
                { type: "mrkdwn", text: `*Source:*\n${payload.source}` },
                { type: "mrkdwn", text: `*Destination:*\n${payload.destination}` },
                { type: "mrkdwn", text: `*Operation:*\n${payload.operation}` },
                { type: "mrkdwn", text: `*Transfer ID:*\n${payload.transfer_id}` }
              ]
            },
            ...(payload.error ? [{
              type: "section",
              text: {
                type: "mrkdwn",
                text: `*Error:*\n\`\`\`${payload.error}\`\`\``
              }
            }] : [])
          ]
        });
        break;
      
      case 'teams':
        body = JSON.stringify({
          "@type": "MessageCard",
          "@context": "http://schema.org/extensions",
          "themeColor": payload.success ? "28a745" : "dc3545",
          "summary": `Transfer ${payload.status}`,
          "sections": [{
            "activityTitle": `CloudKlone Transfer ${payload.status}`,
            "facts": [
              { "name": "Source", "value": payload.source },
              { "name": "Destination", "value": payload.destination },
              { "name": "Operation", "value": payload.operation },
              { "name": "Transfer ID", "value": payload.transfer_id },
              ...(payload.error ? [{ "name": "Error", "value": payload.error }] : [])
            ]
          }]
        });
        break;
      
      case 'discord':
        body = JSON.stringify({
          embeds: [{
            title: `Transfer ${payload.status}`,
            color: payload.success ? 0x28a745 : 0xdc3545,
            fields: [
              { name: "Source", value: payload.source, inline: false },
              { name: "Destination", value: payload.destination, inline: false },
              { name: "Operation", value: payload.operation, inline: true },
              { name: "Transfer ID", value: payload.transfer_id, inline: true },
              ...(payload.error ? [{ name: "Error", value: payload.error, inline: false }] : [])
            ],
            timestamp: new Date().toISOString()
          }]
        });
        break;
      
      default: // generic webhook
        body = JSON.stringify(payload);
    }
    
    const response = await fetch(webhook_url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body
    });
    
    if (!response.ok) {
      throw new Error(`Webhook returned ${response.status}`);
    }
  } catch (error) {
    console.error('Webhook error:', error);
    throw error;
  }
}

async function notifyTransferComplete(transfer, userId, success, error = null) {
  try {
    const settings = await pool.query(
      'SELECT * FROM notification_settings WHERE user_id = $1 AND (email_enabled = true OR webhook_enabled = true)',
      [userId]
    );
    
    if (settings.rows.length === 0) return;
    const s = settings.rows[0];
    
    const status = success ? 'completed successfully' : 'failed';
    
    // Send email notification (if enabled and preference matches)
    if (s.email_enabled && ((success && s.notify_on_success) || (!success && s.notify_on_failure))) {
      const subject = `CloudKlone: Transfer ${status}`;
      const text = `
Transfer ${status}

Source: ${transfer.source_remote}:${transfer.source_path}
Destination: ${transfer.dest_remote}:${transfer.dest_path}
Operation: ${transfer.operation}
${error ? '\nError: ' + error : ''}

Transfer ID: ${transfer.transfer_id}
      `;
      
      await sendEmail(s, { subject, text });
    }
    
    // Send webhook notification (if enabled and webhook preference matches)
    if (s.webhook_enabled && s.webhook_url && 
        ((success && s.webhook_notify_on_success) || (!success && s.webhook_notify_on_failure))) {
      const payload = {
        status,
        success,
        source: `${transfer.source_remote}:${transfer.source_path}`,
        destination: `${transfer.dest_remote}:${transfer.dest_path}`,
        operation: transfer.operation,
        transfer_id: transfer.transfer_id,
        error: error || undefined,
        timestamp: new Date().toISOString()
      };
      
      await sendWebhook(s, payload);
    }
  } catch (error) {
    console.error('Notification error:', error);
  }
}

async function startTransfer(transfer, userId) {
  try {
    const configFile = `/root/.config/rclone/user_${userId}.conf`;
    const command = transfer.operation === 'copy' ? 'copy' : 'sync';
    
    // Ensure config is up to date
    await updateRcloneConfig(userId);
  
  // Build rclone args with proper flags
  const args = [
    command,
    `${transfer.source_remote}:${transfer.source_path}`,
    `${transfer.dest_remote}:${transfer.dest_path}`,
    '--config', configFile,
    '--stats', '1s',         // Stats every second
    '--stats-log-level', 'NOTICE',  // Show transfer details
    '--retries', '3',
    '--low-level-retries', '10',
    '--transfers', '4',
    '--checkers', '8',
    '--buffer-size', '16M',
    '--checksum',            // Hash verification for integrity
    '-v',                    // Verbose to see what's happening
  ];
  
  // Get remote types to add type-specific flags
  const remotes = await pool.query(
    'SELECT name, type, config FROM remotes WHERE user_id = $1 AND (name = $2 OR name = $3)',
    [userId, transfer.source_remote, transfer.dest_remote]
  );
  
  // Add SFTP-specific flags if either remote is SFTP
  const hasSftp = remotes.rows.some(r => r.type === 'sftp');
  if (hasSftp) {
    args.push('--sftp-skip-links');
    args.push('--sftp-set-modtime=false');
    // Note: SFTP with checksum works, no need to ignore
  }
  
  // Add S3-specific flags for R2 (no bucket creation)
  const hasR2 = remotes.rows.some(r => {
    if (r.type !== 's3') return false;
    const config = r.config;
    return config.endpoint && config.endpoint.includes('r2.cloudflarestorage.com');
  });
  if (hasR2) {
    args.push('--s3-no-check-bucket');
  }
  
  const rclone = spawn('rclone', args);
  activeTransfers.set(transfer.transfer_id, { process: rclone, transfer });
  
  // Set initial progress immediately
  const encryptedLabel = transfer.is_encrypted ? '[ENCRYPTED] ' : '';
  const initialProgress = {
    transferred: `${encryptedLabel}Starting transfer...`,
    percentage: 0,
    speed: 'Initializing...',
    eta: 'calculating...'
  };
  await pool.query('UPDATE transfers SET status = $1, progress = $2 WHERE transfer_id = $3', ['running', initialProgress, transfer.transfer_id]);
  broadcast({ type: 'transfer_update', transfer: { ...transfer, status: 'running', progress: initialProgress } });
  
  let lastProgress = initialProgress;
  let lastUpdateTime = Date.now();
  let errorOutput = '';
  let stdOutput = '';
  let bytesTransferred = 0;
  let hasSeenProgress = false;
  
  console.log(`[${transfer.transfer_id}] ${encryptedLabel}Transfer started with args:`, args.join(' '));
  
  // Check for stalled transfers every 5 seconds
  const timeoutCheck = setInterval(() => {
    const timeSinceUpdate = Date.now() - lastUpdateTime;
    
    // After 10 seconds with no progress, show "scanning" message
    if (!hasSeenProgress && timeSinceUpdate > 10000 && timeSinceUpdate < 7200000) {
      const scanProgress = {
        transferred: `${encryptedLabel}Scanning files...`,
        percentage: 0,
        speed: 'Preparing transfer...',
        eta: 'Please wait...'
      };
      pool.query('UPDATE transfers SET progress = $1 WHERE transfer_id = $2', [scanProgress, transfer.transfer_id]);
      broadcast({ type: 'transfer_progress', transferId: transfer.transfer_id, progress: scanProgress });
      console.log(`[${transfer.transfer_id}] ${encryptedLabel}Still scanning...`);
    }
    
    // Shorter timeout if we've seen checking activity but no real progress (likely all skipped)
    if (hasSeenProgress && lastProgress.transferred === 'Checking files...' && timeSinceUpdate > 60000) {
      console.log(`[${transfer.transfer_id}] [WARNING] Stuck in checking state for 60s, killing process`);
      
      // Mark as failed due to timeout (or scheduled for recurring)
      const isRecurringScheduled = transfer.schedule_type === 'recurring';
      
      if (isRecurringScheduled) {
        const time = transfer.schedule_time || '00:00';
        const nextRun = calculateNextRun(transfer.schedule_interval, time);
        pool.query(
          'UPDATE transfers SET status = $1, error = $2, next_run = $3, original_next_run = NULL WHERE transfer_id = $4',
          ['scheduled', 'Transfer timed out while checking files. This may indicate an rclone issue.', nextRun, transfer.transfer_id]
        ).then(() => {
          broadcast({ type: 'transfer_failed', transferId: transfer.transfer_id, error: 'Timed out while checking' });
          console.log(`[${transfer.transfer_id}] Set to run again at: ${nextRun}`);
        });
      } else {
        pool.query(
          'UPDATE transfers SET status = $1, error = $2 WHERE transfer_id = $3',
          ['failed', 'Transfer timed out while checking files. This may indicate an rclone issue.', transfer.transfer_id]
        ).then(() => {
          broadcast({ type: 'transfer_failed', transferId: transfer.transfer_id, error: 'Timed out while checking' });
        });
      }
      
      rclone.kill('SIGTERM');
      setTimeout(() => rclone.kill('SIGKILL'), 5000); // Force kill after 5s if still alive
      clearInterval(timeoutCheck);
    }
    
    // Timeout after 2 hours of no activity
    if (timeSinceUpdate > 7200000) {
      console.log(`[${transfer.transfer_id}] Timed out after 2 hours of inactivity`);
      
      // Mark as failed due to timeout (or scheduled for recurring)
      const isRecurringScheduled = transfer.schedule_type === 'recurring';
      
      if (isRecurringScheduled) {
        const time = transfer.schedule_time || '00:00';
        const nextRun = calculateNextRun(transfer.schedule_interval, time);
        pool.query(
          'UPDATE transfers SET status = $1, error = $2, next_run = $3, original_next_run = NULL WHERE transfer_id = $4',
          ['scheduled', 'Transfer timed out after 2 hours of inactivity', nextRun, transfer.transfer_id]
        ).then(() => {
          broadcast({ type: 'transfer_failed', transferId: transfer.transfer_id, error: 'Timed out' });
          console.log(`[${transfer.transfer_id}] Set to run again at: ${nextRun}`);
        });
      } else {
        pool.query(
          'UPDATE transfers SET status = $1, error = $2 WHERE transfer_id = $3',
          ['failed', 'Transfer timed out after 2 hours of inactivity', transfer.transfer_id]
        ).then(() => {
          broadcast({ type: 'transfer_failed', transferId: transfer.transfer_id, error: 'Timed out' });
        });
      }
      
      rclone.kill('SIGTERM');
      setTimeout(() => rclone.kill('SIGKILL'), 5000);
      clearInterval(timeoutCheck);
    }
  }, 5000);
  
  console.log(`[${transfer.transfer_id}] Starting rclone process...`);
  
  let statsBuffer = '';  // Buffer for multi-line stats
  
  rclone.stderr.on('data', (data) => {
    const output = data.toString();
    errorOutput += output;
    statsBuffer += output;
    lastUpdateTime = Date.now();
    
    // Parse stats - rclone outputs multi-line stats every second
    // Look for the stats block that starts with "Transferred:"
    const statsMatch = statsBuffer.match(/Transferred:\s+([^,]+),\s*(\d+)%/);
    const speedMatch = statsBuffer.match(/([\d.]+\s*[KMGT]?i?Bytes\/s)/);
    const etaMatch = statsBuffer.match(/ETA\s+([^\n]+)/);
    
    // Check for file transfer activity
    const transferringMatch = output.match(/Transferring:\s*\n\s*\*\s*(.+?):\s*(\d+)%/);
    
    // Check for checking/skipped files (always output by rclone)
    const checkingMatch = output.match(/Checking:|Checks:/);
    const skippedMatch = output.match(/Skipped|Not copying|Identical/);
    
    // If we see checking or transferred stats, we've made progress
    if (checkingMatch || statsMatch || transferringMatch) {
      hasSeenProgress = true;
    }
    
    if (statsMatch) {
      const percentage = parseInt(statsMatch[2]);
      
      const progress = {
        transferred: `${encryptedLabel}${statsMatch[1].trim()}`,
        percentage: percentage,
        speed: speedMatch ? speedMatch[1].replace('Bytes', 'B') : 'calculating...',
        eta: etaMatch ? etaMatch[1].trim() : 'calculating...'
      };
      
      // Update if percentage changed
      if (progress.percentage !== lastProgress.percentage) {
        lastProgress = progress;
        pool.query('UPDATE transfers SET progress = $1 WHERE transfer_id = $2', [progress, transfer.transfer_id]);
        broadcast({ type: 'transfer_progress', transferId: transfer.transfer_id, progress });
        console.log(`[${transfer.transfer_id}] ${encryptedLabel}Progress: ${progress.percentage}% @ ${progress.speed}, ETA ${progress.eta}`);
      }
      
      // Clear buffer after parsing
      statsBuffer = '';
    }
    
    // Show active file being transferred
    if (transferringMatch) {
      console.log(`[${transfer.transfer_id}] ${encryptedLabel}Transferring: ${transferringMatch[1]} - ${transferringMatch[2]}%`);
    }
    
    // Detect skipped files - update progress to show checking
    if (skippedMatch || checkingMatch) {
      if (!hasSeenProgress || lastProgress.percentage === 0) {
        const checkProgress = {
          transferred: `${encryptedLabel}Checking files...`,
          percentage: 0,
          speed: 'Verifying...',
          eta: 'Almost done...'
        };
        lastProgress = checkProgress;
        pool.query('UPDATE transfers SET progress = $1 WHERE transfer_id = $2', [checkProgress, transfer.transfer_id]);
        broadcast({ type: 'transfer_progress', transferId: transfer.transfer_id, progress: checkProgress });
      }
      console.log(`[${transfer.transfer_id}] ${encryptedLabel}Checking/skipping files`);
    }
    
    // Clear buffer if it gets too large
    if (statsBuffer.length > 2000) {
      statsBuffer = '';
    }
    
    // Log errors
    if (output.toLowerCase().includes('error') && !output.includes('Errors:')) {
      console.error(`[${transfer.transfer_id}] ERROR:`, output.substring(0, 200));
    }
  });
  
  rclone.stdout.on('data', (data) => {
    stdOutput += data.toString();
    lastUpdateTime = Date.now();
    const output = data.toString();
    console.log(`[${transfer.transfer_id}] STDOUT RAW:`, output);
  });
  
  rclone.on('close', async (code) => {
    console.log(`[${transfer.transfer_id}] Rclone process closed with code ${code}`);
    clearInterval(timeoutCheck);
    activeTransfers.delete(transfer.transfer_id);
    
    // Parse final stats from rclone output
    const checksMatch = errorOutput.match(/Checks:\s+(\d+)\s*\/\s*(\d+)/);
    const transferredMatch = errorOutput.match(/Transferred:\s+(\d+)\s*\/\s*(\d+)/);
    const bytesMatch = errorOutput.match(/Transferred:\s+([\d.]+\s*[KMGT]?i?B)\s*\/\s*([\d.]+\s*[KMGT]?i?B)/);
    
    let filesTransferred = 0;
    let filesChecked = 0;
    let totalBytes = '';
    
    if (transferredMatch) {
      filesTransferred = parseInt(transferredMatch[1]);
    }
    if (checksMatch) {
      filesChecked = parseInt(checksMatch[2]);
    }
    if (bytesMatch) {
      totalBytes = bytesMatch[2];
    }
    
    // Check if all files were skipped (0 transferred, but files were checked)
    const allSkipped = filesTransferred === 0 && filesChecked > 0;
    
    if (code === 0) {
      let completionNote = '';
      if (allSkipped) {
        completionNote = `${filesChecked} file(s) already exist and match - skipped`;
      } else if (filesTransferred > 0) {
        completionNote = `${filesTransferred} file(s) transferred${totalBytes ? ' (' + totalBytes + ')' : ''}`;
      } else {
        completionNote = 'Completed successfully';
      }
      
      // For recurring scheduled transfers, calculate next_run and set back to 'scheduled'
      const isRecurringScheduled = transfer.schedule_type === 'recurring';
      
      if (isRecurringScheduled) {
        const time = transfer.schedule_time || '00:00';
        const nextRun = calculateNextRun(transfer.schedule_interval, time);
        await pool.query(
          'UPDATE transfers SET status = $1, completed_at = CURRENT_TIMESTAMP, error = $2, progress = NULL, next_run = $3, original_next_run = NULL WHERE transfer_id = $4',
          ['scheduled', completionNote, nextRun, transfer.transfer_id]
        );
        console.log(`[${transfer.transfer_id}] [SUCCESS] Completed: ${completionNote}. Next run: ${nextRun}`);
      } else {
        await pool.query(
          'UPDATE transfers SET status = $1, completed_at = CURRENT_TIMESTAMP, error = $2, progress = NULL WHERE transfer_id = $3',
          ['completed', completionNote, transfer.transfer_id]
        );
        console.log(`[${transfer.transfer_id}] [SUCCESS] Completed: ${completionNote}`);
      }
      
      broadcast({ type: 'transfer_complete', transferId: transfer.transfer_id, note: completionNote });
      await notifyTransferComplete(transfer, userId, true);
    } else {
      // Transfer failed - but check if any files were transferred (partial success)
      let errorMessage = `Transfer failed (exit code ${code})`;
      const errorLines = errorOutput.split('\n').filter(line => 
        line.includes('ERROR') || line.includes('Failed') || line.includes('NOTICE')
      );
      
      // Check for partial success
      const hasPermissionErrors = errorOutput.includes('permission denied') || errorOutput.includes('Access is denied');
      const partialSuccess = filesTransferred > 0;
      
      if (partialSuccess && hasPermissionErrors) {
        errorMessage = `Partial success: ${filesTransferred} file(s) transferred${totalBytes ? ' (' + totalBytes + ')' : ''}, but some files failed due to permission errors. Check source file permissions.`;
      } else if (partialSuccess) {
        errorMessage = `Partial success: ${filesTransferred} file(s) transferred${totalBytes ? ' (' + totalBytes + ')' : ''}, but transfer completed with errors.`;
      } else if (errorLines.length > 0) {
        errorMessage = errorLines[0].substring(0, 200);
      }
      
      // Check if error is credential-related (no retry for these)
      const isCredentialError = 
        errorMessage.toLowerCase().includes('authentication') ||
        errorMessage.toLowerCase().includes('unauthorized') ||
        errorMessage.toLowerCase().includes('access denied') ||
        errorMessage.toLowerCase().includes('invalid credentials') ||
        errorMessage.toLowerCase().includes('forbidden') ||
        errorMessage.toLowerCase().includes('403') ||
        errorMessage.toLowerCase().includes('401') ||
        errorMessage.toLowerCase().includes('failed to authenticate') ||
        errorMessage.toLowerCase().includes('failed to authorize');
      
      // Get current retry count
      const retryResult = await pool.query(
        'SELECT retry_count FROM transfers WHERE transfer_id = $1',
        [transfer.transfer_id]
      );
      const retryCount = retryResult.rows[0]?.retry_count || 0;
      
      // Determine if we should retry
      const canRetry = !isCredentialError && retryCount < 3 && !transfer.schedule_type;
      
      if (canRetry) {
        // Increment retry count and requeue
        const newRetryCount = retryCount + 1;
        await pool.query(
          'UPDATE transfers SET status = $1, error = $2, retry_count = $3, progress = NULL WHERE transfer_id = $4',
          ['queued', `Attempt ${newRetryCount} of 3: ${errorMessage}`, newRetryCount, transfer.transfer_id]
        );
        console.log(`[${transfer.transfer_id}]  Retry ${newRetryCount}/3 after failure`);
        broadcast({ type: 'transfer_retry', transferId: transfer.transfer_id, retryCount: newRetryCount });
        
        // Retry after a delay (exponential backoff: 5s, 10s, 20s)
        const delay = Math.pow(2, newRetryCount - 1) * 5000;
        setTimeout(() => {
          startTransfer(transfer, userId);
        }, delay);
      } else {
        // No more retries - mark as failed
        const isRecurringScheduled = transfer.schedule_type === 'recurring';
        
        // Add credential error hint
        if (isCredentialError) {
          errorMessage = `[ERROR] Credential Error: ${errorMessage}\n\n[INFO] Check your bucket credentials in the Remotes tab.`;
        } else if (retryCount > 0) {
          errorMessage = `Failed after ${retryCount} ${retryCount === 1 ? 'retry' : 'retries'}: ${errorMessage}`;
        }
        
        if (isRecurringScheduled) {
          // Calculate next run time for recurring scheduled transfers
          const time = transfer.schedule_time || '00:00';
          const nextRun = calculateNextRun(transfer.schedule_interval, time);
          await pool.query(
            'UPDATE transfers SET status = $1, error = $2, progress = NULL, next_run = $3, original_next_run = NULL WHERE transfer_id = $4',
            ['scheduled', errorMessage, nextRun, transfer.transfer_id]
          );
          console.log(`[${transfer.transfer_id}] [ERROR] Failed: ${errorMessage}. Next run: ${nextRun}`);
        } else {
          await pool.query(
            'UPDATE transfers SET status = $1, error = $2, progress = NULL WHERE transfer_id = $3',
            ['failed', errorMessage, transfer.transfer_id]
          );
          console.log(`[${transfer.transfer_id}] [ERROR] Failed: ${errorMessage}`);
        }
        
        broadcast({ type: 'transfer_failed', transferId: transfer.transfer_id, error: errorMessage });
        await notifyTransferComplete(transfer, userId, false, errorMessage);
      }
    }
  });
  
  rclone.on('error', async (err) => {
    clearInterval(timeoutCheck);
    activeTransfers.delete(transfer.transfer_id);
    let errorMessage = `Failed to start transfer: ${err.message}`;
    
    // Check if error is credential-related
    const isCredentialError = 
      errorMessage.toLowerCase().includes('authentication') ||
      errorMessage.toLowerCase().includes('unauthorized') ||
      errorMessage.toLowerCase().includes('invalid credentials');
    
    // Get current retry count
    const retryResult = await pool.query(
      'SELECT retry_count FROM transfers WHERE transfer_id = $1',
      [transfer.transfer_id]
    );
    const retryCount = retryResult.rows[0]?.retry_count || 0;
    
    // Determine if we should retry
    const canRetry = !isCredentialError && retryCount < 3 && !transfer.schedule_type;
    
    if (canRetry) {
      // Increment retry count and requeue
      const newRetryCount = retryCount + 1;
      await pool.query(
        'UPDATE transfers SET status = $1, error = $2, retry_count = $3 WHERE transfer_id = $4',
        ['queued', `Attempt ${newRetryCount} of 3: ${errorMessage}`, newRetryCount, transfer.transfer_id]
      );
      console.log(`[${transfer.transfer_id}]  Retry ${newRetryCount}/3 after error`);
      broadcast({ type: 'transfer_retry', transferId: transfer.transfer_id, retryCount: newRetryCount });
      
      // Retry after a delay
      const delay = Math.pow(2, newRetryCount - 1) * 5000;
      setTimeout(() => {
        startTransfer(transfer, userId);
      }, delay);
    } else {
      // No more retries
      const isRecurringScheduled = transfer.schedule_type === 'recurring';
      
      if (isCredentialError) {
        errorMessage = `[ERROR] Credential Error: ${errorMessage}\n\n[INFO] Check your bucket credentials in the Remotes tab.`;
      } else if (retryCount > 0) {
        errorMessage = `Failed after ${retryCount} ${retryCount === 1 ? 'retry' : 'retries'}: ${errorMessage}`;
      }
      
      if (isRecurringScheduled) {
        const time = transfer.schedule_time || '00:00';
        const nextRun = calculateNextRun(transfer.schedule_interval, time);
        await pool.query(
          'UPDATE transfers SET status = $1, error = $2, next_run = $3, original_next_run = NULL WHERE transfer_id = $4',
          ['scheduled', errorMessage, nextRun, transfer.transfer_id]
        );
        console.log(`[${transfer.transfer_id}] [ERROR] ${errorMessage}. Next run: ${nextRun}`);
      } else {
        await pool.query(
          'UPDATE transfers SET status = $1, error = $2 WHERE transfer_id = $3',
          ['failed', errorMessage, transfer.transfer_id]
        );
        console.log(`[${transfer.transfer_id}] [ERROR] ${errorMessage}`);
      }
      
      broadcast({ type: 'transfer_failed', transferId: transfer.transfer_id, error: errorMessage });
      await notifyTransferComplete(transfer, userId, false, errorMessage);
    }
  });
  } catch (error) {
    console.error(`[${transfer.transfer_id}] CRITICAL ERROR in startTransfer:`, error);
    
    const isRecurringScheduled = transfer.schedule_type === 'recurring';
    
    if (isRecurringScheduled) {
      const time = transfer.schedule_time || '00:00';
      const nextRun = calculateNextRun(transfer.schedule_interval, time);
      await pool.query(
        'UPDATE transfers SET status = $1, error = $2, next_run = $3, original_next_run = NULL WHERE transfer_id = $4',
        ['scheduled', `Failed to start transfer: ${error.message}`, nextRun, transfer.transfer_id]
      );
      console.log(`[${transfer.transfer_id}] Set to run again at: ${nextRun}`);
    } else {
      await pool.query(
        'UPDATE transfers SET status = $1, error = $2 WHERE transfer_id = $3',
        ['failed', `Failed to start transfer: ${error.message}`, transfer.transfer_id]
      );
    }
    
    broadcast({ type: 'transfer_failed', transferId: transfer.transfer_id, error: error.message });
  }
}

// Daily report cron - check every minute using system timezone
setInterval(async () => {
  try {
    // Get system timezone
    const tzResult = await pool.query(
      `SELECT setting_value FROM system_settings WHERE setting_key = 'timezone'`
    );
    const systemTimezone = tzResult.rows[0]?.setting_value || 'UTC';
    
    // Get system local time using configured timezone
    const now = new Date();
    const systemLocalTime = new Date(now.toLocaleString('en-US', { timeZone: systemTimezone }));
    const hour = systemLocalTime.getHours();
    const minute = systemLocalTime.getMinutes();
    
    // Check if it's midnight (00:00 to 00:05) in system timezone
    if (hour !== 0 || minute > 5) return;
    
    // Check if we already sent today's report (to avoid duplicates)
    const todayDate = systemLocalTime.toDateString();
    const lastReportCheck = await pool.query(
      `SELECT setting_value FROM system_settings WHERE setting_key = 'last_daily_report'`
    );
    
    if (lastReportCheck.rows[0]?.setting_value === todayDate) {
      return; // Already sent today
    }
    
    console.log(`[INFO] Running daily reports for all users at ${now.toISOString()} (System TZ: ${systemTimezone})`);
    
    // Get all users with daily reports enabled
    const users = await pool.query(`
      SELECT u.id, u.username, ns.* 
      FROM users u 
      JOIN notification_settings ns ON u.id = ns.user_id 
      WHERE (ns.email_enabled = true AND ns.daily_report = true) 
         OR (ns.webhook_enabled = true AND ns.webhook_daily_report = true)
    `);
    
    console.log(`[INFO] Found ${users.rows.length} users with daily reports enabled`);
    
    for (const user of users.rows) {
      const yesterday = new Date(now.getTime() - 24 * 60 * 60 * 1000);
      const stats = await pool.query(`
        SELECT 
          COUNT(*) FILTER (WHERE status = 'completed') as completed,
          COUNT(*) FILTER (WHERE status = 'failed') as failed,
          COUNT(*) as total
        FROM transfers 
        WHERE user_id = $1 AND created_at >= $2
      `, [user.id, yesterday]);
      
      if (stats.rows[0].total > 0) {
        const s = stats.rows[0];
        const reportText = `Daily Transfer Report for ${todayDate}\n\nCompleted: ${s.completed}\nFailed: ${s.failed}\nTotal: ${s.total}`;
        
        // Send email report
        if (user.email_enabled && user.daily_report) {
          try {
            await sendEmail(user, {
              subject: 'CloudKlone Daily Report',
              text: reportText
            });
            console.log(`[OK] Daily email report sent to ${user.username}`);
          } catch (err) {
            console.error(`[ERROR] Failed to send daily email to ${user.username}:`, err.message);
          }
        }
        
        // Send webhook report
        if (user.webhook_enabled && user.webhook_daily_report && user.webhook_url) {
          try {
            const payload = {
              report_type: 'daily_summary',
              date: todayDate,
              completed: parseInt(s.completed),
              failed: parseInt(s.failed),
              total: parseInt(s.total),
              timestamp: now.toISOString()
            };
            await sendWebhook(user, payload);
            console.log(`[OK] Daily webhook report sent for ${user.username}`);
          } catch (err) {
            console.error(`[ERROR] Failed to send daily webhook for ${user.username}:`, err.message);
          }
        }
      } else {
        console.log(`[INFO] No transfers in last 24h for ${user.username}, skipping report`);
      }
    }
    
    // Mark report as sent for today
    await pool.query(`
      INSERT INTO system_settings (setting_key, setting_value, updated_at)
      VALUES ('last_daily_report', $1, CURRENT_TIMESTAMP)
      ON CONFLICT (setting_key) 
      DO UPDATE SET setting_value = $1, updated_at = CURRENT_TIMESTAMP
    `, [todayDate]);
    
  } catch (error) {
    console.error('[ERROR] Daily report error:', error);
  }
}, 5 * 60 * 1000); // Check every 5 minutes

// Calculate next run time based on interval
function calculateNextRun(interval, time = '00:00', timezoneOffset = null) {
  const now = new Date();
  const [hours, minutes] = time.split(':').map(Number);
  
  // Create a date for the specified time TODAY in the user's timezone
  // We'll create it in UTC, then adjust
  let next = new Date();
  
  if (timezoneOffset !== null) {
    // User's local time needs to be converted to UTC for storage
    // timezoneOffset is positive for west of UTC (e.g., EST = 300 = UTC-5)
    // To convert user's local time to UTC: subtract the offset
    
    // Get current date components in UTC
    const utcYear = now.getUTCFullYear();
    const utcMonth = now.getUTCMonth();
    const utcDate = now.getUTCDate();
    
    // Create date at the user's specified time, but in UTC coordinates
    next = new Date(Date.UTC(utcYear, utcMonth, utcDate, hours, minutes, 0, 0));
    
    // Now adjust for the user's timezone offset
    // If user is in EST (UTC-5, offset=300), and they want 12:00 AM EST
    // That's 5:00 AM UTC, so we ADD 5 hours (300 minutes)
    next = new Date(next.getTime() + (timezoneOffset * 60 * 1000));
  } else {
    // No timezone info, use server's local time
    next.setHours(hours, minutes, 0, 0);
  }
  
  // Apply interval logic
  switch(interval) {
    case 'hourly':
      // For hourly, just add 1 hour from now
      next = new Date(now.getTime() + 60 * 60 * 1000);
      break;
    case 'daily':
      // If the calculated time has passed today, move to tomorrow
      if (next <= now) {
        next = new Date(next.getTime() + 24 * 60 * 60 * 1000);
      }
      break;
    case 'weekly':
      if (next <= now) {
        next = new Date(next.getTime() + 7 * 24 * 60 * 60 * 1000);
      }
      break;
    case 'monthly':
      if (next <= now) {
        next.setUTCMonth(next.getUTCMonth() + 1);
      }
      break;
  }
  
  return next;
}

// Initialize cron jobs AFTER database is ready
function initializeCronJobs() {
  // Check for scheduled transfers every minute
  cron.schedule('* * * * *', async () => {
    try {
      const now = new Date();
      const transfers = await pool.query(`
        SELECT t.*, u.id as user_id 
        FROM transfers t
        JOIN users u ON t.user_id = u.id
        WHERE t.status = 'scheduled' 
          AND t.enabled = true
          AND t.next_run <= $1
      `, [now]);
      
      for (const transfer of transfers.rows) {
        console.log(`[CRON] Executing scheduled transfer: ${transfer.transfer_id} (${transfer.name})`);
        
        // Set to queued but DON'T update next_run yet - wait for completion
        // Store the current next_run as original_next_run for recovery
        await pool.query(
          'UPDATE transfers SET status = $1, last_run = $2, original_next_run = $3 WHERE transfer_id = $4',
          ['queued', now, transfer.next_run, transfer.transfer_id]
        );
        
        // Start the transfer
        startTransfer(transfer, transfer.user_id);
      }
    } catch (error) {
      console.error('[CRON] Scheduled transfer check error:', error);
    }
  });

// Check for scheduled log reports (runs every hour)
cron.schedule('0 * * * *', async () => {
  try {
    // Get log report schedule settings
    const result = await pool.query(
      "SELECT value FROM system_settings WHERE key = 'log_report_schedule'"
    );
    
    if (result.rows.length === 0) return;
    
    const settings = JSON.parse(result.rows[0].value);
    if (!settings.enabled || !settings.email) return;
    
    const now = new Date();
    const currentHour = now.getHours();
    const currentDay = now.getDay(); // 0=Sunday, 6=Saturday
    const currentDate = now.getDate();
    
    // Parse schedule time
    const [scheduleHour, scheduleMinute] = settings.time.split(':').map(Number);
    
    // Check if it's time to send report
    let shouldSend = false;
    
    if (settings.frequency === 'daily' && currentHour === scheduleHour) {
      shouldSend = true;
    } else if (settings.frequency === 'weekly' && currentDay === settings.day_of_week && currentHour === scheduleHour) {
      shouldSend = true;
    } else if (settings.frequency === 'monthly' && currentDate === 1 && currentHour === scheduleHour) {
      shouldSend = true;
    }
    
    if (!shouldSend) return;
    
    // Check if we already sent today
    const lastSentResult = await pool.query(
      "SELECT value FROM system_settings WHERE key = 'log_report_last_sent'"
    );
    
    if (lastSentResult.rows.length > 0) {
      const lastSent = new Date(lastSentResult.rows[0].value);
      const hoursSinceLastSent = (now - lastSent) / (1000 * 60 * 60);
      
      // Don't send if we sent in the last 23 hours
      if (hoursSinceLastSent < 23) return;
    }
    
    // Get logs from last period
    let startDate;
    if (settings.frequency === 'daily') {
      startDate = new Date(now - 24 * 60 * 60 * 1000);
    } else if (settings.frequency === 'weekly') {
      startDate = new Date(now - 7 * 24 * 60 * 60 * 1000);
    } else {
      startDate = new Date(now - 30 * 24 * 60 * 60 * 1000);
    }
    
    const logs = await pool.query(
      'SELECT * FROM audit_logs WHERE timestamp >= $1 ORDER BY timestamp DESC',
      [startDate]
    );
    
    // Generate CSV
    const csv = convertLogsToCSV(logs.rows);
    
    // Send email with attachment
    await sendLogReportEmail(settings.email, settings.frequency, csv, startDate, now);
    
    // Update last sent time
    await pool.query(
      `INSERT INTO system_settings (key, value, updated_at)
       VALUES ('log_report_last_sent', $1, CURRENT_TIMESTAMP)
       ON CONFLICT (key) 
       DO UPDATE SET value = $1, updated_at = CURRENT_TIMESTAMP`,
      [now.toISOString()]
    );
    
    console.log(`[Scheduled Reports] Sent ${settings.frequency} log report to ${settings.email}`);
    
  } catch (error) {
    console.error('Scheduled log report error:', error);
  }
});

async function sendLogReportEmail(to, frequency, csvContent, startDate, endDate) {
  const smtpSettings = await pool.query(
    "SELECT value FROM system_settings WHERE key = 'smtp_settings'"
  );
  
  if (smtpSettings.rows.length === 0) {
    console.error('[Log Report] SMTP not configured');
    return;
  }
  
  const smtp = JSON.parse(smtpSettings.rows[0].value);
  if (!smtp.host || !smtp.username) {
    console.error('[Log Report] SMTP settings incomplete');
    return;
  }
  
  const transporter = nodemailer.createTransport({
    host: smtp.host,
    port: smtp.port || 587,
    secure: smtp.port === 465,
    auth: {
      user: smtp.username,
      pass: smtp.password
    }
  });
  
  const subject = `CloudKlone ${frequency.charAt(0).toUpperCase() + frequency.slice(1)} Audit Log Report`;
  const body = `
<html>
<body style="font-family: Arial, sans-serif; line-height: 1.6;">
  <h2>CloudKlone Audit Log Report</h2>
  <p>Attached is your ${frequency} audit log report.</p>
  <p><strong>Report Period:</strong> ${startDate.toLocaleDateString()} to ${endDate.toLocaleDateString()}</p>
  <p>The attached CSV file contains all audit log entries from this period.</p>
  <hr>
  <p style="color: #666; font-size: 12px;">
    This is an automated report from CloudKlone.<br>
    To modify or disable these reports, log in to CloudKlone and go to Admin → Log Reports.
  </p>
</body>
</html>
  `;
  
  const filename = `audit-logs-${frequency}-${endDate.toISOString().split('T')[0]}.csv`;
  
  try {
    await transporter.sendMail({
      from: smtp.from || smtp.username,
      to: to,
      subject: subject,
      html: body,
      attachments: [{
        filename: filename,
        content: csvContent,
        contentType: 'text/csv'
      }]
    });
  } catch (error) {
    console.error('[Log Report] Failed to send email:', error.message);
  }
}

// Enterprise v7: Data retention cleanup cron (runs daily at 2 AM)
cron.schedule('0 2 * * *', async () => {
  try {
    console.log('[Data Retention] Running cleanup job...');
    
    // Get compliance settings
    const settingsResult = await pool.query('SELECT * FROM compliance_settings LIMIT 1');
    if (settingsResult.rows.length === 0) return;
    
    const settings = settingsResult.rows[0];
    
    // Only run if auto-delete is enabled
    if (!settings.auto_delete_enabled) {
      console.log('[Data Retention] Auto-delete not enabled, skipping cleanup');
      return;
    }
    
    const dataRetentionDays = settings.data_retention_days || 90;
    const logRetentionDays = settings.log_retention_days || 365;
    
    // Delete old transfers
    const transfersResult = await pool.query(`
      DELETE FROM transfers 
      WHERE created_at < NOW() - INTERVAL '${dataRetentionDays} days'
      AND status IN ('completed', 'failed')
      RETURNING id
    `);
    
    const deletedTransfers = transfersResult.rowCount;
    
    // Delete old audit logs
    const logsResult = await pool.query(`
      DELETE FROM audit_logs 
      WHERE timestamp < NOW() - INTERVAL '${logRetentionDays} days'
      RETURNING id
    `);
    
    const deletedLogs = logsResult.rowCount;
    
    console.log(`[Data Retention] Cleaned up ${deletedTransfers} old transfers and ${deletedLogs} old logs`);
    
    // Log compliance event
    await pool.query(`
      INSERT INTO compliance_events (event_type, event_category, details, ip_address)
      VALUES ($1, $2, $3, $4)
    `, ['data_retention_cleanup', 'data_deletion', 
        JSON.stringify({ 
          deleted_transfers: deletedTransfers, 
          deleted_logs: deletedLogs,
          retention_days: { data: dataRetentionDays, logs: logRetentionDays }
        }), 
        'system']);
    
  } catch (error) {
    console.error('[Data Retention] Cleanup error:', error);
  }
});

  console.log('[OK] Cron jobs initialized');
}

// ==================== DATABASE INIT & SERVER START ====================

async function initDatabase() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS groups (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) UNIQUE NOT NULL,
        description TEXT,
        permissions JSONB DEFAULT '{"role": "operator", "can_create_copy": true, "can_create_sync": false, "can_edit_transfers": false, "can_delete_own_transfers": false, "can_delete_any_transfers": false, "can_manage_remotes": false, "can_manage_settings": false, "can_manage_users": false}',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        is_admin BOOLEAN DEFAULT FALSE,
        role VARCHAR(50) DEFAULT 'user',
        group_id INTEGER REFERENCES groups(id) ON DELETE SET NULL,
        reset_token VARCHAR(255),
        reset_token_expires TIMESTAMP,
        password_changed BOOLEAN DEFAULT true,
        enabled BOOLEAN DEFAULT true,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      
      -- Add password_changed column if it doesn't exist (migration)
      DO $$ 
      BEGIN 
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                       WHERE table_name='users' AND column_name='password_changed') THEN
          ALTER TABLE users ADD COLUMN password_changed BOOLEAN DEFAULT true;
        END IF;
        
        -- Add enabled column if it doesn't exist (migration for v6)
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                       WHERE table_name='users' AND column_name='enabled') THEN
          ALTER TABLE users ADD COLUMN enabled BOOLEAN DEFAULT true;
        END IF;
      END $$;
      
      CREATE TABLE IF NOT EXISTS audit_logs (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        username VARCHAR(255) NOT NULL,
        action VARCHAR(100) NOT NULL,
        resource_type VARCHAR(50) NOT NULL,
        resource_id INTEGER,
        resource_name VARCHAR(255),
        details JSONB,
        ip_address VARCHAR(45),
        user_agent TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      
      CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_id);
      CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp DESC);
      CREATE INDEX IF NOT EXISTS idx_audit_logs_resource ON audit_logs(resource_type, resource_id);
      
      CREATE TABLE IF NOT EXISTS remotes (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        group_id INTEGER REFERENCES groups(id) ON DELETE CASCADE,
        name VARCHAR(255) NOT NULL,
        type VARCHAR(50) NOT NULL,
        config JSONB NOT NULL,
        encrypted_config TEXT,
        is_shared BOOLEAN DEFAULT FALSE,
        ssh_host_key TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, name)
      );
      
      -- Add ssh_host_key column if it doesn't exist (migration)
      DO $$ 
      BEGIN 
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                       WHERE table_name='remotes' AND column_name='ssh_host_key') THEN
          ALTER TABLE remotes ADD COLUMN ssh_host_key TEXT;
        END IF;
      END $$;
      CREATE TABLE IF NOT EXISTS transfers (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        transfer_id VARCHAR(255) UNIQUE NOT NULL,
        source_remote VARCHAR(255) NOT NULL,
        source_path TEXT NOT NULL,
        dest_remote VARCHAR(255) NOT NULL,
        dest_path TEXT NOT NULL,
        operation VARCHAR(20) NOT NULL,
        status VARCHAR(20) DEFAULT 'queued',
        progress JSONB,
        error TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        completed_at TIMESTAMP,
        scheduled_for TIMESTAMP,
        schedule_type VARCHAR(20),
        schedule_interval VARCHAR(50),
        schedule_time VARCHAR(10),
        last_run TIMESTAMP,
        next_run TIMESTAMP,
        enabled BOOLEAN DEFAULT true,
        retry_count INTEGER DEFAULT 0
      );
      
      -- Add schedule_time column if it doesn't exist (migration)
      DO $$ 
      BEGIN 
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                       WHERE table_name='transfers' AND column_name='schedule_time') THEN
          ALTER TABLE transfers ADD COLUMN schedule_time VARCHAR(10);
        END IF;
      END $$;
      
      -- Add retry_count column if it doesn't exist (migration)
      DO $$ 
      BEGIN 
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                       WHERE table_name='transfers' AND column_name='retry_count') THEN
          ALTER TABLE transfers ADD COLUMN retry_count INTEGER DEFAULT 0;
        END IF;
      END $$;
      
      -- Add egress_warning_dismissed column if it doesn't exist (migration)
      DO $$ 
      BEGIN 
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                       WHERE table_name='transfers' AND column_name='egress_warning_dismissed') THEN
          ALTER TABLE transfers ADD COLUMN egress_warning_dismissed BOOLEAN DEFAULT false;
        END IF;
      END $$;
      
      -- Add is_encrypted column if it doesn't exist (migration)
      DO $$ 
      BEGIN 
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                       WHERE table_name='transfers' AND column_name='is_encrypted') THEN
          ALTER TABLE transfers ADD COLUMN is_encrypted BOOLEAN DEFAULT false;
        END IF;
      END $$;
      
      -- Add crypt_password column if it doesn't exist (migration)
      DO $$ 
      BEGIN 
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                       WHERE table_name='transfers' AND column_name='crypt_password') THEN
          ALTER TABLE transfers ADD COLUMN crypt_password VARCHAR(255);
        END IF;
      END $$;
      
      -- Add original_next_run column if it doesn't exist (for scheduled job recovery)
      DO $$ 
      BEGIN 
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                       WHERE table_name='transfers' AND column_name='original_next_run') THEN
          ALTER TABLE transfers ADD COLUMN original_next_run TIMESTAMP;
        END IF;
      END $$;
      
      CREATE TABLE IF NOT EXISTS notification_settings (
        id SERIAL PRIMARY KEY,
        user_id INTEGER UNIQUE REFERENCES users(id) ON DELETE CASCADE,
        email_enabled BOOLEAN DEFAULT false,
        email_address VARCHAR(255),
        from_email VARCHAR(255),
        smtp_host VARCHAR(255),
        smtp_port INTEGER,
        smtp_user VARCHAR(255),
        smtp_pass VARCHAR(255),
        webhook_enabled BOOLEAN DEFAULT false,
        webhook_url TEXT,
        webhook_type VARCHAR(50),
        notify_on_failure BOOLEAN DEFAULT true,
        notify_on_success BOOLEAN DEFAULT false,
        daily_report BOOLEAN DEFAULT false,
        webhook_notify_on_failure BOOLEAN DEFAULT true,
        webhook_notify_on_success BOOLEAN DEFAULT false,
        webhook_daily_report BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      
      -- System-wide settings table
      CREATE TABLE IF NOT EXISTS system_settings (
        id SERIAL PRIMARY KEY,
        setting_key VARCHAR(100) UNIQUE NOT NULL,
        setting_value TEXT,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      
      -- Insert default timezone if not exists
      INSERT INTO system_settings (setting_key, setting_value)
      VALUES ('timezone', 'UTC')
      ON CONFLICT (setting_key) DO NOTHING;
      
      -- Enterprise Feature: Branding settings table
      CREATE TABLE IF NOT EXISTS branding_settings (
        id SERIAL PRIMARY KEY,
        company_name VARCHAR(255) DEFAULT 'CloudKlone',
        logo_url TEXT,
        favicon_url TEXT,
        primary_color VARCHAR(7) DEFAULT '#1a73e8',
        secondary_color VARCHAR(7) DEFAULT '#34a853',
        accent_color VARCHAR(7) DEFAULT '#ff6b00',
        login_background_url TEXT,
        custom_css TEXT,
        footer_text TEXT,
        support_email VARCHAR(255),
        support_url TEXT,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      
      -- Insert default branding if not exists
      INSERT INTO branding_settings (company_name)
      SELECT 'CloudKlone'
      WHERE NOT EXISTS (SELECT 1 FROM branding_settings);
      
      -- Enterprise Feature: Compliance settings table
      CREATE TABLE IF NOT EXISTS compliance_settings (
        id SERIAL PRIMARY KEY,
        data_retention_days INTEGER DEFAULT 90,
        log_retention_days INTEGER DEFAULT 365,
        auto_delete_enabled BOOLEAN DEFAULT false,
        gdpr_enabled BOOLEAN DEFAULT true,
        soc2_enabled BOOLEAN DEFAULT true,
        cookie_consent_enabled BOOLEAN DEFAULT true,
        privacy_policy_url TEXT,
        terms_url TEXT,
        dpo_name VARCHAR(255),
        dpo_email VARCHAR(255),
        last_compliance_check TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      
      -- Insert default compliance settings if not exists
      INSERT INTO compliance_settings (data_retention_days, log_retention_days)
      SELECT 90, 365
      WHERE NOT EXISTS (SELECT 1 FROM compliance_settings);
      
      -- Enterprise Feature: GDPR data export/deletion requests
      CREATE TABLE IF NOT EXISTS gdpr_requests (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        request_type VARCHAR(50) NOT NULL, -- 'export' or 'deletion'
        status VARCHAR(50) DEFAULT 'pending', -- 'pending', 'processing', 'completed', 'failed'
        requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        completed_at TIMESTAMP,
        export_file_path TEXT,
        requester_ip VARCHAR(50),
        notes TEXT
      );
      
      -- Enterprise Feature: Compliance audit trail
      CREATE TABLE IF NOT EXISTS compliance_events (
        id SERIAL PRIMARY KEY,
        event_type VARCHAR(100) NOT NULL,
        event_category VARCHAR(50) NOT NULL, -- 'data_access', 'data_export', 'data_deletion', 'policy_change'
        user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        details JSONB,
        ip_address VARCHAR(50),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      
      -- Enterprise Feature: Data processing records (GDPR Article 30)
      CREATE TABLE IF NOT EXISTS data_processing_records (
        id SERIAL PRIMARY KEY,
        processing_activity VARCHAR(255) NOT NULL,
        purpose TEXT NOT NULL,
        data_categories TEXT[], -- Array of data types processed
        data_subjects TEXT[], -- Array of subject types
        recipients TEXT[], -- Who receives the data
        retention_period VARCHAR(100),
        security_measures TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      
      -- Insert default data processing records
      INSERT INTO data_processing_records (processing_activity, purpose, data_categories, data_subjects, recipients, retention_period, security_measures)
      SELECT 
        'Cloud Data Transfers',
        'Facilitate secure data transfers between cloud storage providers',
        ARRAY['user credentials', 'transfer logs', 'file metadata'],
        ARRAY['registered users', 'administrators'],
        ARRAY['cloud storage providers (AWS, Google, etc.)'],
        '90 days for transfer data, 365 days for audit logs',
        'Encryption at rest and in transit, access controls, audit logging'
      WHERE NOT EXISTS (SELECT 1 FROM data_processing_records WHERE processing_activity = 'Cloud Data Transfers');
      
      -- Enterprise Feature v8: AI Assistant settings
      CREATE TABLE IF NOT EXISTS ai_settings (
        id SERIAL PRIMARY KEY,
        claude_enabled BOOLEAN DEFAULT false,
        claude_api_key TEXT,
        chatgpt_enabled BOOLEAN DEFAULT false,
        chatgpt_api_key TEXT,
        ai_context_depth VARCHAR(50) DEFAULT 'standard', -- 'minimal', 'standard', 'comprehensive'
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      
      -- Insert default AI settings if not exists
      INSERT INTO ai_settings (claude_enabled)
      SELECT false
      WHERE NOT EXISTS (SELECT 1 FROM ai_settings);
      
      -- Enterprise Feature v8: AI conversation history
      CREATE TABLE IF NOT EXISTS ai_conversations (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        provider VARCHAR(50) NOT NULL, -- 'claude', 'chatgpt'
        query TEXT NOT NULL,
        response TEXT,
        context_used JSONB,
        model_used VARCHAR(100),
        tokens_used INTEGER,
        response_time_ms INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      
      CREATE INDEX IF NOT EXISTS idx_ai_conversations_user ON ai_conversations(user_id);
      CREATE INDEX IF NOT EXISTS idx_ai_conversations_created ON ai_conversations(created_at);
      
      -- Add webhook columns if they don't exist (migration)
      DO $$ 
      BEGIN 
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                       WHERE table_name='notification_settings' AND column_name='webhook_enabled') THEN
          ALTER TABLE notification_settings ADD COLUMN webhook_enabled BOOLEAN DEFAULT false;
        END IF;
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                       WHERE table_name='notification_settings' AND column_name='webhook_url') THEN
          ALTER TABLE notification_settings ADD COLUMN webhook_url TEXT;
        END IF;
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                       WHERE table_name='notification_settings' AND column_name='webhook_type') THEN
          ALTER TABLE notification_settings ADD COLUMN webhook_type VARCHAR(50);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                       WHERE table_name='notification_settings' AND column_name='webhook_notify_on_failure') THEN
          ALTER TABLE notification_settings ADD COLUMN webhook_notify_on_failure BOOLEAN DEFAULT true;
        END IF;
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                       WHERE table_name='notification_settings' AND column_name='webhook_notify_on_success') THEN
          ALTER TABLE notification_settings ADD COLUMN webhook_notify_on_success BOOLEAN DEFAULT false;
        END IF;
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                       WHERE table_name='notification_settings' AND column_name='webhook_daily_report') THEN
          ALTER TABLE notification_settings ADD COLUMN webhook_daily_report BOOLEAN DEFAULT false;
        END IF;
        -- Note: last_report_sent column is deprecated (now using system_settings table)
        -- Kept for backward compatibility - can be manually dropped if needed
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                       WHERE table_name='notification_settings' AND column_name='last_report_sent') THEN
          ALTER TABLE notification_settings ADD COLUMN last_report_sent VARCHAR(50);
        END IF;
      END $$;
    `);
    const userCheck = await pool.query('SELECT COUNT(*) FROM users');
    if (parseInt(userCheck.rows[0].count) === 0) {
      const hash = await bcrypt.hash('admin', 10);
      await client.query(
        'INSERT INTO users (username, email, password_hash, is_admin, password_changed) VALUES ($1, $2, $3, $4, $5)',
        ['admin', 'admin@localhost', hash, true, false]
      );
      console.log('[OK] Default admin user created (admin / admin)');
      console.log('[WARNING] IMPORTANT: You will be prompted to change the default password on first login');
    }
    
    // Initialize edition manager
    await editionManager.initialize(pool);
  } finally {
    client.release();
  }
}

const HTTP_PORT = process.env.HTTP_PORT || 3001;
const HTTPS_PORT = process.env.HTTPS_PORT || 3443;

// Retry database connection with exponential backoff
async function connectDatabaseWithRetry(maxRetries = 10, initialDelay = 1000) {
  let retries = 0;
  let delay = initialDelay;
  
  while (retries < maxRetries) {
    try {
      console.log(`[INFO] Attempting database connection (attempt ${retries + 1}/${maxRetries})...`);
      await initDatabase();
      console.log('[OK] Database initialized successfully');
      return; // Success!
    } catch (err) {
      retries++;
      
      if (retries >= maxRetries) {
        console.error('[FATAL] Failed to connect to database after maximum retries');
        throw err;
      }
      
      // Check if it's a connection/DNS error
      const isConnectionError = err.code === 'EAI_AGAIN' || 
                                err.code === 'ENOTFOUND' || 
                                err.code === 'ECONNREFUSED' ||
                                err.message?.includes('getaddrinfo') ||
                                err.message?.includes('Connection refused');
      
      if (isConnectionError) {
        console.log(`[WARN] Database connection failed: ${err.message}`);
        console.log(`[INFO] Retrying in ${delay}ms... (${retries}/${maxRetries})`);
        await new Promise(resolve => setTimeout(resolve, delay));
        delay = Math.min(delay * 1.5, 10000); // Exponential backoff, max 10s
      } else {
        // Non-connection error (e.g., schema error) - don't retry
        console.error('[ERROR] Database error (not retryable):', err.message);
        throw err;
      }
    }
  }
}

connectDatabaseWithRetry()
  .then(async () => {
    // Initialize cron jobs now that database is ready
    initializeCronJobs();
    
    // Ensure SSL certificate exists
    const { certPath, keyPath } = await ensureSSLCertificate();
    
    // Create HTTPS server
    const httpsServer = https.createServer({
      key: fsSync.readFileSync(keyPath),
      cert: fsSync.readFileSync(certPath)
    }, app);
    
    // Create WebSocket server on HTTPS
    wss = new WebSocket.Server({ server: httpsServer, path: '/ws' });
    
    // Setup WebSocket handlers
    wss.on('connection', (ws) => {
      console.log('WebSocket client connected');
      ws.on('message', () => {});
      ws.on('close', () => {
        console.log('WebSocket client disconnected');
      });
    });
    
    // Start HTTP server (will redirect to HTTPS)
    server.listen(HTTP_PORT, '0.0.0.0', () => {
      console.log(`[OK] HTTP server listening on 0.0.0.0:${HTTP_PORT} (redirects to HTTPS)`);
    });
    
    // Start HTTPS server
    httpsServer.listen(HTTPS_PORT, '0.0.0.0', () => {
      console.log(`[OK] HTTPS server listening on 0.0.0.0:${HTTPS_PORT}`);
      console.log(`[OK] WebSocket ready on wss://0.0.0.0:${HTTPS_PORT}/ws`);
      console.log('\n HTTPS is enabled with self-signed certificate');
      console.log('   Browser will show security warning - click "Advanced" → "Proceed" to continue\n');
    });
  })
  .catch((err) => {
    console.error('Failed to initialize:', err);
    process.exit(1);
  });
