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
      'SELECT id, username, email, password_hash, is_admin, password_changed FROM users WHERE username = $1',
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
    const userResult = await pool.query('SELECT username, email FROM users WHERE id = $1', [req.params.id]);
    const deletedUser = userResult.rows[0];
    
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
    
    // Handle encryption
    let isEncrypted = false;
    let cryptPassword = null;
    let generatedPassword = null; // For returning to user
    
    if (encryption && encryption.enabled) {
      isEncrypted = true;
      
      // Generate password if not provided
      if (!encryption.password) {
        // Generate a secure random password (24 chars base64)
        generatedPassword = crypto.randomBytes(18).toString('base64');
        cryptPassword = generatedPassword;
        console.log(`[INFO] Generated encryption password for transfer ${transferId}`);
      } else {
        cryptPassword = encryption.password;
      }
      
      // Obscure the password using rclone obscure before storage
      try {
        cryptPassword = await obscurePassword(cryptPassword);
        console.log(`[OK] Encryption password obscured for transfer ${transferId}`);
      } catch (err) {
        console.error('Failed to obscure encryption password:', err);
        return res.status(500).json({ error: 'Failed to encrypt password' });
      }
    }
    
    const result = await pool.query(
      `INSERT INTO transfers 
       (user_id, transfer_id, source_remote, source_path, dest_remote, dest_path, operation, status, scheduled_for, schedule_type, schedule_interval, schedule_time, next_run, enabled, is_encrypted, crypt_password) 
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) 
       RETURNING *`,
      [
        req.user.id, transferId, sourceRemote, sourcePath, destRemote, destPath, operation,
        schedule && schedule.enabled ? 'scheduled' : 'queued',
        scheduledFor, scheduleType, scheduleInterval, scheduleTime, nextRun, true,
        isEncrypted, cryptPassword
      ]
    );
    
    // Log audit event
    await logAudit({
      user_id: req.user.id,
      username: req.user.username,
      action: 'transfer_created',
      resource_type: 'transfer',
      resource_id: result.rows[0].id,
      resource_name: `${sourceRemote}:${sourcePath} → ${destRemote}:${destPath}${isEncrypted ? ' [ENCRYPTED]' : ''}`,
      details: { operation, scheduled: schedule && schedule.enabled, encrypted: isEncrypted },
      ip_address: req.ip,
      user_agent: req.get('user-agent')
    });
    
    // If not scheduled, start immediately
    if (!schedule || !schedule.enabled) {
      await startTransfer(result.rows[0], req.user.id);
    }
    
    // Return transfer info and generated password if applicable
    const response = { transfer: result.rows[0] };
    if (generatedPassword) {
      response.encryption_password = generatedPassword;
    }
    
    res.status(201).json(response);
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
app.post('/api/decrypt', authenticateToken, async (req, res) => {
  try {
    const { sourceRemote, sourcePath, password, destRemote, destPath } = req.body;
    
    if (!sourceRemote || !destRemote || !password) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    
    const transferId = uuidv4();
    
    // Obscure password for storage
    let obscuredPassword;
    try {
      obscuredPassword = await obscurePassword(password);
    } catch (err) {
      console.error('Failed to obscure decryption password:', err);
      return res.status(500).json({ error: 'Failed to process password' });
    }
    
    // Create transfer record with decryption flag
    const result = await pool.query(
      `INSERT INTO transfers 
       (user_id, transfer_id, source_remote, source_path, dest_remote, dest_path, operation, status, is_encrypted, crypt_password) 
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) 
       RETURNING *`,
      [
        req.user.id, transferId, sourceRemote, sourcePath || '', destRemote, destPath || '', 'decrypt',
        'queued', true, obscuredPassword
      ]
    );
    
    // Log audit event
    await logAudit({
      user_id: req.user.id,
      username: req.user.username,
      action: 'decryption_started',
      resource_type: 'transfer',
      resource_id: result.rows[0].id,
      resource_name: `[DECRYPT] ${sourceRemote}:${sourcePath || '/'} → ${destRemote}:${destPath || '/'}`,
      details: { operation: 'decrypt' },
      ip_address: req.ip,
      user_agent: req.get('user-agent')
    });
    
    // Start decryption transfer immediately
    await startDecryptionTransfer(result.rows[0], req.user.id);
    
    res.status(201).json({ transfer: result.rows[0], transfer_id: transferId });
  } catch (error) {
    console.error('Decryption error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Test decryption password
app.post('/api/decrypt/test', authenticateToken, async (req, res) => {
  try {
    const { sourceRemote, sourcePath, password } = req.body;
    
    if (!sourceRemote || !password) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    
    const configFile = `/root/.config/rclone/user_${req.user.id}.conf`;
    const tempCryptName = `test_crypt_${Date.now()}`;
    
    // Obscure password
    const obscuredPassword = await obscurePassword(password);
    const salt = crypto.randomBytes(16).toString('base64');
    const obscuredSalt = await obscurePassword(salt);
    
    // Create temporary crypt remote config
    const cryptConfig = `
[${tempCryptName}]
type = crypt
remote = ${sourceRemote}:${sourcePath || ''}
password = ${obscuredPassword}
password2 = ${obscuredSalt}
filename_encryption = standard
directory_name_encryption = true

`;
    
    await fs.appendFile(configFile, cryptConfig);
    
    try {
      // Try to list files with this password
      const result = await new Promise((resolve) => {
        const rclone = spawn('rclone', ['lsf', `${tempCryptName}:`, '--config', configFile, '--max-depth', '1']);
        let output = '';
        let errorOutput = '';
        
        rclone.stdout.on('data', (data) => {
          output += data.toString();
        });
        
        rclone.stderr.on('data', (data) => {
          errorOutput += data.toString();
        });
        
        rclone.on('close', (code) => {
          resolve({
            success: code === 0,
            output,
            error: errorOutput
          });
        });
        
        // Timeout after 15 seconds
        setTimeout(() => {
          rclone.kill('SIGTERM');
          resolve({
            success: false,
            error: 'Test timed out'
          });
        }, 15000);
      });
      
      // Remove temporary crypt remote from config
      const configContent = await fs.readFile(configFile, 'utf8');
      const updatedConfig = configContent.replace(cryptConfig, '');
      await fs.writeFile(configFile, updatedConfig);
      
      if (result.success) {
        const fileCount = result.output.split('\n').filter(line => line.trim()).length;
        res.json({ success: true, file_count: fileCount });
      } else {
        res.json({ success: false, error: result.error || 'Password test failed' });
      }
    } catch (err) {
      // Clean up config even on error
      try {
        const configContent = await fs.readFile(configFile, 'utf8');
        const updatedConfig = configContent.replace(cryptConfig, '');
        await fs.writeFile(configFile, updatedConfig);
      } catch (cleanupErr) {
        console.error('Config cleanup error:', cleanupErr);
      }
      throw err;
    }
  } catch (error) {
    console.error('Password test error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

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
        { name: 'client_id', label: 'Client ID', type: 'text', required: false },
        { name: 'client_secret', label: 'Client Secret', type: 'password', required: false },
        { name: 'token', label: 'Token (JSON from rclone config)', type: 'textarea', placeholder: '{"access_token":"...","token_type":"Bearer",...}', required: true },
        { name: 'root_folder_id', label: 'Root Folder ID (optional)', type: 'text', placeholder: 'Leave blank for root', required: false },
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

async function updateRcloneConfigWithCrypt(userId, cryptRemoteName, destRemote, destPath, obscuredPassword) {
  // First, update the regular config
  await updateRcloneConfig(userId);
  
  // Then append the temporary crypt remote
  const configPath = `/root/.config/rclone/user_${userId}.conf`;
  
  // Generate a salt for password2 (also obscured)
  const salt = crypto.randomBytes(16).toString('base64');
  const obscuredSalt = await obscurePassword(salt);
  
  // Append crypt remote configuration
  const cryptConfig = `
[${cryptRemoteName}]
type = crypt
remote = ${destRemote}:${destPath}
password = ${obscuredPassword}
password2 = ${obscuredSalt}
filename_encryption = standard
directory_name_encryption = true

`;
  
  await fs.appendFile(configPath, cryptConfig);
  console.log(`[INFO] Added crypt remote ${cryptRemoteName} to config for user ${userId}`);
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
    
    // Handle encryption - if encrypted, we need to use a crypt remote wrapper
    let destRemote = transfer.dest_remote;
    let destPath = transfer.dest_path;
    let cryptRemoteName = null;
    
    if (transfer.is_encrypted && transfer.crypt_password) {
      // Create temporary crypt remote name
      cryptRemoteName = `crypt_${transfer.transfer_id}`;
      
      // Update config to include crypt remote
      await updateRcloneConfigWithCrypt(userId, cryptRemoteName, transfer.dest_remote, transfer.dest_path, transfer.crypt_password);
      
      // Use crypt remote for destination
      destRemote = cryptRemoteName;
      destPath = ''; // Crypt remote already includes the path
      
      console.log(`[${transfer.transfer_id}] [ENCRYPTED] Using crypt remote: ${cryptRemoteName}`);
    } else {
      // For non-encrypted transfers, ensure config is up to date
      await updateRcloneConfig(userId);
    }
  
  // Build rclone args with proper flags
  const args = [
    command,
    `${transfer.source_remote}:${transfer.source_path}`,
    `${destRemote}:${destPath}`,
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
  // Note: Always query original remotes from database, not the crypt wrapper
  const remotes = await pool.query(
    'SELECT name, type, config FROM remotes WHERE user_id = $1 AND (name = $2 OR name = $3)',
    [userId, transfer.source_remote, transfer.dest_remote]  // Use original dest_remote from transfer object
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
      const finalStatus = isRecurringScheduled ? 'scheduled' : 'failed';
      
      pool.query(
        'UPDATE transfers SET status = $1, error = $2 WHERE transfer_id = $3',
        [finalStatus, 'Transfer timed out while checking files. This may indicate an rclone issue.', transfer.transfer_id]
      ).then(() => {
        broadcast({ type: 'transfer_failed', transferId: transfer.transfer_id, error: 'Timed out while checking' });
      });
      
      rclone.kill('SIGTERM');
      setTimeout(() => rclone.kill('SIGKILL'), 5000); // Force kill after 5s if still alive
      clearInterval(timeoutCheck);
    }
    
    // Timeout after 2 hours of no activity
    if (timeSinceUpdate > 7200000) {
      console.log(`[${transfer.transfer_id}] Timed out after 2 hours of inactivity`);
      
      // Mark as failed due to timeout (or scheduled for recurring)
      const isRecurringScheduled = transfer.schedule_type === 'recurring';
      const finalStatus = isRecurringScheduled ? 'scheduled' : 'failed';
      
      pool.query(
        'UPDATE transfers SET status = $1, error = $2 WHERE transfer_id = $3',
        [finalStatus, 'Transfer timed out after 2 hours of inactivity', transfer.transfer_id]
      ).then(() => {
        broadcast({ type: 'transfer_failed', transferId: transfer.transfer_id, error: 'Timed out' });
      });
      
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
      
      // Clear progress - transfer is done
      // For recurring scheduled transfers, set back to 'scheduled' status
      const isRecurringScheduled = transfer.schedule_type === 'recurring';
      const finalStatus = isRecurringScheduled ? 'scheduled' : 'completed';
      
      await pool.query(
        'UPDATE transfers SET status = $1, completed_at = CURRENT_TIMESTAMP, error = $2, progress = NULL WHERE transfer_id = $3',
        [finalStatus, completionNote, transfer.transfer_id]
      );
      broadcast({ type: 'transfer_complete', transferId: transfer.transfer_id, note: completionNote });
      console.log(`[${transfer.transfer_id}] [SUCCESS] Completed: ${completionNote}${isRecurringScheduled ? ' (will run again)' : ''}`);
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
        const finalStatus = isRecurringScheduled ? 'scheduled' : 'failed';
        
        // Add credential error hint
        if (isCredentialError) {
          errorMessage = `[ERROR] Credential Error: ${errorMessage}\n\n[INFO] Check your bucket credentials in the Remotes tab.`;
        } else if (retryCount > 0) {
          errorMessage = `Failed after ${retryCount} ${retryCount === 1 ? 'retry' : 'retries'}: ${errorMessage}`;
        }
        
        await pool.query(
          'UPDATE transfers SET status = $1, error = $2, progress = NULL WHERE transfer_id = $3',
          [finalStatus, errorMessage, transfer.transfer_id]
        );
        broadcast({ type: 'transfer_failed', transferId: transfer.transfer_id, error: errorMessage });
        console.log(`[${transfer.transfer_id}] [ERROR] Failed: ${errorMessage}${isRecurringScheduled ? ' (will retry at next scheduled time)' : ''}`);
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
      const finalStatus = isRecurringScheduled ? 'scheduled' : 'failed';
      
      if (isCredentialError) {
        errorMessage = `[ERROR] Credential Error: ${errorMessage}\n\n[INFO] Check your bucket credentials in the Remotes tab.`;
      } else if (retryCount > 0) {
        errorMessage = `Failed after ${retryCount} ${retryCount === 1 ? 'retry' : 'retries'}: ${errorMessage}`;
      }
      
      await pool.query(
        'UPDATE transfers SET status = $1, error = $2 WHERE transfer_id = $3',
        [finalStatus, errorMessage, transfer.transfer_id]
      );
      broadcast({ type: 'transfer_failed', transferId: transfer.transfer_id, error: errorMessage });
      await notifyTransferComplete(transfer, userId, false, errorMessage);
    }
  });
  } catch (error) {
    console.error(`[${transfer.transfer_id}] CRITICAL ERROR in startTransfer:`, error);
    await pool.query(
      'UPDATE transfers SET status = $1, error = $2 WHERE transfer_id = $3',
      ['failed', `Failed to start transfer: ${error.message}`, transfer.transfer_id]
    );
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

// Start decryption transfer
async function startDecryptionTransfer(transfer, userId) {
  const configFile = `/root/.config/rclone/user_${userId}.conf`;
  const tempCryptName = `decrypt_crypt_${transfer.transfer_id}`;
  
  try {
    // Ensure rclone config is up to date
    await updateRcloneConfig(userId);
    
    // Create temporary crypt remote for decryption
    const salt = crypto.randomBytes(16).toString('base64');
    const obscuredSalt = await obscurePassword(salt);
    
    // For decryption, the crypt remote points to where the encrypted files are stored
    // The source_path from the user should be the directory containing encrypted files
    let cryptSourcePath = transfer.source_path || '';
    
    // Remove trailing slashes for consistency
    cryptSourcePath = cryptSourcePath.replace(/\/+$/, '');
    
    console.log(`[${transfer.transfer_id}] [DECRYPT] Initial path: ${transfer.source_remote}:${cryptSourcePath}`);
    
    // Verify if the path is a directory by checking if it exists as a directory
    // If user provided a file path by mistake, we need to use the parent directory
    if (cryptSourcePath) {
      try {
        // Try to list the path as a directory using rclone lsf with --dirs-only
        // This will succeed if it's a directory, fail if it's a file
        const testArgs = [
          'lsf',
          `${transfer.source_remote}:${cryptSourcePath}`,
          '--config', configFile,
          '--dirs-only',
          '--max-depth', '1'
        ];
        
        const testProcess = spawn('rclone', testArgs);
        let testOutput = '';
        let testError = '';
        
        testProcess.stdout.on('data', (data) => { testOutput += data.toString(); });
        testProcess.stderr.on('data', (data) => { testError += data.toString(); });
        
        await new Promise((resolve) => {
          testProcess.on('close', (code) => {
            if (code !== 0 || testError.includes('directory not found') || testError.includes('not a directory')) {
              // Path doesn't exist as a directory - might be a file
              console.log(`[${transfer.transfer_id}] [DECRYPT] Path is not a directory, checking if it's a file`);
              
              // Strip the last component and use parent directory
              const pathParts = cryptSourcePath.split('/').filter(p => p.length > 0);
              if (pathParts.length > 0) {
                pathParts.pop(); // Remove last component (potential filename)
                cryptSourcePath = pathParts.join('/');
                console.log(`[${transfer.transfer_id}] [DECRYPT] Adjusted to parent directory: ${cryptSourcePath}`);
              }
            } else {
              console.log(`[${transfer.transfer_id}] [DECRYPT] Path verified as directory`);
            }
            resolve();
          });
        });
      } catch (verifyError) {
        console.error(`[${transfer.transfer_id}] [DECRYPT] Path verification error:`, verifyError.message);
        // Continue anyway with the path as provided
      }
    }
    
    console.log(`[${transfer.transfer_id}] [DECRYPT] Final path for crypt remote: ${transfer.source_remote}:${cryptSourcePath}`);
    
    const cryptConfig = `
[${tempCryptName}]
type = crypt
remote = ${transfer.source_remote}:${cryptSourcePath}
password = ${transfer.crypt_password}
password2 = ${obscuredSalt}
filename_encryption = standard
directory_name_encryption = true

`;
    
    await fs.appendFile(configFile, cryptConfig);
    console.log(`[${transfer.transfer_id}] [DECRYPT] Created crypt remote: ${tempCryptName} -> ${transfer.source_remote}:${cryptSourcePath}`);
    
    // Build rclone copy command (decrypt source → destination)
    // The crypt remote shows the decrypted view, so we copy everything from the crypt remote root
    const args = [
      'copy',
      `${tempCryptName}:`, // Source: decrypted view of encrypted files
      `${transfer.dest_remote}:${transfer.dest_path}`,
      '--config', configFile,
      '--stats', '1s',
      '--stats-log-level', 'NOTICE',
      '--retries', '3',
      '--low-level-retries', '10',
      '--transfers', '4',
      '--checkers', '8',
      '--buffer-size', '16M',
      '--checksum',
      '-v'
    ];
    
    console.log(`[${transfer.transfer_id}] [DECRYPT] Command:`, 'rclone', args.join(' '));
    
    const rclone = spawn('rclone', args);
    activeTransfers.set(transfer.transfer_id, { process: rclone, transfer });
    
    // Set initial progress
    const initialProgress = {
      transferred: '[DECRYPT] Starting decryption...',
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
    let hasSeenProgress = false;
    
    console.log(`[${transfer.transfer_id}] [DECRYPT] Started: ${transfer.source_remote}:${transfer.source_path} → ${transfer.dest_remote}:${transfer.dest_path}`);
    
    // Timeout check
    const timeoutCheck = setInterval(() => {
      const timeSinceUpdate = Date.now() - lastUpdateTime;
      
      if (!hasSeenProgress && timeSinceUpdate > 10000) {
        const scanProgress = {
          transferred: '[DECRYPT] Scanning encrypted files...',
          percentage: 0,
          speed: 'Preparing...',
          eta: 'Please wait...'
        };
        pool.query('UPDATE transfers SET progress = $1 WHERE transfer_id = $2', [scanProgress, transfer.transfer_id]);
        broadcast({ type: 'transfer_progress', transferId: transfer.transfer_id, progress: scanProgress });
      }
    }, 5000);
    
    let statsBuffer = '';
    
    // Handle stdout/stderr
    rclone.stdout.on('data', (data) => {
      stdOutput += data.toString();
      statsBuffer += data.toString();
      lastUpdateTime = Date.now();
      
      // Log all output for debugging
      console.log(`[${transfer.transfer_id}] [DECRYPT] stdout:`, data.toString());
      
      // Parse progress
      const statsMatch = statsBuffer.match(/Transferred:\s+(.*?),\s+(\d+)%/);
      const speedMatch = statsBuffer.match(/(\d+\.\d+\s+\w+\/s)/);
      const etaMatch = statsBuffer.match(/ETA\s+([\w\d:]+)/);
      
      if (statsMatch) {
        hasSeenProgress = true;
        const percentage = parseInt(statsMatch[2]);
        
        const progress = {
          transferred: `[DECRYPT] ${statsMatch[1].trim()}`,
          percentage: percentage,
          speed: speedMatch ? speedMatch[1] : 'calculating...',
          eta: etaMatch ? etaMatch[1] : 'calculating...'
        };
        
        if (progress.percentage !== lastProgress.percentage) {
          lastProgress = progress;
          pool.query('UPDATE transfers SET progress = $1 WHERE transfer_id = $2', [progress, transfer.transfer_id]);
          broadcast({ type: 'transfer_progress', transferId: transfer.transfer_id, progress });
          console.log(`[${transfer.transfer_id}] [DECRYPT] Progress: ${progress.percentage}%`);
        }
        
        statsBuffer = '';
      }
      
      if (statsBuffer.length > 2000) {
        statsBuffer = '';
      }
    });
    
    rclone.stderr.on('data', (data) => {
      errorOutput += data.toString();
      const errorStr = data.toString();
      console.error(`[${transfer.transfer_id}] [DECRYPT] stderr:`, errorStr.substring(0, 200));
      
      // Check for common decryption errors
      if (errorStr.includes('password') || errorStr.includes('decrypt')) {
        console.error(`[${transfer.transfer_id}] [DECRYPT] POSSIBLE PASSWORD ERROR`);
      }
    });
    
    rclone.on('close', async (code) => {
      clearInterval(timeoutCheck);
      activeTransfers.delete(transfer.transfer_id);
      
      console.log(`[${transfer.transfer_id}] [DECRYPT] Process exited with code ${code}`);
      console.log(`[${transfer.transfer_id}] [DECRYPT] Final stdout length: ${stdOutput.length} bytes`);
      console.log(`[${transfer.transfer_id}] [DECRYPT] Final stderr length: ${errorOutput.length} bytes`);
      
      // Clean up temp crypt remote
      try {
        const configContent = await fs.readFile(configFile, 'utf8');
        const updatedConfig = configContent.replace(cryptConfig, '');
        await fs.writeFile(configFile, updatedConfig);
        console.log(`[${transfer.transfer_id}] [DECRYPT] Cleaned up crypt remote`);
      } catch (err) {
        console.error(`[${transfer.transfer_id}] Failed to cleanup crypt remote:`, err);
      }
      
      if (code === 0) {
        // Success
        await pool.query(
          'UPDATE transfers SET status = $1, completed_at = NOW(), progress = $2 WHERE transfer_id = $3',
          ['completed', { transferred: '[DECRYPT] Completed successfully', percentage: 100 }, transfer.transfer_id]
        );
        
        broadcast({
          type: 'transfer_complete',
          transferId: transfer.transfer_id,
          status: 'completed'
        });
        
        console.log(`[${transfer.transfer_id}] [DECRYPT] ✓ Completed successfully`);
      } else {
        // Failed
        await pool.query(
          'UPDATE transfers SET status = $1, error = $2, completed_at = NOW() WHERE transfer_id = $3',
          ['failed', errorOutput || `Decryption failed with exit code ${code}`, transfer.transfer_id]
        );
        
        broadcast({
          type: 'transfer_failed',
          transferId: transfer.transfer_id,
          error: errorOutput
        });
        
        console.error(`[${transfer.transfer_id}] [DECRYPT] ✗ Failed with code ${code}`);
      }
    });
    
  } catch (error) {
    console.error(`[${transfer.transfer_id}] [DECRYPT] Error:`, error);
    await pool.query(
      'UPDATE transfers SET status = $1, error = $2 WHERE transfer_id = $3',
      ['failed', error.message, transfer.transfer_id]
    );
  }
}

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
      console.log(`Executing scheduled transfer: ${transfer.transfer_id}`);
      
      // Update last_run and calculate next_run if recurring
      if (transfer.schedule_type === 'recurring') {
        // Use stored schedule_time or default to 00:00
        const time = transfer.schedule_time || '00:00';
        const nextRun = calculateNextRun(transfer.schedule_interval, time);
        await pool.query(
          'UPDATE transfers SET status = $1, last_run = $2, next_run = $3 WHERE transfer_id = $4',
          ['queued', now, nextRun, transfer.transfer_id]
        );
      } else {
        // One-time transfer - set to queued
        await pool.query(
          'UPDATE transfers SET status = $1, last_run = $2 WHERE transfer_id = $3',
          ['queued', now, transfer.transfer_id]
        );
      }
      
      // Start the transfer
      startTransfer(transfer, transfer.user_id);
    }
  } catch (error) {
    console.error('Scheduled transfer check error:', error);
  }
});

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
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      
      -- Add password_changed column if it doesn't exist (migration)
      DO $$ 
      BEGIN 
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                       WHERE table_name='users' AND column_name='password_changed') THEN
          ALTER TABLE users ADD COLUMN password_changed BOOLEAN DEFAULT true;
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
      console.log('[WARNING]  IMPORTANT: You will be prompted to change the default password on first login');
    }
  } finally {
    client.release();
  }
}

const HTTP_PORT = process.env.HTTP_PORT || 3001;
const HTTPS_PORT = process.env.HTTPS_PORT || 3443;

initDatabase()
  .then(async () => {
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
