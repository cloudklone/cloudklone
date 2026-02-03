const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { spawn } = require('child_process');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs').promises;
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
      console.log(`✓ Loaded ${keyName} from ${ENV_FILE}`);
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
    console.log(`✓ Saved ${keyName} to ${ENV_FILE}`);
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

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server, path: '/ws' });

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
      'SELECT id, username, email, password_hash, is_admin FROM users WHERE username = $1',
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
      user: { id: user.id, username: user.username, email: user.email, isAdmin: user.is_admin },
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
    await pool.query('DELETE FROM users WHERE id = $1', [req.params.id]);
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
    await pool.query('DELETE FROM groups WHERE id = $1', [req.params.id]);
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
      updates.push(`password = $${paramIndex++}`);
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
    if (type === 'sftp') {
      config.skip_links = 'true';
      config.set_modtime = 'false';
      config.key_use_agent = 'false';
      
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
            endpointInfo = `✅ Connected successfully to bucket '${testBucket}'. Found ${lines.length} items.`;
          } else {
            endpointInfo = `✅ Connected successfully. Found ${lines.length} items at root.`;
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
      'INSERT INTO remotes (user_id, name, type, config, encrypted_config) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [req.user.id, name, type, config, encryptedConfig]
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
        let message = `✅ Connection successful. Found ${lines.length} items.`;
        
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
    
    let query = 'SELECT * FROM transfers WHERE user_id = $1 AND status = $2';
    const params = [req.user.id, 'scheduled'];
    
    if (filter === 'recurring') {
      query += ' AND schedule_type = $3';
      params.push('recurring');
    } else if (filter === 'once') {
      query += ' AND schedule_type = $3';
      params.push('once');
    } else if (filter === 'active') {
      query += ' AND enabled = $3';
      params.push(true);
    } else if (filter === 'disabled') {
      query += ' AND enabled = $3';
      params.push(false);
    }
    
    query += ' ORDER BY next_run ASC NULLS LAST';
    
    const result = await pool.query(query, params);
    
    // Get statistics
    const stats = await pool.query(`
      SELECT 
        COUNT(*) as total,
        COUNT(*) FILTER (WHERE enabled = true) as active,
        COUNT(*) FILTER (WHERE enabled = false) as disabled,
        COUNT(*) FILTER (WHERE schedule_type = 'recurring') as recurring
      FROM transfers 
      WHERE user_id = $1 AND status = 'scheduled'
    `, [req.user.id]);
    
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
    const result = await pool.query(
      'UPDATE transfers SET enabled = $1 WHERE id = $2 AND user_id = $3 RETURNING *',
      [enabled, req.params.id, req.user.id]
    );
    res.json({ transfer: result.rows[0] });
  } catch (error) {
    console.error('Toggle transfer error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/transfers', authenticateToken, validateTransferOperation, async (req, res) => {
  try {
    const { sourceRemote, sourcePath, destRemote, destPath, operation, schedule } = req.body;
    if (!sourceRemote || !sourcePath || !destRemote || !destPath || !operation)
      return res.status(400).json({ error: 'Missing required fields' });
    
    const transferId = uuidv4();
    
    // Handle scheduling
    let scheduledFor = null;
    let scheduleType = null;
    let scheduleInterval = null;
    let nextRun = null;
    
    if (schedule && schedule.enabled) {
      scheduleType = schedule.type; // 'once', 'recurring'
      
      if (schedule.type === 'once') {
        scheduledFor = new Date(schedule.datetime);
        nextRun = scheduledFor;
      } else if (schedule.type === 'recurring') {
        scheduleInterval = schedule.interval; // 'hourly', 'daily', 'weekly', 'monthly'
        nextRun = calculateNextRun(scheduleInterval, schedule.time);
      }
    }
    
    const result = await pool.query(
      `INSERT INTO transfers 
       (user_id, transfer_id, source_remote, source_path, dest_remote, dest_path, operation, status, scheduled_for, schedule_type, schedule_interval, next_run, enabled) 
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) 
       RETURNING *`,
      [
        req.user.id, transferId, sourceRemote, sourcePath, destRemote, destPath, operation,
        schedule && schedule.enabled ? 'scheduled' : 'queued',
        scheduledFor, scheduleType, scheduleInterval, nextRun, true
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
    const { email_enabled, email_address, from_email, smtp_host, smtp_port, smtp_user, smtp_pass, notify_on_failure, notify_on_success, daily_report } = req.body;
    
    // Encrypt SMTP password if provided
    const encryptedPass = smtp_pass ? encrypt(smtp_pass) : null;
    
    const result = await pool.query(`
      INSERT INTO notification_settings 
      (user_id, email_enabled, email_address, from_email, smtp_host, smtp_port, smtp_user, smtp_pass, notify_on_failure, notify_on_success, daily_report)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
      ON CONFLICT (user_id) 
      DO UPDATE SET 
        email_enabled = $2,
        email_address = $3,
        from_email = $4,
        smtp_host = $5,
        smtp_port = $6,
        smtp_user = $7,
        smtp_pass = $8,
        notify_on_failure = $9,
        notify_on_success = $10,
        daily_report = $11,
        updated_at = CURRENT_TIMESTAMP
      RETURNING *
    `, [req.user.id, email_enabled, email_address, from_email, smtp_host, smtp_port, smtp_user, encryptedPass, notify_on_failure, notify_on_success, daily_report]);
    
    // Log audit event
    await logAudit({
      user_id: req.user.id,
      username: req.user.username,
      action: 'smtp_configured',
      resource_type: 'settings',
      resource_id: null,
      resource_name: 'SMTP',
      details: { smtp_host, smtp_port, email_enabled },
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

function broadcast(data) {
  wss.clients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN) client.send(JSON.stringify(data));
  });
}

wss.on('connection', (ws) => {
  console.log('WebSocket client connected');
  ws.on('close', () => console.log('WebSocket client disconnected'));
});

async function updateRcloneConfig(userId) {
  const result = await pool.query('SELECT name, type, config FROM remotes WHERE user_id = $1', [userId]);
  const configPath = `/root/.config/rclone/user_${userId}.conf`;
  await fs.mkdir(path.dirname(configPath), { recursive: true });
  let content = '';
  for (const remote of result.rows) {
    content += `[${remote.name}]\ntype = ${remote.type}\n`;
    for (const [key, value] of Object.entries(remote.config)) {
      content += `${key} = ${value}\n`;
    }
    content += '\n';
  }
  await fs.writeFile(configPath, content);
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

async function notifyTransferComplete(transfer, userId, success, error = null) {
  try {
    const settings = await pool.query(
      'SELECT * FROM notification_settings WHERE user_id = $1 AND email_enabled = true',
      [userId]
    );
    
    if (settings.rows.length === 0) return;
    const s = settings.rows[0];
    
    if ((success && s.notify_on_success) || (!success && s.notify_on_failure)) {
      const status = success ? 'completed successfully' : 'failed';
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
  } catch (error) {
    console.error('Email notification error:', error);
  }
}

async function startTransfer(transfer, userId) {
  const configFile = `/root/.config/rclone/user_${userId}.conf`;
  const command = transfer.operation === 'copy' ? 'copy' : 'sync';
  
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
    args.push('--ignore-checksum');
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
  const initialProgress = {
    transferred: 'Starting transfer...',
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
  
  console.log(`[${transfer.transfer_id}] Transfer started with args:`, args.join(' '));
  
  // Check for stalled transfers every 5 seconds
  const timeoutCheck = setInterval(() => {
    const timeSinceUpdate = Date.now() - lastUpdateTime;
    
    // After 10 seconds with no progress, show "scanning" message
    if (!hasSeenProgress && timeSinceUpdate > 10000 && timeSinceUpdate < 7200000) {
      const scanProgress = {
        transferred: 'Scanning files...',
        percentage: 0,
        speed: 'Preparing transfer...',
        eta: 'Please wait...'
      };
      pool.query('UPDATE transfers SET progress = $1 WHERE transfer_id = $2', [scanProgress, transfer.transfer_id]);
      broadcast({ type: 'transfer_progress', transferId: transfer.transfer_id, progress: scanProgress });
      console.log(`[${transfer.transfer_id}] Still scanning...`);
    }
    
    // Shorter timeout if we've seen checking activity but no real progress (likely all skipped)
    if (hasSeenProgress && lastProgress.transferred === 'Checking files...' && timeSinceUpdate > 60000) {
      console.log(`[${transfer.transfer_id}] ⚠️ Stuck in checking state for 60s, killing process`);
      
      // Mark as failed due to timeout
      pool.query(
        'UPDATE transfers SET status = $1, error = $2 WHERE transfer_id = $3',
        ['failed', 'Transfer timed out while checking files. This may indicate an rclone issue.', transfer.transfer_id]
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
      
      // Mark as failed due to timeout
      pool.query(
        'UPDATE transfers SET status = $1, error = $2 WHERE transfer_id = $3',
        ['failed', 'Transfer timed out after 2 hours of inactivity', transfer.transfer_id]
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
        transferred: statsMatch[1].trim(),
        percentage: percentage,
        speed: speedMatch ? speedMatch[1].replace('Bytes', 'B') : 'calculating...',
        eta: etaMatch ? etaMatch[1].trim() : 'calculating...'
      };
      
      // Update if percentage changed
      if (progress.percentage !== lastProgress.percentage) {
        lastProgress = progress;
        pool.query('UPDATE transfers SET progress = $1 WHERE transfer_id = $2', [progress, transfer.transfer_id]);
        broadcast({ type: 'transfer_progress', transferId: transfer.transfer_id, progress });
        console.log(`[${transfer.transfer_id}] Progress: ${progress.percentage}% @ ${progress.speed}, ETA ${progress.eta}`);
      }
      
      // Clear buffer after parsing
      statsBuffer = '';
    }
    
    // Show active file being transferred
    if (transferringMatch) {
      console.log(`[${transfer.transfer_id}] Transferring: ${transferringMatch[1]} - ${transferringMatch[2]}%`);
    }
    
    // Detect skipped files - update progress to show checking
    if (skippedMatch || checkingMatch) {
      if (!hasSeenProgress || lastProgress.percentage === 0) {
        const checkProgress = {
          transferred: 'Checking files...',
          percentage: 0,
          speed: 'Verifying...',
          eta: 'Almost done...'
        };
        lastProgress = checkProgress;
        pool.query('UPDATE transfers SET progress = $1 WHERE transfer_id = $2', [checkProgress, transfer.transfer_id]);
        broadcast({ type: 'transfer_progress', transferId: transfer.transfer_id, progress: checkProgress });
      }
      console.log(`[${transfer.transfer_id}] Checking/skipping files`);
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
      await pool.query(
        'UPDATE transfers SET status = $1, completed_at = CURRENT_TIMESTAMP, error = $2, progress = NULL WHERE transfer_id = $3',
        ['completed', completionNote, transfer.transfer_id]
      );
      broadcast({ type: 'transfer_complete', transferId: transfer.transfer_id, note: completionNote });
      console.log(`[${transfer.transfer_id}] ✅ Completed: ${completionNote}`);
      await notifyTransferComplete(transfer, userId, true);
    } else {
      let errorMessage = `Transfer failed (exit code ${code})`;
      const errorLines = errorOutput.split('\n').filter(line => 
        line.includes('ERROR') || line.includes('Failed') || line.includes('NOTICE')
      );
      if (errorLines.length > 0) {
        errorMessage = errorLines[0].substring(0, 200);
      }
      
      await pool.query(
        'UPDATE transfers SET status = $1, error = $2 WHERE transfer_id = $3',
        ['failed', errorMessage, transfer.transfer_id]
      );
      broadcast({ type: 'transfer_failed', transferId: transfer.transfer_id, error: errorMessage });
      await notifyTransferComplete(transfer, userId, false, errorMessage);
    }
  });
  
  rclone.on('error', async (err) => {
    clearInterval(timeoutCheck);
    activeTransfers.delete(transfer.transfer_id);
    const errorMessage = `Failed to start transfer: ${err.message}`;
    await pool.query(
      'UPDATE transfers SET status = $1, error = $2 WHERE transfer_id = $3',
      ['failed', errorMessage, transfer.transfer_id]
    );
    broadcast({ type: 'transfer_failed', transferId: transfer.transfer_id, error: errorMessage });
    await notifyTransferComplete(transfer, userId, false, errorMessage);
  });
}

// Daily report cron
setInterval(async () => {
  try {
    const now = new Date();
    if (now.getHours() !== 0 || now.getMinutes() > 5) return; // Run once daily at midnight
    
    const users = await pool.query(`
      SELECT u.id, u.username, ns.* 
      FROM users u 
      JOIN notification_settings ns ON u.id = ns.user_id 
      WHERE ns.email_enabled = true AND ns.daily_report = true
    `);
    
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
        await sendEmail(user, {
          subject: 'CloudKlone Daily Report',
          text: `Daily Transfer Report for ${now.toDateString()}\n\nCompleted: ${s.completed}\nFailed: ${s.failed}\nTotal: ${s.total}`
        });
      }
    }
  } catch (error) {
    console.error('Daily report error:', error);
  }
}, 5 * 60 * 1000); // Check every 5 minutes

// Calculate next run time based on interval
function calculateNextRun(interval, time = '00:00') {
  const now = new Date();
  const [hours, minutes] = time.split(':').map(Number);
  
  let next = new Date(now);
  next.setHours(hours || 0, minutes || 0, 0, 0);
  
  switch(interval) {
    case 'hourly':
      next = new Date(now.getTime() + 60 * 60 * 1000);
      break;
    case 'daily':
      if (next <= now) next.setDate(next.getDate() + 1);
      break;
    case 'weekly':
      if (next <= now) next.setDate(next.getDate() + 7);
      break;
    case 'monthly':
      if (next <= now) next.setMonth(next.getMonth() + 1);
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
        const nextRun = calculateNextRun(transfer.schedule_interval, '00:00');
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
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      
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
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, name)
      );
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
        last_run TIMESTAMP,
        next_run TIMESTAMP,
        enabled BOOLEAN DEFAULT true
      );
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
        notify_on_failure BOOLEAN DEFAULT true,
        notify_on_success BOOLEAN DEFAULT false,
        daily_report BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    const userCheck = await pool.query('SELECT COUNT(*) FROM users');
    if (parseInt(userCheck.rows[0].count) === 0) {
      const hash = await bcrypt.hash('admin', 10);
      await client.query(
        'INSERT INTO users (username, email, password_hash, is_admin) VALUES ($1, $2, $3, $4)',
        ['admin', 'admin@localhost', hash, true]
      );
      console.log('✓ Default admin user created (admin / admin)');
    }
  } finally {
    client.release();
  }
}

const PORT = process.env.PORT || 3001;

initDatabase()
  .then(() => {
    server.listen(PORT, '0.0.0.0', () => {
      console.log(`✓ CloudKlone server listening on 0.0.0.0:${PORT}`);
      console.log(`✓ WebSocket ready on ws://0.0.0.0:${PORT}/ws`);
    });
  })
  .catch((err) => {
    console.error('Failed to initialize database:', error);
    process.exit(1);
  });
