/**
 * CloudKlone Edition Manager
 * 
 * Manages feature availability across Community, Professional, and Enterprise editions.
 */

const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

// Public key for license validation (embedded)
const PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwill_be_generated
-----END PUBLIC KEY-----`;

class EditionManager {
  constructor() {
    this.edition = process.env.EDITION || 'community';  // Default to enterprise for our packages
    this.licenseKey = process.env.LICENSE_KEY;
    this.features = null;
    this.initialized = false;
    this.licenseValid = false;
  }

  async initialize(pool) {
    if (this.initialized) return;
    
    this.pool = pool;
    
    // Ensure license table exists
    await this.ensureLicenseTable();
    
    // For now, skip license validation (all features enabled)
    this.licenseValid = true;
    
    // Set features based on edition
    await this.loadFeatures();
    
    this.initialized = true;
    console.log(`[Edition] Running CloudKlone ${this.edition.toUpperCase()}`);
    console.log(`[Edition] Features:`, Object.keys(this.features).filter(k => this.features[k] === true).join(', '));
  }

  async ensureLicenseTable() {
    const createTableQuery = `
      CREATE TABLE IF NOT EXISTS license_info (
        id SERIAL PRIMARY KEY,
        edition VARCHAR(50) NOT NULL,
        license_key TEXT,
        license_data JSONB,
        max_users INTEGER,
        features JSONB,
        expires_at TIMESTAMP,
        last_validated TIMESTAMP,
        is_valid BOOLEAN DEFAULT true,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `;
    
    await this.pool.query(createTableQuery);
    
    // Check if license exists
    const existing = await this.pool.query('SELECT * FROM license_info ORDER BY id DESC LIMIT 1');
    
    if (existing.rows.length === 0) {
      // Insert default license based on edition
      await this.createDefaultLicense();
    } else {
      this.licenseData = existing.rows[0];
    }
  }

  async createDefaultLicense() {
    const features = this.getDefaultFeatures();
    const maxUsers = this.getDefaultMaxUsers();
    
    await this.pool.query(
      `INSERT INTO license_info (edition, is_valid, max_users, features)
       VALUES ($1, true, $2, $3)`,
      [this.edition, maxUsers, JSON.stringify(features)]
    );
  }

  getDefaultFeatures() {
    const features = {
      // Community features (all editions have these)
      transfers: true,
      scheduling: true,
      webhooks: true,
      email_notifications: true,  // FIXED: underscore naming
      tests_queries: true,
      
      // Professional+ features
      audit_logs: false,  // FIXED: underscore naming
      unlimited_history: false,  // FIXED: underscore naming
      multi_user: false,
      
      // Enterprise features
      rbac: false,
      granular_permissions: false,  // FIXED: underscore naming
      compliance_reporting: false,  // FIXED: underscore naming
      log_export: false,  // FIXED: underscore naming
      custom_branding: false,  // FIXED: underscore naming
      multi_tenancy: false,
      multi_server: false,
      ai_integration: false
    };

    if (this.edition === 'professional' || this.edition === 'enterprise') {
      features.audit_logs = true;
      features.unlimited_history = true;
      features.multi_user = true;
      features.log_export = true;
    }

    if (this.edition === 'enterprise') {
      features.rbac = true;
      features.granular_permissions = true;
      features.compliance_reporting = true;
      features.custom_branding = true;
      features.multi_tenancy = false;  // v9 roadmap
      features.multi_server = false;   // v9 roadmap
      features.ai_integration = true;  // v8
    }

    return features;
  }

  getDefaultMaxUsers() {
    if (this.edition === 'community') return 1;
    if (this.edition === 'professional') return 999999; // Unlimited
    if (this.edition === 'enterprise') return 999999; // Unlimited
    return 1;
  }

  async loadFeatures() {
    const result = await this.pool.query('SELECT * FROM license_info ORDER BY id DESC LIMIT 1');
    
    if (result.rows.length > 0) {
      this.licenseData = result.rows[0];
      this.features = this.licenseData.features;
    } else {
      this.features = this.getDefaultFeatures();
    }
  }

  // Feature checks
  hasFeature(featureName) {
    if (!this.features) return false;
    return this.features[featureName] === true;
  }

  // Edition checks
  isCommunity() {
    return this.edition === 'community';
  }

  isProfessional() {
    return this.edition === 'professional';
  }

  isEnterprise() {
    return this.edition === 'enterprise';
  }

  // User limits
  getMaxUsers() {
    if (this.licenseData) return this.licenseData.max_users;
    return this.getDefaultMaxUsers();
  }

  async canCreateUser() {
    const result = await this.pool.query('SELECT COUNT(*) as count FROM users');
    const currentUsers = parseInt(result.rows[0].count);
    return currentUsers < this.getMaxUsers();
  }

  async getUserCount() {
    const result = await this.pool.query('SELECT COUNT(*) as count FROM users');
    return parseInt(result.rows[0].count);
  }

  // History retention
  getHistoryRetentionDays() {
    if (this.hasFeature('unlimited_history')) return null; // Unlimited
    return 30; // Community: 30 days
  }

  // Audit logs
  hasAuditLogs() {
    return this.hasFeature('audit_logs');
  }

  // RBAC
  hasRBAC() {
    return this.hasFeature('rbac');
  }

  // Multi-user
  hasMultiUser() {
    return this.hasFeature('multi_user');
  }

  // License info
  getLicenseInfo() {
    return null; // No license validation for now
  }

  // Edition info for frontend
  getEditionInfo() {
    return {
      edition: this.edition,
      features: this.features,
      limits: {
        maxUsers: this.getMaxUsers(),
        historyRetentionDays: this.getHistoryRetentionDays()
      },
      license: this.getLicenseInfo()
    };
  }

  // Error messages for blocked features
  getUpgradeMessage(feature) {
    const messages = {
      audit_logs: {
        feature: 'Audit logs',
        current: this.edition,
        upgrade: 'professional',
        message: 'Audit logs require Professional or Enterprise edition'
      },
      multi_user: {
        feature: 'Multiple users',
        current: this.edition,
        upgrade: 'professional',
        message: `User limit (${this.getMaxUsers()}) reached. Upgrade to Professional for unlimited users.`
      },
      rbac: {
        feature: 'Role-based access control',
        current: this.edition,
        upgrade: 'enterprise',
        message: 'RBAC requires Enterprise edition'
      },
      granular_permissions: {
        feature: 'Granular permissions',
        current: this.edition,
        upgrade: 'enterprise',
        message: 'Granular permissions require Enterprise edition'
      }
    };

    return messages[feature] || {
      feature: feature,
      current: this.edition,
      upgrade: 'enterprise',
      message: `This feature requires a higher edition`
    };
  }
}

// Singleton instance
const editionManager = new EditionManager();

module.exports = editionManager;
