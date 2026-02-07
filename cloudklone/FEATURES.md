# CloudKlone Feature Reference

## Platform Overview

CloudKlone is an enterprise data transfer orchestration platform that provides centralized control, security, and visibility for multi-cloud data operations. Built on rclone's transfer engine, CloudKlone adds the control plane, security, and operational capabilities required for enterprise deployment.

---

## Core Platform Capabilities

### Centralized Transfer Orchestration

**Multi-Provider Support:**
- Amazon S3 and S3-compatible storage (Wasabi, MinIO, DigitalOcean Spaces)
- Cloudflare R2 with bucket-specific token support
- Backblaze B2
- Google Cloud Storage
- Azure Blob Storage
- Dropbox and Google Drive
- SFTP with SSH host key verification
- 40+ providers via rclone backend

**Transfer Operations:**
- **Copy:** Duplicate files from source to destination (preserves source)
- **Sync:** Make destination identical to source (removes extra files)
- Real-time progress monitoring with transfer rate and ETA
- Automatic retry logic with exponential backoff (3 attempts)
- Smart credential error detection (no retry on authentication failures)
- Transfer history with completion status and error details

**Transfer Lifecycle Management:**
- Queue management for concurrent transfers
- Automatic cancellation of stuck transfers (10+ minutes without progress)
- Transfer ownership and access control
- Complete audit trail of all transfer operations

---

### Enterprise Security

**Authentication & Authorization:**
- JWT token-based authentication (24-hour expiry)
- Forced password change on first admin login
- Bcrypt password hashing (10 rounds)
- Role-based access control (RBAC) with four permission tiers
- Group-based permission management
- Session management and automatic token refresh

**Data Protection:**
- HTTPS by default with auto-generated self-signed certificates
- AES-256 encryption for stored cloud provider credentials
- Automatic SFTP password obscuring via rclone
- SSH host key verification for SFTP connections (no insecure skipping)
- Secure credential storage in encrypted database columns

**SSH Host Key Management:**
- Automatic ssh-keyscan on SFTP remote creation
- Per-remote host key storage and verification
- Admin panel for viewing all SSH host keys
- Rescan capability when server IP changes
- Clear and re-verify for security updates

**Network Security:**
- HTTP to HTTPS automatic redirect (port 80 → 443)
- Configurable port mapping
- Support for reverse proxy deployment
- Ready for Let's Encrypt integration

---

### Role-Based Access Control

**Permission Tiers:**

**Admin:**
- Full system access
- User and group management
- SSH host key management
- System configuration
- View all transfers and audit logs

**Power User:**
- Create copy and sync operations
- Manage own transfers
- Delete own transfers
- Create and manage remotes
- View own audit logs

**Operator:**
- Create copy operations only (no sync)
- View transfer status
- Cannot delete transfers
- Cannot manage remotes
- Limited configuration access

**Viewer:**
- Read-only access to transfers
- View transfer history
- No creation or modification capabilities
- Cannot access sensitive configuration

**Group Management:**
- Assign users to groups
- Group-level permission inheritance
- Bulk user management
- Group-based remote sharing

---

### Operational Intelligence

**Real-Time Monitoring:**
- Live transfer progress via WebSocket
- Transfer rate and bandwidth utilization
- Files transferred and bytes moved
- Estimated time to completion
- Active transfer queue visibility

**Historical Analytics:**
- Complete transfer history
- Success/failure rates
- Transfer duration tracking
- Error pattern analysis
- Per-user activity metrics

**Audit Logging:**
- All user actions logged with timestamp
- IP address and user agent tracking
- Resource-specific audit trails
- Compliance-ready audit exports
- Searchable audit log interface

**Logged Actions:**
- Authentication (login, logout, password changes)
- User management (create, update, delete)
- Group management (create, delete)
- Remote operations (create, update, delete, test)
- Transfer operations (create, delete, schedule)
- SSH host key management (scan, rescan, clear)
- Permission changes and access denials

---

### Workflow Automation

**Scheduled Transfers:**
- **One-time scheduling:** Execute transfer at specific date/time
- **Recurring schedules:** Hourly, daily, weekly, monthly intervals
- Time-zone aware scheduling (UTC-based with local display)
- Automatic execution via cron job
- Next run time calculation and display
- Schedule modification and deletion
- Enable/disable scheduled transfers

**Automatic Retry Logic:**
- Up to 3 automatic retry attempts on failure
- Exponential backoff delay (5s, 10s, 20s)
- Intelligent retry skip for credential errors
- Retry count tracking and display
- Manual retry capability

**Recurring Transfer Management:**
- Failed recurring transfers remain scheduled
- Automatic retry at next scheduled interval
- Transfer ownership and visibility controls
- Enable/disable without deletion

---

### Integration & Notifications

**Email Notifications:**
- SMTP integration with TLS support
- Configurable sender and recipient addresses
- Success and failure notifications
- Daily summary reports
- Custom notification preferences per user

**Webhook Integrations:**
- Slack formatted block messages
- Microsoft Teams MessageCard format
- Discord rich embeds with color coding
- Generic JSON webhooks for custom integrations
- Test webhook functionality
- Payload includes transfer details and error information

**Notification Triggers:**
- Transfer completion (success)
- Transfer failure
- Daily activity summary
- Configurable per-user preferences

---

### Administrative Tools

**User Management Console:**
- Create, edit, and delete users
- Password reset functionality
- Admin privilege assignment
- Group membership management
- User activity monitoring

**SSH Host Key Administration:**
- View all SFTP remotes with host keys
- Display key fingerprints and host information
- Rescan host keys on server changes
- Clear host keys for security updates
- Automatic known_hosts file management

**System Tools:**
- Cancel all stuck transfers
- Database health monitoring
- Configuration backup and restore
- Audit log export
- System status dashboard

**Remote Management:**
- Centralized remote configuration storage
- Test connection before saving
- Update credentials without recreating remote
- Delete remotes with cascading cleanup
- Remote sharing between users

---

## Technical Architecture

### Control Plane

**API Layer:**
- RESTful API design
- JWT authentication on all endpoints
- WebSocket for real-time updates
- Rate limiting and request validation
- Comprehensive error handling

**Orchestration Engine:**
- Transfer queue management
- Concurrent transfer execution
- Progress monitoring and statistics collection
- Automatic cleanup of completed transfers
- Timeout detection and handling

**Metadata Store:**
- PostgreSQL 16 for reliability
- Encrypted credential storage
- Audit log retention
- Configuration versioning
- User and group management

### Data Plane

**Transfer Execution:**
- Rclone 1.x backend for actual transfers
- Per-user rclone configuration files
- SSH known_hosts per-user isolation
- Automatic flag injection based on provider type
- Support for S3-compatible service variations

**Progress Monitoring:**
- Real-time statistics parsing
- Multi-line stats handling for Cloudflare R2
- Percentage calculation and ETA
- Transfer rate monitoring
- Error detection and reporting

---

## Deployment Options

### Standard Deployment

**Docker Compose:**
- Single-command deployment
- Automatic database initialization
- Persistent volumes for data retention
- Health checks and restart policies
- Container networking isolation

**Port Configuration:**
- Port 80: HTTP (redirects to HTTPS)
- Port 443: HTTPS (primary access)
- Configurable port mapping

**Volume Management:**
- postgres_data: Database persistence
- rclone_config: Transfer configurations
- ssl_certs: Certificate storage
- ssh_keys: SSH host key storage

### Production Considerations

**SSL Certificate Options:**
- Auto-generated self-signed (default)
- Let's Encrypt with reverse proxy
- Custom certificate deployment
- Certificate renewal automation

**High Availability:**
- Database backup and restore procedures
- Configuration export/import
- Credential backup with encryption keys
- Audit log retention policies

**Scalability:**
- Single-node deployment (current)
- Horizontal scaling ready (control/data plane separation)
- Database connection pooling
- Transfer queue management

---

## Security Features

### Defense in Depth

**Network Layer:**
- HTTPS mandatory (no HTTP fallback after redirect)
- TLS 1.2+ for all connections
- Configurable certificate validation

**Application Layer:**
- JWT token expiration and validation
- Password complexity enforcement (minimum 6 characters)
- Forced password change for default credentials
- Session timeout and management

**Data Layer:**
- AES-256 credential encryption
- Bcrypt password hashing
- Encrypted database columns
- Secure key generation and storage

**Audit & Compliance:**
- Complete action logging
- IP address and user agent tracking
- Timestamp precision to milliseconds
- Immutable audit records
- Export capability for compliance reporting

---

## Provider-Specific Features

### Cloudflare R2

- Bucket-specific token support
- Automatic --s3-no-check-bucket flag injection
- Multi-line statistics parsing
- Endpoint validation and display
- Graceful handling of limited token permissions

### SFTP

- Automatic SSH host key scanning
- Per-remote host key storage
- Skip symbolic links automatically
- Disable modification time setting
- Password auto-obscuring via rclone

### Amazon S3 / S3-Compatible

- Region detection and validation
- Endpoint URL customization
- Bucket-level operations
- Server-side copy for same-bucket transfers
- Support for path-style and virtual-hosted requests

### Backblaze B2

- Application key authentication
- Bucket ID and name handling
- B2-specific error handling
- Lifecycle policy awareness

---

## Browser Compatibility

**Supported Browsers:**
- Chrome 90+
- Firefox 88+
- Safari 14+
- Edge 90+

**Required Features:**
- JavaScript enabled
- WebSocket support
- Local storage
- Fetch API

---

## System Requirements

**Minimum:**
- 2GB RAM
- 2 CPU cores
- 20GB disk space
- Docker 20.10+
- Docker Compose 1.29+

**Recommended:**
- 4GB RAM
- 4 CPU cores
- 50GB+ disk space (for audit logs)
- SSD storage for database

**Operating System:**
- Ubuntu 20.04+ (recommended)
- Debian 11+
- CentOS 8+
- Any Linux with Docker support

---

## Monitoring & Observability

**Built-in Monitoring:**
- Active transfer count
- Transfer success/failure rates
- User activity metrics
- Remote connection health
- Database connection status

**Log Output:**
- Structured logging format
- Log levels: [OK], [ERROR], [WARNING], [INFO]
- Transfer lifecycle events
- Authentication events
- System health indicators

**Metrics Available:**
- Total transfers executed
- Average transfer duration
- Success rate percentage
- Active user count
- Remote count by provider type

---

## Upgrade Path

**Version Compatibility:**
- Database migrations automatic
- Configuration format versioning
- Backward-compatible API
- Rolling update support

**Data Preservation:**
- All user accounts preserved
- Remote configurations retained
- Transfer history maintained
- Audit logs kept indefinitely
- Encryption keys persisted

---

## Known Limitations

**Current Version:**
- Single-node deployment only
- No built-in load balancing
- Manual SSL certificate renewal
- Local filesystem limited to container
- No S3 multipart upload configuration
- No bandwidth limiting per transfer

**Planned Enhancements:**
- Multi-node support with shared state
- Built-in Let's Encrypt automation
- Transfer bandwidth limits
- Advanced scheduling (cron expressions)
- Transfer templates
- Cost estimation and tracking

---

## Support & Resources

**Documentation:**
- README.md - Quick start guide
- DEPLOYMENT-GUIDE.md - Complete reference
- RELEASE-NOTES.md - Version changelog

**Troubleshooting:**
- See DEPLOYMENT-GUIDE.md troubleshooting section
- Check audit logs for permission issues
- Review container logs for system errors
- Verify provider credentials independently

**Community:**
- File issues for bug reports
- Feature requests welcome
- Contributions encouraged
- Documentation improvements appreciated
