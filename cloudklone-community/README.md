# CloudKlone Community Edition

## What is Community Edition?

CloudKlone Community Edition is a **free, open-source** cloud data orchestration platform for personal use. It includes all core features needed to transfer and sync data between 40+ cloud storage providers.

### Perfect For:
- Individual users
- Homelab enthusiasts
- Personal backups
- Side projects
- Learning and experimentation

### Key Features

**Core Transfer Functionality**
- Copy and sync operations
- Support for 40+ cloud providers (AWS S3, Google Drive, Dropbox, OneDrive, SFTP, and more)
- Real-time transfer monitoring
- Progress tracking with speed and ETA
- Transfer history (30 days)

**Automation**
- Scheduled transfers (one-time or recurring)
- Hourly, daily, weekly, monthly schedules
- Automatic retries on failure

**Notifications**
- Webhook integrations (Slack, Discord, Teams)
- Daily email reports
- Real-time WebSocket updates

**User Interface**
- Professional dark/light theme
- Real-time dashboard statistics
- File browsing and testing tools
- Responsive design

**Today's Activity Dashboard**
- Active transfers count
- Completed today count
- Failed transfers count
- Total data transferred
- Average transfer speed

### Edition Limits

**Single User**
- Maximum 1 user account
- Perfect for personal use
- Admin access only

**History Retention**
- 30 days of transfer history
- Automatic cleanup of older records
- Sufficient for most personal needs

**No Audit Logs**
- Basic logging only
- No detailed audit trail
- Upgrade to Professional for compliance features

## Installation

### Prerequisites
- Docker and Docker Compose
- 4GB RAM minimum (8GB recommended)
- 20GB disk space minimum

### Quick Start

```bash
# Extract package
tar -xzf cloudklone-community-edition.tar.gz
cd cloudklone-community

# Start CloudKlone
docker-compose up -d

# Check status
docker-compose logs -f
```

### First Login

1. Open browser to `http://your-server-ip:80`
2. Default credentials:
   - Username: `admin`
   - Password: `admin123`
3. **Change password immediately** on first login

### Configuration

Edit `docker-compose.yml` to customize:

```yaml
environment:
  DATABASE_URL: postgresql://cloudklone_user:YOUR_PASSWORD@postgres:5432/cloudklone
  HTTP_PORT: 3001
  HTTPS_PORT: 3443
  EDITION: community  # Do not change
```

**Important:** Change the default PostgreSQL password!

## Upgrading to Professional

Need more features? Upgrade to Professional for:

- **Unlimited users** - Add your entire team
- **Full audit logging** - Complete compliance trail
- **Unlimited history** - Never lose transfer records
- **Priority support** - Email ticket support with SLA
- **Professional features** - Advanced monitoring and reporting

**Pricing:** $99/month

**Visit:** https://cloudklone.com/pricing

## Support

### Documentation
- [Installation Guide](docs/00-Installation.md)
- [Getting Started](docs/01-Getting-Started.md)
- [User Guides](docs/README.md)

### Community Support
- GitHub Issues: Report bugs and request features
- Community Forum: Ask questions and share tips
- Documentation: Comprehensive user guides included

### No Paid Support
Community Edition includes community support only. For professional support with SLA, upgrade to Professional Edition.

## What's Different from Professional/Enterprise?

| Feature | Community | Professional | Enterprise |
|---------|-----------|--------------|------------|
| **Users** | 1 user | Unlimited | Unlimited |
| **Audit Logs** | No | Yes | Yes |
| **History Retention** | 30 days | Unlimited | Unlimited |
| **Support** | Community | Email/Ticket | Priority + Phone |
| **RBAC** | No | No | Yes |
| **Multi-tenancy** | No | No | Yes |
| **AI Integration** | No | No | Yes |
| **Price** | FREE | $99/mo | $499+/mo |

## Features Included

All Community Edition features are **production-ready** and **fully functional**:

- Copy and sync between any supported providers
- Schedule automated transfers
- Monitor progress in real-time
- Browse files with built-in tools
- Get notified via webhooks or email
- Professional UI with dark mode
- Real-time dashboard statistics
- Secure credential storage
- SSL/TLS support

## License

CloudKlone Community Edition is open source software.

**License:** MIT License (or your chosen license)

**Free to use** for personal and commercial purposes.

## Getting Help

**Documentation First:**
Check the included documentation in the `docs/` folder for answers to common questions.

**Community Support:**
- Open GitHub issue for bugs
- Community forum for questions
- Documentation wiki for guides

**Upgrade for Support:**
Professional and Enterprise editions include dedicated support teams.

## Quick Commands

```bash
# Start CloudKlone
docker-compose up -d

# Stop CloudKlone
docker-compose down

# View logs
docker-compose logs -f

# Restart after changes
docker-compose restart

# Backup database
docker-compose exec postgres pg_dump -U cloudklone_user cloudklone > backup.sql
```

## Next Steps

1. **Read [Getting Started](docs/01-Getting-Started.md)** - Learn the basics
2. **Add your first remote** - Connect cloud storage
3. **Create a test transfer** - Move some files
4. **Set up a schedule** - Automate your backups
5. **Configure notifications** - Stay informed

## Frequently Asked Questions

**Q: Can I use this for my business?**
A: Yes! Community Edition is free for commercial use. For teams, consider Professional Edition.

**Q: What's the difference between Community and Professional?**
A: Professional adds unlimited users, audit logs, unlimited history, and paid support.

**Q: Can I upgrade later?**
A: Yes! Upgrade anytime. Your data and configuration are preserved.

**Q: Is my data secure?**
A: Yes! All credentials are encrypted, transfers use HTTPS, and you control the infrastructure.

**Q: Do I need to pay for cloud storage?**
A: CloudKlone is free, but you'll need accounts with cloud providers (AWS, Google, etc.) and may incur their fees.

---

**CloudKlone Community Edition** - Professional cloud data orchestration for everyone.

Enjoy!
