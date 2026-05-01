# Production Deployment Guide - ShopEasy E-Commerce Platform

## Pre-Deployment Security Checklist

### ✅ Environment Configuration
- [ ] Generate strong, unique `SESSION_SECRET` (min 32 characters)
  ```bash
  node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
  ```
- [ ] Set `NODE_ENV=production`
- [ ] Configure correct `COOKIE_DOMAIN` for your production domain
- [ ] Set `MONGODB_URI` to production MongoDB instance with authentication
- [ ] Enable MongoDB SSL/TLS connection
- [ ] Configure CORS origins for all legitimate frontend domains
- [ ] Set STRIPE_SECRET_KEY and other sensitive keys in environment variables
- [ ] Create `.env.production` file (never commit to repo)

### ✅ Database Security
- [ ] Enable MongoDB authentication with strong username/password
- [ ] Create separate database user for application with minimal permissions
- [ ] Enable MongoDB encryption at rest
- [ ] Configure SSL/TLS for MongoDB connection
- [ ] Set up automated backups (daily minimum)
- [ ] Test backup restoration procedure
- [ ] Enable audit logging for all database access
- [ ] Whitelist application server IP in MongoDB network access

### ✅ HTTPS/TLS Configuration
- [ ] Obtain SSL certificate from CA (Let's Encrypt recommended)
- [ ] Install certificate on production server
- [ ] Configure HSTS headers (verified in code ✓)
- [ ] Set `secure: true` for cookies in production
- [ ] Redirect all HTTP traffic to HTTPS
- [ ] Test SSL/TLS grade: https://www.ssllabs.com/ssltest/

### ✅ Application Security
- [ ] Review all environment variables are set correctly
- [ ] Verify rate limiting thresholds are appropriate
- [ ] Test all input validation edge cases
- [ ] Verify Helmet CSP policy doesn't block legitimate content
- [ ] Test session management with actual browser cookies
- [ ] Verify authentication flows in production environment
- [ ] Test password hashing with bcrypt salt rounds (10 recommended)

### ✅ Server Security
- [ ] Run application with least privileges (non-root user)
- [ ] Disable unnecessary server services
- [ ] Configure firewall rules (only allow 80, 443)
- [ ] Keep OS and dependencies updated
- [ ] Set up fail2ban for brute force protection
- [ ] Configure log rotation for application logs
- [ ] Disable SSH password authentication (use keys only)
- [ ] Set up process manager (PM2/systemd) for auto-restart

### ✅ Monitoring & Logging
- [ ] Set up centralized logging (ELK stack, CloudWatch, etc.)
- [ ] Configure alerts for security events
- [ ] Monitor login failures and account lockouts
- [ ] Track all API errors and exceptions
- [ ] Set up performance monitoring
- [ ] Configure log retention policy (min 90 days for security logs)
- [ ] Create dashboard for security metrics

### ✅ Incident Response
- [ ] Document incident response procedures
- [ ] Set up on-call escalation
- [ ] Create runbooks for common security issues
- [ ] Test backup restoration under time pressure
- [ ] Have rollback procedure ready
- [ ] Document database backup/restore procedures

## Deployment Steps

### 1. Pre-Deployment Testing
```bash
# Install dependencies
npm install

# Run security tests
npm run test:security

# Run full test suite
npm run test -- --coverage

# Check for vulnerabilities
npm audit

# Lint code
npm run lint

# Build/prepare for production
npm run build  # if applicable
```

### 2. Server Preparation
```bash
# Create non-root user
sudo useradd -m -s /bin/bash shopeasy

# Create application directory
sudo mkdir -p /opt/shopeasy
sudo chown shopeasy:shopeasy /opt/shopeasy
cd /opt/shopeasy

# Set up file permissions
sudo chmod 750 /opt/shopeasy
```

### 3. Application Deployment
```bash
# Clone repository
cd /opt/shopeasy
git clone <repository> .
git checkout <production-branch>

# Install production dependencies
npm install --production

# Set environment variables
sudo cp .env.production /opt/shopeasy/.env
sudo chown shopeasy:shopeasy /opt/shopeasy/.env
sudo chmod 600 /opt/shopeasy/.env
```

### 4. Process Manager Setup (PM2)
```bash
# Install PM2
sudo npm install -g pm2

# Create ecosystem.config.js
cat > ecosystem.config.js << EOF
module.exports = {
  apps: [{
    name: 'shopeasy',
    script: './app.js',
    instances: 'max',
    exec_mode: 'cluster',
    env: {
      NODE_ENV: 'production'
    },
    error_file: '/var/log/shopeasy/error.log',
    out_file: '/var/log/shopeasy/out.log',
    log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
    merge_logs: true
  }]
};
EOF

# Start with PM2
pm2 start ecosystem.config.js
pm2 save
pm2 startup

# Verify it's running
pm2 status
```

### 5. Nginx Reverse Proxy Configuration
```nginx
upstream shopeasy {
  server 127.0.0.1:3000;
}

server {
  listen 80;
  server_name shopeasy.example.com;
  return 301 https://$server_name$request_uri;
}

server {
  listen 443 ssl http2;
  server_name shopeasy.example.com;

  ssl_certificate /etc/letsencrypt/live/shopeasy.example.com/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/shopeasy.example.com/privkey.pem;
  
  # SSL Configuration
  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_ciphers HIGH:!aNULL:!MD5;
  ssl_prefer_server_ciphers on;
  
  # Security Headers
  add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
  add_header X-Frame-Options "DENY" always;
  add_header X-Content-Type-Options "nosniff" always;
  add_header X-XSS-Protection "1; mode=block" always;
  
  # Logging
  access_log /var/log/nginx/shopeasy_access.log combined buffer=32k flush=5s;
  error_log /var/log/nginx/shopeasy_error.log warn;
  
  # Rate limiting
  limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;
  limit_req /api/ zone=api_limit burst=20 nodelay;
  
  # Proxy settings
  proxy_pass http://shopeasy;
  proxy_http_version 1.1;
  proxy_set_header Upgrade $http_upgrade;
  proxy_set_header Connection 'upgrade';
  proxy_set_header Host $host;
  proxy_set_header X-Real-IP $remote_addr;
  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  proxy_set_header X-Forwarded-Proto $scheme;
  proxy_cache_bypass $http_upgrade;
  
  # Timeouts
  proxy_connect_timeout 60s;
  proxy_send_timeout 60s;
  proxy_read_timeout 60s;
}
```

### 6. Database Setup
```bash
# Connect to MongoDB with admin credentials
mongo mongodb://admin:password@localhost:27017/admin

# Create application database user
db.createUser({
  user: "shopeasy_app",
  pwd: "strong-password-here",
  roles: [{
    role: "readWrite",
    db: "shopeasy"
  }]
})

# Verify user creation
db.getUser("shopeasy_app")

# Exit and test with app user
mongo -u shopeasy_app -p --authenticationDatabase shopeasy mongodb://localhost:27017/shopeasy
```

### 7. Backup Configuration
```bash
# Create backup script
sudo cat > /usr/local/bin/backup-shopeasy.sh << 'EOF'
#!/bin/bash
BACKUP_DIR="/backups/shopeasy"
DATE=$(date +%Y%m%d_%H%M%S)
mongodump -u shopeasy_app -p$MONGO_PASSWORD --authenticationDatabase shopeasy \
  --out $BACKUP_DIR/dump_$DATE
gzip -r $BACKUP_DIR/dump_$DATE
# Keep only last 30 days
find $BACKUP_DIR -name "dump_*" -mtime +30 -delete
EOF

sudo chmod +x /usr/local/bin/backup-shopeasy.sh

# Add to cron
sudo crontab -e
# Add: 0 2 * * * /usr/local/bin/backup-shopeasy.sh
```

### 8. Monitoring Setup
```bash
# Install Node monitoring
npm install pm2-plus

# Link PM2 to Plus account
pm2 plus

# Start monitoring
pm2 update
```

### 9. SSL/TLS Certificate Setup (Let's Encrypt)
```bash
# Install Certbot
sudo apt-get install certbot python3-certbot-nginx

# Get certificate
sudo certbot certonly --nginx -d shopeasy.example.com

# Auto-renewal
sudo certbot renew --dry-run
```

### 10. Firewall Configuration
```bash
# Enable UFW
sudo ufw enable

# Allow only necessary ports
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp  # SSH
sudo ufw allow 80/tcp  # HTTP
sudo ufw allow 443/tcp # HTTPS

# Verify
sudo ufw status
```

## Post-Deployment Verification

### Security Testing
```bash
# Test SSL/TLS configuration
curl -I https://shopeasy.example.com

# Verify security headers
curl -I https://shopeasy.example.com | grep -i "strict-transport"

# Test rate limiting
for i in {1..10}; do curl -i https://shopeasy.example.com/api/products; done

# Verify HTTPS redirect
curl -I http://shopeasy.example.com
```

### Health Checks
```bash
# Check application status
pm2 status

# Check MongoDB connection
curl https://shopeasy.example.com/api/health

# Verify logging
tail -f /var/log/shopeasy/error.log

# Check disk usage
df -h

# Check memory usage
free -m
```

### Performance Monitoring
- Monitor CPU usage (should be < 80%)
- Monitor memory usage (should have headroom)
- Monitor disk I/O
- Monitor database query performance
- Monitor response times
- Monitor error rates

## Security Updates & Maintenance

### Regular Tasks
- **Daily**: Review security logs, check system health
- **Weekly**: Verify backups, review error logs
- **Monthly**: Dependency updates, security patch management
- **Quarterly**: Full security audit, penetration testing

### Dependency Updates
```bash
# Check for vulnerabilities
npm audit

# Update packages
npm update

# Major version updates (test thoroughly first)
npm outdated

# After updates, run full test suite
npm test
```

### Certificate Renewal
- Let's Encrypt certificates expire after 90 days
- Certbot auto-renewal is configured
- Monitor renewal logs: `sudo journalctl -u certbot`

## Rollback Procedure

### In Case of Critical Issues
```bash
# Stop current version
pm2 stop shopeasy

# Revert to previous commit
git revert HEAD

# Reinstall dependencies if needed
npm install

# Restart
pm2 start ecosystem.config.js

# Verify
pm2 status
tail -f /var/log/shopeasy/error.log
```

## Disaster Recovery

### Database Restoration
```bash
# List available backups
ls /backups/shopeasy/

# Restore from backup
gunzip /backups/shopeasy/dump_20240101_120000.gz
mongorestore --uri="mongodb://shopeasy_app:password@localhost:27017/shopeasy" \
  --archive=/backups/shopeasy/dump_20240101_120000

# Verify restoration
mongo -u shopeasy_app -p --authenticationDatabase shopeasy
use shopeasy
db.users.count()
```

### System Recovery
1. Restore from system backup if available
2. Redeploy application from repository
3. Restore database from backup
4. Verify all systems are operational
5. Run security validation tests

## Compliance & Auditing

### Security Compliance Checklist
- [ ] Data encryption at rest (MongoDB encryption)
- [ ] Data encryption in transit (TLS 1.2+)
- [ ] Regular security updates applied
- [ ] Backup and recovery tested
- [ ] Access controls enforced
- [ ] Audit logging enabled
- [ ] Security monitoring active
- [ ] Incident response plan in place

### Audit Logging
- All authentication attempts logged
- All authorization decisions logged
- All data modifications logged
- All security events logged
- Logs retained for minimum 90 days

## Support & Escalation

For critical security issues:
1. Immediately stop accepting requests (optional, depends on issue)
2. Isolate affected systems
3. Preserve logs and evidence
4. Notify security team
5. Follow incident response plan
6. Document all actions
7. Post-incident review and improvements
