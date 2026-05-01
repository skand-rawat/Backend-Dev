# Security Best Practices & Code Review Checklist

## Problem 1: E-Commerce Platform

### Security Best Practices for Development Team

#### 1. Authentication & Authorization
**Principles:**
- Always hash passwords using bcrypt with minimum salt rounds of 10
- Never store passwords in plain text or use weak hashing
- Implement role-based access control (RBAC) for all features
- Verify authorization on both client and server side
- Use secure session management with encrypted storage

**Implementation Checklist:**
- ✅ Bcrypt hashing with salt rounds: 10
- ✅ Password minimum length: 8 characters
- ✅ Strong password enforcement (consider requiring uppercase, numbers, symbols)
- ✅ Account lockout after 5 failed attempts
- ✅ Session encryption with MongoStore
- ✅ httpOnly and Secure cookies
- ✅ SameSite=Strict CSRF protection
- ✅ Role verification on protected routes

**When Adding New Features:**
```javascript
// ✅ GOOD: Check authentication and authorization
app.post('/api/admin/users', isAuthenticated, isAdmin, async (req, res) => {
  // Admin-only operation
});

// ❌ BAD: Relies only on frontend validation
app.post('/api/admin/users', async (req, res) => {
  if (req.body.isAdmin) {
    // Processing admin operation - VULNERABLE!
  }
});
```

#### 2. Input Validation & Sanitization
**Principles:**
- Validate all user input on the server side
- Sanitize input before storing or using in queries
- Use allowlist validation rather than blocklist
- Validate data types, formats, lengths, and ranges
- Never trust data from any external source

**Implementation Checklist:**
- ✅ Validator library for format validation
- ✅ Express-mongo-sanitize for NoSQL injection prevention
- ✅ DOMPurify for XSS sanitization
- ✅ Schema validation with Mongoose
- ✅ Manual validation for complex requirements
- ✅ Type checking for numeric values
- ✅ Length constraints on all strings
- ✅ Range checks on numeric values

**When Adding New Endpoints:**
```javascript
// ✅ GOOD: Comprehensive validation
app.post('/api/products', async (req, res) => {
  const { price, name, category } = req.body;
  
  // Type validation
  if (typeof price !== 'number') {
    return res.status(400).json({ error: 'Price must be a number' });
  }
  
  // Range validation
  if (price <= 0 || price > 999999) {
    return res.status(400).json({ error: 'Invalid price' });
  }
  
  // Format validation
  if (!['electronics', 'gadgets', 'accessories'].includes(category)) {
    return res.status(400).json({ error: 'Invalid category' });
  }
  
  // Length validation
  if (name.length > 100) {
    return res.status(400).json({ error: 'Name too long' });
  }
});

// ❌ BAD: No validation
app.post('/api/products', async (req, res) => {
  const product = new Product(req.body);
  await product.save();
});
```

#### 3. Protection Against Common Attacks

##### XSS (Cross-Site Scripting)
```javascript
// ✅ GOOD: Sanitize before storage
reviewSchema.pre('save', function(next) {
  this.content = DOMPurify.sanitize(this.content, { 
    ALLOWED_TAGS: [],
    ALLOWED_ATTR: []
  });
  next();
});

// ✅ GOOD: Escape in output (framework-dependent)
// Most frameworks auto-escape in templates

// ❌ BAD: Store unsanitized user input
const review = new Review({
  content: req.body.content // Directly from user
});

// ❌ BAD: Direct HTML rendering
res.send(`<div>${userContent}</div>`);
```

##### MongoDB Injection
```javascript
// ✅ GOOD: Use mongoSanitize middleware
app.use(mongoSanitize());

// ✅ GOOD: Validate and escape before use
const searchTerm = validator.escape(req.query.search);
Product.find({ name: new RegExp(searchTerm, 'i') });

// ❌ BAD: Direct query construction
Product.find({ $where: userInput });

// ❌ BAD: No sanitization
Product.find({ name: userInput });
```

##### CSRF (Cross-Site Request Forgery)
```javascript
// ✅ GOOD: Use csurf middleware
app.use(csrf({ cookie: false }));

// ✅ GOOD: Verify CSRF token on state-changing requests
app.post('/api/transfer', verifyCsrfToken, async (req, res) => {
  // Token automatically verified by middleware
});

// ❌ BAD: No CSRF protection
app.post('/api/transfer', async (req, res) => {
  // Vulnerable to CSRF attacks
});
```

#### 4. Session Management
**Best Practices:**
- Store sessions in persistent storage (MongoDB), not memory
- Use encrypted session storage
- Set appropriate session timeouts
- Use secure, httpOnly cookies
- Implement session invalidation on logout
- Use secure session names (not default "connect.sid")

**Configuration:**
```javascript
// ✅ GOOD: Production-ready session
app.use(session({
  store: new MongoStore({ mongoUrl: MONGODB_URI }),
  secret: process.env.SESSION_SECRET, // Strong, unique secret
  resave: false,
  saveUninitialized: false,
  name: 'sessionId', // Custom name
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 30 * 60 * 1000 // 30 minutes
  }
}));
```

#### 5. Rate Limiting & DoS Protection
**Principles:**
- Implement rate limiting on all public endpoints
- Use stricter limits for authentication endpoints
- Track by IP address and/or user ID
- Return appropriate 429 status codes
- Include rate limit headers in responses

**When Adding New Endpoints:**
```javascript
// ✅ GOOD: Different limits for different operations
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 });
const apiLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });

app.post('/api/auth/login', authLimiter, loginHandler);
app.get('/api/products', apiLimiter, searchHandler);

// ❌ BAD: Same limit for all requests
app.use(rateLimit({ windowMs: 60 * 1000, max: 1000 }));
```

#### 6. Error Handling & Logging
**Principles:**
- Never expose sensitive information in error messages
- Log all security events
- Use appropriate HTTP status codes
- Implement proper error handling middleware
- Monitor and alert on suspicious patterns

**Implementation:**
```javascript
// ✅ GOOD: Generic error in production
app.use((err, req, res, next) => {
  const isDev = process.env.NODE_ENV === 'development';
  res.status(err.status || 500).json({
    error: isDev ? err.message : 'An error occurred'
  });
});

// ❌ BAD: Exposed sensitive information
app.use((err, req, res, next) => {
  res.status(500).json({
    error: err.message, // Could expose database details
    query: err.query,   // Exposes query structure
    stack: err.stack    // Security risk
  });
});
```

#### 7. Security Headers
**All Endpoints Should Have:**
```
✅ Content-Security-Policy: Strict policy to prevent script injection
✅ X-Frame-Options: DENY to prevent clickjacking
✅ X-Content-Type-Options: nosniff to prevent MIME sniffing
✅ Strict-Transport-Security: Force HTTPS
✅ Referrer-Policy: Control referrer information
✅ X-XSS-Protection: Additional XSS protection
```

#### 8. Data Protection
**Principles:**
- Encrypt sensitive data at rest
- Use TLS for data in transit
- Implement proper access controls
- Encrypt backups
- Implement secure deletion for sensitive data

**For E-Commerce:**
```javascript
// ✅ TODO: Encrypt sensitive fields
// - Credit card data (tokenize with Stripe instead)
// - Personal identification numbers
// - Medical information (if applicable)

// ✅ GOOD: Use Stripe tokenization
app.post('/api/payment', async (req, res) => {
  const token = req.body.stripeToken;
  // Never store raw card data
});
```

#### 9. Dependency Management
**Best Practices:**
- Regularly update dependencies
- Use npm audit to check for vulnerabilities
- Review security advisories
- Pin specific versions in production
- Automate dependency scanning in CI/CD

**Regular Tasks:**
```bash
# Check for vulnerabilities
npm audit

# Update dependencies
npm update

# Major updates (test thoroughly)
npm outdated

# Automate in CI/CD pipeline
```

#### 10. Testing & Code Review
**Security Testing Checklist:**
- [ ] Authentication tests (valid/invalid credentials)
- [ ] Authorization tests (user/admin separation)
- [ ] Input validation tests (boundary cases)
- [ ] XSS prevention tests
- [ ] CSRF protection tests
- [ ] Rate limiting tests
- [ ] Session security tests
- [ ] Error handling tests (no information disclosure)
- [ ] SQL/NoSQL injection tests
- [ ] CORS misconfiguration tests

---

## Code Review Checklist for E-Commerce Applications

### Authentication & Sessions
- [ ] Passwords are hashed with bcrypt (salt rounds ≥ 10)
- [ ] Session data is stored server-side in persistent storage
- [ ] Session cookies have httpOnly, Secure, and SameSite flags
- [ ] Session timeout is appropriate (not too long, not too short)
- [ ] Password reset tokens have expiration times
- [ ] Failed login attempts are tracked and rate limited
- [ ] No hardcoded credentials or secrets in code
- [ ] JWT tokens (if used) are properly validated on every request

### Authorization
- [ ] Role-based access control is consistently applied
- [ ] Admin routes check for admin role before processing
- [ ] Users can only access their own data
- [ ] Authorization is checked on server-side (not just frontend)
- [ ] Permission checks are performed at the beginning of route handlers
- [ ] No implicit trust in user-supplied role information

### Input Validation
- [ ] All user inputs are validated on server-side
- [ ] Data types are validated (string, number, boolean, array)
- [ ] Numeric values have range checks
- [ ] Strings have length constraints
- [ ] File uploads are validated (type, size, content)
- [ ] Regular expressions use proper escaping
- [ ] Validation errors don't expose system details
- [ ] No eval() or similar dangerous functions with user input

### XSS Prevention
- [ ] User-generated content is sanitized before display
- [ ] DOMPurify or similar sanitizer is used for HTML content
- [ ] All output is properly escaped
- [ ] Content Security Policy headers are configured
- [ ] Dangerous HTML attributes (onclick, onerror) are removed
- [ ] JavaScript URLs are prevented (javascript://)
- [ ] Data attributes are validated

### NoSQL/SQL Injection
- [ ] mongoSanitize middleware is applied
- [ ] User input is not directly used in query construction
- [ ] Query operators ($where, $ne, etc.) are not passed user input
- [ ] String inputs are escaped or parameterized
- [ ] Regex patterns use escaped user input
- [ ] Database queries use helper libraries

### CSRF Protection
- [ ] CSRF middleware (csurf) is implemented
- [ ] CSRF tokens are validated on all state-changing requests (POST, PUT, DELETE)
- [ ] SameSite cookie flag is set to 'Strict' or 'Lax'
- [ ] Token generation and validation is correct
- [ ] Exemptions for CSRF (if any) are clearly documented

### Security Headers
- [ ] Helmet.js or equivalent is configured
- [ ] CSP headers are set with strict policy
- [ ] X-Frame-Options is set to 'DENY'
- [ ] X-Content-Type-Options is set to 'nosniff'
- [ ] HSTS header is present in production
- [ ] Referrer-Policy is configured
- [ ] CORS headers are restrictive

### Rate Limiting
- [ ] Authentication endpoints are rate limited (5-10 attempts per 15 min)
- [ ] API endpoints are rate limited (100+ per 15 min)
- [ ] Search/resource endpoints are rate limited appropriately
- [ ] Rate limiting returns 429 status code
- [ ] Rate limit headers are included in responses
- [ ] Legitimate traffic isn't blocked by rate limits

### Error Handling
- [ ] Errors don't expose sensitive information (database details, file paths)
- [ ] Stack traces are hidden in production
- [ ] All exceptions are caught and handled
- [ ] Error responses use generic messages in production
- [ ] Logging of errors doesn't log sensitive data
- [ ] HTTP status codes are used correctly (4xx for client, 5xx for server)

### Logging & Monitoring
- [ ] Security events are logged (login, access denied, validation failures)
- [ ] Sensitive data is not logged (passwords, tokens, card numbers)
- [ ] Log retention policy is implemented (90+ days for security logs)
- [ ] Logs are centralized and monitored
- [ ] Alerts are configured for suspicious activity
- [ ] Failed login attempts trigger alerts after threshold

### Configuration & Secrets
- [ ] No secrets are hardcoded in source code
- [ ] Secrets are loaded from environment variables
- [ ] .env files are in .gitignore
- [ ] Different secrets for different environments (dev, staging, prod)
- [ ] Secrets are rotated regularly
- [ ] Secret management tool is used (for teams)

### Database Security
- [ ] Database uses authentication (username/password)
- [ ] Database user has minimal required permissions
- [ ] Database connections use SSL/TLS
- [ ] Connection strings are not logged
- [ ] Backups are encrypted
- [ ] Backup retention policy is documented

### API Security
- [ ] API uses HTTPS only
- [ ] CORS is configured to allow specific origins only
- [ ] API endpoints have versioning (/api/v1/)
- [ ] Sensitive data is not exposed in API responses
- [ ] API documentation doesn't contain credentials

### Business Logic
- [ ] Price validation prevents negative or excessive prices
- [ ] Quantity validation prevents invalid stock levels
- [ ] Status transitions are validated (correct state machine)
- [ ] Duplicate checks prevent data integrity issues
- [ ] Calculations are done server-side (not trusted from client)
- [ ] Transaction operations use proper database transactions

### Code Quality
- [ ] Code follows consistent style and conventions
- [ ] Functions are single-responsibility
- [ ] Sensitive operations are in separate modules
- [ ] No hardcoded values that should be configurable
- [ ] Comments explain security-critical decisions
- [ ] Dependencies are from official, trusted sources

### Testing
- [ ] Unit tests cover validation logic
- [ ] Integration tests cover authentication flows
- [ ] Security tests cover common vulnerabilities
- [ ] Tests verify error handling doesn't leak information
- [ ] Tests verify rate limiting works correctly
- [ ] Test data doesn't contain real sensitive information

### Deployment
- [ ] Production environment variables are set correctly
- [ ] Application runs with minimal required privileges
- [ ] HTTPS is enforced in production
- [ ] Application uses process manager for reliability
- [ ] Logs are rotated and retained appropriately
- [ ] Monitoring and alerts are configured

---

## Review Template for E-Commerce Security

```
## Security Review Checklist

**Reviewer:** ___________________  
**Date:** ___________________  
**Component/Feature:** ___________________

### Critical Issues Found:
- [ ] None
- [ ] Issues found (list below)

### Medium Issues Found:
- [ ] None
- [ ] Issues found (list below)

### Low/Info Issues Found:
- [ ] None
- [ ] Issues found (list below)

### Authentication & Authorization
- [ ] Properly authenticated? ✓/✗
- [ ] Properly authorized? ✓/✗
- [ ] Comments: _____________________

### Input Validation
- [ ] All inputs validated? ✓/✗
- [ ] Server-side validation? ✓/✗
- [ ] Comments: _____________________

### XSS Prevention
- [ ] Content sanitized? ✓/✗
- [ ] No dangerous patterns? ✓/✗
- [ ] Comments: _____________________

### Injection Prevention
- [ ] No SQL/NoSQL injection? ✓/✗
- [ ] Proper escaping? ✓/✗
- [ ] Comments: _____________________

### CSRF Protection
- [ ] CSRF tokens used? ✓/✗
- [ ] SameSite cookies set? ✓/✗
- [ ] Comments: _____________________

### Error Handling
- [ ] No information disclosure? ✓/✗
- [ ] Proper logging? ✓/✗
- [ ] Comments: _____________________

### Overall Assessment:
- [ ] Approved
- [ ] Approved with minor fixes
- [ ] Requires revision
- [ ] Rejected

**Comments:** _____________________

**Approved By:** ___________________
```

## Security Training Topics for Team

1. **OWASP Top 10** - Common web vulnerabilities and mitigations
2. **Secure Coding Practices** - Writing security-first code
3. **Authentication & Authorization** - Proper implementation patterns
4. **Input Validation** - Common pitfalls and best practices
5. **Cryptography Basics** - Hashing, encryption, key management
6. **SQL/NoSQL Injection** - How to prevent and test for
7. **XSS Attacks** - Prevention techniques and testing
8. **CSRF Attacks** - Protection mechanisms
9. **Security Headers** - Purpose and configuration
10. **Dependency Management** - Vulnerability scanning and updates

## Resources

- [OWASP Top 10](https://owasp.org/Top10/)
- [OWASP Cheat Sheets](https://cheatsheetseries.owasp.org/)
- [Node.js Security Best Practices](https://nodejs.org/en/docs/guides/security/)
- [Express Security](https://expressjs.com/en/advanced/best-practice-security.html)
- [NPM Security](https://docs.npmjs.com/about-npm-audit)
