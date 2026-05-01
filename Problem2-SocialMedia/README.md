# Problem 2: ConnectHub - Social Media API Security

## Vulnerability Analysis

### Identified Vulnerabilities

1. **Private Message Access (Authorization Bypass)**
   - Risk Level: CRITICAL
   - Impact: Complete privacy breach, data theft

2. **XSS in Posts (Stored XSS)**
   - Risk Level: CRITICAL
   - Impact: Account takeover, malware distribution

3. **Bio HTML Formatting Issues (XSS)**
   - Risk Level: HIGH
   - Impact: Page breakage, XSS attacks

4. **Email Validation Missing (Input Validation)**
   - Risk Level: MEDIUM
   - Impact: Invalid registrations, account hijacking

5. **Profile Picture Redirect (Open Redirect)**
   - Risk Level: MEDIUM
   - Impact: Phishing attacks, malware delivery

6. **Infinite Session Duration (Session Management)**
   - Risk Level: HIGH
   - Impact: Session hijacking, unauthorized access

---

## Implementation

