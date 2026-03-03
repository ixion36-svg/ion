# ION Security Assessment Report

**Assessment Date:** 2026-01-21
**Scope:** Web application penetration testing (code review + analysis)
**Application Version:** 0.1.0

---

## Executive Summary

The ION application demonstrates good security fundamentals with proper password hashing, parameterized queries, and RBAC implementation. However, several vulnerabilities and security improvements were identified that should be addressed before production deployment.

| Severity | Count |
|----------|-------|
| Critical | 1 |
| High | 3 |
| Medium | 4 |
| Low | 3 |

---

## Critical Findings

### 1. Server-Side Template Injection (SSTI) - CRITICAL

**Location:** `src/ion/engine/renderer.py:21-26`

**Issue:** The Jinja2 template engine is configured with `autoescape=False`, and user-controlled template content is rendered directly. This allows arbitrary code execution via SSTI payloads.

```python
self.env = Environment(
    loader=StringLoader(),
    autoescape=False,  # DANGEROUS
    trim_blocks=True,
    lstrip_blocks=True,
)
```

**Attack Vector:**
```
Template content: {{ ''.__class__.__mro__[1].__subclasses__() }}
```

**Impact:** Remote Code Execution (RCE) - An attacker with template:create permission can execute arbitrary Python code on the server.

**Recommendation:**
1. Use a sandboxed Jinja2 environment (`jinja2.sandbox.SandboxedEnvironment`)
2. Implement a whitelist of allowed template constructs
3. Consider using a safer templating engine for user content

---

## High Severity Findings

### 2. Missing CSRF Protection on State-Changing Operations - HIGH

**Location:** All POST/PUT/DELETE API endpoints

**Issue:** The application does not implement CSRF protection tokens. While `SameSite=strict` cookies provide some protection, they don't protect against subdomain attacks or users on older browsers.

**Affected Endpoints:**
- `POST /api/auth/login`
- `POST /api/auth/logout`
- `POST /api/users`
- `DELETE /api/users/{id}`
- `PUT /api/templates/{id}`
- All other state-changing endpoints

**Recommendation:**
1. Implement CSRF tokens using FastAPI middleware or a library like `starlette-csrf`
2. Add `X-Requested-With` header validation for AJAX requests
3. Consider implementing double-submit cookie pattern

### 3. OIDC State Parameter Not Validated - HIGH

**Location:** `src/ion/web/api.py:298-448` (oidc_callback)

**Issue:** The OIDC callback endpoint receives a `state` parameter but does not validate it against the state stored in the user's session. This makes the application vulnerable to CSRF attacks during the OAuth flow.

```python
async def oidc_callback(
    ...
    state: Optional[str] = None,  # Received but never validated!
    ...
):
```

**Recommendation:**
1. Store state in server-side session or signed cookie before redirect
2. Validate state matches on callback
3. Use cryptographically random state values

### 4. Open Redirect in OIDC Error Handling - HIGH

**Location:** `src/ion/web/api.py:315-320, 428-448`

**Issue:** Error messages from Keycloak or internal errors are directly embedded in redirect URLs without URL encoding, potentially allowing XSS via the error parameter.

```python
return RedirectResponse(
    url=f"/login?error={error_msg}",  # error_msg not URL-encoded
    status_code=302,
)
```

**Attack Vector:**
```
/api/auth/oidc/callback?error=<script>alert(1)</script>
```

**Recommendation:**
1. URL-encode all dynamic values in redirect URLs: `urllib.parse.quote(error_msg)`
2. Whitelist allowed error messages
3. Use flash messages stored server-side instead

---

## Medium Severity Findings

### 5. No Rate Limiting - MEDIUM

**Location:** Application-wide

**Issue:** No rate limiting is implemented on any endpoints, making the application vulnerable to:
- Brute force attacks on login
- Password spraying
- DoS attacks
- API abuse

**Recommendation:**
1. Implement rate limiting using `slowapi` or similar
2. Add specific limits for authentication endpoints (e.g., 5 attempts/minute)
3. Implement account lockout after failed attempts
4. Consider CAPTCHA for repeated failures

### 6. Timing Attack on User Enumeration - MEDIUM

**Location:** `src/ion/auth/service.py:59-74`

**Issue:** The login function has different code paths for "user not found" vs "invalid password", potentially allowing timing-based user enumeration.

```python
if user is None:
    self._log_failed_login(username, ip_address, "User not found")
    return None, None, "Invalid username or password"
# ... later
if not password_hasher.verify(password, user.password_hash):
    self._log_failed_login(username, ip_address, "Invalid password")
```

**Recommendation:**
1. Always perform a dummy password hash verification even when user doesn't exist
2. Ensure consistent response times for both scenarios

### 7. Session Token Not Rotated After Login - MEDIUM

**Location:** `src/ion/auth/service.py:76-86`

**Issue:** When using OIDC, if a user already has an active session and logs in again, the old session tokens remain valid. This can lead to session fixation-like issues.

**Recommendation:**
1. Invalidate all existing sessions on new login (or at least notify user)
2. Implement session rotation on privilege changes

### 8. Information Disclosure in Error Messages - MEDIUM

**Location:** Multiple API endpoints

**Issue:** Some error messages reveal internal implementation details:

```python
raise HTTPException(status_code=400, detail=str(e))  # Exposes exception details
```

**Recommendation:**
1. Use generic error messages for users
2. Log detailed errors server-side
3. Implement custom exception handlers

---

## Low Severity Findings

### 9. Cookie Secure Flag Hardcoded to False - LOW

**Location:** `src/ion/web/api.py:185, 422`

**Issue:** The session cookie `secure` flag is hardcoded to `False`:

```python
secure=False,  # Set to True in production with HTTPS
```

**Recommendation:**
1. Make this configurable via environment variable
2. Default to `True` or detect HTTPS automatically

### 10. Default Admin Credentials - LOW

**Location:** `src/ion/auth/service.py:469-494`

**Issue:** Default admin user is created with predictable credentials:
- Username: `admin`
- Password: `changeme`

While `must_change_password` is set, this is a known-weak default.

**Recommendation:**
1. Generate random initial password
2. Display password only once during setup
3. Or require password to be set via CLI/environment variable

### 11. Missing Security Headers - LOW

**Location:** `src/ion/web/server.py`

**Issue:** The application does not set security headers:
- `X-Content-Type-Options`
- `X-Frame-Options`
- `Content-Security-Policy`
- `Strict-Transport-Security`

**Recommendation:**
Add middleware to set security headers:
```python
from starlette.middleware import Middleware
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware

# Add headers middleware
```

---

## Positive Security Observations

### What's Done Well:

1. **Password Hashing:** Bcrypt with cost factor 12 - industry standard
2. **Session Tokens:** Using `secrets.token_urlsafe(32)` - cryptographically secure
3. **SQL Injection Protection:** SQLAlchemy ORM with parameterized queries throughout
4. **XSS Protection (Frontend):** Consistent use of `escapeHtml()` function
5. **RBAC Implementation:** Proper permission checks on all sensitive endpoints
6. **Audit Logging:** Comprehensive logging of security-relevant events
7. **Session Validation:** Proper expiration checking and user status verification
8. **Cookie Flags:** HttpOnly and SameSite=Strict properly set

---

## Remediation Priority

| Priority | Finding | Effort |
|----------|---------|--------|
| P1 | SSTI (Sandbox Jinja2) | Medium |
| P1 | OIDC State Validation | Low |
| P2 | CSRF Protection | Medium |
| P2 | Open Redirect Fix | Low |
| P2 | Rate Limiting | Medium |
| P3 | Timing Attack | Low |
| P3 | Session Rotation | Low |
| P3 | Error Message Cleanup | Low |
| P4 | Security Headers | Low |
| P4 | Secure Cookie Config | Low |
| P4 | Default Credentials | Low |

---

## Testing Commands

To verify some findings, you can test:

```bash
# Test SSTI (requires template:create permission)
# Create template with content: {{ config }}

# Test missing rate limiting
for i in {1..100}; do
  curl -X POST http://localhost:8000/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"wrong"}'
done

# Test OIDC open redirect
curl "http://localhost:8000/api/auth/oidc/callback?error=<script>alert(1)</script>"
```

---

## Conclusion

ION has a solid security foundation but requires remediation of the identified vulnerabilities before production deployment. The critical SSTI vulnerability should be addressed immediately, followed by the OIDC and CSRF issues. The codebase shows security-conscious development practices that can be built upon.

---

*Report generated by security assessment - 2026-01-21*
