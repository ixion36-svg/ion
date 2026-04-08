# ION Security Assessment Report

**Assessment Date:** 2026-04-07 (updated from 2026-01-21 original)
**Application Version:** 0.9.43
**Scope:** Web application security review

---

## Executive Summary

ION demonstrates strong security fundamentals with proper password hashing (bcrypt), parameterized queries (SQLAlchemy ORM), sandboxed template rendering, RBAC with 7-tier role hierarchy, and rate limiting on auth endpoints. Circuit breakers prevent cascading failures from external service outages.

| Severity | Original (v0.1.0) | Current (v0.9.43) |
|----------|-------------------|-------------------|
| Critical | 1 | **0 (fixed)** |
| High | 3 | **0 (fixed)** |
| Medium | 4 | **2 remaining** |
| Low | 3 | **3 remaining** |

---

## Fixed Since Original Assessment

### FIXED: SSTI (Critical) — v0.3.0
Template engine changed to `SandboxedEnvironment`. User content is rendered in a restricted sandbox that blocks access to `__class__`, `__globals__`, etc.

### FIXED: Open Redirect on Login — v0.9.34
Login redirect now validates that the target is a relative path (`starts_with('/')`, no `//`, no `://`).

### FIXED: ES System Index Access — v0.9.34
Discover page blocks queries against `.kibana`, `.security`, and other system indices.

### FIXED: File Upload Size Limit — v0.9.34
50MB upload cap enforced on all file upload endpoints.

### FIXED: Kibana Multi-Alert Attachment — v0.9.34
Sequential attachment with version conflict handling.

---

## Current Findings

### Medium

**M1: CSP `unsafe-inline` for scripts**
Inline event handlers in templates require `unsafe-inline` in Content-Security-Policy. Mitigated by DOMPurify sanitization on all user-generated HTML content. Full CSP hardening would require refactoring all onclick handlers to addEventListener.

**M2: SIEM webhook export lacks SSRF validation**
The webhook export feature accepts user-provided URLs. While authenticated (requires integration:manage permission), the URLs are not validated against internal networks. Add SSRF protection (block private IP ranges) before enabling webhooks in production.

### Low

**L1: Default admin password fallback**
If `ION_ADMIN_PASSWORD` is not set, falls back to `changeme`. Mitigated: startup config validation now warns about weak passwords. `must_change_password` is set for default passwords.

**L2: `cookie_secure` defaults to false**
Session cookies don't have the `Secure` flag unless `ION_COOKIE_SECURE=true`. Appropriate for HTTP development but should be enabled behind TLS in production.

**L3: `python-jose` dependency**
JWT library is unmaintained. Consider migrating to `PyJWT` or `authlib`. Low risk as OIDC/JWT is optional.

---

## Security Features

| Feature | Status |
|---------|--------|
| Password hashing | bcrypt via passlib |
| SQL injection | Protected — SQLAlchemy ORM parameterized queries |
| SSTI | Protected — SandboxedEnvironment |
| XSS | Protected — DOMPurify on user content |
| CSRF | Protected — OIDC state parameter, SameSite cookies |
| Rate limiting | Applied — login (5/min), password (5/min), OIDC (10/min), bulk ops (20/min), escalation (10/min), token regen (3/min) |
| Session management | Server-side sessions, configurable expiry |
| Account lockout | Configurable threshold (default: 5 attempts) |
| Circuit breakers | ES, OpenCTI, TIDE, Ollama, Kibana — prevent cascading failures |
| Startup validation | Config validated at boot — blocks on fatal errors |
| Audit logging | Full action trail per user |
| File uploads | 50MB limit, type validation |
| RBAC | 7 roles, permission-based access, focus mode |

---

## Recommendations for Production

1. Set `ION_COOKIE_SECURE=true` behind TLS
2. Set `ION_DEBUG_MODE=false` to disable `/docs` and `/redoc`
3. Use a custom `ION_ADMIN_PASSWORD` (not defaults)
4. Add SSRF validation to webhook URLs before enabling
5. Consider migrating from `python-jose` to `PyJWT`
6. Deploy behind nginx/reverse proxy with TLS termination
7. Enable `ION_CA_BUNDLE` for internal certificate trust
