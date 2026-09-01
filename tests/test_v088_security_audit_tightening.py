"""Audit-subsystem tightening: auth-aware content scanning + authz-failure alerting.

Covers the two changes:
  1. Payload-pattern WAF checks (SQLi/XSS/command/template) are gated by
     `scan_content`; structural checks (path traversal, scanner UA) always run.
  2. `record_authorization_failure` records 401/403 and escalates a per-actor
     burst to a HIGH event once the threshold is crossed.
"""

from ion.models.security import SecurityEventSeverity, SecurityEventType
from ion.services.security_service import RequestContext, SecurityDetectionService


def _svc(session):
    return SecurityDetectionService(session)


# --- 1. Auth-aware content scanning --------------------------------------

def test_content_scanned_when_enabled(session):
    ctx = RequestContext(
        source_ip="10.0.0.9",
        request_path="/api/search",
        request_method="POST",
        body="UNION SELECT * FROM users",
    )
    results = _svc(session).analyze_request(ctx, scan_content=True)
    types = {r.event_type for r in results}
    assert SecurityEventType.SQL_INJECTION in types


def test_content_suppressed_for_authenticated(session):
    """Authenticated analysts legitimately handle malicious content — the
    payload-pattern hits must be dropped when scan_content is False."""
    ctx = RequestContext(
        source_ip="10.0.0.9",
        request_path="/api/notes",
        request_method="POST",
        body="'; DROP TABLE users -- <script>alert(1)</script> $(whoami) {{7*7}}",
    )
    results = _svc(session).analyze_request(ctx, scan_content=False)
    types = {r.event_type for r in results}
    assert SecurityEventType.SQL_INJECTION not in types
    assert SecurityEventType.XSS_ATTEMPT not in types
    assert SecurityEventType.COMMAND_INJECTION not in types
    assert SecurityEventType.TEMPLATE_INJECTION not in types


def test_structural_checks_run_even_when_content_suppressed(session):
    """Path traversal in the URL and scanner UAs signal an attack on ION
    regardless of who sends the request — they must survive scan_content=False."""
    ctx = RequestContext(
        source_ip="10.0.0.9",
        request_path="/api/../../etc/passwd",
        request_method="GET",
        user_agent="sqlmap/1.5",
    )
    results = _svc(session).analyze_request(ctx, scan_content=False)
    types = {r.event_type for r in results}
    assert SecurityEventType.PATH_TRAVERSAL in types
    assert SecurityEventType.SCANNER_DETECTED in types


# --- 2. Authorization-failure auditing -----------------------------------

def _authz_ctx(path="/api/admin/users"):
    return RequestContext(
        source_ip="10.0.0.42",
        request_path=path,
        request_method="GET",
        username="analyst1",
        user_id=7,
    )


def test_single_403_is_low_privilege_event(session):
    event, escalated = _svc(session).record_authorization_failure(
        _authz_ctx(), status_code=403, threshold=3, window_minutes=5
    )
    assert event.event_type == SecurityEventType.PRIVILEGE_ESCALATION
    assert event.severity == SecurityEventSeverity.LOW
    assert escalated is False


def test_401_is_unauthorized_access(session):
    event, escalated = _svc(session).record_authorization_failure(
        RequestContext(source_ip="10.0.0.50", request_path="/api/cases", request_method="GET"),
        status_code=401,
        threshold=3,
    )
    assert event.event_type == SecurityEventType.UNAUTHORIZED_ACCESS
    assert escalated is False


def test_repeated_403_escalates_to_high(session):
    svc = _svc(session)
    escalated = False
    for _ in range(3):
        session.flush()
        _event, escalated = svc.record_authorization_failure(
            _authz_ctx(), status_code=403, threshold=3, window_minutes=5
        )
    assert escalated is True
    assert _event.severity == SecurityEventSeverity.HIGH
    assert _event.event_count >= 3
    assert "Repeated" in _event.title
