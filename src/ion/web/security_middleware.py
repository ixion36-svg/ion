"""Security monitoring middleware for FastAPI."""

from typing import Callable

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from ion.core.client_ip import get_client_ip
from ion.core.client_ip import is_trusted_proxy as _is_trusted_proxy
from ion.core.client_ip import peer_ip as _peer_ip
from ion.core.config import get_config
from ion.core.logging import get_structured_logger
from ion.models.security import SecurityEventType
from ion.services.security_service import (
    RequestContext,
    SecurityDetectionService,
)

# Payload-pattern detections that reflect content the caller supplied — dropped
# for authenticated analysts (who legitimately handle malicious content). The
# structural detections (path traversal, scanner, suspicious UA) are not here:
# they signal an attack on ION regardless of who sends the request.
_CONTENT_EVENT_TYPES = frozenset({
    SecurityEventType.SQL_INJECTION,
    SecurityEventType.XSS_ATTEMPT,
    SecurityEventType.COMMAND_INJECTION,
    SecurityEventType.TEMPLATE_INJECTION,
})
from ion.storage.database import get_engine, get_session_factory

logger = get_structured_logger(__name__)


# _peer_ip / _is_trusted_proxy / get_client_ip now live in ion.core.client_ip
# (imported above) — a single trusted-proxy-aware source of truth shared with
# the auth layer, audit logging, and the login rate-limiter.


class SecurityMonitoringMiddleware(BaseHTTPMiddleware):
    """Middleware for detecting and logging security threats.

    Features:
    - Analyzes requests for attack patterns
    - Blocks requests from blocked IPs
    - Records security events
    - Integrates with the security dashboard
    """

    # Trusted IPs that are never blocked or scanned (localhost/development)
    TRUSTED_IPS = (
        "127.0.0.1",
        "localhost",
        "::1",  # IPv6 localhost
    )

    # Paths excluded from IP blocking and attack detection
    # (admins must be able to access dashboard to unblock, templates/extract contain code-like content)
    EXCLUDED_PATHS = (
        "/security",
        "/api/security/",
        "/static/",
        "/login",
        "/api/auth/",  # Auth endpoints (login, OIDC callback — codes/state params trigger false positives)
        "/api/extract/",  # Extract endpoints analyze user documents which may contain code
        "/extract",
        "/api/templates",  # Templates contain Jinja2 syntax like {{ }} which triggers patterns
        "/templates",
        "/api/collections",  # Collection management
        "/api/elasticsearch/alerts",  # Alert/case bodies contain security content (shell commands, exploit code)
        "/api/ai/",  # AI endpoints receive alert data for analysis
    )

    def __init__(self, app, enabled: bool = True):
        super().__init__(app)
        self.enabled = enabled
        # IP auto-blocking is opt-in (ION_IP_BLOCKING_ENABLED, default off).
        # Attack detections are ALWAYS logged; blocking only acts when this is
        # on. Behind a shared ingress, also set ION_TRUSTED_PROXIES so client_ip
        # resolves to the real client — otherwise a block would hit the ingress
        # IP and take down every user (the dispatch guards refuse to block a
        # trusted proxy / localhost as a backstop).
        self.blocking_enabled = False

        # FP tightening + authz auditing knobs (see SecurityDetectionService).
        self.scan_authenticated = False
        self.authz_alert_enabled = True
        self.authz_threshold = 5
        self.authz_window_minutes = 5

        # Initialize database connection
        try:
            config = get_config()
            self.blocking_enabled = bool(getattr(config, "ip_blocking_enabled", False))
            self.scan_authenticated = bool(getattr(config, "security_scan_authenticated", False))
            self.authz_alert_enabled = bool(getattr(config, "authz_alert_enabled", True))
            self.authz_threshold = int(getattr(config, "authz_alert_threshold", 5))
            self.authz_window_minutes = int(getattr(config, "authz_alert_window_minutes", 5))
            self.engine = get_engine(config.db_path)
            self.session_factory = get_session_factory(self.engine)
        except Exception as e:
            logger.error(f"Failed to initialize security middleware: {e}")
            self.engine = None
            self.session_factory = None

    def _is_excluded_path(self, path: str) -> bool:
        """Check if path is excluded from security blocking."""
        for excluded in self.EXCLUDED_PATHS:
            if path == excluded or path.startswith(excluded):
                return True
        return False

    def _is_trusted_ip(self, ip: str) -> bool:
        """Check if IP is in the trusted list (localhost/development)."""
        return ip in self.TRUSTED_IPS

    # Paths where a 401/403 is not privilege-probing worth auditing: the login
    # surface (brute-force is recorded separately), static assets, and the
    # security dashboard itself (an admin unblocking must reach it).
    AUTHZ_SKIP_PREFIXES = (
        "/login",
        "/api/auth/",
        "/static/",
        "/favicon",
        "/security",
        "/api/security/",
    )

    def _is_authz_skip(self, path: str) -> bool:
        return any(path == p or path.startswith(p) for p in self.AUTHZ_SKIP_PREFIXES)

    def _resolve_user(self, request: Request, session):
        """Return the authenticated User, or None. Only hits the DB when a
        session token is actually present, so anonymous traffic pays nothing and
        a forged cookie cannot suppress scanning (validation must succeed)."""
        try:
            from ion.auth.dependencies import get_session_token
            from ion.auth.service import AuthService

            token = get_session_token(request)
            if not token:
                return None
            return AuthService(session).validate_session(token)
        except Exception:
            return None

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if not self.enabled or not self.session_factory:
            return await call_next(request)

        # CRITICAL: trust check uses the actual TCP peer, NOT the result of
        # get_client_ip() — the latter can be derived from X-Forwarded-For
        # which is attacker-controlled. Without this, an external attacker
        # could send `X-Forwarded-For: 127.0.0.1` to bypass all detection.
        peer_ip = _peer_ip(request)
        client_ip = get_client_ip(request)  # used for logging/recording only

        # Skip all security checks for trusted IPs (localhost)
        if self._is_trusted_ip(peer_ip):
            return await call_next(request)

        session = self.session_factory()
        try:
            security_service = SecurityDetectionService(session)

            # IP auto-blocking (opt-in via ION_IP_BLOCKING_ENABLED). Never block
            # a trusted proxy or localhost: behind a shared ingress with no
            # ION_TRUSTED_PROXIES set, client_ip resolves to the ingress and a
            # block would take down every user. Detections are logged regardless.
            if (
                self.blocking_enabled
                and not _is_trusted_proxy(client_ip)
                and not self._is_trusted_ip(client_ip)
                and not self._is_excluded_path(request.url.path)
                and security_service.is_ip_blocked(client_ip)
            ):
                logger.security_event(
                    action="blocked_ip_request",
                    outcome="blocked",
                    details={"ip": client_ip, "path": request.url.path},
                )
                return JSONResponse(
                    status_code=403,
                    content={"detail": "Access denied"},
                )

            # Attack detection runs on non-excluded paths. (Excluded paths still
            # get post-response authz auditing below.)
            if not self._is_excluded_path(request.url.path):
                # Build request context
                body = None
                if request.method in ("POST", "PUT", "PATCH"):
                    try:
                        body_bytes = await request.body()
                        body = body_bytes.decode("utf-8", errors="ignore")[:10000]  # Limit size
                    except Exception:
                        pass

                ctx = RequestContext(
                    source_ip=client_ip,
                    request_path=request.url.path,
                    request_method=request.method,
                    user_agent=request.headers.get("User-Agent"),
                    query_string=str(request.query_params),
                    body=body,
                    headers=dict(request.headers),
                )

                # Analyze request for attacks (cheap regex; no DB).
                detections = security_service.analyze_request(ctx)

                # FP tightening: a payload-pattern hit (SQLi/XSS/command/template)
                # from an authenticated analyst is expected content, not an
                # attack on ION — drop it. Resolve the user only when such a hit
                # actually fires (rare), so normal traffic pays no session lookup.
                if (
                    detections
                    and not self.scan_authenticated
                    and any(d.event_type in _CONTENT_EVENT_TYPES for d in detections)
                ):
                    actor = self._resolve_user(request, session)
                    if actor is not None:
                        ctx.user_id = actor.id
                        ctx.username = actor.username
                        detections = [
                            d for d in detections
                            if d.event_type not in _CONTENT_EVENT_TYPES
                        ]

                # Record and handle detections
                for detection in detections:
                    # Capture raw data for forensics
                    raw_data = {
                        "path": ctx.request_path,
                        "query_string": ctx.query_string if ctx.query_string else None,
                        "body": ctx.body[:2000] if ctx.body else None,  # Limit stored body size
                        "matched_content": detection.matched_content if hasattr(detection, 'matched_content') and detection.matched_content else None,
                    }
                    # Remove empty values
                    raw_data = {k: v for k, v in raw_data.items() if v}

                    event = security_service.record_event(ctx, detection, raw_data=raw_data)
                    session.commit()

                    logger.security_event(
                        action=detection.event_type.value if detection.event_type else "unknown",
                        outcome="detected",
                        details={
                            "ip": client_ip,
                            "path": request.url.path,
                            "confidence": detection.confidence_score,
                            "patterns": detection.matched_patterns[:3],  # Limit logged patterns
                        },
                    )

                    # Auto-block on high-confidence detections (opt-in; same trusted
                    # proxy / localhost backstop as the is_ip_blocked guard above).
                    if (
                        self.blocking_enabled
                        and getattr(detection, "should_block", False)
                        and not _is_trusted_proxy(client_ip)
                        and not self._is_trusted_ip(client_ip)
                    ):
                        security_service.block_ip(
                            ip_address=client_ip,
                            reason=f"Automatic block: {detection.title}",
                            duration_minutes=60,
                            security_event_id=event.id,
                        )
                        session.commit()

            # Continue with request
            response = await call_next(request)

            # Authorization-failure auditing: record 401/403 and escalate a burst
            # from one actor (IDOR / privilege probing, unauthenticated scanning)
            # into a HIGH event. Runs on the response so it needs no route hooks.
            if (
                self.authz_alert_enabled
                and response.status_code in (401, 403)
                and not self._is_authz_skip(request.url.path)
            ):
                try:
                    actor = self._resolve_user(request, session)
                    authz_ctx = RequestContext(
                        source_ip=client_ip,
                        request_path=request.url.path,
                        request_method=request.method,
                        user_agent=request.headers.get("User-Agent"),
                        user_id=getattr(actor, "id", None),
                        username=getattr(actor, "username", None),
                    )
                    _ev, escalated = security_service.record_authorization_failure(
                        authz_ctx,
                        response.status_code,
                        threshold=self.authz_threshold,
                        window_minutes=self.authz_window_minutes,
                    )
                    session.commit()
                    if escalated:
                        logger.security_event(
                            action="authz_failure_burst",
                            outcome="detected",
                            details={
                                "ip": client_ip,
                                "path": request.url.path,
                                "status": response.status_code,
                                "actor": authz_ctx.username or authz_ctx.user_id or client_ip,
                            },
                        )
                except Exception as e:
                    logger.error(f"Authz-failure auditing error: {e}")

            return response

        except Exception as e:
            logger.error(f"Security middleware error: {e}", exc_info=True)
            # Don't block requests on middleware errors
            return await call_next(request)

        finally:
            session.close()


class RateLimitSecurityMiddleware(BaseHTTPMiddleware):
    """Middleware that records rate limit violations as security events."""

    def __init__(self, app):
        super().__init__(app)

        try:
            config = get_config()
            self.engine = get_engine(config.db_path)
            self.session_factory = get_session_factory(self.engine)
        except Exception:
            self.engine = None
            self.session_factory = None

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)

        # Check if rate limited (429 status)
        if response.status_code == 429 and self.session_factory:
            session = self.session_factory()
            try:
                security_service = SecurityDetectionService(session)
                client_ip = get_client_ip(request)

                security_service.record_rate_limit_exceeded(
                    source_ip=client_ip,
                    request_path=request.url.path,
                    user_agent=request.headers.get("User-Agent"),
                )
                session.commit()

            except Exception as e:
                logger.error(f"Error recording rate limit event: {e}")
            finally:
                session.close()

        return response
