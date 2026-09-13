"""CSRF enforcement: session-derived token plus Origin validation.

Two independent checks. The token proves the request came from a page ION
rendered. The Origin check proves it came from ION's site. Either alone stops a
classic CSRF, and neither depends on the other, so a defect in one does not
silently disarm the control.

The token is demanded only when the request carries a session COOKIE. A request
authenticating with `Authorization: Bearer` and no cookie is exempt, because CSRF
exploits credentials the browser attaches automatically and a Bearer token is not
one of those — an attacker who knows the token does not need the victim's browser
at all. Origin validation still applies to those requests.

THE INVARIANT: the exemption keys on cookie ABSENCE, never on Bearer PRESENCE.
Keyed the other way round, an attacker appends `Authorization: Bearer junk` to a
cookie-carrying request, this middleware waves it through, and the cookie still
authenticates it downstream because get_session_token() reads the cookie first.
That is a total bypass. Guarded by
test_csrf_protection.py::test_bearer_header_does_not_exempt_cookie_request.

Context: the session cookie is already HttpOnly + SameSite=strict, so current
browsers do not attach it cross-site at all. This middleware is defence in depth
against a future SameSite relaxation, same-site attacker positions, and older or
buggy clients.
"""
from __future__ import annotations

import logging

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from ion.auth.dependencies import SESSION_COOKIE_NAME
from ion.core.client_ip import get_client_ip
from ion.core.config import get_config
from ion.core.csrf import derive_token, expected_origins, origin_allowed, tokens_match
from ion.web._csrf_token import _csrf_token_var

logger = logging.getLogger(__name__)

CSRF_HEADER = "X-CSRF-Token"

# Only these can change state, so only these are challenged.
_UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# Exact-match exemptions. Keep this list short; every entry needs a reason.
_EXEMPT_PATHS = frozenset({
    # No session exists yet to bind a token to. Already rate limited at 10/min.
    "/api/auth/login",
})

# Prefix exemptions, for routes carrying a variable path segment.
_EXEMPT_PREFIXES = (
    # Inbound from external systems, authenticated by the token in the path
    # (integration_api.py). No browser involved, so no CSRF surface.
    "/api/integrations/webhooks/receive/",
)

# The OIDC routes deliberately have no entry here: /api/auth/oidc/config and
# /api/auth/oidc/callback are both GET, so the method gate already excludes
# them. A dead exemption entry would only mislead the next reader.


def is_exempt(path: str) -> bool:
    """True when ``path`` is excused from the token check."""
    if path in _EXEMPT_PATHS:
        return True
    return any(path.startswith(prefix) for prefix in _EXEMPT_PREFIXES)


def _request_scheme(request: Request) -> str:
    """Scheme as the client sees it, honouring the proxy header.

    Mirrors the X-Forwarded-Proto handling SecurityHeadersMiddleware already
    uses, so a TLS-terminating proxy does not make every Origin look foreign.
    """
    if request.headers.get("X-Forwarded-Proto") == "https":
        return "https"
    return request.url.scheme


class CSRFMiddleware(BaseHTTPMiddleware):
    """Reject cross-site state-changing requests; publish the token for templates."""

    async def dispatch(self, request: Request, call_next):
        session_token = request.cookies.get(SESSION_COOKIE_NAME) or ""

        # Publish on every request, including GETs, so the page being rendered
        # can put the token in its meta tag.
        ctx_token = _csrf_token_var.set(derive_token(session_token))
        try:
            rejection = self._check(request, session_token)
            if rejection is not None:
                return rejection
            return await call_next(request)
        finally:
            _csrf_token_var.reset(ctx_token)

    def _check(self, request: Request, session_token: str):
        """Return a 403 response when the request must be rejected, else None."""
        if request.method not in _UNSAFE_METHODS:
            return None

        config = get_config()
        if not config.csrf_enabled:
            return None

        path = request.url.path

        # Origin first, and before the exemption check, so a cross-site request
        # to an exempt route is still caught and the log names the real reason.
        allowed = expected_origins(
            host=request.headers.get("Host", ""),
            scheme=_request_scheme(request),
            base_url=getattr(config, "base_url", ""),
            extra=[
                o for o in getattr(config, "csrf_extra_origins", "").split(",") if o.strip()
            ],
        )
        if not origin_allowed(
            request.headers.get("Origin", ""),
            request.headers.get("Referer", ""),
            allowed,
        ):
            return self._reject(request, "origin_invalid", "Cross-origin request rejected")

        if is_exempt(path):
            return None

        # The invariant. Absence of a cookie, never presence of a Bearer header.
        if not session_token:
            return None

        if not tokens_match(session_token, request.headers.get(CSRF_HEADER, "")):
            return self._reject(request, "csrf_invalid", "Missing or invalid CSRF token")

        return None

    def _reject(self, request: Request, code: str, detail: str) -> JSONResponse:
        logger.warning(
            "CSRF rejection (%s): %s %s from %s",
            code,
            request.method,
            request.url.path,
            get_client_ip(request),
        )
        return JSONResponse(status_code=403, content={"detail": detail, "code": code})
