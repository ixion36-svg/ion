"""Per-request CSRF token shared across all Jinja2Templates instances.

Mirrors _csp_nonce.py. CSRFMiddleware sets the token in _csrf_token_var at the
start of every request; templates read it as the `csrf_token` global, so no
route handler has to thread it through.

The proxy is falsy when empty. base.html relies on that to skip the meta tag
entirely on anonymous pages — a bare object would always be truthy and would
emit an empty, pointless tag to logged-out visitors.
"""
from __future__ import annotations

import contextvars

_csrf_token_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "csrf_token", default=""
)


class _CSRFTokenProxy:
    """Resolves to the current request's CSRF token when Jinja2 interpolates it."""

    def __str__(self) -> str:
        return _csrf_token_var.get()

    def __html__(self) -> str:
        return _csrf_token_var.get()

    def __bool__(self) -> bool:
        return bool(_csrf_token_var.get())
