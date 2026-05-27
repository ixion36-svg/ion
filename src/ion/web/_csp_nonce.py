"""Per-request CSP nonce shared across all Jinja2Templates instances.

server.py sets the nonce in SecurityHeadersMiddleware via _csp_nonce_var;
API modules that own their own Jinja2Templates instances import _CSPNonceProxy
from here and register it as templates.env.globals["csp_nonce"].
"""
from __future__ import annotations

import contextvars

_csp_nonce_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "csp_nonce", default=""
)


class _CSPNonceProxy:
    """Resolves to the current request's CSP nonce when Jinja2 interpolates it."""

    def __str__(self) -> str:
        return _csp_nonce_var.get()

    def __html__(self) -> str:
        return _csp_nonce_var.get()
