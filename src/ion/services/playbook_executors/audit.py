"""Redaction helper shared by all executor adapters.

Before any adapter stores its HTTP/LDAP request or response payload on
an :class:`ExecutorResult`, it MUST pass the payload through
:func:`redact` so secret-y fields never make it into the database or
the action log UI.
"""

from __future__ import annotations

import re
from typing import Any

# Keys matching this pattern will have their values replaced with "***REDACTED***"
# when found in request / response payload dicts.
_SECRET_KEY_RE = re.compile(
    r"password|secret|token|authorization|api[_-]?key|bearer|credential",
    re.IGNORECASE,
)

_REDACTED = "***REDACTED***"


def _redact_value(value: Any) -> Any:
    """Recursively redact a single value (dict, list, or scalar)."""
    if isinstance(value, dict):
        return redact(value)
    if isinstance(value, list):
        return [_redact_value(v) for v in value]
    if isinstance(value, tuple):
        return tuple(_redact_value(v) for v in value)
    return value


def redact(obj: Any) -> Any:
    """Strip secret-y fields from a dict (or list/tuple containing dicts).

    Keys matching ``password``, ``secret``, ``token``, ``authorization``,
    ``api_key``/``api-key``, ``bearer`` or ``credential`` (case-insensitive,
    anywhere in the key name) have their values replaced with a redacted
    placeholder.  The function is recursive so nested structures are
    cleaned as well.  Returns a new object; the input is not mutated.

    Non-dict / non-list inputs are returned unchanged (after recursing
    into any nested dicts).  ``None`` is passed through as ``None``.
    """
    if obj is None:
        return None
    if isinstance(obj, dict):
        out: dict = {}
        for k, v in obj.items():
            if isinstance(k, str) and _SECRET_KEY_RE.search(k):
                out[k] = _REDACTED
            else:
                out[k] = _redact_value(v)
        return out
    if isinstance(obj, list):
        return [_redact_value(v) for v in obj]
    if isinstance(obj, tuple):
        return tuple(_redact_value(v) for v in obj)
    return obj


__all__ = ["redact"]
