"""Credential redaction for settings and integration diagnostic text."""

from __future__ import annotations

import os
import re
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from ion.core.config import get_config

_SECRET_NAMES = ("password", "token", "secret", "api_key", "apikey", "credential", "license", "dsn")
_ASSIGNMENT = re.compile(
    r"""(?ix)(["']?(?:password|token|secret|api[_-]?key|credential|authorization)["']?\s*[:=]\s*)
        (?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;}]+)"""
)
_BEARER = re.compile(r'(?i)\bBearer\s+[^\s,;"\']+')
_URL = re.compile(r'[a-zA-Z][\w+.-]*://[^\s<>"\']+')


def _configured_secrets() -> set[str]:
    values: set[str] = set()
    config = get_config()
    fields = dict(vars(config))
    fields.update({key: os.environ[key] for key in ("ION_ADMIN_PASSWORD", "ION_DB_PASSWORD") if key in os.environ})
    for name, value in fields.items():
        if not isinstance(value, str) or not value:
            continue
        if any(hint in name.lower() for hint in _SECRET_NAMES):
            values.add(value)
        if "://" in value:
            try:
                parsed = urlsplit(value)
                if parsed.password:
                    values.add(parsed.password)
                values.update(item for key, item in parse_qsl(parsed.query) if item and any(hint in key.lower() for hint in _SECRET_NAMES))
            except ValueError:
                continue
    return values


def _address(match: re.Match) -> str:
    value = match.group(0)
    try:
        parsed = urlsplit(value)
        if not parsed.hostname or value.endswith("..."):
            return "[address redacted]"
        host = "[" + parsed.hostname + "]" if ":" in parsed.hostname else parsed.hostname
        port = ":" + str(parsed.port) if parsed.port is not None else ""
        return urlunsplit((parsed.scheme, host + port, parsed.path, "", ""))
    except ValueError:
        return "[address redacted]"


def safe_diagnostic(value: object) -> str:
    """Retain diagnostic prose while removing known and labelled credentials."""
    if not isinstance(value, str):
        return ""
    text = value
    for secret in sorted(_configured_secrets(), key=len, reverse=True):
        text = text.replace(secret, "[redacted]")
    text = _URL.sub(_address, text)
    text = _BEARER.sub("Bearer [redacted]", text)
    return _ASSIGNMENT.sub(lambda match: match.group(1) + "[redacted]", text)
