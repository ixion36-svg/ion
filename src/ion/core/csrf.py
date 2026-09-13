"""CSRF token derivation and Origin validation primitives.

Deliberately dependency-light: no FastAPI, no database, no service imports. That
keeps the whole module unit-testable in isolation and means importing it from
middleware can never introduce a cycle.

The token is an HMAC keyed on the caller's own session token. That buys three
things a random token would not: no new secret to distribute to an air-gapped
deployment, no migration, and correctness across workers, since every worker
derives the same value from the same session. The token's lifetime is the
session's lifetime, which is the coupling we want — when the session dies the
token is meaningless.

Handing an HMAC of the session token to page JavaScript does not weaken the
session: the derivation is one-way, so an XSS that reads the CSRF token still
cannot reconstruct the session token it came from.
"""
from __future__ import annotations

import hmac
from hashlib import sha256
from typing import Iterable
from urllib.parse import urlsplit

# Versioned so the derivation can be changed later without silently accepting
# tokens minted under the old scheme.
_CSRF_MESSAGE = b"ion-csrf-v1"


def derive_token(session_token: str) -> str:
    """Return the CSRF token bound to ``session_token``.

    Empty in, empty out: an unauthenticated request has no token, and the
    middleware never challenges one.
    """
    if not session_token:
        return ""
    return hmac.new(session_token.encode("utf-8"), _CSRF_MESSAGE, sha256).hexdigest()


def tokens_match(session_token: str, presented: str) -> bool:
    """Constant-time check of ``presented`` against the token for this session."""
    if not session_token or not presented:
        return False
    return hmac.compare_digest(derive_token(session_token), presented)


def _origin_of(url: str) -> str:
    """Return ``scheme://host[:port]`` for ``url``, or "" when unparseable.

    "" is the signal for "this was not a usable origin", which callers treat as
    hostile when the header was present and as absent when it was not.
    """
    if not url:
        return ""
    parts = urlsplit(url.strip())
    if not parts.scheme or not parts.netloc:
        return ""
    return f"{parts.scheme}://{parts.netloc}"


def expected_origins(
    host: str,
    scheme: str,
    base_url: str,
    extra: Iterable[str] = (),
) -> set[str]:
    """Origins a state-changing request may legitimately claim to come from.

    ``host`` and ``scheme`` are the request's own. Comparing Origin against the
    request's own Host is sound against CSRF: the browser sets Origin to the
    attacking page's site while Host stays ION's, so the two cannot match. It is
    also what makes access by IP or localhost work on the range with no
    configuration at all.

    ``base_url`` is the configured deployment URL, kept as a backstop for
    proxied setups. ``extra`` covers a deployment fronted by another hostname.
    """
    origins: set[str] = set()
    if host and scheme:
        origins.add(f"{scheme}://{host}")
    configured = _origin_of(base_url)
    if configured:
        origins.add(configured)
    for candidate in extra:
        parsed = _origin_of(candidate)
        if parsed:
            origins.add(parsed)
    return origins


def origin_allowed(origin_header: str, referer_header: str, allowed: set[str]) -> bool:
    """True when the browser-supplied origin is absent, or is one of ``allowed``.

    Absent means a non-browser client — curl, CI, an integration. Those are
    allowed: an attacker controlling the client could omit or forge the header
    anyway, so rejecting would break automation for no security gain. This check
    earns its keep against browser-driven attacks specifically, where the browser
    sets Origin and the attacking page cannot suppress it.

    Present-but-unparseable (notably ``Origin: null`` from a sandboxed iframe) is
    rejected rather than treated as absent.
    """
    if origin_header:
        candidate = _origin_of(origin_header)
        return bool(candidate) and candidate in allowed
    if referer_header:
        candidate = _origin_of(referer_header)
        return bool(candidate) and candidate in allowed
    return True
