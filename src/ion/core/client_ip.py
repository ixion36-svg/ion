"""Canonical client-IP derivation — trusted-proxy aware, single source of truth.

Rate limiting, audit logging, IP blocking, and security monitoring must all
agree on *who the client is*. Before v0.39.3 there were two divergent
implementations: a security-middleware one that correctly required a trusted
proxy before honouring forwarded headers, and an auth-layer one that blindly
trusted the first ``X-Forwarded-For`` value (spoofable). This module unifies
them.

Forwarded headers (``X-Forwarded-For`` / ``X-Real-IP``) are honoured ONLY when
the immediate TCP peer is in the ``ION_TRUSTED_PROXIES`` allowlist; otherwise
they are attacker-controlled and ignored — any external client can send
``X-Forwarded-For: 127.0.0.1``.

Safe by default: with ``ION_TRUSTED_PROXIES`` unset, ION uses the TCP peer for
every request and trusts no forwarded headers. Behind a shared platform ingress
(e.g. Guardedglass) set ``ION_TRUSTED_PROXIES`` to the ingress CIDR(s) so ION
(a) sees the real client IP instead of the proxy's, and (b) cannot be tricked
into attributing a request to a spoofed source.
"""

import ipaddress
import logging
import os
from typing import List, Optional, Union

from fastapi import Request

logger = logging.getLogger(__name__)

_IPNet = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


def _parse_trusted_proxies() -> List[_IPNet]:
    """Parse ION_TRUSTED_PROXIES env var (comma-separated CIDRs/IPs)."""
    raw = os.environ.get("ION_TRUSTED_PROXIES", "")
    nets: List[_IPNet] = []
    for s in raw.split(","):
        s = s.strip()
        if not s:
            continue
        try:
            nets.append(ipaddress.ip_network(s, strict=False))
        except ValueError:
            logger.warning("Ignoring invalid CIDR in ION_TRUSTED_PROXIES: %s", s)
    return nets


# Parsed once at import. ION_TRUSTED_PROXIES is deployment-static; a restart
# picks up changes (consistent with the other env-driven config in ION).
_TRUSTED_PROXIES = _parse_trusted_proxies()


def peer_ip(request: Request) -> str:
    """Actual TCP peer IP — never spoofable via headers."""
    return request.client.host if request.client else "unknown"


def is_trusted_proxy(ip: str) -> bool:
    """Is the given IP a configured trusted reverse proxy?"""
    if not _TRUSTED_PROXIES:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _TRUSTED_PROXIES)


def get_client_ip(request: Request) -> Optional[str]:
    """Best-effort real client IP, honouring forwarded headers only from trusted peers.

    Returns the TCP peer when the peer is not a trusted proxy (the safe default).
    For trusted peers, walks ``X-Forwarded-For`` right-to-left and returns the
    first non-trusted entry — the original client behind a chain of trusted
    proxies — then falls back to ``X-Real-IP``, then the peer.
    """
    peer = peer_ip(request)

    # Untrusted peer: ignore any forwarded headers (attacker-controlled).
    if not is_trusted_proxy(peer):
        return peer

    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        for entry in reversed([s.strip() for s in forwarded.split(",")]):
            if entry and not is_trusted_proxy(entry):
                return entry

    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        # Validate before trusting: a malformed X-Real-IP would otherwise land
        # in source_ip audit fields and rate-limit / IP-block bucket keys. Fall
        # through to the trusted peer if it isn't a well-formed address.
        try:
            ipaddress.ip_address(real_ip)
            return real_ip
        except ValueError:
            pass

    return peer
