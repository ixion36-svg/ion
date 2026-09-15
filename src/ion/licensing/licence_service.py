"""Verify and read an offline module licence.

A licence is an Ed25519-signed JWT. Claims:

    {
      "customer_id": "acme",
      "modules": ["detection_engineering"],
      "licence_id": "<uuid>",       # -> jti
      "iat": <issued unix ts>,
      "exp": <optional expiry ts>   # informational: a valid signature past exp
                                    # is reported expired but still entitled;
                                    # enforcement policy decides what to do.
    }

Signature is always required. Expiry is surfaced, never fatal here — the
gating layer owns the enforcement decision.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from typing import List, Optional

import jwt
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from ion.licensing.vendor_key import VENDOR_PUBLIC_KEY_PEM

logger = logging.getLogger(__name__)


@dataclass
class LicenceStatus:
    valid: bool = False               # signature verified and claims parsed
    reason: str = "no licence configured"
    customer_id: Optional[str] = None
    modules: List[str] = field(default_factory=list)
    licence_id: Optional[str] = None
    issued_at: Optional[int] = None
    expires_at: Optional[int] = None
    expired: bool = False

    def entitles(self, module: str) -> bool:
        """True if the licence is validly signed and names ``module``.

        Expiry does not revoke entitlement here — the caller decides whether an
        expired-but-signed licence still counts.
        """
        return self.valid and module in self.modules


def _resolve_source(source: str) -> str:
    """A licence source is either an inline token or a path to one on disk."""
    if not source:
        return ""
    # A JWT has no path separators or newlines; treat anything file-like as a path.
    if ("/" in source or "\\" in source) and os.path.isfile(source):
        try:
            with open(source, "r", encoding="utf-8") as fh:
                return fh.read().strip()
        except OSError as exc:
            logger.warning("Licence file %s unreadable: %s", source, exc)
            return ""
    return source.strip()


class LicenceService:
    """Verifies a licence against a public key (the vendor key by default)."""

    def __init__(self, public_key_pem: str = VENDOR_PUBLIC_KEY_PEM):
        self._public_key = load_pem_public_key(public_key_pem.encode())
        self._status: Optional[LicenceStatus] = None

    def verify(self, source: str) -> LicenceStatus:
        """Verify a licence token/path and return its status (no caching)."""
        token = _resolve_source(source)
        if not token:
            return LicenceStatus(valid=False, reason="no licence configured")
        try:
            claims = jwt.decode(
                token,
                key=self._public_key,
                algorithms=["EdDSA"],
                # Signature is enforced; expiry is read below, not enforced here.
                options={"verify_exp": False, "verify_aud": False},
            )
        except jwt.InvalidTokenError as exc:
            logger.warning("Licence rejected: %s", exc)
            return LicenceStatus(valid=False, reason=f"invalid licence: {exc}")

        modules = claims.get("modules") or []
        if not isinstance(modules, list):
            return LicenceStatus(valid=False, reason="licence 'modules' is not a list")
        exp = claims.get("exp")
        expired = bool(exp) and time.time() > float(exp)
        return LicenceStatus(
            valid=True,
            reason="ok",
            customer_id=claims.get("customer_id"),
            modules=[str(m) for m in modules],
            licence_id=claims.get("licence_id") or claims.get("jti"),
            issued_at=claims.get("iat"),
            expires_at=exp,
            expired=expired,
        )

    def status(self) -> LicenceStatus:
        """Cached status, loaded from ``ION_DE_LICENSE``/config on first call."""
        if self._status is None:
            from ion.core.config import get_config
            self._status = self.verify(get_config().de_license)
        return self._status


_service: Optional[LicenceService] = None


def get_licence_service() -> LicenceService:
    global _service
    if _service is None:
        _service = LicenceService()
    return _service


def reset_licence_service() -> None:
    """Drop the cached singleton — used by tests and after a config reload."""
    global _service
    _service = None
