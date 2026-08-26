"""ION → Arkime WISE intel feed.

Serves ION's active IOC set (observables flagged IOC/watched, high/critical
threat level, or OpenCTI-malicious) in the flat JSON shape Arkime's WISE
``json`` source consumes, so matching sessions get tagged **at capture time**
instead of waiting for the RTMON polling detector.

WISE is a machine client with no ION session, so auth is a static bearer
token: set ``ION_WISE_TOKEN`` and configure the same value in ``wise.ini``.
The endpoint answers 404 while the token is unset — the feature simply does
not exist until it is deliberately turned on. Header-only auth (Authorization
bearer or ``x-ion-token``); the token never belongs in the URL, where it
would land in every proxy log.

wise.ini example (one source per WISE type):

    [json:ion-ioc-ip]
    url=https://ion.example/api/wise/ion-iocs?type=ip
    headers=x-ion-token: <ION_WISE_TOKEN value>
    reload=5
    keyPath=value
    type=ip
    tags=ion-ioc
    fields=field:ion.label;db:ion.label;kind:lotermfield;friendly:ION Label;shortcut:label\nfield:ion.threat;db:ion.threat;kind:lotermfield;friendly:ION Threat;shortcut:threat_level

Repeat with ``type=domain`` / ``type=md5`` / ``type=sha256`` (WISE has no
sha1 type; sha1 IOCs are not served). Sessions then carry the ``ion-ioc`` tag
and ``tags == ion-ioc`` is retroactively searchable in the viewer.
"""

from __future__ import annotations

import hmac
import logging
import os
import time
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import or_
from sqlalchemy.orm import Session

from ion.auth.dependencies import get_db_session

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/wise", tags=["wise"])

_TYPE_MAP: Dict[str, List[str]] = {
    "ip": ["ipv4", "ipv6"],
    "domain": ["domain", "hostname"],
    "md5": ["md5"],
    "sha256": ["sha256"],
}

_CACHE_TTL_S = 60.0
_cache: Dict[str, Any] = {}


def _max_iocs() -> int:
    try:
        return max(1, int(os.environ.get("ION_WISE_MAX_IOCS", "10000")))
    except (TypeError, ValueError):
        return 10000


def _check_token(request: Request) -> None:
    expected = os.environ.get("ION_WISE_TOKEN", "").strip()
    if not expected:
        # Feature off — indistinguishable from a route that doesn't exist.
        raise HTTPException(status_code=404, detail="Not found")
    supplied = (request.headers.get("x-ion-token") or "").strip()
    if not supplied:
        auth = request.headers.get("authorization") or ""
        if auth.lower().startswith("bearer "):
            supplied = auth[7:].strip()
    if not supplied or not hmac.compare_digest(supplied, expected):
        raise HTTPException(status_code=401, detail="Invalid token")


def _load_iocs(session: Session, type_values: List[str], cap: int) -> List[Dict[str, Any]]:
    from ion.models.observable import (
        Observable,
        ObservableEnrichment,
        ObservableType,
        ThreatLevel,
    )

    types = [ObservableType(v) for v in type_values]
    rows = (
        session.query(Observable)
        .filter(Observable.type.in_(types))
        .filter(Observable.is_whitelisted.is_(False))
        .filter(
            or_(
                Observable.is_ioc.is_(True),
                Observable.is_watched.is_(True),
                Observable.threat_level.in_([ThreatLevel.HIGH, ThreatLevel.CRITICAL]),
            )
        )
        .limit(cap)
        .all()
    )
    out: Dict[str, Dict[str, Any]] = {}
    for o in rows:
        tl = getattr(o, "threat_level", None)
        out[o.value] = {
            "value": o.value,
            "label": "ioc" if o.is_ioc else ("watched" if o.is_watched else "high-risk"),
            "threat_level": getattr(tl, "value", str(tl)) if tl else "unknown",
        }
    if len(out) < cap:
        mal = (
            session.query(Observable)
            .join(
                ObservableEnrichment,
                ObservableEnrichment.observable_id == Observable.id,
            )
            .filter(Observable.type.in_(types))
            .filter(Observable.is_whitelisted.is_(False))
            .filter(ObservableEnrichment.is_malicious.is_(True))
            .limit(cap - len(out))
            .all()
        )
        for o in mal:
            out.setdefault(o.value, {
                "value": o.value,
                "label": "opencti-malicious",
                "threat_level": "high",
            })
    return list(out.values())


@router.get("/ion-iocs")
def wise_ion_iocs(
    request: Request,
    type: str = "ip",
    session: Session = Depends(get_db_session),
) -> List[Dict[str, Any]]:
    """ION's active IOC set for one WISE type, as a flat JSON array."""
    _check_token(request)
    wise_type = type.strip().lower()
    if wise_type not in _TYPE_MAP:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown type {wise_type!r}. Use: {', '.join(sorted(_TYPE_MAP))}",
        )
    now = time.time()
    cached = _cache.get(wise_type)
    if cached and now - cached["ts"] < _CACHE_TTL_S:
        return cached["data"]
    try:
        data = _load_iocs(session, _TYPE_MAP[wise_type], _max_iocs())
    except Exception as exc:  # noqa: BLE001
        logger.warning("WISE feed load failed: %s", exc)
        raise HTTPException(status_code=500, detail="IOC load failed")
    _cache[wise_type] = {"ts": now, "data": data}
    return data
