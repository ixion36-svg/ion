"""Resolve an alert's source_system (data_stream.namespace) to CyAB + TIDE identity.

The chain:
    ES alert.data_stream.namespace
        → CyabDataSource.data_namespace
        → CyabSystem (parent, via FK)
        → CyabDataSource.tide_system_id (string)
        → TIDE system (via tide_service.get_systems())

A 60-second in-process cache holds the full namespace map so we don't hit
Postgres or TIDE on every alert serialization. The cache rebuilds lazily on
first request after expiry; a forced refresh helper exists for callers who
just mutated CyAB.

Resolver returns a flat dict ready to merge into an alert dict:
    {
        "source_system": "production",   # raw namespace
        "cyab_system_id": 4,
        "cyab_system_name": "Production Endpoints",
        "cyab_data_source_name": "CrowdStrike production",
        "tide_system_id": "8f2c…",
        "tide_system_name": "Production Endpoints",
    }

Missing legs return None on those keys but never error.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Dict, Iterable, Optional

from sqlalchemy.orm import Session

from ion.models.cyab import CyabDataSource, CyabSystem
from ion.services.tide_service import get_tide_service

logger = logging.getLogger(__name__)


_CACHE_TTL_SECONDS = 60.0

# Per-process cache + lock. Multiple uvicorn workers each maintain their own
# cache — eventually consistent on CyAB edits within TTL.
_cache_lock = threading.Lock()
_cache: Dict[str, Dict[str, Any]] = {}
_cache_loaded_at: float = 0.0


def _build_cache(session: Session) -> Dict[str, Dict[str, Any]]:
    """Rebuild the namespace → resolution map.

    Single SQL query that joins CyabDataSource → CyabSystem on the FK, then
    one TIDE query for the systems list. Both results merged in Python.
    """
    rows = (
        session.query(
            CyabDataSource.data_namespace,
            CyabDataSource.id,
            CyabDataSource.name,
            CyabDataSource.tide_system_id,
            CyabSystem.id,
            CyabSystem.name,
        )
        .join(CyabSystem, CyabSystem.id == CyabDataSource.system_id)
        .filter(CyabDataSource.data_namespace.isnot(None))
        .filter(CyabDataSource.data_namespace != "")
        .all()
    )

    # Cheap TIDE systems lookup — TIDE service has its own cache, so this is
    # essentially free on warm path. Falls back to {} on TIDE outage.
    tide_systems_by_id: Dict[str, str] = {}
    try:
        for ts in get_tide_service().get_systems() or []:
            tid = ts.get("id")
            tname = ts.get("name")
            if tid and tname:
                tide_systems_by_id[str(tid)] = tname
    except Exception as e:
        logger.debug("TIDE systems fetch failed during resolver build: %s", e)

    new_cache: Dict[str, Dict[str, Any]] = {}
    for ds_namespace, ds_id, ds_name, ds_tide_id, sys_id, sys_name in rows:
        ns = (ds_namespace or "").strip().lower()
        if not ns:
            continue
        tide_name: Optional[str] = None
        if ds_tide_id and ds_tide_id in tide_systems_by_id:
            tide_name = tide_systems_by_id[ds_tide_id]
        # If we don't have a TIDE id-based hit but the CyAB system name
        # matches a TIDE system name, use that — covers the case the user
        # described where CyAB and TIDE intentionally share names.
        elif sys_name in tide_systems_by_id.values():
            tide_name = sys_name

        new_cache[ns] = {
            "cyab_system_id": sys_id,
            "cyab_system_name": sys_name,
            "cyab_data_source_id": ds_id,
            "cyab_data_source_name": ds_name,
            "tide_system_id": ds_tide_id,
            "tide_system_name": tide_name,
        }

    return new_cache


def _ensure_fresh(session: Session) -> None:
    """Rebuild the cache if expired. Cheap fast-path under the lock."""
    global _cache, _cache_loaded_at
    now = time.monotonic()
    with _cache_lock:
        if now - _cache_loaded_at < _CACHE_TTL_SECONDS and _cache:
            return
        try:
            _cache = _build_cache(session)
            _cache_loaded_at = now
        except Exception as e:
            logger.warning("system_resolver cache rebuild failed: %s", e)


def resolve_namespace(session: Session, namespace: Optional[str]) -> Dict[str, Any]:
    """Resolve a single namespace to its system identity.

    Always returns a dict — missing fields are None rather than absent so
    callers can blindly merge into an alert dict.
    """
    base: Dict[str, Any] = {
        "source_system": namespace,
        "cyab_system_id": None,
        "cyab_system_name": None,
        "cyab_data_source_id": None,
        "cyab_data_source_name": None,
        "tide_system_id": None,
        "tide_system_name": None,
    }
    if not namespace:
        return base

    _ensure_fresh(session)

    ns = namespace.strip().lower()
    hit = _cache.get(ns)
    if not hit:
        return base

    base.update(hit)
    return base


def bulk_resolve(
    session: Session, namespaces: Iterable[Optional[str]]
) -> Dict[str, Dict[str, Any]]:
    """Resolve many namespaces at once.

    Used by the alerts list endpoint to enrich a whole page of alerts in
    one cache build instead of N lookups. The map is keyed by the raw
    namespace string the caller passed in (preserving casing) so the caller
    can index back into it.
    """
    _ensure_fresh(session)
    out: Dict[str, Dict[str, Any]] = {}
    for ns in namespaces:
        if ns is None or ns in out:
            continue
        out[ns] = resolve_namespace(session, ns)
    return out


def list_known_systems(session: Session) -> list[Dict[str, Any]]:
    """Return every known namespace → system mapping for UI dropdowns.

    Sorted by display name. Each entry contains namespace, cyab_*, tide_*
    fields suitable for filter UIs.
    """
    _ensure_fresh(session)
    out: list[Dict[str, Any]] = []
    for ns, hit in _cache.items():
        out.append({
            "namespace": ns,
            "display_name": hit.get("cyab_system_name") or hit.get("tide_system_name") or ns,
            **hit,
        })
    out.sort(key=lambda r: (r["display_name"] or "").lower())
    return out


def invalidate() -> None:
    """Force the cache to rebuild on the next call.

    Should be invoked from CyAB write endpoints (create/update/delete data
    source) so users see their changes reflected on alerts within the next
    request, not after the 60s TTL.
    """
    global _cache, _cache_loaded_at
    with _cache_lock:
        _cache = {}
        _cache_loaded_at = 0.0
