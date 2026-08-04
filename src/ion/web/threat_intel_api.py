"""Threat Intel API — search OpenCTI actors/campaigns, manage watches, view matches."""

import json
import logging
import re
from pathlib import Path
from typing import Dict, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from ion.auth.dependencies import get_db_session, require_permission
from ion.core.safe_errors import safe_error
from ion.models.threat_intel import ThreatIntelWatch
from ion.models.user import User
from ion.services.country_mapper import country_code_to_flag, get_country_code, get_country_name
from ion.services.observable_service import DISPLAY_ONLY_TYPES
from ion.services.opencti_service import OpenCTIError, get_opencti_service
from ion.services.threat_intel_service import ThreatIntelService
from ion.services.tide_service import get_tide_service

logger = logging.getLogger(__name__)

router = APIRouter(tags=["threat-intel"])

# ---------------------------------------------------------------------------
# Bundled ATT&CK snapshot helpers (used by technique drill endpoint)
# ---------------------------------------------------------------------------

_SNAPSHOT_PATH = Path(__file__).parent.parent / "data" / "attack_techniques.json"
_TECHNIQUE_NORM_RE = re.compile(r"^T?(\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
_snapshot_cache: Optional[Tuple[Dict[str, dict], Dict[str, str]]] = None


def _load_snapshot() -> Tuple[Dict[str, dict], Dict[str, str]]:
    raw = json.loads(_SNAPSHOT_PATH.read_text(encoding="utf-8"))
    by_id: Dict[str, dict] = {}
    by_name: Dict[str, str] = {}
    for entry in raw:
        tid = entry["id"].upper()
        by_id[tid] = {
            "name": entry["name"],
            "tactic_ids": entry.get("tactic_ids", []),
            "is_subtechnique": entry.get("is_subtechnique", False),
            "parent_id": entry.get("parent_id"),
        }
        by_name[entry["name"].lower()] = tid
    return by_id, by_name


def _get_snapshot() -> Tuple[Dict[str, dict], Dict[str, str]]:
    global _snapshot_cache
    if _snapshot_cache is None:
        _snapshot_cache = _load_snapshot()
    return _snapshot_cache


def normalize_technique_id(raw: str) -> Optional[str]:
    m = _TECHNIQUE_NORM_RE.match(raw.strip())
    if not m:
        return None
    return "T" + m.group(1).upper()


# ---- Request/Response Models ----

class AddWatchRequest(BaseModel):
    entity_type: str  # "threat_actor" or "campaign"
    opencti_id: str
    name: str
    description: Optional[str] = None
    aliases: Optional[list] = None
    labels: Optional[list] = None
    reason: Optional[str] = None


# ---- Helper ----

def _watch_to_dict(w) -> dict:
    aliases = None
    if w.aliases:
        try:
            aliases = json.loads(w.aliases)
        except (json.JSONDecodeError, TypeError):
            aliases = []
    labels = None
    if w.labels:
        try:
            labels = json.loads(w.labels)
        except (json.JSONDecodeError, TypeError):
            labels = []
    code = get_country_code(w.name, aliases)
    return {
        "id": w.id,
        "entity_type": w.entity_type,
        "opencti_id": w.opencti_id,
        "name": w.name,
        "description": w.description,
        "aliases": aliases,
        "labels": labels,
        "country_code": code,
        "country_name": get_country_name(code),
        "country_flag": country_code_to_flag(code),
        "last_seen_at": w.last_seen_at.isoformat() if w.last_seen_at else None,
        "match_count": w.match_count,
        "watched_by": w.watched_by,
        "watch_reason": w.watch_reason,
        "is_active": w.is_active,
        "created_at": w.created_at.isoformat() if w.created_at else None,
    }


def _match_to_dict(m) -> dict:
    return {
        "id": m.id,
        "observable_id": m.observable_id,
        "observable_value": m.observable.value if m.observable else None,
        "observable_type": m.observable.type.value if m.observable else None,
        "alert_type": m.alert_type.value if hasattr(m.alert_type, "value") else m.alert_type,
        "message": m.message,
        "details": m.details,
        "is_read": m.is_read,
        "created_at": m.created_at.isoformat() if m.created_at else None,
    }


# ---- OpenCTI Search Endpoints ----

@router.get("/actors")
async def search_actors(
    search: str = Query("", description="Search term"),
    first: int = Query(20, ge=1, le=100),
    after: Optional[str] = Query(None),
    user: User = Depends(require_permission("observable:read")),
):
    """Search OpenCTI for threat actors."""
    service = get_opencti_service()
    if not service.is_configured:
        raise HTTPException(status_code=503, detail="OpenCTI integration is not configured")
    try:
        result = await service.search_threat_actors(search=search, first=first, after=after)
        return result
    except OpenCTIError as e:
        raise HTTPException(status_code=502, detail=safe_error(e, "threat_intel"))


@router.get("/actors/{entity_id}")
async def get_actor_detail(
    entity_id: str,
    entity_class: str = Query("threat_actor", description="threat_actor or intrusion_set"),
    user: User = Depends(require_permission("observable:read")),
):
    """Get detailed info for a threat actor or intrusion set from OpenCTI."""
    service = get_opencti_service()
    if not service.is_configured:
        raise HTTPException(status_code=503, detail="OpenCTI integration is not configured")
    try:
        result = await service.get_entity_detail(entity_id, entity_class)
        if result.get("error"):
            raise HTTPException(status_code=404, detail=result["error"])
        return result
    except OpenCTIError as e:
        raise HTTPException(status_code=502, detail=safe_error(e, "threat_intel"))


@router.get("/campaigns")
async def search_campaigns(
    search: str = Query("", description="Search term"),
    first: int = Query(20, ge=1, le=100),
    after: Optional[str] = Query(None),
    user: User = Depends(require_permission("observable:read")),
):
    """Search OpenCTI for campaigns."""
    service = get_opencti_service()
    if not service.is_configured:
        raise HTTPException(status_code=503, detail="OpenCTI integration is not configured")
    try:
        result = await service.search_campaigns(search=search, first=first, after=after)
        return result
    except OpenCTIError as e:
        raise HTTPException(status_code=502, detail=safe_error(e, "threat_intel"))


@router.get("/campaigns/{entity_id}")
async def get_campaign_detail(
    entity_id: str,
    user: User = Depends(require_permission("observable:read")),
):
    """Get detailed info for a campaign from OpenCTI."""
    service = get_opencti_service()
    if not service.is_configured:
        raise HTTPException(status_code=503, detail="OpenCTI integration is not configured")
    try:
        result = await service.get_entity_detail(entity_id, "campaign")
        if result.get("error"):
            raise HTTPException(status_code=404, detail=result["error"])
        return result
    except OpenCTIError as e:
        raise HTTPException(status_code=502, detail=safe_error(e, "threat_intel"))


# ---- Watch Management ----

@router.get("/watches")
async def list_watches(
    entity_type: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    session: Session = Depends(get_db_session),
    user: User = Depends(require_permission("observable:read")),
):
    """List watched threat actors and campaigns."""
    service = ThreatIntelService(session)
    items, total = service.get_watches(entity_type=entity_type, limit=limit, offset=offset)
    return {
        "watches": [_watch_to_dict(w) for w in items],
        "total": total,
    }


@router.post("/watches")
async def add_watch(
    data: AddWatchRequest,
    session: Session = Depends(get_db_session),
    user: User = Depends(require_permission("observable:enrich")),
):
    """Add an entity to the threat intel watchlist."""
    if data.entity_type not in ("threat_actor", "campaign"):
        raise HTTPException(status_code=400, detail="entity_type must be 'threat_actor' or 'campaign'")

    service = ThreatIntelService(session)
    watch = service.add_watch(
        entity_type=data.entity_type,
        opencti_id=data.opencti_id,
        name=data.name,
        description=data.description,
        aliases=data.aliases,
        labels=data.labels,
        watched_by=user.username,
        reason=data.reason,
    )
    session.commit()
    return _watch_to_dict(watch)


@router.delete("/watches/{watch_id}")
async def remove_watch(
    watch_id: int,
    session: Session = Depends(get_db_session),
    user: User = Depends(require_permission("observable:enrich")),
):
    """Remove (deactivate) a watch."""
    service = ThreatIntelService(session)
    if not service.remove_watch(watch_id):
        raise HTTPException(status_code=404, detail="Watch not found")
    session.commit()
    return {"ok": True}


# ---- Match Alerts ----

@router.get("/matches")
async def list_matches(
    unread_only: bool = Query(False),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    session: Session = Depends(get_db_session),
    user: User = Depends(require_permission("observable:read")),
):
    """List threat actor match alerts."""
    service = ThreatIntelService(session)
    items, total = service.get_matches(unread_only=unread_only, limit=limit, offset=offset)
    return {
        "matches": [_match_to_dict(m) for m in items],
        "total": total,
    }


@router.post("/matches/{match_id}/read")
async def mark_match_read(
    match_id: int,
    session: Session = Depends(get_db_session),
    user: User = Depends(require_permission("observable:read")),
):
    """Mark a match alert as read."""
    service = ThreatIntelService(session)
    if not service.mark_match_read(match_id, user.username):
        raise HTTPException(status_code=404, detail="Match not found")
    session.commit()
    return {"ok": True}


# ---- Overview ----

@router.get("/overview")
async def get_overview(
    session: Session = Depends(get_db_session),
    user: User = Depends(require_permission("observable:read")),
):
    """Get threat intel overview stats."""
    service = ThreatIntelService(session)
    return service.get_overview_stats()


# ---- v0.27.0: Unified search + recently-active ---------------------------

@router.get("/unified-search")
async def unified_search(
    q: str = Query(..., min_length=2, description="Search term"),
    limit_per_kind: int = Query(8, ge=1, le=25),
    session: Session = Depends(get_db_session),
    user: User = Depends(require_permission("observable:read")),
):
    """v0.27.0: cross-entity search bar for the unified /threat-intel page.

    Fans out to OpenCTI (actors + campaigns) and the ION case DB
    (observables matching the term + attack stories whose alerts
    mention it). Returns a typed bundle so the UI can group results
    under headings. Each sub-call is wrapped in its own try/except so
    one source going down doesn't break the others.

    Auth: ``observable:read`` (same gate as the other TI endpoints).
    """
    from sqlalchemy import or_

    from ion.models.alert_triage import AlertCase

    out: dict = {"q": q, "actors": [], "campaigns": [], "iocs": [], "cases": []}

    # Actors + campaigns from OpenCTI (best-effort).
    try:
        svc = get_opencti_service()
        if svc.is_configured:
            try:
                a = await svc.search_threat_actors(search=q, first=limit_per_kind)
                out["actors"] = a.get("actors", []) if isinstance(a, dict) else []
            except Exception as e:
                logger.debug("unified-search: actor search failed: %s", e)
            try:
                c = await svc.search_campaigns(search=q, first=limit_per_kind)
                out["campaigns"] = c.get("campaigns", []) if isinstance(c, dict) else []
            except Exception as e:
                logger.debug("unified-search: campaign search failed: %s", e)
    except Exception as e:
        logger.debug("unified-search: OpenCTI service unavailable: %s", e)

    # Cases whose title or observables JSON mention the term. We use
    # ``.ilike()`` so SQLAlchemy emits dialect-appropriate SQL (Postgres
    # ILIKE, SQLite case-insensitive LIKE). For the observables JSON
    # column we cast to text first; SQLAlchemy's ``cast()`` handles the
    # type translation across dialects.
    try:
        from sqlalchemy import String as _SQLString
        from sqlalchemy import cast
        like = f"%{q}%"
        case_rows = (
            session.query(AlertCase)
            .filter(
                or_(
                    AlertCase.title.ilike(like),
                    cast(AlertCase.observables, _SQLString).ilike(like),
                )
            )
            .order_by(AlertCase.created_at.desc())
            .limit(limit_per_kind)
            .all()
        )
        out["cases"] = [
            {
                "id": c.id,
                "case_number": c.case_number,
                "title": c.title,
                "status": c.status.value if hasattr(c.status, "value") else str(c.status),
                "severity": c.severity,
                "created_at": c.created_at.isoformat() if c.created_at else None,
            }
            for c in case_rows
        ]
    except Exception as e:
        logger.debug("unified-search: case scan failed: %s", e)

    # IOC search: ION's observables table is the right home. Reuse the
    # existing observable_service search rather than re-implementing.
    try:
        from ion.services.observable_service import ObservableService
        obs_svc = ObservableService(session)
        # ObservableService doesn't have a typed-search helper that
        # matches our q-against-value semantics, so use a direct query.
        from ion.models.observable import Observable
        ioc_rows = (
            session.query(Observable)
            .filter(
                or_(
                    Observable.value.ilike(like),
                    Observable.normalized_value.ilike(like),
                )
            )
            .order_by(Observable.last_seen.desc())
            .limit(limit_per_kind)
            .all()
        )
        out["iocs"] = [
            {
                "id": o.id,
                "type": o.type.value if hasattr(o.type, "value") else str(o.type),
                "value": o.value,
                "threat_level": o.threat_level.value if hasattr(o.threat_level, "value") else str(o.threat_level),
                "is_ioc": bool(getattr(o, "is_ioc", False)),
                "is_watched": bool(getattr(o, "is_watched", False)),
            }
            for o in ioc_rows
        ]
        _ = obs_svc  # touch to keep the helper available for follow-ups
    except Exception as e:
        logger.debug("unified-search: IOC scan failed: %s", e)

    out["total"] = (
        len(out["actors"]) + len(out["campaigns"])
        + len(out["iocs"]) + len(out["cases"])
    )
    return out


@router.get("/recently-active")
def recently_active(
    days: int = Query(30, ge=1, le=365),
    top_n: int = Query(10, ge=1, le=50),
    hide_rule_observables: bool = Query(
        True, description="Exclude rule-field / command-content observables (file paths, process/command lines, registry) from the IOC list."
    ),
    session: Session = Depends(get_db_session),
    user: User = Depends(require_permission("observable:read")),
):
    """v0.27.0: "Recently active in cases" widget for the Overview tab.

    Aggregates the last ``days`` of case + triage activity into a
    top-N list of:
      - **observables** — types/values that appear most often in
        AlertCase.observables JSON over the window;
      - **MITRE techniques** — most-frequent technique ids in
        AlertTriage.mitre_techniques JSON over the window.

    No external network — pure SQL + Python aggregation against the
    local DB. Safe to call on cold caches; the queries are bounded by
    the days window and a hard 5000-row scan limit per table.
    """
    from collections import Counter
    from datetime import datetime, timedelta, timezone

    from ion.models.alert_triage import AlertCase, AlertTriage

    cutoff = datetime.now(timezone.utc) - timedelta(days=int(days))

    obs_counter: Counter = Counter()
    case_rows = (
        session.query(AlertCase.observables, AlertCase.created_at)
        .filter(AlertCase.created_at >= cutoff)
        .order_by(AlertCase.created_at.desc())
        .limit(5000)
        .all()
    )
    for obs_json, _created in case_rows:
        if not obs_json:
            continue
        try:
            obs_list = obs_json if isinstance(obs_json, list) else json.loads(obs_json)
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        for o in obs_list or []:
            if isinstance(o, dict):
                t = str(o.get("type") or "")
                v = str(o.get("value") or "")
                # Rule-field / command-content roles (process_name, command_line,
                # file_path, registry_*, …) are not trackable IOCs — the user can
                # toggle them out (default on).
                if hide_rule_observables and t in DISPLAY_ONLY_TYPES:
                    continue
                if t and v:
                    obs_counter[(t, v)] += 1

    tech_counter: Counter = Counter()
    triage_rows = (
        session.query(AlertTriage.mitre_techniques, AlertTriage.created_at)
        .filter(AlertTriage.created_at >= cutoff)
        .order_by(AlertTriage.created_at.desc())
        .limit(5000)
        .all()
    )
    for tech_json, _created in triage_rows:
        if not tech_json:
            continue
        try:
            tech_list = (
                tech_json if isinstance(tech_json, list) else json.loads(tech_json)
            )
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        for t in tech_list or []:
            if not t:
                continue
            # The column is written in two shapes: bare ids ("T1059", from
            # seeds/fixtures) and dicts ({"technique_id": "T1059", ...}, from the
            # manual triage-edit PUT). Tolerate both — str(dict) used to produce
            # a Python-repr that never matched a Txxxx id, blanking the widget.
            tid = t.get("technique_id") if isinstance(t, dict) else str(t)
            if tid:
                tech_counter[str(tid).upper()] += 1

    return {
        "time_window_days": days,
        "case_sample_size": len(case_rows),
        "triage_sample_size": len(triage_rows),
        "observables": [
            {"type": t, "value": v, "count": c}
            for (t, v), c in obs_counter.most_common(top_n)
        ],
        "techniques": [
            {"id": tid, "count": c}
            for tid, c in tech_counter.most_common(top_n)
        ],
    }


@router.get("/ioc-sightings")
def ioc_sightings(
    value: str = Query(..., min_length=2, description="IOC value (case-insensitive)"),
    months: int = Query(12, ge=1, le=36),
    session: Session = Depends(get_db_session),
    user: User = Depends(require_permission("observable:read")),
):
    """v0.27.0: per-IOC histogram across the last N months of local cases.

    Powers the sparkline in the IOC Feed tab. Returns one bucket per
    calendar month, oldest → newest, each ``{"month": "YYYY-MM",
    "count": int}``. A bucket count is the number of distinct
    AlertCase rows whose ``observables`` JSON column mentions the
    given value (case-insensitive substring match — keeps the query
    cheap and dialect-portable).

    Empty histogram (all zeros) means "never seen locally" — useful
    signal that an IOC from OpenCTI hasn't landed in any of our cases.
    """
    from collections import OrderedDict
    from datetime import datetime, timedelta, timezone

    from sqlalchemy import String as _SQLString
    from sqlalchemy import cast

    from ion.models.alert_triage import AlertCase

    now = datetime.now(timezone.utc)
    # Build N month buckets newest → oldest then reverse, so the JSON
    # response renders left-to-right as time progresses.
    buckets: "OrderedDict[str, int]" = OrderedDict()
    cursor = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    for _ in range(int(months)):
        buckets[cursor.strftime("%Y-%m")] = 0
        # Step back one month (handles year rollover).
        if cursor.month == 1:
            cursor = cursor.replace(year=cursor.year - 1, month=12)
        else:
            cursor = cursor.replace(month=cursor.month - 1)
    # Reverse so the OrderedDict iterates oldest → newest.
    buckets = OrderedDict(reversed(list(buckets.items())))

    cutoff = now - timedelta(days=int(months) * 31)
    like = f"%{value}%"
    rows = (
        session.query(AlertCase.created_at)
        .filter(
            AlertCase.created_at >= cutoff,
            cast(AlertCase.observables, _SQLString).ilike(like),
        )
        .limit(5000)
        .all()
    )
    for (created,) in rows:
        if created is None:
            continue
        key = created.strftime("%Y-%m")
        if key in buckets:
            buckets[key] += 1

    series = [{"month": m, "count": c} for m, c in buckets.items()]
    total = sum(c for c in buckets.values())
    return {
        "value": value,
        "months": months,
        "total_sightings": total,
        "series": series,
    }


@router.get("/techniques/{technique_id}/drill")
def technique_drill(
    technique_id: str,
    session: Session = Depends(get_db_session),
    user: User = Depends(require_permission("observable:read")),
):
    """v0.27.0: click-to-drill on a MITRE technique.

    Returns:
      * Technique metadata from the bundled ATT&CK v15.1 snapshot
        (id, name, tactic_ids, is_subtechnique).
      * Local cases whose AlertTriage rows carry this technique in
        their ``mitre_techniques`` JSON column (last 90 days).
      * Optionally: actors in OpenCTI known to use this technique.
        Wraps the existing OpenCTI service in a try/except so an
        unconfigured deployment doesn't 500 the panel.
    """
    from datetime import datetime, timedelta, timezone

    from sqlalchemy import String as _SQLString
    from sqlalchemy import cast

    from ion.models.alert_triage import AlertCase, AlertTriage

    tid = normalize_technique_id(technique_id)
    if not tid:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid technique id: {technique_id!r}",
        )

    by_id, _ = _get_snapshot()
    meta = by_id.get(tid)
    if meta is None:
        raise HTTPException(
            status_code=404,
            detail=f"Technique {tid} not in bundled ATT&CK snapshot",
        )

    # Local cases referencing this technique. SQLite + Postgres both
    # accept the cast-to-text + ilike pattern for JSON columns.
    cutoff = datetime.now(timezone.utc) - timedelta(days=90)
    like_pattern = f'%"{tid}"%'  # technique strings are JSON-quoted
    case_rows = (
        session.query(
            AlertCase.id,
            AlertCase.case_number,
            AlertCase.title,
            AlertCase.severity,
            AlertCase.created_at,
        )
        .join(AlertTriage, AlertTriage.case_id == AlertCase.id)
        .filter(
            AlertTriage.created_at >= cutoff,
            cast(AlertTriage.mitre_techniques, _SQLString).ilike(like_pattern),
        )
        .distinct()
        .order_by(AlertCase.created_at.desc())
        .limit(25)
        .all()
    )

    out: dict = {
        "technique_id": tid,
        "name": meta["name"],
        "tactic_ids": meta["tactic_ids"],
        "is_subtechnique": meta["is_subtechnique"],
        "parent_id": meta["parent_id"],
        "local_cases": [
            {
                "id": r[0], "case_number": r[1], "title": r[2],
                "severity": r[3],
                "created_at": r[4].isoformat() if r[4] else None,
            }
            for r in case_rows
        ],
        "actors": [],
        "actors_error": None,
    }

    # Best-effort OpenCTI lookup for actors using this technique.
    try:
        svc = get_opencti_service()
        if svc.is_configured and hasattr(svc, "search_actors_by_technique"):
            # Optional method — may not exist on every OpenCTI service
            # build. The fallback is "skip silently" so the panel still
            # renders the local-case half.
            actors = svc.search_actors_by_technique(tid)  # type: ignore[attr-defined]
            if hasattr(actors, "__await__"):
                import asyncio
                actors = asyncio.run(actors)
            out["actors"] = actors or []
    except Exception as exc:
        out["actors_error"] = safe_error(exc, "threat_intel.actors_by_technique")

    return out


@router.get("/actors/{entity_id}/profile")
async def actor_profile(
    entity_id: str,
    entity_class: str = Query("intrusion_set"),
    session: Session = Depends(get_db_session),
    user: User = Depends(require_permission("observable:read")),
):
    """v0.27.0: actor deep-dive profile.

    Returns the OpenCTI actor detail (description, aliases, TTPs,
    malware, indicators) plus a "recently active in your cases" feed
    derived from local cases whose linked alerts mention this actor
    by name/alias in their analyst notes, observables, or triggered
    rule names.

    Best-effort fan-out: OpenCTI errors don't break the local-case
    half; missing local cases don't break the OpenCTI half.
    """
    from datetime import datetime, timedelta, timezone

    from sqlalchemy import String as _SQLString
    from sqlalchemy import cast, or_

    from ion.models.alert_triage import AlertCase

    out: dict = {
        "entity_id": entity_id, "entity_class": entity_class,
        "actor": None, "actor_error": None,
        "recent_cases": [],
    }

    # OpenCTI side
    try:
        svc = get_opencti_service()
        if not svc.is_configured:
            out["actor_error"] = "OpenCTI not configured"
        else:
            detail = await svc.get_entity_detail(entity_id, entity_class)
            if detail.get("error"):
                out["actor_error"] = detail["error"]
            else:
                out["actor"] = detail
    except Exception as exc:
        out["actor_error"] = safe_error(exc, "threat_intel.actor_profile")

    # Local cases referencing this actor by name or alias. Use the
    # actor's name + aliases as the haystack terms.
    actor = out.get("actor") or {}
    needles: list[str] = []
    if actor.get("name"):
        needles.append(str(actor["name"]))
    aliases_raw = actor.get("aliases")
    if aliases_raw:
        if isinstance(aliases_raw, list):
            needles.extend(str(a) for a in aliases_raw if a)
        elif isinstance(aliases_raw, str):
            needles.append(aliases_raw)
    # Trim short / generic aliases that would produce too-broad hits
    # (e.g. "G0007"). Keep names ≥ 4 chars.
    needles = [n for n in needles if n and len(n) >= 4]
    needles = list(dict.fromkeys(needles))  # dedup, preserve order

    if needles:
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(days=180)
            like_clauses = [
                cast(AlertCase.observables, _SQLString).ilike(f"%{n}%")
                for n in needles
            ] + [
                AlertCase.title.ilike(f"%{n}%") for n in needles
            ] + [
                cast(AlertCase.affected_users, _SQLString).ilike(f"%{n}%")
                for n in needles
            ]
            rows = (
                session.query(AlertCase)
                .filter(
                    AlertCase.created_at >= cutoff,
                    or_(*like_clauses),
                )
                .order_by(AlertCase.created_at.desc())
                .limit(15)
                .all()
            )
            out["recent_cases"] = [
                {
                    "id": c.id, "case_number": c.case_number,
                    "title": c.title,
                    "status": c.status.value if hasattr(c.status, "value") else str(c.status),
                    "severity": c.severity,
                    "created_at": c.created_at.isoformat() if c.created_at else None,
                }
                for c in rows
            ]
        except Exception as exc:
            logger.debug("actor_profile: local case match failed: %s", exc)

    return out


# ── Watch gap analysis (merged from threat_watch_gap_api, route audit phase 2) ──
# Was /api/threat-intel/threat-watch-gaps/{check,check-and-notify}. The POST
# "check-and-notify" half stopped notifying in v0.9.76 and differed from /check
# only by a derived counter, so the two collapse into this single GET. Exposed
# as a projection *of watches*, and aligned to observable:read (the permission
# every other ThreatIntelWatch read uses) instead of alert:read.

async def _check_watch_gaps(session: Session) -> dict:
    """Core logic: check all active watches for TIDE detection gaps."""
    tide = get_tide_service()
    if not tide or not tide.enabled:
        return {"enabled": False, "error": "TIDE integration is not configured or disabled"}

    opencti = get_opencti_service()
    if not opencti or not opencti.is_configured:
        return {"enabled": False, "error": "OpenCTI integration is not configured"}

    coverage_data = tide.get_global_mitre_coverage()
    if not coverage_data:
        return {"enabled": False, "error": "Unable to retrieve TIDE coverage data"}

    tide_techniques = coverage_data.get("techniques", {})

    watches = session.execute(
        select(ThreatIntelWatch).where(ThreatIntelWatch.is_active == True)
    ).scalars().all()

    results = []
    for watch in watches:
        try:
            detail = await opencti.get_entity_detail(watch.opencti_id, watch.entity_type)
        except Exception:
            logger.warning("Failed to get OpenCTI detail for watch %s (%s)", watch.id, watch.name)
            continue

        ttps = detail.get("ttps", []) if detail else []
        if not ttps:
            continue

        gap_techniques = []
        covered_count = 0

        for ttp in ttps:
            mitre_id = ttp.get("mitre_id", "")
            parent_id = mitre_id.split(".")[0] if mitre_id else ""

            if parent_id and parent_id in tide_techniques:
                tech = tide_techniques[parent_id]
                if tech.get("rule_count", 0) > 0:
                    covered_count += 1
                    continue

            gap_techniques.append({"mitre_id": mitre_id, "name": ttp.get("name", "")})

        total = len(ttps)
        coverage_pct = round((covered_count / total) * 100, 1) if total > 0 else 0.0

        results.append({
            "watch_id": watch.id,
            "actor_name": watch.name,
            "watched_by": watch.watched_by,
            "total_ttps": total,
            "covered": covered_count,
            "gaps": len(gap_techniques),
            "gap_techniques": gap_techniques,
            "coverage_pct": coverage_pct,
        })

    gaps_found = sum(1 for r in results if r["gaps"] > 0)

    return {
        "checked": len(results),
        "gaps_found": gaps_found,
        "results": results,
    }


@router.get("/watches/gaps")
async def watch_gaps(
    min_gap_count: int = Query(1, ge=0),
    current_user: User = Depends(require_permission("observable:read")),
    session: Session = Depends(get_db_session),
):
    """Detection-coverage gaps for actively watched actors (TIDE vs their TTPs)."""
    result = await _check_watch_gaps(session)
    if "enabled" in result and not result["enabled"]:
        return result

    result["gaps_detected"] = sum(
        1 for r in result.get("results", []) if r.get("gaps", 0) >= min_gap_count
    )
    for r in result.get("results", []):
        r.pop("watched_by", None)
    return result
