"""Repository for investigation memory (Investigations, IOC sightings, FP signatures).

All functions take an explicit ``db: Session`` so the caller controls
transaction boundaries (either a FastAPI dependency session or a
service-managed session factory). They flush but do NOT commit — that's
the caller's responsibility.
"""

from __future__ import annotations

import fnmatch
import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional, Tuple

from sqlalchemy import and_, desc, select
from sqlalchemy.orm import Session

from ion.models.investigation import (
    FalsePositiveSignature,
    IOCSighting,
    Investigation,
)

logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _to_json(value: Any) -> Optional[str]:
    """JSON-serialize a python object, tolerating strings and None."""
    if value is None:
        return None
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, default=str)
    except (TypeError, ValueError):
        return None


# =========================================================================
# Investigations
# =========================================================================

def record_investigation_start(alert: dict, db: Session) -> Investigation:
    """Create an Investigation row in ``pending`` status for this alert.

    The ``alert`` dict is expected to carry at minimum an ``_id`` (the
    ES alert id) and a signature/rule name. Missing fields are tolerated
    and stored as NULL so a partial alert still produces a row.
    """
    source = alert.get("_source", alert) if isinstance(alert, dict) else {}

    def _get_path(d: dict, path: str):
        """Walk a dotted path into nested dicts. Returns None on miss."""
        cur: Any = d
        for part in path.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                return None
        return cur

    def get(key: str):
        """Support flat-key ('host.name'), dotted drill-in, and nested fallback."""
        for root in (alert, source):
            if not isinstance(root, dict):
                continue
            if key in root:
                return root[key]
            v = _get_path(root, key)
            if v is not None:
                return v
        return None

    def _as_str_or_none(v, *sub_keys):
        """Coerce v to a string. If v is a dict, try sub_keys in order for a string-valued leaf."""
        if v is None:
            return None
        if isinstance(v, str):
            return v or None
        if isinstance(v, dict):
            for k in sub_keys:
                cand = v.get(k)
                if isinstance(cand, str) and cand:
                    return cand
            return None
        return str(v)

    signature = (
        get("alert_signature")
        or get("signature")
        or get("rule_name")
        or get("rule.name")
        or get("kibana.alert.rule.name")
        or "unknown"
    )

    host_val = _as_str_or_none(get("host"), "hostname", "name") \
        or _as_str_or_none(get("host_name")) \
        or _as_str_or_none(get("host.name"))
    source_ip_val = _as_str_or_none(get("source_ip")) \
        or _as_str_or_none(get("source"), "ip") \
        or _as_str_or_none(get("source.ip"))
    user_name_val = _as_str_or_none(get("user_name")) \
        or _as_str_or_none(get("user"), "name", "username") \
        or _as_str_or_none(get("user.name"))

    inv = Investigation(
        alert_id_ref=str(alert.get("_id") or get("alert_id") or get("id") or ""),
        alert_signature=str(signature)[:500] if not isinstance(signature, dict) else "unknown",
        host=host_val,
        source_ip=source_ip_val,
        user_name=user_name_val,
        status="pending",
        created_at=_utcnow(),
    )
    db.add(inv)
    db.flush()
    return inv


def record_investigation_end(
    inv_id: int,
    verdict: Optional[str],
    severity: Optional[str],
    summary: Optional[str],
    actions: Any,
    iocs: Any,
    llm_model: Optional[str],
    tokens: Optional[int],
    duration_ms: Optional[int],
    db: Session,
    prompt_snapshot: Optional[str] = None,
    raw_response: Optional[str] = None,
    key_observations: Any = None,
) -> Optional[Investigation]:
    """Mark an investigation as completed with its outcome + telemetry."""
    inv = db.get(Investigation, inv_id)
    if inv is None:
        logger.warning("record_investigation_end: no investigation with id=%s", inv_id)
        return None

    inv.status = "completed"
    inv.verdict = verdict
    inv.severity_assessment = severity
    inv.summary_text = summary
    inv.recommended_actions_json = _to_json(actions)
    inv.ioc_snapshot_json = _to_json(iocs)
    inv.llm_model_used = llm_model
    inv.tokens_used = tokens
    inv.duration_ms = duration_ms
    inv.completed_at = _utcnow()
    if prompt_snapshot is not None:
        inv.prompt_snapshot = prompt_snapshot[:100_000]  # hard cap for runaway prompts
    if raw_response is not None:
        inv.raw_response = raw_response[:100_000]
    if key_observations is not None:
        inv.key_observations_json = _to_json(key_observations)
    db.flush()
    return inv


def mark_investigation_failed(
    inv_id: int, error: Optional[str], db: Session
) -> Optional[Investigation]:
    """Mark an investigation as failed (e.g. the LLM call errored)."""
    inv = db.get(Investigation, inv_id)
    if inv is None:
        return None
    inv.status = "failed"
    inv.summary_text = (error or "investigation failed")[:4000]
    inv.completed_at = _utcnow()
    db.flush()
    return inv


def list_investigations(
    filters: dict,
    db: Session,
    limit: int = 50,
    offset: int = 0,
) -> list[Investigation]:
    """List investigations matching ``filters``.

    Supported filters: ``verdict``, ``status``, ``alert_signature``,
    ``host``, ``from_date``, ``to_date`` (ISO strings or datetime).
    Unknown keys are ignored so the caller can pass query params verbatim.
    """
    stmt = select(Investigation)
    filters = filters or {}

    if filters.get("verdict"):
        stmt = stmt.where(Investigation.verdict == filters["verdict"])
    if filters.get("status"):
        stmt = stmt.where(Investigation.status == filters["status"])
    if filters.get("alert_signature"):
        stmt = stmt.where(Investigation.alert_signature == filters["alert_signature"])
    if filters.get("host"):
        stmt = stmt.where(Investigation.host == filters["host"])

    from_date = filters.get("from_date")
    if from_date:
        if isinstance(from_date, str):
            try:
                from_date = datetime.fromisoformat(from_date)
            except ValueError:
                from_date = None
        if from_date:
            stmt = stmt.where(Investigation.created_at >= from_date)

    to_date = filters.get("to_date")
    if to_date:
        if isinstance(to_date, str):
            try:
                to_date = datetime.fromisoformat(to_date)
            except ValueError:
                to_date = None
        if to_date:
            stmt = stmt.where(Investigation.created_at <= to_date)

    stmt = stmt.order_by(desc(Investigation.created_at)).limit(limit).offset(offset)
    return list(db.execute(stmt).scalars().all())


def get_investigation(inv_id: int, db: Session) -> Optional[Investigation]:
    """Fetch one investigation by id."""
    return db.get(Investigation, inv_id)


def past_investigations_for_signature(
    alert_signature: str, db: Session, limit: int = 5
) -> list[Investigation]:
    """Return the most recent *completed* investigations for this rule.

    Used by the autonomous loop to say "we've seen this rule N times —
    here's what happened before". We filter to completed runs because
    pending/failed runs carry no useful verdict.
    """
    stmt = (
        select(Investigation)
        .where(
            Investigation.alert_signature == alert_signature,
            Investigation.status == "completed",
        )
        .order_by(desc(Investigation.created_at))
        .limit(limit)
    )
    return list(db.execute(stmt).scalars().all())


# =========================================================================
# IOC Sightings
# =========================================================================

def upsert_ioc_sighting(
    ioc_type: str,
    ioc_value: str,
    db: Session,
    reputation: Any = None,
    inv_id: Optional[int] = None,
) -> IOCSighting:
    """Insert or update a sighting for this IOC.

    On insert: seen_count=1, first_seen_at=now.
    On update: seen_count += 1, last_seen_at=now; reputation snapshot
    is only overwritten when a non-None value is supplied (we don't
    erase a cached reputation with a missing one).
    """
    stmt = select(IOCSighting).where(
        IOCSighting.ioc_type == ioc_type,
        IOCSighting.ioc_value == ioc_value,
    )
    sighting = db.execute(stmt).scalar_one_or_none()

    now = _utcnow()

    if sighting is None:
        sighting = IOCSighting(
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            seen_count=1,
            first_seen_at=now,
            last_seen_at=now,
            last_investigation_id=inv_id,
            reputation_snapshot_json=_to_json(reputation),
        )
        db.add(sighting)
    else:
        sighting.seen_count = (sighting.seen_count or 0) + 1
        sighting.last_seen_at = now
        if inv_id is not None:
            sighting.last_investigation_id = inv_id
        if reputation is not None:
            sighting.reputation_snapshot_json = _to_json(reputation)

    db.flush()
    return sighting


def lookup_ioc_history(
    ioc_type: str, ioc_value: str, db: Session
) -> Optional[IOCSighting]:
    """Return the existing IOCSighting or None."""
    stmt = select(IOCSighting).where(
        IOCSighting.ioc_type == ioc_type,
        IOCSighting.ioc_value == ioc_value,
    )
    return db.execute(stmt).scalar_one_or_none()


def list_ioc_sightings(
    db: Session,
    ioc_type: Optional[str] = None,
    is_known_bad: Optional[bool] = None,
    limit: int = 100,
    offset: int = 0,
) -> list[IOCSighting]:
    """List IOC sightings with optional filters, newest first."""
    stmt = select(IOCSighting)
    if ioc_type:
        stmt = stmt.where(IOCSighting.ioc_type == ioc_type)
    if is_known_bad is not None:
        stmt = stmt.where(IOCSighting.is_known_bad.is_(is_known_bad))
    stmt = stmt.order_by(desc(IOCSighting.last_seen_at)).limit(limit).offset(offset)
    return list(db.execute(stmt).scalars().all())


def recent_sightings_for_host(
    host: str, db: Session, limit: int = 10
) -> list[IOCSighting]:
    """Return recent IOC sightings tied to investigations on this host.

    Joins through ``investigations.host`` via the soft
    ``last_investigation_id`` reference. If the investigation row has
    been purged, those sightings are skipped.
    """
    if not host:
        return []

    stmt = (
        select(IOCSighting)
        .join(
            Investigation,
            Investigation.id == IOCSighting.last_investigation_id,
        )
        .where(Investigation.host == host)
        .order_by(desc(IOCSighting.last_seen_at))
        .limit(limit)
    )
    return list(db.execute(stmt).scalars().all())


# =========================================================================
# False Positive Signatures
# =========================================================================

def record_fp(
    db: Session,
    reason: str,
    confidence: int = 80,
    recorded_by: Optional[int] = None,
    rule_id: Optional[str] = None,
    rule_name: Optional[str] = None,
    alert_signature: Optional[str] = None,
    host_pattern: Optional[str] = None,
    user_pattern: Optional[str] = None,
) -> FalsePositiveSignature:
    """Create a new FP signature. Any of the match fields may be None."""
    fp = FalsePositiveSignature(
        rule_id=rule_id,
        rule_name=rule_name,
        alert_signature=alert_signature,
        host_pattern=host_pattern,
        user_pattern=user_pattern,
        reason=reason,
        confidence=max(0, min(100, int(confidence))),
        recorded_by=recorded_by,
        recorded_at=_utcnow(),
        enabled=True,
    )
    db.add(fp)
    db.flush()
    return fp


def _extract_alert_fields(alert: dict) -> tuple[str, str, str, str, str]:
    """Pull rule_id / rule_name / signature / host / user from any alert shape."""
    source = alert.get("_source", alert) if isinstance(alert, dict) else {}
    g = lambda k: alert.get(k) or source.get(k) or ""
    rule_id = g("rule_id") or g("kibana.alert.rule.uuid") or g("rule.id") or ""
    rule_name = g("rule_name") or g("kibana.alert.rule.name") or g("rule.name") or ""
    signature = g("alert_signature") or g("signature") or rule_name
    host = g("host") or g("host.name") or g("host_name") or ""
    user = g("user_name") or g("user.name") or ""
    return str(rule_id), str(rule_name), str(signature), str(host), str(user)


def is_likely_fp(
    alert: dict, db: Session
) -> Tuple[bool, Optional[FalsePositiveSignature]]:
    """Check if this alert matches any enabled FP signature.

    Match precedence:
      1. ``rule_id`` exact
      2. ``rule_name`` exact
      3. ``alert_signature`` exact
    If any of those match, we then verify host_pattern and user_pattern
    using fnmatch (if set). An FP signature with no host/user constraint
    matches any host/user.

    Returns (matched, signature). When matched, ``hit_count`` and
    ``last_matched_at`` on the signature are bumped as a side effect so
    analysts can see which rules are earning their keep.
    """
    rule_id, rule_name, signature, host, user = _extract_alert_fields(alert)

    stmt = (
        select(FalsePositiveSignature)
        .where(FalsePositiveSignature.enabled.is_(True))
        .order_by(desc(FalsePositiveSignature.confidence))
    )
    candidates = db.execute(stmt).scalars().all()

    for fp in candidates:
        # At least ONE of rule_id/rule_name/alert_signature must be set and match.
        id_match = fp.rule_id and rule_id and fp.rule_id == rule_id
        name_match = fp.rule_name and rule_name and fp.rule_name == rule_name
        sig_match = (
            fp.alert_signature
            and signature
            and fp.alert_signature == signature
        )
        if not (id_match or name_match or sig_match):
            continue

        # Host / user pattern gates — only apply if the FP sets them.
        if fp.host_pattern and not fnmatch.fnmatch(host or "", fp.host_pattern):
            continue
        if fp.user_pattern and not fnmatch.fnmatch(user or "", fp.user_pattern):
            continue

        # Matched — bump telemetry.
        fp.hit_count = (fp.hit_count or 0) + 1
        fp.last_matched_at = _utcnow()
        db.flush()
        return True, fp

    return False, None


def list_fps(
    db: Session, limit: int = 100, offset: int = 0
) -> list[FalsePositiveSignature]:
    """List FP signatures newest first."""
    stmt = (
        select(FalsePositiveSignature)
        .order_by(desc(FalsePositiveSignature.recorded_at))
        .limit(limit)
        .offset(offset)
    )
    return list(db.execute(stmt).scalars().all())


def get_fp(fp_id: int, db: Session) -> Optional[FalsePositiveSignature]:
    return db.get(FalsePositiveSignature, fp_id)


def delete_fp(fp_id: int, db: Session) -> bool:
    """Hard-delete the FP signature. Returns True if it existed."""
    fp = db.get(FalsePositiveSignature, fp_id)
    if fp is None:
        return False
    db.delete(fp)
    db.flush()
    return True


def toggle_fp(fp_id: int, db: Session) -> Optional[FalsePositiveSignature]:
    """Flip ``enabled`` on an FP signature."""
    fp = db.get(FalsePositiveSignature, fp_id)
    if fp is None:
        return None
    fp.enabled = not bool(fp.enabled)
    db.flush()
    return fp
