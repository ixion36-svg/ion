"""System Quirks service — Phase 2 of the DE module.

Raise (pending) → verify (a DIFFERENT person, → active) → revert. Plus the
advisory matcher `quirk_match`, whose output ONLY decorates an alert dict — there
is deliberately no code path here that closes, filters, or hides an alert.

Anti-abuse invariants enforced here (roadmap §4):
- separation of duties: `verify_quirk` rejects `verified_by == raised_by`;
- scoped blast radius: `raise_quirk` requires ≥1 concrete scope value and rejects
  wildcards;
- mandatory expiry: `review_date` must be in the future; `quirk_match` ignores
  any quirk at/after its review_date (on-read expiry — a lapsed quirk is inert);
- full audit: raise/verify/revert each write an append-only AuditLog entry.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from ion.models.system_quirk import SystemQuirk, SystemQuirkStatus
from ion.storage.auth_repository import AuditLogRepository

_WILDCARDS = {"", "*", "all", "any", "%"}


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _parse_dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "")).replace(tzinfo=None)
    except (TypeError, ValueError):
        return None


def _clean_scope(values: Any) -> List[str]:
    """Normalise a scope list: lowercase, de-dup, drop blanks. Raise on wildcard."""
    out: List[str] = []
    if not isinstance(values, list):
        return out
    for v in values:
        s = str(v).strip().lower()
        if s in _WILDCARDS:
            raise ValueError("wildcard scope values are not allowed")
        if s and s not in out:
            out.append(s)
    return out


def _clean_observables(values: Any) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    if not isinstance(values, list):
        return out
    for o in values:
        if isinstance(o, dict):
            t = str(o.get("type") or "").strip().lower()
            val = str(o.get("value") or "").strip().lower()
            if val in _WILDCARDS or t in _WILDCARDS:
                raise ValueError("wildcard scope values are not allowed")
            if val:
                out.append({"type": t, "value": val})
    return out


def _audit(session: Session, action: str, user_id: Optional[int], quirk: SystemQuirk,
           extra: Optional[Dict[str, Any]] = None) -> None:
    details = {
        "quirk_id": quirk.id,
        "title": quirk.title,
        "status": quirk.status,
        "scope": {
            "rules": quirk.scope_rules or [],
            "hosts": quirk.scope_hosts or [],
            "users": quirk.scope_users or [],
            "ips": quirk.scope_ips or [],
            "observables": quirk.scope_observables or [],
        },
        "raised_by_id": quirk.raised_by_id,
        "verified_by_id": quirk.verified_by_id,
    }
    if extra:
        details.update(extra)
    AuditLogRepository(session).create(
        action=action, user_id=user_id, resource_type="system_quirk",
        resource_id=quirk.id, details=details,
    )


def raise_quirk(session: Session, payload: Dict[str, Any], user_id: Optional[int]) -> SystemQuirk:
    """Create a pending quirk. Raises ValueError on invalid scope/fields."""
    title = (payload.get("title") or "").strip()
    annotation = (payload.get("annotation") or "").strip()
    justification = (payload.get("justification") or "").strip()
    if not title:
        raise ValueError("title is required")
    if not annotation:
        raise ValueError("annotation is required")
    if not justification:
        raise ValueError("justification is required")

    review_date = _parse_dt(payload.get("review_date"))
    if review_date is None:
        raise ValueError("review_date is required (quirks must expire)")
    if review_date <= _now():
        raise ValueError("review_date must be in the future")

    rules = _clean_scope(payload.get("scope_rules"))
    hosts = _clean_scope(payload.get("scope_hosts"))
    users = _clean_scope(payload.get("scope_users"))
    ips = _clean_scope(payload.get("scope_ips"))
    observables = _clean_observables(payload.get("scope_observables"))
    if not (rules or hosts or users or ips or observables):
        raise ValueError(
            "at least one concrete scope (rule / host / user / ip / observable) is required — "
            "a quirk cannot be global"
        )

    try:
        nudge = int(payload.get("priority_nudge") or 0)
    except (TypeError, ValueError):
        nudge = 0
    nudge = max(-5, min(5, nudge))

    quirk = SystemQuirk(
        title=title,
        scope_rules=rules,
        scope_hosts=hosts,
        scope_users=users,
        scope_ips=ips,
        scope_observables=observables,
        annotation=annotation,
        priority_nudge=nudge,
        justification=justification,
        status=SystemQuirkStatus.PENDING,
        review_date=review_date,
        raised_by_id=user_id,
    )
    session.add(quirk)
    session.flush()
    _audit(session, "quirk_raised", user_id, quirk)
    session.commit()
    session.refresh(quirk)
    return quirk


def verify_quirk(session: Session, quirk_id: int, user_id: Optional[int]) -> SystemQuirk:
    """Activate a pending quirk. Enforces separation of duties in code."""
    q = session.get(SystemQuirk, quirk_id)
    if q is None:
        raise ValueError("quirk not found")
    if q.status != SystemQuirkStatus.PENDING:
        raise ValueError(f"quirk is {q.status} — only pending quirks can be verified")
    # Separation of duties — independent of permissions held.
    if q.raised_by_id is not None and q.raised_by_id == user_id:
        raise ValueError("separation of duties: a quirk must be verified by a different user")

    q.status = SystemQuirkStatus.ACTIVE
    q.verified_by_id = user_id
    q.verified_at = _now()
    _audit(session, "quirk_verified", user_id, q)
    session.commit()
    session.refresh(q)
    return q


def revert_quirk(session: Session, quirk_id: int, user_id: Optional[int],
                 reason: Optional[str] = None) -> SystemQuirk:
    """Revoke a quirk (pending or active) — one click, fully audited."""
    q = session.get(SystemQuirk, quirk_id)
    if q is None:
        raise ValueError("quirk not found")
    if q.status == SystemQuirkStatus.REVERTED:
        raise ValueError("quirk is already reverted")
    q.status = SystemQuirkStatus.REVERTED
    q.reverted_by_id = user_id
    q.reverted_at = _now()
    q.revert_reason = (reason or None)
    _audit(session, "quirk_reverted", user_id, q, {"reason": reason})
    session.commit()
    session.refresh(q)
    return q


def list_quirks(session: Session, status: Optional[str] = None, limit: int = 200) -> List[Dict[str, Any]]:
    q = select(SystemQuirk).order_by(SystemQuirk.created_at.desc())
    if status and status != "all":
        q = q.where(SystemQuirk.status == SystemQuirkStatus(status))
    rows = session.execute(q.limit(limit)).scalars().all()
    return [r.to_dict() for r in rows]


def get_quirk(session: Session, quirk_id: int) -> Optional[Dict[str, Any]]:
    q = session.get(SystemQuirk, quirk_id)
    return q.to_dict() if q else None


# ── advisory matcher (annotate-only) ─────────────────────────────────────────


def _active_quirks(session: Session, now: Optional[datetime] = None) -> List[SystemQuirk]:
    """Active quirks that have not passed their review_date (on-read expiry)."""
    ref = now or _now()
    rows = session.execute(
        select(SystemQuirk)
        .where(SystemQuirk.status == SystemQuirkStatus.ACTIVE)
        .where(SystemQuirk.review_date > ref)
    ).scalars().all()
    return list(rows)


def _norm(v: Any) -> str:
    return str(v).strip().lower()


def _alert_values(alert: Dict[str, Any]) -> Dict[str, set]:
    """Pull comparable values out of an alert dict (scalars OR lists tolerated)."""
    def collect(*keys) -> set:
        vals: set = set()
        for k in keys:
            v = alert.get(k)
            if isinstance(v, list):
                vals.update(_norm(x) for x in v if x is not None and str(x).strip())
            elif v is not None and str(v).strip():
                vals.add(_norm(v))
        return vals

    obs: set = set()
    raw_obs = alert.get("observables")
    if isinstance(raw_obs, list):
        for o in raw_obs:
            if isinstance(o, dict):
                val = _norm(o.get("value") or "")
                t = _norm(o.get("type") or "")
                if val:
                    obs.add(f"{t}:{val}")
                    obs.add(val)  # allow type-agnostic value match
            elif isinstance(o, str) and o.strip():
                obs.add(_norm(o))
    return {
        "rules": collect("rule_name", "rule", "triggered_rules"),
        "hosts": collect("host", "hostname", "affected_hosts"),
        "users": collect("user", "username", "affected_users"),
        "ips": collect("source_ip", "destination_ip", "src_ip", "dest_ip", "ip"),
        "observables": obs,
    }


def _matches(quirk: SystemQuirk, av: Dict[str, set]) -> bool:
    """AND across the scope dimensions the quirk specifies, OR within each list.

    A quirk only annotates an alert that satisfies EVERY scope dimension it sets —
    precise by design, so a genuinely malicious alert isn't badged 'known benign'
    just for sharing one attribute. Unspecified dimensions are ignored.
    """
    checks = [
        (quirk.scope_rules, av["rules"]),
        (quirk.scope_hosts, av["hosts"]),
        (quirk.scope_users, av["users"]),
        (quirk.scope_ips, av["ips"]),
    ]
    specified = False
    for scope, alert_vals in checks:
        if scope:
            specified = True
            if not (set(_norm(s) for s in scope) & alert_vals):
                return False
    if quirk.scope_observables:
        specified = True
        want = set()
        for o in quirk.scope_observables:
            val = _norm(o.get("value") or "")
            t = _norm(o.get("type") or "")
            if val:
                want.add(f"{t}:{val}")
                want.add(val)
        if not (want & av["observables"]):
            return False
    return specified  # never match a quirk with no effective scope


def annotate_alerts(session: Session, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Attach advisory quirk annotations to a list of alert dicts, IN PLACE.

    Additive only — sets ``d["quirks"] = [...]`` on matches and touches nothing
    else. Never removes, reorders, or filters an alert. Loads active quirks once
    (not per-alert). Returns the same list for convenience.
    """
    quirks = _active_quirks(session)
    if not quirks:
        return alerts
    for d in alerts:
        if not isinstance(d, dict):
            continue
        av = _alert_values(d)
        hits = [
            {"quirk_id": q.id, "title": q.title, "annotation": q.annotation,
             "priority_nudge": q.priority_nudge}
            for q in quirks if _matches(q, av)
        ]
        if hits:
            d["quirks"] = hits
    return alerts


def quirk_match(session: Session, alert: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return advisory annotations for active, non-expired quirks matching an alert.

    ADVISORY ONLY. The returned dicts are meant to be attached to the alert
    response (badge/note/nudge). This function never mutates alert/case/triage
    state and never signals suppression — callers must only *decorate*.
    """
    if not isinstance(alert, dict):
        return []
    av = _alert_values(alert)
    out: List[Dict[str, Any]] = []
    for q in _active_quirks(session):
        if _matches(q, av):
            out.append({
                "quirk_id": q.id,
                "title": q.title,
                "annotation": q.annotation,
                "priority_nudge": q.priority_nudge,
            })
    return out
