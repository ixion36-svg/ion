"""Wallboard snapshot service (v0.14.0).

A single point-in-time snapshot of the whole ION estate, intended for
display on a wall monitor. Six metric panels (alerts, cases, Bob,
detection, CYAB, curriculum), a service-health strip, and the most
recent ticker entries.

**Caching strategy:** the snapshot is computed at most once per 5 min.
Concurrent wallboard loads serve the cached snapshot; the cache
populates lazily on first request after expiry. This means N wall
displays cost the same as 1 — the intent is wall displays don't hammer
the DB.

**Failure mode:** each panel-collector is wrapped so a broken
integration (e.g. ES unreachable) emits a partial result with
``error: <msg>`` rather than blowing up the whole snapshot. The
wallboard renders an "unavailable" tile for that panel.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

# Cache TTL — recompute the snapshot at most once every 300 seconds.
_CACHE_TTL_SECONDS = 300

# Module-level cache. Single in-process snapshot — this is fine because
# the snapshot is a read-only summary; even with N workers each computes
# its own copy at first hit, and they converge after the first interval.
_cached: Optional[Dict[str, Any]] = None
_cached_at: float = 0.0
_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _safe(label: str, fn, *, default: Any = None) -> Any:
    """Run a panel-collector; on exception, return ``{"error": str(e)}``.

    ``label`` only goes to the log; never user-visible. ``default`` is
    the fallback structure if the collector throws (typically a dict
    with zeroed counts so the renderer doesn't crash).
    """
    try:
        return fn()
    except Exception as exc:
        logger.warning("wallboard: %s collector failed: %s", label, exc)
        if isinstance(default, dict):
            return {**default, "error": str(exc)}
        return {"error": str(exc)}


# ---------------------------------------------------------------------------
# Panel collectors
# ---------------------------------------------------------------------------


def _collect_alerts(session: Session) -> Dict[str, Any]:
    """Open / acked / closed counts; verdict distribution + 24h hourly histogram."""
    from ion.models.alert_triage import AlertTriage, AlertTriageStatus

    by_status = {
        s.value: int(session.scalar(
            select(func.count()).select_from(AlertTriage).where(AlertTriage.status == s)
        ) or 0)
        for s in AlertTriageStatus
    }
    cutoff_24h = datetime.utcnow() - timedelta(hours=24)
    last_24h_total = int(session.scalar(
        select(func.count()).select_from(AlertTriage)
        .where(AlertTriage.created_at >= cutoff_24h)
    ) or 0)

    # Bob's suggested_verdict distribution — last 7d, where present.
    cutoff_7d = datetime.utcnow() - timedelta(days=7)
    rows = session.execute(
        select(AlertTriage.suggested_verdict, func.count())
        .where(AlertTriage.created_at >= cutoff_7d)
        .where(AlertTriage.suggested_verdict.isnot(None))
        .group_by(AlertTriage.suggested_verdict)
    ).all()
    verdict_distribution = {str(k): int(v) for k, v in rows if k}

    # 24-hour hourly histogram for the sparkline. Build all 24 buckets so
    # the renderer always gets a smooth line even on a quiet estate.
    histogram_24h: List[Dict[str, Any]] = []
    now = datetime.utcnow()
    for i in range(23, -1, -1):
        bucket_start = (now - timedelta(hours=i + 1)).replace(minute=0, second=0, microsecond=0)
        bucket_end = bucket_start + timedelta(hours=1)
        count = int(session.scalar(
            select(func.count()).select_from(AlertTriage)
            .where(AlertTriage.created_at >= bucket_start)
            .where(AlertTriage.created_at < bucket_end)
        ) or 0)
        histogram_24h.append({"hour": bucket_start.isoformat(), "count": count})

    return {
        "by_status": by_status,
        "last_24h_total": last_24h_total,
        "verdict_distribution_7d": verdict_distribution,
        "histogram_24h": histogram_24h,
    }


def _collect_cases(session: Session) -> Dict[str, Any]:
    """Cases by status + severity; recent closure stats."""
    from ion.models.alert_triage import AlertCase, AlertCaseStatus

    by_status = {
        s.value: int(session.scalar(
            select(func.count()).select_from(AlertCase).where(AlertCase.status == s)
        ) or 0)
        for s in AlertCaseStatus
    }

    # Severity distribution on currently-open cases.
    rows = session.execute(
        select(AlertCase.severity, func.count())
        .where(AlertCase.status != AlertCaseStatus.CLOSED)
        .group_by(AlertCase.severity)
    ).all()
    open_by_severity = {str(k or "unknown"): int(v) for k, v in rows}

    # Closures in the last 24h, by closure_reason.
    cutoff_24h = datetime.utcnow() - timedelta(hours=24)
    rows = session.execute(
        select(AlertCase.closure_reason, func.count())
        .where(AlertCase.closed_at >= cutoff_24h)
        .where(AlertCase.closure_reason.isnot(None))
        .group_by(AlertCase.closure_reason)
    ).all()
    closures_24h = {str(k): int(v) for k, v in rows if k}
    closures_24h_total = sum(closures_24h.values())

    # 7-day daily histogram of closures for the sparkline.
    history_7d: List[Dict[str, Any]] = []
    now = datetime.utcnow()
    for i in range(6, -1, -1):
        bucket_start = (now - timedelta(days=i + 1)).replace(hour=0, minute=0, second=0, microsecond=0)
        bucket_end = bucket_start + timedelta(days=1)
        count = int(session.scalar(
            select(func.count()).select_from(AlertCase)
            .where(AlertCase.closed_at >= bucket_start)
            .where(AlertCase.closed_at < bucket_end)
        ) or 0)
        history_7d.append({"day": bucket_start.isoformat(), "count": count})

    return {
        "by_status": by_status,
        "open_by_severity": open_by_severity,
        "closures_24h": closures_24h,
        "closures_24h_total": closures_24h_total,
        "closures_history_7d": history_7d,
    }


def _collect_bob(session: Session) -> Dict[str, Any]:
    """Investigations + AI-feedback agreement rate."""
    from ion.models.investigation import Investigation
    from ion.models.ai_feedback import AIFeedback

    cutoff_24h = datetime.utcnow() - timedelta(hours=24)
    investigations_24h = int(session.scalar(
        select(func.count()).select_from(Investigation)
        .where(Investigation.created_at >= cutoff_24h)
    ) or 0)

    investigations_total = int(session.scalar(
        select(func.count()).select_from(Investigation)
    ) or 0)

    cutoff_7d = datetime.utcnow() - timedelta(days=7)

    # Per-week feedback metrics.
    feedback_7d_total = int(session.scalar(
        select(func.count()).select_from(AIFeedback)
        .where(AIFeedback.created_at >= cutoff_7d)
    ) or 0)

    # Agreement = analyst_verdict matches bob_verdict (or both null).
    agreement_count = 0
    if feedback_7d_total > 0:
        rows = session.execute(
            select(AIFeedback.analyst_verdict, AIFeedback.bob_verdict)
            .where(AIFeedback.created_at >= cutoff_7d)
        ).all()
        agreement_count = sum(1 for av, bv in rows if av is not None and bv is not None and av == bv)
    agreement_pct = (
        round(agreement_count * 100 / feedback_7d_total) if feedback_7d_total else None
    )

    # 7-day daily histogram of Bob investigations.
    history_7d: List[Dict[str, Any]] = []
    now = datetime.utcnow()
    for i in range(6, -1, -1):
        bucket_start = (now - timedelta(days=i + 1)).replace(hour=0, minute=0, second=0, microsecond=0)
        bucket_end = bucket_start + timedelta(days=1)
        count = int(session.scalar(
            select(func.count()).select_from(Investigation)
            .where(Investigation.created_at >= bucket_start)
            .where(Investigation.created_at < bucket_end)
        ) or 0)
        history_7d.append({"day": bucket_start.isoformat(), "count": count})

    return {
        "investigations_24h": investigations_24h,
        "investigations_total": investigations_total,
        "feedback_7d_total": feedback_7d_total,
        "agreement_pct": agreement_pct,
        "agreement_count": agreement_count,
        "history_7d": history_7d,
    }


def _collect_detection(session: Session) -> Dict[str, Any]:
    """TIDE / detection-engineering rollup from cached snapshots."""
    from ion.models.tide_snapshot import TideSnapshot
    from ion.models.alert_prompt import AlertPromptTemplate

    # AlertPromptTemplate count — Bob's per-rule guides, count of
    # populated templates.
    template_count = int(session.scalar(
        select(func.count()).select_from(AlertPromptTemplate)
    ) or 0)

    # Most recent TIDE snapshots — return the data_key + age.
    rows = session.execute(
        select(TideSnapshot.data_key, TideSnapshot.fetched_at, TideSnapshot.error)
        .order_by(TideSnapshot.fetched_at.desc())
        .limit(20)
    ).all()
    tide_snapshots = []
    for k, fa, err in rows:
        age_min = int((datetime.utcnow() - fa).total_seconds() / 60) if fa else None
        tide_snapshots.append({
            "data_key": k,
            "fetched_at": fa.isoformat() if fa else None,
            "age_min": age_min,
            "ok": not err,
        })

    return {
        "alert_prompt_template_count": template_count,
        "tide_snapshots": tide_snapshots,
        "tide_healthy_count": sum(1 for s in tide_snapshots if s["ok"]),
        "tide_total_count": len(tide_snapshots),
    }


def _collect_cyab(session: Session) -> Dict[str, Any]:
    """CYAB systems + sub-profile assignment + Onboarding Studio rollup."""
    from ion.models.cyab import CyabSystem, CyabDataSource
    from ion.models.cyab_subprofile import CyabSubProfile

    system_count = int(session.scalar(
        select(func.count()).select_from(CyabSystem)
    ) or 0)
    avg_readiness = session.scalar(
        select(func.avg(CyabSystem.readiness_score)).select_from(CyabSystem)
    )
    avg_readiness = round(float(avg_readiness)) if avg_readiness is not None else 0

    by_status = dict(session.execute(
        select(CyabSystem.status, func.count())
        .group_by(CyabSystem.status)
    ).all())
    by_status = {str(k or "unknown"): int(v) for k, v in by_status.items()}

    # Onboarding Studio: how many data sources have a subprofile_id?
    ds_total = int(session.scalar(
        select(func.count()).select_from(CyabDataSource)
    ) or 0)
    ds_with_subprofile = int(session.scalar(
        select(func.count()).select_from(CyabDataSource)
        .where(CyabDataSource.subprofile_id.isnot(None))
    ) or 0)
    subprofile_assignment_pct = (
        round(ds_with_subprofile * 100 / ds_total) if ds_total else 0
    )

    subprofile_count = int(session.scalar(
        select(func.count()).select_from(CyabSubProfile)
    ) or 0)

    return {
        "system_count": system_count,
        "avg_readiness_score": avg_readiness,
        "system_by_status": by_status,
        "data_source_total": ds_total,
        "data_source_with_subprofile": ds_with_subprofile,
        "subprofile_assignment_pct": subprofile_assignment_pct,
        "subprofile_catalogue_count": subprofile_count,
    }


def _collect_curriculum(session: Session) -> Dict[str, Any]:
    """Course enrolments + completions + top-3 courses by enrolment."""
    from ion.models.course import Course, UserEnrolment, Lesson

    enrolment_total = int(session.scalar(
        select(func.count()).select_from(UserEnrolment)
    ) or 0)
    completion_total = int(session.scalar(
        select(func.count()).select_from(UserEnrolment)
        .where(UserEnrolment.completed_at.isnot(None))
    ) or 0)
    cert_issued_count = int(session.scalar(
        select(func.count()).select_from(UserEnrolment)
        .where(UserEnrolment.certificate_url.isnot(None))
    ) or 0)

    # Top-3 enrolled courses
    rows = session.execute(
        select(Course.title, Course.level, func.count(UserEnrolment.id).label("cnt"))
        .join(UserEnrolment, UserEnrolment.course_id == Course.id, isouter=True)
        .group_by(Course.id, Course.title, Course.level)
        .order_by(func.count(UserEnrolment.id).desc())
        .limit(3)
    ).all()
    top_courses = [
        {"title": str(t), "level": str(lv), "enrolments": int(c)}
        for t, lv, c in rows
    ]

    # Lesson totals across all courses (catalogue size)
    lesson_total = int(session.scalar(
        select(func.count()).select_from(Lesson)
    ) or 0)

    return {
        "enrolment_total": enrolment_total,
        "completion_total": completion_total,
        "cert_issued_count": cert_issued_count,
        "top_courses": top_courses,
        "catalogue_lesson_count": lesson_total,
    }


def _collect_ticker(session: Session) -> Dict[str, Any]:
    """Most-recent active Ticker entries (announcements + critical alerts)."""
    from ion.models.ticker import Ticker, TickerSeverity, TickerKind

    rows = session.execute(
        select(
            Ticker.id, Ticker.kind, Ticker.severity, Ticker.title, Ticker.body,
            Ticker.created_at, Ticker.expires_at,
        )
        .order_by(Ticker.created_at.desc())
        .limit(10)
    ).all()
    now = datetime.utcnow()
    items = []
    for r in rows:
        expires = r.expires_at
        if expires and expires < now:
            continue  # skip expired
        items.append({
            "id": int(r.id),
            "kind": str(r.kind) if r.kind else "unknown",
            "severity": str(r.severity) if r.severity else "info",
            "title": str(r.title or ""),
            "body": str(r.body or "")[:300],
            "created_at": r.created_at.isoformat() if r.created_at else None,
        })
    return {"items": items, "count": len(items)}


def _collect_service_health(session: Session) -> Dict[str, Any]:
    """Light health check per integration. Best-effort; never blocks > 1s each."""
    health: Dict[str, Any] = {}

    # Postgres — by definition reachable here, since we hold a session.
    health["postgres"] = {"status": "up", "details": "active session"}

    # Elasticsearch — attempt the existing ES service's health check.
    try:
        from ion.services.elasticsearch_service import ElasticsearchService
        es = ElasticsearchService()
        # ES service may expose an `is_configured` and a quick ping
        configured = bool(getattr(es, "is_configured", False) or getattr(es, "url", None))
        health["elasticsearch"] = {"status": "up" if configured else "off", "details": "configured" if configured else "not configured"}
    except Exception as exc:
        health["elasticsearch"] = {"status": "down", "details": str(exc)[:80]}

    # TIDE — circuit-breaker / connector state.
    try:
        from ion.services.tide_service import get_tide_service
        tide = get_tide_service()
        configured = tide is not None and getattr(tide, "is_configured", lambda: False)()
        health["tide"] = {"status": "up" if configured else "off", "details": "configured" if configured else "not configured"}
    except Exception as exc:
        health["tide"] = {"status": "down", "details": str(exc)[:80]}

    # OpenCTI — connector state.
    try:
        from ion.services.opencti_service import OpenctiService
        oc = OpenctiService()
        configured = bool(getattr(oc, "url", None))
        health["opencti"] = {"status": "up" if configured else "off", "details": "configured" if configured else "not configured"}
    except Exception as exc:
        health["opencti"] = {"status": "down", "details": str(exc)[:80]}

    # Kibana — via the connector registry.
    try:
        from ion.services.connectors import get_connector_registry
        reg = get_connector_registry()
        kib = reg.get("kibana_cases") if reg else None
        configured = bool(kib and getattr(kib, "is_configured", False))
        health["kibana"] = {"status": "up" if configured else "off", "details": "configured" if configured else "not configured"}
    except Exception as exc:
        health["kibana"] = {"status": "down", "details": str(exc)[:80]}

    # Ollama — for Bob.
    try:
        import os
        ollama_url = os.environ.get("ION_OLLAMA_URL") or os.environ.get("OLLAMA_HOST")
        configured = bool(ollama_url)
        health["ollama"] = {"status": "up" if configured else "off", "details": ollama_url[:60] if ollama_url else "not configured"}
    except Exception as exc:
        health["ollama"] = {"status": "down", "details": str(exc)[:80]}

    # Bob (the AI analyst service account)
    try:
        from ion.models.user import User
        bob = session.scalar(select(User).where(User.username == "bob"))
        health["bob"] = {"status": "up" if bob else "off", "details": "service account active" if bob else "not seeded"}
    except Exception as exc:
        health["bob"] = {"status": "down", "details": str(exc)[:80]}

    return health


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def _gather(session: Session) -> Dict[str, Any]:
    """Build a single snapshot. Each panel is in its own try/except."""
    return {
        "captured_at": _utc_now_iso(),
        "alerts": _safe("alerts", lambda: _collect_alerts(session), default={"by_status": {}, "last_24h_total": 0}),
        "cases": _safe("cases", lambda: _collect_cases(session), default={"by_status": {}, "open_by_severity": {}, "closures_24h_total": 0}),
        "bob": _safe("bob", lambda: _collect_bob(session), default={"investigations_24h": 0, "agreement_pct": None}),
        "detection": _safe("detection", lambda: _collect_detection(session), default={"alert_prompt_template_count": 0, "tide_snapshots": []}),
        "cyab": _safe("cyab", lambda: _collect_cyab(session), default={"system_count": 0, "avg_readiness_score": 0}),
        "curriculum": _safe("curriculum", lambda: _collect_curriculum(session), default={"enrolment_total": 0, "completion_total": 0, "top_courses": []}),
        "ticker": _safe("ticker", lambda: _collect_ticker(session), default={"items": [], "count": 0}),
        "service_health": _safe("service_health", lambda: _collect_service_health(session), default={}),
    }


def get_snapshot(session: Session, *, force: bool = False) -> Dict[str, Any]:
    """Return the snapshot, recomputing if older than 5 minutes.

    ``force=True`` bypasses the cache (useful for admin refresh).
    """
    global _cached, _cached_at
    now = time.time()
    with _lock:
        if not force and _cached is not None and (now - _cached_at) < _CACHE_TTL_SECONDS:
            return {**_cached, "cache_age_seconds": int(now - _cached_at)}
        try:
            snap = _gather(session)
            _cached = snap
            _cached_at = now
            return {**snap, "cache_age_seconds": 0}
        except Exception as exc:
            logger.error("wallboard: gather failed: %s", exc)
            # If gather itself fails, return the previous cached snapshot if
            # any (with explicit error indicator); otherwise an empty
            # placeholder so the page can render.
            if _cached is not None:
                return {**_cached, "cache_age_seconds": int(now - _cached_at), "stale_due_to_error": str(exc)}
            return {
                "captured_at": _utc_now_iso(),
                "error": str(exc),
                "cache_age_seconds": 0,
            }
