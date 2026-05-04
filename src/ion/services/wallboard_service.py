"""Wallboard snapshot service (v0.15.0).

A single point-in-time snapshot of the whole ION estate, intended for
display on a wall monitor. Six metric panels (alerts, cases, Bob, rules,
topology, threat landscape), and the most recent ticker entries.

v0.15.0: detection / cyab / curriculum panels were swapped for
operational content — the detection panel now surfaces real rule posture
metrics from TIDE; cyab was replaced with a hub-and-spoke platform
topology graph; curriculum was replaced with an AI-generated threat
landscape summary (5-min cached).

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
    from ion.models.ai_feedback import AIFeedback
    from ion.models.investigation import Investigation

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


def _collect_rules(session: Session) -> Dict[str, Any]:
    """Detection-rule posture metrics from TIDE.

    Returns the real shape of the rule estate: total / enabled / disabled,
    severity distribution, quality bands, MITRE technique coverage. Falls
    back to a stats-only response if TIDE is offline.
    """
    from ion.services.tide_service import get_tide_service

    tide = get_tide_service()
    posture = None
    try:
        posture = tide.get_posture_stats() if tide else None
    except Exception as exc:
        logger.warning("wallboard: TIDE posture fetch failed: %s", exc)
        posture = None

    if not posture:
        return {
            "total_rules": 0, "enabled_rules": 0, "disabled_rules": 0,
            "severity": {}, "quality": {}, "unmapped_rules": 0,
            "covered_techniques": 0, "total_techniques": 0,
            "tide_unavailable": True,
        }

    return {
        "total_rules": int(posture.get("total_rules") or 0),
        "enabled_rules": int(posture.get("enabled_rules") or 0),
        "disabled_rules": int(posture.get("disabled_rules") or 0),
        "severity": posture.get("severity") or {},
        "quality": posture.get("quality") or {},
        "unmapped_rules": int(posture.get("unmapped_rules") or 0),
        "covered_techniques": int(posture.get("covered_techniques") or 0),
        "total_techniques": int(posture.get("total_techniques") or 0),
        "total_systems": int(posture.get("total_systems") or 0),
        "tide_unavailable": False,
    }


def _collect_topology(health: Dict[str, Any]) -> Dict[str, Any]:
    """Hub-and-spoke topology rollup. ION sits at the centre; every
    integration is a spoke labelled with its current status.

    The renderer uses these to draw an SVG graph; this service only
    decides node order, role labels, and groupings so that the layout is
    stable across refreshes (don't re-shuffle nodes when something flips
    state — the eye reads movement as instability on a wall display).
    """
    # Stable node order, grouped clockwise from top so the visual flows
    # data-source → analytics → output. Each label keeps role + family
    # so a glance tells you "this is the SIEM, this is the LLM, etc."
    NODE_DEFS = [
        {"key": "elasticsearch", "label": "Elasticsearch", "family": "siem",       "role": "ingest"},
        {"key": "kibana",        "label": "Kibana",        "family": "siem",       "role": "ingest"},
        {"key": "tide",          "label": "TIDE",          "family": "intel",      "role": "intel"},
        {"key": "opencti",       "label": "OpenCTI",       "family": "intel",      "role": "intel"},
        {"key": "ollama",        "label": "Ollama",        "family": "ai",         "role": "ai"},
        {"key": "bob",           "label": "Bob",           "family": "ai",         "role": "ai"},
        {"key": "postgres",      "label": "Postgres",      "family": "infra",      "role": "store"},
    ]

    nodes: List[Dict[str, Any]] = []
    for d in NODE_DEFS:
        h = (health or {}).get(d["key"]) or {}
        nodes.append({
            "key":     d["key"],
            "label":   d["label"],
            "family":  d["family"],
            "role":    d["role"],
            "status":  h.get("status") or "off",
            "details": h.get("details") or "",
        })

    counts = {
        "up":   sum(1 for n in nodes if n["status"] == "up"),
        "down": sum(1 for n in nodes if n["status"] == "down"),
        "off":  sum(1 for n in nodes if n["status"] == "off"),
    }
    return {"nodes": nodes, "counts": counts}


def _gather_threat_stats(session: Session) -> Dict[str, Any]:
    """Aggregate the inputs the LLM uses to write the landscape summary.

    Always cheap (a handful of grouped counts). Returned as part of the
    snapshot regardless of whether Ollama is reachable — the renderer
    falls back to a "stats only" view if the LLM-produced paragraph is
    missing.
    """
    from ion.models.alert_triage import AlertCase, AlertCaseStatus, AlertTriage

    cutoff_24h = datetime.utcnow() - timedelta(hours=24)
    cutoff_7d = datetime.utcnow() - timedelta(days=7)

    alerts_24h = int(session.scalar(
        select(func.count()).select_from(AlertTriage)
        .where(AlertTriage.created_at >= cutoff_24h)
    ) or 0)

    # Priority distribution across last-24h alerts. (AlertTriage tracks
    # `priority`, not `severity` — severity lives on AlertCase.)
    pri_rows = session.execute(
        select(AlertTriage.priority, func.count())
        .where(AlertTriage.created_at >= cutoff_24h)
        .where(AlertTriage.priority.isnot(None))
        .group_by(AlertTriage.priority)
    ).all()
    severity_dist = {str(k): int(v) for k, v in pri_rows if k}

    # Verdict distribution across last-7d alerts (longer window, more signal).
    verdict_rows = session.execute(
        select(AlertTriage.suggested_verdict, func.count())
        .where(AlertTriage.created_at >= cutoff_7d)
        .where(AlertTriage.suggested_verdict.isnot(None))
        .group_by(AlertTriage.suggested_verdict)
    ).all()
    verdict_dist = {str(k): int(v) for k, v in verdict_rows if k}

    # Top closed-case closure reasons in the last 7d.
    closure_rows = session.execute(
        select(AlertCase.closure_reason, func.count())
        .where(AlertCase.closed_at >= cutoff_7d)
        .where(AlertCase.closure_reason.isnot(None))
        .group_by(AlertCase.closure_reason)
        .order_by(func.count().desc())
        .limit(5)
    ).all()
    top_closures = [{"reason": str(r), "count": int(c)} for r, c in closure_rows if r]

    # Open-case backlog severity profile (what's currently weighing on the team).
    backlog_rows = session.execute(
        select(AlertCase.severity, func.count())
        .where(AlertCase.status != AlertCaseStatus.CLOSED)
        .group_by(AlertCase.severity)
    ).all()
    open_backlog = {str(k or "unknown"): int(v) for k, v in backlog_rows}

    return {
        "alerts_24h_total":  alerts_24h,
        "severity_24h":      severity_dist,
        "verdict_7d":        verdict_dist,
        "top_closures_7d":   top_closures,
        "open_backlog_sev":  open_backlog,
    }


def _build_threat_summary_prompt(stats: Dict[str, Any]) -> str:
    """Pack the stats into a compact analyst-grade prompt."""
    sev = ", ".join(f"{k}={v}" for k, v in (stats.get("severity_24h") or {}).items()) or "—"
    ver = ", ".join(f"{k}={v}" for k, v in (stats.get("verdict_7d") or {}).items()) or "—"
    closures = ", ".join(
        f"{c.get('reason')}={c.get('count')}" for c in (stats.get("top_closures_7d") or [])
    ) or "—"
    backlog = ", ".join(f"{k}={v}" for k, v in (stats.get("open_backlog_sev") or {}).items()) or "—"
    return (
        "You are a SOC duty manager writing a wall-display summary for analysts on shift.\n"
        "Output 2-3 short sentences in plain English describing the current threat landscape, "
        "followed by 2-3 single-line bullet trends prefixed with '- '.\n\n"
        f"Last 24h alerts: {stats.get('alerts_24h_total', 0)}\n"
        f"Severity (24h): {sev}\n"
        f"Verdicts (7d): {ver}\n"
        f"Top closure reasons (7d): {closures}\n"
        f"Open case backlog by severity: {backlog}\n\n"
        "Keep total output under 90 words. No headings, no preamble, no markdown bold/italic. "
        "Lead with the most actionable observation."
    )


def _generate_landscape_text(prompt: str, *, timeout: float = 15.0) -> Optional[str]:
    """Synchronous Ollama call. Returns None if Ollama is unreachable.

    Uses the bare /api/generate endpoint with a tight timeout so the
    snapshot collector can't be blocked indefinitely. The wallboard's
    5-min cache TTL means this is called at most once per TTL.
    """
    import os
    try:
        import httpx  # type: ignore
    except Exception:
        return None

    url = (
        os.environ.get("ION_OLLAMA_URL")
        or os.environ.get("OLLAMA_HOST")
        or os.environ.get("OLLAMA_URL")
    )
    if not url:
        return None
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    model = (
        os.environ.get("ION_WALLBOARD_OLLAMA_MODEL")
        or os.environ.get("ION_OLLAMA_MODEL")
        or "llama3.1:8b"
    )

    try:
        with httpx.Client(timeout=timeout) as client:
            r = client.post(
                f"{url.rstrip('/')}/api/generate",
                json={
                    "model": model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"temperature": 0.4, "num_predict": 220},
                },
            )
            r.raise_for_status()
            text = (r.json().get("response") or "").strip()
            return text or None
    except Exception as exc:
        logger.info("wallboard: threat-landscape Ollama call failed: %s", exc)
        return None


def _collect_threat_landscape(session: Session) -> Dict[str, Any]:
    """AI-generated threat landscape summary + the stats that backed it.

    Always returns the stats; the LLM paragraph is optional. The renderer
    shows the paragraph if present, otherwise composes a stats-only
    fallback locally so the panel never goes blank on a wall display.
    """
    stats = _gather_threat_stats(session)
    prompt = _build_threat_summary_prompt(stats)
    text = _generate_landscape_text(prompt)
    return {
        "summary":      text,
        "summary_kind": "ai" if text else "stats",
        "stats":        stats,
        "generated_at": _utc_now_iso(),
    }


def _collect_ticker(session: Session) -> Dict[str, Any]:
    """Most-recent active Ticker entries (announcements + critical alerts)."""
    from ion.models.ticker import Ticker

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
    health = _safe("service_health", lambda: _collect_service_health(session), default={})
    return {
        "captured_at":      _utc_now_iso(),
        "alerts":           _safe("alerts", lambda: _collect_alerts(session), default={"by_status": {}, "last_24h_total": 0}),
        "cases":            _safe("cases", lambda: _collect_cases(session), default={"by_status": {}, "open_by_severity": {}, "closures_24h_total": 0}),
        "bob":              _safe("bob", lambda: _collect_bob(session), default={"investigations_24h": 0, "agreement_pct": None}),
        "rules":            _safe("rules", lambda: _collect_rules(session), default={"total_rules": 0, "enabled_rules": 0, "severity": {}, "tide_unavailable": True}),
        "topology":         _safe("topology", lambda: _collect_topology(health), default={"nodes": [], "counts": {}}),
        "threat_landscape": _safe("threat_landscape", lambda: _collect_threat_landscape(session), default={"summary": None, "summary_kind": "stats", "stats": {}}),
        "ticker":           _safe("ticker", lambda: _collect_ticker(session), default={"items": [], "count": 0}),
        "service_health":   health,
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
