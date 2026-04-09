"""Morning Threat Briefing service.

Pulls a snapshot of recent SOC activity from every connected source we have:

- Elasticsearch: overnight alert volume, severity mix, top firing rules
- OpenCTI:       freshly added or recently active threat actors
- TIDE:          which detection rules fired, which kill-chain steps progressed
- ION DB:        open cases & current case backlog

Then assembles a structured briefing dict and (optionally) feeds it to Ollama
for an executive-style narrative summary.

Designed to run on-demand from the dashboard, but the result is shaped so it
can also be scheduled by ``report_scheduler_service`` later.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from ion.models.alert_triage import AlertCase, AlertCaseStatus

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data collectors
# ---------------------------------------------------------------------------

async def _collect_es(hours: int) -> dict:
    """Aggregate ES alert volume for the briefing window."""
    from ion.services.elasticsearch_service import ElasticsearchService

    out = {"enabled": False, "total": 0, "by_severity": {}, "top_rules": []}
    es = ElasticsearchService()
    if not es.is_configured:
        return out
    out["enabled"] = True

    try:
        stats = await es.get_alert_stats(hours=hours)
    except Exception as e:
        out["error"] = type(e).__name__
        return out

    out["total"] = stats.get("total", 0)
    out["by_severity"] = stats.get("by_severity") or {}
    # Some ES service versions return top rules under different keys; try a few
    out["top_rules"] = (
        stats.get("top_rules")
        or stats.get("top_rule_names")
        or stats.get("rules")
        or []
    )[:10]
    return out


def _collect_cases(session: Session, hours: int) -> dict:
    """Snapshot of cases opened/closed/backlog."""
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    opened = session.execute(
        select(AlertCase).where(AlertCase.created_at >= cutoff)
    ).scalars().all()
    closed = session.execute(
        select(AlertCase).where(
            AlertCase.closed_at.isnot(None),
            AlertCase.closed_at >= cutoff,
        )
    ).scalars().all()
    open_backlog = session.execute(
        select(AlertCase).where(AlertCase.status != AlertCaseStatus.CLOSED.value)
    ).scalars().all()

    by_severity: dict[str, int] = {}
    for c in opened:
        sev = (c.severity or "unknown").lower()
        by_severity[sev] = by_severity.get(sev, 0) + 1

    notable = []
    for c in sorted(opened, key=lambda x: (x.severity or "", x.created_at or datetime.min), reverse=True)[:5]:
        notable.append({
            "case_number": c.case_number or f"#{c.id}",
            "title": (c.title or "")[:120],
            "severity": c.severity,
            "status": c.status,
        })

    return {
        "opened": len(opened),
        "closed": len(closed),
        "open_backlog": len(open_backlog),
        "by_severity": by_severity,
        "notable": notable,
    }


def _collect_opencti() -> dict:
    """Recently observed threat actors from OpenCTI."""
    out = {"enabled": False, "actors": []}
    try:
        from ion.services.opencti_service import get_opencti_service
        svc = get_opencti_service()
        if not svc.is_configured:
            return out
        out["enabled"] = True
        # Limit to 5 to keep the briefing short
        try:
            actors = svc.list_threat_actors(limit=5) if hasattr(svc, "list_threat_actors") else []
        except Exception as e:
            out["error"] = type(e).__name__
            return out
        out["actors"] = [
            {
                "name": a.get("name") or a.get("standard_id") or "Unknown",
                "aliases": (a.get("aliases") or [])[:3],
                "modified": a.get("modified") or a.get("updated_at"),
            }
            for a in (actors or [])
        ]
    except Exception as e:
        out["error"] = type(e).__name__
    return out


def _collect_tide() -> dict:
    """Snapshot of TIDE rule activity / posture."""
    from ion.services.tide_service import get_tide_service

    out = {"enabled": False}
    svc = get_tide_service()
    if not svc.enabled:
        return out
    out["enabled"] = True
    try:
        # Posture stats give a quick snapshot of total enabled / quality / mitre
        stats = svc.get_posture_stats() if hasattr(svc, "get_posture_stats") else None
        if stats:
            out["total_rules"] = stats.get("total_rules")
            out["enabled_rules"] = stats.get("enabled_rules")
            out["mitre_techniques_covered"] = stats.get("mitre_techniques_covered")
            out["quality_avg"] = stats.get("quality_avg")
    except Exception as e:
        out["error"] = type(e).__name__
    return out


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def build_briefing(session: Session, hours: int = 12, ai: bool = False) -> dict:
    """Compose the briefing dict.

    Args:
        session: SQLAlchemy session.
        hours: how far back to look (default = overnight, 12h).
        ai: if True, ask Ollama to write an executive narrative summary.
    """
    es = await _collect_es(hours)
    cases = _collect_cases(session, hours)
    octi = _collect_opencti()
    tide = _collect_tide()

    # Headline metrics that the dashboard widget can show
    headlines = {
        "alerts_total": es.get("total", 0),
        "cases_opened": cases.get("opened", 0),
        "cases_closed": cases.get("closed", 0),
        "open_backlog": cases.get("open_backlog", 0),
        "actors_tracked": len(octi.get("actors") or []),
        "tide_rules_enabled": tide.get("enabled_rules"),
    }

    # Sources we successfully reached
    sources_reached = []
    if es.get("enabled") and not es.get("error"):
        sources_reached.append("elasticsearch")
    if octi.get("enabled") and not octi.get("error"):
        sources_reached.append("opencti")
    if tide.get("enabled") and not tide.get("error"):
        sources_reached.append("tide")

    briefing = {
        "generated_at": datetime.utcnow().isoformat(),
        "window_hours": hours,
        "sources_reached": sources_reached,
        "headlines": headlines,
        "es": es,
        "cases": cases,
        "opencti": octi,
        "tide": tide,
        "narrative": None,
    }

    if ai:
        briefing["narrative"] = await _ai_narrative(briefing)

    return briefing


async def _ai_narrative(briefing: dict) -> Optional[str]:
    """Ask Ollama to write a 5–8 sentence executive briefing from the snapshot."""
    try:
        from ion.services.ollama_service import get_ollama_service
        svc = get_ollama_service()
        if not svc.enabled:
            return None
    except Exception:
        return None

    h = briefing.get("headlines", {})
    es = briefing.get("es", {})
    cases = briefing.get("cases", {})
    octi = briefing.get("opencti", {})
    tide = briefing.get("tide", {})

    # Compact, structured input — better for LLM than dumping full JSON
    prompt = f"""You are writing a SOC morning briefing for the Lead Analyst.
The window is the last {briefing.get('window_hours')} hours.

Activity snapshot:
- Elasticsearch alerts: {h.get('alerts_total', 0)}
- Severity mix: {es.get('by_severity', {})}
- Top firing rules: {[r.get('name') if isinstance(r, dict) else r for r in (es.get('top_rules') or [])][:5]}
- Cases opened: {h.get('cases_opened', 0)}
- Cases closed: {h.get('cases_closed', 0)}
- Open case backlog: {h.get('open_backlog', 0)}
- Notable cases: {[(c.get('case_number'), c.get('severity'), c.get('title')) for c in cases.get('notable', [])]}
- Threat actors recently active in OpenCTI: {[a.get('name') for a in octi.get('actors', [])]}
- TIDE rules enabled: {tide.get('enabled_rules')} of {tide.get('total_rules')} (avg quality: {tide.get('quality_avg')})

Write a 5–8 sentence briefing in the voice of an experienced SOC lead.
Lead with the most important fact. Call out anomalies (severity spikes, backlog
trending up, repeat firing rules, named threat actors). End with a one-sentence
priority recommendation for today's shift.

Do NOT list raw numbers in bullet form — write it as prose."""

    try:
        return await svc.generate(prompt=prompt, temperature=0.3)
    except Exception as e:
        logger.warning("Briefing AI narrative failed: %s", e)
        return None
