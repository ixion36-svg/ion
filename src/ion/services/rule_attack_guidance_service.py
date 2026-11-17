"""MITRE's detection guidance for the techniques one rule's alerts carry.

What remains of Detection Health: its per-rule figures are rule_health_service
now (closures from rule_outcome_service, problems from TIDE Rule Monitoring).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from ion.models.alert_triage import AlertTriage
from ion.services.attack_detection_service import (
    log_sources_for_technique,
    snapshot_status,
    strategies_for_technique,
)
from ion.services.attack_revocation_service import resolve
from ion.services.rule_outcome_service import DEFAULT_WINDOW_DAYS
from ion.services.rule_outcome_service import UNMAPPED as _UNMAPPED


def get_rule_attack_guidance(
    session: Session, rule_name: str, days: Optional[int] = None
) -> Dict[str, Any]:
    """What MITRE says to look for behind the techniques a rule's alerts carry.

    The table above says a rule is noisy. The next question is what the
    behaviour is supposed to look like and whether the telemetry to see it is
    even collected, and since ATT&CK v18 MITRE answers both: a Detection
    Strategy per technique, its analytics, the log sources they read, and the
    fields an engineer is expected to tune.

    Technique ids are resolved forward before lookup. An alert triaged before
    a catalogue bump carries the id of its day -- the `T1562` tree moved to
    `T1685` at v18/v19 -- and looking that up unresolved finds nothing, which
    renders as "MITRE has no guidance" rather than "this id was retired".

    Separates three states the caller must not collapse: the snapshot did not
    load, the rule's alerts carry no technique at all, and the techniques are
    known but carry no analytic.
    """
    lookback = days if days is not None else DEFAULT_WINDOW_DAYS
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    cutoff = now - timedelta(days=lookback)

    # `(unmapped)` is the bucket for alerts with no rule_name, and is a legal
    # value arriving from the table, so it selects the NULL rows it stands for.
    criterion = (
        AlertTriage.rule_name.is_(None)
        if rule_name == _UNMAPPED
        else AlertTriage.rule_name == rule_name
    )
    rows = session.execute(
        select(AlertTriage.mitre_techniques)
        .where(criterion)
        .where(AlertTriage.created_at >= cutoff)
    ).all()

    raw_ids: set[str] = set()
    for (techniques,) in rows:
        for tid in techniques or []:
            if isinstance(tid, str) and tid.strip():
                raw_ids.add(tid.strip().upper())

    # Retired ids are kept beside their replacement rather than silently
    # rewritten: an engineer reading a rule tagged T1562.002 needs to see that
    # the guidance below is filed under T1685.001.
    resolved: Dict[str, set] = {}
    for tid in raw_ids:
        resolved.setdefault(resolve(tid), set()).add(tid)

    techniques_out: List[Dict[str, Any]] = []
    without_guidance: List[str] = []
    for tid in sorted(resolved):
        strategies = strategies_for_technique(tid)
        retired_from = sorted(o for o in resolved[tid] if o != tid)
        if not strategies:
            without_guidance.append(tid)
            continue
        techniques_out.append({
            "technique_id": tid,
            "retired_from": retired_from,
            "strategies": strategies,
            "analytic_count": sum(len(s.get("analytics", [])) for s in strategies),
        })

    # Collected across the whole rule, because the telemetry question is asked
    # once per rule and not once per technique.
    log_sources: Dict[tuple, Dict[str, Any]] = {}
    for tid in sorted(resolved):
        for source in log_sources_for_technique(tid):
            key = (source["name"], source["channel"])
            entry = log_sources.setdefault(key, {**source, "technique_ids": []})
            if tid not in entry["technique_ids"]:
                entry["technique_ids"].append(tid)

    return {
        "rule_name": rule_name,
        "period_days": lookback,
        "snapshot": snapshot_status(),
        "alerts_seen": len(rows),
        "techniques": techniques_out,
        "techniques_without_guidance": sorted(without_guidance),
        "log_sources": sorted(
            log_sources.values(),
            key=lambda s: (s["name"] or "", s["channel"] or ""),
        ),
    }
