"""Detection Health — per-rule performance analytics (v0.47.0).

Closes the IR->detection feedback loop using data ION already collects. The
closure figures come from ``rule_outcome_service``, the measure DE Metrics and
the external rule-outcomes API read too, so a rule's false-positive rate is the
same number on every surface. Per detection rule:

- **volume** — alerts fired in the window (triage rows created),
- **closed** — alerts whose case closed with a reason (the rate denominator),
- **fp_rate / tp_yield** — false-positive rate and true-positive yield,
- **silent** — fires but has never produced a confirmed true positive,
- **noisy** — ``NoisyPolicy``, defined once in rule_outcome_service,
- **decaying** — true-positive rate trending down (recent half vs older half),
- **bob_disagreement_rate** — where Bob's suggested verdict disagreed with the
  human (excludes abstentions / circuit-breaker auto-escalations). This one
  stays on the ``AIFeedback`` ledger: it measures Bob, not the rule.

Read/aggregate only — no new external integration. The dashboard's one-click
"create tuning proposal" reuses the existing proposal queue.

Dedup contract for the Bob figures (load-bearing): every alert gets a fire-time
``human_verdict = "pending"`` row AND, later, a case-close row. Readers MUST
keep ``MAX(id)`` per (alert_id, alert_prompt_template_id), identical to
``bob_eval_service._fetch_deduped_feedback``.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from ion.models.ai_feedback import AIFeedback
from ion.models.alert_triage import AlertTriage
from ion.services.ai_feedback_dedupe import deduped_feedback_ids
from ion.services.attack_detection_service import (
    log_sources_for_technique,
    snapshot_status,
    strategies_for_technique,
)
from ion.services.attack_revocation_service import resolve
from ion.services.rule_outcome_service import (
    DEFAULT_WINDOW_DAYS,
    UNMAPPED,
    NoisyPolicy,
    RuleKey,
    RuleOutcome,
    Window,
    rule_outcomes,
)

_UNMAPPED = UNMAPPED


def _thresholds() -> Dict[str, Any]:
    """Env-tunable thresholds, read at call time so tests can monkeypatch."""
    try:
        lookback = int(os.environ.get("ION_DH_LOOKBACK_DAYS", DEFAULT_WINDOW_DAYS))
    except (TypeError, ValueError):
        lookback = DEFAULT_WINDOW_DAYS
    try:
        decay = float(os.environ.get("ION_DH_DECAY_DELTA_PCT", 20.0))
    except (TypeError, ValueError):
        decay = 20.0
    policy = NoisyPolicy.from_env()
    return {
        "lookback_days": lookback,
        "min_sample": policy.min_closed,
        "noisy_fp_pct": policy.fp_rate_pct,
        "decay_delta_pct": decay,
    }


def _pct(num: int, denom: int) -> Optional[float]:
    """Percentage, or None when there's no denominator (suppress noise)."""
    if denom <= 0:
        return None
    return round(num / denom * 100, 1)


def _is_decaying(recent: Optional[RuleOutcome], older: Optional[RuleOutcome],
                 min_sample: int, delta: float) -> bool:
    """TP rate fell by ``delta`` points; both halves need a sample to compare."""
    half = max(1, min_sample // 2)
    if recent is None or older is None:
        return False
    if recent.closed < half or older.closed < half:
        return False
    return (recent.true_positive / recent.closed * 100
            <= older.true_positive / older.closed * 100 - delta)


def get_detection_health(session: Session, days: Optional[int] = None) -> Dict[str, Any]:
    """Aggregate per-rule detection-health metrics over the lookback window."""
    th = _thresholds()
    lookback = days if days is not None else th["lookback_days"]
    policy = NoisyPolicy.from_env()
    window = Window.last(lookback)
    outcomes = rule_outcomes(session, window)
    recent = rule_outcomes(session, Window(window.midpoint, window.until))
    older = rule_outcomes(session, Window(window.since, window.midpoint))

    bob = _bob_scores(session, window, outcomes)
    keys = set(outcomes.records) | set(bob)

    rules: List[Dict[str, Any]] = []
    n_silent = n_noisy = n_decaying = 0
    for key in keys:
        rec = outcomes.get(key) or RuleOutcome(key=key, rule_name=key.rule_name or _UNMAPPED)
        scored, disagreed = bob.get(key, (0, 0))
        judged = policy.judges(rec)
        flags = {
            "silent": judged and rec.true_positive == 0,
            "noisy": policy.is_noisy(rec),
            "decaying": judged and _is_decaying(
                recent.get(key), older.get(key), policy.min_closed, th["decay_delta_pct"]),
        }
        n_silent += flags["silent"]
        n_noisy += flags["noisy"]
        n_decaying += flags["decaying"]
        rules.append({
            "rule_id": key.rule_id,
            "rule_name": rec.rule_name,
            "volume": rec.alerts,
            "closed": rec.closed,
            "tp_count": rec.true_positive,
            "fp_count": rec.false_positive,
            "fp_rate": rec.fp_rate,
            "tp_yield": rec.tp_yield,
            "bob_disagreement_rate": _pct(disagreed, scored),
            "bob_scored": scored,
            "flags": flags,
            "flagged": any(flags.values()),
        })

    # Worst-first: flagged rules, then by volume, then by name so ties are stable.
    rules.sort(key=lambda r: (not r["flagged"], -(r["volume"] or 0), r["rule_name"]))

    unmapped = outcomes.get(RuleKey())
    return {
        "period_days": lookback,
        "generated_at": window.until.isoformat(),
        "thresholds": th,
        "summary": {
            "rules_tracked": len(rules),
            "total_alerts": sum(r["volume"] for r in rules),
            "total_closed": sum(r["closed"] for r in rules),
            "silent_rules": n_silent,
            "noisy_rules": n_noisy,
            "decaying_rules": n_decaying,
            "unmapped_alerts": unmapped.alerts if unmapped else 0,
        },
        "rules": rules,
    }


def _bob_scores(session: Session, window: Window, outcomes) -> Dict[RuleKey, tuple]:
    """(scored, disagreed) per rule, keyed exactly as the closure outcomes are.

    Only rows where Bob made a scored suggestion count: not abstentions, not
    circuit-breaker auto-escalations.
    """
    rows = session.execute(
        select(
            AIFeedback.bob_suggested_verdict,
            AIFeedback.agreement,
            AIFeedback.auto_escalated,
            AlertTriage.rule_id,
            AlertTriage.rule_name,
        )
        .outerjoin(AlertTriage, AlertTriage.es_alert_id == AIFeedback.alert_id)
        .where(AIFeedback.id.in_(deduped_feedback_ids(window.since)))
    ).all()
    scores: Dict[RuleKey, list] = {}
    for bob_verdict, agreement, auto_escalated, rule_id, rule_name in rows:
        if not bob_verdict or agreement is None or auto_escalated:
            continue
        tally = scores.setdefault(outcomes.key_for(rule_id, rule_name), [0, 0])
        tally[0] += 1
        tally[1] += agreement is False
    return {k: (v[0], v[1]) for k, v in scores.items()}


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
    th = _thresholds()
    lookback = days if days is not None else th["lookback_days"]
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


def get_rule_disagreements(session: Session, rule_name: str, days: Optional[int] = None) -> Dict[str, Any]:
    """Drill-down: the Bob-vs-analyst disagreements for one rule."""
    th = _thresholds()
    lookback = days if days is not None else th["lookback_days"]
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=lookback)
    deduped_ids = deduped_feedback_ids(cutoff)
    target = None if rule_name == _UNMAPPED else rule_name
    q = (
        select(
            AIFeedback.alert_id,
            AIFeedback.bob_suggested_verdict,
            AIFeedback.human_verdict,
            AIFeedback.created_at,
        )
        .outerjoin(AlertTriage, AlertTriage.es_alert_id == AIFeedback.alert_id)
        .where(AIFeedback.id.in_(deduped_ids))
        .where(AIFeedback.agreement.is_(False))
        .where(AIFeedback.auto_escalated.is_(False))
    )
    if target is None:
        q = q.where(AlertTriage.rule_name.is_(None))
    else:
        q = q.where(AlertTriage.rule_name == target)
    rows = session.execute(q.limit(100)).all()
    return {
        "rule_name": rule_name,
        "disagreements": [
            {
                "alert_id": a,
                "bob_suggested_verdict": b,
                "human_verdict": h,
                "created_at": c.isoformat() if c else None,
            }
            for (a, b, h, c) in rows
        ],
    }
