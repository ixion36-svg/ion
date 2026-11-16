"""Detection Health — per-rule performance analytics (v0.47.0).

Closes the IR→detection feedback loop using data ION already collects. Reads the
`AIFeedback` ledger (Bob's verdict + the human closure verdict, written at
case-close) joined to `AlertTriage.rule_name`, and aggregates per detection rule:

- **volume** — alerts fired (incl. still-open),
- **closed** — alerts resolved with a real verdict (the rate denominator),
- **fp_rate / tp_yield** — false-positive rate and true-positive yield,
- **silent** — fires but has never produced a confirmed true positive,
- **noisy** — false-positive rate at/above a threshold,
- **decaying** — true-positive rate trending down (recent half vs older half),
- **bob_disagreement_rate** — where Bob's suggested verdict disagreed with the
  human (excludes abstentions / circuit-breaker auto-escalations).

Read/aggregate only — no new external integration. The dashboard's one-click
"create tuning proposal" reuses the existing `TuningProposal` model.

Dedup contract (load-bearing): every alert gets a fire-time `human_verdict =
"pending"` row AND, later, a case-close row. Readers MUST keep `MAX(id)` per
(alert_id, alert_prompt_template_id) so a closed alert is counted once with its
real verdict — identical to `bob_eval_service._fetch_deduped_feedback`.

v2 hook: Bob could draft a `suggested_change` per noisy rule via the existing
Ollama integration + the `tuning_recommendation` contract — deliberately out of
scope for v1 (keeps this surface read-only).
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

_PENDING = "pending"
_UNMAPPED = "(unmapped)"
_TRUE_POSITIVE = "true_positive"
_FALSE_POSITIVE = "false_positive"
_BENIGN_TP = "benign_true_positive"


def _thresholds() -> Dict[str, Any]:
    """Env-tunable thresholds, read at call time so tests can monkeypatch."""

    def _f(name: str, default: float) -> float:
        try:
            return float(os.environ.get(name, default))
        except (TypeError, ValueError):
            return default

    def _i(name: str, default: int) -> int:
        try:
            return int(os.environ.get(name, default))
        except (TypeError, ValueError):
            return default

    return {
        "lookback_days": _i("ION_DH_LOOKBACK_DAYS", 90),
        "min_sample": _i("ION_DH_MIN_SAMPLE", 5),
        "noisy_fp_pct": _f("ION_DH_NOISY_FP_PCT", 70.0),
        "decay_delta_pct": _f("ION_DH_DECAY_DELTA_PCT", 20.0),
        "benign_tp_as_fp": os.environ.get("ION_DH_BENIGN_TP_AS_FP", "true").lower()
        in ("true", "1", "yes", "on"),
    }


def _pct(num: int, denom: int) -> Optional[float]:
    """Percentage, or None when there's no denominator (suppress noise)."""
    if denom <= 0:
        return None
    return round(num / denom * 100, 1)


class _RuleAgg:
    """Mutable per-rule accumulator."""

    __slots__ = (
        "rule_name", "volume", "closed", "tp", "fp",
        "recent_closed", "recent_tp", "older_closed", "older_tp",
        "bob_scored", "bob_disagree", "disagreements",
    )

    def __init__(self, rule_name: str) -> None:
        self.rule_name = rule_name
        self.volume = 0
        self.closed = 0
        self.tp = 0
        self.fp = 0
        self.recent_closed = 0
        self.recent_tp = 0
        self.older_closed = 0
        self.older_tp = 0
        self.bob_scored = 0  # rows where Bob made a scored suggestion
        self.bob_disagree = 0
        self.disagreements: List[Dict[str, Any]] = []


def get_detection_health(session: Session, days: Optional[int] = None) -> Dict[str, Any]:
    """Aggregate per-rule detection-health metrics over the lookback window."""
    th = _thresholds()
    lookback = days if days is not None else th["lookback_days"]
    # AIFeedback.created_at is a naive DateTime (no tz) on both SQLite and
    # Postgres, so do all window math in naive UTC to avoid aware/naive
    # comparison errors when bucketing recent-vs-older in Python below.
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    cutoff = now - timedelta(days=lookback)
    midpoint = cutoff + (now - cutoff) / 2
    fp_set = {_FALSE_POSITIVE}
    if th["benign_tp_as_fp"]:
        fp_set.add(_BENIGN_TP)

    # Dedup contract lives in ai_feedback_dedupe — see that module for why.
    deduped_ids = deduped_feedback_ids(cutoff)
    rows = session.execute(
        select(
            AIFeedback.human_verdict,
            AIFeedback.bob_suggested_verdict,
            AIFeedback.agreement,
            AIFeedback.auto_escalated,
            AIFeedback.created_at,
            AIFeedback.alert_id,
            AIFeedback.alert_prompt_template_id,
            AlertTriage.rule_name,
        )
        .outerjoin(AlertTriage, AlertTriage.es_alert_id == AIFeedback.alert_id)
        .where(AIFeedback.id.in_(deduped_ids))
    ).all()

    aggs: Dict[str, _RuleAgg] = {}
    unmapped_count = 0

    for (human_verdict, bob_verdict, agreement, auto_escalated,
         created_at, alert_id, template_id, rule_name) in rows:
        rn = rule_name or _UNMAPPED
        if rule_name is None:
            unmapped_count += 1
        agg = aggs.get(rn)
        if agg is None:
            agg = aggs[rn] = _RuleAgg(rn)

        agg.volume += 1
        is_recent = created_at is not None and created_at >= midpoint
        hv = (human_verdict or "").lower()
        closed = hv != _PENDING and hv != ""
        if closed:
            agg.closed += 1
            is_tp = hv == _TRUE_POSITIVE
            is_fp = hv in fp_set
            if is_tp:
                agg.tp += 1
            if is_fp:
                agg.fp += 1
            if is_recent:
                agg.recent_closed += 1
                if is_tp:
                    agg.recent_tp += 1
            else:
                agg.older_closed += 1
                if is_tp:
                    agg.older_tp += 1

        # Bob-vs-analyst: only rows where Bob actually scored a suggestion
        # (not abstentions / circuit-breaker auto-escalations).
        if bob_verdict and agreement is not None and not auto_escalated:
            agg.bob_scored += 1
            if agreement is False:
                agg.bob_disagree += 1
                if len(agg.disagreements) < 25:
                    agg.disagreements.append({
                        "alert_id": alert_id,
                        "bob_suggested_verdict": bob_verdict,
                        "human_verdict": human_verdict,
                        "created_at": created_at.isoformat() if created_at else None,
                    })

    min_sample = th["min_sample"]
    noisy_pct = th["noisy_fp_pct"]
    decay_delta = th["decay_delta_pct"]

    rules: List[Dict[str, Any]] = []
    n_silent = n_noisy = n_decaying = 0
    for agg in aggs.values():
        fp_rate = _pct(agg.fp, agg.closed)
        tp_yield = _pct(agg.tp, agg.closed)
        bob_dis_rate = _pct(agg.bob_disagree, agg.bob_scored)

        flags = {"silent": False, "noisy": False, "decaying": False}
        if agg.closed >= min_sample:
            flags["silent"] = agg.tp == 0
            flags["noisy"] = fp_rate is not None and fp_rate >= noisy_pct
            # Decay: both halves need a minimum sample to compare fairly.
            half = max(1, min_sample // 2)
            if agg.recent_closed >= half and agg.older_closed >= half:
                recent_tp_rate = agg.recent_tp / agg.recent_closed * 100
                older_tp_rate = agg.older_tp / agg.older_closed * 100
                flags["decaying"] = recent_tp_rate <= older_tp_rate - decay_delta

        n_silent += flags["silent"]
        n_noisy += flags["noisy"]
        n_decaying += flags["decaying"]

        rules.append({
            "rule_name": agg.rule_name,
            "volume": agg.volume,
            "closed": agg.closed,
            "tp_count": agg.tp,
            "fp_count": agg.fp,
            "fp_rate": fp_rate,
            "tp_yield": tp_yield,
            "bob_disagreement_rate": bob_dis_rate,
            "bob_scored": agg.bob_scored,
            "flags": flags,
            "flagged": any(flags.values()),
        })

    # Worst-first: flagged rules, then by volume.
    rules.sort(key=lambda r: (not r["flagged"], -(r["volume"] or 0)))

    return {
        "period_days": lookback,
        "generated_at": now.isoformat(),
        "thresholds": th,
        "summary": {
            "rules_tracked": len(rules),
            "total_alerts": sum(r["volume"] for r in rules),
            "total_closed": sum(r["closed"] for r in rules),
            "silent_rules": n_silent,
            "noisy_rules": n_noisy,
            "decaying_rules": n_decaying,
            "unmapped_alerts": unmapped_count,
        },
        "rules": rules,
    }


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
