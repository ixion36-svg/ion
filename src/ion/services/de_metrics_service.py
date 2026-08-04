"""Detection-Engineering metrics — Phase 0 of the optional DE module.

Read-only measurement over data ION already collects. Two things, no write path:

- **Noise Campaigns** — clusters of false-positive / benign-true-positive alert
  closures grouped by detection *rule*, each with a first/last-seen window, a
  severity mix, a MITRE union, the top triggering signatures/hosts, and an
  **addressable analyst-hours** estimate (``fp_alerts × ION_DE_MINUTES_PER_ALERT``).
  This is the unit of DE work — "which rule is wasting the most analyst time".
  Sourced from the ``AlertTriage → AlertCase`` join (rule name lives on triage,
  the FP/benign verdict on the closed case), so it counts *every* FP closure —
  it does not depend on Bob having run.

- **DE Metrics** — the campaign roll-up plus a noise trend (recent vs older half)
  and the Bob-vs-human agreement rate off the deduped ``AIFeedback`` ledger.

Design constraints from the roadmap (docs/superpowers/plans/2026-07-26-…):
*ION drafts and measures; the analyst decides and acts.* Phase 0 has **no write
path** — nothing here mutates detections, closures or the ledger. "Hours saved"
in the roadmap is deliberately surfaced here as **addressable / reclaimable**
hours (the cost still being paid), because nothing has been tuned out yet; real
"saved" arrives in Phase 1 when a Detection Proposal lands.

Cluster granularity is **rule-level** in Phase 0. Sub-clustering by exact trigger
signature is a Phase 1 refinement gated on validating the observable schema
against real ES data (roadmap §5, open question 2) — so here the signature is
surfaced *within* each campaign (top observable tokens + hosts) rather than being
part of the group key, which keeps clustering robust to messy JSON.

Dedup contract for the Bob-agreement metric is identical to
``detection_health_service`` / ``bob_eval_service._fetch_deduped_feedback``:
keep ``MAX(id)`` per ``(alert_id, alert_prompt_template_id)``.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ion.models.ai_feedback import AIFeedback
from ion.models.alert_triage import AlertCase, AlertTriage
from ion.services.ai_feedback_dedupe import (
    deduped_feedback_ids,
    is_scored,
)

_FALSE_POSITIVE = "false_positive"
_BENIGN_TP = "benign_true_positive"
_UNMAPPED = "(unmapped)"


def _settings() -> Dict[str, Any]:
    """Env-tunable knobs, read at call time so tests can monkeypatch."""

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
        "lookback_days": _i("ION_DE_LOOKBACK_DAYS", 90),
        # Minutes of analyst time a single FP alert is assumed to cost. Fixed and
        # transparent — good enough to rank campaigns by wasted effort.
        "minutes_per_alert": _f("ION_DE_MINUTES_PER_ALERT", 10.0),
        # A campaign must have at least this many FP alerts to be worth listing.
        "min_campaign": _i("ION_DE_MIN_CAMPAIGN", 2),
        # Whether benign-true-positive closures count as noise (like Detection Health).
        "benign_tp_as_fp": os.environ.get("ION_DE_BENIGN_TP_AS_FP", "true").lower()
        in ("true", "1", "yes", "on"),
    }


def _pct(num: int, denom: int) -> Optional[float]:
    if denom <= 0:
        return None
    return round(num / denom * 100, 1)


def _obs_tokens(observables: Any) -> List[str]:
    """Best-effort normalise an observables JSON blob into ``type:value`` tokens.

    Tolerates the shapes ION's observables take across sources: a list of dicts
    (``{type,value}`` / ``{kind,name}`` / ``{id}``), a list of plain strings, or
    a flat dict. Never raises — unknown shapes just yield nothing.
    """
    out: List[str] = []
    if isinstance(observables, list):
        for o in observables:
            if isinstance(o, dict):
                t = str(o.get("type") or o.get("kind") or "").strip()
                v = str(o.get("value") or o.get("name") or o.get("id") or "").strip()
                tok = f"{t}:{v}" if t and v else (v or t)
                if tok:
                    out.append(tok)
            elif isinstance(o, str) and o.strip():
                out.append(o.strip())
    elif isinstance(observables, dict):
        for k, v in observables.items():
            if isinstance(v, (str, int, float)) and str(v).strip():
                out.append(f"{k}:{v}")
    return out[:50]


def _host_tokens(hosts: Any) -> List[str]:
    """Normalise an affected-hosts JSON blob into hostname strings."""
    out: List[str] = []
    if isinstance(hosts, list):
        for h in hosts:
            if isinstance(h, str) and h.strip():
                out.append(h.strip())
            elif isinstance(h, dict):
                v = h.get("name") or h.get("hostname") or h.get("host") or h.get("value")
                if isinstance(v, str) and v.strip():
                    out.append(v.strip())
    elif isinstance(hosts, str) and hosts.strip():
        out.append(hosts.strip())
    return out[:50]


def _top(counter: Dict[str, int], n: int) -> List[Dict[str, Any]]:
    """Top-n ``{value,count}`` from a token→count map, highest first."""
    items = sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))
    return [{"value": k, "count": v} for k, v in items[:n]]


class _Campaign:
    """Mutable per-rule false-positive accumulator (the Noise Campaign)."""

    __slots__ = (
        "rule_name", "fp_alerts", "case_ids", "first_seen", "last_seen",
        "fp_count", "benign_count", "severity", "mitre", "signatures",
        "hosts", "sample_alert_ids",
    )

    def __init__(self, rule_name: str) -> None:
        self.rule_name = rule_name
        self.fp_alerts = 0
        self.case_ids: set = set()
        self.first_seen: Optional[datetime] = None
        self.last_seen: Optional[datetime] = None
        self.fp_count = 0            # closure_reason == false_positive
        self.benign_count = 0        # closure_reason == benign_true_positive
        self.severity: Dict[str, int] = {}
        self.mitre: set = set()
        self.signatures: Dict[str, int] = {}
        self.hosts: Dict[str, int] = {}
        self.sample_alert_ids: List[str] = []


def get_noise_campaigns(session: Session, days: Optional[int] = None) -> Dict[str, Any]:
    """Cluster FP/benign alert closures by rule over the lookback window."""
    st = _settings()
    lookback = days if days is not None else st["lookback_days"]
    minutes = st["minutes_per_alert"]
    min_campaign = st["min_campaign"]
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    cutoff = now - timedelta(days=lookback)

    reasons = [_FALSE_POSITIVE]
    if st["benign_tp_as_fp"]:
        reasons.append(_BENIGN_TP)

    # One row per FP alert: triage (rule name / observables / MITRE) joined to
    # its closed case (verdict / closed_at / severity / hosts).
    rows = session.execute(
        select(
            AlertTriage.rule_name,
            AlertTriage.es_alert_id,
            AlertTriage.observables,
            AlertTriage.mitre_techniques,
            AlertCase.id,
            AlertCase.closure_reason,
            AlertCase.closed_at,
            AlertCase.severity,
            AlertCase.affected_hosts,
        )
        .join(AlertCase, AlertTriage.case_id == AlertCase.id)
        .where(AlertCase.closure_reason.in_(reasons))
        .where(AlertCase.closed_at.is_not(None))
        .where(AlertCase.closed_at >= cutoff)
    ).all()

    camps: Dict[str, _Campaign] = {}
    for (rule_name, alert_id, observables, mitre, case_id,
         closure_reason, closed_at, severity, hosts) in rows:
        rn = rule_name or _UNMAPPED
        c = camps.get(rn)
        if c is None:
            c = camps[rn] = _Campaign(rn)

        c.fp_alerts += 1
        if case_id is not None:
            c.case_ids.add(case_id)
        if closed_at is not None:
            if c.first_seen is None or closed_at < c.first_seen:
                c.first_seen = closed_at
            if c.last_seen is None or closed_at > c.last_seen:
                c.last_seen = closed_at
        if closure_reason == _BENIGN_TP:
            c.benign_count += 1
        else:
            c.fp_count += 1
        sev = (severity or "unknown").lower()
        c.severity[sev] = c.severity.get(sev, 0) + 1
        if isinstance(mitre, list):
            for m in mitre:
                if isinstance(m, str) and m.strip():
                    c.mitre.add(m.strip())
                elif isinstance(m, dict):
                    tid = m.get("technique_id") or m.get("id") or m.get("technique")
                    if isinstance(tid, str) and tid.strip():
                        c.mitre.add(tid.strip())
        for tok in _obs_tokens(observables):
            c.signatures[tok] = c.signatures.get(tok, 0) + 1
        for h in _host_tokens(hosts):
            c.hosts[h] = c.hosts.get(h, 0) + 1
        if alert_id and len(c.sample_alert_ids) < 10:
            c.sample_alert_ids.append(alert_id)

    campaigns: List[Dict[str, Any]] = []
    for c in camps.values():
        if c.fp_alerts < min_campaign:
            continue
        cost_hours = round(c.fp_alerts * minutes / 60.0, 1)
        campaigns.append({
            "rule_name": c.rule_name,
            "fp_alerts": c.fp_alerts,
            "case_count": len(c.case_ids),
            "false_positive": c.fp_count,
            "benign_true_positive": c.benign_count,
            "first_seen": c.first_seen.isoformat() if c.first_seen else None,
            "last_seen": c.last_seen.isoformat() if c.last_seen else None,
            "cost_hours": cost_hours,
            "severity_mix": dict(sorted(c.severity.items(), key=lambda kv: -kv[1])),
            "mitre_techniques": sorted(c.mitre)[:20],
            "top_signatures": _top(c.signatures, 5),
            "top_hosts": _top(c.hosts, 5),
            "sample_alert_ids": c.sample_alert_ids,
        })

    # Biggest noise first: by wasted hours, then alert count.
    campaigns.sort(key=lambda x: (-(x["cost_hours"] or 0), -(x["fp_alerts"] or 0)))

    total_fp = sum(x["fp_alerts"] for x in campaigns)
    total_hours = round(sum(x["cost_hours"] for x in campaigns), 1)
    return {
        "period_days": lookback,
        "generated_at": now.isoformat(),
        "minutes_per_alert": minutes,
        "campaign_count": len(campaigns),
        "total_fp_alerts": total_fp,
        "addressable_hours": total_hours,
        "campaigns": campaigns,
    }


def fp_alerts_for_rule(
    session: Session, rule_name: str, start: datetime, end: datetime
) -> int:
    """Count FP/benign alerts for one rule with `start <= closed_at < end`.

    The atom behind noise campaigns (one triage row = one FP alert), reused by
    Phase 1 outcome measurement to compare a rule's noise before vs after a
    proposal is applied. Honours the same benign-as-FP toggle as the campaigns.
    """
    st = _settings()
    reasons = [_FALSE_POSITIVE]
    if st["benign_tp_as_fp"]:
        reasons.append(_BENIGN_TP)
    q = (
        select(func.count())
        .select_from(AlertTriage)
        .join(AlertCase, AlertTriage.case_id == AlertCase.id)
        .where(AlertCase.closure_reason.in_(reasons))
        .where(AlertCase.closed_at.is_not(None))
        .where(AlertCase.closed_at >= start)
        .where(AlertCase.closed_at < end)
    )
    if rule_name == _UNMAPPED:
        q = q.where(AlertTriage.rule_name.is_(None))
    else:
        q = q.where(AlertTriage.rule_name == rule_name)
    return int(session.execute(q).scalar_one())


def _noise_trend(session: Session, cutoff: datetime, midpoint: datetime,
                 reasons: List[str]) -> Dict[str, Any]:
    """Recent-half vs older-half FP-closure counts → is noise rising or falling."""
    recent = session.execute(
        select(func.count())
        .select_from(AlertCase)
        .where(AlertCase.closure_reason.in_(reasons))
        .where(AlertCase.closed_at >= midpoint)
    ).scalar_one()
    older = session.execute(
        select(func.count())
        .select_from(AlertCase)
        .where(AlertCase.closure_reason.in_(reasons))
        .where(AlertCase.closed_at >= cutoff)
        .where(AlertCase.closed_at < midpoint)
    ).scalar_one()
    delta_pct = None
    if older > 0:
        delta_pct = round((recent - older) / older * 100, 1)
    direction = "flat"
    if delta_pct is not None:
        if delta_pct >= 10:
            direction = "rising"
        elif delta_pct <= -10:
            direction = "falling"
    return {
        "recent_fp_closures": int(recent),
        "older_fp_closures": int(older),
        "delta_pct": delta_pct,
        "direction": direction,
    }


def _bob_agreement(session: Session, cutoff: datetime) -> Dict[str, Any]:
    """Bob-vs-human agreement rate off the deduped AIFeedback ledger."""
    deduped_ids = deduped_feedback_ids(cutoff)
    rows = session.execute(
        select(
            AIFeedback.agreement,
            AIFeedback.bob_suggested_verdict,
            AIFeedback.auto_escalated,
        ).where(AIFeedback.id.in_(deduped_ids))
    ).all()
    scored = agreed = 0
    for agreement, bob_verdict, auto_escalated in rows:
        if is_scored(bob_verdict, agreement, auto_escalated):
            scored += 1
            if agreement is True:
                agreed += 1
    return {
        "scored": scored,
        "agreed": agreed,
        "agreement_rate": _pct(agreed, scored),
    }


def get_de_metrics(session: Session, days: Optional[int] = None) -> Dict[str, Any]:
    """The DE Metrics dashboard payload: campaigns + trend + Bob agreement."""
    st = _settings()
    lookback = days if days is not None else st["lookback_days"]
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    cutoff = now - timedelta(days=lookback)
    midpoint = cutoff + (now - cutoff) / 2
    reasons = [_FALSE_POSITIVE]
    if st["benign_tp_as_fp"]:
        reasons.append(_BENIGN_TP)

    nc = get_noise_campaigns(session, days=lookback)
    campaigns = nc["campaigns"]
    trend = _noise_trend(session, cutoff, midpoint, reasons)
    agreement = _bob_agreement(session, cutoff)

    top = campaigns[0] if campaigns else None
    return {
        "period_days": lookback,
        "generated_at": now.isoformat(),
        "settings": st,
        "summary": {
            "campaign_count": nc["campaign_count"],
            "total_fp_alerts": nc["total_fp_alerts"],
            "addressable_hours": nc["addressable_hours"],
            "top_reclaimable_hours": top["cost_hours"] if top else 0.0,
            "noisiest_rule": top["rule_name"] if top else None,
            "noise_trend": trend,
            "bob_agreement": agreement,
        },
        "campaigns": campaigns,
    }
