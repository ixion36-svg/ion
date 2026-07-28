"""Detection Proposals service — Phase 1 of the DE module.

Drafts a reviewable tuning proposal **from a Noise Campaign** (deterministic, no
LLM — air-gap-friendly and testable), persists the human-owned draft, records the
human's one-shot decision (applied / rejected), and later measures the realized
noise drop for an applied proposal by re-running the Phase-0 metric before vs
after `applied_at`.

Hard constraint (roadmap): ION never writes to a detection backend. "Applied"
means the human applied it in their own backend and is recording that fact here.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from ion.models.detection_proposal import (
    DetectionProposal,
    DetectionProposalChangeType,
    DetectionProposalStatus,
)
from ion.services.de_metrics_service import fp_alerts_for_rule, get_noise_campaigns

_CHANGE_TYPES = {c.value for c in DetectionProposalChangeType}


def _now() -> datetime:
    """Naive UTC — matches AlertCase.closed_at / the DE metric window math."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _parse_dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "")).replace(tzinfo=None)
    except (TypeError, ValueError):
        return None


def _campaign_for_rule(session: Session, rule_name: str, days: int) -> Optional[Dict[str, Any]]:
    nc = get_noise_campaigns(session, days=days)
    return next((c for c in nc["campaigns"] if c["rule_name"] == rule_name), None)


def draft_from_campaign(
    session: Session, rule_name: str, days: int = 90
) -> Optional[Dict[str, Any]]:
    """Deterministic, unsaved draft for a rule's current campaign (a preview).

    Returns None when the rule has no qualifying campaign in the window. The
    caller (human) edits every field before saving.
    """
    c = _campaign_for_rule(session, rule_name, days)
    if not c:
        return None

    top_sig = c["top_signatures"][0]["value"] if c["top_signatures"] else None
    top_hosts = [h["value"] for h in c["top_hosts"][:3]]
    scope_bits: List[str] = []
    if top_sig:
        scope_bits.append(f"trigger `{top_sig}`")
    if top_hosts:
        scope_bits.append("host(s) " + ", ".join(f"`{h}`" for h in top_hosts))
    scope = " on ".join(scope_bits) if scope_bits else "the recurring benign trigger"

    suggested = (
        f'Add an exception to rule "{rule_name}" for {scope}. This benign pattern '
        f"accounts for {c['fp_alerts']} false-positive alert(s) across "
        f"{c['case_count']} case(s) in the last {days} days (~{c['cost_hours']}h of "
        f"analyst time). Scope the exception to the benign context above — do not "
        f"blanket the rule, and preserve coverage of the MITRE techniques listed."
    )
    sig_list = ", ".join(s["value"] for s in c["top_signatures"][:3]) or "n/a"
    rationale = (
        f'Rule "{rule_name}" produced {c["fp_alerts"]} FP/benign closures '
        f"({c['false_positive']} FP + {c['benign_true_positive']} benign) between "
        f"{c['first_seen']} and {c['last_seen']}. Top signatures: {sig_list}."
    )
    return {
        "rule_name": rule_name,
        "change_type": DetectionProposalChangeType.EXCLUSION.value,
        "title": f'Tune "{rule_name}" — {c["fp_alerts"]} FP alerts (~{c["cost_hours"]}h)',
        "suggested_change": suggested,
        "rationale": rationale,
        "scope": scope,
        "expected_fp_reduction": c["fp_alerts"],
        "expected_hours_reclaimed": c["cost_hours"],
        "campaign_snapshot": c,
        "mitre_techniques": c["mitre_techniques"],
    }


def create_proposal(
    session: Session, payload: Dict[str, Any], user_id: Optional[int]
) -> DetectionProposal:
    """Persist a human-owned draft. Raises ValueError on invalid input."""
    title = (payload.get("title") or "").strip()
    change = (payload.get("suggested_change") or "").strip()
    if not title:
        raise ValueError("title is required")
    if not change:
        raise ValueError("suggested_change is required")
    change_type = (payload.get("change_type") or "exclusion").strip()
    if change_type not in _CHANGE_TYPES:
        raise ValueError(f"invalid change_type '{change_type}'")

    proposal = DetectionProposal(
        rule_name=(payload.get("rule_name") or None),
        change_type=DetectionProposalChangeType(change_type),
        title=title,
        suggested_change=change,
        rationale=(payload.get("rationale") or None),
        scope=(payload.get("scope") or None),
        expected_fp_reduction=payload.get("expected_fp_reduction"),
        expected_hours_reclaimed=payload.get("expected_hours_reclaimed"),
        campaign_snapshot=payload.get("campaign_snapshot"),
        mitre_techniques=payload.get("mitre_techniques") or [],
        status=DetectionProposalStatus.DRAFT,
        created_by_id=user_id,
    )
    session.add(proposal)
    session.commit()
    session.refresh(proposal)
    return proposal


def update_proposal(
    session: Session, proposal_id: int, payload: Dict[str, Any]
) -> DetectionProposal:
    """Edit an editable (DRAFT) proposal. Raises ValueError if not found / decided."""
    p = session.get(DetectionProposal, proposal_id)
    if p is None:
        raise ValueError("proposal not found")
    if p.status != DetectionProposalStatus.DRAFT:
        raise ValueError("only draft proposals can be edited")

    if "title" in payload:
        title = (payload.get("title") or "").strip()
        if not title:
            raise ValueError("title cannot be empty")
        p.title = title
    if "suggested_change" in payload:
        change = (payload.get("suggested_change") or "").strip()
        if not change:
            raise ValueError("suggested_change cannot be empty")
        p.suggested_change = change
    if "change_type" in payload:
        ct = (payload.get("change_type") or "").strip()
        if ct not in _CHANGE_TYPES:
            raise ValueError(f"invalid change_type '{ct}'")
        p.change_type = DetectionProposalChangeType(ct)
    for field in ("rationale", "scope"):
        if field in payload:
            setattr(p, field, payload.get(field) or None)
    session.commit()
    session.refresh(p)
    return p


def decide_proposal(
    session: Session,
    proposal_id: int,
    decision: str,
    user_id: Optional[int],
    notes: Optional[str] = None,
    applied_at: Optional[str] = None,
) -> DetectionProposal:
    """One-shot decision: DRAFT → APPLIED | REJECTED (mirrors tuning _review)."""
    p = session.get(DetectionProposal, proposal_id)
    if p is None:
        raise ValueError("proposal not found")
    if p.status != DetectionProposalStatus.DRAFT:
        raise ValueError(f"proposal already {p.status} — decisions are one-shot")

    decision = (decision or "").strip().lower()
    if decision not in ("applied", "rejected"):
        raise ValueError("decision must be 'applied' or 'rejected'")

    p.decided_by_id = user_id
    p.decided_at = _now()
    p.decision_notes = (notes or None)
    if decision == "applied":
        p.status = DetectionProposalStatus.APPLIED
        p.applied_at = _parse_dt(applied_at) or _now()
    else:
        p.status = DetectionProposalStatus.REJECTED
    session.commit()
    session.refresh(p)
    return p


def measure_outcome(
    session: Session, proposal_id: int, days: int = 30
) -> Dict[str, Any]:
    """Measure realized noise drop for an APPLIED proposal: rule FP count in the
    `days` before `applied_at` vs since `applied_at`. Persists to outcome_json."""
    p = session.get(DetectionProposal, proposal_id)
    if p is None:
        raise ValueError("proposal not found")
    if p.status != DetectionProposalStatus.APPLIED or p.applied_at is None:
        raise ValueError("outcome can only be measured for an applied proposal")
    if not p.rule_name:
        raise ValueError("proposal has no rule_name to measure")

    now = _now()
    applied = p.applied_at
    before_start = applied - timedelta(days=days)
    after_end = min(now, applied + timedelta(days=days))
    before = fp_alerts_for_rule(session, p.rule_name, before_start, applied)
    after = fp_alerts_for_rule(session, p.rule_name, applied, after_end)
    days_observed = max(0, (after_end - applied).days)

    drop_pct: Optional[float] = None
    if before > 0:
        drop_pct = round((before - after) / before * 100, 1)
    outcome = {
        "before_count": before,
        "after_count": after,
        "window_days": days,
        "days_observed": days_observed,
        "drop_pct": drop_pct,
        "measured_at": now.isoformat(),
        "note": (
            "Fewer FP closures observed since the change was applied is consistent "
            "with the tuning working; it is not proof of causation."
        ),
    }
    p.outcome_json = outcome
    session.commit()
    return outcome


def list_proposals(
    session: Session, status: Optional[str] = None, limit: int = 200
) -> List[Dict[str, Any]]:
    q = select(DetectionProposal).order_by(DetectionProposal.created_at.desc())
    if status and status != "all":
        q = q.where(DetectionProposal.status == DetectionProposalStatus(status))
    rows = session.execute(q.limit(limit)).scalars().all()
    return [p.to_dict() for p in rows]


def get_proposal(session: Session, proposal_id: int) -> Optional[Dict[str, Any]]:
    p = session.get(DetectionProposal, proposal_id)
    return p.to_dict() if p else None
