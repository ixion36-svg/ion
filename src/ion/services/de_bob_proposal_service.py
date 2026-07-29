"""Bob-tuning proposals service — Phase 3 write side.

Draft (from a Bob Feedback Item) → edit → **approve (a DIFFERENT person, gated
``de:approve``)** → the approved change is APPLIED to the rule's
``AlertPromptTemplate.prompt_text`` (which Bob renders live). The template text is
snapshotted *before* the write so ``revert`` restores it exactly. Every
approve/reject/revert writes an append-only AuditLog entry. Nothing here mutates
a template without an explicit human approval — there is no auto-apply path.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from ion.models.bob_tuning_proposal import BobTuningProposal, BobTuningProposalStatus
from ion.services.de_bob_service import get_bob_feedback
from ion.storage.alert_prompt_repository import AlertPromptRepository
from ion.storage.auth_repository import AuditLogRepository


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _audit(session: Session, action: str, user_id: Optional[int], p: BobTuningProposal) -> None:
    AuditLogRepository(session).create(
        action=action, user_id=user_id, resource_type="bob_tuning_proposal",
        resource_id=p.id,
        details={
            "proposal_id": p.id, "rule_name": p.rule_name, "template_id": p.template_id,
            "status": p.status, "created_by_id": p.created_by_id,
            "decided_by_id": p.decided_by_id,
        },
    )


def draft_from_feedback(
    session: Session, rule_name: str, bob_verdict: str, human_verdict: str,
    days: int = 90,
) -> Optional[Dict[str, Any]]:
    """Deterministic scaffold for a disagreement class (unsaved preview).

    Surfaces the evidence + the template's current guide; the human authors the
    improved guidance. No LLM. Returns None if that class isn't present.
    """
    fb = get_bob_feedback(session, days=days)
    cls = next(
        (c for c in fb["classes"]
         if c["rule_name"] == rule_name and c["bob_verdict"] == bob_verdict
         and (c["human_verdict"] or "").lower() == (human_verdict or "").lower()),
        None,
    )
    if not cls:
        return None

    tmpl = None
    if cls.get("template_id"):
        tmpl = AlertPromptRepository(session).get_by_id(cls["template_id"])
    current = (tmpl.prompt_text if tmpl else "") or ""
    reasons = "; ".join(cls["sample_reasons"][:3]) or "(no analyst notes recorded)"
    problem = (
        f"Bob suggested '{bob_verdict}' but analysts closed '{human_verdict}' on "
        f"{cls['count']} alert(s) for rule '{rule_name}'. Analyst reasons: {reasons}."
    )
    proposed = current + (
        "\n\n# DE tuning (draft — edit before submitting): add guidance so Bob "
        "weighs the analyst reasoning above. Describe the benign/malicious "
        "distinguisher; do not hard-code a verdict."
    )
    return {
        "rule_name": rule_name,
        "template_id": cls.get("template_id"),
        "title": f"Tune Bob for '{rule_name}' — {cls['count']} disagreement(s) "
                 f"({bob_verdict}→{human_verdict})",
        "problem_statement": problem,
        "feedback_snapshot": cls,
        "current_text": current,
        "proposed_text": proposed,
    }


def create_proposal(session: Session, payload: Dict[str, Any], user_id: Optional[int]) -> BobTuningProposal:
    title = (payload.get("title") or "").strip()
    proposed = (payload.get("proposed_text") or "").strip()
    if not title:
        raise ValueError("title is required")
    if not proposed:
        raise ValueError("proposed_text is required")
    p = BobTuningProposal(
        rule_name=(payload.get("rule_name") or None),
        template_id=payload.get("template_id"),
        title=title,
        problem_statement=(payload.get("problem_statement") or None),
        feedback_snapshot=payload.get("feedback_snapshot"),
        current_text=(payload.get("current_text") or None),
        proposed_text=proposed,
        status=BobTuningProposalStatus.DRAFT,
        created_by_id=user_id,
    )
    session.add(p)
    session.commit()
    session.refresh(p)
    return p


def update_proposal(session: Session, proposal_id: int, payload: Dict[str, Any]) -> BobTuningProposal:
    p = session.get(BobTuningProposal, proposal_id)
    if p is None:
        raise ValueError("proposal not found")
    if p.status != BobTuningProposalStatus.DRAFT:
        raise ValueError("only draft proposals can be edited")
    if "title" in payload:
        t = (payload.get("title") or "").strip()
        if not t:
            raise ValueError("title cannot be empty")
        p.title = t
    if "proposed_text" in payload:
        pt = (payload.get("proposed_text") or "").strip()
        if not pt:
            raise ValueError("proposed_text cannot be empty")
        p.proposed_text = pt
    if "problem_statement" in payload:
        p.problem_statement = payload.get("problem_statement") or None
    session.commit()
    session.refresh(p)
    return p


def approve_proposal(session: Session, proposal_id: int, user_id: Optional[int],
                     notes: Optional[str] = None) -> BobTuningProposal:
    """Approve + APPLY to the live template. SoD: approver != drafter. Versioned."""
    p = session.get(BobTuningProposal, proposal_id)
    if p is None:
        raise ValueError("proposal not found")
    if p.status != BobTuningProposalStatus.DRAFT:
        raise ValueError(f"proposal is {p.status} — only a draft can be approved")
    if p.created_by_id is not None and p.created_by_id == user_id:
        raise ValueError("separation of duties: a different user must approve")
    if not p.template_id:
        raise ValueError("proposal has no target template to apply to")

    repo = AlertPromptRepository(session)
    tmpl = repo.get_by_id(p.template_id)
    if tmpl is None:
        raise ValueError("target template no longer exists")

    # Snapshot BEFORE the write so revert restores exactly (prompt_text renders live).
    p.before_text = tmpl.prompt_text or ""
    repo.update(tmpl, prompt_text=p.proposed_text)
    p.status = BobTuningProposalStatus.APPROVED
    p.decided_by_id = user_id
    p.decided_at = _now()
    p.decision_notes = (notes or None)
    p.applied_at = _now()
    _audit(session, "bob_tuning_approved", user_id, p)
    session.commit()
    session.refresh(p)
    return p


def reject_proposal(session: Session, proposal_id: int, user_id: Optional[int],
                    notes: Optional[str] = None) -> BobTuningProposal:
    p = session.get(BobTuningProposal, proposal_id)
    if p is None:
        raise ValueError("proposal not found")
    if p.status != BobTuningProposalStatus.DRAFT:
        raise ValueError(f"proposal is {p.status} — only a draft can be rejected")
    p.status = BobTuningProposalStatus.REJECTED
    p.decided_by_id = user_id
    p.decided_at = _now()
    p.decision_notes = (notes or None)
    _audit(session, "bob_tuning_rejected", user_id, p)
    session.commit()
    session.refresh(p)
    return p


def revert_proposal(session: Session, proposal_id: int, user_id: Optional[int]) -> BobTuningProposal:
    """Roll an approved change back: restore the snapshotted before_text."""
    p = session.get(BobTuningProposal, proposal_id)
    if p is None:
        raise ValueError("proposal not found")
    if p.status != BobTuningProposalStatus.APPROVED:
        raise ValueError("only an approved proposal can be reverted")
    if p.template_id and p.before_text is not None:
        repo = AlertPromptRepository(session)
        tmpl = repo.get_by_id(p.template_id)
        if tmpl is not None:
            repo.update(tmpl, prompt_text=p.before_text)
    p.status = BobTuningProposalStatus.REVERTED
    p.reverted_by_id = user_id
    p.reverted_at = _now()
    _audit(session, "bob_tuning_reverted", user_id, p)
    session.commit()
    session.refresh(p)
    return p


def list_proposals(session: Session, status: Optional[str] = None, limit: int = 200) -> List[Dict[str, Any]]:
    q = select(BobTuningProposal).order_by(BobTuningProposal.created_at.desc())
    if status and status != "all":
        q = q.where(BobTuningProposal.status == BobTuningProposalStatus(status))
    rows = session.execute(q.limit(limit)).scalars().all()
    return [p.to_dict() for p in rows]


def get_proposal(session: Session, proposal_id: int) -> Optional[Dict[str, Any]]:
    p = session.get(BobTuningProposal, proposal_id)
    return p.to_dict() if p else None
