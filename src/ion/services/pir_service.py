"""Post-Incident Review service.

CRUD over PIRs and their action items, plus an Ollama-powered "suggest
improvements" helper that takes a closed case and returns a draft PIR.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from ion.models.alert_triage import AlertCase, Note, NoteEntityType
from ion.models.pir import PIRActionItem, PIRActionStatus, PIRStatus, PostIncidentReview

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------

def list_pirs(session: Session, status: Optional[str] = None) -> List[dict]:
    stmt = select(PostIncidentReview).order_by(PostIncidentReview.updated_at.desc())
    if status:
        stmt = stmt.where(PostIncidentReview.status == status)
    rows = session.execute(stmt).scalars().all()
    return [r.to_dict(include_actions=False) for r in rows]


def get_pir(session: Session, pir_id: int) -> Optional[PostIncidentReview]:
    return session.get(PostIncidentReview, pir_id)


def get_pir_by_case(session: Session, case_id: int) -> Optional[PostIncidentReview]:
    return session.execute(
        select(PostIncidentReview).where(PostIncidentReview.case_id == case_id)
    ).scalar_one_or_none()


def create_pir(
    session: Session,
    *,
    case_id: int,
    created_by_id: Optional[int],
) -> PostIncidentReview:
    """Create an empty PIR for a closed case (idempotent)."""
    existing = get_pir_by_case(session, case_id)
    if existing:
        return existing
    case = session.get(AlertCase, case_id)
    if not case:
        raise ValueError("Case not found")
    pir = PostIncidentReview(
        case_id=case_id,
        status=PIRStatus.DRAFT.value,
        created_by_id=created_by_id,
        metrics=_compute_metrics(case),
    )
    session.add(pir)
    session.commit()
    session.refresh(pir)
    return pir


def update_pir(session: Session, pir_id: int, **fields) -> Optional[PostIncidentReview]:
    pir = session.get(PostIncidentReview, pir_id)
    if not pir:
        return None
    allowed = {
        "status", "summary", "timeline", "what_worked", "what_didnt",
        "root_cause", "detection_gaps", "response_gaps", "metrics",
    }
    for k, v in fields.items():
        if k in allowed:
            setattr(pir, k, v)
    if fields.get("status") == PIRStatus.APPROVED.value and not pir.approved_at:
        pir.approved_at = datetime.utcnow()
    session.commit()
    session.refresh(pir)
    return pir


def delete_pir(session: Session, pir_id: int) -> bool:
    pir = session.get(PostIncidentReview, pir_id)
    if not pir:
        return False
    session.delete(pir)
    session.commit()
    return True


# ---------------------------------------------------------------------------
# Action items
# ---------------------------------------------------------------------------

def add_action(
    session: Session,
    pir_id: int,
    *,
    title: str,
    description: Optional[str] = None,
    category: Optional[str] = None,
    priority: str = "medium",
    owner_id: Optional[int] = None,
    due_date=None,
) -> PIRActionItem:
    pir = session.get(PostIncidentReview, pir_id)
    if not pir:
        raise ValueError("PIR not found")
    a = PIRActionItem(
        pir_id=pir_id,
        title=title.strip(),
        description=description,
        category=category,
        priority=priority,
        owner_id=owner_id,
        due_date=due_date,
        status=PIRActionStatus.OPEN.value,
    )
    session.add(a)
    session.commit()
    session.refresh(a)
    return a


def update_action(session: Session, action_id: int, **fields) -> Optional[PIRActionItem]:
    a = session.get(PIRActionItem, action_id)
    if not a:
        return None
    allowed = {"title", "description", "category", "priority", "status", "owner_id", "due_date"}
    for k, v in fields.items():
        if k in allowed:
            setattr(a, k, v)
    if fields.get("status") == PIRActionStatus.DONE.value and not a.completed_at:
        a.completed_at = datetime.utcnow()
    session.commit()
    session.refresh(a)
    return a


def delete_action(session: Session, action_id: int) -> bool:
    a = session.get(PIRActionItem, action_id)
    if not a:
        return False
    session.delete(a)
    session.commit()
    return True


def backlog(session: Session) -> List[dict]:
    """Return all open PIR action items across the org for the dashboard."""
    rows = session.execute(
        select(PIRActionItem).where(
            PIRActionItem.status.in_([
                PIRActionStatus.OPEN.value,
                PIRActionStatus.IN_PROGRESS.value,
                PIRActionStatus.BLOCKED.value,
            ])
        ).order_by(PIRActionItem.due_date.asc().nullslast(), PIRActionItem.priority.desc())
    ).scalars().all()
    return [a.to_dict() for a in rows]


# ---------------------------------------------------------------------------
# AI suggest
# ---------------------------------------------------------------------------

def _compute_metrics(case: AlertCase) -> dict:
    """Pull a few quantitative facts from the case for the metrics panel."""
    metrics: dict = {
        "case_number": case.case_number,
        "severity": case.severity,
        "closure_reason": case.closure_reason,
    }
    if case.created_at and case.closed_at:
        delta = case.closed_at - case.created_at
        metrics["mttr_hours"] = round(delta.total_seconds() / 3600, 1)
    metrics["affected_hosts"] = len(case.affected_hosts or [])
    metrics["affected_users"] = len(case.affected_users or [])
    metrics["observable_count"] = len(case.observables or [])
    return metrics


def _gather_case_notes(session: Session, case_id: int) -> str:
    """Concatenate analyst notes for the case (used in the AI prompt)."""
    notes = session.execute(
        select(Note).where(
            Note.entity_type == NoteEntityType.CASE.value,
            Note.entity_id == case_id,
        ).order_by(Note.created_at.asc())
    ).scalars().all()
    parts = []
    for n in notes[:30]:
        author = (n.created_by.username if n.created_by else "?")
        ts = n.created_at.isoformat() if n.created_at else ""
        parts.append(f"[{ts} {author}] {n.content[:400]}")
    return "\n".join(parts)


async def suggest_improvements(session: Session, pir_id: int) -> Optional[str]:
    """Ask Ollama to draft improvement bullets for this PIR."""
    pir = session.get(PostIncidentReview, pir_id)
    if not pir:
        return None
    case = session.get(AlertCase, pir.case_id)
    if not case:
        return None

    notes_blob = _gather_case_notes(session, case.id)
    metrics = _compute_metrics(case)

    try:
        from ion.services.ollama_service import get_ollama_service
        svc = get_ollama_service()
        if not svc.enabled:
            return None
    except Exception:
        return None

    prompt = f"""You are reviewing a closed SOC case and writing the
"Improvements" section of a post-incident review.

Case: {case.case_number or case.id}
Title: {case.title or '-'}
Severity: {case.severity or '-'}
Closure reason: {case.closure_reason or '-'}
MTTR (hours): {metrics.get('mttr_hours', '-')}
Affected hosts: {metrics.get('affected_hosts', 0)}
Affected users: {metrics.get('affected_users', 0)}
Observables: {metrics.get('observable_count', 0)}

Analyst notes (most recent first):
{notes_blob[:3000] if notes_blob else '(none)'}

Existing summary: {pir.summary or '(empty)'}
Existing root cause: {pir.root_cause or '(empty)'}

Write 4 to 7 concrete, specific improvement actions in plain bullet points
(use "- " prefix). Focus on detection rules, playbooks, training, tooling,
and process gaps that THIS case revealed. Avoid generic advice. Each bullet
should describe a single action an engineer can act on this week."""

    try:
        text = await svc.generate(prompt=prompt, temperature=0.3)
    except Exception as e:
        logger.warning("PIR AI suggest failed: %s", e)
        return None

    pir.ai_suggestions = text
    pir.ai_generated_at = datetime.utcnow()
    session.commit()
    return text
