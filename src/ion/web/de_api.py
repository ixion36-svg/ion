"""Detection-Engineering API — Phases 0 + 1 of the optional DE module.

Phase 0 (read-only): false-positive "Noise Campaigns" clustered by rule + the DE
Metrics roll-up (noise trend + Bob-vs-human agreement). Gated ``de:read``.

Phase 1 (Detection Proposals): draft a reviewable tuning proposal from a campaign,
edit it, record the human's one-shot decision (applied / rejected), and measure
the realized noise drop for an applied proposal. Write gate ``de:propose``.
ION only records the draft + the decision — it never writes to a detection
backend (roadmap: *ION drafts and measures; the analyst decides and acts*).
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ion.auth.dependencies import get_current_user, require_permission
from ion.models.user import User
from ion.web.api import get_db_session

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/de", tags=["detection-engineering"])


# ── Phase 0 — metrics (read-only) ────────────────────────────────────────────


@router.get("/metrics", dependencies=[Depends(require_permission("de:read"))])
def de_metrics(
    days: int = Query(90, ge=1, le=365, description="Lookback window in days"),
    session: Session = Depends(get_db_session),
):
    """DE Metrics dashboard payload: noise campaigns + trend + Bob agreement."""
    from ion.services.de_metrics_service import get_de_metrics

    return get_de_metrics(session, days=days)


@router.get("/campaigns", dependencies=[Depends(require_permission("de:read"))])
def de_campaigns(
    days: int = Query(90, ge=1, le=365, description="Lookback window in days"),
    session: Session = Depends(get_db_session),
):
    """Noise Campaigns only (FP/benign closures clustered by rule)."""
    from ion.services.de_metrics_service import get_noise_campaigns

    return get_noise_campaigns(session, days=days)


# ── Phase 1 — detection proposals ────────────────────────────────────────────


class DraftRequest(BaseModel):
    rule_name: str
    days: int = 90


class ProposalCreate(BaseModel):
    rule_name: Optional[str] = None
    change_type: str = "exclusion"
    title: str
    suggested_change: str
    rationale: Optional[str] = None
    scope: Optional[str] = None
    expected_fp_reduction: Optional[int] = None
    expected_hours_reclaimed: Optional[float] = None
    campaign_snapshot: Optional[dict] = None
    mitre_techniques: Optional[list] = None


class ProposalUpdate(BaseModel):
    title: Optional[str] = None
    suggested_change: Optional[str] = None
    change_type: Optional[str] = None
    rationale: Optional[str] = None
    scope: Optional[str] = None


class DecideRequest(BaseModel):
    decision: str  # "applied" | "rejected"
    notes: Optional[str] = None
    applied_at: Optional[str] = None  # ISO; defaults to now on the server


class OutcomeRequest(BaseModel):
    days: int = 30


@router.get("/proposals", dependencies=[Depends(require_permission("de:read"))])
def list_proposals(
    status: str = Query("all", description="draft | applied | rejected | duplicate | all"),
    source: str = Query("all", description="bob | human | all"),
    session: Session = Depends(get_db_session),
):
    from ion.services.de_proposal_service import list_proposals as _list

    return {"proposals": _list(session, status=status, source=source)}


@router.get("/proposals/{proposal_id}", dependencies=[Depends(require_permission("de:read"))])
def get_proposal(proposal_id: int, session: Session = Depends(get_db_session)):
    from ion.services.de_proposal_service import get_proposal as _get

    p = _get(session, proposal_id)
    if p is None:
        raise HTTPException(status_code=404, detail="proposal not found")
    return p


@router.post("/proposals/draft", dependencies=[Depends(require_permission("de:propose"))])
def draft_proposal(payload: DraftRequest, session: Session = Depends(get_db_session)):
    """Deterministic, unsaved draft preview from a rule's current campaign."""
    from ion.services.de_proposal_service import draft_from_campaign

    draft = draft_from_campaign(session, payload.rule_name, days=payload.days)
    if draft is None:
        raise HTTPException(
            status_code=404,
            detail=f"no active noise campaign for rule '{payload.rule_name}' in the last {payload.days}d",
        )
    return draft


@router.post("/proposals", dependencies=[Depends(require_permission("de:propose"))])
def create_proposal(
    payload: ProposalCreate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    from ion.services.de_proposal_service import create_proposal as _create

    try:
        proposal = _create(session, payload.model_dump(), current_user.id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    logger.info("DE proposal %d created for rule %r by user %s",
                proposal.id, proposal.rule_name, current_user.id)
    return proposal.to_dict()


@router.patch("/proposals/{proposal_id}", dependencies=[Depends(require_permission("de:propose"))])
def update_proposal(
    proposal_id: int,
    payload: ProposalUpdate,
    session: Session = Depends(get_db_session),
):
    from ion.services.de_proposal_service import update_proposal as _update

    try:
        proposal = _update(session, proposal_id, payload.model_dump(exclude_unset=True))
    except ValueError as e:
        detail = str(e)
        raise HTTPException(status_code=404 if "not found" in detail else 400, detail=detail)
    return proposal.to_dict()


@router.post("/proposals/{proposal_id}/decide", dependencies=[Depends(require_permission("de:propose"))])
def decide_proposal(
    proposal_id: int,
    payload: DecideRequest,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    from ion.services.de_proposal_service import decide_proposal as _decide

    try:
        proposal = _decide(session, proposal_id, payload.decision, current_user.id,
                           notes=payload.notes, applied_at=payload.applied_at)
    except ValueError as e:
        detail = str(e)
        code = 404 if "not found" in detail else (409 if "one-shot" in detail else 400)
        raise HTTPException(status_code=code, detail=detail)
    logger.info("DE proposal %d decided '%s' by user %s",
                proposal_id, payload.decision, current_user.id)
    return proposal.to_dict()


@router.post("/proposals/{proposal_id}/measure-outcome", dependencies=[Depends(require_permission("de:propose"))])
def measure_outcome(
    proposal_id: int,
    payload: OutcomeRequest,
    session: Session = Depends(get_db_session),
):
    from ion.services.de_proposal_service import measure_outcome as _measure

    try:
        return _measure(session, proposal_id, days=payload.days)
    except ValueError as e:
        detail = str(e)
        raise HTTPException(status_code=404 if "not found" in detail else 400, detail=detail)


# ── Phase 2 — system quirks (advisory; SoD on verify) ────────────────────────


class QuirkCreate(BaseModel):
    title: str
    annotation: str
    justification: str
    review_date: str  # ISO; must be in the future
    scope_rules: Optional[list] = None
    scope_hosts: Optional[list] = None
    scope_users: Optional[list] = None
    scope_ips: Optional[list] = None
    scope_observables: Optional[list] = None
    priority_nudge: Optional[int] = 0


class RevertRequest(BaseModel):
    reason: Optional[str] = None


def _quirk_err(e: ValueError):
    detail = str(e)
    if "not found" in detail:
        code = 404
    elif "separation of duties" in detail:
        code = 409
    else:
        code = 400
    raise HTTPException(status_code=code, detail=detail)


@router.get("/quirks", dependencies=[Depends(require_permission("de:read"))])
def list_quirks(
    status: str = Query("all", description="pending | active | reverted | all"),
    session: Session = Depends(get_db_session),
):
    from ion.services.de_quirk_service import list_quirks as _list

    return {"quirks": _list(session, status=status)}


@router.get("/quirks/{quirk_id}", dependencies=[Depends(require_permission("de:read"))])
def get_quirk(quirk_id: int, session: Session = Depends(get_db_session)):
    from ion.services.de_quirk_service import get_quirk as _get

    q = _get(session, quirk_id)
    if q is None:
        raise HTTPException(status_code=404, detail="quirk not found")
    return q


@router.post("/quirks", dependencies=[Depends(require_permission("de:propose"))])
def raise_quirk(
    payload: QuirkCreate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    from ion.services.de_quirk_service import raise_quirk as _raise

    try:
        q = _raise(session, payload.model_dump(), current_user.id)
    except ValueError as e:
        _quirk_err(e)
    logger.info("DE quirk %d raised by user %s", q.id, current_user.id)
    return q.to_dict()


@router.post("/quirks/{quirk_id}/verify", dependencies=[Depends(require_permission("de:verify"))])
def verify_quirk(
    quirk_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Activate a pending quirk — a DIFFERENT user than the raiser (SoD)."""
    from ion.services.de_quirk_service import verify_quirk as _verify

    try:
        q = _verify(session, quirk_id, current_user.id)
    except ValueError as e:
        _quirk_err(e)
    logger.info("DE quirk %d verified by user %s", quirk_id, current_user.id)
    return q.to_dict()


@router.post("/quirks/{quirk_id}/revert", dependencies=[Depends(require_permission("de:verify"))])
def revert_quirk(
    quirk_id: int,
    payload: RevertRequest,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    from ion.services.de_quirk_service import revert_quirk as _revert

    try:
        q = _revert(session, quirk_id, current_user.id, reason=payload.reason)
    except ValueError as e:
        _quirk_err(e)
    logger.info("DE quirk %d reverted by user %s", quirk_id, current_user.id)
    return q.to_dict()


# ── Phase 3 — Bob improvement loop (feedback + scorecard + tuning proposals) ──


class BobDraftRequest(BaseModel):
    rule_name: str
    bob_verdict: str
    human_verdict: str
    days: int = 90


class BobProposalCreate(BaseModel):
    title: str
    proposed_text: str
    rule_name: Optional[str] = None
    template_id: Optional[int] = None
    problem_statement: Optional[str] = None
    current_text: Optional[str] = None
    feedback_snapshot: Optional[dict] = None


class BobProposalUpdate(BaseModel):
    title: Optional[str] = None
    proposed_text: Optional[str] = None
    problem_statement: Optional[str] = None


class DecisionRequest(BaseModel):
    notes: Optional[str] = None


def _bob_err(e: ValueError):
    detail = str(e)
    if "not found" in detail:
        code = 404
    elif "separation of duties" in detail:
        code = 409
    else:
        code = 400
    raise HTTPException(status_code=code, detail=detail)


@router.get("/bob-feedback", dependencies=[Depends(require_permission("de:read"))])
def bob_feedback(
    days: int = Query(90, ge=1, le=365),
    session: Session = Depends(get_db_session),
):
    """Bob-vs-analyst disagreement classes (the evidence for tuning proposals)."""
    from ion.services.de_bob_service import get_bob_feedback

    return get_bob_feedback(session, days=days)


@router.get("/scorecard", dependencies=[Depends(require_permission("de:read"))])
def bob_scorecard(
    days: int = Query(90, ge=1, le=365),
    session: Session = Depends(get_db_session),
):
    """Bob scorecard: agreement rate + drift + top disagreement classes."""
    from ion.services.de_bob_service import get_bob_scorecard

    return get_bob_scorecard(session, days=days)


@router.get("/bob-proposals", dependencies=[Depends(require_permission("de:read"))])
def list_bob_proposals(
    status: str = Query("all", description="draft | approved | rejected | reverted | all"),
    session: Session = Depends(get_db_session),
):
    from ion.services.de_bob_proposal_service import list_proposals as _list

    return {"proposals": _list(session, status=status)}


@router.get("/bob-proposals/{proposal_id}", dependencies=[Depends(require_permission("de:read"))])
def get_bob_proposal(proposal_id: int, session: Session = Depends(get_db_session)):
    from ion.services.de_bob_proposal_service import get_proposal as _get

    p = _get(session, proposal_id)
    if p is None:
        raise HTTPException(status_code=404, detail="proposal not found")
    return p


@router.post("/bob-proposals/draft", dependencies=[Depends(require_permission("de:propose"))])
def draft_bob_proposal(payload: BobDraftRequest, session: Session = Depends(get_db_session)):
    """Deterministic scaffold for a disagreement class (unsaved)."""
    from ion.services.de_bob_proposal_service import draft_from_feedback

    draft = draft_from_feedback(session, payload.rule_name, payload.bob_verdict,
                                payload.human_verdict, days=payload.days)
    if draft is None:
        raise HTTPException(status_code=404, detail="no such disagreement class in the window")
    return draft


@router.post("/bob-proposals", dependencies=[Depends(require_permission("de:propose"))])
def create_bob_proposal(
    payload: BobProposalCreate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    from ion.services.de_bob_proposal_service import create_proposal as _create

    try:
        p = _create(session, payload.model_dump(), current_user.id)
    except ValueError as e:
        _bob_err(e)
    logger.info("Bob-tuning proposal %d created by user %s", p.id, current_user.id)
    return p.to_dict()


@router.patch("/bob-proposals/{proposal_id}", dependencies=[Depends(require_permission("de:propose"))])
def update_bob_proposal(
    proposal_id: int,
    payload: BobProposalUpdate,
    session: Session = Depends(get_db_session),
):
    from ion.services.de_bob_proposal_service import update_proposal as _update

    try:
        p = _update(session, proposal_id, payload.model_dump(exclude_unset=True))
    except ValueError as e:
        _bob_err(e)
    return p.to_dict()


@router.post("/bob-proposals/{proposal_id}/approve", dependencies=[Depends(require_permission("de:approve"))])
def approve_bob_proposal(
    proposal_id: int,
    payload: DecisionRequest,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Approve + apply to the live template. SoD: approver must differ from drafter."""
    from ion.services.de_bob_proposal_service import approve_proposal as _approve

    try:
        p = _approve(session, proposal_id, current_user.id, notes=payload.notes)
    except ValueError as e:
        _bob_err(e)
    logger.info("Bob-tuning proposal %d APPROVED+applied by user %s", proposal_id, current_user.id)
    return p.to_dict()


@router.post("/bob-proposals/{proposal_id}/reject", dependencies=[Depends(require_permission("de:approve"))])
def reject_bob_proposal(
    proposal_id: int,
    payload: DecisionRequest,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    from ion.services.de_bob_proposal_service import reject_proposal as _reject

    try:
        p = _reject(session, proposal_id, current_user.id, notes=payload.notes)
    except ValueError as e:
        _bob_err(e)
    return p.to_dict()


@router.post("/bob-proposals/{proposal_id}/revert", dependencies=[Depends(require_permission("de:approve"))])
def revert_bob_proposal(
    proposal_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Roll back an approved change — restores the snapshotted template text."""
    from ion.services.de_bob_proposal_service import revert_proposal as _revert

    try:
        p = _revert(session, proposal_id, current_user.id)
    except ValueError as e:
        _bob_err(e)
    logger.info("Bob-tuning proposal %d reverted by user %s", proposal_id, current_user.id)
    return p.to_dict()


# ── §4 control #7 — abuse monitor (oversight, read-only) ─────────────────────
# The detective control over the DE module: flags two-person collusion, high-
# volume actors, and blanket-scope quirks that the preventive controls allow.
# Gated de:verify — the oversight tier, not the raise/propose tier.


@router.get("/abuse-scan", dependencies=[Depends(require_permission("de:verify"))])
def de_abuse_scan(
    days: int = Query(90, ge=1, le=365, description="Lookback window in days"),
    session: Session = Depends(get_db_session),
):
    """Read-only scan for DE abuse patterns (collusion / volume / blanket scope).

    Reports only — mutates nothing. For an oversight reviewer to triage.
    """
    from ion.services.de_abuse_service import scan_abuse

    return scan_abuse(session, days=days)
