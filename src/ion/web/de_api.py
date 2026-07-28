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
    status: str = Query("all", description="draft | applied | rejected | all"),
    session: Session = Depends(get_db_session),
):
    from ion.services.de_proposal_service import list_proposals as _list

    return {"proposals": _list(session, status=status)}


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
