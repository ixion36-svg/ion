"""Detection-Engineering metrics API — Phase 0 of the optional DE module.

Read-only measurement endpoints over data ION already collects: false-positive
"Noise Campaigns" grouped by rule and the DE Metrics roll-up (noise trend +
Bob-vs-human agreement). No write path — nothing here mutates detections,
closures or the ledger (roadmap: *ION drafts and measures; the analyst decides
and acts*). Gated ``de:read`` (lead / detection-engineer audience).
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.web.api import get_db_session

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/de", tags=["detection-engineering"])


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
