"""Case Similarity API — find similar past cases."""

import logging
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from ion.auth.dependencies import require_permission
from ion.web.api import get_db_session

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/case-similarity", tags=["case-similarity"])


@router.get("/{case_id}", dependencies=[Depends(require_permission("case:read"))])
def get_similar_cases(
    case_id: int,
    limit: int = Query(10, ge=1, le=50),
    session: Session = Depends(get_db_session),
):
    """Find cases similar to the given case."""
    from ion.services.case_similarity_service import find_similar_cases
    return find_similar_cases(session, case_id=case_id, limit=limit)
