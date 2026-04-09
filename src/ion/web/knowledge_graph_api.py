"""Knowledge Graph API."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.core.safe_errors import safe_error
from ion.services import knowledge_graph_service
from ion.web.api import get_db_session

router = APIRouter(prefix="/knowledge-graph", tags=["knowledge-graph"])


@router.get("", dependencies=[Depends(require_permission("alert:read"))])
def graph_endpoint(
    case_limit: int = Query(50, ge=1, le=300),
    include_closed: bool = False,
    seed: Optional[str] = Query(None, description="Optional observable value to seed the subgraph"),
    session: Session = Depends(get_db_session),
):
    """Build a knowledge graph from cases / alerts / observables / TTPs."""
    try:
        return knowledge_graph_service.build_graph(
            session,
            case_limit=case_limit,
            include_closed=include_closed,
            seed_value=seed,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=safe_error(e, "knowledge_graph"))
