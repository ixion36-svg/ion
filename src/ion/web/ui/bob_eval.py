"""One page of BOB eval samples, rows and pager together."""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.storage.database import get_db_session
from ion.web.ui._shared import templates

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get(
    "/bob-eval/samples",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission("system:settings"))],
)
def bob_eval_samples_fragment(
    request: Request,
    run_id: int = Query(...),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """One page of eval samples, rows and pager together.

    Replaces four innerHTML sites in bob_eval.html, three of them `+=`.
    The pager links in the fragment are hx-gets back here, so paging needs
    no JavaScript and there is one definition of a sample row.

    It calls bob_eval_api.samples_payload, the same function the JSON
    endpoint calls, rather than repeating the pagination maths and the
    ION_BOB_STORE_REASONING gate. Those are precisely the pair that drifts:
    one copy would keep emitting reasoning text after the flag flipped.

    `system:settings` matches the JSON endpoint. A fragment must not be a
    softer way in than the API it mirrors.
    """
    from ion.web.bob_eval_api import samples_payload

    try:
        payload = samples_payload(run_id, page, page_size, session)
    except Exception:
        logger.exception("bob-eval samples fragment could not be rendered")
        payload = None

    # run_id goes in separately because the fragment's heading and Close
    # button render in the not-found case too, where payload is None. A
    # dismissable error beats one that strands the panel open.
    return templates.TemplateResponse(
        request=request,
        name="_fragments/bob_eval_samples.html",
        context={"payload": payload, "run_id": run_id},
    )
