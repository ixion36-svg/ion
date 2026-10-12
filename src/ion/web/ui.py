"""Server-rendered HTML fragments for htmx.

The redesign's `server` column passes when a template contains no
`innerHTML`. The reason is not taste: a thing built from strings in
JavaScript cannot be restyled from markup, so every such site is a place a
sweep of the stylesheet silently fails to reach. 1,033 of them remain across
the tree.

This router is where the replacements live. A page keeps its shell in its own
template and pulls its data-driven parts from `/ui/...` with `hx-get`, so the
markup has one definition, in Jinja, on the server.

Why `/ui` and not `/api`:

  * `/api` is a JSON contract. Other things consume it, including the MCP
    surface and the tests, and adding HTML responses to it would make
    "what does this endpoint return" depend on the caller.
  * A fragment is a view, versioned with the template it belongs to, not
    with the API.

Why `require_permission` rather than `require_page_permission`: the page
dependency redirects to /login when a session has expired, and htmx would
swap a login page into the middle of a dashboard. A 403 is not swapped by
default, so the stale content stays and the user sees no lie.

Each endpoint reuses the same service function its JSON counterpart calls,
so the two cannot drift apart.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.storage.database import get_db_session
from ion.web.templating import make_templates

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ui", tags=["ui-fragments"])


def _systems_display(raw: object, limit: int = 3) -> str:
    """The first few system names from a JSON-encoded list.

    `systems` is stored as a JSON string. The JavaScript this replaces did
    `JSON.parse(a.systems||'[]').slice(0,3).join(', ')` inside a try/catch
    that fell back to the raw string, so a row with malformed JSON showed
    the raw value rather than breaking the table. Same behaviour here: a
    value that will not parse is shown as-is, because a visible oddity beats
    a blank cell that looks like "no systems".
    """
    if not raw:
        return ""
    if isinstance(raw, (list, tuple)):
        return ", ".join(str(x) for x in list(raw)[:limit])
    try:
        import json

        parsed = json.loads(raw)
    except (TypeError, ValueError):
        return str(raw)
    if isinstance(parsed, (list, tuple)):
        return ", ".join(str(x) for x in list(parsed)[:limit])
    return str(parsed)

# The shared Jinja env from the factory (bytecode cache, ion_version,
# csp_nonce). Importing server.templates would loop.
templates = make_templates()


@router.get(
    "/service-accounts",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission("alert:read"))],
)
def service_accounts_fragment(
    request: Request,
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """The risk summary and the account table, as one fragment.

    service_accounts.html used to fetch /api/service-accounts and
    /api/service-accounts/risk-summary in parallel and build both with
    innerHTML, 55 lines of string concatenation including a hand-rolled
    `esc()`. One request renders both here, and Jinja escapes.
    """
    from ion.services.service_account_service import (
        get_account_risk_summary,
        get_service_accounts,
    )

    try:
        accounts = [dict(a) for a in get_service_accounts(session)]
        summary = get_account_risk_summary(session)
        for a in accounts:
            a["systems_display"] = _systems_display(a.get("systems"))
    except Exception:
        logger.exception("Service account fragment could not be rendered")
        # A failed read is not an empty estate. The fragment says which it
        # is, because "no service accounts" and "we could not look" lead to
        # opposite actions.
        return templates.TemplateResponse(
            request=request,
            name="_fragments/service_accounts.html",
            context={"accounts": None, "summary": None, "failed": True},
            status_code=200,
        )

    return templates.TemplateResponse(
        request=request,
        name="_fragments/service_accounts.html",
        context={"accounts": accounts, "summary": summary, "failed": False},
    )


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
