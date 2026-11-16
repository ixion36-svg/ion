"""The morning briefing, composed on the server as one fragment."""
from __future__ import annotations

import json
import logging
from datetime import datetime

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.storage.database import get_db_session
from ion.web.ui._shared import templates

logger = logging.getLogger(__name__)

router = APIRouter()

FRAGMENT = "_fragments/briefing.html"


def _fmt_generated(iso: object) -> str:
    """`generated_at` as a readable stamp that names its zone.

    build_briefing stores `datetime.utcnow().isoformat()`, which carries no
    offset. The JavaScript this replaces did `new Date(iso).toLocaleString()`,
    and a browser reads an offset-less ISO string as *local* time, so the
    "Generated" line was wrong by the viewer's UTC offset and said nothing
    about which zone it meant. Naming the zone is half the point of moving
    the formatting here.

    A value that will not parse is shown as-is, which is what the old
    try/catch did: a visible oddity beats a blank that reads as "never".
    """
    if not iso:
        return "-"
    try:
        return datetime.fromisoformat(str(iso)).strftime("%Y-%m-%d %H:%M UTC")
    except (TypeError, ValueError):
        return str(iso)


def _top_rules(raw: object, limit: int = 6) -> list[dict]:
    """The top firing rules, flattened to a name and a count.

    _collect_es reads `top_rules` from whichever of three Elasticsearch keys
    the aggregation returned, so a row arrives as a dict carrying `count`, as
    a dict carrying `doc_count`, or as a bare rule-name string. The
    JavaScript normalised all three inline inside the markup loop. Doing it
    here keeps the template a straight render and makes the shapes testable
    without a template at all.

    A count of 0 stays 0. `(r.count) || (r.doc_count) || ''` turned a rule
    that fired zero times into a blank cell, indistinguishable from a rule
    whose count the aggregation never returned.

    An unexpected row shape keeps the JavaScript's JSON.stringify fallback,
    so it shows as something odd rather than disappearing from the table.
    """
    out: list[dict] = []
    for r in list(raw or [])[:limit]:
        if not isinstance(r, dict):
            out.append({"name": str(r), "count": None})
            continue
        count = r.get("count")
        if count is None:
            count = r.get("doc_count")
        name = r.get("name")
        if name is None:
            name = json.dumps(r, sort_keys=True, default=str)
        out.append({"name": name, "count": count})
    return out


@router.get(
    "/briefing",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission("alert:read"))],
)
async def briefing_fragment(
    request: Request,
    hours: int = Query(12, ge=1, le=168),
    ai: bool = Query(False, description="If true, ask Ollama for a narrative"),
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """The whole briefing as one fragment.

    Replaces three innerHTML writes and 150 lines of inline JavaScript in
    briefing.html, where brfRender built the meta line, the AI narrative
    card, six headline tiles and four source cards out of concatenated
    strings with a hand-rolled brfEsc. Jinja escapes, so brfEsc is gone.

    It calls briefing_service.build_briefing, the same function
    /api/briefing calls, rather than reassembling the snapshot. There is no
    pagination maths or feature gate inline in that JSON route to extract,
    so the service function is already the single definition.

    `alert:read` matches /api/briefing. A fragment must not be a softer way
    in than the API it mirrors.

    The window select and the three buttons stay in the page shell, outside
    the swap target, so no response can swap away the controls that request
    the next one. `hours` is passed in separately because the failure branch
    still has to name the window it could not compose, and the payload is
    None in exactly that case.
    """
    from ion.services import briefing_service

    try:
        b = await briefing_service.build_briefing(session, hours=hours, ai=ai)
    except Exception:
        logger.exception("Briefing fragment could not be composed")
        # A failed compose is not a quiet shift. /api/briefing answers 500
        # here; a fragment has to render, so it renders the distinction and
        # prints no figures, because a grid of zeros reads as "nothing
        # happened overnight" and leads to the opposite action.
        return templates.TemplateResponse(
            request=request,
            name=FRAGMENT,
            context={"b": None, "failed": True, "hours": hours,
                     "generated_at": "-", "top_rules": []},
            status_code=200,
        )

    return templates.TemplateResponse(
        request=request,
        name=FRAGMENT,
        context={
            "b": b,
            "failed": False,
            "hours": hours,
            "generated_at": _fmt_generated(b.get("generated_at")),
            "top_rules": _top_rules((b.get("es") or {}).get("top_rules")),
        },
    )
