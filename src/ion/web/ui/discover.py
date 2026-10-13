"""Discover: the search results table.

Stage one of discover.html. The page has 21 remaining DOM write sites and
this takes the three that are the page: the results table, its header row
and its count badge. The index browser, the field statistics, the IOC hunt
and the saved searches are later stages.

Permissions. Every endpoint this page reads is bare authentication, with no
named permission, while the page route itself is gated on `alert:read`. So
the fragment takes the page's permission: stricter than the endpoint, never
softer, which is the call `ui/analyst.py` documents and the tools
conversion made for the two OpenCTI endpoints. There is a registry for
fragments that deliberately drop to bare auth,
`tests/unit/test_ui_fragment_registry.py`'s BARE_AUTH_FRAGMENTS, and this
is not a case for it: the page already demands more.

What the JavaScript did, measured by reading it:

  * ``header.innerHTML = displayFields.map(f => `<th>${f}</th>`)``. Field
    names are Elasticsearch document keys, which in a log ingest system are
    whatever the logs carried, and they went into the markup unescaped. The
    cells below were escaped with escapeHtml; the headers were not. Jinja
    escapes both by default.

  * `!data.hits || data.hits.length === 0` rendered "No results found", so
    a 200 whose `hits` was not a list said we looked and there were none.

  * ``countBadge.textContent = `${data.total} hits (${data.took_ms}ms)` ``
    printed "undefined hits (undefinedms)" for a payload missing either
    figure, and did it before the shape check, so it printed that even on
    the empty branch.

  * The endpoint tells four failures apart and the page showed one sentence
    for all of them: 400 when Elasticsearch is not enabled, 400 when it is
    not configured, 403 when the index pattern is outside the allowed set,
    and 500 on a search error. "Elasticsearch is not configured" and "that
    query failed" lead to opposite actions, and one of them is not an
    analyst's to fix.

  * A cell whose field was absent from the hit and a cell whose value was
    explicitly null both rendered "-". In log analysis those are different
    facts, and the second one is often the finding.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Optional, TypedDict

from fastapi import APIRouter, Depends, Form, Request, Response
from fastapi.responses import HTMLResponse

from ion.auth.dependencies import get_current_user, require_permission
from ion.models.user import User
from ion.web.ui._shared import plain, render_view

logger = logging.getLogger(__name__)

router = APIRouter()

FRAGMENT = "_fragments/discover_search.html"

#: What the page route requires. The endpoints require only a session.
PERMISSION = "alert:read"

#: The columns worth showing first when the hits carry them, in this order.
#: From the page's own `priorityFields`.
PRIORITY_FIELDS: tuple[str, ...] = (
    "@timestamp", "_index", "message", "host.name", "source.ip",
    "user.name", "event.action",
)

#: How many columns the table aims for, topping up from whatever keys the
#: hits carry. From `if (displayFields.length < 5)`.
COLUMNS = 5

#: How much of a value fits in a cell, as the page sliced it.
CELL_CHARS = 100


class SearchView(TypedDict):
    """`state` is the five answers this read has, not two.

    "data"            hits, and they are in rows
    "empty"           the search ran and matched nothing
    "unconfigured"    Elasticsearch is off or not set up
    "refused"         the index pattern is outside the allowed set
    "failed"          the search ran and did not answer, or answered a
                      shape we could not read
    """

    state: str
    detail: Optional[str]
    fields: list[str]
    rows: list[list[Optional[str]]]
    total: Optional[int]
    took_ms: Optional[int]


def _int(value: Any) -> Optional[int]:
    """An int, or None for anything that is not one.

    bool first, because True is an int in Python and "1 hit" is not what it
    means.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def columns(hits: list) -> list[str]:
    """The columns to show, priority order first then topped up.

    Underscore-prefixed keys are skipped, as the page skipped them, except
    the ones named in PRIORITY_FIELDS: `_index` is the index a hit came
    from and is worth a column.
    """
    keys: list[str] = []
    for hit in hits:
        if not isinstance(hit, dict):
            continue
        for key in hit:
            if isinstance(key, str) and not key.startswith("_") \
                    and key not in keys:
                keys.append(key)
    chosen = [f for f in PRIORITY_FIELDS
              if f in keys or any(isinstance(h, dict) and f in h
                                  for h in hits)]
    for key in keys:
        if len(chosen) >= COLUMNS:
            break
        if key not in chosen:
            chosen.append(key)
    return chosen


def cell(hit: dict, field: str) -> Optional[str]:
    """One cell, or None when the hit does not carry that field.

    None is the fourth outcome in miniature. The page rendered "-" both for
    a field the document did not have and for a field it had set to null,
    and in log analysis the second is often the point.
    """
    if field not in hit:
        return None
    value = hit[field]
    if value is None:
        return "null"
    if isinstance(value, (dict, list)):
        try:
            text = json.dumps(value, default=str)
        except (TypeError, ValueError):
            text = str(value)
    else:
        text = str(value)
    if len(text) > CELL_CHARS:
        return text[:CELL_CHARS] + "..."
    return text


def search_view(payload: Any) -> SearchView:
    """The endpoint's body as the table's model."""
    hits = payload.get("hits") if isinstance(payload, dict) else None
    if not isinstance(hits, list):
        return {
            "state": "failed",
            "detail": "The search answered something this page could not read.",
            "fields": [], "rows": [], "total": None, "took_ms": None,
        }
    total = _int(payload.get("total"))
    took = _int(payload.get("took_ms"))
    readable = [h for h in hits if isinstance(h, dict)]
    if not readable:
        return {
            "state": "failed" if hits else "empty",
            "detail": ("The search returned rows this page could not read."
                       if hits else None),
            "fields": [], "rows": [], "total": total, "took_ms": took,
        }
    fields = columns(readable)
    return {
        "state": "data",
        "detail": None,
        "fields": fields,
        "rows": [[cell(hit, f) for f in fields] for hit in readable],
        "total": total,
        "took_ms": took,
    }


def failure(status: int, detail: Any) -> SearchView:
    """One of the endpoint's refusals as the table's model.

    400 is Elasticsearch being off or unset, which is not an analyst's to
    fix and should not read as a failed query. 403 is the index pattern
    being outside the allowed set, which is a refusal and not a failure.
    """
    text = str(detail) if detail else None
    if status == 400:
        state = "unconfigured"
    elif status == 403:
        state = "refused"
    else:
        state = "failed"
    return {"state": state, "detail": text, "fields": [], "rows": [],
            "total": None, "took_ms": None}


@router.post(
    "/discover/search",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))],
)
async def discover_search_fragment(
    request: Request,
    index_pattern: str = Form("logs-*"),
    query: str = Form("*"),
    time_field: str = Form("@timestamp"),
    time_from: str = Form("now-24h"),
    time_to: str = Form("now"),
    size: int = Form(100),
    sort_field: str = Form(""),
    sort_order: str = Form("desc"),
    current_user: User = Depends(get_current_user),
) -> Response:
    """The results table.

    The form field names are the search controls' own names, so the page
    hands them over rather than this route reimplementing the query. The
    endpoint's handler is called directly, so the row a reader sees is the
    row the JSON reports.
    """
    from fastapi import HTTPException

    from ion.web.elasticsearch_api import (
        DiscoverSearchRequest,
        discover_search,
    )

    body = DiscoverSearchRequest(
        index_pattern=index_pattern,
        query=query or "*",
        time_field=time_field,
        time_from=time_from,
        time_to=time_to,
        size=size,
        sort_field=sort_field or None,
        sort_order=sort_order,
    )
    try:
        payload = await discover_search(body, current_user=current_user)
    except HTTPException as refusal:
        view = failure(refusal.status_code, refusal.detail)
    except Exception:
        logger.exception("Discover search fragment could not search")
        view = failure(500, "The search did not complete.")
    else:
        view = search_view(payload)

    return render_view(request, FRAGMENT, view)
