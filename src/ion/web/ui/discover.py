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

from sqlalchemy.orm import Session

from ion.auth.dependencies import get_current_user, require_permission
from ion.models.user import User
from ion.storage.database import get_db_session
from ion.web.ui._shared import instant_label, plain, render_view

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


# ---------------------------------------------------------------------------
# The time histogram
# ---------------------------------------------------------------------------
#
# POST /api/elasticsearch/discover/histogram, drawn as one bar per bucket
# with its height as a percentage of the tallest.
#
#   * ``title="${b.timestamp}: ${b.count} events"`` interpolated an
#     Elasticsearch value into an attribute with no escaping. A timestamp
#     is unlikely to carry a quote, which is what makes it the kind of
#     place that stops being true quietly: the same pattern one field along
#     is a broken attribute.
#   * `total.textContent = `${data.total} total events`` printed "undefined
#     total events" for a payload without one.
#   * `!data.buckets || data.buckets.length === 0` sent a body whose
#     buckets were not a list to "No data for histogram".
#   * `Math.max(...data.buckets.map(b => b.count))` spreads every bucket
#     into an argument list, and a bucket whose count was not a number made
#     every height NaN, so the whole chart rendered as nothing with no
#     error. The maximum is taken over readable counts only.

HISTOGRAM_FRAGMENT = "_fragments/discover_histogram.html"


class HistogramBar(TypedDict):
    """One bucket. `height` is a percentage of the tallest readable bucket,
    and None for a bucket whose count we could not read: that bar is drawn
    as unmeasured rather than as zero."""

    when: Optional[str]
    count: Optional[int]
    height: Optional[float]


class HistogramView(TypedDict):
    state: str
    detail: Optional[str]
    bars: list[HistogramBar]
    total: Optional[int]


def histogram_view(payload: Any) -> HistogramView:
    """The endpoint's body as the chart's model."""
    buckets = payload.get("buckets") if isinstance(payload, dict) else None
    if not isinstance(buckets, list):
        return {
            "state": "failed",
            "detail": "The histogram answered something this page could not read.",
            "bars": [], "total": None,
        }
    total = _int(payload.get("total"))
    if not buckets:
        return {"state": "empty", "detail": None, "bars": [],
                "total": total}

    readable = [b for b in buckets if isinstance(b, dict)]
    counts = [c for c in (_int(b.get("count")) for b in readable)
              if c is not None]
    tallest = max(counts) if counts else 0
    bars: list[HistogramBar] = []
    for bucket in readable:
        count = _int(bucket.get("count"))
        when = plain(bucket.get("timestamp"))
        bars.append({
            "when": str(when) if when is not None else None,
            "count": count,
            "height": (round(count / tallest * 100, 2)
                       if count is not None and tallest > 0 else None),
        })
    if not bars:
        return {
            "state": "failed",
            "detail": "The histogram returned buckets this page could not read.",
            "bars": [], "total": total,
        }
    return {"state": "data", "detail": None, "bars": bars, "total": total}


@router.post(
    "/discover/histogram",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))],
)
async def discover_histogram_fragment(
    request: Request,
    index_pattern: str = Form("logs-*"),
    query: str = Form("*"),
    time_field: str = Form("@timestamp"),
    time_from: str = Form("now-24h"),
    time_to: str = Form("now"),
    interval: str = Form("1h"),
    current_user: User = Depends(get_current_user),
) -> Response:
    """The time histogram."""
    from fastapi import HTTPException

    from ion.web.elasticsearch_api import (
        DiscoverHistogramRequest,
        discover_histogram,
    )

    body = DiscoverHistogramRequest(
        index_pattern=index_pattern,
        query=query or "*",
        time_field=time_field,
        time_from=time_from,
        time_to=time_to,
        interval=interval,
    )
    try:
        payload = await discover_histogram(body, current_user=current_user)
    except HTTPException as refusal:
        view: HistogramView = {
            "state": failure(refusal.status_code, refusal.detail)["state"],
            "detail": str(refusal.detail) if refusal.detail else None,
            "bars": [], "total": None,
        }
    except Exception:
        logger.exception("Discover histogram fragment could not read")
        view = {"state": "failed",
                "detail": "The histogram did not complete.",
                "bars": [], "total": None}
    else:
        view = histogram_view(payload)

    return render_view(request, HISTOGRAM_FRAGMENT, view)


# ---------------------------------------------------------------------------
# IOC hunt
# ---------------------------------------------------------------------------
#
# POST /api/elasticsearch/ioc-hunt: one indicator across every index, with
# a summary, the indices it was found in, and the hits.
#
# The details column has a live rendering bug, not just an escaping one.
# The page built it as
#
#     `<strong>${k}:</strong> ${v}`
#
# joined with " | ", and then wrote `escapeHtml(details.substring(0, 200))`.
# escapeHtml runs over the finished markup, so the <strong> tags are
# escaped too and the cell shows the literal text `<strong>host.name:</strong>
# web-01` to the analyst. The escaping does neutralise an injected value,
# by accident, at the cost of the formatting it was meant to keep.
#
# Four values went in unescaped alongside it: `${data.ioc_type}` in the
# summary, `${i.index}` in the indices badges, and `${hit['@timestamp']}`
# and `${hit._index}` in the rows. Index names come from Elasticsearch.
#
# Also: `${data.total} hits`, `${data.total}` and `${data.took_ms}ms` all
# printed "undefined" for a payload missing them, and `data.hits.length`
# threw on a body whose hits were not a list, which the caller's catch
# turned into a toast.

IOC_FRAGMENT = "_fragments/discover_ioc_hunt.html"

#: How many fields of a hit the details column summarises, and how much of
#: the result fits, as the page sliced them.
IOC_DETAIL_FIELDS = 5
IOC_DETAIL_CHARS = 200


class IOCDetail(TypedDict):
    """One `key: value` pair of the details column, kept as two values so
    the template can emphasise the key without building markup first."""

    field: str
    value: str


class IOCHit(TypedDict):
    when: Optional[str]
    index: Optional[str]
    details: list[IOCDetail]


class IOCIndex(TypedDict):
    index: Optional[str]
    count: Optional[int]


class IOCHuntView(TypedDict):
    state: str
    detail: Optional[str]
    ioc_value: Optional[str]
    ioc_type: Optional[str]
    total: Optional[int]
    took_ms: Optional[int]
    indices: list[IOCIndex]
    hits: list[IOCHit]


def ioc_details(hit: dict) -> list[IOCDetail]:
    """The first few fields of a hit, as pairs.

    Underscore keys and @timestamp are skipped, as the page skipped them,
    because both have their own column.
    """
    out: list[IOCDetail] = []
    for key, value in hit.items():
        if len(out) >= IOC_DETAIL_FIELDS:
            break
        if not isinstance(key, str) or key.startswith("_") \
                or key == "@timestamp":
            continue
        if isinstance(value, (dict, list)):
            try:
                text = json.dumps(value, default=str)
            except (TypeError, ValueError):
                text = str(value)
        else:
            text = str(value)
        out.append({"field": key, "value": text[:IOC_DETAIL_CHARS]})
    return out


def ioc_hunt_view(payload: Any) -> IOCHuntView:
    """The endpoint's body as the panel's model."""
    hits = payload.get("hits") if isinstance(payload, dict) else None
    if not isinstance(hits, list):
        return {
            "state": "failed",
            "detail": "The hunt answered something this page could not read.",
            "ioc_value": None, "ioc_type": None, "total": None,
            "took_ms": None, "indices": [], "hits": [],
        }
    value = plain(payload.get("ioc_value"))
    kind = plain(payload.get("ioc_type"))
    found = payload.get("indices_found")
    indices: list[IOCIndex] = []
    for entry in (found if isinstance(found, list) else []):
        if not isinstance(entry, dict):
            continue
        name = plain(entry.get("index"))
        indices.append({
            "index": str(name) if name is not None else None,
            "count": _int(entry.get("count")),
        })
    rows = [
        {
            "when": (str(plain(h.get("@timestamp")))
                     if plain(h.get("@timestamp")) is not None else None),
            "index": (str(plain(h.get("_index")))
                      if plain(h.get("_index")) is not None else None),
            "details": ioc_details(h),
        }
        for h in hits if isinstance(h, dict)
    ]
    return {
        "state": "data" if rows else ("failed" if hits else "empty"),
        "detail": ("The hunt returned rows this page could not read."
                   if hits and not rows else None),
        "ioc_value": str(value) if value is not None else None,
        "ioc_type": str(kind) if kind is not None else None,
        "total": _int(payload.get("total")),
        "took_ms": _int(payload.get("took_ms")),
        "indices": indices,
        "hits": rows,
    }


@router.post(
    "/discover/ioc-hunt",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))],
)
async def discover_ioc_hunt_fragment(
    request: Request,
    ioc_value: str = Form(""),
    ioc_type: str = Form(""),
    index_pattern: str = Form("*,-.*"),
    time_field: str = Form("@timestamp"),
    time_from: str = Form("now-30d"),
    time_to: str = Form("now"),
    size: int = Form(100),
    current_user: User = Depends(get_current_user),
) -> Response:
    """One indicator, hunted across the indices."""
    from fastapi import HTTPException

    from ion.web.elasticsearch_api import IOCHuntRequest, ioc_hunt

    if not ioc_value.strip():
        # An empty box is a bad request, not a hunt that found nothing.
        view: IOCHuntView = {
            "state": "failed", "detail": "Enter an indicator to hunt for.",
            "ioc_value": None, "ioc_type": None, "total": None,
            "took_ms": None, "indices": [], "hits": [],
        }
        return render_view(request, IOC_FRAGMENT, view, status_code=422)

    body = IOCHuntRequest(
        ioc_value=ioc_value.strip(),
        ioc_type=ioc_type or None,
        index_pattern=index_pattern,
        time_field=time_field,
        time_from=time_from,
        time_to=time_to,
        size=size,
    )
    try:
        payload = await ioc_hunt(body, current_user=current_user)
    except HTTPException as refusal:
        view = {
            "state": failure(refusal.status_code, refusal.detail)["state"],
            "detail": str(refusal.detail) if refusal.detail else None,
            "ioc_value": ioc_value.strip(), "ioc_type": ioc_type or None,
            "total": None, "took_ms": None, "indices": [], "hits": [],
        }
    except Exception:
        logger.exception("Discover IOC hunt fragment could not hunt")
        view = {
            "state": "failed", "detail": "The hunt did not complete.",
            "ioc_value": ioc_value.strip(), "ioc_type": ioc_type or None,
            "total": None, "took_ms": None, "indices": [], "hits": [],
        }
    else:
        view = ioc_hunt_view(payload)

    return render_view(request, IOC_FRAGMENT, view)


# ---------------------------------------------------------------------------
# Bulk IOC hunt
# ---------------------------------------------------------------------------
#
# POST /api/elasticsearch/ioc-hunt/bulk, one row per indicator.
#
#   * ``data-args='["${escapeHtml(r.ioc_value)}"]'``. This is the fourth
#     shape of the same defect. escapeHtml turns a `"` into `&quot;`, which
#     inside a JSON string is the literal six characters, so JSON.parse
#     reads a different indicator than the one on screen; and a value
#     containing `'` closes the attribute. An indicator is attacker-supplied
#     by definition: it is the thing being hunted.
#   * `${r.ioc_type}`, `${r.hit_count}` and the joined indices went in
#     unescaped.
#   * `data.results.map` threw on a body whose results were not a list, and
#     `r.indices.slice` threw on a row whose indices were not, both of
#     which the caller's catch turned into a toast.
#   * `${data.found_count}/${data.total_searched} found` printed
#     "undefined/undefined found".

BULK_FRAGMENT = "_fragments/discover_ioc_bulk.html"

#: How many index names a row lists before "...".
BULK_INDICES_SHOWN = 3


class BulkRow(TypedDict):
    value: Optional[str]
    kind: Optional[str]
    found: Optional[bool]
    hits: Optional[int]
    indices: list[str]
    more: int


class BulkView(TypedDict):
    state: str
    detail: Optional[str]
    searched: Optional[int]
    found: Optional[int]
    not_found: Optional[int]
    rows: list[BulkRow]


def bulk_row(raw: Any) -> Optional[BulkRow]:
    """One indicator's result, or None for an entry that is not a mapping."""
    if not isinstance(raw, dict):
        return None
    value = plain(raw.get("ioc_value"))
    kind = plain(raw.get("ioc_type"))
    found = raw.get("found")
    names = raw.get("indices")
    listed = [str(n) for n in names[:BULK_INDICES_SHOWN]] \
        if isinstance(names, list) else []
    return {
        "value": str(value) if value is not None else None,
        "kind": str(kind) if kind is not None else None,
        # Not truthiness: a row that did not say whether it was found is
        # not a row that was not found.
        "found": found if isinstance(found, bool) else None,
        "hits": _int(raw.get("hit_count")),
        "indices": listed,
        "more": (max(0, len(names) - BULK_INDICES_SHOWN)
                 if isinstance(names, list) else 0),
    }


def bulk_view(payload: Any) -> BulkView:
    """The endpoint's body as the table's model."""
    results = payload.get("results") if isinstance(payload, dict) else None
    if not isinstance(results, list):
        return {
            "state": "failed",
            "detail": "The bulk hunt answered something this page could not read.",
            "searched": None, "found": None, "not_found": None, "rows": [],
        }
    rows = [r for r in (bulk_row(r) for r in results) if r is not None]
    return {
        "state": "data" if rows else ("failed" if results else "empty"),
        "detail": ("The bulk hunt returned rows this page could not read."
                   if results and not rows else None),
        "searched": _int(payload.get("total_searched")),
        "found": _int(payload.get("found_count")),
        "not_found": _int(payload.get("not_found_count")),
        "rows": rows,
    }


@router.post(
    "/discover/ioc-hunt/bulk",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))],
)
async def discover_ioc_bulk_fragment(
    request: Request,
    ioc_values: str = Form(""),
    index_pattern: str = Form("*,-.*"),
    time_from: str = Form("now-30d"),
    time_to: str = Form("now"),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Many indicators at once. `ioc_values` arrives newline separated, as
    the textarea holds it."""
    from fastapi import HTTPException

    from ion.web.elasticsearch_api import IOCHuntBulkRequest, ioc_hunt_bulk

    values = [line.strip() for line in ioc_values.splitlines()
              if line.strip()]
    if not values:
        view: BulkView = {
            "state": "failed",
            "detail": "Enter at least one indicator to hunt for.",
            "searched": None, "found": None, "not_found": None, "rows": [],
        }
        return render_view(request, BULK_FRAGMENT, view, status_code=422)

    body = IOCHuntBulkRequest(
        ioc_values=values,
        index_pattern=index_pattern,
        time_from=time_from,
        time_to=time_to,
    )
    try:
        payload = await ioc_hunt_bulk(body, current_user=current_user)
    except HTTPException as refusal:
        view = {
            "state": failure(refusal.status_code, refusal.detail)["state"],
            "detail": str(refusal.detail) if refusal.detail else None,
            "searched": None, "found": None, "not_found": None, "rows": [],
        }
    except Exception:
        logger.exception("Discover bulk IOC fragment could not hunt")
        view = {"state": "failed",
                "detail": "The bulk hunt did not complete.",
                "searched": None, "found": None, "not_found": None,
                "rows": []}
    else:
        view = bulk_view(payload)

    return render_view(request, BULK_FRAGMENT, view)


# ---------------------------------------------------------------------------
# Saved searches
# ---------------------------------------------------------------------------
#
# GET /api/saved-searches returns what this account may see: its own, plus
# the shared ones. The page then split them into three lists in the
# browser, which needed it to know who it was, so it fetched /api/auth/me
# and kept the id in getCurrentUserId(). The server knows.
#
# That split was also wrong. `mine` was
#
#     s => !s.is_shared || s.created_by_id === getCurrentUserId()
#
# so an unshared search belonging to somebody else landed in "My
# searches". The repository is not expected to return one, which is what
# made it survive: a filter that is wrong only about rows you should not
# have is a filter nobody notices until the day you have them.
#
# Three more:
#
#   * `new Date(s.last_executed_at).toLocaleDateString()` over isoformat()
#     of a naive UTC column, so the date was read in the viewer's zone.
#     Fifth page with this one.
#   * `${search.execution_count} runs` printed "undefined runs".
#   * `${search.created_by_username || 'Unknown'}` put a username into
#     markup unescaped.

SAVED_FRAGMENT = "_fragments/discover_saved_searches.html"


class SavedSearch(TypedDict):
    id: Any
    name: Optional[str]
    shared: bool
    favorite: bool
    runs: Optional[int]
    last_run: Optional[str]
    owner: Optional[str]
    mine: bool


class SavedSearchesView(TypedDict):
    """Three buckets and a state. `state` is "failed" when the read did not
    answer or answered a shape we could not read, which is not the same as
    an account with no saved searches."""

    state: str
    favorites: list[SavedSearch]
    mine: list[SavedSearch]
    shared: list[SavedSearch]


def saved_search(raw: Any, user_id: Any) -> Optional[SavedSearch]:
    if not isinstance(raw, dict):
        return None
    ident = raw.get("id")
    if ident is None:
        return None
    name = plain(raw.get("name"))
    owner = plain(raw.get("created_by_username"))
    created_by = raw.get("created_by_id")
    return {
        "id": ident,
        "name": str(name) if name is not None else None,
        "shared": raw.get("is_shared") is True,
        "favorite": raw.get("is_favorite") is True,
        "runs": _int(raw.get("execution_count")),
        "last_run": instant_label(raw.get("last_executed_at")),
        "owner": str(owner) if owner is not None else None,
        "mine": created_by is not None and created_by == user_id,
    }


def saved_searches_view(payload: Any, user_id: Any) -> SavedSearchesView:
    """The endpoint's body as the three lists.

    The split is by ownership, which the server knows: a search is mine, or
    it is somebody else's and shared with me. There is no third case, and
    the page's filter put one there.
    """
    rows = payload.get("saved_searches") if isinstance(payload, dict) \
        else None
    if not isinstance(rows, list):
        return {"state": "failed", "favorites": [], "mine": [],
                "shared": []}
    items = [s for s in (saved_search(r, user_id) for r in rows)
             if s is not None]
    return {
        "state": "data",
        "favorites": [s for s in items if s["favorite"]],
        "mine": [s for s in items if s["mine"]],
        "shared": [s for s in items if not s["mine"] and s["shared"]],
    }


@router.get(
    "/discover/saved-searches",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))],
)
def discover_saved_searches_fragment(
    request: Request,
    search_type: str = "discover",
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> Response:
    """The three saved-search lists."""
    try:
        from ion.web.api import list_saved_searches

        payload = list_saved_searches(
            search_type=search_type,
            favorites_only=False,
            current_user=current_user,
            session=session,
        )
    except Exception:
        logger.exception("Discover fragment could not list saved searches")
        payload = None

    view = saved_searches_view(
        payload, getattr(current_user, "id", None))
    return render_view(request, SAVED_FRAGMENT, view)
