"""The knowledge graph's meta bar, legend, states and node details.

knowledge_graph.html built six pieces of markup from strings in the browser:
the canvas loading overlay, the canvas error overlay, the `#kg-meta` counts
and legend, the "no data to graph" overlay, the selected node's detail card,
and the detail panel's placeholder line. Every rule frontend/ion-pages.css
carries for `.kg-legend`, `.kg-legend-item`, `.kg-legend-dot`, `.kg-loading`,
`#kg-meta strong`, `.kg-detail h3`, `.kg-detail-meta` and `.kg-detail-link`
was therefore unreachable from the stylesheet, which is what the redesign's
`server` column measures. Two of those CSS blocks say so in a comment.

What stays in the browser is the graph itself. vis-network consumes nodes and
edges as JavaScript objects with nested colour and shape, and `/api/knowledge-graph`
already exists to hand them over, so the page keeps fetching it. Physics,
stabilisation and hit-testing are the library's, and the selection a click
produces is only known in the browser. This module renders the markup that
selection reveals, and the page toggles a class rather than assembling a card.

The permission is `alert:read`, which is what `/api/knowledge-graph` carries on
its own route decorator, applied through `require_permission` so an expired
session gets a 403 rather than a login form swapped into the page.

One cost worth naming: the fragment and the page's JSON fetch each call
`build_graph`, so a refresh reads twice. Carrying the nodes and edges in this
fragment instead would halve it, and would mean reimplementing in Jinja and
`data-` attributes the payload the JSON endpoint is for. The read is bounded
by `case_limit`, and the alternative puts a rendering library's input through a
template, so the duplicate read is the cheaper of the two.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.services import knowledge_graph_service
from ion.storage.database import get_db_session
from ion.web.ui._shared import plain, templates

logger = logging.getLogger(__name__)

router = APIRouter()

FRAGMENT = "_fragments/knowledge_graph.html"

#: Legend order, and only the order. Membership is not a filter: a type the
#: stats name that is missing from here is appended by `legend_entries`, so a
#: node type the service grows cannot be counted in the totals and left out of
#: the legend beside them. The pre-change JavaScript hard-coded its list and
#: iterated that instead of the counts, which is how a new type would have gone
#: missing. "actor" is here because the service carries a colour and a shape
#: for it; nothing in build_graph emits one today, so this is where it lands if
#: that changes rather than a defect being repaired.
LEGEND_ORDER = ("case", "alert", "observable", "host", "user", "technique", "actor")

#: The dot colour for a type the service has no colour for. Mirrors the
#: fallback background in knowledge_graph_service._node, so a new node type
#: renders a grey dot in the legend and a grey node in the graph rather than a
#: legend entry with no dot at all.
FALLBACK_COLOR = "#8b949e"

#: Node field -> the label the detail card gave it, in render order. A table
#: rather than five `if` blocks in the template: the order is the thing that
#: has to match the markup this replaces, and here it is one readable line
#: each instead of being spread across a Jinja block per field.
DETAIL_FIELDS = (
    ("severity", "Severity"),
    ("status", "Status"),
    ("threat_level", "Threat"),
    ("obs_type", None),
)


@dataclass(frozen=True)
class LegendEntry:
    """One type's legend dot, its name and how many nodes carry it."""

    type: str
    count: Optional[int]
    color: str


@dataclass(frozen=True)
class NodeDetail:
    """The detail card for one node.

    `meta` is already ordered and already unwrapped: `status`, `threat_level`
    and the observable's type are `SQLEnum` columns, so a row read through the
    ORM carries the enum member. The JSON endpoint got the string for free
    because FastAPI serialises a str-mixin enum by value; a template would
    render "AlertCaseStatus.OPEN".
    """

    id: str
    label: str
    url: Optional[str]
    meta: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class GraphMarkup:
    """Everything on this page that is markup rather than graph data.

    `has_nodes` is its own field rather than `total_nodes > 0`, because
    `total_nodes` is a count that may be missing and "we did not get a count"
    is not "the graph is empty". The page's empty state is a claim about the
    node list, so it is read off the node list.
    """

    total_nodes: Optional[int]
    total_edges: Optional[int]
    has_nodes: bool
    legend: tuple[LegendEntry, ...]
    details: tuple[NodeDetail, ...]


def _present(value: object) -> Optional[str]:
    """A field's display string, or None if it has nothing to show.

    Used for the detail card's text fields only. An empty string renders as
    "Severity: " with nothing after it, which reads as a broken template, so an
    absent field and a blank one are treated alike. Numbers do not come through
    here: the two counts are guarded with `is not none` in the template,
    because 0 nodes is a measurement and has to render as 0.
    """
    unwrapped = plain(value)
    if unwrapped is None:
        return None
    text = str(unwrapped)
    return text if text else None


def legend_entries(by_type: object) -> tuple[LegendEntry, ...]:
    """A legend dot per node type the graph actually contains.

    A type absent from `by_type` has no nodes and gets no entry, which is what
    the JavaScript's `if (!counts[t]) continue` did. A type present with a
    count of 0 does get one: that is a measured zero, and the same test that
    drops it would drop a type the graph is about to lose its last node of.
    """
    if not isinstance(by_type, dict):
        return ()
    extra = sorted(k for k in by_type if k not in LEGEND_ORDER)
    out = []
    for ntype in (*LEGEND_ORDER, *extra):
        if ntype not in by_type:
            continue
        colors = knowledge_graph_service.NODE_COLORS.get(ntype) or {}
        out.append(
            LegendEntry(
                type=ntype,
                count=by_type[ntype],
                color=colors.get("background") or FALLBACK_COLOR,
            )
        )
    return tuple(out)


def node_details(nodes: object) -> tuple[NodeDetail, ...]:
    """A detail card per node, ready to be revealed by id.

    Every node gets one up front rather than one request per click. A click is
    the commonest thing done on this page and `build_graph` is a multi-table
    read, so a fragment per selection would put that read behind every click.
    The fields here are the same ones the JSON payload the page already
    downloads carries, so this roughly doubles the transfer and removes a
    round trip per node.
    """
    if not isinstance(nodes, list):
        return ()
    out = []
    for node in nodes:
        if not isinstance(node, dict):
            continue
        meta = [("Type", _present(node.get("type")) or "unknown")]
        for key, label in DETAIL_FIELDS:
            shown = _present(node.get(key))
            if shown is None:
                continue
            meta.append((label, shown) if label else ("", shown))
        out.append(
            NodeDetail(
                id=str(node.get("id", "")),
                label=str(node.get("label", "")),
                url=node.get("url"),
                meta=tuple(meta),
            )
        )
    return tuple(out)


def graph_markup(
    session: Session,
    *,
    case_limit: int = 50,
    include_closed: bool = False,
    seed_value: Optional[str] = None,
) -> GraphMarkup:
    """The markup half of one `build_graph` call.

    Calls the same service function `/api/knowledge-graph` calls, with the same
    arguments, so the legend and the graph beside it cannot disagree about what
    the filters mean.
    """
    graph = knowledge_graph_service.build_graph(
        session,
        case_limit=case_limit,
        include_closed=include_closed,
        seed_value=seed_value,
    )
    stats = graph.get("stats") or {}
    nodes = graph.get("nodes")
    return GraphMarkup(
        total_nodes=stats.get("total_nodes"),
        total_edges=stats.get("total_edges"),
        has_nodes=bool(nodes),
        legend=legend_entries(stats.get("by_type")),
        details=node_details(nodes),
    )


@router.get(
    "/knowledge-graph",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission("alert:read"))],
)
def knowledge_graph_fragment(
    request: Request,
    case_limit: int = Query(50, ge=1, le=300),
    include_closed: bool = False,
    seed: Optional[str] = Query(None),
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """The meta bar, the legend, the graph's state and every node's detail card.

    The bounds on `case_limit` are the JSON endpoint's, repeated so the
    fragment is not a way to ask for a bigger read than the API allows.

    A read that raises renders a fragment that says the read failed, with a
    retry in it. An empty graph and an unreadable one lead to opposite actions:
    the first says link some observables, the second says look at the logs.
    Printing the empty state for a failed read would tell an analyst the first
    when the second is true.
    """
    try:
        payload = graph_markup(
            session,
            case_limit=case_limit,
            include_closed=include_closed,
            seed_value=seed,
        )
    except Exception:
        logger.exception("Knowledge graph fragment could not be rendered")
        payload = None

    return templates.TemplateResponse(
        request=request,
        name=FRAGMENT,
        context={"payload": payload},
    )
