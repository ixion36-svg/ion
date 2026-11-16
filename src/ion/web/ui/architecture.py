"""The architecture diagram's rings, nodes and workflow links, as one fragment.

architecture.html described ION's own topology in three JavaScript array
constants and then built each node's card with `innerHTML`, mapping a Lucide
icon name to an `icon-*` class in a fourth constant on the way. The whole
diagram was therefore unreachable from the stylesheet, which is what the
redesign's `server` column measures.

This module is the one definition of that topology. The fragment emits the
node cards and the ring labels as markup and the workflow links as
`data-from`/`data-to` elements, so the page's remaining JavaScript does
geometry only: it positions elements that already exist and draws the SVG
lines between them with `createElementNS`.

Unlike the other conversions there is no JSON endpoint to share a service
function with. `/architecture` is a static page in server.py's `_PAGES`
table and its JavaScript fetched nothing; `/api/admin/architecture-health`
exists but has no caller and reads log-derived health, not topology. So the
permission matched here is the page's own entry in that table,
`security:read`, applied through `require_permission` rather than
`require_page_permission` so an expired session gets a 403 instead of a
login form swapped into the diagram.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse

from ion.auth.dependencies import require_permission
from ion.web.ui._shared import templates

logger = logging.getLogger(__name__)

router = APIRouter()

#: Lucide icon name -> ION `icon-*` class. Resolved here so the fragment
#: emits a finished class name and the browser never maps one to markup.
_ICON_CLASSES = {
    "bell": "icon-bell",
    "bell-ring": "icon-bell-ring",
    "book-open": "icon-book-open",
    "bot": "icon-bot",
    "brain": "icon-brain",
    "database": "icon-database",
    "eye": "icon-eye",
    "file-scan": "icon-file-text",
    "file-text": "icon-file-text",
    "folder-open": "icon-folder",
    "git-merge": "icon-git-merge",
    "globe": "icon-globe",
    "graduation-cap": "icon-graduation-cap",
    "layout-dashboard": "icon-layout-dashboard",
    "lock": "icon-lock",
    "message-circle": "icon-message-circle",
    "route": "icon-git-branch",
    "scroll-text": "icon-scroll-text",
    "search": "icon-search",
    "shield": "icon-shield",
    "shield-check": "icon-shield-check",
}

#: What an unmapped icon name renders as, matching the JavaScript's
#: `ICON_MAP[name] || 'icon-circle'`.
FALLBACK_ICON = "icon-circle"

_HUB_ID = "hub"


def icon_class(lucide_name: str) -> str:
    """The ION `icon-*` class for a Lucide icon name.

    The JavaScript's `getIconClass`. An unmapped name falls back rather than
    rendering an empty class, so a new node with a name nobody mapped shows a
    plain circle instead of an iconless card that reads as a render bug.
    """
    return _ICON_CLASSES.get(lucide_name, FALLBACK_ICON)


@dataclass(frozen=True)
class Node:
    """One module or external service, with its icon class already resolved."""

    id: str
    name: str
    icon: str


@dataclass(frozen=True)
class Ring:
    """One concentric ring of nodes, with the geometry its label implies.

    The radius numbers live here rather than in the page's JavaScript so
    that "which rings exist" has a single answer. With the ring set in Python
    and the radii in JavaScript, adding a ring meant editing both and a
    mismatch left its nodes stacked at the container's origin.

    `angle_offset` is 0 for the core ring. That is a measured offset, not a
    missing one, which is why the fragment guards every one of these numbers
    with `is not none`: under a truthiness test the core ring would lose its
    attribute and its nodes would be placed at NaN.
    """

    index: int
    label: str
    min_radius: int
    radius_factor: float
    angle_offset: float
    nodes: tuple[Node, ...]


@dataclass(frozen=True)
class Link:
    """A directed edge of a workflow.

    Named `source`/`target` rather than the JavaScript's `from`/`to` because
    `from` is a keyword in both Python and Jinja, so a template could not
    read the attribute at all.
    """

    source: str
    target: str


_RING_SPECS: tuple[tuple[int, str, int, float, float, tuple[tuple[str, str, str], ...]], ...] = (
    (
        1,
        "Core Cluster",
        160,
        0.38,
        0.0,
        (
            ("api", "API Router", "route"),
            ("alerts", "Alerts Engine", "bell"),
            ("cases", "Case Manager", "folder-open"),
            ("observables", "Observables", "eye"),
        ),
    ),
    (
        2,
        "System Services",
        300,
        0.68,
        0.3,
        (
            ("auth", "Auth Service", "lock"),
            ("database", "Storage", "database"),
            ("ai_chat", "AI Analytics", "bot"),
            ("pcap", "PCAP Engine", "file-scan"),
            ("forensics", "Forensics", "search"),
            ("logging", "Logging", "scroll-text"),
            ("security", "Shield", "shield"),
            ("notifications", "Notify", "bell-ring"),
            ("knowledge_base", "Knowledge", "book-open"),
            ("templates", "Templates", "file-text"),
            ("chat", "Team Chat", "message-circle"),
            ("skills", "Training", "graduation-cap"),
        ),
    ),
    (
        3,
        "External Integrations",
        430,
        0.92,
        -0.5,
        (
            ("elasticsearch", "Elasticsearch", "database"),
            ("kibana", "Kibana", "layout-dashboard"),
            ("ollama", "Ollama LLM", "brain"),
            ("gitlab", "GitLab", "git-merge"),
            ("opencti", "OpenCTI", "globe"),
            ("dfir_iris", "DFIR-IRIS", "shield-check"),
        ),
    ),
)

#: Scenario id -> the ordered edges it lights up. Order is load-bearing: the
#: page staggers each packet animation by its index, so reordering changes
#: what the diagram looks like.
_WORKFLOW_LINKS: dict[str, tuple[tuple[str, str], ...]] = {
    "default": (
        (_HUB_ID, "api"), ("api", "auth"), ("api", "database"),
        ("api", "alerts"), ("alerts", "elasticsearch"),
        ("alerts", "cases"), ("cases", "kibana"),
        ("cases", "dfir_iris"), ("observables", "opencti"),
        ("ai_chat", "ollama"), ("security", "api"),
    ),
    "auth": (
        ("api", "security"),
        ("security", "auth"),
        ("auth", "database"),
        ("database", "auth"),
        ("auth", "api"),
    ),
    "detection": (
        ("elasticsearch", "alerts"),
        ("alerts", "api"),
        ("api", "cases"),
        ("cases", "notifications"),
    ),
    "incident": (
        ("cases", "observables"),
        ("observables", "opencti"),
        ("cases", "dfir_iris"),
        ("cases", "forensics"),
    ),
    "ai": (
        ("cases", "ai_chat"),
        ("ai_chat", "ollama"),
        ("ollama", "ai_chat"),
        ("ai_chat", "api"),
    ),
    "infra": (
        ("security", "logging"),
        ("api", "logging"),
        ("logging", "elasticsearch"),
        ("database", "logging"),
    ),
}


def diagram_payload() -> dict:
    """The rings, their nodes and every workflow's links, as one value.

    Separate from the route so the inventory can be asserted directly and so
    a later JSON endpoint has something to call rather than a second copy.
    """
    rings = tuple(
        Ring(
            index=index,
            label=label,
            min_radius=min_radius,
            radius_factor=radius_factor,
            angle_offset=angle_offset,
            nodes=tuple(
                Node(id=nid, name=name, icon=icon_class(icon))
                for nid, name, icon in members
            ),
        )
        for index, label, min_radius, radius_factor, angle_offset, members in _RING_SPECS
    )
    workflows = {
        name: tuple(Link(source=src, target=dst) for src, dst in edges)
        for name, edges in _WORKFLOW_LINKS.items()
    }
    return {"rings": rings, "workflows": workflows, "hub_id": _HUB_ID}


@router.get(
    "/architecture/diagram",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission("security:read"))],
)
def architecture_diagram_fragment(request: Request) -> HTMLResponse:
    """The diagram's nodes, ring labels and workflow links.

    The error branch is not decoration. The payload is the only description
    of the topology the browser gets, so a build that raises would otherwise
    swap in an empty container, and an empty container on this page reads as
    "ION has no modules and nothing is connected" rather than "we could not
    describe it". The fragment says which, and offers a retry, because the
    page's own status badge is outside the swap.
    """
    try:
        payload = diagram_payload()
    except Exception:
        logger.exception("Architecture diagram fragment could not be rendered")
        payload = None

    return templates.TemplateResponse(
        request=request,
        name="_fragments/architecture_diagram.html",
        context={"payload": payload},
    )
