"""The group-membership ingestion flow, as one server-rendered fragment.

data_flow.html described two whole ingestion pipelines in JavaScript
constants and then built every panel on the page out of strings: the Event
Viewer mock-up, the Kibana end-state panel in both its table and JSON
views, the code block, and the two analyst notes. Three `innerHTML` writes
did it, which is what the redesign's `server` column measures, and every
rule frontend/ion-pages.css carries for `.df-winlog*`, `.df-kib*`,
`.df-content-title`, `.df-code-block` and `.df-notes` was unreachable from
the stylesheet while they were. The sheet even says so at line 1174:
"JS innerHTML: #df-content-panel title / payload / notes."

Nothing on this page feeds a rendering library and nothing computes
geometry: there is no chart, no `createElementNS` and no element size read
anywhere in the script that was removed. So all three writes were markup
and all three moved. The two payload objects were data, but the page's only
use for them was `JSON.stringify` into one of those markup strings, so they
move as pre-serialised text rather than as objects for the browser to
format.

The four pipeline nodes and the four sidebar metrics moved with them even
though the JavaScript wrote those through `textContent` and `className`
rather than `innerHTML`. They are not a separate surface: their labels,
icons and readings are the same per-flow description as the panel's, and
leaving them behind would have kept the topology in JavaScript to serve two
attribute writes, which is the drift the architecture conversion removed.

The one number that cannot come from the stylesheet is each metric bar's
width. `style-src-attr 'none'` forbids an inline `style=`, so the fragment
emits `data-ion-style="width:NN%"` and static/js/ion-dynamic-styles.js
applies it with `setProperty` after every swap. That is ION's one
definition for a computed style, and it is why the `w-[0%]` and `w-[80%]`
classes the old markup carried were decoration: no `w-[N%]` rule exists in
the compiled stylesheet, so the widths only ever came from JavaScript.

There is no JSON endpoint to share a service function with. The page's
script fetched nothing at all; both pipelines were hardcoded. So the
permission matched here is the page's own entry in server.py's `_PAGES`
table, `alert:read`, applied through `require_permission` rather than
`require_page_permission` so an expired session gets a 403 instead of a
login form swapped into the middle of the diagram.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Literal

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse

from ion.auth.dependencies import require_permission
from ion.web.ui._shared import templates

logger = logging.getLogger(__name__)

router = APIRouter()

#: The ECS document the modern pipeline delivers. Key order is load-bearing:
#: it is printed verbatim as the Elastic Agent's output and as the modern end
#: state's JSON view, so reordering changes what the page shows.
ECS_PAYLOAD: dict = {
    "@timestamp": "2026-03-26T10:15:00.450Z",
    "event": {"code": "4728", "action": "added-member-to-group", "outcome": "success"},
    "user": {"name": "Admin_Bob", "target": {"name": "John Doe", "id": "S-1-5-21-345...-1001"}},
    "group": {"name": "Privileged_Admins"},
    "host": {"name": "DC-PROD-01"},
    "winlog": {"channel": "Security", "task": "Security Group Management"},
}

#: What the legacy pipeline delivers instead. `targetUser` is null on
#: purpose: that null is the whole finding the page exists to show, so it is
#: printed, not dropped.
LEGACY_PAYLOAD: dict = {
    "timestamp": "Mar 26, 10:15:00",
    "deviceProduct": "Windows",
    "externalId": "4728",
    "suser": "Admin_Bob",
    "msg": "Member added to Privileged_Admins",
    "targetUser": None,
    "_warning": "FIELD 'targetUser' NOT MAPPED IN STANDARD SMARTCONNECTOR SCHEMA",
}


def payload_json(document: dict) -> str:
    """A document as the page printed it, with `JSON.stringify(x, null, 2)`.

    Same separators and same indent, so the JSON view reads identically to
    the one the browser used to build. Serialised here rather than in the
    template because the template must not be the place a format decision
    lives twice.
    """
    return json.dumps(document, indent=2)


@dataclass(frozen=True)
class Node:
    """One stage of a pipeline, with the panel it shows when selected.

    `kind` picks the panel: "winlog" is the Event Viewer mock-up, "code" is
    the `<pre>` block fed from `code`, and "kibana" is the end-state panel
    for `side`. It replaces the JavaScript's `type`, where "kibana-legacy"
    and "kibana-modern" encoded two facts in one string and the template
    would have had to take it apart again.
    """

    index: int
    label: str
    icon: str
    kind: str
    details: str
    analyst_note: str
    code: str | None = None
    side: str | None = None


@dataclass(frozen=True)
class Metric:
    """One forensic-completeness reading in the sidebar.

    `bar_percent` is a measurement and two of the eight readings are
    literally 0, which is why the fragment guards it with `is not none`. A
    truthiness test drops the width declaration for exactly the two bars
    that are reporting a total loss, and an empty track reads as "not
    measured" rather than "zero".
    """

    key: str
    label: str
    status: str
    status_class: str
    bar_percent: int
    bar_class: str


@dataclass(frozen=True)
class EndState:
    """What lands in Elastic Security at the end of one pipeline.

    `missing` says whether the target user survived the trip. It is the one
    claim on this page worth making carefully: folding an unknown into the
    false branch would print the identity as PRESENT, which is the opposite
    of the finding. The fragment tests it with `is true` / `is false` and
    says "unknown" for anything else.
    """

    side: str
    missing: bool
    payload_json: str
    #: Who the pipeline says was added, when it still knows. Read out of the
    #: ECS document rather than written again, so the table cell and the JSON
    #: view cannot disagree about the name.
    target_user: str | None = None


@dataclass(frozen=True)
class Flow:
    """One pipeline: its stages, its readings and its end state."""

    key: str
    label: str
    nodes: tuple[Node, ...]
    metrics: tuple[Metric, ...]

    @property
    def selected_class(self) -> str:
        """ion-pages.css defines `.df-node-btn.selected-legacy` and
        `.selected-modern`, so the per-flow half of the selection colour is
        derived from the key rather than written out a second time."""
        return f"selected-{self.key}"


@dataclass(frozen=True)
class FlowChoice:
    """A segment of the flow toggle, available whether or not the read worked.

    The toggle is the control the user retries with, so the error branch
    renders it too. It is built from the flows at import, so a branch that
    has no payload still has the segments.
    """

    key: str
    label: str
    active_class: str


#: Metric id -> its sidebar label. One definition, because the readings
#: below would otherwise spell each label out twice and the two would drift.
_METRIC_LABELS: dict[str, str] = {
    "m1": "Target User Resolution",
    "m2": "Member SID Preservation",
    "m3": "NiFi Overhead",
    "m4": "Analyst Readiness",
}

#: Flow key -> (metric id, status, status class, bar percent, bar class).
#: Read off renderMetrics(), which set these four pairs from one `isLegacy`.
_METRIC_READINGS: dict[str, tuple[tuple[str, str, str, int, str], ...]] = {
    "legacy": (
        ("m1", "FAILED", "fail", 0, "red"),
        ("m2", "LOST", "fail", 0, "red"),
        ("m3", "High", "warn", 80, "orange"),
        ("m4", "BLOCKED", "fail", 15, "red"),
    ),
    "modern": (
        ("m1", "SUCCESS", "success", 100, "green"),
        ("m2", "PRESERVED", "success", 100, "green"),
        ("m3", "Low", "info", 20, "blue"),
        ("m4", "READY", "success", 100, "green"),
    ),
}


def _metrics(flow_key: str) -> tuple[Metric, ...]:
    return tuple(
        Metric(
            key=key,
            label=_METRIC_LABELS[key],
            status=status,
            status_class=status_class,
            bar_percent=bar_percent,
            bar_class=bar_class,
        )
        for key, status, status_class, bar_percent, bar_class in _METRIC_READINGS[flow_key]
    )


_END_STATES: dict[str, EndState] = {
    "legacy": EndState(
        side="legacy",
        missing=True,
        payload_json=payload_json(LEGACY_PAYLOAD),
    ),
    "modern": EndState(
        side="modern",
        missing=False,
        payload_json=payload_json(ECS_PAYLOAD),
        target_user=ECS_PAYLOAD["user"]["target"]["name"],
    ),
}

_LEGACY_NODES: tuple[Node, ...] = (
    Node(
        index=0,
        label="DC (Source)",
        icon="icon-server",
        kind="winlog",
        details=(
            "Event 4728 is generated by the DC with full XML, including "
            "MemberName and MemberSid in the EventData section."
        ),
        analyst_note="Event 4728 contains 'John Doe' in the XML Data MemberName field.",
    ),
    Node(
        index=1,
        label="Connector",
        icon="icon-shield-alert",
        kind="code",
        code="CEF:0|Microsoft|Windows|...|4728|...|suser=Admin_Bob msg=Added to group",
        details=(
            "Standard CEF mapping for 4728 ignores 'MemberName' attribute "
            "unless custom parsing is written."
        ),
        analyst_note=(
            "The SmartConnector maps only standard fields. MemberName is not "
            "part of the default CEF mapping."
        ),
    ),
    Node(
        index=2,
        label="NiFi",
        icon="icon-settings",
        kind="code",
        code=(
            "Extract 'suser' and 'msg'\n"
            "\n"
            "// NiFi cannot enrich what is not in the stream\n"
            "// 'Member' field is null — no target user available\n"
            "// Additional lookup would require DC query (expensive, often blocked)"
        ),
        details="NiFi cannot enrich what is not in the stream. 'Member' field is null.",
        analyst_note=(
            "NiFi passes data through but has no way to recover the lost field "
            "without querying the DC directly."
        ),
    ),
    Node(
        index=3,
        label="Elastic Security",
        icon="icon-layout",
        kind="kibana",
        side="legacy",
        details=(
            "Elastic Security receives the truncated CEF event. The alert fires "
            "on group modification but cannot show who was added."
        ),
        analyst_note="Analyst sees Bob modified a group, but doesn't know who Bob added.",
    ),
)

_MODERN_NODES: tuple[Node, ...] = (
    Node(
        index=0,
        label="DC (Source)",
        icon="icon-server",
        kind="winlog",
        details=(
            "Same Event 4728 with full XML. The Elastic Agent reads the Windows "
            "Security channel directly."
        ),
        analyst_note=(
            "Event 4728 contains 'John Doe' in the XML Data MemberName field "
            "— same source, different collection method."
        ),
    ),
    Node(
        index=1,
        label="Elastic Agent",
        icon="icon-database",
        kind="code",
        code=payload_json(ECS_PAYLOAD),
        details=(
            "Elastic Windows Integration maps all 4728 XML attributes to ECS "
            "fields automatically."
        ),
        analyst_note=(
            "The agent preserves every field from the original event, including "
            "user.target.name and MemberSid."
        ),
    ),
    Node(
        index=2,
        label="NiFi",
        icon="icon-cpu",
        kind="code",
        code=(
            "Route validated JSON to target index\n"
            "\n"
            "// Zero parsing overhead — NiFi simply directs the rich JSON\n"
            "// All fields are already mapped to ECS by the Elastic Agent\n"
            "// NiFi acts as a transport layer only"
        ),
        details=(
            "Zero-parsing overhead. NiFi simply directs the rich JSON to the "
            "correct index."
        ),
        analyst_note=(
            "NiFi routing only — no field extraction or enrichment needed. "
            "Lower CPU, lower latency, fewer failure modes."
        ),
    ),
    Node(
        index=3,
        label="Elastic Security",
        icon="icon-shield-check",
        kind="kibana",
        side="modern",
        details=(
            "Full ECS event lands in Elastic Security. Detection rules can match "
            "on user.target.name for precise alerting."
        ),
        analyst_note="Immediate visibility: Admin_Bob added John Doe to Privileged_Admins.",
    ),
)

#: Flow key -> the pipeline, in the order the toggle shows them.
_FLOWS: dict[str, Flow] = {
    "legacy": Flow(
        key="legacy",
        label="Legacy",
        nodes=_LEGACY_NODES,
        metrics=_metrics("legacy"),
    ),
    "modern": Flow(
        key="modern",
        label="Modern",
        nodes=_MODERN_NODES,
        metrics=_metrics("modern"),
    ),
}

#: The toggle's segments, derived so adding a flow does not mean editing a
#: second list that the error branch reads.
FLOW_CHOICES: tuple[FlowChoice, ...] = tuple(
    FlowChoice(key=flow.key, label=flow.label, active_class=f"active-{flow.key}")
    for flow in _FLOWS.values()
)

#: Stages per pipeline. Derived, and checked, because the selected stage
#: survives a flow switch: if one pipeline were shorter than the other, the
#: switch would ask for a stage that does not exist.
NODE_COUNT: int = len(_FLOWS["legacy"].nodes)

def _check_flows() -> None:
    """Refuse to start on a pipeline table that cannot be navigated.

    The loader in ui/__init__.py does not swallow an import error, so a flow
    table these checks reject takes the app down rather than serving a page
    whose stage buttons ask for stages that are not there.
    """
    for flow in _FLOWS.values():
        if len(flow.nodes) != NODE_COUNT:
            raise ValueError(
                f"flow {flow.key!r} has {len(flow.nodes)} stages, expected "
                f"{NODE_COUNT}: a stage index valid for one pipeline must be "
                "valid for the other, because the selection survives a switch"
            )
        for index, node in enumerate(flow.nodes):
            if node.index != index:
                raise ValueError(
                    f"flow {flow.key!r} stage {index} declares index {node.index}: "
                    "the index is what the stage buttons request, so it must match"
                )
            if node.kind == "kibana" and node.side not in _END_STATES:
                raise ValueError(
                    f"flow {flow.key!r} stage {index} shows an end state "
                    f"{node.side!r} that does not exist"
                )


_check_flows()


def data_flow_payload(flow: str, node: int) -> dict:
    """The selected pipeline, the selected stage and both end states.

    Separate from the route so the inventory can be asserted directly, and
    so a later JSON endpoint has something to call rather than a second copy
    of two pipelines.

    The lookups are deliberately not defensive. An unknown flow key or an
    out-of-range stage means the query validation and this table have
    drifted apart, and the route turns the exception into a fragment that
    says the description could not be read, which is true. Clamping would
    show a different pipeline than the one asked for and call it success.
    """
    selected = _FLOWS[flow]
    return {
        "flows": tuple(_FLOWS.values()),
        "flow": selected,
        "node": selected.nodes[node],
        "end_states": _END_STATES,
    }


@router.get(
    "/data-flow",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission("alert:read"))],
)
def data_flow_fragment(
    request: Request,
    flow: Literal["legacy", "modern"] = "legacy",
    node: int = Query(0, ge=0, lt=NODE_COUNT),
    view: Literal["table", "json"] = "table",
    compare: bool = False,
) -> HTMLResponse:
    """The whole interactive surface for one selection of the four controls.

    Every control is an `hx-get` back here with the next selection in its
    URL, so "what the page shows for this selection" has one definition and
    the browser holds no state. That is also why the fragment, not the page,
    carries the flow toggle: the active segment is part of the state, and
    only the response knows it. The toggle is rendered in the failure branch
    too, and the page keeps a Reload control outside the swap, so no render
    can remove the way back.

    A failure is not an empty pipeline. An empty panel on this page reads as
    "nothing was ingested", which is the opposite conclusion from "we could
    not describe the ingestion", so the error branch says which and prints
    no readings at all rather than a row of zeroes.
    """
    try:
        payload = data_flow_payload(flow, node)
    except Exception:
        logger.exception(
            "Data flow fragment could not be built (flow=%s, node=%s)", flow, node
        )
        payload = None

    return templates.TemplateResponse(
        request=request,
        name="_fragments/data_flow.html",
        context={
            "payload": payload,
            "flow_choices": FLOW_CHOICES,
            # The requested selection, echoed back for the hidden state the
            # page's Reload control includes and for the retry URL. It is
            # available in both branches because the error branch has to be
            # able to retry the same request.
            "state": {"flow": flow, "node": node, "view": view, "compare": compare},
        },
    )
