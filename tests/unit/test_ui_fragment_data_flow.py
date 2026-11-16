"""The ingestion-flow page, moved out of JavaScript and into a fragment.

data_flow.html held two complete ingestion pipelines in JavaScript
constants and built every panel on the page from strings: the Event Viewer
mock-up, the Kibana end state in both its views, the code block and the two
analyst notes. Three `innerHTML` writes did it, so every rule
frontend/ion-pages.css carries for `.df-winlog*`, `.df-kibana*`,
`.df-kib-*`, `.df-content-title`, `.df-code-block` and `.df-notes` was
unreachable from the stylesheet. The sheet says so itself at line 1174.

These tests are the pin for that move. The inventory cases exist because a
hand-port drops a stage or a note silently, and the zero cases exist
because this page has four of them: the first stage's index is 0 and two of
the eight forensic readings are 0 percent, which is a measured total loss
rather than an absent measurement.

Every assertion here was made to fail first by putting the defect back, one
at a time. The mutation table is in the conversion report.
"""
from __future__ import annotations

import re
from html import unescape
from pathlib import Path

import pytest

from ion.web.templating import make_templates
from ion.web.ui import data_flow as page
from ion.web.ui.data_flow import (
    ECS_PAYLOAD,
    LEGACY_PAYLOAD,
    NODE_COUNT,
    EndState,
    data_flow_payload,
    payload_json,
)

FRAGMENT = "_fragments/data_flow.html"

PAGE_TEMPLATE = (
    Path(page.__file__).resolve().parents[1] / "templates" / "data_flow.html"
)
FRAGMENT_TEMPLATES = [
    Path(page.__file__).resolve().parents[1] / "templates" / "_fragments" / name
    for name in ("data_flow.html", "data_flow_panels.html")
]

#: Every stage both pipelines declared, read out of the pre-change `flows`
#: constant and written out by hand. A list derived from the new dataclasses
#: would pass even if the port lost a stage.
EXPECTED_STAGES = {
    "legacy": [
        ("DC (Source)", "icon-server"),
        ("Connector", "icon-shield-alert"),
        ("NiFi", "icon-settings"),
        ("Elastic Security", "icon-layout"),
    ],
    "modern": [
        ("DC (Source)", "icon-server"),
        ("Elastic Agent", "icon-database"),
        ("NiFi", "icon-cpu"),
        ("Elastic Security", "icon-shield-check"),
    ],
}

#: One analyst note per stage, as the JavaScript declared them. These
#: strings existed nowhere but inside that constant, so a copy left behind
#: in the page is a second definition that drifts.
EXPECTED_NOTES = [
    "Event 4728 contains 'John Doe' in the XML Data MemberName field.",
    "The SmartConnector maps only standard fields. MemberName is not part of "
    "the default CEF mapping.",
    "NiFi passes data through but has no way to recover the lost field without "
    "querying the DC directly.",
    "Analyst sees Bob modified a group, but doesn't know who Bob added.",
    "The agent preserves every field from the original event, including "
    "user.target.name and MemberSid.",
    "Immediate visibility: Admin_Bob added John Doe to Privileged_Admins.",
]

#: Flow -> the four sidebar readings renderMetrics() set, as
#: (label, status, bar percent). The two zeroes are the point of this table.
EXPECTED_READINGS = {
    "legacy": [
        ("Target User Resolution", "FAILED", 0),
        ("Member SID Preservation", "LOST", 0),
        ("NiFi Overhead", "High", 80),
        ("Analyst Readiness", "BLOCKED", 15),
    ],
    "modern": [
        ("Target User Resolution", "SUCCESS", 100),
        ("Member SID Preservation", "PRESERVED", 100),
        ("NiFi Overhead", "Low", 20),
        ("Analyst Readiness", "READY", 100),
    ],
}


def render(flow="legacy", node=0, view="table", compare=False, payload=True) -> str:
    """The fragment as the route renders it, for one selection."""
    built = data_flow_payload(flow, node) if payload else None
    return make_templates().env.get_template(FRAGMENT).render(
        payload=built,
        flow_choices=page.FLOW_CHOICES,
        state={"flow": flow, "node": node, "view": view, "compare": compare},
    )


def page_source() -> str:
    return PAGE_TEMPLATE.read_text(encoding="utf-8")


def fragment_sources() -> str:
    return "\n".join(p.read_text(encoding="utf-8") for p in FRAGMENT_TEMPLATES)


def without_comments(source: str) -> str:
    """Template source with its Jinja comments removed.

    The comments in these templates name the htmx features that are banned
    here and say why, so a grep for them over the raw source finds the
    explanation and reports it as the defect.
    """
    return re.sub(r"\{#.*?#\}", "", source, flags=re.S)


def rendered_stages(html: str) -> list[tuple[str, str]]:
    """(label, icon class) for each pipeline stage, in the order drawn.

    Read off the stage buttons rather than searched for anywhere in the
    response. A substring check over the whole fragment is not a check: the
    mutation pass renamed the "Elastic Agent" stage to "Agent" and the
    assertion stayed green, because the stage's own analyst note and the
    sidebar's prose both say "Elastic Agent" too.
    """
    pairs = re.findall(
        r'<button class="df-node-btn[^"]*"><i class="([\w-]+)"></i></button>\s*'
        r'<span class="df-node-label[^"]*">([^<]*)</span>',
        html,
    )
    return [(unescape(label), icon) for icon, label in pairs]


def page_slot() -> str:
    """The `#df-view` opening tag, with the template's comments removed.

    Also a lesson from the mutation pass: `hx-trigger="load"` deleted from
    the slot left the page with nothing requesting the fragment at all, and
    a grep over the whole template still found the string, in the comment
    that explains why the attribute is there.
    """
    src = without_comments(page_source())
    tag = re.search(r'<div id="df-view"[^>]*>', src, re.S)
    assert tag, "the page has no #df-view slot"
    return tag.group(0)


# ---------------------------------------------------------------------------
# Registration and permission
# ---------------------------------------------------------------------------


def _route():
    import ion.web.ui as ui

    for r in ui.router.routes:
        if r.path == "/ui/data-flow":
            return r
    raise AssertionError("the data flow fragment route is not mounted")


def _dependency_calls(route) -> list:
    out, stack = [], list(route.dependant.dependencies)
    while stack:
        dep = stack.pop()
        if dep.call is not None:
            out.append(dep.call)
        stack.extend(dep.dependencies)
    return out


def _required_permissions(route) -> list[str]:
    found = []
    for fn in _dependency_calls(route):
        if not getattr(fn, "__qualname__", "").startswith("require_permission."):
            continue
        cells = dict(zip(fn.__code__.co_freevars,
                         (c.cell_contents for c in (fn.__closure__ or ()))))
        name = cells.get("permission_name")
        if name:
            found.append(name)
    return found


def test_the_module_exposes_a_mounted_router():
    """Discovery means nothing announces itself, so check it is really there.

    A 404 here renders an empty slot, and an empty slot on this page reads
    as an ingestion pipeline that carried nothing.
    """
    import ion.web.ui as ui

    assert "/ui/data-flow" in {r.path for r in ui.router.routes}


def test_the_fragment_permission_is_the_pages_own_permission():
    """The fragment must not be a softer way in than the page it serves.

    This page has no JSON endpoint to mirror: its script fetched nothing and
    both pipelines were hardcoded. So the authority compared against is
    server.py's own _PAGES row, read here rather than restated, so widening
    the page's permission fails this test instead of quietly widening the
    fragment.
    """
    from ion.web.server import _PAGES

    page_perms = [p for _path, tpl, p in _PAGES if tpl == "data_flow.html"]
    assert page_perms == ["alert:read"], page_perms
    assert _required_permissions(_route()) == page_perms


def test_the_fragment_does_not_use_a_redirecting_page_dependency():
    for call in _dependency_calls(_route()):
        name = getattr(call, "__qualname__", "")
        assert "require_page_permission" not in name
        assert "require_page_auth" not in name


# ---------------------------------------------------------------------------
# The pipelines that moved
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("flow", sorted(EXPECTED_STAGES))
def test_every_stage_renders_with_its_label_and_icon(flow):
    html = render(flow=flow)
    assert rendered_stages(html) == EXPECTED_STAGES[flow]
    assert html.count('class="df-node-btn') == len(EXPECTED_STAGES[flow])


@pytest.mark.parametrize("flow", sorted(EXPECTED_STAGES))
def test_every_stage_is_requestable_by_its_index(flow):
    """A stage with no index in its request is a stage nothing can select."""
    html = render(flow=flow)
    for index in range(NODE_COUNT):
        assert f'data-df-node="{index}"' in html, index
        assert f"node={index}" in unescape(html), index


def test_stage_zero_is_still_requestable():
    """The first zero on this page.

    The first stage's index is 0. Under a truthiness test it would be the
    one stage rendered without an index, so clicking the source event would
    request nothing, and the page would look complete.
    """
    html = render(node=1)
    assert 'data-df-node="0"' in html
    assert "node=0" in unescape(html)


def test_the_hidden_state_keeps_stage_zero():
    """The same zero, in the selection the Reload control sends back.

    Reload reads the hidden inputs. Dropped for stage 0, a reload from the
    source event would silently reset to the default selection, which is the
    same stage here and a different one as soon as the default changes.
    """
    html = render(node=0)
    assert re.search(r'<input type="hidden" name="node" value="0">', html)


@pytest.mark.parametrize("flow,expected_class", [
    ("legacy", "selected-legacy"),
    ("modern", "selected-modern"),
])
def test_the_selected_stage_carries_the_flows_own_selection_class(flow, expected_class):
    """ion-pages.css colours the selection per pipeline, and the class is
    derived from the flow key so the two cannot drift."""
    html = render(flow=flow, node=2)
    assert html.count(expected_class) == 1
    selected = re.search(r'<button class="df-node-btn ([a-z-]+)"><i class="([\w-]+)"',
                         html)
    assert selected, html
    assert selected.group(1) == expected_class
    assert selected.group(2) == EXPECTED_STAGES[flow][2][1]


@pytest.mark.parametrize("note", EXPECTED_NOTES)
def test_every_analyst_note_renders_on_its_own_stage(note):
    """One case per note, so a partial port names the one it dropped."""
    found = any(
        note in unescape(render(flow=flow, node=node))
        for flow in EXPECTED_STAGES
        for node in range(NODE_COUNT)
    )
    assert found, note


def test_the_source_event_mock_up_renders_as_markup():
    html = render(node=0)
    assert 'class="df-winlog"' in html
    assert "Event Viewer - [Event 4728, Security]" in html
    assert "CN=John Doe,OU=Users,DC=Corp" in html


def test_a_code_stage_renders_its_payload_in_a_pre_block():
    html = render(flow="legacy", node=1)
    assert '<div class="df-code-block"><pre>CEF:0|Microsoft' in html


def test_the_ecs_document_renders_exactly_as_json_stringify_left_it():
    """The modern agent's stage printed `JSON.stringify(ecsPayload, null, 2)`.

    Same indent and same separators, so the document reads as it did. The
    quotes come out of Jinja as `&#34;`, which the browser decodes on parse,
    which is what let the hand-rolled escHtml() go rather than be ported.
    """
    html = render(flow="modern", node=1)
    text = unescape(html)
    assert '"@timestamp": "2026-03-26T10:15:00.450Z"' in text
    assert '"target": {\n      "name": "John Doe"' in text
    assert payload_json(ECS_PAYLOAD) in text


def test_the_dropped_field_is_printed_as_null_not_omitted():
    """`targetUser: null` is the finding, so it has to survive the move."""
    text = unescape(render(flow="legacy", node=3, view="json"))
    assert '"targetUser": null' in text
    assert payload_json(LEGACY_PAYLOAD) in text


# ---------------------------------------------------------------------------
# The forensic readings, and the two zeroes among them
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("flow", sorted(EXPECTED_READINGS))
def test_every_reading_renders_with_its_status_and_width(flow):
    html = render(flow=flow)
    for label, status, percent in EXPECTED_READINGS[flow]:
        assert label in html, label
        assert f">{status}</span>" in html, status
        assert f'data-ion-style="width:{percent}%"' in html, (label, percent)


def test_a_zero_reading_still_emits_its_width():
    """The two zeroes that matter on this page.

    Target User Resolution and Member SID Preservation are 0 percent on the
    legacy pipeline: a measured total loss. Under a truthiness test those
    two bars alone would render with no width declaration, and an empty
    track reads as "not measured", which is the opposite claim.
    """
    html = render(flow="legacy")
    assert html.count('data-ion-style="width:0%"') == 2
    assert html.count('data-df-bar-percent="0"') == 2


@pytest.mark.parametrize("flow", sorted(EXPECTED_READINGS))
def test_every_bar_declares_a_width(flow):
    html = render(flow=flow)
    bars = re.findall(r'<div class="df-bar-fill [a-z]+"([^>]*)>', html)
    assert len(bars) == len(EXPECTED_READINGS[flow])
    for attrs in bars:
        assert "data-ion-style=" in attrs, attrs


def test_a_width_goes_out_as_data_ion_style_not_as_an_inline_style():
    """`style-src-attr 'none'` blocks an inline style attribute outright.

    A width written as `style="width:15%"` would be dropped by the browser
    and every bar would render empty, which on this page reads as a total
    loss on both pipelines.
    """
    html = render()
    assert not re.search(r'(?<![-\w])style="', html)
    assert "data-ion-style=" in html


# ---------------------------------------------------------------------------
# The end state, and the three ways it can read
# ---------------------------------------------------------------------------


def test_the_legacy_end_state_reports_the_identity_missing():
    html = render(flow="legacy", node=3)
    assert 'class="df-kib-missing"' in html
    assert "MISSING" in html
    assert 'class="df-kib-alert"' in html
    assert "John Doe</span>" not in html


def test_the_modern_end_state_names_the_target_user_and_raises_no_alert():
    html = render(flow="modern", node=3)
    assert '<span class="df-kib-present">John Doe</span>' in html
    assert "df-kib-missing" not in html
    assert "df-kib-alert" not in html


def test_an_unknown_end_state_is_not_reported_as_present():
    """Three states stay three.

    `missing` is the claim this page exists to make. Folded into the false
    branch by a truthiness test, a pipeline nobody established anything
    about would print a forensic identity as PRESENT, which is worse than
    either true answer.
    """
    unknown = EndState(side="legacy", missing=None, payload_json="{}",
                       target_user="John Doe")
    html = render()  # warm the environment, then render the macro directly
    assert html
    macro = make_templates().env.get_template(
        "_fragments/data_flow_panels.html"
    ).module.kibana(unknown, "table", "/ui/data-flow", "/ui/data-flow")
    assert "UNKNOWN" in macro
    assert "df-kib-present" not in macro
    assert "John Doe" not in macro
    assert "df-kib-alert" not in macro


def test_the_json_view_replaces_the_table_rather_than_joining_it():
    table = render(flow="modern", node=3, view="table")
    js = render(flow="modern", node=3, view="json")
    assert 'class="df-kib-table"' in table
    assert "df-kib-json" not in table
    assert 'class="df-kib-json"' in js
    assert "df-kib-table" not in js


@pytest.mark.parametrize("view", ["table", "json"])
def test_the_view_toggle_marks_the_view_it_is_showing(view):
    html = render(flow="modern", node=3, view=view)
    active = re.findall(r'<button class="active"\s+data-df-view="(\w+)"', html)
    assert active == [view], html


def test_the_json_block_starts_with_the_document_and_no_blank_line():
    """`.df-kib-json` is `white-space: pre`, so an indented newline between
    the tag and the document prints as an empty first line."""
    html = render(flow="modern", node=3, view="json")
    assert '<div class="df-kib-json">{\n' in html


# ---------------------------------------------------------------------------
# The comparison
# ---------------------------------------------------------------------------


def test_the_comparison_renders_both_end_states_side_by_side():
    html = render(compare=True)
    assert 'data-df-end-state="legacy"' in html
    assert 'data-df-end-state="modern"' in html
    assert html.count('class="df-kibana"') == 2
    assert "Legacy End State (Missing Fields)" in html
    assert "Modern End State (Full Visibility)" in html
    # The pipeline and the readings belong to the single-flow view.
    assert "df-node-btn" not in html
    assert "df-bar-fill" not in html


def test_the_comparison_segment_turns_the_comparison_off_again():
    """dfToggleCompare() toggled. The server knows the state, so the URL does
    the toggling and the button needs no handler."""
    on = unescape(render(compare=False))
    off = unescape(render(compare=True))
    assert "compare=1" in on
    assert "compare=0" in off


def test_the_comparison_keeps_the_pipeline_it_was_opened_from():
    """Leaving the comparison must return to the pipeline that was selected,
    not to the default one."""
    html = unescape(render(flow="modern", node=2, compare=True))
    assert "flow=modern&node=2&view=table&compare=0" in html


# ---------------------------------------------------------------------------
# Escaping, which replaces the JavaScript's hand-rolled escaper
# ---------------------------------------------------------------------------


def test_jinja_escapes_a_hostile_stage_label():
    """renderContent() interpolated `node.label` into an innerHTML string
    with no escaping, and escHtml() was applied only to the code block."""
    hostile = page.Node(
        index=0,
        label="<script>alert(1)</script>",
        icon="icon-bug",
        kind="code",
        code="<script>alert(2)</script>",
        details="<img src=x onerror=alert(3)>",
        analyst_note="<b>note</b>",
    )
    flow = page.Flow(key="legacy", label="L", nodes=(hostile,), metrics=())
    html = make_templates().env.get_template(FRAGMENT).render(
        payload={"flows": (flow,), "flow": flow, "node": hostile, "end_states": {}},
        flow_choices=page.FLOW_CHOICES,
        state={"flow": "legacy", "node": 0, "view": "table", "compare": False},
    )
    assert "<script>alert(1)</script>" not in html
    assert "<script>alert(2)</script>" not in html
    assert "<img src=x" not in html
    assert "<b>note</b>" not in html
    assert "&lt;script&gt;" in html


def test_no_fragment_template_marks_anything_safe():
    """`|safe` would reintroduce exactly the hole escHtml() half-closed."""
    assert "|safe" not in fragment_sources()


# ---------------------------------------------------------------------------
# A failed build is not an empty pipeline
# ---------------------------------------------------------------------------


def test_a_failed_build_says_so_and_prints_no_readings():
    html = render(payload=False)
    assert "could not be described" in html
    assert "Nothing here was measured to be zero" in html
    assert "df-bar-fill" not in html
    assert "df-node-btn" not in html
    assert "df-kibana" not in html
    assert "data-ion-style" not in html


def test_the_failed_branch_can_retry_the_same_selection():
    html = render(flow="modern", node=2, view="json", payload=False)
    assert 'data-df-flow-failed="true"' in html
    assert "Retry" in html
    retry = unescape(html)
    assert "/ui/data-flow?flow=modern&node=2&view=json&compare=0" in retry


def test_the_failed_branch_still_carries_the_flow_toggle():
    """Chrome wraps both states.

    The toggle is the only control inside this swap, so a failure that
    removed it would leave the page with one way back: the Reload button in
    the shell, which is why that one is outside the swap. Both exist.
    """
    html = render(payload=False)
    assert html.count("df-toggle-btn") == 3
    assert 'id="df-state"' in html


def test_the_route_renders_the_failed_branch_when_the_build_raises(monkeypatch):
    from starlette.requests import Request

    def boom(flow, node):
        raise RuntimeError("pipeline table unavailable")

    monkeypatch.setattr(page, "data_flow_payload", boom)
    request = Request({
        "type": "http", "method": "GET", "path": "/ui/data-flow",
        "headers": [], "query_string": b"", "root_path": "",
    })
    body = page.data_flow_fragment(request).body.decode("utf-8")
    assert "could not be described" in body
    assert "df-bar-fill" not in body
    assert "df-toggle-btn" in body


# ---------------------------------------------------------------------------
# URL hygiene
# ---------------------------------------------------------------------------


def test_every_request_url_is_built_as_one_value():
    """`{{ base }}&view=json` emits `&amp;` for the variable's separators and
    a bare `&` for the literal one, so half the URL is escaped and half is
    not. Built as one value, every separator is escaped the same way and
    getAttribute hands htmx the string back intact."""
    for kwargs in ({}, {"node": 3}, {"view": "json"}, {"compare": True},
                   {"payload": False}):
        html = render(**kwargs)
        for url in re.findall(r'hx-get="([^"]*)"', html):
            if "&" not in url:
                continue
            assert "&amp;" in url, url
            assert not re.search(r"&(?!amp;)", url), url


def test_every_request_url_names_this_fragment():
    html = render()
    for url in re.findall(r'hx-get="([^"]*)"', html):
        assert url.startswith("/ui/data-flow"), url


# ---------------------------------------------------------------------------
# No htmx feature that compiles a string
# ---------------------------------------------------------------------------


def test_no_htmx_attribute_needs_an_expression_evaluated():
    """ION serves no `unsafe-eval`, so anything htmx hands to Function()
    throws and the control silently does nothing while looking right. One
    converted page shipped a dead Enter key this way."""
    for source in (without_comments(page_source()),
                   without_comments(fragment_sources())):
        assert "hx-on" not in source
        assert "hx-vals" not in source
        assert "hx-headers" not in source
        assert "js:" not in source
        assert not re.search(r"hx-trigger=\"[^\"]*\[", source)


def test_the_page_writes_no_htmx_error_handler_of_its_own():
    """static/js/htmx-errors.js is the one definition of what a failed swap
    means, and a per-page copy is a second answer to what an expired session
    is."""
    src = page_source()
    assert "htmx:responseError" not in src
    assert "htmx:beforeSwap" not in src
    assert "htmx:afterSwap" not in src


# ---------------------------------------------------------------------------
# What is left in the page
# ---------------------------------------------------------------------------


def test_the_page_builds_no_markup_in_javascript():
    """The measurement the redesign's `server` column makes, asserted here so
    the page cannot regress without this file failing."""
    src = page_source()
    assert not re.search(r"innerHTML\s*\+?=", src)
    assert "insertAdjacentHTML" not in src
    assert not re.search(r"outerHTML\s*\+?=", src)


def test_the_page_has_no_javascript_left_at_all():
    """Everything the script did was markup or the state that selected it,
    so there is nothing left to keep. A leftover block would be a second
    definition of a panel."""
    assert "<script" not in page_source()


def test_the_page_holds_an_htmx_slot_rather_than_two_pipelines():
    slot = page_slot()
    assert 'hx-get="/ui/data-flow"' in slot, slot
    assert 'hx-trigger="load"' in slot, slot
    assert 'hx-swap="innerHTML"' in slot, slot


@pytest.mark.parametrize("dead", [
    "ecsPayload", "legacyPayload", "renderWinlog", "renderKibana", "escHtml",
    "renderContent", "renderMetrics", "renderNodes", "renderCompare",
    "dfSetFlow", "dfToggleCompare", "dfSelectNode", "dfSetViewMode",
    "df-content-panel", "df-compare-kibana-legacy", "df-compare-kibana-modern",
    "df-m1-status", "df-node-0",
])
def test_no_part_of_the_old_renderer_is_left_in_the_page(dead):
    """One case per name, so a partial port names what it left behind.

    Unused is not the same as gone: a second copy of a panel or a pipeline
    is the thing that drifts from the one being rendered.
    """
    assert dead not in page_source(), dead


@pytest.mark.parametrize("flow", sorted(EXPECTED_STAGES))
def test_no_stage_label_or_note_is_left_in_the_page(flow):
    src = page_source()
    for label, icon in EXPECTED_STAGES[flow]:
        assert label not in src, label
        assert icon not in src, icon
    for note in EXPECTED_NOTES:
        assert note not in src, note


def test_the_retry_control_outside_the_swap_target_sends_the_selection():
    """A control inside the swap can be removed by the render that fails.

    The flow toggle has to be in the fragment, because the active segment is
    part of the state. So the page keeps one control of its own, outside the
    target, and hx-include sends the hidden selection so it retries what was
    asked for rather than resetting the view.
    """
    src = page_source()
    assert 'hx-include="#df-state"' in src
    assert src.index('id="df-reload"') < src.index('id="df-view"')


def test_the_page_renders_no_timestamp_and_stores_no_url():
    """The two traps this page does not have, asserted rather than assumed.

    Both JSON documents carry a timestamp field, but they are printed
    verbatim as the raw document each pipeline delivers, which is the whole
    subject of the page. Running one through the `ts` macro would put
    `<time>` markup inside a JSON payload and claim the viewer's clock for a
    string that is part of the evidence. Nothing here is a stored URL, and
    nothing is read through the ORM, so there is no `|safe_url` and no
    `ui._shared.plain` site either.
    """
    sources = fragment_sources()
    assert "_time.html" not in sources
    assert "safe_url" not in sources
    module = Path(page.__file__).read_text(encoding="utf-8")
    assert "strftime" not in module
    assert "plain(" not in module


# ---------------------------------------------------------------------------
# The table itself
# ---------------------------------------------------------------------------


def test_both_pipelines_have_the_same_number_of_stages():
    """The selection survives a flow switch, so a shorter pipeline would
    mean switching from its last stage asked for a stage that is not there.
    The module refuses to import rather than discover that per request."""
    payload = data_flow_payload("legacy", 0)
    assert len(payload["flows"]) == 2
    for flow in payload["flows"]:
        assert len(flow.nodes) == NODE_COUNT


def test_every_kibana_stage_names_an_end_state_that_exists():
    payload = data_flow_payload("legacy", 0)
    for flow in payload["flows"]:
        for node in flow.nodes:
            if node.kind == "kibana":
                assert node.side in payload["end_states"], (flow.key, node.side)
