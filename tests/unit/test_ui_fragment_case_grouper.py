"""The case grouper status fragment, and the honesty contract it carries.

case_grouper.html built the whole panel with four `innerHTML` writes fed by
137 lines of inline JavaScript. What moved to Jinja is not only markup: this
panel's figures are what an analyst reads to decide whether the grouper is
doing its job, and on a quiet shift every one of them is legitimately zero.

So most of what is tested here is the difference between a figure of zero and
no figure at all:

  * a pass that scanned nothing prints 0
  * no completed pass prints no figures and says so
  * a figure missing from a recorded summary says it was not reported
  * a side-effect gate the panel could not resolve says unknown, not off

Every case below was watched failing against a truthiness version of the
template before it was made to pass; scratchpad/falsify_case_grouper.py
mutates each guard back and checks the named test goes red.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
from starlette.requests import Request

import ion.web
from ion.web.templating import make_templates
from ion.web.ui.case_grouper import (
    METRICS,
    error_note,
    metric_rows,
)

FRAGMENT = "_fragments/case_grouper_status.html"

PAGE = Path(ion.web.__file__).parent / "templates" / "case_grouper.html"

RAN_AT = datetime(2026, 10, 12, 9, 30, tzinfo=timezone.utc)

#: A summary with every key the service writes, all non-zero, so a test that
#: wants one missing or zeroed figure changes exactly that one.
FULL_SUMMARY: dict[str, Any] = {
    "scanned": 12,
    "grouped_new_cases": 3,
    "grouped_extended_cases": 2,
    "alerts_attached": 9,
    "investigations_queued": 4,
    "errors": 1,
}


def _flat(html: str) -> str:
    """Whitespace-normalised, so an assertion does not encode the indenting."""
    return " ".join(html.split())


def _payload(**over: Any) -> dict[str, Any]:
    """A payload shaped like case_grouper_api.status_payload's return."""
    base: dict[str, Any] = {
        "enabled": True,
        "interval_s": 60,
        "window_minutes": 15,
        "push_to_kibana": True,
        "auto_investigate": True,
        "last_run_at": RAN_AT,
        "last_result": dict(FULL_SUMMARY),
        "auto_cases_total": 42,
    }
    base.update(over)
    return base


def render(payload: dict[str, Any]) -> str:
    """Render through the real view builders, so a break in either fails."""
    env = make_templates().env
    return env.get_template(FRAGMENT).render(
        failed=False,
        status=payload,
        metrics=metric_rows(payload.get("last_result")),
        error_note=error_note(payload.get("last_result")),
    )


def render_failed() -> str:
    env = make_templates().env
    return env.get_template(FRAGMENT).render(
        failed=True, status=None, metrics=None, error_note=None,
    )


def _inline_js(page: str) -> str:
    return "".join(
        m.group(1) for m in re.finditer(
            r"<script(?![^>]*src=)[^>]*>(.*?)</script>", page, re.S)
    )


_ROW = re.compile(r"<tr>(.*?)</tr>", re.S)


def _cell(html: str, label: str) -> str | None:
    """The value cell of the Last run row carrying this label.

    Asserted per row rather than by searching the whole fragment, because
    "0 appears somewhere" is true of a page with one zero in the wrong place
    and of a page with six in the right ones.
    """
    for match in _ROW.finditer(html):
        row = match.group(1)
        if label not in row:
            continue
        cells = re.findall(r"<td[^>]*>(.*?)</td>", row, re.S)
        return " ".join(cells[-1].split()) if cells else None
    return None


def _js_code(page: str) -> str:
    """The inline JavaScript with its `//` comments removed.

    A comment naming what the conversion deleted is not the deleted thing.
    The first version of these assertions searched the whole page and failed
    on the comment explaining that cgEsc() had gone, which would have pushed
    the explanation out of the file to satisfy a test.
    """
    return re.sub(r"(?m)^\s*//.*$", "", _inline_js(page))


# ---------------------------------------------------------------------------
# The Last run figures: zero is a measurement, no run is not
# ---------------------------------------------------------------------------


def test_a_pass_that_scanned_nothing_prints_zero():
    """The case a truthiness port gets wrong in the dangerous direction.

    `{% if row.value %}` is false for 0, so a pass that genuinely scanned no
    alerts would report its figures as missing. Zero scanned on a quiet
    shift is the single most common value on this table.
    """
    html = render(_payload(last_result=dict(
        FULL_SUMMARY, scanned=0, grouped_new_cases=0, alerts_attached=0,
    )))
    assert _cell(html, "Scanned") == "0"
    assert _cell(html, "New cases") == "0"
    assert _cell(html, "Alerts attached") == "0"
    assert _cell(html, "Investigations queued") == "4"
    assert "not reported" not in html


def test_no_completed_pass_is_not_a_table_of_zeros():
    """The grouper writes its summary after a pass finishes.

    An absent summary means no pass has finished in this process. Six zeros
    would describe a pass that ran and found nothing, which is the opposite
    conclusion, and it is what `s.last_result || {}` would have produced had
    the JavaScript not defaulted every cell to an em-dash.
    """
    html = _flat(render(_payload(last_result=None)))
    assert "no completed pass recorded" in html
    assert ">0<" not in html
    for _, label, _note in METRICS:
        assert f">{label}" not in html


def test_a_figure_missing_from_a_recorded_summary_says_so():
    """Absent and zero are different facts about a pass that did run."""
    partial = {k: v for k, v in FULL_SUMMARY.items() if k != "investigations_queued"}
    html = render(_payload(last_result=partial))
    assert _cell(html, "Investigations queued") == \
        '<span class="italic opacity-60">not reported</span>'
    assert _cell(html, "Scanned") == "12"
    assert "no completed pass recorded" not in html


def test_metric_rows_distinguishes_no_run_from_a_run_with_no_figures():
    assert metric_rows(None) is None
    rows = metric_rows({})
    assert [r["value"] for r in rows] == [None] * len(METRICS)


def test_a_zero_figure_survives_the_view_builder():
    rows = metric_rows(dict(FULL_SUMMARY, errors=0))
    assert {r["label"]: r["value"] for r in rows}["Errors"] == 0


def test_the_rows_render_in_the_order_the_module_declares():
    html = render(_payload())
    positions = [html.index(label) for _, label, _n in METRICS]
    assert positions == sorted(positions)


# ---------------------------------------------------------------------------
# The stat tiles
# ---------------------------------------------------------------------------


def test_a_zero_auto_case_count_prints_zero_rather_than_unknown():
    html = _flat(render(_payload(auto_cases_total=0)))
    assert "Total auto-cases" in html
    assert "unknown" not in html
    assert "stat opacity-75" in html


def test_an_unknown_auto_case_count_is_not_printed_as_zero():
    """A count the panel does not have is not a count of zero.

    This also pins the ordering of the dimming test: a bare `> 0` against
    None raises in Jinja, so the guard has to be `is not none and > 0`.
    """
    html = _flat(render(_payload(auto_cases_total=None)))
    assert "unknown" in html
    assert ">0<" not in html


@pytest.mark.parametrize("field,suffix", [
    ("interval_s", "s"), ("window_minutes", "m"),
])
def test_a_zero_interval_or_window_is_a_setting_not_a_blank(field, suffix):
    """0 is a real configured value and `{% if x %}` hides it."""
    html = _flat(render(_payload(**{field: 0})))
    assert f">0{suffix}" in html
    assert "unknown" not in html


@pytest.mark.parametrize("field", ["interval_s", "window_minutes"])
def test_an_unresolvable_interval_or_window_says_unknown(field):
    html = _flat(render(_payload(**{field: None})))
    assert "unknown" in html


@pytest.mark.parametrize("enabled,shown", [
    (True, "Enabled"), (False, "Disabled"), (None, "Unknown"),
])
def test_the_enabled_flag_keeps_three_states(enabled, shown):
    """A truthiness test prints "Disabled" for a flag nobody could read,
    which is a claim about the service rather than about the read."""
    html = _flat(render(_payload(enabled=enabled)))
    assert shown in html
    if enabled is not True:
        assert "text-success" not in html


@pytest.mark.parametrize("flag", ["push_to_kibana", "auto_investigate"])
def test_a_side_effect_gate_that_could_not_be_read_is_not_rendered_as_off(flag):
    """Switching a side-effect off and failing to read whether it is on are
    different facts about a job that attaches alerts to cases."""
    html = _flat(render(_payload(**{flag: None})))
    assert "badge-warning uppercase" in html or "uppercase badge-warning" in html
    assert ">unknown<" in html
    assert html.count(">off<") == 0


@pytest.mark.parametrize("flag", ["push_to_kibana", "auto_investigate"])
def test_a_side_effect_gate_that_is_off_says_off(flag):
    html = _flat(render(_payload(**{flag: False})))
    assert ">off<" in html
    assert ">unknown<" not in html


# ---------------------------------------------------------------------------
# The timestamp
# ---------------------------------------------------------------------------


def test_the_run_timestamp_is_emitted_for_the_viewers_clock():
    """Never formatted on the server.

    The JavaScript called its own relative formatter plus `toLocaleString()`,
    which is the viewer's clock. A server knows only its own, so the macro
    emits `<time datetime>` and static/js/local-time.js rewrites the text.
    """
    html = render(_payload())
    assert '<time datetime="2026-10-12T09:30:00+00:00"' in html
    assert 'data-ts-local="yes"' in html
    assert "ago" not in html


def test_a_grouper_that_has_never_run_says_never_not_the_epoch():
    html = _flat(render(_payload(last_run_at=None, last_result=None)))
    assert "never" in html
    assert "1970" not in html
    assert "<time" not in html


# ---------------------------------------------------------------------------
# A pass that raised
# ---------------------------------------------------------------------------


def test_a_pass_that_raised_is_not_rendered_as_a_quiet_night():
    """`_tick` records zeros plus an `error` message when the pass blew up.

    The JavaScript showed the zeros and dropped the message, so a crash was
    indistinguishable from a shift with nothing to group.
    """
    html = _flat(render(_payload(last_result={
        "scanned": 0, "grouped_new_cases": 0, "grouped_extended_cases": 0,
        "alerts_attached": 0, "investigations_queued": 0, "errors": 1,
        "error": "elasticsearch unreachable",
    })))
    assert "The last pass failed: elasticsearch unreachable" in html
    assert "alert-warning" in html


def test_a_clean_pass_carries_no_failure_note():
    assert error_note(dict(FULL_SUMMARY)) is None
    assert error_note(None) is None
    assert error_note({}) is None
    assert "The last pass failed" not in render(_payload())


# ---------------------------------------------------------------------------
# Escaping, which retires the hand-rolled cgEsc()
# ---------------------------------------------------------------------------


def test_jinja_escapes_what_the_hand_rolled_esc_used_to():
    html = render(_payload(last_result={
        "scanned": "<img src=x onerror=alert(1)>",
        "error": "<script>alert(1)</script>",
    }))
    assert "<script>" not in html
    assert "<img src=x" not in html
    assert "&lt;script&gt;" in html
    assert "&lt;img src=x" in html


# ---------------------------------------------------------------------------
# A failed read is not empty data
# ---------------------------------------------------------------------------


def test_a_failed_read_says_so_and_prints_no_figure_at_all():
    html = _flat(render_failed())
    assert "could not be read" in html
    assert "not the same as a grouper that found nothing" in html
    assert "stat-value" not in html
    assert "Last run" not in html
    assert "Side-effects" not in html
    assert ">0<" not in html


def test_the_route_renders_the_failed_fragment_when_the_read_raises(monkeypatch):
    """A read that fails must not reach the browser as a 500, which htmx does
    not swap, leaving the page's spinner turning as if it were still
    loading."""
    import ion.web.case_grouper_api as api
    from ion.web.ui.case_grouper import case_grouper_status_fragment

    def _boom(session):
        raise RuntimeError("database gone")

    monkeypatch.setattr(api, "status_payload", _boom)
    response = case_grouper_status_fragment(request=_request(), session=None)

    assert response.status_code == 200
    body = response.body.decode()
    assert "could not be read" in body
    assert "stat-value" not in body


def _request() -> Request:
    return Request({"type": "http", "method": "GET",
                    "path": "/ui/case-grouper/status", "headers": [],
                    "query_string": b"", "app": None})


# ---------------------------------------------------------------------------
# One definition: the fragment and the JSON endpoint read the same payload
# ---------------------------------------------------------------------------


def test_the_fragment_renders_the_shared_payload(monkeypatch):
    """Reuse asserted by observation, not by reading the import.

    The two side-effect gates are parsed from the environment inside
    status_payload. A second copy in the fragment would keep rendering "on"
    after the variable flipped, and nothing on the page would look different.
    """
    import ion.web.case_grouper_api as api
    from ion.web.ui.case_grouper import case_grouper_status_fragment

    seen: list[object] = []

    def _fake(session):
        seen.append(session)
        return _payload(auto_cases_total=1234)

    monkeypatch.setattr(api, "status_payload", _fake)
    response = case_grouper_status_fragment(request=_request(),
                                            session="SENTINEL-SESSION")
    assert seen == ["SENTINEL-SESSION"]
    assert "1234" in response.body.decode()


def test_the_json_endpoint_serialises_the_same_payload(monkeypatch):
    """status_payload hands back the datetime; only the JSON route isoformats.

    A template needs the instant so the `ts` macro can label it, and the API
    contract needs the string. Both read every other field from one place.
    """
    import ion.web.case_grouper_api as api

    monkeypatch.setattr(api, "count_auto_cases", lambda session: 7)
    monkeypatch.setattr(api, "get_last_run_info",
                        lambda: (RAN_AT, dict(FULL_SUMMARY)))

    payload = api.status_payload(session=None)
    body = api.status(session=None)

    assert payload["last_run_at"] == RAN_AT
    assert body["last_run_at"] == RAN_AT.isoformat()
    assert {k: v for k, v in body.items() if k != "last_run_at"} == \
           {k: v for k, v in payload.items() if k != "last_run_at"}


# ---------------------------------------------------------------------------
# Wiring: the fragment is not a softer way in than the API it mirrors
# ---------------------------------------------------------------------------


def _dependency_calls(route) -> list:
    out, stack = [], list(getattr(route.dependant, "dependencies", []))
    while stack:
        dep = stack.pop()
        if dep.call is not None:
            out.append(dep.call)
        stack.extend(dep.dependencies)
    return out


def _permissions(route) -> set[str]:
    found = set()
    for fn in _dependency_calls(route):
        if not getattr(fn, "__qualname__", "").startswith("require_permission."):
            continue
        cells = dict(zip(fn.__code__.co_freevars,
                         (c.cell_contents for c in (fn.__closure__ or ()))))
        name = cells.get("permission_name")
        if name:
            found.add(name)
    return found


def test_the_fragment_permission_matches_the_json_endpoint_exactly():
    """Read off both routers rather than asserting a literal, so the test
    fails if either side is changed and the other is not."""
    from ion.web.case_grouper_api import router as api_router
    from ion.web.ui.case_grouper import router as ui_router

    api = [r for r in api_router.routes
           if r.path == "/api/case-grouper/status"]
    ui = [r for r in ui_router.routes if r.path.endswith("/status")]
    assert len(api) == 1 and len(ui) == 1

    assert _permissions(ui[0]), "the fragment requires no permission at all"
    assert _permissions(ui[0]) == _permissions(api[0]) == {"alert:triage"}


def test_the_fragment_does_not_use_a_redirecting_page_dependency():
    """require_page_auth redirects to /login when a session expires, and htmx
    would swap that login form into the middle of the panel."""
    from ion.web.ui.case_grouper import router as ui_router

    for route in ui_router.routes:
        for call in _dependency_calls(route):
            name = getattr(call, "__qualname__", "")
            assert "require_page_auth" not in name
            assert "require_page_permission" not in name


def test_the_module_exposes_a_mounted_router():
    import ion.web.ui as ui

    assert "/ui/case-grouper/status" in {r.path for r in ui.router.routes}


# ---------------------------------------------------------------------------
# The page: the redesign's `server` column, asserted where the work was done
# ---------------------------------------------------------------------------


def test_the_page_builds_no_markup_in_javascript():
    """Counted inside inline `<script>` blocks only, the same way
    tools/ui_redesign_status.py measures it. A bare search of the file would
    hit `hx-swap="innerHTML"`, which is htmx being told where to put
    server-rendered HTML and is the opposite of the thing being removed."""
    page = PAGE.read_text(encoding="utf-8")
    writes = re.findall(r"innerHTML\s*\+?=|insertAdjacentHTML|outerHTML\s*\+?=",
                        _inline_js(page))
    assert writes == []


def test_the_page_holds_an_htmx_slot_rather_than_a_renderer():
    page = PAGE.read_text(encoding="utf-8")
    assert 'hx-get="/ui/case-grouper/status"' in page
    assert 'hx-trigger="load, cg:changed from:body"' in page
    code = _js_code(page)
    for gone in ("cgRender", "cgEsc", "cgFmtTime", "cgLoad"):
        assert gone not in code, f"{gone} survived the conversion"


def test_run_now_re_requests_the_fragment_instead_of_rebuilding_the_panel():
    """The one action that mutates state keeps its POST and then asks the
    server for the panel again, so a row has one definition."""
    js = _inline_js(PAGE.read_text(encoding="utf-8"))
    assert "'/api/case-grouper/run-now'" in js
    assert "new CustomEvent('cg:changed')" in js
    assert "textContent" in js


def test_the_flash_does_not_invent_a_figure_the_run_did_not_report():
    """`sum.scanned||0` printed a confident 0 for an absent key in the only
    line that reports what a manual pass actually did."""
    js = _js_code(PAGE.read_text(encoding="utf-8"))
    assert "||0" not in js.replace(" ", "")
    assert "cgNum(" in js


def test_the_page_controls_sit_outside_the_swap_target():
    """A Refresh button inside the fragment is removed by any render that
    does not include it, so a failed read takes away the retry."""
    page = PAGE.read_text(encoding="utf-8")
    slot = page.index('id="cg-content"')
    assert page.index('id="cg-run-btn"') < slot
    assert page.index('hx-target="#cg-content"') < slot
    assert page.index('id="cg-flash"') < slot
