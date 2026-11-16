"""The investigation queue as a server-rendered fragment.

investigation_queue.html built the three table bodies and each one's empty
state out of template literals and wrote them into `#iq-running-tbody`,
`#iq-completed-tbody` and `#iq-failed-tbody` at six innerHTML sites, with a
hand-rolled iqEscape(), a toLocaleString() formatter and three pill-colour
tables, across 280 lines of inline JavaScript.

Two things the JavaScript got wrong, which are the substance of this file:

* `iqFetch()` caught a failed request and returned
  `{running:[],pending:[],completed:[],failed:[]}`, so a queue nobody could
  read rendered as "No active investigations." with four stat values of 0.
  On a page whose job is to say what the autonomous pipeline is doing,
  "nothing is waiting" and "we could not look" are opposite instructions.
* `iqLoadLoopStatus()` returned silently on a non-OK response, leaving the
  button reading "Pause loop", which asserts the loop is running.

Rows are fixtures rather than live data: the dev database's queue is empty,
and an empty render proves nothing about the row, which is all that moved.
"""
from __future__ import annotations

import json
import re
from enum import Enum
from pathlib import Path
from typing import Any

import pytest

from ion.web.templating import make_templates
from ion.web.ui.investigation_queue import (
    _PERM,
    _TRIAGE_PERM,
    _duration,
    _jobs_view,
    router,
)

FRAGMENT = "_fragments/investigation_queue.html"
PAGE = (
    Path(__file__).resolve().parents[2]
    / "src/ion/web/templates/investigation_queue.html"
)


def flat(html: str) -> str:
    """Whitespace collapsed, because the template wraps its sentences.

    A prose assertion against the raw render fails on the line break Jinja
    kept, and the obvious fix is to shorten the sentence in the template
    until the test passes, which is the test dictating the wording.
    """
    return re.sub(r"\s+", " ", html)


def render(**ctx: Any) -> str:
    env = make_templates().env
    base = {
        "jobs": None,
        "jobs_failed": False,
        "loop_paused": False,
        "can_triage": True,
    }
    base.update(ctx)
    return env.get_template(FRAGMENT).render(**base)


def _inv(**over: Any) -> dict:
    """One row shaped like investigation_jobs_payload() emits it.

    The payload is `InvestigationSummary.model_dump()`, so the timestamps
    arrive as ISO strings and the enum-backed columns as whatever the ORM
    handed over, exactly as the JSON endpoint's caller sees them.
    """
    base = {
        "id": 77,
        "alert_id_ref": "7c4fd2abc1234567890deadbeef",
        "alert_signature": "Suspicious PowerShell Execution",
        "host": "WS-014",
        "source_ip": "10.1.2.3",
        "user_name": "jdoe",
        "status": "running",
        "verdict": None,
        "severity_assessment": None,
        "summary_text": None,
        "llm_model_used": None,
        "tokens_used": None,
        "duration_ms": None,
        "prompt_template_id": None,
        "created_at": "2026-10-12T08:30:11+00:00",
        "completed_at": None,
        "recommended_actions": None,
        "ioc_snapshot": None,
    }
    base.update(over)
    return base


def jobs(
    running: list[dict] | None = None,
    pending: list[dict] | None = None,
    completed: list[dict] | None = None,
    failed: list[dict] | None = None,
    *,
    can_triage: bool = True,
) -> dict:
    return _jobs_view(
        {
            "running": running or [],
            "pending": pending or [],
            "completed": completed or [],
            "failed": failed or [],
        },
        can_triage=can_triage,
    )


# ---------------------------------------------------------------------------
# An empty queue and an unreadable queue, which this page must never confuse
# ---------------------------------------------------------------------------


def test_an_empty_queue_says_nothing_is_waiting():
    html = flat(render(jobs=jobs()))
    assert "No active investigations." in html
    assert "No completed investigations yet." in html
    assert "No recent failures." in html


def test_a_failed_read_is_not_an_empty_queue():
    """The claim that ends a shift. `iqFetch()`'s catch returned four empty
    arrays, so every failed request rendered as a quiet, idle pipeline."""
    html = flat(render(jobs=None, jobs_failed=True))
    assert "could not be read" in html
    assert "not an empty queue" in html
    assert "No active investigations." not in html
    assert "No completed investigations yet." not in html
    assert "No recent failures." not in html


def test_a_failed_read_prints_no_count_at_all():
    """A queue depth of 0 is a measurement. A depth nobody read is not, and
    `(data.running || []).length` on a failed fetch reported the second as
    the first in all four stat values."""
    html = render(jobs=None, jobs_failed=True)
    assert "not a depth of zero" in flat(html)
    assert "stat-value" not in html
    assert ">0<" not in html


def test_a_zero_depth_is_a_measurement_not_an_unknown():
    """The good news this page exists to deliver. Truthiness renders it as
    "Unknown", which reads as a failure."""
    html = render(jobs=jobs())
    assert re.search(r'class="stat-value[^"]*">\s*0\s*<', html)
    assert "Unknown" not in html


def test_the_depths_are_the_lengths_of_the_four_buckets():
    view = jobs(
        running=[_inv(id=1)],
        pending=[_inv(id=2), _inv(id=3)],
        completed=[_inv(id=4, status="completed")],
        failed=[],
    )
    assert view["counts"] == {
        "running": 1, "pending": 2, "completed": 1, "failed": 0,
    }


def test_running_and_pending_share_one_table_running_first():
    """The JavaScript spread running before pending into one array, so a
    running job is never below a job that has not started."""
    view = jobs(running=[_inv(id=1)], pending=[_inv(id=2, status="pending")])
    assert [row["id"] for row in view["active"]] == [1, 2]


# ---------------------------------------------------------------------------
# The sweep loop: paused, running, or a state nobody could read
# ---------------------------------------------------------------------------


def test_a_paused_loop_says_new_investigations_are_not_being_queued():
    html = flat(render(jobs=jobs(), loop_paused=True))
    assert "New investigations will not be auto-queued until you resume." in html
    assert "Resume loop" in html
    assert "Pause loop" not in html


def test_a_running_loop_offers_the_pause_verb():
    html = flat(render(jobs=jobs(), loop_paused=False))
    assert "Sweep loop is running." in html
    assert "Pause loop" in html
    assert "Resume loop" not in html


def test_an_unreadable_loop_state_is_neither_paused_nor_running():
    """The branch a truthiness port loses. `if (data.paused)` treats a read
    that never happened as a loop that is running, which is this page
    telling an analyst the pipeline is working when it does not know.

    Mutating `is true` to truthiness changes nothing here while `is false`
    still catches None, so the middle branch is the one that carries it.
    """
    html = flat(render(jobs=jobs(), loop_paused=None))
    assert "sweep-loop state could not be read" in html
    assert "Sweep loop is running." not in html
    assert "Pause loop" not in html
    assert "Resume loop" not in html


def test_an_unreadable_loop_state_does_not_cost_the_analyst_the_queue():
    html = flat(render(jobs=jobs(running=[_inv()]), loop_paused=None))
    assert "sweep-loop state could not be read" in html
    assert "Suspicious PowerShell Execution" in html


def test_an_unreadable_queue_does_not_hide_the_loop_state():
    html = flat(render(jobs=None, jobs_failed=True, loop_paused=True))
    assert "New investigations will not be auto-queued until you resume." in html
    assert "not an empty queue" in html


def test_the_loop_toggle_is_withheld_from_a_viewer_who_cannot_triage():
    """pause and resume take alert:triage; this fragment takes alert:read.
    A read-only analyst offered the button learns the server refuses by
    clicking it."""
    for paused in (True, False):
        html = flat(render(jobs=jobs(), loop_paused=paused, can_triage=False))
        assert "Pause loop" not in html
        assert "Resume loop" not in html
        assert "iqSetLoop" not in html


# ---------------------------------------------------------------------------
# The per-row Cancel button, derived from what cancel_one actually accepts
# ---------------------------------------------------------------------------


def test_the_cancellable_statuses_are_the_services_own():
    """The button must not be a second copy of the rule. cancel_one's UPDATE
    is bound to this tuple, so a status added to one is added to both."""
    from ion.web.investigation_api import CANCELLABLE_STATUSES

    assert set(CANCELLABLE_STATUSES) == {"pending", "running"}


@pytest.mark.parametrize("status,expected", [
    ("pending", True),
    ("running", True),
    ("completed", False),
    ("failed", False),
    ("cancelled", False),
    (None, False),
])
def test_cancel_is_offered_only_for_a_status_the_service_would_cancel(
    status, expected
):
    view = jobs(running=[_inv(status=status)])
    assert view["active"][0]["can_cancel"] is expected


def test_cancel_is_withheld_from_a_viewer_who_cannot_triage():
    view = jobs(running=[_inv(status="running")], can_triage=False)
    assert view["active"][0]["can_cancel"] is False


def test_a_cancellable_row_renders_the_button():
    html = render(jobs=jobs(running=[_inv(status="running")]))
    assert "iqCancelOne" in html
    assert "data-args='[77]'" in html


def test_a_terminal_row_renders_no_cancel_button():
    html = render(jobs=jobs(completed=[_inv(status="completed")]))
    assert "iqCancelOne" not in html


def test_the_cancel_button_carries_parseable_args():
    """The delegated listener JSON.parses data-args and bails on a parse
    error, which leaves a button that looks live and does nothing."""
    html = render(jobs=jobs(running=[_inv(status="pending")]))
    args = re.findall(r"data-args='([^']*)'", html)
    assert args, "no delegated action rendered"
    for raw in args:
        parsed = json.loads(raw.replace("&#34;", '"'))
        assert isinstance(parsed, list)


# ---------------------------------------------------------------------------
# Numbers: `is not none`, never truthiness
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("ms,expected", [
    (0, "0 ms"),
    (1, "1 ms"),
    (999, "999 ms"),
    (1000, "1.0s"),
    (1500, "1.5s"),
    (59999, "60.0s"),
    (90000, "1m 30s"),
    (None, None),
])
def test_a_duration_is_formatted_the_way_the_javascript_formatted_it(
    ms, expected
):
    assert _duration(ms) == expected


def test_a_zero_duration_is_a_measurement():
    """An investigation that returned instantly is the interesting case: it
    means the model answered from cache or refused. Truthiness renders it as
    a duration nobody recorded."""
    html = flat(render(jobs=jobs(completed=[_inv(duration_ms=0)])))
    assert "0 ms" in html
    assert "not recorded" not in html


def test_an_unrecorded_duration_says_so_rather_than_printing_zero():
    html = flat(render(jobs=jobs(completed=[_inv(duration_ms=None)])))
    assert "not recorded" in html
    assert "0 ms" not in html


# ---------------------------------------------------------------------------
# Timestamps: the viewer's clock, never the server's
# ---------------------------------------------------------------------------


def test_the_timestamps_go_through_the_time_macro():
    """toLocaleString() is the viewer's clock. A server knows only its own,
    so a server-formatted timestamp is wrong for every analyst in another
    timezone."""
    html = render(jobs=jobs(
        running=[_inv()],
        completed=[_inv(status="completed", completed_at="2026-10-12T09:00:00+00:00")],
        failed=[_inv(status="failed", completed_at="2026-10-12T09:05:00+00:00")],
    ))
    assert html.count("<time datetime=") == 3
    assert 'data-ts-local="yes"' in html
    assert "2026-10-12" in html


def test_a_row_with_no_timestamp_says_so_rather_than_showing_the_epoch():
    html = flat(render(jobs=jobs(running=[_inv(created_at=None)])))
    assert "at an unrecorded time" in html
    assert "1970" not in html


def test_a_failed_row_falls_back_to_when_it_was_queued():
    """A row that failed before completed_at was stamped still has a
    created_at, and the JavaScript used it. Dropping the fallback would
    print "at an unrecorded time" on the rows most worth a timestamp."""
    view = jobs(failed=[_inv(status="failed", completed_at=None,
                             created_at="2026-10-12T08:30:11+00:00")])
    assert view["failed"][0]["when"] == "2026-10-12T08:30:11+00:00"


def test_a_failed_row_prefers_the_completion_time_when_it_has_one():
    view = jobs(failed=[_inv(status="failed",
                             completed_at="2026-10-12T09:05:00+00:00",
                             created_at="2026-10-12T08:30:11+00:00")])
    assert view["failed"][0]["when"] == "2026-10-12T09:05:00+00:00"


# ---------------------------------------------------------------------------
# The pills, and what the hand-rolled iqEscape() used to do
# ---------------------------------------------------------------------------


def test_the_status_pill_keeps_its_colour():
    html = render(jobs=jobs(running=[_inv(status="running")]))
    assert "iq-pill-running" in html
    assert ">running<" in html


def test_an_unknown_status_falls_back_rather_than_rendering_no_class():
    html = render(jobs=jobs(running=[_inv(status="quiesced")]))
    assert "iq-pill-pending" in html
    assert "quiesced" in html


def test_a_missing_status_is_named_rather_than_left_blank():
    html = flat(render(jobs=jobs(running=[_inv(status=None)])))
    assert "unknown" in html


def test_the_verdict_pill_keeps_its_colour():
    html = render(jobs=jobs(completed=[_inv(status="completed",
                                            verdict="false_positive")]))
    assert "iq-pill-fp" in html
    assert "false positive" in html


def test_a_completed_row_without_a_verdict_says_none_was_recorded():
    """`iqVerdictPill(null)` rendered an inconclusive-coloured dash, which
    claims the model reached a conclusion it never reached."""
    html = flat(render(jobs=jobs(completed=[_inv(status="completed",
                                                 verdict=None)])))
    assert "no verdict recorded" in html
    assert "iq-pill-inc" not in html


def test_the_severity_pill_keeps_its_colour():
    html = render(jobs=jobs(completed=[_inv(status="completed",
                                            severity_assessment="critical")]))
    assert "iq-pill-sev-critical" in html
    assert "critical" in html


def test_an_unassessed_severity_is_not_rendered_as_a_low_one():
    """`iqSeverityPill(null)` fell back to iq-pill-sev-low, so an
    investigation that assessed nothing looked like one that assessed the
    risk as low."""
    html = flat(render(jobs=jobs(completed=[_inv(status="completed",
                                                 severity_assessment=None)])))
    assert "not assessed" in html
    assert "iq-pill-sev-low" not in html


class _Status(str, Enum):
    RUNNING = "running"


class _Severity(str, Enum):
    HIGH = "high"


def test_a_pill_reads_the_enum_value_not_its_repr():
    """status, verdict and severity_assessment each feed a colour-map lookup
    and visible text at once. All three are String columns today, so the
    unwrap is routed through ui._shared.plain rather than relied on: if one
    is tightened to SQLEnum, value equality keeps the colour right while the
    pill reads "_Status.RUNNING", which is the failure that survives a
    glance."""
    html = render(jobs=jobs(
        running=[_inv(status=_Status.RUNNING)],
        completed=[_inv(status="completed", severity_assessment=_Severity.HIGH)],
    ))
    assert "_Status" not in html
    assert "_Severity" not in html
    assert "iq-pill-running" in html
    assert "iq-pill-sev-high" in html
    assert ">running<" in html


def test_jinja_escapes_what_the_hand_rolled_iqescape_used_to():
    """iqEscape() was five chained .replace() calls. This replaces it."""
    html = render(jobs=jobs(running=[_inv(
        alert_signature="<script>alert(1)</script>",
        host="<img src=x onerror=1>",
        user_name="</td><td>injected",
    )]))
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
    assert "<img src=x" not in html
    assert "</td><td>injected" not in html


def test_the_alert_reference_is_truncated_but_still_recoverable():
    """The JavaScript sliced to 16 characters and dropped the rest, so the
    id the manual-trigger box wants could not be copied off the row."""
    html = render(jobs=jobs(running=[_inv()]))
    assert "7c4fd2abc1234567" in html
    assert 'title="7c4fd2abc1234567890deadbeef"' in html


def test_a_long_summary_is_truncated_with_the_whole_text_in_the_title():
    long = "x" * 400
    html = render(jobs=jobs(completed=[_inv(status="completed",
                                            summary_text=long)]))
    assert "x" * 240 in html
    assert "x" * 241 not in re.sub(r'title="[^"]*"', "", html)


def test_a_failed_rows_error_text_is_given_more_room_than_a_summary():
    """A failure's summary_text is the error, and the JavaScript kept 400
    characters of it rather than 240 for exactly that reason."""
    long = "y" * 500
    html = render(jobs=jobs(failed=[_inv(status="failed", summary_text=long)]))
    assert "y" * 400 in html


# ---------------------------------------------------------------------------
# The route, which is what selects a state
# ---------------------------------------------------------------------------


def _call_route(monkeypatch, **patches) -> str:
    """The route itself, with its reads stubbed.

    The template tests above render each state directly, which proves the
    markup and says nothing about whether the route ever selects it. An
    except-handler that returned four empty lists with `jobs_failed=False`
    would be exactly the JavaScript's defect and would leave every test
    above green.
    """
    from starlette.requests import Request

    from ion.web.ui import investigation_queue as mod

    for name, value in patches.items():
        monkeypatch.setattr(mod, name, value)

    request = Request({
        "type": "http", "method": "GET", "path": "/ui/investigation-queue",
        "headers": [], "query_string": b"", "scheme": "http",
        "server": ("testserver", 80), "root_path": "",
    })

    class _Viewer:
        id = 9

        def has_permission(self, name: str) -> bool:
            return name == _TRIAGE_PERM

    return mod.investigation_queue_fragment(
        request=request, user=_Viewer(), session=object(),
    ).body.decode("utf-8")


def _empty_payload() -> dict:
    return {"running": [], "pending": [], "completed": [], "failed": []}


def test_the_route_renders_the_queue_when_both_reads_succeed(monkeypatch):
    """The positive control. Without it the two failure tests below pass for
    a route that only ever renders a failure."""
    html = flat(_call_route(
        monkeypatch,
        investigation_jobs_payload=lambda: {
            **_empty_payload(), "running": [_inv()],
        },
        sweep_loop_paused=lambda session: False,
    ))
    assert "Suspicious PowerShell Execution" in html
    assert "Sweep loop is running." in html
    assert "could not be read" not in html


def test_the_route_renders_the_failure_state_when_the_queue_read_raises(
    monkeypatch
):
    """htmx does not swap a non-2xx body, so a route that raised would leave
    the loading spinner's generic alert rather than the wording that says
    what is and is not known."""
    def boom():
        raise RuntimeError("the jobs query failed")

    html = flat(_call_route(
        monkeypatch,
        investigation_jobs_payload=boom,
        sweep_loop_paused=lambda session: False,
    ))
    assert "not an empty queue" in html
    assert "not a depth of zero" in html
    assert "No active investigations." not in html


def test_the_route_renders_the_unknown_loop_state_when_that_read_raises(
    monkeypatch
):
    def boom(session):
        raise RuntimeError("the flag read failed")

    html = flat(_call_route(
        monkeypatch,
        investigation_jobs_payload=_empty_payload,
        sweep_loop_paused=boom,
    ))
    assert "sweep-loop state could not be read" in html
    assert "Sweep loop is running." not in html


def test_the_two_reads_fail_independently(monkeypatch):
    """One try block around both would turn a flag-table hiccup into "the
    queue could not be read", and the queue is the page."""
    def boom(session):
        raise RuntimeError("the flag read failed")

    html = flat(_call_route(
        monkeypatch,
        investigation_jobs_payload=lambda: {
            **_empty_payload(), "running": [_inv()],
        },
        sweep_loop_paused=boom,
    ))
    assert "Suspicious PowerShell Execution" in html
    assert "not an empty queue" not in html


def test_the_route_asks_the_viewer_rather_than_assuming_triage(monkeypatch):
    """can_triage comes off the authenticated user, so a read-only analyst
    is not offered a button pause/resume and cancel would refuse."""
    class _ReadOnly:
        id = 9

        def has_permission(self, name: str) -> bool:
            return False

    from starlette.requests import Request

    from ion.web.ui import investigation_queue as mod

    monkeypatch.setattr(mod, "investigation_jobs_payload",
                        lambda: {**_empty_payload(),
                                 "running": [_inv(status="running")]})
    monkeypatch.setattr(mod, "sweep_loop_paused", lambda session: False)
    request = Request({
        "type": "http", "method": "GET", "path": "/ui/investigation-queue",
        "headers": [], "query_string": b"", "scheme": "http",
        "server": ("testserver", 80), "root_path": "",
    })
    html = mod.investigation_queue_fragment(
        request=request, user=_ReadOnly(), session=object(),
    ).body.decode("utf-8")
    assert "iqCancelOne" not in html
    assert "iqSetLoop" not in html


# ---------------------------------------------------------------------------
# Permission, and the payload both callers share
# ---------------------------------------------------------------------------


def _permission_of(route) -> str | None:
    stack, out = list(route.dependant.dependencies), None
    while stack:
        dep = stack.pop()
        fn = dep.call
        if getattr(fn, "__qualname__", "").startswith("require_permission."):
            cells = dict(zip(fn.__code__.co_freevars,
                             (c.cell_contents for c in (fn.__closure__ or ()))))
            out = cells.get("permission_name")
        stack.extend(dep.dependencies)
    return out


def _api_permission(path: str, method: str) -> str | None:
    from ion.web.investigation_api import router as api_router

    for route in api_router.routes:
        if route.path == path and method in route.methods:
            return _permission_of(route)
    raise AssertionError(f"no {method} {path} route to read a permission off")


def test_the_fragment_permission_matches_the_json_endpoint():
    """Read off the live route rather than restated here, so the fragment
    cannot stay on alert:read while /api/investigate/jobs moves."""
    assert _api_permission("/api/investigate/jobs", "GET") == _PERM
    assert [_permission_of(r) for r in router.routes] == [_PERM]


def test_the_fragment_is_not_a_softer_way_in_than_the_endpoint():
    assert _PERM == "alert:read"
    assert _PERM != _TRIAGE_PERM


def test_the_triage_permission_is_the_one_the_mutations_take():
    """The buttons the fragment withholds are withheld on the permission the
    server would really check, not on a guess."""
    for path in ("/api/investigate/loop/pause",
                 "/api/investigate/loop/resume",
                 "/api/investigate/jobs/{inv_id}/cancel"):
        assert _api_permission(path, "POST") == _TRIAGE_PERM, path


def test_the_json_endpoint_and_the_fragment_share_one_payload():
    from ion.web import investigation_api

    assert hasattr(investigation_api, "investigation_jobs_payload")
    assert hasattr(investigation_api, "sweep_loop_paused")


def test_the_queue_has_no_per_caller_scope_to_reimplement():
    """Checked rather than assumed. /api/investigate/jobs filters on status
    and nothing else, so every analyst holding alert:read sees the whole
    queue, and a filter invented in the fragment would hide rows the API
    returns. If a scope is ever added to the payload this fails, which is
    the point: the fragment must then pick it up rather than drift.
    """
    import inspect

    from ion.web import investigation_api

    source = inspect.getsource(investigation_api.investigation_jobs_payload)
    assert "user" not in source
    assert "triggered_by" not in source
    assert list(
        inspect.signature(investigation_api.investigation_jobs_payload).parameters
    ) == []


# ---------------------------------------------------------------------------
# The page shell
# ---------------------------------------------------------------------------


def _page_js() -> str:
    src = PAGE.read_text(encoding="utf-8")
    return "".join(
        re.findall(r"<script(?![^>]*src=)[^>]*>(.*?)</script>", src, re.S)
    )


def _page_code() -> str:
    """The page's inline JavaScript with its comments removed.

    The comments name the helpers that were deleted and the fetch that no
    longer happens, which is the point of them, so a test for those names
    has to read the code rather than the prose about it.
    """
    return re.sub(r"//[^\n]*", "", _page_js())


def test_the_page_builds_no_markup_in_javascript():
    """The `server` column, measured the way tools/ui_redesign_status.py
    does. Scoped to the inline script bodies: `hx-swap="innerHTML"` is an
    attribute telling htmx where to put server-rendered markup, which is the
    opposite of the thing being removed."""
    js = _page_js()
    assert js.strip(), "no inline script found, so this proves nothing"
    assert not re.findall(
        r"innerHTML\s*\+?=|insertAdjacentHTML|outerHTML\s*\+?=", js
    )


def test_the_page_requests_the_fragment_on_load():
    src = PAGE.read_text(encoding="utf-8")
    assert 'hx-get="/ui/investigation-queue"' in src
    assert 'hx-trigger="load"' in src


def test_the_page_carries_no_second_copy_of_the_servers_tables():
    js = _page_code()
    assert "function iqEscape" not in js, "Jinja autoescapes"
    assert "toLocaleString" not in js, "the ts macro is the viewer's clock"
    assert "iqVerdictPill" not in js, "the pill maps live in the fragment"
    assert "iqSeverityPill" not in js
    assert "iqStatusPill" not in js
    assert "iqFmtDuration" not in js
    assert "No active investigations" not in js, "the empty state is the server's"


def test_the_page_writes_no_htmx_error_handler_of_its_own():
    """static/js/htmx-errors.js is the one definition of what a failed
    fragment request means, including what an expired session means."""
    src = PAGE.read_text(encoding="utf-8")
    assert "htmx:responseError" not in src
    assert "htmx:sendError" not in src


def test_the_controls_sit_outside_the_swap_target():
    """A render that says the read failed must not remove the control that
    retries it, or a page reload is the only way back."""
    src = PAGE.read_text(encoding="utf-8")
    target = src.index('id="iq-content"')
    assert src.index("Refresh") < target
    assert src.index("iq-manual-form") < target


@pytest.mark.parametrize("path_attr", ["PAGE", "FRAGMENT"])
def test_no_htmx_feature_that_compiles_a_string(path_attr):
    """ION serves script-src with no unsafe-eval, so anything htmx hands to
    Function() throws and the feature silently does nothing. One converted
    page shipped a dead Enter key this way."""
    if path_attr == "PAGE":
        src = PAGE.read_text(encoding="utf-8")
    else:
        src = (
            PAGE.parent / "_fragments/investigation_queue.html"
        ).read_text(encoding="utf-8")
    assert "hx-on" not in src
    assert "js:" not in src
    assert not re.search(r"hx-trigger=\"[^\"]*\[", src)


def test_the_loop_toggle_no_longer_reads_the_state_before_flipping():
    """iqTogglePause() fetched /loop/status, decided the verb from the
    answer and then posted. The server renders the verb now, so the race
    between the read and the flip is gone with it."""
    js = _page_code()
    assert "loop/status" not in js
    assert "iqSetLoop" in js


MUTATIONS = ("iqRunSweep", "iqManualSubmit", "iqCancelAllPending",
             "iqCancelOne", "iqSetLoop")


def test_every_mutation_re_requests_the_fragment():
    """Each one used to call iqLoad(), which rebuilt the three table bodies
    from strings. They are still mutations; what changed is the aftermath.

    Counted rather than searched per function: one definition plus one call
    from each handler. A handler that patched the DOM itself instead would
    leave the count short.
    """
    js = _page_js()
    assert "iqLoad" not in js
    for handler in MUTATIONS:
        assert "function " + handler in js, handler
    assert js.count("refreshInvestigationQueue") == len(MUTATIONS) + 2, (
        "expected one definition, one call per mutation, and the live-updates "
        "callback"
    )
