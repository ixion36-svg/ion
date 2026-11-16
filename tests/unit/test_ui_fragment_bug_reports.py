"""The /bug-reports list fragment: the replacement for three innerHTML sites.

bug_reports.html built its table, its empty state and its load-failure
message from JavaScript string concatenation, with a hand-rolled `esc()` and
a hand-rolled date formatter. That is the shape the redesign's `server`
column exists to remove: markup assembled in JavaScript cannot be restyled
from the stylesheet, so every such site is a place a sweep silently fails to
reach.

These tests render the fragment directly with fixture data. The dev database
has no bug reports, so an empty render proves nothing about the table, which
is the bulk of what moved. Each case is one the old JavaScript either got
right and must keep, or got wrong.
"""
from __future__ import annotations

from typing import Any

import pytest

from ion.models.service_desk import BugReportSeverity, BugReportStatus
from ion.web.templating import make_templates
from ion.web.ui.bug_reports import _fmt_dt, _rows

FRAGMENT = "_fragments/bug_reports.html"


def render(reports: Any, failed: bool = False, status: str = "all",
           mine: bool = False) -> str:
    env = make_templates().env
    return env.get_template(FRAGMENT).render(
        reports=reports, failed=failed, status=status, mine=mine,
    )


def _report(**over: Any) -> dict:
    base = {
        "id": 7,
        "title": "Alerts page spins forever",
        "severity": "high",
        "component": "/alerts",
        "status": "open",
        "gitlab_issue_iid": 42,
        "gitlab_issue_url": "https://gitlab.example/ion/-/issues/42",
        "gitlab_state": "opened",
        "gitlab_error": None,
        "reported_by_username": "analyst",
        "created_at": "2026-10-12T09:30:11",
    }
    base.update(over)
    return _rows([base])[0]


# ---------------------------------------------------------------------------
# The table, which is what actually moved
# ---------------------------------------------------------------------------


def test_a_report_renders_its_row():
    html = render([_report()])
    assert "Alerts page spins forever" in html
    assert "/alerts" in html
    assert "analyst" in html
    assert "ion-c-amber" in html, "high severity keeps its amber pill"
    assert "2026-10-12 09:30" in html


def test_a_severity_from_the_orm_renders_its_value_not_its_repr():
    """The column is SQLEnum(BugReportSeverity), so a row read through the
    ORM carries the enum member, not the string the JSON endpoint showed.
    On Python 3.11+ `str()` of a str-mixin enum is "BugReportSeverity.HIGH",
    so an unnormalised port prints the class name into the pill and misses
    the colour lookup, both of which the JavaScript got right for free
    because it read JSON."""
    html = render([_report(severity=BugReportSeverity.HIGH,
                           status=BugReportStatus.IN_PROGRESS)])
    assert "BugReportSeverity" not in html
    assert "BugReportStatus" not in html
    assert ">high<" in html
    assert ">in_progress<" in html
    assert "ion-c-amber" in html, "the colour lookup needs the plain value"
    assert "ion-c-cyan" in html


def test_a_zero_issue_iid_still_gets_its_sync_button():
    """`is not none`, not truthiness, for a number.

    A GitLab iid of 0 is unusual, but the rule is the point: the only thing
    that means "no linked issue" is None, and a truthiness test folds 0 in
    with it, hiding the Sync button on a row that has an issue to sync.
    """
    html = render([_report(gitlab_issue_iid=0)])
    assert 'data-click-action="syncBug"' in html
    assert "#0" in html


def test_an_unlinked_report_has_no_sync_button():
    html = render([_report(gitlab_issue_iid=None, gitlab_issue_url=None,
                           gitlab_error="GitLab not configured")])
    assert 'data-click-action="syncBug"' not in html
    assert "GitLab not configured" in html


def test_jinja_escapes_what_the_hand_rolled_esc_used_to():
    """The template carried its own `esc()` over every interpolated field.
    Jinja autoescapes, which retires it; this proves the replacement
    actually escapes."""
    html = render([_report(title="<script>alert(1)</script>")])
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_no_reports_is_an_empty_queue_not_a_failure():
    html = render([])
    assert "No bug reports." in html
    assert "could not be read" not in html


def test_a_failed_read_says_so_and_keeps_its_escape_hatch():
    """"Nothing filed" and "we could not look" lead to opposite actions, so
    the fragment must never render the empty-table wording for a failure.

    The filters and the Refresh button are chrome, so they wrap both states.
    With the error as a bare alert, a filter change that failed swapped the
    filters away and left the panel with no way to change the filter back or
    retry, short of reloading the page.
    """
    html = render(None, failed=True)
    assert "could not be read" in html
    assert "not an empty" in html
    assert "No bug reports." not in html
    assert 'id="bug-filters"' in html, "the filters must survive a failure"
    assert "Refresh" in html, "a failed read needs a retry on screen"


# ---------------------------------------------------------------------------
# The filters, which used to be two JavaScript handlers
# ---------------------------------------------------------------------------


def test_the_filters_are_an_htmx_request_not_a_javascript_handler():
    html = render([_report()])
    assert 'data-change-action="loadBugs"' not in html
    assert 'hx-get="/ui/bug-reports"' in html
    assert 'hx-target="#bugs-content"' in html


def test_the_filter_bar_is_what_every_reload_goes_through():
    """Submitting or syncing a report fires `bugs:changed` on the body, and
    this bar is what listens, because it is the only element that knows
    which filters are on screen. Drop the trigger and a filed report stops
    appearing until the page is reloaded by hand, with nothing to see in the
    template to say why.
    """
    html = render([_report()])
    assert "bugs:changed from:body" in html
    assert "click from:#bugs-refresh" in html
    assert 'hx-include="#bug-filters"' in html


@pytest.mark.parametrize("status", ["all", "open", "in_progress", "resolved",
                                    "closed"])
def test_the_status_filter_comes_back_selected(status):
    """The select is inside the swapped fragment, so its state lives on the
    server. Rendered without the echo, every swap resets the filter to All
    while the rows stay filtered, which reads as a broken table."""
    html = render([], status=status)
    assert f'value="{status}" selected' in html


def test_only_mine_comes_back_checked():
    assert "checked" in render([], mine=True)
    assert "checked" not in render([], mine=False)


# ---------------------------------------------------------------------------
# The date formatter, ported from a try/catch
# ---------------------------------------------------------------------------


def test_fmt_dt_matches_what_the_javascript_printed():
    assert _fmt_dt("2026-10-12T09:30:11") == "2026-10-12 09:30"


def test_fmt_dt_shows_an_unparseable_value_raw():
    """The JavaScript's catch returned the raw string, so an odd value showed
    something odd rather than an empty cell that reads as "never"."""
    assert _fmt_dt("not a date") == "not a date"


@pytest.mark.parametrize("raw", [None, ""])
def test_fmt_dt_is_empty_when_there_is_no_timestamp(raw):
    assert _fmt_dt(raw) == ""


def test_rows_adds_the_display_fields_without_touching_the_payload():
    """The payload dicts are the JSON endpoint's own shape. _rows must add to
    a copy, or the fragment's formatting would leak into the API response if
    the two ever shared a call."""
    source = {"id": 1, "created_at": "2026-10-12T09:30:11"}
    rows = _rows([source])
    assert rows[0]["created_display"] == "2026-10-12 09:30"
    assert "created_display" not in source
