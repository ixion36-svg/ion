"""The analytics job panels as fragments.

All eleven panels on analytics.html opened with the same line:

    if (!job || !job.result) { container.innerHTML =
        '<div class="empty-state">No data yet. Click "Run All Jobs" to
        generate.</div>'; return; }

That is three situations in one sentence. The job type is not registered;
the job is registered and has never run; and the job has run and stored a
result the page cannot read. Only the middle one is answered by clicking
Run All Jobs.

Each panel then collapsed the next outcome the same way, `job.result.rules
|| []`, and rendered a reassurance for it. "No stale investigations found.
All items have recent activity" is a sentence an analyst stops reading on,
and an unparseable payload produced it.
"""
from __future__ import annotations

import re
from html import unescape
from pathlib import Path

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from ion.web.ui.analytics import PERMISSION, STALE_DANGER_DAYS, router

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "src/ion/web/templates/analytics.html"

URL = "/ui/analytics/stale"


class _User:
    id = 1
    username = "analytics-tester"

    def __init__(self, *permissions):
        self.permissions = set(permissions)

    def has_permission(self, name):
        return name in self.permissions


def _app(user):
    from ion.auth.dependencies import get_current_user
    from ion.storage.database import get_db_session

    application = FastAPI()
    application.include_router(router, prefix="/ui")
    application.dependency_overrides[get_current_user] = lambda: user
    application.dependency_overrides[get_db_session] = lambda: None
    return application


def _get(user, accept=None):
    headers = {"accept": accept} if accept else None
    with TestClient(_app(user)) as client:
        return client.get(URL, headers=headers)


def _reader():
    return _User(PERMISSION)


@pytest.fixture
def job(monkeypatch):
    def set(payload=None, raises=None):
        def handler(job_type, current_user=None, session=None):
            if raises is not None:
                raise raises
            return payload

        monkeypatch.setattr(
            "ion.web.analytics_api.get_analytics_job", handler)

    return set


def flat(html: str) -> str:
    return " ".join(unescape(re.sub(r"<[^>]+>", " ", html)).split())


def _case(**over):
    c = {"case_number": "CASE-7", "title": "beaconing",
         "severity": "high", "assigned_to": "lyndon",
         "last_activity": "2026-09-01T10:30:00", "days_stale": 12}
    c.update(over)
    return c


def _job(result="default", **over):
    j = {"job_type": "stale_investigations",
         "display_name": "Stale Investigations",
         "last_run_at": "2026-09-01T10:30:00", "last_error": None,
         "result": {"stale_cases": [_case()], "stale_alerts": []}
         if result == "default" else result}
    j.update(over)
    return j


# ---------------------------------------------------------------------------
# Gate
# ---------------------------------------------------------------------------


def test_the_panel_needs_the_pages_permission(job):
    """The page and the read endpoints take alert:read, and so does this
    fragment. A viewer without it is refused."""
    job(payload=_job())
    assert _get(_User()).status_code == 403
    assert _get(_reader()).status_code == 200


# ---------------------------------------------------------------------------
# One sentence became four
# ---------------------------------------------------------------------------


def test_a_job_type_that_is_not_registered_says_so(job):
    """The endpoint raises 404 for it, and clicking Run All Jobs will not
    help: there is nothing to run."""
    job(raises=HTTPException(status_code=404, detail="Job not found"))
    body = flat(_get(_reader()).text)
    assert "not registered" in body
    assert "Run All Jobs" not in body


def test_a_job_that_has_never_run_is_the_one_run_all_jobs_answers(job):
    job(payload=_job(result=None))
    body = flat(_get(_reader()).text)
    assert "Run All Jobs" in body
    assert "cannot read" not in body


@pytest.mark.parametrize("result", ["oops", 7, ["list"]])
def test_a_result_that_is_not_a_mapping_says_it_cannot_be_read(job, result):
    """Distinct from never having run, because this one is a bug to look
    at rather than a button to press."""
    job(payload=_job(result=result))
    body = flat(_get(_reader()).text)
    assert "cannot read" in body, result
    assert "Run All Jobs" not in body, result


def test_an_unreadable_result_reports_when_it_last_ran(job):
    job(payload=_job(result="oops"))
    assert "2026-09-01 10:30 UTC" in flat(_get(_reader()).text)


def test_a_last_error_is_surfaced_rather_than_kept(job):
    job(payload=_job(result=None, last_error="connection refused"))
    assert "connection refused" in flat(_get(_reader()).text)


def test_a_read_that_raised_is_not_an_empty_panel(job):
    job(raises=RuntimeError("the session went away"))
    body = flat(_get(_reader()).text)
    assert "not registered" in body or "cannot read" in body
    assert "All items have recent activity" not in body


# ---------------------------------------------------------------------------
# The reassurance that was given for unreadable data
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("result", [
    {},
    {"stale_cases": None, "stale_alerts": None},
    {"stale_cases": "two", "stale_alerts": "three"},
])
def test_lists_that_cannot_be_read_do_not_claim_recent_activity(
        job, result):
    """The defect this panel exists to fix. `r.stale_cases || []` sent an
    unreadable payload to "All items have recent activity"."""
    job(payload=_job(result=result))
    body = flat(_get(_reader()).text)
    assert "All items have recent activity" not in body, result
    assert "not in a shape" in body, result


def test_genuinely_empty_lists_do_say_everything_is_recent(job):
    job(payload=_job(result={"stale_cases": [], "stale_alerts": []}))
    body = flat(_get(_reader()).text)
    assert "All items have recent activity" in body
    assert "not in a shape" not in body


def test_one_unreadable_list_does_not_hide_the_other(job):
    job(payload=_job(result={"stale_cases": [_case()],
                             "stale_alerts": "broken"}))
    body = flat(_get(_reader()).text)
    assert "CASE-7" in body
    assert "stale alerts" in body


# ---------------------------------------------------------------------------
# Rows
# ---------------------------------------------------------------------------


def test_a_row_renders_its_reference_title_and_severity(job):
    job(payload=_job())
    html = _get(_reader()).text
    body = flat(html)
    assert "CASE-7" in body
    assert "beaconing" in body
    assert "severity-high" in html
    assert "12d" in body


@pytest.mark.parametrize("value", [None, "", "catastrophic"])
def test_a_missing_or_unknown_severity_is_not_painted_as_medium(job, value):
    """`c.severity || 'medium'` put it in the middle of the scale, which is
    a claim about how urgent it is."""
    job(payload=_job(result={"stale_cases": [_case(severity=value)],
                             "stale_alerts": []}))
    html = _get(_reader()).text
    assert "severity-medium" not in html
    assert "severity-unknown" in html


def test_an_unknown_severity_keeps_its_own_text(job):
    job(payload=_job(result={"stale_cases": [_case(severity="catastrophic")],
                             "stale_alerts": []}))
    assert "catastrophic" in flat(_get(_reader()).text)


@pytest.mark.parametrize("value", [None, "lots", {}])
def test_a_missing_staleness_figure_is_not_the_milder_state(job, value):
    """`c.days_stale > 7 ? 'danger' : 'warn'` is false for undefined, so a
    row with no figure was drawn as a warning and labelled "undefinedd"."""
    job(payload=_job(result={"stale_cases": [_case(days_stale=value)],
                             "stale_alerts": []}))
    html = _get(_reader()).text
    assert "undefined" not in html
    assert "warn" not in html
    assert "danger" not in html
    assert "an-absent" in html


def test_the_danger_threshold_is_the_one_the_page_used(job):
    job(payload=_job(result={
        "stale_cases": [_case(case_number="over",
                              days_stale=STALE_DANGER_DAYS + 1),
                        _case(case_number="under",
                              days_stale=STALE_DANGER_DAYS)],
        "stale_alerts": []}))
    html = _get(_reader()).text
    rows = re.findall(r"<tr>.*?</tr>", html, re.S)
    over = [r for r in rows if "over" in r]
    under = [r for r in rows if "under" in r]
    assert over and "danger" in over[0]
    assert under and "warn" in under[0]


def test_a_row_that_is_not_a_mapping_is_skipped_not_fatal(job):
    job(payload=_job(result={"stale_cases": ["junk", _case()],
                             "stale_alerts": []}))
    body = flat(_get(_reader()).text)
    assert "CASE-7" in body
    assert "not in a shape" not in body


def test_an_unassigned_row_is_told_apart_from_a_missing_field(job):
    job(payload=_job(result={"stale_cases": [_case(assigned_to=None)],
                             "stale_alerts": []}))
    html = _get(_reader()).text
    assert "Unassigned" in flat(html)
    assert "an-absent" in html


# ---------------------------------------------------------------------------
# CSP and the page
# ---------------------------------------------------------------------------


def test_the_fragment_ships_no_colour_or_inline_style(job):
    job(payload=_job())
    html = _get(_reader()).text
    assert "CASE-7" in flat(html)
    assert not re.search(r'\sstyle="', html)
    assert not re.search(r"#[0-9a-fA-F]{3,8}\b", html)
    assert "javascript:" not in html


def test_the_route_answers_json_when_asked_for_json_only(job):
    job(payload=_job())
    view = _get(_reader(), accept="application/json").json()
    assert view["job"]["state"] == "ok"
    assert view["cases"][0]["severity_key"] == "high"
    assert view["cases"][0]["urgent"] is True


def test_the_page_no_longer_builds_the_stale_panel():
    body = re.sub(r"\{#.*?#\}", "", PAGE.read_text(encoding="utf-8"),
                  flags=re.S)
    block = re.search(r"\bfunction renderStaleInvestigations\(.*?\n\}",
                      body, re.S)
    assert block, "the entry point is still there"
    assert not re.search(r"\.innerHTML\s*=", block.group(0))
    assert "htmx.ajax" in block.group(0)


# ---------------------------------------------------------------------------
# Where the classes are painted
# ---------------------------------------------------------------------------


def test_the_page_links_its_stylesheet_from_head_css():
    head = re.search(r"\{%\s*block head_css\s*%\}(.*?)\{%\s*endblock\s*%\}",
                     PAGE.read_text(encoding="utf-8"), re.S)
    assert head, "linked from head_css"
    assert "analytics-page.css" in head.group(1)


def test_the_absent_marker_has_a_rule_and_nothing_outranks_it():
    sheet = (ROOT / "src/ion/web/static/css/analytics-page.css").read_text(
        encoding="utf-8")
    assert ".an-absent" in sheet
    page = PAGE.read_text(encoding="utf-8")
    blocks = "\n".join(re.findall(r"<style[^>]*>(.*?)</style>", page, re.S))
    assert ".an-absent" not in blocks, (
        "the page's in-body block loads after head_css and would win")


def test_the_severity_unknown_rule_is_declared_exactly_once():
    """This used to assert the rule was absent from analytics-page.css.

    Its premise was that analytics.html carried an in-body <style> block,
    which loaded after head_css, so a copy in the page sheet would be
    present and never win. That block has since moved into
    analytics-page.css whole, so there is nothing left to lose to and the
    rule legitimately lives there now.

    What still matters is that it is declared once. Two copies in one
    sheet is the duplicate the original was really guarding against, and
    the later one would quietly win.
    """
    sheet = (ROOT / "src/ion/web/static/css/analytics-page.css").read_text(
        encoding="utf-8")
    rules = re.sub(r"/\*.*?\*/", "", sheet, flags=re.S)
    assert ".severity-unknown" in rules, (
        "the rule the fragment relies on")
    hits = re.findall(r"\.severity-badge\.severity-unknown", rules)
    assert len(hits) == 1, hits
    assert "<style" not in PAGE.read_text(encoding="utf-8")
