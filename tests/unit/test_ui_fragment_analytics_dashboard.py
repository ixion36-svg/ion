"""The analytics summary bar, the overview grid and the job config table.

Three defects worth the conversion.

THE STALENESS BADGE WAS DECIDED IN THE VIEWER'S TIMEZONE

    const age = Date.now() - new Date(job.last_run_at).getTime();
    if (age > 2 * 3600000) return { cls: 'stale', label: 'Stale' };

`last_run_at` is isoformat() of a naive UTC column, so `new Date` read it
in the viewer's zone. Against a two-hour threshold that is not a rounding
error: a viewer at UTC+5 saw every job that ran in the last five hours as
fresh, and one at UTC-5 saw a job that ran twenty minutes ago as stale.
Seventh page with the zoneless-UTC defect and the first where it changes a
badge rather than a number.

A SUMMARY FIGURE OF ZERO MEANT FOUR DIFFERENT THINGS

GET /api/analytics/dashboard builds `summary` from a dict seeded with
zeros and only overwrites a key when a job of that type exists:

    summary = {"entities_at_risk": 0, ...}
    if job.job_type == "entity_risk_score":
        summary["entities_at_risk"] = r.get("total_scored", 0)

with `r = job.last_result or {}`. So "0 entities at risk" was returned for
a job that scored zero entities, a job that has never run, a job whose
result recorded no such figure, and a job type not registered at all. The
page then applied `s.entities_at_risk || 0` on top. The per-job state is
decidable from the same payload, so the bar is computed from `jobs` here
rather than from `summary`, and only a measured zero prints as zero.

`astat-stale` was worse: `(s.stale_cases || 0) + (s.stale_alerts || 0)`
silently halves the total when one half is missing.

AN ENTITY NAME WENT INTO MARKUP UNESCAPED

    detail: `Top: ${top.entity} (${top.risk_score})`
    <div class="overview-card-detail">${metric.detail}</div>

The card title went through esc(). The detail line beside it did not, and
an entity name is whatever the alerts carried.

Smaller ones: `${j.run_count}` and `${j.schedule_minutes}` printed
"undefined" in the config table, and `${job.last_duration_ms ? ... : ''}`
hid a genuine 0ms run.
"""
from __future__ import annotations

import re
from html import unescape
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ion.web.ui.analytics import PERMISSION, router

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "src/ion/web/templates/analytics.html"
SHEET = ROOT / "src/ion/web/static/css/analytics-page.css"

DASH = "/ui/analytics/dashboard"
CONFIG = "/ui/analytics/config"


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


def _get(url, user):
    with TestClient(_app(user)) as client:
        return client.get(url)


def _reader():
    return _User(PERMISSION)


def flat(html: str) -> str:
    return " ".join(unescape(re.sub(r"<[^>]+>", " ", html)).split())


@pytest.fixture
def dashboard(monkeypatch):
    def set(payload=None, raises=None):
        def handler(current_user=None, session=None):
            if raises is not None:
                raise raises
            return payload

        monkeypatch.setattr(
            "ion.web.analytics_api.get_analytics_dashboard", handler)

    return set


@pytest.fixture
def jobs(monkeypatch):
    def set(payload=None, raises=None):
        def handler(current_user=None, session=None):
            if raises is not None:
                raise raises
            return payload

        monkeypatch.setattr(
            "ion.web.analytics_api.list_analytics_jobs", handler)

    return set


def _job(**over):
    """One entry of /dashboard's `jobs` dict."""
    job = {
        "display_name": "Entity Risk Score",
        "enabled": True,
        "last_run_at": "2026-10-13T09:00:00",
        "last_duration_ms": 120,
        "last_error": None,
        "run_count": 7,
        "result": {},
    }
    job.update(over)
    return job


def _stat(html: str, ident: str) -> str:
    match = re.search('id="' + ident + r'"[^>]*>(.*?)</span>', html, re.S)
    assert match, (ident, html[:600])
    return match.group(1)


def _card(html: str, job_type: str) -> str:
    """One overview card's markup, found by the data-job-type the
    conversion added. The grid had no per-card identifier before."""
    start = html.find('data-job-type="' + job_type + '"')
    assert start != -1, (job_type, html[:600])
    opened = html.rfind("<div ", 0, start)
    return html[opened:html.find("</div>", html.find(
        "overview-card-footer", opened))]


# ---------------------------------------------------------------------------
# Gates
# ---------------------------------------------------------------------------


def test_both_panels_need_the_pages_permission(dashboard, jobs):
    dashboard(payload={"jobs": {}, "summary": {}})
    jobs(payload={"jobs": []})
    assert _get(DASH, _User()).status_code == 403
    assert _get(CONFIG, _User()).status_code == 403
    assert _get(DASH, _reader()).status_code == 200
    assert _get(CONFIG, _reader()).status_code == 200


# ---------------------------------------------------------------------------
# The staleness badge
# ---------------------------------------------------------------------------


def test_a_zoneless_run_time_is_read_as_utc_for_the_staleness_badge(
        dashboard, monkeypatch):
    """The defect this panel exists to fix. 09:00 UTC against a 10:00 UTC
    clock is one hour old, so inside the two-hour window, whatever zone
    the viewer keeps."""
    import ion.web.ui.analytics as module

    from datetime import datetime, timezone

    monkeypatch.setattr(
        module, "_now",
        lambda: datetime(2026, 10, 13, 10, 0, tzinfo=timezone.utc))
    dashboard(payload={"jobs": {"entity_risk_score": _job(
        last_run_at="2026-10-13T09:00:00")}, "summary": {}})
    card = _card(_get(DASH, _reader()).text, "entity_risk_score")
    assert "OK" in flat(card)
    assert "Stale" not in flat(card)


def test_a_run_older_than_the_window_is_stale(dashboard, monkeypatch):
    import ion.web.ui.analytics as module

    from datetime import datetime, timezone

    monkeypatch.setattr(
        module, "_now",
        lambda: datetime(2026, 10, 13, 12, 1, tzinfo=timezone.utc))
    dashboard(payload={"jobs": {"entity_risk_score": _job(
        last_run_at="2026-10-13T09:00:00")}, "summary": {}})
    assert "Stale" in flat(_card(_get(DASH, _reader()).text,
                                 "entity_risk_score"))


def test_an_error_outranks_the_run_time(dashboard):
    dashboard(payload={"jobs": {"entity_risk_score": _job(
        last_error="the engine blew up")}, "summary": {}})
    card = _card(_get(DASH, _reader()).text, "entity_risk_score")
    assert "Error" in flat(card)


def test_a_job_that_never_ran_is_pending(dashboard):
    dashboard(payload={"jobs": {"entity_risk_score": _job(
        last_run_at=None)}, "summary": {}})
    card = flat(_card(_get(DASH, _reader()).text, "entity_risk_score"))
    assert "Pending" in card
    assert "Never run" in card


# ---------------------------------------------------------------------------
# The summary bar
# ---------------------------------------------------------------------------


def test_a_job_that_never_ran_does_not_report_zero_entities_at_risk(
        dashboard):
    """The endpoint returns `entities_at_risk: 0` for this. Zero entities
    at risk is a reassuring thing to tell someone when nothing was
    measured."""
    dashboard(payload={"jobs": {"entity_risk_score": _job(
        last_run_at=None, result={})},
        "summary": {"entities_at_risk": 0}})
    html = _get(DASH, _reader()).text
    assert "an-absent" in _stat(html, "astat-entities")


def test_an_unregistered_job_type_does_not_report_zero(dashboard):
    """`summary` is seeded with zeros and only overwritten when a job of
    that type exists, so an estate with no entity-risk job at all also
    reported zero."""
    dashboard(payload={"jobs": {}, "summary": {"entities_at_risk": 0}})
    html = _get(DASH, _reader()).text
    assert "an-absent" in _stat(html, "astat-entities")
    # The reason sits in the title attribute, which flat() strips.
    assert "No job of this type is registered" in html


def test_a_measured_zero_is_shown_as_zero(dashboard):
    dashboard(payload={"jobs": {"entity_risk_score": _job(
        result={"total_scored": 0})}, "summary": {}})
    assert "0" in _stat(_get(DASH, _reader()).text, "astat-entities")


def test_a_measured_figure_is_shown(dashboard):
    dashboard(payload={"jobs": {"entity_risk_score": _job(
        result={"total_scored": 41})}, "summary": {}})
    assert "41" in _stat(_get(DASH, _reader()).text, "astat-entities")


def test_a_result_that_recorded_no_figure_is_not_zero(dashboard):
    """The job ran, so it is not pending, but this figure is not in what
    it stored."""
    dashboard(payload={"jobs": {"entity_risk_score": _job(
        result={"something_else": 3})}, "summary": {}})
    assert "an-absent" in _stat(_get(DASH, _reader()).text,
                                "astat-entities")


def test_one_missing_half_does_not_silently_halve_the_stale_total(
        dashboard):
    """`(s.stale_cases || 0) + (s.stale_alerts || 0)` reported 4 when
    there were 4 cases and an unreadable number of alerts."""
    dashboard(payload={"jobs": {"stale_investigations": _job(
        result={"total_stale_cases": 4})}, "summary": {}})
    html = _get(DASH, _reader()).text
    assert "4" not in flat(_stat(html, "astat-stale"))
    assert "an-absent" in _stat(html, "astat-stale")


def test_both_halves_of_the_stale_total_are_added(dashboard):
    dashboard(payload={"jobs": {"stale_investigations": _job(
        result={"total_stale_cases": 4, "total_stale_alerts": 9})},
        "summary": {}})
    assert "13" in _stat(_get(DASH, _reader()).text, "astat-stale")


def test_the_noisy_rule_count_is_measured_from_the_rules(dashboard):
    dashboard(payload={"jobs": {"rule_noise": _job(result={"rules": [
        {"fp_ratio": 0.9}, {"fp_ratio": 0.1}, {"fp_ratio": 0.7}]})},
        "summary": {}})
    assert "2" in _stat(_get(DASH, _reader()).text, "astat-noisy")


def test_a_rules_list_that_is_not_a_list_is_not_zero_noisy_rules(
        dashboard):
    dashboard(payload={"jobs": {"rule_noise": _job(
        result={"rules": "broken"})}, "summary": {}})
    assert "an-absent" in _stat(_get(DASH, _reader()).text, "astat-noisy")


def test_an_mttr_of_zero_differs_from_an_unrecorded_mttr(dashboard):
    dashboard(payload={"jobs": {"case_metrics": _job(
        result={"mttr_hours": 0})}, "summary": {}})
    assert "0" in _stat(_get(DASH, _reader()).text, "astat-mttr")
    dashboard(payload={"jobs": {"case_metrics": _job(result={})},
                       "summary": {}})
    assert "an-absent" in _stat(_get(DASH, _reader()).text, "astat-mttr")


# ---------------------------------------------------------------------------
# The overview cards
# ---------------------------------------------------------------------------


def test_an_entity_name_does_not_reach_markup_unescaped(dashboard):
    """The card title went through esc(). The detail beside it did not."""
    dashboard(payload={"jobs": {"entity_risk_score": _job(result={
        "total_scored": 2,
        "entities": [{"entity": "<img src=x onerror=alert(1)>",
                      "risk_score": 90}]})}, "summary": {}})
    html = _get(DASH, _reader()).text
    # The tag is what matters. `onerror=alert(1)` is still a substring of
    # the correctly escaped text, so asserting on it would pass against
    # escaped and unescaped output alike.
    assert "<img src=x" not in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html


def test_a_display_name_does_not_reach_markup_unescaped(dashboard):
    dashboard(payload={"jobs": {"entity_risk_score": _job(
        display_name="<script>alert(1)</script>")}, "summary": {}})
    html = _get(DASH, _reader()).text
    assert "<script>alert(1)" not in html
    assert "alert(1)" in flat(html)


def test_the_entity_risk_card_opens_the_entity_risk_tab(dashboard):
    """The page's nested ternary renamed exactly one job type."""
    dashboard(payload={"jobs": {"entity_risk_score": _job()},
                       "summary": {}})
    card = _card(_get(DASH, _reader()).text, "entity_risk_score")
    assert "&#34;entity_risk&#34;" in card or '"entity_risk"' in card


def test_every_other_card_opens_the_tab_of_its_own_name(dashboard):
    dashboard(payload={"jobs": {"rule_noise": _job()}, "summary": {}})
    card = _card(_get(DASH, _reader()).text, "rule_noise")
    assert "&#34;rule_noise&#34;" in card or '"rule_noise"' in card


def test_a_card_argument_is_serialised_rather_than_interpolated(dashboard):
    """`data-args='["${type}"]'` put a database value straight into a
    single-quoted attribute."""
    module = (ROOT / "src/ion/web/ui/analytics.py").read_text(
        encoding="utf-8")
    assert "DASHBOARD_FRAGMENT" in module
    fragment = (ROOT / "src/ion/web/templates/_fragments"
                / "analytics_dashboard.html").read_text(encoding="utf-8")
    for match in re.finditer(r"data-args='([^']*)'", fragment):
        assert "tojson" in match.group(1), match.group(1)


def test_a_zero_millisecond_run_is_reported(dashboard):
    """`job.last_duration_ms ? ... : ''` hid it."""
    dashboard(payload={"jobs": {"rule_noise": _job(last_duration_ms=0)},
                       "summary": {}})
    assert "0ms" in flat(_card(_get(DASH, _reader()).text, "rule_noise"))


def test_a_card_metric_that_was_not_recorded_is_not_zero(dashboard):
    dashboard(payload={"jobs": {"repeat_offenders": _job(result={})},
                       "summary": {}})
    card = _card(_get(DASH, _reader()).text, "repeat_offenders")
    assert "an-absent" in card


def test_a_card_reports_the_threshold_it_used(dashboard):
    dashboard(payload={"jobs": {"repeat_offenders": _job(
        result={"total_flagged": 6, "threshold": 5})}, "summary": {}})
    body = flat(_card(_get(DASH, _reader()).text, "repeat_offenders"))
    assert "5" in body


def test_no_jobs_at_all_says_so(dashboard):
    dashboard(payload={"jobs": {}, "summary": {}})
    assert "No analytics jobs" in flat(_get(DASH, _reader()).text)


@pytest.mark.parametrize("payload", [None, "broken", [], {"jobs": "x"}])
def test_a_body_that_is_not_a_mapping_is_a_failure(dashboard, payload):
    dashboard(payload=payload)
    body = flat(_get(DASH, _reader()).text).lower()
    assert "could not" in body
    assert "no analytics jobs" not in body


def test_an_exception_does_not_render_an_empty_dashboard(dashboard):
    dashboard(raises=RuntimeError("the service went away"))
    body = flat(_get(DASH, _reader()).text).lower()
    assert "could not" in body


# ---------------------------------------------------------------------------
# The config table
# ---------------------------------------------------------------------------


def _row(html: str, job_type: str) -> str:
    start = html.find(job_type)
    assert start != -1, (job_type, html[:600])
    opened = html.rfind("<tr", 0, start)
    return html[opened:html.find("</tr>", opened)]


def _cfg(**over):
    job = {
        "job_type": "rule_noise",
        "display_name": "Rule Noise",
        "enabled": True,
        "schedule_minutes": 60,
        "last_run_at": "2026-10-13T09:00:00",
        "next_run_at": "2026-10-13T10:00:00",
        "last_duration_ms": 90,
        "last_error": None,
        "run_count": 12,
        "has_results": True,
    }
    job.update(over)
    return job


def test_a_missing_run_count_does_not_print_undefined(jobs):
    jobs(payload={"jobs": [_cfg(run_count=None)]})
    html = _get(CONFIG, _reader()).text
    assert "undefined" not in html
    assert "an-absent" in _row(html, "rule_noise")


def test_a_missing_schedule_does_not_print_undefined(jobs):
    jobs(payload={"jobs": [_cfg(schedule_minutes=None)]})
    html = _get(CONFIG, _reader()).text
    assert "undefined" not in html
    assert 'value=""' in html or "value=''" in html


def test_a_recorded_schedule_is_the_input_value(jobs):
    jobs(payload={"jobs": [_cfg(schedule_minutes=45)]})
    assert 'value="45"' in _get(CONFIG, _reader()).text


def test_a_job_error_does_not_reach_the_title_attribute_unescaped(jobs):
    jobs(payload={"jobs": [_cfg(
        last_error='" onmouseover="alert(1)')]})
    html = _get(CONFIG, _reader()).text
    assert 'onmouseover="alert(1)' not in html
    assert "Error" in flat(html)


def test_the_enabled_toggle_sends_the_opposite_of_the_current_state(jobs):
    jobs(payload={"jobs": [_cfg(enabled=True)]})
    row = _row(_get(CONFIG, _reader()).text, "rule_noise")
    assert "false" in row
    jobs(payload={"jobs": [_cfg(enabled=False)]})
    row = _row(_get(CONFIG, _reader()).text, "rule_noise")
    assert "true" in row


def test_no_jobs_configured_says_so(jobs):
    jobs(payload={"jobs": []})
    assert "No jobs configured" in flat(_get(CONFIG, _reader()).text)


@pytest.mark.parametrize("payload", [None, "broken", {"jobs": "x"}])
def test_a_config_body_that_is_not_a_mapping_is_a_failure(jobs, payload):
    jobs(payload=payload)
    body = flat(_get(CONFIG, _reader()).text).lower()
    assert "could not" in body
    assert "no jobs configured" not in body


def test_a_config_exception_is_a_failure(jobs):
    jobs(raises=RuntimeError("gone"))
    assert "could not" in flat(_get(CONFIG, _reader()).text).lower()


# ---------------------------------------------------------------------------
# The page
# ---------------------------------------------------------------------------


def _page_js() -> str:
    body = re.sub(r"\{#.*?#\}", "", PAGE.read_text(encoding="utf-8"),
                  flags=re.S)
    return re.sub(r"//[^\n]*", "", body)


def test_the_page_no_longer_sets_the_summary_bar_itself():
    body = _page_js()
    for ident in ("astat-entities", "astat-offenders", "astat-noisy",
                  "astat-mttr", "astat-velocity", "astat-stale"):
        assert "setText('" + ident not in body, ident


def test_the_page_no_longer_builds_the_overview_or_the_config_table():
    body = _page_js()
    assert "function renderOverview" not in body
    assert "function getOverviewMetric" not in body
    assert "function getJobStatus" not in body
    # renderConfig survives as the htmx.ajax call, like every other
    # converted panel on this page. What must be gone is the builder.
    # `.config-table` and `.schedule-input` are still rules in the page's
    # own style block, so the builder is identified by what it did.
    assert "jobsList.map" not in body
    config = re.search(r"function renderConfig\(\).*?\n\}", body, re.S)
    assert config, "renderConfig"
    assert "htmx.ajax" in config.group(0)
    assert not re.search(r"\.innerHTML\s*\+?=", config.group(0))


def test_the_two_status_colours_moved_into_the_stylesheet():
    """`text-[#ef4444]` and `text-[#22c55e]` were written into the row.

    Comments are stripped before matching because the module's own note
    about the old code quotes it, and prose has broken five checks on this
    project by matching the thing it describes.
    """
    body = _page_js()
    assert "text-[#ef4444]" not in body
    assert "text-[#22c55e]" not in body
    sheet = SHEET.read_text(encoding="utf-8")
    assert ".config-status-error" in sheet
    assert ".config-status-ok" in sheet


def test_the_page_still_links_its_stylesheet():
    """A sheet nobody links is the mistake that left the forensics
    preview bare."""
    assert "analytics-page.css" in PAGE.read_text(encoding="utf-8")
