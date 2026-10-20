"""Case metrics and observable velocity, the last two analytics job panels.

Measured on analytics.html before the change:

  * `r.total_cases || 0`, `r.open_cases || 0`, `r.closed_cases || 0`.
    Three confident zeros for figures the job did not record, on the
    numbers at the top of the panel. Only mttr_hours was guarded.
  * `Math.max(...trend.map(d => d.count), 1)` on both sparklines, so one
    unreadable day made every height NaN and the chart vanished.
  * `Object.values(reasons).reduce((a, b) => a + b, 0) || 1`. One
    non-numeric value makes the sum NaN and `|| 1` turns that into a
    denominator of one, so every percentage became the count times a
    hundred.
  * `s.days_stale > 21 ? 'danger' : 'warn'` on the dormant indicators, the
    same fall-through as the stale panel, plus "undefinedd".
  * `severity-${s.threat_level}` and `cl-${reason}` put server values into
    class attributes, and `<span class="entity-type-badge host">` hard-
    coded `host` whatever the type actually was, so every dormant
    indicator looked like a host.
  * The Cases by Severity table sorted with `indexOf` over a fixed list, so
    a severity outside it returned -1 and sorted above critical, and
    `data.open || 0` printed a zero per missing figure.
"""
from __future__ import annotations

import re
from html import unescape
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from page_css import page_css

from ion.web.ui.analytics import IOC_DANGER_DAYS, PERMISSION, router

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "src/ion/web/templates/analytics.html"

METRICS = "/ui/analytics/case-metrics"
VELOCITY = "/ui/analytics/observable-velocity"


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


def _get(user, url):
    with TestClient(_app(user)) as client:
        return client.get(url)


def _reader():
    return _User(PERMISSION)


@pytest.fixture
def job(monkeypatch):
    def set(result):
        def handler(job_type, current_user=None, session=None):
            return {"job_type": job_type, "display_name": "X",
                    "last_run_at": "2026-09-01T10:30:00",
                    "last_error": None, "result": result}

        monkeypatch.setattr(
            "ion.web.analytics_api.get_analytics_job", handler)

    return set


def flat(html: str) -> str:
    return " ".join(unescape(re.sub(r"<[^>]+>", " ", html)).split())


# ---------------------------------------------------------------------------
# The four cards
# ---------------------------------------------------------------------------


def test_the_cards_report_what_the_job_recorded(job):
    job(result={"mttr_hours": 4.5, "total_cases": 30, "open_cases": 8,
                "closed_cases": 22})
    body = flat(_get(_reader(), METRICS).text)
    for figure in ("4.5", "30", "8", "22"):
        assert figure in body, figure


@pytest.mark.parametrize("field", ["total_cases", "open_cases",
                                    "closed_cases"])
def test_a_missing_card_figure_is_not_a_zero(job, field):
    """`r.total_cases || 0` and its two siblings printed a zero for a
    figure the job did not record, on the numbers read first."""
    figures = {"total_cases": 30, "open_cases": 8, "closed_cases": 22}
    figures.pop(field)
    job(result=figures)
    html = _get(_reader(), METRICS).text
    assert "an-absent" in html
    # The other two still show, so this is about the missing one only.
    assert len(re.findall(r"an-absent", html)) >= 1


def test_the_card_colours_are_not_arbitrary_tailwind_values(job):
    """They were text-[#eab308] and text-[#22c55e] in a JS string."""
    job(result={"total_cases": 1, "open_cases": 1, "closed_cases": 1})
    html = _get(_reader(), METRICS).text
    assert not re.search(r"#[0-9a-fA-F]{3,8}\b", html)
    assert "an-open-cases" in html
    assert "an-closed-cases" in html


# ---------------------------------------------------------------------------
# Sparklines
# ---------------------------------------------------------------------------


def test_one_unreadable_day_does_not_flatten_the_sparkline(job):
    job(result={"daily_trend": [{"date": "d1", "count": 10},
                                {"date": "d2", "count": "x"}]})
    html = _get(_reader(), METRICS).text
    assert "NaN" not in html
    assert "height:56px" in html
    assert "an-spark-unmeasured" in html


def test_a_series_that_is_not_a_list_says_so(job):
    job(result={"daily_trend": "broken"})
    body = flat(_get(_reader(), METRICS).text)
    assert "not in a shape" in body
    assert "quiet period" in body


def test_a_sparkline_title_cannot_break_its_attribute(job):
    """`title="${d.date}: ${d.count}"` was interpolated."""
    job(result={"daily_trend": [
        {"date": 'x" onmouseover="alert(1)', "count": 1}]})
    html = _get(_reader(), METRICS).text
    assert 'onmouseover="alert(1)"' not in html


# ---------------------------------------------------------------------------
# Shares
# ---------------------------------------------------------------------------


def test_one_unreadable_value_does_not_wreck_every_percentage(job):
    """`reduce((a, b) => a + b, 0) || 1` is NaN then 1, so each percentage
    became the count times a hundred."""
    job(result={"closure_reasons": {"true_positive": 3,
                                    "false_positive": "x"}})
    html = _get(_reader(), METRICS).text
    assert "width: 100%" in html
    assert "300%" not in html
    assert "an-absent" in html


def test_a_reason_key_cannot_escape_its_class(job):
    """`cl-${reason}` put the key into a class attribute."""
    job(result={"closure_reasons": {'a" onload="alert(1)': 2}})
    html = _get(_reader(), METRICS).text
    assert 'onload="alert(1)"' not in html
    assert "cl-unknown" in html


# ---------------------------------------------------------------------------
# Cases by severity
# ---------------------------------------------------------------------------


def test_the_severity_table_is_restored_and_ordered(job):
    """I dropped this table when I first converted the panel. It sorts
    critical first, and a severity outside the known list goes last: the
    page's `indexOf` returned -1 for one, which sorted it above critical."""
    job(result={"by_severity": {
        "low": {"open": 1, "closed": 1, "total": 2},
        "weird": {"open": 1, "closed": 0, "total": 1},
        "critical": {"open": 5, "closed": 1, "total": 6}}})
    body = flat(_get(_reader(), METRICS).text)
    assert "Cases by Severity" in body
    order = [body.index(s) for s in ("critical", "low", "weird")]
    assert order == sorted(order), body


def test_a_missing_severity_figure_is_not_a_zero(job):
    job(result={"by_severity": {"critical": {"open": 5}}})
    html = _get(_reader(), METRICS).text
    assert "an-absent" in html


def test_severity_figures_that_are_not_a_mapping_say_so(job):
    job(result={"by_severity": "broken"})
    assert "not in a shape" in flat(_get(_reader(), METRICS).text)


# ---------------------------------------------------------------------------
# Dormant indicators
# ---------------------------------------------------------------------------


def _ioc(**over):
    i = {"value": "203.0.113.9", "type": "ip", "threat_level": "high",
         "days_stale": 30}
    i.update(over)
    return i


def test_a_dormant_indicator_shows_its_real_type(job):
    """`<span class="entity-type-badge host">` hard-coded host, so every
    indicator looked like one."""
    job(result={"stale_iocs": [_ioc(type="domain")]})
    html = _get(_reader(), VELOCITY).text
    assert "entity-type-badge domain" in html
    assert "entity-type-badge host" not in html


def test_a_threat_level_cannot_escape_its_class(job):
    job(result={"stale_iocs": [_ioc(threat_level='a" onload="x')]})
    html = _get(_reader(), VELOCITY).text
    assert 'onload="x"' not in html
    assert "severity-unknown" in html


def test_a_dormant_indicator_with_no_figure_is_not_the_milder_state(job):
    job(result={"stale_iocs": [_ioc(days_stale=None)]})
    html = _get(_reader(), VELOCITY).text
    assert "undefined" not in html
    assert "warn" not in html
    assert "danger" not in html
    assert "an-absent" in html


def test_the_dormancy_threshold_is_the_one_the_page_used(job):
    job(result={"stale_iocs": [
        _ioc(value="over", days_stale=IOC_DANGER_DAYS + 1),
        _ioc(value="under", days_stale=IOC_DANGER_DAYS)]})
    html = _get(_reader(), VELOCITY).text
    rows = re.findall(r"<tr>.*?</tr>", html, re.S)
    over = [r for r in rows if "over" in r]
    under = [r for r in rows if "under" in r]
    assert over and "danger" in over[0]
    assert under and "warn" in under[0]


def test_dormant_indicators_that_are_not_a_list_say_so(job):
    job(result={"stale_iocs": "broken"})
    assert "not in a shape" in flat(_get(_reader(), VELOCITY).text)


def test_no_dormant_indicators_says_so(job):
    job(result={"stale_iocs": []})
    assert "No dormant indicators" in flat(_get(_reader(), VELOCITY).text)


# ---------------------------------------------------------------------------
# Shared
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("url", [METRICS, VELOCITY])
def test_both_panels_need_the_pages_permission(job, url):
    job(result={})
    assert _get(_User(), url).status_code == 403
    assert _get(_reader(), url).status_code == 200


@pytest.mark.parametrize("url", [METRICS, VELOCITY])
def test_both_panels_separate_never_run_from_unreadable(job, url):
    job(result=None)
    assert "Run All Jobs" in flat(_get(_reader(), url).text), url
    job(result="oops")
    assert "cannot read" in flat(_get(_reader(), url).text), url


@pytest.mark.parametrize("url", [METRICS, VELOCITY])
def test_neither_panel_ships_an_inline_style(job, url):
    job(result={"stale_iocs": [_ioc()], "total_cases": 1,
                "daily_trend": [{"date": "d", "count": 1}],
                "daily_counts": [{"date": "d", "count": 1}]})
    html = _get(_reader(), url).text
    assert not re.search(r'\sstyle="', html), url


def test_the_page_builds_neither_panel_nor_the_breakdown():
    body = re.sub(r"\{#.*?#\}", "", PAGE.read_text(encoding="utf-8"),
                  flags=re.S)
    for name in ("renderCaseMetrics", "renderObservableVelocity"):
        block = re.search(r"\bfunction " + name + r"\(.*?\n\}", body, re.S)
        assert block, name
        assert not re.search(r"\.innerHTML\s*=", block.group(0)), name
        assert "htmx.ajax" in block.group(0), name
    assert "function renderSeverityBreakdown" not in body, (
        "it only existed to build a string for renderCaseMetrics")


# ---------------------------------------------------------------------------
# The threat distribution, restored after my own regression
# ---------------------------------------------------------------------------


def test_the_distribution_always_lists_its_six_levels(job):
    """The page iterated a fixed list, so a level with no observables
    showed as a zero row. My first pass used a generic macro over the
    payload's keys instead, and those rows vanished."""
    job(result={"threat_distribution": {"critical": 3}})
    body = flat(_get(_reader(), VELOCITY).text)
    for level in ("critical", "high", "medium", "low", "benign", "unknown"):
        assert level in body, level


def test_a_level_absent_from_the_payload_shows_as_zero(job):
    """`dist[level] || 0`, which is a real statement: none of them."""
    job(result={"threat_distribution": {"critical": 3}})
    html = _get(_reader(), VELOCITY).text
    # Up to and including the count span: an earlier version of this
    # pattern stopped at the track's closing divs, so the count it was
    # asserting on was not in the captured text.
    rows = re.findall(
        r'threat-dist-row.*?threat-dist-count">(.*?)</span>', html, re.S)
    labels = re.findall(r'threat-dist-label">(\w+)</span>', html)
    counts = dict(zip(labels, (c.strip() for c in rows)))
    assert counts.get("critical") == "3", counts
    assert counts.get("benign") == "0", counts


def test_the_distribution_bar_has_its_track(job):
    """_ion-s-8bc7ebe99c, which my first pass dropped and the rewrite audit
    caught by comparing its contents rather than its exit code."""
    job(result={"threat_distribution": {"critical": 3}})
    html = _get(_reader(), VELOCITY).text
    assert "an-dist-track" in html
    sheet = page_css("analytics")
    rule = re.search(r"\.an-dist-track\s*\{([^}]*)\}", sheet)
    assert rule, "the track rule"
    for declaration in ("flex", "background", "border-radius", "height",
                        "overflow"):
        assert declaration in rule.group(1), declaration


def test_the_totals_line_is_back(job):
    """`Total: ${r.total_observables || 0} | Watched: ${r.total_watched ||
    0}` went with the macro too."""
    job(result={"threat_distribution": {}, "total_observables": 120,
                "total_watched": 9})
    body = flat(_get(_reader(), VELOCITY).text)
    assert "Total: 120" in body
    assert "Watched: 9" in body


def test_a_missing_total_is_not_printed_as_zero(job):
    job(result={"threat_distribution": {}})
    html = _get(_reader(), VELOCITY).text
    assert "Total: 0" not in flat(html)
    assert "an-absent" in html


def test_a_distribution_that_is_not_a_mapping_says_so(job):
    job(result={"threat_distribution": "broken"})
    assert "not in a shape" in flat(_get(_reader(), VELOCITY).text)
