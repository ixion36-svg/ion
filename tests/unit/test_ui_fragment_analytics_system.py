"""The analytics system tab's stats bar and index breakdown.

The reason this panel was worth converting is one flag the page never read.

GET /api/analytics/system-overview merges two halves: the Elasticsearch
alert figures, and the CyAB namespace mappings out of ION's own database.
The endpoint carries `es_failed`, and its own comment says what that means:

    # Whether the Elasticsearch half of this payload happened. The
    # figures above that come from it are placeholders when this is
    # true, not measurements of a quiet estate.

The page rendered those placeholders as measurements, with
`(data.total_alerts || 0).toLocaleString()` and four more like it. So a
deployment whose Elasticsearch was unreachable saw zero alerts, zero logs
and no severity anywhere: a clean estate. The flag was added to the
endpoint to make that visible and nothing was ever taught to read it.

Three smaller ones in the same panel:

  * `idx.count.toLocaleString()` throws on undefined, taking the index
    breakdown down through the caller's catch, which then put the
    exception message where the whole tab should be.
  * `Math.max(...indices.map(i => i.count), 1)` is NaN if any one count is
    not a number, so every bar width became "NaN%".
  * The severity pills used `if (sev.critical)`, so a recorded zero and a
    severity that was never recorded both drew nothing, and the fallback
    sentence turned on `sys.alert_count > 0`, false for a missing count as
    well as a real zero.
"""
from __future__ import annotations

import re
from html import unescape
from pathlib import Path

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from ion.web.ui.analytics import PERMISSION, router

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "src/ion/web/templates/analytics.html"

URL = "/ui/analytics/system"


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
def overview(monkeypatch):
    def set(payload=None, raises=None):
        async def handler(hours=168, current_user=None, session=None):
            if raises is not None:
                raise raises
            return payload

        monkeypatch.setattr(
            "ion.web.analytics_api.get_system_overview", handler)

    return set


def flat(html: str) -> str:
    return " ".join(unescape(re.sub(r"<[^>]+>", " ", html)).split())


def _payload(**over):
    p = {
        "es_failed": False,
        "error": None,
        "hours": 24,
        "total_alerts": 1200,
        "total_logs_ingested": 98000,
        "total_severity": {"critical": 3, "high": 7},
        "total_systems": 9,
        "mapped_systems": 4,
        "avg_tide_coverage": 62,
        "systems": [],
        "indices": [{"index": "logs-1", "count": 800,
                     "severity": {"high": 2}}],
    }
    p.update(over)
    return p


def _stat(html: str, ident: str) -> str:
    """One out-of-band stat span's contents."""
    match = re.search(
        'id="' + ident + r'"[^>]*>(.*?)</span>', html, re.S)
    assert match, (ident, html[:400])
    return match.group(1)


# ---------------------------------------------------------------------------
# Gate
# ---------------------------------------------------------------------------


def test_the_panel_needs_the_pages_permission(overview):
    overview(payload=_payload())
    assert _get(_User()).status_code == 403
    assert _get(_reader()).status_code == 200


# ---------------------------------------------------------------------------
# The flag the page never read
# ---------------------------------------------------------------------------


def test_a_failed_elasticsearch_read_is_not_a_quiet_estate(overview):
    """The defect this panel exists to fix."""
    overview(payload=_payload(es_failed=True, total_alerts=0,
                              total_logs_ingested=0,
                              total_severity={},
                              error="Elasticsearch is not configured"))
    html = _get(_reader()).text
    body = flat(html)
    assert "not a quiet estate" in body
    assert "Elasticsearch is not configured" in body
    # None of the three Elasticsearch figures is shown as a number.
    for ident in ("sys-s-total", "sys-s-logs", "sys-s-critical"):
        assert "an-absent" in _stat(html, ident), ident


def test_the_database_half_still_answers_when_elasticsearch_did_not(
        overview):
    """The endpoint merges two halves and says it "can be a real answer
    even when this half failed". The system and coverage figures come from
    ION's own records."""
    overview(payload=_payload(es_failed=True, total_systems=9,
                              mapped_systems=4, avg_tide_coverage=62))
    html = _get(_reader()).text
    assert "9" in _stat(html, "sys-s-systems")
    assert "4" in _stat(html, "sys-s-mapped")
    assert "62" in _stat(html, "sys-s-coverage")


def test_a_healthy_read_shows_the_elasticsearch_figures(overview):
    overview(payload=_payload())
    html = _get(_reader()).text
    assert "1,200" in _stat(html, "sys-s-total")
    assert "98,000" in _stat(html, "sys-s-logs")
    assert "3" in _stat(html, "sys-s-critical")
    assert "not a quiet estate" not in flat(html)


def test_the_index_breakdown_is_withheld_when_elasticsearch_failed(
        overview):
    """It is built from the same half."""
    overview(payload=_payload(es_failed=True, indices=[]))
    body = flat(_get(_reader()).text)
    assert "No indices found" not in body
    assert "not a quiet estate" in body


# ---------------------------------------------------------------------------
# The coverage colour
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("coverage,cls", [
    (85, "an-cov-good"), (55, "an-cov-fair"), (10, "an-cov-poor"),
])
def test_the_coverage_threshold_colour_is_a_class(overview, coverage, cls):
    """It was three thresholds written into covEl.style.color."""
    overview(payload=_payload(avg_tide_coverage=coverage))
    assert cls in _get(_reader()).text


def test_a_missing_coverage_figure_is_not_shown_as_zero_percent(overview):
    """`(data.avg_tide_coverage || 0) + '%'` printed 0%, which on a
    coverage figure reads as "nothing is covered"."""
    overview(payload=_payload(avg_tide_coverage=None))
    html = _get(_reader()).text
    assert "0%" not in flat(html)
    assert "an-absent" in _stat(html, "sys-s-coverage")


# ---------------------------------------------------------------------------
# The index breakdown
# ---------------------------------------------------------------------------


def test_an_index_renders_its_name_count_and_bar(overview):
    overview(payload=_payload())
    html = _get(_reader()).text
    assert "logs-1" in flat(html)
    assert "800" in flat(html)
    assert "data-ion-style" in html


def test_an_index_with_no_count_does_not_take_the_tab_down(overview):
    """`idx.count.toLocaleString()` threw on undefined, and the caller's
    catch replaced the whole tab with the exception message."""
    overview(payload=_payload(indices=[{"index": "logs-1"}]))
    html = _get(_reader()).text
    assert "logs-1" in flat(html)
    assert "an-absent" in html


def test_one_unreadable_count_does_not_make_every_bar_nan(overview):
    overview(payload=_payload(indices=[
        {"index": "good", "count": 10},
        {"index": "bad", "count": "lots"}]))
    html = _get(_reader()).text
    assert "NaN" not in html
    assert "width: 100.0%" in html or "width: 100%" in html


def test_no_indices_says_so(overview):
    overview(payload=_payload(indices=[]))
    assert "No indices found" in flat(_get(_reader()).text)


def test_indices_that_are_not_a_list_say_so(overview):
    overview(payload=_payload(indices="broken"))
    body = flat(_get(_reader()).text)
    assert "not in a shape" in body
    assert "No indices found" not in body


# ---------------------------------------------------------------------------
# Severity pills
# ---------------------------------------------------------------------------


def test_a_recorded_zero_and_an_unrecorded_severity_differ(overview):
    """`if (sev.critical)` drew nothing for both."""
    overview(payload=_payload(indices=[
        {"index": "zeros", "count": 5, "severity": {"critical": 0}},
        {"index": "nothing", "count": 5}]))
    html = _get(_reader()).text
    assert "no severity breakdown" in flat(html)
    assert "no severity data" in flat(html)


def test_an_index_with_no_alerts_says_so_rather_than_nothing(overview):
    overview(payload=_payload(indices=[
        {"index": "quiet", "count": 0, "severity": {}}]))
    assert "no alerts in time range" in flat(_get(_reader()).text)


# ---------------------------------------------------------------------------
# Failures of the read itself
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("payload", [None, "broken", []])
def test_a_body_that_is_not_a_mapping_is_a_failure(overview, payload):
    overview(payload=payload)
    body = flat(_get(_reader()).text)
    assert "could not" in body.lower() or "not a quiet estate" in body


def test_a_refusal_is_reported(overview):
    overview(raises=HTTPException(status_code=400, detail="hours too large"))
    assert "hours too large" in flat(_get(_reader()).text)


def test_an_unexpected_exception_does_not_render_an_empty_estate(overview):
    overview(raises=RuntimeError("the service went away"))
    body = flat(_get(_reader()).text)
    assert "not a quiet estate" in body


# ---------------------------------------------------------------------------
# The page
# ---------------------------------------------------------------------------


def test_the_page_no_longer_sets_the_stats_bar_itself():
    """Two things writing the same six spans would disagree."""
    body = re.sub(r"\{#.*?#\}", "", PAGE.read_text(encoding="utf-8"),
                  flags=re.S)
    body = re.sub(r"//[^\n]*", "", body)
    for ident in ("sys-s-total", "sys-s-logs", "sys-s-systems",
                  "sys-s-mapped", "sys-s-critical"):
        assert "setText('" + ident not in body, ident
    assert "covEl.style.color" not in body


def test_the_page_no_longer_builds_the_index_table():
    body = re.sub(r"\{#.*?#\}", "", PAGE.read_text(encoding="utf-8"),
                  flags=re.S)
    assert "function renderIndexTable" not in body
    assert "loadSystemFragment" in body


def test_the_card_grid_messages_are_built_rather_than_parsed():
    body = re.sub(r"\{#.*?#\}", "", PAGE.read_text(encoding="utf-8"),
                  flags=re.S)
    helper = re.search(r"\bfunction ionSysMessage\(.*?\n\}", body, re.S)
    assert helper, "the shared message helper"
    assert "textContent" in helper.group(0)
    assert "replaceChildren" in helper.group(0)
    assert not re.search(r"\.innerHTML\s*=", helper.group(0))


def test_the_card_grid_moved_with_its_structure_intact():
    """buildSysCard was a hundred lines: a mapped indicator, a
    per-namespace icon and colour, a sparkline, a top-rules table, a TIDE
    coverage bar with its own thresholds, a CyAB readiness line and an
    unmapped badge. It was deferred on the first pass precisely because a
    simplified card would have dropped most of it, so what this checks is
    that every piece came across.
    """
    body = PAGE.read_text(encoding="utf-8")
    assert "function buildSysCard" not in body
    fragment = (ROOT / "src/ion/web/templates/_fragments"
                / "analytics_system.html").read_text(encoding="utf-8")
    for piece in ("sys-card-header", "sys-icon", "sys-card-alerts",
                  "sys-sev-row", "sys-sparkline", "sys-meta",
                  "sys-rules-section", "sys-rule-row", "sys-rule-count",
                  "sys-tide-bar", "sys-tide-progress-fill",
                  "sys-tide-stats", "sys-unmapped-badge",
                  "tide-label-left", "tide-label-right"):
        assert piece in fragment, piece
