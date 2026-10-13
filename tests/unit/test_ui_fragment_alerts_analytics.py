"""The analytics drawer's trend chart, donuts and bar lists as a fragment.

Every test drives the route. The helpers are also asserted directly where
the thing under test is a boundary a render cannot pin precisely, and each
of those says why.

Measured on the page before this stage:

  * renderTrendChart opened with `if (!container || allAlerts.length === 0)`
    and then wrote `container.innerHTML` inside that branch, dereferencing
    the thing it had just tested for null.
  * All five renderers answered an empty set with "No data", and allAlerts
    stays empty after a failed read, so a window nobody could read showed
    "No data" in five charts at once.
  * The trend labels came from toLocaleTimeString over buckets computed as
    absolute instants, so the axis moved with the reader's zone.
  * renderTopCountries counted `geo.country_name || geo.country_iso_code`
    and skipped an alert whose geo block had neither, so a window of alerts
    all geolocated to nowhere read as a window with no geo data.
  * renderTriageStatusDonut read `triageCache[a.id]?.status || 'open'`, so
    the statuses came from the batch read and an alert with no record
    counted as open.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import ion.web.elasticsearch_api as es_api
from ion.web.ui import alerts as mod
from ion.web.ui.alerts import (
    ANALYTICS_TOP_N,
    QUEUE_LIMIT,
    SEVERITY_COLOURS,
    TRIAGE_COLOURS,
    country_counts,
    donut_arcs,
    router,
    top_counts,
    trend_buckets,
    triage_slice_counts,
)

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "src/ion/web/templates/alerts.html"
FRAGMENTS = ROOT / "src/ion/web/templates/_fragments"
URL = "/ui/alerts/analytics"

NOW = datetime.now(timezone.utc)


def text_of(markup: str) -> str:
    import html as _html
    return " ".join(_html.unescape(re.sub(r"<[^>]+>", " ", markup)).split())


class _User:
    id = 1
    username = "analytics-tester"

    def __init__(self, *permissions: str):
        self.permissions = set(permissions)

    def has_permission(self, name: str) -> bool:
        return name in self.permissions


def _alert(hours_ago=2, severity="high", host="ws-01", rule="Odd login",
           country="Germany", alert_id=None):
    row: dict[str, Any] = {
        "id": alert_id or f"a{hours_ago}-{host}-{rule}",
        "timestamp": (NOW - timedelta(hours=hours_ago)).isoformat(),
        "severity": severity, "host": host, "rule_name": rule,
    }
    if country is not None:
        row["raw_data"] = {"source": {"geo": {"country_name": country}}}
    return row


@pytest.fixture
def read(monkeypatch):
    """Stub the alerts read and the triage batch the route makes."""
    box: dict[str, Any] = {"payload": {"alerts": []}, "triage": {}}

    async def alerts(**_kw):
        value = box["payload"]
        if isinstance(value, Exception):
            raise value
        return value

    async def triage(ids, current_user, session):
        return box["triage"]

    monkeypatch.setattr(es_api, "get_es_alerts", alerts)
    monkeypatch.setattr(mod, "_triage_map", triage)
    return box


def get(*permissions: str, query: str = "time_range=24"):
    from ion.auth.dependencies import get_current_user
    from ion.storage.database import get_db_session

    app = FastAPI()
    app.include_router(router, prefix="/ui")
    app.dependency_overrides[get_current_user] = lambda: _User(
        *(permissions or ("alert:read",)))
    app.dependency_overrides[get_db_session] = lambda: None
    with TestClient(app) as client:
        return client.get(f"{URL}?{query}")


# ---------------------------------------------------------------------------
# The gate
# ---------------------------------------------------------------------------


def test_the_fragment_carries_the_gate_its_read_requires(read):
    assert get("case:read").status_code == 403
    assert get("alert:read").status_code == 200


# ---------------------------------------------------------------------------
# One answer where there were five wrong ones
# ---------------------------------------------------------------------------


def test_a_failed_read_says_so_once_and_no_chart_claims_a_measurement(read):
    read["payload"] = RuntimeError("elasticsearch down")
    body = get().text
    assert "could not be read" in text_of(body)
    assert "No data" not in body, (
        "the page said No data in five charts for a read nobody could do")
    # Each of the five out-of-band charts says it was not counted.
    for container in ("chart-severity", "chart-triage-status",
                      "chart-top-countries", "chart-top-hosts",
                      "chart-top-rules"):
        block = body[body.index(f'id="{container}"'):]
        block = block[:block.index("</div>")]
        assert "Not counted" in block, container


def test_a_payload_with_no_alert_list_is_a_failed_read(read):
    read["payload"] = {"message": "Elasticsearch is not configured"}
    assert "could not be read" in text_of(get().text)


def test_an_empty_window_is_a_measurement_not_a_failure(read):
    read["payload"] = {"alerts": []}
    body = get().text
    assert "could not be read" not in text_of(body)
    assert "No alerts in the last 24 hours" in text_of(body)
    assert "Not counted" not in body


def test_a_degraded_read_shows_its_message_beside_the_charts(read):
    read["payload"] = {"alerts": [_alert()], "message": "lab fixtures only"}
    body = get().text
    assert "lab fixtures only" in body
    assert "could not be read" not in text_of(body)


# ---------------------------------------------------------------------------
# The trend chart
# ---------------------------------------------------------------------------


def test_a_bucket_with_nothing_in_it_is_a_measured_zero(read):
    read["payload"] = {"alerts": [_alert(hours_ago=2)]}
    body = get().text
    bars = re.findall(r'<rect[^>]*class="chart-bar', body)
    assert len(bars) == 24, "a 24 hour window has 24 hourly buckets"
    assert 'height="0' in body or 'height="0.0"' in body, (
        "the empty buckets render as zero-height bars, which is the point of "
        "a trend chart")


def test_the_axis_is_labelled_utc_rather_than_the_readers_clock(read):
    read["payload"] = {"alerts": [_alert()]}
    body = get().text
    assert "times in UTC" in body
    assert "in UTC" in body[body.index("aria-label"):body.index("aria-label") + 120]


@pytest.mark.parametrize("hours, buckets", [
    (1, 12), (24, 24), (168, 28), (720, 30),
])
def test_the_bucket_plan_is_the_one_the_page_chose(hours, buckets):
    """Asserted on the helper. The boundaries are the point, and driving a
    720 hour window through a render would need 30 buckets of synthetic
    alerts to say anything about the plan."""
    out = trend_buckets([], hours, now=NOW)
    assert len(out["buckets"]) == buckets


def test_an_alert_with_no_timestamp_is_not_bucketed(read):
    read["payload"] = {"alerts": [
        {"id": "x", "severity": "high", "host": "h", "rule_name": "r"}]}
    body = get().text
    assert "No alerts in the last 24 hours" in text_of(body), (
        "an alert that cannot be placed in time is not in any bucket")


def test_an_alert_outside_the_window_is_not_bucketed():
    out = trend_buckets([_alert(hours_ago=48)], 24, now=NOW)
    assert out["total"] == 0


def test_the_bar_title_names_the_bucket_and_its_severities(read):
    read["payload"] = {"alerts": [
        _alert(hours_ago=2, severity="critical"),
        _alert(hours_ago=2, severity="high", host="ws-02"),
    ]}
    body = get().text
    assert "2 alerts" in body
    assert "1 critical" in body
    assert "1 high" in body


# ---------------------------------------------------------------------------
# The donuts
# ---------------------------------------------------------------------------


def test_a_donut_with_no_list_is_none_rather_than_an_empty_one():
    """None in, None out, so the template can say it was not counted. A
    total of zero is a different thing and the next test pins it."""
    assert donut_arcs(None, SEVERITY_COLOURS) is None


def test_a_donut_of_all_zeroes_is_a_measurement():
    out = donut_arcs([{"label": "Critical", "value": 0},
                      {"label": "High", "value": 0}], SEVERITY_COLOURS)
    assert out is not None
    assert out["total"] == 0
    assert out["arcs"] == [] and out["legend"] == []


def test_a_zero_slice_is_left_out_of_the_drawing(read):
    """`if (d.value === 0) return;` in both loops. A severity nothing arrived
    under is not a wedge of zero width and not a legend row."""
    read["payload"] = {"alerts": [_alert(severity="critical")]}
    body = get().text
    severity = body[body.index('id="chart-severity"'):]
    severity = severity[:severity.index("</div>")]
    assert severity.count("donut-segment") == 1
    assert "Critical" in severity
    assert "Medium" not in severity


def test_the_donut_colours_are_the_ones_that_were_on_screen(read):
    """The port is meant to be invisible, so these are the page's hexes and
    not ones that merely look similar."""
    read["payload"] = {"alerts": [_alert(severity="critical")]}
    read["triage"] = {}
    body = get().text
    assert SEVERITY_COLOURS[0] == "#f44336"
    assert TRIAGE_COLOURS[0] == "#1976d2"
    assert "#f44336" in body


def test_the_centre_total_and_the_legend_percentages_are_rendered(read):
    read["payload"] = {"alerts": [_alert(severity="critical"),
                                  _alert(severity="high", host="ws-02")]}
    body = get().text
    severity = body[body.index('id="chart-severity"'):]
    assert ">2<" in severity[:severity.index("</div>")]
    assert "(50%)" in severity[:severity.index("</div>")]


# ---------------------------------------------------------------------------
# The triage donut reads the batch, not the alert rows
# ---------------------------------------------------------------------------


def test_an_alert_with_no_triage_record_counts_as_open(read):
    """`triageCache[a.id]?.status || 'open'` is the page's rule: an alert
    nobody has triaged is open."""
    read["payload"] = {"alerts": [_alert(alert_id="a1")]}
    read["triage"] = {}
    body = get().text
    block = body[body.index('id="chart-triage-status"'):]
    block = block[:block.index("</div>")]
    assert "Open" in block
    assert "Not counted" not in block


def test_the_triage_statuses_come_from_the_batch_read(read):
    read["payload"] = {"alerts": [_alert(alert_id="a1"), _alert(alert_id="a2",
                                                                host="ws-02")]}
    read["triage"] = {"a1": {"status": "closed"}}
    body = get().text
    block = body[body.index('id="chart-triage-status"'):]
    block = block[:block.index("</div>")]
    assert "Closed" in block and "Open" in block


def test_a_failed_triage_batch_blames_the_triage_read_not_the_alert_read(read):
    """Two reads, two causes. Saying "the alerts could not be read" for a
    failed triage batch names the wrong one, and the alerts were read."""
    read["payload"] = {"alerts": [_alert(alert_id="a1")]}
    read["triage"] = None
    body = get().text
    block = body[body.index('id="chart-triage-status"'):]
    block = block[:block.index("</div>")]
    assert "triage records" in text_of(block)
    assert "the alerts could not be read" not in text_of(block)
    # The severity donut still renders: its own read succeeded.
    severity = body[body.index('id="chart-severity"'):]
    assert "donut-segment" in severity[:severity.index("</div>")]


def test_a_non_mapping_triage_record_is_treated_as_untriaged():
    out = triage_slice_counts([{"id": "a1"}], {"a1": "not a dict"})
    assert out[0] == {"label": "Open", "value": 1}


# ---------------------------------------------------------------------------
# The three bar lists
# ---------------------------------------------------------------------------


def test_the_bars_are_ordered_by_count_and_capped(read):
    read["payload"] = {"alerts": (
        [_alert(host="busy") for _ in range(3)]
        + [_alert(host=f"h{i}") for i in range(ANALYTICS_TOP_N + 4)]
    )}
    body = get().text
    # The hosts block runs to where the rules block starts.
    hosts = body[body.index('id="chart-top-hosts"'):body.index('id="chart-top-rules"')]
    assert hosts.count("hbar-row") == ANALYTICS_TOP_N, (
        "capped at the page's slice(0, 7)")
    first = hosts.index("hbar-label")
    assert "busy" in hosts[first:first + 200], "the busiest host is listed first"


def test_the_bar_widths_are_shares_of_the_largest():
    rows = top_counts([_alert(host="a"), _alert(host="a"), _alert(host="b")],
                      "host")
    assert rows[0] == {"name": "a", "count": 2, "pct": 100}
    assert rows[1] == {"name": "b", "count": 1, "pct": 50}


def test_an_alert_with_no_value_for_the_field_is_not_counted():
    rows = top_counts([{"host": ""}, {"host": None}, {"host": "a"}], "host")
    assert rows == [{"name": "a", "count": 1, "pct": 100}]


def test_a_geo_block_with_no_country_is_counted_as_unattributed(read):
    """The page skipped these silently, so a window whose alerts were all
    geolocated to nowhere read as a window with no geo data at all."""
    read["payload"] = {"alerts": [{
        "id": "x", "timestamp": NOW.isoformat(), "severity": "high",
        "host": "h", "rule_name": "r",
        "raw_data": {"source": {"geo": {"continent_name": "Europe"}}}}]}
    body = get().text
    assert "no country in it" in text_of(body)


def test_an_alert_with_no_geo_block_is_not_unattributed():
    out = country_counts([_alert(country=None)])
    assert out["unattributed"] == 0
    assert out["rows"] == []


def test_the_country_iso_code_is_used_when_the_name_is_absent():
    rows = country_counts([{
        "raw_data": {"source": {"geo": {"country_iso_code": "DE"}}}}])["rows"]
    assert rows == [{"name": "DE", "count": 1, "pct": 100, "hue": 200}]


# ---------------------------------------------------------------------------
# The window the charts actually read
# ---------------------------------------------------------------------------


def test_the_truncation_is_said_out_loud(read):
    read["payload"] = {"alerts": [_alert(host=f"h{i}") for i in range(QUEUE_LIMIT)]}
    body = text_of(get().text)
    assert f"newest {QUEUE_LIMIT}" in body
    assert "not totals for the whole window" in body


def test_a_window_the_controls_could_not_express_is_said_out_loud(read):
    read["payload"] = {"alerts": [_alert()]}
    body = text_of(get(query="time_range=banana").text)
    assert "did not express a window" in body


def test_the_same_window_helpers_as_the_queue_are_used():
    """One definition of the window, so the drawer and the table cannot
    disagree about which alerts are in it."""
    import inspect
    source = inspect.getsource(mod.alerts_analytics_fragment)
    assert "queue_window(" in source
    assert "include_closed(" in source
    assert "QUEUE_LIMIT" in source


# ---------------------------------------------------------------------------
# What the page no longer does
# ---------------------------------------------------------------------------


def _page() -> str:
    return PAGE.read_text(encoding="utf-8")


WRITES = re.compile(r"innerHTML\s*\+?=|insertAdjacentHTML|outerHTML\s*\+?=")


def test_the_retired_chart_writers_are_gone():
    page = _page()
    for name in ("renderTrendChart", "renderDonut", "renderSeverityDonut",
                 "renderTriageStatusDonut", "renderTopCountries",
                 "renderHBarChart"):
        assert not re.search(r"(?<![\w.])" + name + r"\s*\(", page), name


def test_the_chevron_is_a_class_change_and_not_a_markup_build():
    page = _page()
    body = page[page.index("function toggleAnalytics("):].replace("\r\n", "\n")
    body = body[:body.index("\n}")]
    assert not WRITES.search(body)
    assert "icon-chevron-down" in body and "icon-chevron-right" in body
    assert "className" in body


def test_render_analytics_dispatches_rather_than_building_a_query_string():
    """hx-include on the container names the six controls, so the window has
    one definition. Building a query string here would be a second one."""
    page = _page()
    body = page[page.index("function renderAnalytics("):].replace("\r\n", "\n")
    body = body[:body.index("\n}")]
    assert not WRITES.search(body)
    assert "alerts-analytics" in body
    assert "URLSearchParams" not in body


def test_the_trend_container_requests_the_fragment_with_the_filter_controls():
    page = _page()
    div = page[page.index('id="chart-trend"'):]
    div = div[:div.index(">") + 1]
    assert 'hx-get="/ui/alerts/analytics"' in div
    assert 'hx-trigger="alerts-analytics from:body"' in div
    for control in ("#alert-time-range", "#custom-time-from", "#custom-time-to",
                    "#aq-tz-offset", "#alert-status-filter",
                    "#alert-system-filter"):
        assert control in div, control


def test_the_fragment_uses_no_inline_style_attribute():
    """style-src-attr is 'none' in this app's CSP, so an inline style
    attribute is dropped and a bar would lose its width."""
    text = (FRAGMENTS / "alerts_analytics.html").read_text(encoding="utf-8")
    assert not re.search(r"\sstyle=\"", text)
    assert "data-ion-style" in text


def test_the_fragment_compiles_no_htmx_expression():
    text = (FRAGMENTS / "alerts_analytics.html").read_text(encoding="utf-8")
    assert "hx-on" not in text
    assert "js:" not in text


# ---------------------------------------------------------------------------
# The survivors of this stage's mutation pass.
#
# One is an equivalent mutant and is pinned rather than tested:
# `isinstance(record, dict)` against `hasattr(record, "get")` in
# triage_slice_counts. A JSON payload yields a dict, a list, a string, a
# number, a bool or None, and none of those but dict carries `.get`, so no
# input the batch handler can produce tells the two apart. The test below
# pins that property instead of pretending to cover the branch.
#
# The other six were real gaps, each the sibling of a case already covered.
# ---------------------------------------------------------------------------


def test_only_a_mapping_is_read_as_a_triage_record():
    """Pins the equivalence behind one survivor. The isinstance check is
    correct and currently indistinguishable from a hasattr check, because
    nothing a JSON payload can hold under a key has `.get` except a dict.
    If the batch handler ever returns something that does, the check becomes
    load-bearing and this fails rather than the distinction being lost."""
    for value in ("a string", ["a", "list"], 7, 7.5, True, None):
        assert not hasattr(value, "get"), value
        out = triage_slice_counts([{"id": "a1"}], {"a1": value})
        assert out[0] == {"label": "Open", "value": 1}, value


def test_the_bucket_count_rounds_up_for_a_partial_bucket():
    """Closes a survivor. The parametrised plan test used 720 hours, which
    is 30 whole days, so ceil and floor agree and dropping the round-up
    changed nothing. A window that does not divide evenly is the only shape
    that can tell them apart, and flooring it would drop the newest partial
    bucket, which is the one holding the alerts that just arrived."""
    # 730 hours takes the daily branch: 30 whole days plus a partial one.
    assert len(trend_buckets([], 730, now=NOW)["buckets"]) == 31
    # 100 and 25 take the six-hourly branch, and neither divides evenly.
    assert len(trend_buckets([], 100, now=NOW)["buckets"]) == 17
    assert len(trend_buckets([], 25, now=NOW)["buckets"]) == 5


def test_the_bars_are_ordered_by_count_not_by_name():
    """Closes a survivor. The ordering test used a host called "busy", which
    sorts before h0..h10 alphabetically as well as by count, so sorting by
    name instead changed nothing. This name sorts last and counts most."""
    rows = top_counts(
        [{"host": "zzz-busiest"}] * 3 + [{"host": "aaa-quiet"}], "host")
    assert [r["name"] for r in rows] == ["zzz-busiest", "aaa-quiet"]
    assert rows[0]["count"] == 3


def test_the_donut_geometry_is_the_arc_that_was_on_screen():
    """Closes two survivors. Nothing asserted the path data, so the large-arc
    flag could be forced off and the slices could all start at the same
    angle without a test noticing: the donut would still have the right
    number of segments in the right colours and be drawn wrong.

    Two slices of three quarters and one quarter. The first sweeps more than
    180 degrees, so its large-arc flag is 1, and the second must start where
    the first ended rather than back at the top.
    """
    out = donut_arcs([{"label": "A", "value": 3}, {"label": "B", "value": 1}],
                     SEVERITY_COLOURS)
    assert len(out["arcs"]) == 2

    first, second = out["arcs"][0]["d"], out["arcs"][1]["d"]
    # The large-arc flag sits between the radii and the sweep flag.
    assert re.search(r"A58,58 0 1,1 ", first), ("three quarters is a large arc", first)
    assert re.search(r"A58,58 0 0,1 ", second), ("one quarter is not", second)

    # The second arc starts where the first finished. The first begins at the
    # top of the circle, so a second that also begins there means the angle
    # never advanced.
    start_first = first.split(" ")[0]
    start_second = second.split(" ")[0]
    assert start_first != start_second, (
        "every slice starting at the same angle draws them all on top of "
        "each other")
    assert start_first.startswith("M70.00,"), "the first slice starts at the top"


def test_a_failed_read_says_so_in_the_drawer_itself(read):
    """Closes a survivor. The original assertion looked for "could not be
    read" anywhere in the response, and the out-of-band donuts carry that
    phrase in their own message, so removing the failed branch from the
    drawer's own region still passed. Scoped to the region before the first
    out-of-band swap."""
    read["payload"] = RuntimeError("elasticsearch down")
    body = get().text
    drawer = body[:body.index('hx-swap-oob')]
    assert "could not be read" in text_of(drawer)
    assert "none of these charts" in text_of(drawer)
    assert "No alerts in the last" not in text_of(drawer), (
        "a failed read is not a window with no alerts in it")


def test_the_bar_lists_name_the_failed_read_rather_than_just_not_counting(read):
    """Closes a survivor. Both the failed branch and the rows-is-none branch
    said "Not counted", so dropping the first changed only which sentence
    appeared and the assertion matched either. The failed read names its
    cause."""
    read["payload"] = RuntimeError("elasticsearch down")
    body = get().text
    hosts = body[body.index('id="chart-top-hosts"'):body.index('id="chart-top-rules"')]
    assert "the alerts could not be read" in text_of(hosts), (
        "the bars say why they were not counted")
