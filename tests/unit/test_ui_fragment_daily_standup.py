"""The duty check report: a sweep that refused must not read as a clean SOC.

Every assertion here is about one of the three outcomes staying three. The
page this replaces collapsed them at eighteen separate sites: `?? 0` on the
critical-alert count, `|| []` on the alert list, the stale-case list, the
host list and the rule-failure list, `?? 0` on hours-open, on gap hours, on
every per-node packet and byte figure, and `|| 0` on the per-country session
count. A standup is read once a morning by somebody deciding whether to
escalate, so "we could not look" rendering as "nothing to see" is the worst
failure this page has.

The routes are driven with TestClient and a stubbed reader rather than the
fragment templates being rendered directly, because a template rendered
directly never exercises the branch that decides which outcome it is.
"""
from __future__ import annotations

import re
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ion.auth.dependencies import get_current_user
from ion.web.ui import daily_standup as page

PAGE = Path(__file__).parents[2] / "src/ion/web/templates/daily_standup.html"


def user(*permissions):
    return SimpleNamespace(
        id=7, username="duty", display_name="Duty Analyst",
        has_permission=lambda p: p in permissions,
    )


@pytest.fixture()
def client():
    app = FastAPI()
    app.include_router(page.router, prefix="/ui")
    app.dependency_overrides[get_current_user] = lambda: user(
        "alert:read", "observable:read")
    return TestClient(app)


def checks(**overrides):
    """A /checks payload with every region present and readable."""
    return dict({
        "cluster_health": {
            "status": "green", "number_of_nodes": 3, "active_shards": 40,
            "indices_count": 12, "store_size": 1024,
        },
        "critical_alerts": {"critical_count": 0, "total": 0, "alerts": []},
        "stale_cases": {"count": 0, "cases": []},
        "dc_log_health": {"total_events_24h": 0, "hosts_with_gaps": 0,
                          "hosts_below_average": 0, "hosts": []},
        "wef_log_health": {"total_events_24h": 0, "hosts_with_gaps": 0,
                           "hosts_below_average": 0, "hosts": []},
        "rule_failures": {"rules": []},
        "alerts_24h": {"total": 0, "by_severity": {}, "by_status": {},
                       "source": "es"},
        "case_status_counts": {"intake_24h": 0, "open": 0, "in_progress": 0,
                               "closed_24h": 0, "by_severity_24h": {}},
        "triage_throughput": {"triaged_24h": 0, "avg_mtta_minutes": 0.0,
                              "p50_mtta_minutes": 0.0, "p90_mtta_minutes": 0.0},
        "duty": {"assigned": False, "user": None, "acknowledged": False},
    }, **overrides)


def stub_checks(monkeypatch, payload):
    async def reader():
        return payload
    monkeypatch.setattr(page, "daily_checks_payload", reader)


# ---------------------------------------------------------------------------
# /checks — the sweep
# ---------------------------------------------------------------------------


def test_a_measured_zero_and_an_unmeasured_figure_are_different(
        monkeypatch, client):
    """Every counter on this page used `?? 0`, so an absent key printed 0.

    The same render is asked for twice: once with zeros that were measured
    and once with the keys simply missing. If the two bodies are equal the
    page is still collapsing the outcomes.
    """
    stub_checks(monkeypatch, checks())
    measured = client.get("/ui/daily-standup/checks").text

    stub_checks(monkeypatch, checks(
        critical_alerts={"alerts": []},
        alerts_24h={"by_severity": {}, "by_status": {}},
        case_status_counts={"by_severity_24h": {}},
        triage_throughput={},
        stale_cases={"cases": []},
        dc_log_health={"hosts": []},
        wef_log_health={"hosts": []},
    ))
    unmeasured = client.get("/ui/daily-standup/checks").text

    assert measured != unmeasured
    assert "Unknown" in unmeasured
    # and the zeros really were rendered as zeros in the first pass
    assert re.search(r">\s*0\s*<", measured)


def test_a_refused_sweep_states_the_refusal_and_measures_nothing(
        monkeypatch, client, caplog):
    def boom():
        raise RuntimeError("elasticsearch unreachable")

    async def reader():
        boom()
    monkeypatch.setattr(page, "daily_checks_payload", reader)

    response = client.get("/ui/daily-standup/checks")
    assert response.status_code == 200          # htmx will not swap a 5xx
    body = response.text
    assert "could not be read" in body
    for sentence in ("No critical alerts in last 24h", "No stale cases",
                     "No rule failures detected"):
        assert sentence not in body
    assert any(r.exc_info for r in caplog.records)


def test_a_region_that_threw_inside_the_sweep_is_not_an_empty_region(
        monkeypatch, client):
    """`daily_checks_payload` catches a check's exception and substitutes
    `{"error": ...}`. That is a failed read, not a quiet estate."""
    stub_checks(monkeypatch, checks(
        critical_alerts={"error": "es timeout"},
        stale_cases={"error": "db locked"},
        rule_failures={"error": "no index"},
        dc_log_health={"error": "boom"},
    ))
    body = client.get("/ui/daily-standup/checks").text
    assert "No critical alerts in last 24h" not in body
    assert "No stale cases" not in body
    assert "No rule failures detected" not in body
    assert body.count("could not be read") >= 4


def test_an_empty_sweep_says_nothing_found_rather_than_failing(
        monkeypatch, client):
    """The positive control: with every list measured and empty the page
    must use the empty-state wording, or the test above proves nothing."""
    stub_checks(monkeypatch, checks())
    body = client.get("/ui/daily-standup/checks").text
    assert "No critical alerts in last 24h" in body
    assert "No stale cases" in body
    assert "No rule failures detected" in body
    assert "could not be read" not in body


def test_a_severity_nobody_set_is_not_rendered_as_low(monkeypatch, client):
    """`{critical:..,high:..,medium:..,low:..}[s] || 'ds-sev-low'` painted an
    unclassified alert with the low pill, so it looked triaged."""
    stub_checks(monkeypatch, checks(critical_alerts={
        "critical_count": 2, "total": 2,
        "alerts": [
            {"timestamp": "2026-10-13T06:00:00+00:00", "severity": None,
             "rule_name": "No severity", "host": "h1", "status": "open"},
            {"timestamp": "2026-10-13T06:05:00+00:00", "severity": "critical",
             "rule_name": "Has severity", "host": "h2", "status": "open"},
        ],
    }))
    body = client.get("/ui/daily-standup/checks").text
    assert "ds-sev-unknown" in body
    assert body.count("ds-sev-low") == 0


def test_the_rule_column_never_falls_back_to_a_document_id(
        monkeypatch, client):
    """The raw Elasticsearch document id leaked into the Rule Name column
    whenever rule_name and title were both missing, and analysts read it as
    the rule's name. The id stays in the carried sweep, which is the record
    POSTed to /save; it is the reader's column that must not show it."""
    stub_checks(monkeypatch, checks(critical_alerts={
        "critical_count": 1, "total": 1,
        "alerts": [{"id": "abcd-1234-leaked", "severity": "high",
                    "host": "h", "status": "open"}],
    }))
    model = client.get("/ui/daily-standup/checks",
                       headers={"accept": "application/json"}).json()
    row = model["alerts"]["rows"][0]
    assert row["rule"] == "(rule unknown)"
    assert "abcd-1234-leaked" not in row.values()

    body = client.get("/ui/daily-standup/checks").text
    table = body.split("Critical Alerts (Last 24h)", 1)[1].split("</table>", 1)[0]
    assert "abcd-1234-leaked" not in table
    assert "(rule unknown)" in table


def test_the_fallback_banner_appears_only_for_the_fallback_source(
        monkeypatch, client):
    stub_checks(monkeypatch, checks(critical_alerts={
        "critical_count": 1, "total": 1, "alerts": [],
        "source": "ion_fallback", "fallback_reason": "ES returned nothing",
    }))
    assert "ION-local fallback" in client.get("/ui/daily-standup/checks").text
    stub_checks(monkeypatch, checks())
    assert "ION-local fallback" not in client.get(
        "/ui/daily-standup/checks").text


def test_hours_open_without_a_creation_time_is_not_zero_point_zero(
        monkeypatch, client):
    """`(c.hours_open ?? 0).toFixed(1)` printed "0.0" hours open for a case
    whose creation time the query did not return, and hours open is the one
    figure that decides whether a stale case gets chased today."""
    stub_checks(monkeypatch, checks(stale_cases={
        "count": 1,
        "cases": [{"case_number": "CASE-1", "title": "t", "severity": "high",
                   "assigned_to": "nobody", "triggered_rules": []}],
    }))
    model = client.get("/ui/daily-standup/checks",
                       headers={"accept": "application/json"}).json()
    row = model["stale"]["rows"][0]
    assert row["hours"] is None and row["hours_state"] is None

    body = client.get("/ui/daily-standup/checks").text
    table = body.split("Stale Cases", 1)[1].split("</table>", 1)[0]
    assert "0.0" not in table
    assert "Unknown" in table
    # and a case that does carry hours still prints them
    stub_checks(monkeypatch, checks(stale_cases={
        "count": 1,
        "cases": [{"case_number": "CASE-1", "title": "t", "severity": "high",
                   "assigned_to": "nobody", "triggered_rules": [],
                   "hours_open": 80}],
    }))
    body = client.get("/ui/daily-standup/checks").text
    table = body.split("Stale Cases", 1)[1].split("</table>", 1)[0]
    assert "80.0" in table
    assert "ds-hours-critical" in table


def test_log_health_tells_apart_error_unconfigured_and_zero_hosts(
        monkeypatch, client):
    bodies = {}
    for key, health in [
        ("error", {"status": "error", "error": "field missing",
                   "diag": {"index": "logs-*", "host_field": "host.name",
                            "patterns": ["dc*"], "total_hits": 0,
                            "host_count": 0}}),
        ("unconfigured", {"status": "not_configured",
                          "error": "Set ION_ELASTICSEARCH_URL"}),
        ("empty", {"total_events_24h": 0, "hosts_with_gaps": 0,
                   "hosts_below_average": 0, "hosts": []}),
    ]:
        stub_checks(monkeypatch, checks(dc_log_health=health))
        bodies[key] = client.get("/ui/daily-standup/checks").text

    assert "Elasticsearch query failed" in bodies["error"]
    assert "Not configured" in bodies["unconfigured"]
    assert "patterns matched zero hosts" in bodies["empty"]
    assert len({bodies["error"], bodies["unconfigured"], bodies["empty"]}) == 3


def test_a_panel_light_reports_the_worst_host_not_the_first(
        monkeypatch, client):
    """`hosts.some(h => h.status === 'critical')` is what the JavaScript did
    and it is right. The ordering is what makes it worth pinning: the good
    host is first in the list."""
    stub_checks(monkeypatch, checks(dc_log_health={
        "total_events_24h": 10, "hosts_with_gaps": 1,
        "hosts_below_average": 0,
        "hosts": [
            {"hostname": "ok-1", "status": "ok", "count_24h": 5, "avg_7d": 5,
             "gap_hours": 0},
            {"hostname": "bad-1", "status": "critical", "count_24h": 0,
             "avg_7d": 5, "gap_hours": 9},
        ],
    }))
    model = client.get("/ui/daily-standup/checks",
                       headers={"accept": "application/json"}).json()
    panel = model["log_health"][0]
    assert panel["state"] == "critical"
    assert [h["state"] for h in panel["hosts"]] == ["good", "critical"]
    assert "ds-rag-critical" in client.get("/ui/daily-standup/checks").text


def test_a_host_with_no_status_is_unknown_rather_than_green(
        monkeypatch, client):
    """`h.status || 'ok'` painted a host whose status was never read with
    the green light, which is the only light that means "stop looking"."""
    stub_checks(monkeypatch, checks(dc_log_health={
        "total_events_24h": 1, "hosts_with_gaps": 0, "hosts_below_average": 0,
        "hosts": [{"hostname": "mystery", "count_24h": 1}],
    }))
    model = client.get("/ui/daily-standup/checks",
                       headers={"accept": "application/json"}).json()
    assert model["log_health"][0]["hosts"][0]["state"] == "unknown"
    assert model["log_health"][0]["state"] == "unknown"


def test_a_host_without_a_measured_count_prints_no_count(monkeypatch, client):
    """`(h.count_24h ?? h.events_24h ?? 0).toLocaleString()` reported a host
    that sent no figure as a host that saw no events, which is the exact
    reading a log-source panel exists to prevent."""
    stub_checks(monkeypatch, checks(dc_log_health={
        "total_events_24h": 1, "hosts_with_gaps": 0, "hosts_below_average": 0,
        "hosts": [{"hostname": "silent", "status": "critical"}],
    }))
    model = client.get("/ui/daily-standup/checks",
                       headers={"accept": "application/json"}).json()
    host = model["log_health"][0]["hosts"][0]
    assert host["name"] == "silent"
    assert host["events"] is None and host["avg"] is None
    assert host["gaps"] is None and host["gap_shown"] is False
    assert "silent" in client.get("/ui/daily-standup/checks").text


def test_rule_failures_read_both_payload_shapes(monkeypatch, client):
    stub_checks(monkeypatch, checks(rule_failures={"rules": [
        {"name": "new shape", "failures": 4, "last_failure": None},
        {"rule_name": "old shape", "failure_count": 2, "last_failure": None},
    ]}))
    body = client.get("/ui/daily-standup/checks").text
    assert "new shape" in body and "old shape" in body
    assert ">4<" in body and ">2<" in body


def test_the_saved_payload_is_the_payload_that_was_rendered(
        monkeypatch, client):
    """The page POSTs `checks_data` to /save, /pdf and /pptx. It used to be
    the JSON the browser had fetched. The fragment carries the same object so
    a sign-off still records the sweep the analyst actually read, without a
    second Elasticsearch sweep to go and fetch it again."""
    stub_checks(monkeypatch, checks())
    body = client.get("/ui/daily-standup/checks").text
    assert "data-ds-checks=" in body
    assert "cluster_health" in body

    stub_checks(monkeypatch, checks())
    model = client.get("/ui/daily-standup/checks",
                       headers={"accept": "application/json"}).json()
    assert model["raw"]["cluster_health"]["status"] == "green"


def test_the_cluster_badge_carries_a_state_not_a_colour(monkeypatch, client):
    seen = {}
    for status, token in [("green", "good"), ("yellow", "warning"),
                          ("red", "critical")]:
        stub_checks(monkeypatch, checks(cluster_health={"status": status}))
        seen[status] = client.get(
            "/ui/daily-standup/checks",
            headers={"accept": "application/json"}).json()["cluster"]["state"]
    assert seen == {"green": "good", "yellow": "warning", "red": "critical"}


# ---------------------------------------------------------------------------
# /duty — three states, because each sends somebody somewhere different
# ---------------------------------------------------------------------------


def test_duty_keeps_unavailable_apart_from_nobody_rostered(
        monkeypatch, client):
    monkeypatch.setattr(page, "duty_today", lambda: None)
    unavailable = client.get("/ui/daily-standup/duty").text

    monkeypatch.setattr(page, "duty_today",
                        lambda: {"assigned": False, "user": None})
    nobody = client.get("/ui/daily-standup/duty").text

    monkeypatch.setattr(page, "duty_today", lambda: {
        "assigned": True, "acknowledged": False,
        "user": {"name": "Alex <b>Doe</b>"}})
    named = client.get("/ui/daily-standup/duty").text

    assert "unavailable" in unavailable.lower()
    assert "Nobody is on duty" in nobody
    assert "not acknowledged" in named
    assert "Alex &lt;b&gt;Doe&lt;/b&gt;" in named
    assert "<b>Doe</b>" not in named
    assert len({unavailable, nobody, named}) == 3


def test_a_duty_lookup_that_throws_is_unavailable_not_nobody(
        monkeypatch, client, caplog):
    def boom():
        raise RuntimeError("rota table gone")
    monkeypatch.setattr(page, "duty_today", boom)
    body = client.get("/ui/daily-standup/duty").text
    assert "unavailable" in body.lower()
    assert "Nobody is on duty" not in body
    assert any(r.exc_info for r in caplog.records)


# ---------------------------------------------------------------------------
# Arkime panels
# ---------------------------------------------------------------------------


def test_every_high_risk_country_is_listed_even_with_no_sessions(
        monkeypatch, client):
    async def reader(current_user):
        return {"configured": True, "countries": [
            {"country_code": "RU", "session_count": 3, "nodes": []}]}
    monkeypatch.setattr(page, "check_arkime_high_risk", reader)
    body = client.get("/ui/daily-standup/arkime/countries").text
    for code in ("RU", "CN", "IR", "KP", "SY"):
        assert f'data-country="{code}"' in body
    assert "ds-country-count active" in body or "active" in body


def test_an_unconfigured_arkime_is_not_five_countries_with_no_traffic(
        monkeypatch, client):
    async def reader(current_user):
        return {"configured": False}
    monkeypatch.setattr(page, "check_arkime_high_risk", reader)
    body = client.get("/ui/daily-standup/arkime/countries").text
    assert "not configured" in body.lower()
    assert "Sessions: 0" not in body


def test_an_arkime_country_read_that_threw_says_so(monkeypatch, client, caplog):
    async def reader(current_user):
        raise RuntimeError("arkime down")
    monkeypatch.setattr(page, "check_arkime_high_risk", reader)
    body = client.get("/ui/daily-standup/arkime/countries").text
    assert "could not be read" in body
    assert "Sessions: 0" not in body
    assert any(r.exc_info for r in caplog.records)


def test_node_stats_keep_unconfigured_error_and_empty_apart(
        monkeypatch, client):
    bodies = []
    for payload in ({"configured": False},
                    {"configured": True, "error": "HTTP 502"},
                    {"configured": True, "nodes": []}):
        async def reader(current_user, _p=payload):
            return _p
        monkeypatch.setattr(page, "arkime_node_stats", reader)
        bodies.append(client.get("/ui/daily-standup/arkime/nodes").text)
    assert "not configured" in bodies[0].lower()
    assert "HTTP 502" in bodies[1]
    assert "No capture nodes" in bodies[2]
    assert len(set(bodies)) == 3


def test_a_node_without_counters_prints_no_counters(monkeypatch, client):
    async def reader(current_user):
        return {"configured": True, "nodes": [{"name": "cap-1"}]}
    monkeypatch.setattr(page, "arkime_node_stats", reader)
    body = client.get("/ui/daily-standup/arkime/nodes").text
    assert "cap-1" in body
    assert "Unknown" in body
    # `(n.packets_24h || 0).toLocaleString()` printed a confident 0
    assert ">0<" not in body


def test_a_node_with_drops_is_marked_and_one_without_is_not(
        monkeypatch, client):
    async def reader(current_user):
        return {"configured": True, "nodes": [
            {"name": "clean", "dropped": 0, "es_dropped": 0,
             "overload_dropped": 0, "cpu": 1, "packets_24h": 1,
             "bytes_24h": 1, "sessions_24h": 1},
            {"name": "dropping", "dropped": 5, "es_dropped": 0,
             "overload_dropped": 0, "cpu": 1, "packets_24h": 1,
             "bytes_24h": 1, "sessions_24h": 1},
        ]}
    monkeypatch.setattr(page, "arkime_node_stats", reader)
    body = client.get("/ui/daily-standup/arkime/nodes").text
    assert body.count("ds-node-dropping") == 1


# ---------------------------------------------------------------------------
# Threat landscape: reports, one report, the AI summary
# ---------------------------------------------------------------------------


def test_no_reports_available_is_not_a_failed_opencti_read(
        monkeypatch, client, caplog):
    async def empty(limit, user):
        return {"reports": []}
    monkeypatch.setattr(page, "get_recent_reports", empty)
    assert "No reports available" in client.get(
        "/ui/daily-standup/reports").text

    async def boom(limit, user):
        raise RuntimeError("opencti refused")
    monkeypatch.setattr(page, "get_recent_reports", boom)
    body = client.get("/ui/daily-standup/reports").text
    assert "could not be read" in body
    assert "No reports available" not in body
    assert any(r.exc_info for r in caplog.records)


def test_a_report_row_carries_its_id_through_tojson(monkeypatch, client):
    async def reader(limit, user):
        return {"reports": [{"id": "report--a'b", "name": "Quarterly",
                             "published": None}]}
    monkeypatch.setattr(page, "get_recent_reports", reader)
    body = client.get("/ui/daily-standup/reports").text
    assert "data-click-action=\"dsOpenReport\"" in body
    assert "report--a" in body
    assert "report--a'b" not in body       # escaped, not interpolated raw


def test_a_report_detail_that_refuses_is_not_an_empty_report(
        monkeypatch, client, caplog):
    async def boom(report_id, user):
        raise RuntimeError("opencti refused")
    monkeypatch.setattr(page, "get_report_detail", boom)
    body = client.get("/ui/daily-standup/reports/report--1").text
    assert "could not be read" in body
    assert "No details available" not in body
    assert any(r.exc_info for r in caplog.records)

    async def bare(report_id, user):
        return {"name": "Bare report"}
    monkeypatch.setattr(page, "get_report_detail", bare)
    body = client.get("/ui/daily-standup/reports/report--1").text
    assert "No details available" in body
    assert "could not be read" not in body


def test_a_confidence_of_zero_is_shown_and_a_missing_one_is_not(
        monkeypatch, client):
    async def zero(report_id, user):
        return {"name": "r", "confidence": 0, "body": "b"}
    monkeypatch.setattr(page, "get_report_detail", zero)
    assert "Confidence 0%" in client.get(
        "/ui/daily-standup/reports/report--1").text

    async def absent(report_id, user):
        return {"name": "r", "body": "b"}
    monkeypatch.setattr(page, "get_report_detail", absent)
    assert "Confidence" not in client.get(
        "/ui/daily-standup/reports/report--1").text


def test_the_ai_summary_distinguishes_a_refusal_from_an_empty_answer(
        monkeypatch, client, caplog):
    async def boom(user):
        raise RuntimeError("ollama offline")
    monkeypatch.setattr(page, "ai_threat_summary", boom)
    body = client.post("/ui/daily-standup/threat-summary").text
    assert "could not be" in body
    assert any(r.exc_info for r in caplog.records)

    async def blank(user):
        return {"summary": ""}
    monkeypatch.setattr(page, "ai_threat_summary", blank)
    body = client.post("/ui/daily-standup/threat-summary").text
    assert "returned no summary" in body
    assert "could not be" not in body


def test_the_ai_summary_is_carried_as_text_for_the_browsers_sanitiser(
        monkeypatch, client):
    async def reader(user):
        return {"summary": "# Heading\n<img src=x onerror=alert(1)>"}
    monkeypatch.setattr(page, "ai_threat_summary", reader)
    body = client.post("/ui/daily-standup/threat-summary").text
    assert "<img src=x" not in body
    assert "&lt;img src=x" in body


# ---------------------------------------------------------------------------
# Gates. Each fragment must be exactly as hard to reach as its JSON twin.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("method,path,permission", [
    ("get", "/ui/daily-standup/checks", "alert:read"),
    ("get", "/ui/daily-standup/duty", "alert:read"),
    ("get", "/ui/daily-standup/arkime/countries", "alert:read"),
    ("get", "/ui/daily-standup/arkime/nodes", "alert:read"),
    ("get", "/ui/daily-standup/reports", "observable:read"),
    ("get", "/ui/daily-standup/reports/report--1", "observable:read"),
    ("post", "/ui/daily-standup/threat-summary", "observable:read"),
])
def test_each_fragment_mirrors_its_endpoints_permission(
        method, path, permission, monkeypatch):
    # Every reader stubbed, so a permitted request renders rather than
    # sweeping Elasticsearch and the local database from a unit test.
    async def nothing(*args, **kwargs):
        return {}
    for name in ("daily_checks_payload", "check_arkime_high_risk",
                 "arkime_node_stats", "get_recent_reports",
                 "get_report_detail", "ai_threat_summary"):
        monkeypatch.setattr(page, name, nothing)
    monkeypatch.setattr(page, "duty_today", lambda: None)

    app = FastAPI()
    app.include_router(page.router, prefix="/ui")
    client = TestClient(app)
    call = getattr(client, method)

    assert call(path).status_code == 401
    app.dependency_overrides[get_current_user] = lambda: user("nothing:at:all")
    assert call(path).status_code == 403
    app.dependency_overrides[get_current_user] = lambda: user(permission)
    assert call(path).status_code == 200


# ---------------------------------------------------------------------------
# The page shell
# ---------------------------------------------------------------------------


def shell() -> str:
    """The page with its comments stripped.

    Four checks in this repository have passed against their own
    explanatory prose, so the prose is removed before anything is matched.
    """
    source = PAGE.read_text(encoding="utf-8")
    return re.sub(r"<!--.*?-->|\{#.*?#\}|/\*.*?\*/", "", source, flags=re.S)


def test_the_shell_builds_no_markup_and_carries_no_stylesheet():
    source = shell()
    assert ".innerHTML" not in source
    assert "insertAdjacentHTML" not in source
    assert "<style" not in source
    assert "function esc(" not in source
    assert "function sevPill(" not in source
    assert "ds-standup.css" in source


def test_the_controls_that_retry_sit_outside_what_they_swap():
    """A render that says the sweep failed must not remove the button that
    runs it again."""
    source = shell()
    before, after = source.split('id="ds-checks"', 1)
    assert 'id="btn-run-checks"' in before
    assert "hx-get=\"/ui/daily-standup/checks\"" in before


def test_client_only_markup_is_a_template_outside_the_script_block():
    """A <template> inside <script> is inert text and cloneTemplate returns
    null, so every control built from it vanishes silently."""
    source = shell()
    head, script = source.split("<script", 1)
    for template_id in ("ds-save-dirty-template", "ds-save-ok-template",
                        "ds-save-failed-template"):
        assert f'id="{template_id}"' in head, template_id
        assert f'id="{template_id}"' not in script, template_id
