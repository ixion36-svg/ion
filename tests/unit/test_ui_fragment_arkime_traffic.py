"""Traffic analytics: a refused Arkime query must not read as a quiet link.

The page this replaces wrote six regions with innerHTML behind its own
`escHtml`, and every numeric read on the way in was `Number(b) || 0` or
`|| []`. On an Arkime that was reachable but refusing, the stats bar showed
0 sessions and 0 bytes, the top-talker table was empty and the delta spans
were blank, which is exactly what a genuinely silent network looks like.

Routes are driven through TestClient with the API function stubbed, because
the branch that decides which of the three outcomes it is lives in the
route, not in the template.
"""
from __future__ import annotations

import re
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from ion.auth.dependencies import get_current_user
from ion.storage.database import get_db_session
from ion.web.ui import arkime_traffic as page

PAGE = Path(__file__).parents[2] / "src/ion/web/templates/arkime_traffic.html"


def user(*permissions):
    return SimpleNamespace(
        id=3, username="analyst", has_permission=lambda p: p in permissions)


def probe_app(monkeypatch):
    """A one-router app whose Arkime is configured and whose session is a
    sentinel.

    `arkime_configured` is stubbed True so the demo branch does not swallow
    the stubbed readers: these tests are about what the page says when
    Arkime IS configured, and the demo branch has its own two below.
    """
    monkeypatch.setattr(page, "arkime_configured", lambda: True)
    app = FastAPI()
    app.include_router(page.router, prefix="/ui")
    app.dependency_overrides[get_db_session] = lambda: object()
    return app


@pytest.fixture()
def client(monkeypatch):
    app = probe_app(monkeypatch)
    app.dependency_overrides[get_current_user] = lambda: user(
        "alert:read", "security:read")
    return TestClient(app)


#: list_exclusions is the one endpoint body here that is not a coroutine.
SYNC_READERS = {"list_exclusions"}


def stub(monkeypatch, name, result):
    def answer():
        if isinstance(result, Exception):
            raise result
        return result

    if name in SYNC_READERS:
        def reader(*args, **kwargs):
            return answer()
    else:
        async def reader(*args, **kwargs):
            return answer()
    monkeypatch.setattr(page, name, reader)


# ---------------------------------------------------------------------------
# /overview — the stats bar, the trend deltas and the chart series
# ---------------------------------------------------------------------------


OVERVIEW = {
    "src_histo": [[1000, 10], [2000, 20]],
    "dst_histo": [[1000, 5]],
    "protocols": {"tcp": 10, "udp": 4},
    "total_sessions": 14,
    "total_bytes": 35,
    "trend": {"sessions_pct": 12.5, "bytes_pct": -3.0},
    "range": "24h",
}


def test_zero_traffic_and_unmeasured_traffic_are_different_renders(
        monkeypatch, client):
    stub(monkeypatch, "traffic_overview", dict(
        OVERVIEW, total_sessions=0, total_bytes=0, src_histo=[], dst_histo=[],
        protocols={}))
    measured = client.get("/ui/arkime-traffic/overview?range=24h").text

    stub(monkeypatch, "traffic_overview", {"range": "24h"})
    unmeasured = client.get("/ui/arkime-traffic/overview?range=24h").text

    assert measured != unmeasured
    assert "0 B" in measured
    assert "Unknown" in unmeasured
    assert "0 B" not in unmeasured


def test_a_refused_overview_is_not_a_silent_network(
        monkeypatch, client, caplog):
    stub(monkeypatch, "traffic_overview",
         HTTPException(status_code=502, detail="Arkime refused"))
    response = client.get("/ui/arkime-traffic/overview?range=24h")
    assert response.status_code == 200          # htmx will not swap a 502
    body = response.text
    assert "Arkime refused" in body
    assert "No data for this range" not in body
    assert "0 B" not in body


def test_an_unconfigured_arkime_says_so_rather_than_reporting_no_traffic(
        monkeypatch, client):
    stub(monkeypatch, "traffic_overview",
         HTTPException(status_code=503, detail="Arkime is not configured"))
    body = client.get("/ui/arkime-traffic/overview?range=24h").text
    assert "not configured" in body.lower()
    assert "0 B" not in body


def test_a_missing_trend_is_not_a_flat_one(monkeypatch, client):
    stub(monkeypatch, "traffic_overview", dict(OVERVIEW, trend=None))
    none = client.get("/ui/arkime-traffic/overview?range=24h").text
    stub(monkeypatch, "traffic_overview", dict(
        OVERVIEW, trend={"sessions_pct": 0, "bytes_pct": 0}))
    flat = client.get("/ui/arkime-traffic/overview?range=24h").text
    assert none != flat
    assert "0%" in flat
    assert "0%" not in none


def test_a_trend_direction_is_a_state_not_a_colour(monkeypatch, client):
    stub(monkeypatch, "traffic_overview", OVERVIEW)
    model = client.get("/ui/arkime-traffic/overview?range=24h",
                       headers={"accept": "application/json"}).json()
    assert model["sessions_trend"]["direction"] == "up"
    assert model["bytes_trend"]["direction"] == "down"
    assert model["bytes_trend"]["pct"] == 3.0


def test_the_chart_series_travel_as_json_not_as_interpolated_markup(
        monkeypatch, client):
    stub(monkeypatch, "traffic_overview", OVERVIEW)
    body = client.get("/ui/arkime-traffic/overview?range=24h").text
    assert "data-atf-series=" in body
    assert "src_histo" in body


def test_the_range_is_validated_before_arkime_is_asked(monkeypatch, client):
    called = {"n": 0}

    async def reader(*args, **kwargs):
        called["n"] += 1
        return OVERVIEW
    monkeypatch.setattr(page, "traffic_overview", reader)
    body = client.get("/ui/arkime-traffic/overview?range=all-time").text
    assert called["n"] == 0
    assert "24h" in body or "range" in body.lower()


def test_an_unconfigured_arkime_serves_the_demo_shape_and_labels_it(
        monkeypatch, client):
    """The page showed synthetic traffic when Arkime is unconfigured so an
    evaluator sees the shape of the thing. That branch had to move with the
    render path, or an unconfigured deployment would show synthetic sensor
    and country charts beside an overview saying Arkime is not configured.

    It says so on the panel now. The page's banner was the only marking
    before, and a reader who scrolled past it had no way to tell."""
    monkeypatch.setattr(page, "arkime_configured", lambda: False)
    called = {"n": 0}

    async def reader(*a, **k):
        called["n"] += 1
        return OVERVIEW
    monkeypatch.setattr(page, "traffic_overview", reader)

    body = client.get("/ui/arkime-traffic/overview?range=24h").text
    assert called["n"] == 0
    assert "synthetic" in body
    assert "src_histo" in body

    monkeypatch.setattr(page, "traffic_top_talkers", reader)
    talkers = client.get("/ui/arkime-traffic/talkers?range=24h").text
    assert called["n"] == 0
    assert "synthetic" in talkers
    assert "10.10.45.23" in talkers


def test_demo_is_also_reachable_on_a_configured_deployment(
        monkeypatch, client):
    """?demo=1 is how ION is demonstrated on a cluster that IS configured,
    and the page decided it from the URL. The fragment has to honour the
    same flag or the demo shows real figures in half the panels."""
    called = {"n": 0}

    async def reader(*a, **k):
        called["n"] += 1
        return OVERVIEW
    monkeypatch.setattr(page, "traffic_overview", reader)
    body = client.get("/ui/arkime-traffic/overview?range=24h&demo=true").text
    assert called["n"] == 0
    assert "synthetic" in body


# ---------------------------------------------------------------------------
# /talkers
# ---------------------------------------------------------------------------


TALKERS = {
    "by_src": [{"ip": "10.0.0.1", "bytes": 2048, "sessions": 7}],
    "by_dst": [{"ip": "8.8.8.8", "bytes": 1024, "sessions": 3}],
    "method": "spigraph",
}


def test_both_directions_are_rendered_once_from_one_read(monkeypatch, client):
    """The direction tabs are control state, which the browser holds. Asking
    Arkime again for the other half of a payload it already sent would be a
    second aggregation per click."""
    stub(monkeypatch, "traffic_top_talkers", TALKERS)
    body = client.get("/ui/arkime-traffic/talkers?range=24h").text
    assert "10.0.0.1" in body and "8.8.8.8" in body
    assert body.count('data-atf-dir="src"') == 1
    assert body.count('data-atf-dir="dst"') == 1


def test_no_talkers_is_not_a_failed_talker_query(
        monkeypatch, client, caplog):
    stub(monkeypatch, "traffic_top_talkers",
         {"by_src": [], "by_dst": [], "method": "spigraph"})
    assert "No data for this range" in client.get(
        "/ui/arkime-traffic/talkers?range=24h").text

    stub(monkeypatch, "traffic_top_talkers", RuntimeError("arkime down"))
    body = client.get("/ui/arkime-traffic/talkers?range=24h").text
    assert "could not be read" in body
    assert "No data for this range" not in body
    assert any(r.exc_info for r in caplog.records)


def test_a_sampled_method_is_not_reported_as_a_full_aggregation(
        monkeypatch, client):
    stub(monkeypatch, "traffic_top_talkers", dict(TALKERS, method="sample"))
    assert "approximate" in client.get(
        "/ui/arkime-traffic/talkers?range=24h").text
    stub(monkeypatch, "traffic_top_talkers", TALKERS)
    assert "every session in the range" in client.get(
        "/ui/arkime-traffic/talkers?range=24h").text


def test_a_talker_row_without_a_byte_count_prints_no_byte_count(
        monkeypatch, client):
    stub(monkeypatch, "traffic_top_talkers",
         {"by_src": [{"ip": "10.0.0.9"}], "by_dst": [], "method": "sample"})
    body = client.get("/ui/arkime-traffic/talkers?range=24h").text
    assert "10.0.0.9" in body
    assert "0 B" not in body
    assert "Unknown" in body


def test_a_talker_ip_is_escaped_rather_than_concatenated(monkeypatch, client):
    stub(monkeypatch, "traffic_top_talkers", {
        "by_src": [{"ip": "<script>x</script>", "bytes": 1, "sessions": 1}],
        "by_dst": [], "method": "sample"})
    body = client.get("/ui/arkime-traffic/talkers?range=24h").text
    assert "<script>x</script>" not in body
    assert "&lt;script&gt;" in body


# ---------------------------------------------------------------------------
# /hunts
# ---------------------------------------------------------------------------


def test_no_hunts_submitted_is_not_a_failed_hunt_read(
        monkeypatch, client, caplog):
    stub(monkeypatch, "list_hunts", {"hunts": []})
    assert "No hunts submitted yet" in client.get(
        "/ui/arkime-traffic/hunts").text

    stub(monkeypatch, "list_hunts", RuntimeError("db gone"))
    body = client.get("/ui/arkime-traffic/hunts").text
    assert "could not be read" in body
    assert "No hunts submitted yet" not in body
    assert any(r.exc_info for r in caplog.records)


def test_a_hunt_with_no_match_count_is_not_zero_matches(monkeypatch, client):
    stub(monkeypatch, "list_hunts", {"hunts": [
        {"name": "running", "search": "x", "search_type": "ascii",
         "status": "running", "matched_sessions": None,
         "created_at": "2026-10-13T06:00:00"},
        {"name": "done", "search": "y", "search_type": "ascii",
         "status": "finished", "matched_sessions": 0,
         "created_at": "2026-10-13T06:00:00"},
    ]})
    body = client.get("/ui/arkime-traffic/hunts").text
    assert body.count("Unknown") == 1
    assert ">0<" in body


def test_the_arkime_deep_link_is_only_offered_for_a_finished_hunt(
        monkeypatch, client):
    monkeypatch.setattr(page, "arkime_web_url", lambda: "https://arkime.test")
    stub(monkeypatch, "list_hunts", {"hunts": [
        {"name": "a", "search": "s", "search_type": "ascii",
         "status": "running", "arkime_hunt_id": "h1",
         "matched_sessions": 0, "created_at": None},
        {"name": "b", "search": "s", "search_type": "ascii",
         "status": "finished", "arkime_hunt_id": "h2",
         "matched_sessions": 0, "created_at": None},
    ]})
    body = client.get("/ui/arkime-traffic/hunts").text
    assert body.count("Open in Arkime") == 1
    assert "huntId%20%3D%3D%20h2" in body


def test_without_a_viewer_url_no_hunt_links_to_nowhere(monkeypatch, client):
    monkeypatch.setattr(page, "arkime_web_url", lambda: None)
    stub(monkeypatch, "list_hunts", {"hunts": [
        {"name": "b", "search": "s", "search_type": "ascii",
         "status": "finished", "arkime_hunt_id": "h2",
         "matched_sessions": 0, "created_at": None}]})
    assert "Open in Arkime" not in client.get(
        "/ui/arkime-traffic/hunts").text


# ---------------------------------------------------------------------------
# /exclusions
# ---------------------------------------------------------------------------


def test_no_exclusions_is_not_a_failed_exclusion_read(
        monkeypatch, client, caplog):
    stub(monkeypatch, "list_exclusions", {"exclusions": []})
    assert "No exclusions" in client.get(
        "/ui/arkime-traffic/exclusions").text

    stub(monkeypatch, "list_exclusions", RuntimeError("db gone"))
    body = client.get("/ui/arkime-traffic/exclusions").text
    assert "could not be read" in body
    assert "No exclusions" not in body
    assert any(r.exc_info for r in caplog.records)


def test_an_exclusion_chip_carries_its_id_in_a_data_attribute(
        monkeypatch, client):
    stub(monkeypatch, "list_exclusions",
         {"exclusions": [{"id": 4, "cidr": "10.0.0.0/8"}]})
    body = client.get("/ui/arkime-traffic/exclusions").text
    assert 'data-excl-id="4"' in body
    assert "10.0.0.0/8" in body


# ---------------------------------------------------------------------------
# /ai-review
# ---------------------------------------------------------------------------


def test_a_review_without_a_node_is_refused_before_bob_is_called(
        monkeypatch, client):
    called = {"n": 0}

    async def reader(*a, **k):
        called["n"] += 1
        return {"analysis": "ok", "model": "m"}
    monkeypatch.setattr(page, "traffic_ai_review", reader)
    body = client.post("/ui/arkime-traffic/ai-review",
                       data={"node": "", "range": "24h"}).text
    assert called["n"] == 0
    assert "Select a node" in body


def test_a_failed_review_is_not_an_empty_review(monkeypatch, client, caplog):
    stub(monkeypatch, "traffic_ai_review", RuntimeError("ollama offline"))
    body = client.post("/ui/arkime-traffic/ai-review",
                       data={"node": "cap-1", "range": "24h"}).text
    assert "could not be" in body
    assert any(r.exc_info for r in caplog.records)


def test_the_review_markdown_is_handed_over_as_text(monkeypatch, client):
    """ION ships no HTML sanitiser, so the markdown is sent as text for the
    page's own `safeMarkdown` (marked plus DOMPurify) to paint, which is the
    call template_render already made for the same reason."""
    stub(monkeypatch, "traffic_ai_review",
         {"analysis": "## Finding\n<img src=x onerror=alert(1)>",
          "model": "foundation-sec"})
    body = client.post("/ui/arkime-traffic/ai-review",
                       data={"node": "cap-1", "range": "24h"}).text
    assert "<img src=x" not in body
    assert "&lt;img src=x" in body
    assert "foundation-sec" in body
    assert "<textarea" in body


def test_an_empty_analysis_is_not_a_successful_review(monkeypatch, client):
    stub(monkeypatch, "traffic_ai_review", {"analysis": "", "model": "m"})
    body = client.post("/ui/arkime-traffic/ai-review",
                       data={"node": "cap-1", "range": "24h"}).text
    assert "returned no analysis" in body


# ---------------------------------------------------------------------------
# Gates
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("method,path", [
    ("get", "/ui/arkime-traffic/overview?range=24h"),
    ("get", "/ui/arkime-traffic/talkers?range=24h"),
    ("get", "/ui/arkime-traffic/hunts"),
    ("get", "/ui/arkime-traffic/exclusions"),
    ("post", "/ui/arkime-traffic/ai-review"),
])
def test_every_fragment_requires_alert_read_exactly(method, path, monkeypatch):
    """alert:read is what all five JSON endpoints these mirror require.
    POST /api/arkime/hunts and POST /api/arkime/traffic/exclusions require
    security:read, and neither is mirrored here: this module reads."""
    for name in ("traffic_overview", "traffic_top_talkers", "list_hunts",
                 "list_exclusions", "traffic_ai_review"):
        stub(monkeypatch, name, {})
    app = probe_app(monkeypatch)
    client = TestClient(app)
    call = getattr(client, method)

    assert call(path).status_code == 401
    app.dependency_overrides[get_current_user] = lambda: user("security:read")
    assert call(path).status_code == 403
    app.dependency_overrides[get_current_user] = lambda: user("alert:read")
    assert call(path).status_code != 403


# ---------------------------------------------------------------------------
# The page shell
# ---------------------------------------------------------------------------


def shell() -> str:
    source = PAGE.read_text(encoding="utf-8")
    return re.sub(r"<!--.*?-->|\{#.*?#\}|/\*.*?\*/", "", source, flags=re.S)


def test_the_shell_builds_no_markup_and_carries_no_stylesheet():
    source = shell()
    assert ".innerHTML" not in source
    assert "insertAdjacentHTML" not in source
    assert "<style" not in source
    assert "function escHtml(" not in source
    assert "arkime-traffic.css" in source


def test_the_range_tabs_sit_outside_every_panel_they_reload():
    source = shell()
    before, _ = source.split('id="atf-overview"', 1)
    assert 'id="range-tabs"' in before


def test_client_only_markup_is_a_template_outside_the_script_block():
    source = shell()
    head, script = source.split("<script", 1)
    for template_id in ("atf-ai-pick-node-template",
                        "atf-ai-pending-template"):
        assert f'id="{template_id}"' in head, template_id
        assert f'id="{template_id}"' not in script, template_id
