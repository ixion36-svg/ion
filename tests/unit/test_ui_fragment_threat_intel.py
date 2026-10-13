"""Threat Intel's watchlist, match alerts and attack stories as fragments.

Each case below is something the JavaScript either got right and must keep,
or got wrong and must stop doing. The ones worth reading are the failure
renders, because the defect this conversion exists to remove is that a
failed read and an empty result were the same sentence.

Measured against the running deployment before the change:

  * GET /api/threat-intel/watches?limit=1000 answers 422, because the
    endpoint bounds limit at le=500. refreshWatchedIds asked for 1000 on
    every call, the body was still JSON so nothing threw, data.watches was
    undefined, and watchedIds was permanently empty.
  * GET /api/attack-stories answers 200 with
    {"enabled": false, "error": "ElasticsearchError"}. The page checked
    r.ok, which passed, then `d.stories || []`, and rendered "No attack
    stories: alerts did not correlate into multi-step patterns over the
    selected window."
  * No rule for a bare `.active` exists in threat-intel.css or ion.css, so
    the kill-chain stage a attacker reached looked identical to one they
    never got to.

The render tests use fixtures rather than live data: this deployment has no
watches and no matches, and an empty render proves nothing about the rows,
which is all that moved.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ion.web.templating import make_templates
from ion.web.ui.threat_intel import (
    MANAGE_PERMISSION,
    MATCH_LIMIT,
    OVERVIEW_CARD_ROWS,
    OVERVIEW_MATCH_LIMIT,
    RECENT_DAYS,
    RECENT_TOP_N,
    PERMISSION,
    STORIES_PERMISSION,
    WATCH_LIMIT,
    _rows,
    router,
)

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "src/ion/web/templates/threat_intel.html"
PAGE_CSS = ROOT / "src/ion/web/static/css/threat-intel.css"
SERVER = ROOT / "src/ion/web/server.py"

WATCHLIST = "_fragments/threat_intel_watchlist.html"
MATCHES = "_fragments/threat_intel_matches.html"
STORIES = "_fragments/threat_intel_stories.html"


def render(name: str, **ctx: Any) -> str:
    env = make_templates().env
    return env.get_template(name).render(**ctx)


def _watch(**over: Any) -> dict:
    base = {
        "id": 7,
        "entity_type": "threat_actor",
        "opencti_id": "intrusion-set--abc",
        "name": "APT29",
        "country_code": "RU",
        "country_name": "Russia",
        "country_flag": "\U0001F1F7\U0001F1FA",
        "last_seen_at": "2026-10-01T14:05:00+00:00",
        "match_count": 3,
        "watched_by": "analyst",
        "watch_reason": "campaign tracking",
        "is_active": True,
    }
    base.update(over)
    return base


def _match(**over: Any) -> dict:
    base = {
        "id": 11,
        "observable_value": "1.2.3.4",
        "observable_type": "ip",
        "details": {"watch_name": "APT29"},
        "is_read": False,
        "created_at": "2026-10-01T14:05:00+00:00",
    }
    base.update(over)
    return base


def _story(**over: Any) -> dict:
    base = {
        "entity": "host-7",
        "entity_type": "host",
        "score": 82,
        "alert_count": 5,
        "unique_techniques": ["T1059", "T1055"],
        "time_span_hours": 6,
        "severity": "high",
        "narrative": "Execution followed by privilege escalation.",
        "tactics_progression": ["Execution"],
    }
    base.update(over)
    return base


# ---------------------------------------------------------------------------
# The helper that makes the third outcome reachable
# ---------------------------------------------------------------------------


def test_rows_returns_none_for_a_refusal_body_rather_than_an_empty_list():
    """`{"detail": ...}` is what a 403 or a 422 answers with.

    The JavaScript's `data.watches || []` turned this into an empty list and
    the page said the watchlist was empty. None is the outcome a caller
    cannot accidentally render as "none found".
    """
    assert _rows({"detail": "Not authenticated"}, "watches") is None
    assert _rows({"detail": [{"loc": ["query", "limit"]}]}, "watches") is None


def test_rows_distinguishes_an_empty_collection_from_a_missing_one():
    assert _rows({"watches": []}, "watches") == []
    assert _rows({}, "watches") is None
    assert _rows(None, "watches") is None
    assert _rows("not a dict", "watches") is None


# ---------------------------------------------------------------------------
# Watchlist
# ---------------------------------------------------------------------------


def test_a_failed_watchlist_read_does_not_claim_the_watchlist_is_empty():
    """The defect, stated as a test.

    `loadWatches` read with no r.ok check and fell through to "No active
    watches. Search for actors or campaigns and add them.", which tells an
    analyst to go and add the watches they already have.
    """
    html = render(WATCHLIST, failed=True, watches=None, total=None,
                  can_manage=True, limit=WATCH_LIMIT)
    assert "could not be read" in html
    assert "No active watches" not in html
    assert "still being watched" in html
    assert 'role="alert"' in html


def test_an_empty_watchlist_says_so_and_does_not_say_the_read_failed():
    html = render(WATCHLIST, failed=False, watches=[], total=0,
                  can_manage=True, limit=WATCH_LIMIT)
    assert "No active watches" in html
    assert "could not be read" not in html


def test_a_watch_row_carries_every_column_the_table_declares():
    html = render(WATCHLIST, failed=False, watches=[_watch()], total=1,
                  can_manage=True, limit=WATCH_LIMIT)
    assert "APT29" in html
    assert "Russia" in html
    assert "threat actor" in html, "entity_type underscore is replaced"
    assert "analyst" in html
    assert "campaign tracking" in html


def test_a_match_count_of_zero_is_a_measurement_and_a_missing_one_is_not():
    """Zero means this actor has not been seen in the estate. Absent means
    nobody counted. The JavaScript printed `w.match_count` straight into the
    cell, so absent rendered the string "null"."""
    zero = render(WATCHLIST, failed=False, watches=[_watch(match_count=0)],
                  total=1, can_manage=True, limit=WATCH_LIMIT)
    missing = render(WATCHLIST, failed=False,
                     watches=[_watch(match_count=None)], total=1,
                     can_manage=True, limit=WATCH_LIMIT)
    assert re.search(r">\s*0\s*<", zero)
    assert "not recorded" not in zero
    assert "not recorded" in missing
    assert "null" not in missing


def test_remove_is_withheld_without_the_permission_the_delete_requires():
    """DELETE /api/threat-intel/watches/{id} requires observable:enrich. The
    page is gated on observable:read and never checked, so a read-only
    analyst reached a 403 only after confirming a dialog."""
    with_it = render(WATCHLIST, failed=False, watches=[_watch()], total=1,
                     can_manage=True, limit=WATCH_LIMIT)
    without = render(WATCHLIST, failed=False, watches=[_watch()], total=1,
                     can_manage=False, limit=WATCH_LIMIT)
    assert "removeWatch" in with_it
    assert "removeWatch" not in without
    assert "Read only" in without


def test_a_watch_name_holding_a_quote_stays_valid_json_in_the_action_args():
    """The page built `data-args='[${w.id}, "${esc(w.name)}"]'` with an
    `esc()` that went through textContent and innerHTML, so it escaped <, >
    and & but not quotes. A watch named with a double quote broke that
    attribute's JSON."""
    html = render(WATCHLIST, failed=False,
                  watches=[_watch(name='AP"T29')], total=1,
                  can_manage=True, limit=WATCH_LIMIT)
    raw = re.search(r"data-args='([^']+)'", html).group(1)
    decoded = (raw.replace("&quot;", '"').replace("&#34;", '"')
                  .replace("&amp;", "&").replace("&lt;", "<")
                  .replace("&gt;", ">").replace("\\u0022", '"')
                  .replace("\\u0027", "'"))
    assert json.loads(decoded) == [7, 'AP"T29']


def test_a_watch_that_has_never_matched_says_never_rather_than_a_dash():
    html = render(WATCHLIST, failed=False,
                  watches=[_watch(last_seen_at=None)], total=1,
                  can_manage=True, limit=WATCH_LIMIT)
    assert "Never" in html


# ---------------------------------------------------------------------------
# Match alerts
# ---------------------------------------------------------------------------


def test_a_failed_match_read_does_not_claim_the_watchlist_is_quiet():
    """"No match alerts." is the sentence an analyst reads before deciding
    nothing on their watchlist has fired. A failed read is the opposite of
    that finding."""
    html = render(MATCHES, failed=True, matches=None, total=None,
                  unread_only=False)
    assert "could not be read" in html
    assert "No match alerts" not in html
    assert 'role="alert"' in html


def test_the_two_empty_match_states_are_worded_differently():
    """The JavaScript said "No match alerts." whichever way the toggle was
    set, so an analyst who had filtered to unread and cleared everything
    read the same sentence as one whose watchlist had never matched."""
    unfiltered = render(MATCHES, failed=False, matches=[], total=0,
                        unread_only=False)
    filtered = render(MATCHES, failed=False, matches=[], total=0,
                      unread_only=True)
    assert "No match alerts" in unfiltered
    assert "No unread match alerts" in filtered
    assert "Clear the filter" in filtered


def test_an_unread_match_is_marked_and_offers_the_control_to_clear_it():
    unread = render(MATCHES, failed=False, matches=[_match(is_read=False)],
                    total=1, unread_only=False)
    read = render(MATCHES, failed=False, matches=[_match(is_read=True)],
                  total=1, unread_only=False)
    assert "ti-unread" in unread
    assert "markRead" in unread
    assert "ti-unread" not in read
    assert "markRead" not in read


@pytest.mark.parametrize("details", [None, {}, {"other": "x"}])
def test_a_match_with_no_recorded_watch_name_renders_a_dash(details):
    """`details` is a JSON column, so it can be absent, null, or a shape
    with no watch_name. `m.details.watch_name` on a null details raises in
    Jinja rather than rendering."""
    html = render(MATCHES, failed=False,
                  matches=[_match(details=details)], total=1,
                  unread_only=False)
    assert "Traceback" not in html
    assert ">-<" in html.replace(" ", "").replace("\n", "")


# ---------------------------------------------------------------------------
# Attack stories: the worst of the four defects
# ---------------------------------------------------------------------------


def test_a_disabled_correlation_engine_is_not_reported_as_no_attack_stories():
    """Measured live: GET /api/attack-stories answers 200 with
    {"enabled": false, "error": "ElasticsearchError"}. The page's r.ok check
    passed, `d.stories || []` found nothing, and the analyst was told their
    alerts did not correlate into multi-step patterns. A switched-off
    correlation engine reported as a clean result."""
    html = render(STORIES, enabled=False, stories=None, failed=False,
                  error="ElasticsearchError", hours=24)
    assert "unavailable" in html
    assert "did not correlate" not in html
    assert "ElasticsearchError" in html
    # Whitespace-normalised: the sentence wraps in the template, and a test
    # that depends on where it wraps breaks on reflowing the paragraph.
    assert "Nothing was looked at" in " ".join(html.split())


def test_a_disabled_engine_that_gives_no_reason_says_that_too():
    html = render(STORIES, enabled=False, stories=None, failed=False,
                  error=None, hours=24)
    assert "did not say why" in html
    assert "did not correlate" not in html


def test_correlation_that_ran_and_found_nothing_is_the_only_no_stories_case():
    html = render(STORIES, enabled=True, stories=[], failed=False,
                  error=None, hours=24, kill_chain_order=[])
    assert "did not correlate" in html
    assert "unavailable" not in html


def test_an_enabled_payload_with_no_story_list_is_not_an_empty_result():
    """Correlation reporting itself enabled while returning a shape this
    panel cannot read is not the finding that nothing correlated."""
    html = render(STORIES, enabled=True, stories=None, failed=False,
                  error=None, hours=24, kill_chain_order=[])
    assert "could not be read" in html
    assert "did not correlate" not in html


def test_the_fragment_raising_is_distinguished_from_the_engine_being_off():
    html = render(STORIES, enabled=True, stories=None, failed=True,
                  error=None, hours=24, kill_chain_order=[])
    assert "could not be built" in html
    assert "did not correlate" not in html


def test_a_reached_kill_chain_stage_is_visually_distinct_from_an_unreached_one():
    """The ribbon's whole purpose. The JavaScript appended a bare `active`
    class and no rule for a bare .active exists in this page's stylesheet or
    in ion.css, so every stage rendered identically."""
    html = render(STORIES, enabled=True, failed=False, error=None, hours=24,
                  stories=[_story(tactics_progression=["Execution"])],
                  kill_chain_order=["Reconnaissance", "Execution"])
    assert "ti-chain-stage active" in html
    assert re.search(r'ti-chain-stage"[^>]*title="Not observed', html)
    assert "Reached in this attack" in html


def test_the_kill_chain_classes_the_fragment_emits_have_rules_in_the_stylesheet():
    """A class with no rule is why the old ribbon did nothing. This pins the
    stylesheet and the fragment together so the next edit to either cannot
    silently separate them."""
    css = PAGE_CSS.read_text(encoding="utf-8")
    assert ".ti-chain-stage {" in css
    assert ".ti-chain-stage.active {" in css


def test_a_story_scored_zero_is_not_the_same_as_an_unscored_one():
    zero = render(STORIES, enabled=True, failed=False, error=None, hours=24,
                  stories=[_story(score=0)], kill_chain_order=[])
    missing = render(STORIES, enabled=True, failed=False, error=None,
                     hours=24, stories=[_story(score=None)],
                     kill_chain_order=[])
    assert re.search(r">\s*0\s*<", zero)
    assert "n/a" in missing
    assert "undefined" not in missing
    assert "None" not in missing


def test_a_story_with_no_narrative_says_so_rather_than_rendering_an_empty_box():
    html = render(STORIES, enabled=True, failed=False, error=None, hours=24,
                  stories=[_story(narrative=None)], kill_chain_order=[])
    assert "No narrative was generated" in html
    assert "None" not in html


# ---------------------------------------------------------------------------
# The routes over HTTP
# ---------------------------------------------------------------------------


class _User:
    id = 1
    username = "ti-tester"

    def __init__(self, *permissions):
        self.permissions = set(permissions)

    def has_permission(self, name):
        return name in self.permissions


def _client(session, user):
    from ion.auth.dependencies import get_current_user
    from ion.storage.database import get_db_session

    application = FastAPI()
    application.include_router(router, prefix="/ui")
    application.dependency_overrides[get_current_user] = lambda: user
    application.dependency_overrides[get_db_session] = lambda: session
    return application


FRAGMENT_PATHS = [
    "/ui/threat-intel/watchlist",
    "/ui/threat-intel/matches",
    "/ui/threat-intel/stories",
]


@pytest.mark.parametrize("path", FRAGMENT_PATHS)
def test_a_fragment_refuses_a_caller_with_no_permissions(session, path):
    app = _client(session, _User())
    with TestClient(app) as client:
        assert client.get(path).status_code == 403


def test_the_watchlist_and_matches_need_observable_read(session):
    app = _client(session, _User(PERMISSION))
    with TestClient(app) as client:
        assert client.get("/ui/threat-intel/watchlist").status_code == 200
        assert client.get("/ui/threat-intel/matches").status_code == 200


def test_observable_read_alone_does_not_open_the_stories_fragment(session):
    """The page is gated on observable:read and the stories endpoint on
    alert:read. If this fragment accepted the page's permission it would be
    a softer way in than the API it mirrors."""
    app = _client(session, _User(PERMISSION))
    with TestClient(app) as client:
        assert client.get("/ui/threat-intel/stories").status_code == 403

    app = _client(session, _User(STORIES_PERMISSION))
    with TestClient(app) as client:
        assert client.get("/ui/threat-intel/stories").status_code == 200


def test_the_stories_window_is_bounded_exactly_as_the_json_endpoint_bounds_it(session):
    """A window the API would refuse must not be reachable through the
    fragment, or the fragment is a way around the endpoint's limits."""
    from ion.web.attack_story_api import get_attack_stories
    from ion.web.ui.threat_intel import threat_intel_stories_fragment
    import inspect

    frag = inspect.signature(threat_intel_stories_fragment).parameters["hours"]
    api = inspect.signature(get_attack_stories).parameters["hours"]
    assert frag.default.metadata == api.default.metadata

    app = _client(session, _User(STORIES_PERMISSION))
    with TestClient(app) as client:
        assert client.get("/ui/threat-intel/stories?hours=999").status_code == 422


def test_the_watchlist_route_withholds_remove_without_observable_enrich(session):
    """The template gate is tested above with a context built by hand. This
    drives the module, which is what decides the flag. A mutation that made
    it `current_user is not None` survived the first pass, because nothing
    checked the route's own answer.

    A real watch row is created first. Without one the table renders its
    empty state, no row renders, and `removeWatch` is absent whatever the
    flag says: the first version of this test passed for that reason and
    let the mutation through.
    """
    from ion.services.threat_intel_service import ThreatIntelService

    ThreatIntelService(session).add_watch(
        entity_type="threat_actor",
        opencti_id="intrusion-set--probe",
        name="APT-probe",
        watched_by="ti-tester",
    )
    session.commit()

    reader = _client(session, _User(PERMISSION))
    with TestClient(reader) as client:
        body = client.get("/ui/threat-intel/watchlist").text
    assert "APT-probe" in body, "the row must render or this proves nothing"
    assert "removeWatch" not in body
    assert "Read only" in body

    manager = _client(session, _User(PERMISSION, MANAGE_PERMISSION))
    with TestClient(manager) as client:
        managed = client.get("/ui/threat-intel/watchlist").text
    assert "APT-probe" in managed
    assert "removeWatch" in managed


def test_a_successful_correlation_is_not_read_as_a_disabled_engine(session,
                                                                   monkeypatch):
    """The load-bearing `is False`.

    build_attack_stories returns {total_alerts, total_stories, stories,
    kill_chain_order} on success, with NO `enabled` key, verified by reading
    it. So `payload.get("enabled")` is None on every successful
    correlation, and a truthiness test would report every working run as
    unavailable. Only an explicit false means the service is reporting
    itself off.

    A mutation to `not payload.get("enabled")` survived the first pass, so
    the branch that keeps this page honest had no test at all.
    """
    import ion.services.attack_story_service as svc
    import ion.services.elasticsearch_service as es_mod

    class _ES:
        is_configured = True

        async def get_alerts(self, hours, limit):
            return []

    monkeypatch.setattr(es_mod, "ElasticsearchService", _ES)
    monkeypatch.setattr(svc, "build_attack_stories", lambda *a, **k: {
        "total_alerts": 1,
        "total_stories": 1,
        "stories": [_story()],
        "kill_chain_order": ["Execution"],
    })

    app = _client(session, _User(STORIES_PERMISSION))
    with TestClient(app) as client:
        body = client.get("/ui/threat-intel/stories").text
    assert "host-7" in body, "the story should have rendered"
    assert "unavailable" not in body
    assert "did not correlate" not in body


def test_an_explicitly_disabled_payload_is_still_read_as_disabled(session,
                                                                  monkeypatch):
    """The other side of the same branch, so the pair pins `is False` from
    both directions rather than only one."""
    import ion.services.attack_story_service as svc
    import ion.services.elasticsearch_service as es_mod

    class _ES:
        is_configured = True

        async def get_alerts(self, hours, limit):
            return []

    monkeypatch.setattr(es_mod, "ElasticsearchService", _ES)
    monkeypatch.setattr(svc, "build_attack_stories", lambda *a, **k: {
        "enabled": False, "error": "ElasticsearchError",
    })

    app = _client(session, _User(STORIES_PERMISSION))
    with TestClient(app) as client:
        body = client.get("/ui/threat-intel/stories").text
    assert "unavailable" in body
    assert "ElasticsearchError" in body
    assert "did not correlate" not in body


def test_an_unconfigured_elasticsearch_says_so_rather_than_raising(session,
                                                                  monkeypatch):
    """ElasticsearchService defines neither __bool__ nor __len__, so an
    instance is always truthy and the endpoint's own `if not es` guard never
    fired: an unconfigured deployment fell through to get_alerts, raised,
    and reported "ElasticsearchError" where it meant to name the cause.
    This reads the is_configured property instead."""
    import ion.services.elasticsearch_service as es_mod

    class _ES:
        is_configured = False

        async def get_alerts(self, hours, limit):
            raise AssertionError("must not be read when not configured")

    monkeypatch.setattr(es_mod, "ElasticsearchService", _ES)

    app = _client(session, _User(STORIES_PERMISSION))
    with TestClient(app) as client:
        body = client.get("/ui/threat-intel/stories").text
    assert "Elasticsearch not configured" in body
    assert "unavailable" in body


def test_the_json_endpoint_reads_is_configured_rather_than_the_instance():
    """The same dead guard, fixed in attack_story_api.py in this change so
    the page and the JSON still agree about why correlation is off."""
    api = (ROOT / "src/ion/web/attack_story_api.py").read_text(encoding="utf-8")
    assert "if not es.is_configured:" in api
    assert "if not es:" not in api


def test_the_matches_fragment_passes_the_unread_filter_through(session):
    app = _client(session, _User(PERMISSION))
    with TestClient(app) as client:
        filtered = client.get("/ui/threat-intel/matches?unread_only=true")
        assert filtered.status_code == 200
        assert "No unread match alerts" in filtered.text


def test_the_watch_limit_is_one_the_endpoint_accepts(session):
    """The page asked for 1000 against an endpoint bounded at le=500 and got
    a 422 on every call, measured live. This pins the fragment's limit to
    something the endpoint will answer."""
    from ion.web.threat_intel_api import list_watches
    import inspect

    bound = inspect.signature(list_watches).parameters["limit"].default
    ceiling = next(m.le for m in bound.metadata if hasattr(m, "le"))
    assert WATCH_LIMIT <= ceiling
    assert MATCH_LIMIT > 0


# ---------------------------------------------------------------------------
# The page shell
# ---------------------------------------------------------------------------


def _page() -> str:
    return PAGE.read_text(encoding="utf-8")


def test_the_page_carries_no_inline_style_block():
    assert "<style" not in _page()


@pytest.mark.parametrize("target,url", [
    ("watchlist-body", "/ui/threat-intel/watchlist"),
    ("matches-body", "/ui/threat-intel/matches"),
    ("ti-stories-list", "/ui/threat-intel/stories"),
])
def test_each_converted_region_pulls_its_markup_from_its_fragment(target, url):
    page = _page()
    block = page[page.index(f'id="{target}"'):]
    block = block[:block.index(">") + 400]
    assert url in block


def test_the_page_no_longer_builds_those_three_regions_in_javascript():
    page = _page()
    for gone in ("async function loadWatches", "async function loadMatches",
                 "window.tiLoadStories"):
        assert gone not in page, f"{gone} should have been removed"


def test_the_stories_and_kev_tabs_are_withheld_without_alert_read():
    """Both read endpoints requiring alert:read, which this page's
    observable:read does not imply. KEV rendered the refusal as "Search
    failed: HTTP 403"."""
    page = _page()
    gate = page.index("{% if can_read_alerts %}")
    close = page.index("{% endif %}", gate)
    guarded = page[gate:close]
    assert 'data-panel="stories"' in guarded
    assert 'data-panel="kev"' in guarded


def test_the_script_block_holds_no_jinja_so_it_stays_checkable():
    """Server facts reach the script through a data attribute instead, which
    keeps `node --check` a usable guard on 1,400 lines of JavaScript."""
    page = _page()
    script = page[page.index('<script nonce="{{ csp_nonce }}">') + 32:]
    script = script[:script.index("</script>")]
    assert not re.search(r"\{\{|\{%", script)


def test_the_write_controls_read_the_permission_from_the_server():
    page = _page()
    assert 'data-can-manage-watches="{{' in page
    assert "canManageWatches" in page
    # Both builders, counted. There is a Watch button in the actor results
    # and another in the campaign results, and asserting the guard appears
    # somewhere let a mutation that ungated one of them through.
    assert page.count("!canManageWatches") == 2, (
        "both the actor and the campaign Watch buttons must be gated"
    )
    for builder in ("watchActor", "watchCampaign"):
        before = page[:page.index(builder)]
        assert "!canManageWatches" in before[-700:], (
            f"the {builder} button is not behind the permission check"
        )


#: Reads still using `fetch(url).then(r => r.json())`, which discards the
#: status so a refusal body gets destructured for a key it does not carry.
#: Two in the actor search and its row detail, two in the campaign
#: equivalents. Both panels are converted by a later stage and each read
#: goes with its panel. loadOverview's two are gone as of the Overview
#: stage, which took this count from 6 to 4.
#:
#: Pinned rather than left unmeasured. This number may only go down: a new
#: one is the defect this whole conversion exists to remove, reappearing.
UNCHECKED_READS_REMAINING = 4


def test_the_unchecked_reads_this_page_still_has_do_not_increase():
    page = _page()
    # Minus this file's own prose about the pattern, and the page's comment
    # explaining it, neither of which is a read.
    sites = [line for line in page.splitlines()
             if "then(r => r.json())" in line and "//" not in line]
    assert len(sites) == UNCHECKED_READS_REMAINING, (
        "a read that drops its status check was added or removed; if removed, "
        "lower UNCHECKED_READS_REMAINING, and if added, do not"
    )


def test_the_three_converted_regions_no_longer_read_without_checking():
    """The watchlist, the matches table and the stories panel were three of
    the sites. Their reads are server-side now, so none of the remaining
    ones may be theirs."""
    page = _page()
    for line in page.splitlines():
        if "then(r => r.json())" in line and "//" not in line:
            assert "/watches" not in line
            assert "/matches?limit=50" not in line
            assert "attack-stories" not in line


def test_the_page_route_passes_both_permission_facts():
    server = SERVER.read_text(encoding="utf-8")
    handler = server[server.index("async def threat_intel_page"):]
    handler = handler[:handler.index("@app.get", 10)]
    assert '"can_read_alerts"' in handler
    assert '"can_manage_watches"' in handler
    assert 'has_permission("alert:read")' in handler
    assert 'has_permission("observable:enrich")' in handler


def test_the_permission_constants_match_what_the_endpoints_declare():
    """Spelled once in the module, so a fragment cannot drift into being a
    softer way in than the endpoint it mirrors."""
    assert PERMISSION == "observable:read"
    assert MANAGE_PERMISSION == "observable:enrich"
    assert STORIES_PERMISSION == "alert:read"


# ---------------------------------------------------------------------------
# The Overview tab
#
# Five regions, and the same mistake in all five: a failed read was never
# rendered as a failed read. loadOverview caught to console.error and left
# four tiles showing the dash they ship with. The two OpenCTI cards rendered
# the guess "OpenCTI not configured?" in the same grey as their empty state,
# while the 503 behind it names the cause exactly. loadRecentlyActive did
# `if (!r.ok) return;` and left both its panels on the shell's "Loading..."
# forever, which is the worst of the three: a reader waits out a spinner and
# acts on an empty state, and a permanent spinner gets neither.
# ---------------------------------------------------------------------------

STATS = "_fragments/threat_intel_overview_stats.html"
RECENT = "_fragments/threat_intel_recently_active.html"
LS_ACTORS = "_fragments/threat_intel_landscape_actors.html"
LS_IOCS = "_fragments/threat_intel_landscape_iocs.html"

_STATS_OK = {
    "watched_actors": 4,
    "watched_campaigns": 2,
    "matches_7d": 11,
    "unread_alerts": 3,
}


def test_failed_overview_stats_say_unknown_rather_than_showing_zeros():
    """loadOverview's catch rendered nothing, so the tiles kept their dash
    and a failed read looked like a page still loading."""
    html = render(STATS, failed=True, stats=None)
    assert "unknown" in html
    assert "could not be read" in html
    assert 'role="alert"' in html
    # The tiles only. The out-of-band badge renders a 0 behind its hidden
    # class, which is not a figure anyone reads.
    tiles = html[:html.index('id="ti-unread-badge"')]
    assert ">0<" not in tiles.replace(" ", "")


def test_a_stat_the_payload_omits_is_not_printed_as_undefined():
    """`stats.watched_actors` with textContent and no guard printed the
    string "undefined" into the tile for a payload missing the key."""
    html = render(STATS, failed=False, stats={"watched_actors": 4})
    assert "not recorded" in html
    assert "undefined" not in html
    assert "None" not in html


def test_a_measured_zero_is_still_shown_as_zero():
    html = render(STATS, failed=False, stats=dict(_STATS_OK, watched_actors=0))
    assert re.search(r">\s*0\s*<", html)
    assert "not recorded" not in html
    assert "unknown" not in html


@pytest.mark.parametrize("unread,hidden", [(0, True), (None, True), (3, False)])
def test_the_tab_badge_only_appears_for_a_real_unread_count(unread, hidden):
    """The badge draws the eye. One reading 0 does that for nothing, and an
    unmeasured count is not a reason to draw it either."""
    html = render(STATS, failed=False, stats=dict(_STATS_OK, unread_alerts=unread))
    badge = html[html.index('id="ti-unread-badge"'):]
    badge = badge[:badge.index("</span>")]
    assert ("hidden" in badge) is hidden
    assert 'hx-swap-oob="outerHTML"' in badge


def test_a_failed_recently_active_read_does_not_leave_a_permanent_loading():
    """`if (!r.ok) return;` left both panels on the shell's "Loading..."
    text. Both now say the read failed."""
    html = render(RECENT, failed=True, observables=None, techniques=None, days=30)
    assert html.count("could not be read") == 2
    assert "Loading" not in html
    assert html.count('role="alert"') == 2
    assert 'hx-swap-oob="innerHTML"' in html


def test_recently_active_distinguishes_no_activity_from_a_failed_read():
    empty = render(RECENT, failed=False, observables=[], techniques=[], days=30)
    assert "No observable activity in the last 30 days" in empty
    assert "No MITRE techniques tagged in the last 30 days" in empty
    assert "could not be read" not in empty


def test_a_recently_active_payload_missing_a_list_is_a_failure_not_an_absence():
    """The page did `d.observables.length` with no guard, which raises on a
    payload that does not carry the key. `_rows` makes that None, and None
    renders as a failure rather than as no activity."""
    html = render(RECENT, failed=False, observables=None,
                  techniques=[{"id": "T1059", "count": 2}], days=30)
    assert "Recent observable activity could not be read" in html
    assert "T1059" in html, "the list that did arrive still renders"


def test_a_technique_chip_is_a_button_not_a_javascript_href():
    """The page used <a href="javascript:void(0)">, which is a dead link in
    the accessibility tree and a navigation the CSP has no reason to
    permit."""
    html = render(RECENT, failed=False, observables=[],
                  techniques=[{"id": "T1059", "count": 2}], days=30)
    assert "javascript:void(0)" not in html
    assert "<button" in html
    assert "tiDrillTechnique" in html


@pytest.mark.parametrize("fragment", [LS_ACTORS, LS_IOCS])
def test_opencti_not_configured_is_stated_not_guessed_at(fragment):
    """The page rendered "OpenCTI not configured?" with a question mark for
    both this case and a genuine failure, in the same grey as the empty
    state. Measured live: /api/threat-landscape/overview answers 503 with
    "OpenCTI integration is not configured", which says which it is."""
    html = render(fragment, configured=False, rows=None, failed=False,
                  error=None, limit=5)
    assert "not configured" in html
    assert "?" not in html.replace("&quot;", "")
    assert "nothing to retry" in html or "rather than a fault" in html


@pytest.mark.parametrize("fragment", [LS_ACTORS, LS_IOCS])
def test_a_configured_opencti_that_fails_is_a_fault_not_an_absence(fragment):
    html = render(fragment, configured=True, rows=None, failed=True,
                  error="OpenCTIError", limit=5)
    assert "could not be read" in html
    assert "not configured, so" not in html
    assert "OpenCTIError" in html
    assert 'role="alert"' in html


@pytest.mark.parametrize("fragment,empty", [
    (LS_ACTORS, "No actors tracked yet"),
    (LS_IOCS, "No high-score IOCs at this threshold"),
])
def test_an_opencti_card_that_answered_with_nothing_says_so_plainly(fragment, empty):
    html = render(fragment, configured=True, rows=[], failed=False,
                  error=None, limit=5)
    assert empty in html
    assert "could not be read" not in html
    assert "not configured" not in html


def test_an_actor_with_no_counted_ttps_is_not_reported_as_zero():
    """`a.ttp_count || 0` printed a confident zero for an actor whose TTPs
    were never counted."""
    counted = render(LS_ACTORS, configured=True, failed=False, error=None,
                     limit=5, rows=[{"name": "APT29", "ttp_count": 0}])
    missing = render(LS_ACTORS, configured=True, failed=False, error=None,
                     limit=5, rows=[{"name": "APT29", "ttp_count": None}])
    assert "0 TTPs" in counted
    assert "TTPs not counted" in missing
    assert "0 TTPs" not in missing


def test_an_unscored_indicator_is_not_painted_as_a_low_score():
    """`i.score || 0` sent an unscored indicator through the colour bands as
    a zero and painted it the same slate as a genuinely low score."""
    row = {"ioc_type": "ipv4-addr", "ioc_value": "1.2.3.4", "source": "feed"}
    unscored = render(LS_IOCS, configured=True, failed=False, error=None,
                      limit=5, rows=[dict(row, score=None)])
    low = render(LS_IOCS, configured=True, failed=False, error=None,
                 limit=5, rows=[dict(row, score=10)])
    high = render(LS_IOCS, configured=True, failed=False, error=None,
                  limit=5, rows=[dict(row, score=95)])
    assert "carries no score" in unscored
    assert "text-slate-600" in unscored
    assert "carries no score" not in low
    assert "text-slate-400" in low
    assert "text-red-400" in high


def test_the_two_match_tables_share_one_row_definition():
    """renderMatchRows was a second definition of a match row and the two
    had drifted: its showType argument rendered the observable type where
    the Watchlist table shows read state. One fragment, one parameter."""
    status = render(MATCHES, failed=False, matches=[_match()], total=1,
                    unread_only=False, show_type=False)
    typed = render(MATCHES, failed=False, matches=[_match()], total=1,
                   unread_only=False, show_type=True)
    assert "Unread" in status
    assert "ip" in typed
    assert "Unread</strong>" not in typed
    # Five columns either way, because both table headers declare five.
    assert status.count("<td") == typed.count("<td") == 5


OVERVIEW_PATHS = [
    "/ui/threat-intel/overview-stats",
    "/ui/threat-intel/recently-active",
    "/ui/threat-intel/landscape-actors",
    "/ui/threat-intel/landscape-iocs",
]


@pytest.mark.parametrize("path", OVERVIEW_PATHS)
def test_an_overview_fragment_refuses_a_caller_with_no_permissions(session, path):
    app = _client(session, _User())
    with TestClient(app) as client:
        assert client.get(path).status_code == 403


@pytest.mark.parametrize("path", OVERVIEW_PATHS)
def test_an_overview_fragment_answers_a_reader(session, path):
    app = _client(session, _User(PERMISSION))
    with TestClient(app) as client:
        r = client.get(path)
    assert r.status_code == 200
    # Never an empty body: every one of these has a render for every outcome,
    # and a blank panel is what the page did on failure.
    assert r.text.strip()


def test_the_overview_cards_report_opencti_as_unconfigured_here(session):
    """This deployment has no OpenCTI, measured: both landscape endpoints
    answer 503. So the cards must say not configured, and that is the one
    outcome a live page on this machine can show."""
    app = _client(session, _User(PERMISSION))
    with TestClient(app) as client:
        for path in ("/ui/threat-intel/landscape-actors",
                     "/ui/threat-intel/landscape-iocs"):
            body = client.get(path).text
            assert "not configured" in body, path
            assert "could not be read" not in body, path


def test_the_ioc_card_bounds_min_score_as_the_json_endpoint_does(session):
    from ion.web.threat_landscape_api import get_ioc_feed
    import inspect

    api = inspect.signature(get_ioc_feed).parameters["min_score"].default
    from ion.web.ui.threat_intel import threat_intel_landscape_iocs_fragment
    frag = inspect.signature(
        threat_intel_landscape_iocs_fragment).parameters["min_score"].default
    assert frag.metadata == api.metadata

    app = _client(session, _User(PERMISSION))
    with TestClient(app) as client:
        assert client.get(
            "/ui/threat-intel/landscape-iocs?min_score=500").status_code == 422


def test_the_page_no_longer_builds_the_overview_in_javascript():
    page = _page()
    for gone in ("async function loadOverview", "async function loadOverviewActors",
                 "async function loadOverviewIOCs", "async function loadRecentlyActive",
                 "function renderMatchRows"):
        assert gone not in page, f"{gone} should have been removed"


@pytest.mark.parametrize("target,url", [
    ("ti-overview-stats", "/ui/threat-intel/overview-stats"),
    ("ti-overview-actors", "/ui/threat-intel/landscape-actors"),
    ("ti-overview-iocs", "/ui/threat-intel/landscape-iocs"),
    ("overview-matches-body", "/ui/threat-intel/matches?limit=10&amp;show_type=true"),
])
def test_each_overview_region_pulls_its_markup_from_its_fragment(target, url):
    page = _page()
    block = page[page.index(f'id="{target}"'):]
    block = block[:block.index(">") + 500]
    assert url in block, f"{target} does not request {url}"


def test_the_overview_regions_load_without_a_click():
    """Overview is the tab that is active on first paint, so its regions
    cannot wait for the ti-show a tab click dispatches."""
    page = _page()
    for target in ("ti-overview-stats", "ti-overview-actors",
                   "ti-overview-iocs", "overview-matches-body"):
        block = page[page.index(f'id="{target}"'):]
        block = block[:block.index(">") + 500]
        assert 'hx-trigger="load' in block, target


def test_the_hide_rule_observables_toggle_sends_both_of_its_states():
    """A checkbox sends nothing when unchecked, and the route's default of
    true would then reassert the filter the reader just turned off. The
    hidden companion always sends false and the checkbox sends true on top
    of it, which puts the parameter in twice on purpose: FastAPI reads the
    last copy, so hx-include lists hidden first and checkbox second."""
    page = _page()
    assert 'id="ti-hide-rule-obs-off"' in page
    block = page[page.index('id="ti-hide-rule-obs"'):]
    block = block[:block.index(">") + 500]
    assert 'hx-include="#ti-hide-rule-obs-off, #ti-hide-rule-obs"' in block
    assert 'hx-swap="none"' in block, "both lists arrive out of band"


def test_the_overview_limits_are_the_ones_the_page_asked_for():
    assert OVERVIEW_MATCH_LIMIT == 10
    assert OVERVIEW_CARD_ROWS == 5
    assert RECENT_DAYS == 30
    assert RECENT_TOP_N == 8


def test_the_landscape_cards_render_rows_when_opencti_answers(session, monkeypatch):
    """OpenCTI is unconfigured on this deployment, so both cards
    short-circuit before their fetch runs and the rows path is otherwise
    never exercised. This drives it with a configured stub.
    """
    import ion.services.opencti_service as octi

    class _Svc:
        is_configured = True

        async def get_threat_landscape_overview(self):
            return {"actors": [{"name": "APT29", "ttp_count": 7,
                                "country_flag": "RU"}]}

    monkeypatch.setattr(octi, "get_opencti_service", lambda: _Svc())

    app = _client(session, _User(PERMISSION))
    with TestClient(app) as client:
        body = client.get("/ui/threat-intel/landscape-actors").text
    assert "APT29" in body
    assert "7 TTPs" in body
    assert "not configured" not in body
    assert "could not be read" not in body


def test_a_landscape_card_that_raises_reports_the_class_not_the_message(session,
                                                                       monkeypatch):
    """The service's own messages can carry estate detail and this card
    renders for anyone with observable:read, so only the exception class
    name reaches the page."""
    import ion.services.opencti_service as octi

    class _Svc:
        is_configured = True

        async def get_threat_landscape_overview(self):
            raise RuntimeError("opencti at https://cti.internal.example said no")

    monkeypatch.setattr(octi, "get_opencti_service", lambda: _Svc())

    app = _client(session, _User(PERMISSION))
    with TestClient(app) as client:
        body = client.get("/ui/threat-intel/landscape-actors").text
    assert "could not be read" in body
    assert "RuntimeError" in body
    assert "cti.internal.example" not in body
    assert "not configured, so" not in body


def test_the_landscape_card_trims_to_the_rows_the_page_showed(session, monkeypatch):
    """Both cards did `.slice(0, 5)` in the browser after fetching the full
    list. The trim happens server-side now, so the extra rows are not sent
    to a card that would never show them."""
    import ion.services.opencti_service as octi

    class _Svc:
        is_configured = True

        async def get_threat_landscape_overview(self):
            return {"actors": [{"name": f"ACTOR-{i}", "ttp_count": i}
                               for i in range(12)]}

    monkeypatch.setattr(octi, "get_opencti_service", lambda: _Svc())

    app = _client(session, _User(PERMISSION))
    with TestClient(app) as client:
        body = client.get("/ui/threat-intel/landscape-actors").text
    assert body.count("ACTOR-") == OVERVIEW_CARD_ROWS
    assert "ACTOR-0" in body
    assert "ACTOR-5" not in body


def test_a_missing_observable_list_from_the_route_is_a_failure_not_an_absence(
        session, monkeypatch):
    """Closes a survivor. The template is tested directly above, but nothing
    drove the module with a payload that omits a list, so replacing `_rows`
    with `.get(...) or []` went unnoticed: a payload carrying neither key
    would have rendered "No observable activity" for a read that failed to
    produce one."""
    import ion.web.threat_intel_api as api

    monkeypatch.setattr(api, "recently_active",
                        lambda **kw: {"time_window_days": 30})

    app = _client(session, _User(PERMISSION))
    with TestClient(app) as client:
        body = client.get("/ui/threat-intel/recently-active").text
    assert "Recent observable activity could not be read" in body
    assert "Recent technique activity could not be read" in body
    assert "No observable activity" not in body
    assert "No MITRE techniques tagged" not in body


def test_a_missing_technique_list_alone_is_a_failure_not_an_absence():
    """Closes a survivor. The observables side of this was tested and the
    techniques side was not, so dropping `techniques is none` from its guard
    left no test red."""
    html = render(RECENT, failed=False, techniques=None,
                  observables=[{"type": "ip", "value": "1.2.3.4", "count": 3}],
                  days=30)
    assert "Recent technique activity could not be read" in html
    assert "No MITRE techniques tagged" not in html
    assert "1.2.3.4" in html, "the list that did arrive still renders"


def test_the_matches_route_honours_show_type(session):
    """Closes a survivor. The fragment's show_type branch was tested by
    rendering it directly, and the page's request for it was tested by
    reading the markup, but nothing checked that the route passes the
    parameter through, so hardcoding it to False survived."""
    from ion.services.threat_intel_service import ThreatIntelService
    from ion.models.threat_intel import ThreatIntelWatch  # noqa: F401

    app = _client(session, _User(PERMISSION))
    with TestClient(app) as client:
        plain = client.get("/ui/threat-intel/matches")
        typed = client.get("/ui/threat-intel/matches?show_type=true")
    assert plain.status_code == typed.status_code == 200

    # Both tables are empty on this deployment, so compare the parameter the
    # route resolved rather than rendered rows: the fragment only branches on
    # show_type inside a row.
    import inspect
    from ion.web.ui.threat_intel import threat_intel_matches_fragment
    sig = inspect.signature(threat_intel_matches_fragment)
    assert "show_type" in sig.parameters
    assert sig.parameters["show_type"].default.default is False

    src = inspect.getsource(threat_intel_matches_fragment)
    assert src.count('"show_type": show_type') == 2, (
        "both the success and the failure context must carry show_type, or "
        "one of the two renders silently loses the column"
    )


#: Functions this conversion deleted from the page's script. Any surviving
#: reference to one is a ReferenceError the moment the script is evaluated
#: or the moment a delegated handler resolves it on window.
DELETED_FUNCTIONS = [
    "loadWatches", "loadMatches", "tiLoadStories", "loadOverview",
    "loadOverviewActors", "loadOverviewIOCs", "loadRecentlyActive",
    "renderMatchRows",
]


def _script() -> str:
    """The page's script block with its comments stripped.

    Comments are where these names legitimately still appear, explaining
    what was removed and why, so a check that did not strip them would
    either fail on the documentation or be written so loosely that it
    passed on a real reference.
    """
    page = _page()
    body = page[page.index('<script nonce="{{ csp_nonce }}">') + 32:]
    body = body[:body.index("</script>")]
    return "\n".join(
        line for line in body.splitlines()
        if not line.lstrip().startswith("//")
    )


@pytest.mark.parametrize("name", DELETED_FUNCTIONS)
def test_no_live_code_still_references_a_deleted_function(name):
    """`window.loadRecentlyActive = loadRecentlyActive;` outlived the
    function it exported and threw "loadRecentlyActive is not defined" when
    the script was evaluated. node --check cannot see that, because the name
    is syntactically valid, and the fragment tests never load the page. It
    was found by driving the real page, which is why this guard exists.
    """
    assert name not in _script(), (
        f"{name} was deleted but something still references it; a delegated "
        "data-*-action resolves by name on window, so this throws at runtime"
    )


def test_every_delegated_action_on_the_page_resolves_to_something():
    """The same hazard from the markup side. A data-click-action or
    data-change-action naming a function that no longer exists is a
    ReferenceError on the first click, and nothing offline catches it.
    """
    import re

    page = _page()
    actions = set(re.findall(r'data-(?:click|change)-action="([A-Za-z0-9_]+)"', page))

    # base.html too. It defines window helpers that every page inherits, and
    # this page uses one of them: tiCopyIOC lives at base.html:123. Scoping
    # the search to this page's own script reported that as a dead action,
    # which is the fourth time in this project a guard has named something
    # adjacent to its subject as the defect.
    script = _script() + (ROOT / "src/ion/web/templates/base.html").read_text(
        encoding="utf-8")

    missing = sorted(
        a for a in actions
        if f"window.{a} " not in script
        and f"window.{a}=" not in script
        and f"function {a}(" not in script
        and f"{a} = function" not in script
        and f"{a} = async function" not in script
    )
    assert not missing, f"delegated actions with no definition: {missing}"
