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


def flat(html: str) -> str:
    """Rendered HTML with its whitespace collapsed.

    Prose in a template wraps, so a sentence asserted as one string
    fails on where the paragraph happens to break rather than on what
    it says. Three tests in this file failed that way before this
    existed, and reflowing a comment should not red a guard.
    """
    return " ".join(html.split())


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
    # The gate itself moved server-side when the actor and campaign tables
    # became fragments: watch_cell in _threat_intel_cells.html withholds the
    # button, so there is no client-side branch left to count. The page still
    # carries the flag because the script needs to know whether it may offer
    # a write at all.
    cells = (ROOT / "src/ion/web/templates/_fragments/_threat_intel_cells.html"
             ).read_text(encoding="utf-8")
    assert "{%- if not can_manage -%}" in cells
    assert "Read only" in cells


#: Reads still using `fetch(url).then(r => r.json())`, which discards the
#: status so a refusal body gets destructured for a key it does not carry.
#: Zero. Every read on this page now goes through a fragment that checks
#: its own outcome, or through a handler that reads r.ok. The count went
#: 6 after the watchlist stage, 4 after the Overview stage, and 0 after the
#: actors and campaigns stage. It may only stay there.
#:
#: Pinned rather than left unmeasured. This number may only go down: a new
#: one is the defect this whole conversion exists to remove, reappearing.
UNCHECKED_READS_REMAINING = 0


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
    "renderMatchRows", "searchActors", "searchCampaigns",
    "toggleActorDetail", "toggleCampaignDetail", "refreshWatchedIds",
    "kevRenderStatus", "kevRow", "kevDetail", "kevRansomware",
    "tiUnifiedSearch",
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


# ---------------------------------------------------------------------------
# The Actors and Campaigns tabs
#
# searchActors and searchCampaigns read with `fetch(url).then(r => r.json())`
# and no r.ok check, then branched on data.detail and rendered it in the
# ti-empty class, which is the no-results styling. So a 503 from an
# unconfigured OpenCTI, a refusal, and a genuine zero-match search were
# three different facts in one voice.
#
# The detail rows were sharper: they tested four sections for content and
# fell through to "No additional detail available." A refusal body carries
# none of those sections, so a failed read claimed OpenCTI holds nothing on
# the actor in front of you.
# ---------------------------------------------------------------------------

ACTOR_RESULTS = "_fragments/threat_intel_actor_results.html"
CAMPAIGN_RESULTS = "_fragments/threat_intel_campaign_results.html"
ENTITY_DETAIL = "_fragments/threat_intel_entity_detail.html"


def _actor(**over):
    base = {
        "id": "intrusion-set--abc",
        "name": "APT29",
        "description": "A Russian state actor.",
        "aliases": ["Cozy Bear", "Nobelium", "YTTRIUM", "UNC2452"],
        "labels": [{"value": "apt", "color": "#ff0000"}],
        "threat_actor_types": ["intrusion-set"],
        "confidence": 85,
        "country_flag": "\U0001F1F7\U0001F1FA",
        "country_name": "Russia",
        "first_seen": "2020-01-01T00:00:00+00:00",
        "last_seen": "2026-10-01T00:00:00+00:00",
    }
    base.update(over)
    return base


def _results(fragment, key, rows, **over):
    ctx = {"q": "apt", "configured": True, "failed": False, "error": None,
           "can_manage": True, "watched_ids": set(), "prompt": False,
           key: rows}
    ctx.update(over)
    return render(fragment, **ctx)


@pytest.mark.parametrize("fragment,key", [
    (ACTOR_RESULTS, "actors"), (CAMPAIGN_RESULTS, "campaigns"),
])
def test_an_unconfigured_opencti_is_not_reported_as_a_search_with_no_matches(
        fragment, key):
    """The defect. A 503 arrived as {"detail": ...} through a read with no
    r.ok check, and the data.detail branch rendered it in the ti-empty
    class, so a reader searching an unconfigured estate was told their
    search found nothing."""
    html = _results(fragment, key, None, configured=False)
    assert "not configured" in html
    assert "cannot be searched" in html
    assert "No threat actors found" not in html
    assert "No campaigns found" not in html


@pytest.mark.parametrize("fragment,key", [
    (ACTOR_RESULTS, "actors"), (CAMPAIGN_RESULTS, "campaigns"),
])
def test_a_failed_search_is_a_fault_not_an_absence_of_matches(fragment, key):
    html = _results(fragment, key, None, failed=True, error="OpenCTIError")
    assert "did not complete" in html
    assert "fault rather than an absence of matches" in flat(html)
    assert "OpenCTIError" in html
    assert 'role="alert"' in html


@pytest.mark.parametrize("fragment,key,empty", [
    (ACTOR_RESULTS, "actors", "No threat actors found for apt"),
    (CAMPAIGN_RESULTS, "campaigns", "No campaigns found for apt"),
])
def test_a_search_that_matched_nothing_says_so_with_the_term_in_it(
        fragment, key, empty):
    html = _results(fragment, key, [])
    assert empty in html
    assert "not configured" not in html
    assert "did not complete" not in html


@pytest.mark.parametrize("fragment,key", [
    (ACTOR_RESULTS, "actors"), (CAMPAIGN_RESULTS, "campaigns"),
])
def test_the_resting_state_is_a_branch_not_markup_left_in_the_shell(
        fragment, key):
    """A copy left in the page shell would survive a search and sit above
    the results."""
    html = _results(fragment, key, [], prompt=True, q="")
    assert "Enter a search term" in html
    assert "No threat actors found" not in html
    assert "No campaigns found" not in html


def test_an_actor_row_carries_every_column_the_table_declares():
    html = _results(ACTOR_RESULTS, "actors", [_actor()])
    assert "APT29" in html
    assert "Russia" in html
    assert "Intrusion Set" in html, "the intrusion-set type is relabelled"
    assert "Cozy Bear" in html
    assert "ti-confidence high" in html
    assert "/threat-intel/actors/" in html, "the profile deep link"
    assert "entity_class=intrusion_set" in html


def test_an_entity_with_no_confidence_is_not_painted_as_unreliable():
    """`conf >= 70 ? 'high' : conf >= 40 ? 'medium' : 'low'` after
    defaulting a missing confidence to a dash meant an unassessed entity
    rendered a dash in the `low` colour: it looked as though OpenCTI had
    assessed it and found it unreliable."""
    low = _results(ACTOR_RESULTS, "actors", [_actor(confidence=10)])
    missing = _results(ACTOR_RESULTS, "actors", [_actor(confidence=None)])
    assert "ti-confidence low" in low
    assert "ti-confidence" not in missing
    assert "not assessed" in missing


def test_both_tables_show_how_many_aliases_they_truncated():
    """The actor table had a "+N" indicator and the campaign table silently
    truncated at three, so an entity with twelve aliases was reported as
    having three. One macro now, so they cannot disagree again."""
    for fragment, key in ((ACTOR_RESULTS, "actors"),
                          (CAMPAIGN_RESULTS, "campaigns")):
        html = _results(fragment, key, [_actor()])
        assert "Cozy Bear, Nobelium, YTTRIUM" in html
        assert "+1" in html, f"{key} must say an alias was hidden"


def test_a_label_colour_travels_as_data_ion_style_not_a_style_attribute():
    """The CSP sets style-src-attr 'none', so an inline style is blocked.
    The colour is OpenCTI's own per-label value, so it cannot be a class."""
    html = _results(ACTOR_RESULTS, "actors", [_actor()])
    assert "data-ion-style=" in html
    assert "#ff0000" in html
    # A leading space, because data-ion-style="background:..." contains
    # the substring this would otherwise match: the guard would have
    # failed on the very attribute it exists to require.
    assert ' style="background' not in html


def test_the_watch_button_carries_its_whole_payload():
    """The page looked the entity up by index in container._actors, which
    the server does not have. event-delegation.js JSON-parses data-args and
    applies it, so a one-element array hands the payload over."""
    html = _results(ACTOR_RESULTS, "actors", [_actor()])
    raw = re.search(r"data-args='(\[\{.*?\}\])'", html, re.S).group(1)
    decoded = (raw.replace("&quot;", '"').replace("&#34;", '"')
                  .replace("&amp;", "&").replace("&lt;", "<")
                  .replace("&gt;", ">").replace("\\u0022", '"')
                  .replace("\\u0027", "'").replace("&#39;", "'"))
    payload = json.loads(decoded)[0]
    assert payload["entity_type"] == "threat_actor"
    assert payload["opencti_id"] == "intrusion-set--abc"
    assert payload["name"] == "APT29"
    assert payload["labels"] == ["apt"], "labels are flattened to their values"
    assert "Cozy Bear" in payload["aliases"]


def test_an_already_watched_entity_offers_no_watch_button():
    watched = _results(ACTOR_RESULTS, "actors", [_actor()],
                       watched_ids={"intrusion-set--abc"})
    assert "Watched" in watched
    assert "watchActor" not in watched


def test_the_watch_button_is_withheld_without_observable_enrich():
    html = _results(ACTOR_RESULTS, "actors", [_actor()], can_manage=False)
    assert "watchActor" not in html
    assert "Read only" in html


@pytest.mark.parametrize("columns", [9, 7])
def test_a_failed_detail_read_does_not_claim_opencti_holds_nothing(columns):
    """The sharpest version of the defect. The page tested four sections for
    content and fell through to "No additional detail available", and a
    refusal body carries none of them."""
    html = render(ENTITY_DETAIL, columns=columns, configured=True,
                  failed=True, detail=None)
    assert "could not be read" in html
    assert "No additional detail available" not in html
    assert f'colspan="{columns}"' in html


def test_a_detail_payload_that_is_not_a_mapping_is_a_failure():
    html = render(ENTITY_DETAIL, columns=9, configured=True, failed=False,
                  detail=None)
    assert "cannot read" in html
    assert "No additional detail available" not in html


def test_an_entity_opencti_genuinely_holds_nothing_on_says_so():
    html = render(ENTITY_DETAIL, columns=9, configured=True, failed=False,
                  detail={"description": None, "campaigns": [], "ttps": [],
                          "indicators": []})
    assert "No additional detail available" in html
    assert "could not be read" not in html


def test_a_detail_row_renders_every_section_opencti_returned():
    html = render(ENTITY_DETAIL, columns=9, configured=True, failed=False,
                  detail={
                      "description": "A Russian state actor.",
                      "campaigns": [{"name": "SolarWinds"}],
                      "ttps": [{"mitre_id": "T1059", "name": "Command Line",
                                "description": "runs commands"}],
                      "indicators": [{"name": "1.2.3.4"}],
                  })
    assert "A Russian state actor." in html
    assert "SolarWinds" in html
    assert "T1059: Command Line" in html
    assert "1.2.3.4" in html
    assert "Related Campaigns (1)" in html
    assert "MITRE ATT&amp;CK TTPs (1)" in html


def test_a_ttp_with_no_mitre_id_still_renders_its_name():
    html = render(ENTITY_DETAIL, columns=9, configured=True, failed=False,
                  detail={"ttps": [{"name": "Unmapped Technique"}]})
    assert "Unmapped Technique" in html
    assert "None:" not in html


SEARCH_PATHS = [
    "/ui/threat-intel/actor-search",
    "/ui/threat-intel/campaign-search",
]
DETAIL_PATHS = [
    "/ui/threat-intel/actor-detail?entity_id=x",
    "/ui/threat-intel/campaign-detail?entity_id=x",
]


@pytest.mark.parametrize("path", SEARCH_PATHS + DETAIL_PATHS)
def test_a_search_or_detail_fragment_refuses_a_caller_with_no_permissions(
        session, path):
    app = _client(session, _User())
    with TestClient(app) as client:
        assert client.get(path).status_code == 403


@pytest.mark.parametrize("path", SEARCH_PATHS)
def test_an_empty_search_renders_the_prompt_rather_than_searching(session, path):
    app = _client(session, _User(PERMISSION))
    with TestClient(app) as client:
        body = client.get(path).text
    assert "Enter a search term" in body
    assert "found for" not in body


@pytest.mark.parametrize("path", SEARCH_PATHS)
def test_a_search_on_this_deployment_reports_opencti_unconfigured(session, path):
    """Measured: OpenCTI is not configured here, so this is the outcome a
    live page on this machine shows, and it must not read as no matches."""
    app = _client(session, _User(PERMISSION))
    with TestClient(app) as client:
        body = client.get(f"{path}?q=apt").text
    assert "not configured" in body
    assert "found for apt" not in body


@pytest.mark.parametrize("path", DETAIL_PATHS)
def test_a_detail_row_requires_an_entity_id(session, path):
    app = _client(session, _User(PERMISSION))
    with TestClient(app) as client:
        bare = path.split("?")[0]
        assert client.get(bare).status_code == 422


def test_the_actor_detail_entity_class_default_matches_the_json_endpoint():
    """entity_class decides which OpenCTI lookup path is used, so a
    different default here would make the fragment answer about a different
    entity than the API does for the same id."""
    import inspect
    from ion.web.threat_intel_api import get_actor_detail
    from ion.web.ui.threat_intel import threat_intel_actor_detail_fragment

    api = inspect.signature(get_actor_detail).parameters["entity_class"].default
    frag = inspect.signature(
        threat_intel_actor_detail_fragment).parameters["entity_class"].default
    assert frag.default == api.default == "threat_actor"


def test_the_search_size_is_within_what_the_endpoint_accepts(session):
    import inspect
    from ion.web.threat_intel_api import search_actors
    from ion.web.ui.threat_intel import SEARCH_FIRST

    bound = inspect.signature(search_actors).parameters["first"].default
    ceiling = next(m.le for m in bound.metadata if hasattr(m, "le"))
    assert SEARCH_FIRST <= ceiling


def test_the_detail_column_counts_match_the_tables_that_hold_them():
    """A detail row is one cell spanning its parent table, so a wrong count
    breaks the table layout rather than failing loudly."""
    from ion.web.ui.threat_intel import ACTOR_COLUMNS, CAMPAIGN_COLUMNS

    page = _page()
    for fragment, count in ((ACTOR_RESULTS, ACTOR_COLUMNS),
                            (CAMPAIGN_RESULTS, CAMPAIGN_COLUMNS)):
        src = (ROOT / "src/ion/web/templates" / fragment).read_text(
            encoding="utf-8")
        assert src.count("<th>") == count, fragment
        assert f'colspan="{count}"' in src, fragment


def test_the_search_boxes_are_forms_so_enter_needs_no_event_filter():
    """hx-trigger cannot express Enter here: an event filter like
    [key=='Enter'] is compiled with Function() and this CSP carries no
    unsafe-eval. A form submits on Enter natively."""
    page = _page()
    for panel, url in (("panel-actors", "/ui/threat-intel/actor-search"),
                       ("panel-campaigns", "/ui/threat-intel/campaign-search")):
        block = page[page.index(f'id="{panel}"'):]
        block = block[:block.index("</div>\n\n") if "</div>\n\n" in block else 1400]
        assert "<form" in block, panel
        assert url in block, panel
        assert 'name="q"' in block, panel
    # The attribute values, not the file text. An hx-trigger event filter
    # is the thing that cannot work here, and a prose comment saying so
    # contains the same characters: checking the text failed on the comment
    # that documents the rule, which is the fifth time in this project a
    # guard has matched its own explanation.
    triggers = re.findall(r'hx-trigger="([^"]*)"', page)
    assert triggers, "the page should carry hx-trigger attributes"
    for value in triggers:
        assert "[" not in value, (
            f"hx-trigger={value!r} carries an event filter, which htmx "
            "compiles with Function() and this CSP has no unsafe-eval for"
        )


def test_the_page_no_longer_searches_or_expands_rows_in_javascript():
    page = _page()
    for gone in ("window.searchActors", "window.searchCampaigns",
                 "window.toggleActorDetail", "window.toggleCampaignDetail",
                 "async function refreshWatchedIds", "container._actors"):
        assert gone not in _script(), f"{gone} should have been removed"
    # `_actors` on its own is a substring of `related_actors`, which was
    # the report drill panel's and was not that stage's to remove. The
    # drill is a fragment now, so the name is gone from the script and
    # this guard checks the precise token instead.
    assert "container._actors" not in _script()


def test_the_client_side_watched_set_is_gone():
    """It asked for `?limit=1000` against an endpoint bounded at le=500 and
    so answered 422 on every call, measured live, leaving the set empty
    permanently and every result rendered as not-watched. The fragments read
    the watchlist per request instead."""
    # _script() strips comments, which is where both of these names still
    # legitimately appear explaining what was removed and why.
    assert "watchedIds" not in _script()
    assert "limit=1000" not in _script()


def test_the_watch_handler_checks_the_response_before_claiming_success():
    script = _script()
    watch = script[script.index("window.watchActor = async function"):]
    watch = watch[:watch.index("window.watchCampaign")]
    assert "if (!r.ok)" in watch
    assert "403" in watch, "a refusal is worded, not reported as success"


# ---------------------------------------------------------------------------
# The search and detail paths past the is_configured gate
#
# OpenCTI is not configured on this deployment, so every test above
# short-circuits at `if not service.is_configured` and nothing past it runs.
# Four mutations survived the first pass for exactly that reason: dropping
# `_rows`, accepting a non-mapping detail payload, and never reading the
# watchlist all went unnoticed because no test reached those lines. These
# drive them with a configured stub.
# ---------------------------------------------------------------------------


class _ConfiguredOpenCTI:
    """A configured service whose reads return whatever a test hands it."""

    is_configured = True

    def __init__(self, payload):
        self._payload = payload

    async def _answer(self, *a, **k):
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


def _stub_opencti(monkeypatch, payload):
    import ion.services.opencti_service as octi
    monkeypatch.setattr(octi, "get_opencti_service",
                        lambda: _ConfiguredOpenCTI(payload))


def _stub_search(monkeypatch, payload):
    """The search routes call the JSON handler, not the service, so both are
    stubbed: the service decides `configured` and the handler the payload."""
    import ion.web.threat_intel_api as api

    async def answer(**kw):
        if isinstance(payload, Exception):
            raise payload
        return payload

    monkeypatch.setattr(api, "search_actors", answer)
    monkeypatch.setattr(api, "search_campaigns", answer)
    monkeypatch.setattr(api, "get_actor_detail", answer)
    monkeypatch.setattr(api, "get_campaign_detail", answer)
    _stub_opencti(monkeypatch, {})


def test_a_search_payload_with_no_actor_list_is_a_failure_not_an_absence(
        session, monkeypatch):
    """Closes a survivor. Replacing `_rows` with `.get(...) or []` turned a
    payload carrying no `actors` key into an empty list, and the table then
    said the search matched nothing."""
    _stub_search(monkeypatch, {"detail": "Not authenticated"})

    app = _client(session, _User(PERMISSION))
    with TestClient(app) as client:
        body = client.get("/ui/threat-intel/actor-search?q=apt").text
    assert "cannot read" in body
    assert "No threat actors found" not in body


def test_a_search_that_matched_nothing_still_reads_as_nothing_matched(
        session, monkeypatch):
    """The other side of the same branch, so the pair pins `_rows` from both
    directions: an empty list is an empty result, a missing key is not."""
    _stub_search(monkeypatch, {"actors": []})

    app = _client(session, _User(PERMISSION))
    with TestClient(app) as client:
        body = client.get("/ui/threat-intel/actor-search?q=apt").text
    assert "No threat actors found for apt" in body
    assert "cannot read" not in body


def test_a_search_renders_its_rows_and_marks_the_ones_already_watched(
        session, monkeypatch):
    """Closes a survivor. `watched_ids` was never read by any test, so
    hardcoding it to an empty set went unnoticed, which is the same defect
    the client-side watchedIds set had: every result rendered as
    not-watched whatever the watchlist held."""
    from ion.services.threat_intel_service import ThreatIntelService

    ThreatIntelService(session).add_watch(
        entity_type="threat_actor",
        opencti_id="intrusion-set--watched",
        name="Already Watched",
        watched_by="ti-tester",
    )
    session.commit()

    _stub_search(monkeypatch, {"actors": [
        {"id": "intrusion-set--watched", "name": "Already Watched"},
        {"id": "intrusion-set--new", "name": "Not Watched Yet"},
    ]})

    app = _client(session, _User(PERMISSION, MANAGE_PERMISSION))
    with TestClient(app) as client:
        body = client.get("/ui/threat-intel/actor-search?q=w").text

    assert "Already Watched" in body
    assert "Not Watched Yet" in body
    # One Watch button, for the entity that is not watched. The other row
    # shows the disabled Watched state.
    assert body.count("watchActor") == 1
    assert "ti-btn-watched" in body


def test_a_detail_payload_that_is_not_a_mapping_is_rejected_by_the_route(
        session, monkeypatch):
    """Closes a survivor. Dropping the isinstance check let a list or a
    string reach the template, where `detail.description` on a list is
    undefined and every section skipped, so the row said OpenCTI holds
    nothing on the entity."""
    _stub_search(monkeypatch, ["not", "a", "mapping"])

    app = _client(session, _User(PERMISSION))
    with TestClient(app) as client:
        body = client.get("/ui/threat-intel/actor-detail?entity_id=x").text
    assert "cannot read" in body
    assert "No additional detail available" not in body


def test_a_detail_route_renders_the_sections_opencti_returned(session, monkeypatch):
    _stub_search(monkeypatch, {
        "description": "A Russian state actor.",
        "ttps": [{"mitre_id": "T1059", "name": "Command Line"}],
    })

    app = _client(session, _User(PERMISSION))
    with TestClient(app) as client:
        body = client.get("/ui/threat-intel/actor-detail?entity_id=x").text
    assert "A Russian state actor." in body
    assert "T1059: Command Line" in body
    assert "No additional detail available" not in body


def test_a_null_actor_list_in_the_template_is_not_an_empty_one():
    """Closes a survivor. The failed branch was tested and this one was not,
    so dropping `actors is none` from its guard left no test red: a payload
    the table cannot read would have rendered as a search that matched
    nothing."""
    html = _results(ACTOR_RESULTS, "actors", None)
    assert "cannot read" in html
    assert "No threat actors found" not in html


def test_a_null_campaign_list_in_the_template_is_not_an_empty_one():
    html = _results(CAMPAIGN_RESULTS, "campaigns", None)
    assert "cannot read" in html
    assert "No campaigns found" not in html


def test_a_search_that_raises_is_reported_without_the_services_own_message(
        session, monkeypatch):
    """The service's messages can carry estate detail and this renders for
    anyone with observable:read, so only the exception class reaches the
    page."""
    _stub_search(monkeypatch, RuntimeError("opencti at https://cti.internal said no"))

    app = _client(session, _User(PERMISSION))
    with TestClient(app) as client:
        body = client.get("/ui/threat-intel/actor-search?q=apt").text
    assert "did not complete" in body
    assert "RuntimeError" in body
    assert "cti.internal" not in body


# ---------------------------------------------------------------------------
# The global search bar and the KEV Catalog tab
#
# Both rendered their failures into the ti-empty class, which is the
# no-results styling, so "Search failed: HTTP 403" and "no matches" looked
# alike. On the KEV panel that is the worst confusion available: the panel
# exists to answer whether a CVE is being exploited right now, and an empty
# catalog reads as no.
# ---------------------------------------------------------------------------

UNIFIED = "_fragments/threat_intel_unified_search.html"
KEV = "_fragments/threat_intel_kev.html"

KINDS = (("actors", "Threat Actors"), ("campaigns", "Campaigns"),
         ("iocs", "IOCs"), ("cases", "Cases"))


def _unified(groups, **over):
    ctx = {"q": "apt", "failed": False, "error": None, "too_short": False,
           "groups": groups, "total": None, "kinds": KINDS, "min_chars": 2}
    ctx.update(over)
    return render(UNIFIED, **ctx)


def _kev(results, status=None, **over):
    ctx = {"q": "", "ransomware_only": False, "failed": False,
           "results": results,
           "status": status if status is not None else {
               "loaded": True, "catalog_version": "2026.10.01",
               "count": 1284, "age_days": 12, "ahead_of_bundle": False}}
    ctx.update(over)
    return render(KEV, **ctx)


def _entry(**over):
    base = {
        "cve_id": "CVE-2026-8037",
        "vendor_project": "Fortinet",
        "product": "FortiOS",
        "vulnerability_name": "Path traversal",
        "date_added": "2026-09-01",
        "due_date": "2026-09-22",
        "known_ransomware": False,
        "known_ransomware_raw": "Unknown",
        "short_description": "Traversal in the admin API.",
        "required_action": "Apply the vendor patch.",
        "cwes": ["CWE-22"],
        "notes": "https://example.invalid/advisory",
        "catalog_version": "2026.10.01",
        "source": "bundled",
    }
    base.update(over)
    return base


def test_a_failed_global_search_is_not_styled_as_no_matches():
    html = _unified(None, failed=True)
    assert "did not complete" in html
    assert "rather than an absence of matches" in flat(html)
    assert 'role="alert"' in html
    assert "No matches for" not in html


def test_a_global_search_with_nothing_under_any_heading_says_no_matches():
    html = _unified({k: [] for k, _ in KINDS})
    assert "No matches for apt" in html
    assert "did not complete" not in html


def test_a_source_that_could_not_be_read_is_not_a_source_with_no_matches():
    """The endpoint pre-seeds all four keys, so a missing one means the shape
    changed rather than that a source was quiet. Either way it is not a
    finding that nothing matched under that heading."""
    html = _unified({"actors": None, "campaigns": [{"name": "SolarWinds"}],
                     "iocs": [], "cases": []})
    assert "could not be read" in html
    assert "SolarWinds" in html, "the source that did answer still renders"


def test_a_term_shorter_than_the_endpoint_accepts_says_so():
    """`if (q.length < 2) return;` silently did nothing and left results
    from a previous search on screen."""
    html = _unified(None, too_short=True, q="a")
    assert "at least 2 characters" in html
    assert "No matches" not in html


def test_the_result_count_is_computed_when_the_payload_gives_no_total():
    """`${d.total}` went in unguarded, so a payload without a total read
    "undefined results"."""
    rows = {"actors": [{"name": "A"}, {"name": "B"}], "campaigns": [],
            "iocs": [], "cases": []}
    without = _unified(rows, total=None)
    withtotal = _unified(rows, total=99)
    assert "2 results for apt" in without
    assert "undefined" not in without
    assert "99 results for apt" in withtotal


def test_one_result_is_not_pluralised():
    html = _unified({"actors": [{"name": "A"}], "campaigns": [], "iocs": [],
                     "cases": []})
    assert "1 result for apt" in html
    assert "1 results" not in html


def test_the_search_says_a_missing_heading_is_not_proof_of_nothing():
    """The endpoint wraps each source in its own try/except and returns an
    empty list for one that fails, logging at debug, so the payload cannot
    tell them apart. The page should not imply it can."""
    html = _unified({"actors": [{"name": "A"}], "campaigns": [], "iocs": [],
                     "cases": []})
    assert "not distinguished from one that matched nothing" in flat(html)


def test_an_ioc_and_a_case_result_link_to_their_own_pages():
    html = _unified({"actors": [], "campaigns": [],
                     "iocs": [{"id": "7", "type": "ipv4-addr", "value": "1.2.3.4"}],
                     "cases": [{"id": "3", "case_number": "CASE-0003", "title": "t"}]})
    assert "/observables/7" in html
    assert "/cases?selected=3" in html


def test_a_failed_kev_lookup_is_not_an_empty_catalog():
    """The panel answers whether a CVE is being exploited right now, so a
    failure styled as no results is the worst confusion it can offer."""
    html = _kev(None, failed=True)
    assert "did not complete" in html
    assert "fault rather than an empty catalog" in flat(html)
    assert html.count('role="alert"') == 2, "the status bar says so too"
    assert "No entries in catalog" not in html


def test_an_unreadable_kev_payload_is_not_an_empty_catalog():
    html = _kev(None)
    assert "cannot read" in html
    assert "No entries in catalog" not in html


def test_an_empty_kev_result_names_the_catalog_that_found_nothing():
    """A bare "no results" invites the reader to conclude the CVE is safe,
    when what they have learned is that one snapshot does not list it. The
    page got this right and it is kept."""
    html = _kev([], q="CVE-2026-9999")
    assert "No entries in catalog 2026.10.01" in html
    assert "CVE-2026-9999" in html


def test_an_empty_kev_result_says_when_the_ransomware_filter_was_applied():
    html = _kev([], ransomware_only=True)
    assert "ransomware-linked filter applied" in html


def test_a_kev_row_carries_its_whole_entry():
    html = _kev([_entry()])
    assert "CVE-2026-8037" in html
    assert "Fortinet" in html
    assert "Path traversal" in html
    assert "Apply the vendor patch." in html
    assert "CWE-22" in html
    assert "2026-09-22" in html


def test_ransomware_unknown_is_worded_as_not_established_not_as_ruled_out():
    """CISA not having established use is not the same as having ruled it
    out, and an analyst reading this cell is deciding how urgent a patch
    is."""
    unknown = _kev([_entry(known_ransomware=False)])
    known = _kev([_entry(known_ransomware=True)])
    assert "has not established ransomware use" in unknown
    assert "not the same as ruling it out" in unknown
    assert "ransomware: unknown" in unknown
    assert "ransomware: known" in known
    assert "not established" not in known


def test_kev_references_are_text_rather_than_links():
    """ION ships to air-gapped sites where an external anchor is a dead end
    that looks broken."""
    html = _kev([_entry()])
    assert "example.invalid/advisory" in html
    assert "ti-kev-notes" in html
    assert '<a href="https://example.invalid' not in html


def test_a_catalog_that_was_never_loaded_says_so_rather_than_showing_an_age():
    html = _kev([], status={"loaded": False})
    assert "No KEV catalog loaded" in html
    assert "days old" not in html


def test_a_catalog_of_unknown_age_is_not_painted_as_fresh():
    """`age <= 30` on a null age would band as fresh. The page got this
    right with an explicit null check and it is kept: an age nobody measured
    is not a recent catalog."""
    unknown = _kev([], status={"loaded": True, "catalog_version": "x",
                               "count": 1, "age_days": None})
    fresh = _kev([], status={"loaded": True, "catalog_version": "x",
                             "count": 1, "age_days": 5})
    stale = _kev([], status={"loaded": True, "catalog_version": "x",
                             "count": 1, "age_days": 200})
    assert "age unknown" in unknown
    assert "text-ion-lime" not in unknown
    assert "text-ion-lime" in fresh
    assert "text-ion-coral" in stale


def test_a_catalog_with_no_recorded_count_does_not_print_undefined():
    """`${st.count}` went in unguarded."""
    html = _kev([], status={"loaded": True, "catalog_version": "x",
                            "count": None, "age_days": 1})
    assert "number of known-exploited CVEs" in html
    assert "undefined" not in html
    assert "None" not in html


def test_the_kev_status_bar_swaps_out_of_band():
    """One read answers both regions, because GET /api/kev returns the status
    block alongside the results."""
    html = _kev([_entry()])
    assert 'id="kev-status-bar"' in html
    assert 'hx-swap-oob="innerHTML"' in html


def test_the_unified_search_fragment_needs_observable_read(session):
    app = _client(session, _User())
    with TestClient(app) as client:
        assert client.get("/ui/threat-intel/unified-search?q=apt").status_code == 403
    app = _client(session, _User(PERMISSION))
    with TestClient(app) as client:
        assert client.get("/ui/threat-intel/unified-search?q=apt").status_code == 200


def test_the_kev_fragment_needs_alert_read_not_the_pages_own_permission(session):
    """/api/kev requires alert:read, which this page's observable:read does
    not imply. The tab is withheld from a viewer without it; this is the
    second gate, so a direct request cannot reach what the tab does not
    offer."""
    app = _client(session, _User(PERMISSION))
    with TestClient(app) as client:
        assert client.get("/ui/threat-intel/kev").status_code == 403
    app = _client(session, _User(STORIES_PERMISSION))
    with TestClient(app) as client:
        assert client.get("/ui/threat-intel/kev").status_code == 200


def test_a_short_term_reaches_the_prompt_rather_than_the_endpoint(session):
    """The endpoint declares min_length=2 and would answer 422. The fragment
    renders the prompt instead, so a reader typing one character sees why
    nothing happened."""
    app = _client(session, _User(PERMISSION))
    with TestClient(app) as client:
        r = client.get("/ui/threat-intel/unified-search?q=a")
    assert r.status_code == 200
    assert "at least 2 characters" in r.text


def test_the_kev_route_answers_the_real_catalog_on_this_deployment(session):
    """KEV is a snapshot shipped in the image, so unlike OpenCTI it has real
    data here: measured, /api/kev returned 5 results. This is the one search
    on this page a test can exercise end to end against real rows."""
    app = _client(session, _User(STORIES_PERMISSION))
    with TestClient(app) as client:
        body = client.get("/ui/threat-intel/kev").text
    assert "did not complete" not in body
    assert "cannot read" not in body


def test_the_unified_limits_match_what_the_endpoint_declares():
    import inspect
    from ion.web.threat_intel_api import unified_search
    from ion.web.ui.threat_intel import UNIFIED_MIN_CHARS, UNIFIED_PER_KIND

    q = inspect.signature(unified_search).parameters["q"].default
    per = inspect.signature(unified_search).parameters["limit_per_kind"].default
    assert UNIFIED_MIN_CHARS == next(m.min_length for m in q.metadata
                                     if hasattr(m, "min_length"))
    assert UNIFIED_PER_KIND <= next(m.le for m in per.metadata if hasattr(m, "le"))


def test_both_new_search_boxes_are_forms():
    page = _page()
    for url in ("/ui/threat-intel/unified-search", "/ui/threat-intel/kev"):
        i = page.index('hx-get="' + url + '"')
        before = page[max(0, i - 300):i]
        assert "<form" in before, url


def test_the_ransomware_toggle_sends_both_of_its_states():
    page = _page()
    assert 'name="ransomware_only" value="false"' in page
    assert 'name="ransomware_only" value="true"' in page


def test_the_page_no_longer_renders_kev_or_the_search_bar_in_javascript():
    for gone in ("function kevRenderStatus", "function kevRow",
                 "function kevDetail", "function kevRansomware",
                 "async function kevSearch", "window.tiUnifiedSearch"):
        assert gone not in _script(), gone + " should have been removed"


def test_clearing_the_global_search_uses_classes_not_inline_styles():
    """style-src-attr is 'none', and a class keeps the decision in the
    stylesheet where a sweep can reach it."""
    script = _script()
    clear = script[script.index("window.tiClearSearch"):]
    clear = clear[:clear.index("};")]
    assert "classList.add" in clear
    assert "style.display" not in clear


# ---------------------------------------------------------------------------
# The module paths behind the two searches
#
# Three mutations survived the first pass over this stage, and all three
# were the same gap that has now shown up in seven rounds of this project:
# the template is tested by rendering it with a hand-built context while the
# module function that computes that context is never driven. A template
# test proves the branch renders; it proves nothing about whether the module
# ever selects it.
#
# Dropping `_rows` for `.get(key) or []` in either search, and dropping the
# isinstance check on the KEV status, were all invisible to the renders
# above. These drive the routes with the service stubbed.
# ---------------------------------------------------------------------------


def _stub_unified(monkeypatch, payload):
    import ion.web.threat_intel_api as api

    async def answer(**kw):
        if isinstance(payload, Exception):
            raise payload
        return payload

    monkeypatch.setattr(api, "unified_search", answer)


def _stub_kev(monkeypatch, payload):
    import ion.web.kev_api as api

    def answer(**kw):
        if isinstance(payload, Exception):
            raise payload
        return payload

    monkeypatch.setattr(api, "kev_search", answer)


def test_a_search_payload_missing_a_kind_is_a_failure_for_that_kind(
        session, monkeypatch):
    """Closes a survivor. `.get(key) or []` turns a kind the payload does not
    carry into an empty list, and that heading then reads as a source which
    matched nothing."""
    _stub_unified(monkeypatch, {"q": "apt", "campaigns": [{"name": "Solar"}],
                                "iocs": [], "cases": [], "total": 1})

    app = _client(session, _User(PERMISSION))
    with TestClient(app) as client:
        body = client.get("/ui/threat-intel/unified-search?q=apt").text
    assert "could not be read" in body
    assert "Solar" in body, "the kinds that did arrive still render"


def test_a_search_payload_carrying_every_kind_renders_none_as_a_failure(
        session, monkeypatch):
    """The other side of the same branch, so the pair pins `_rows` from both
    directions: an empty list is an empty result, a missing key is not."""
    _stub_unified(monkeypatch, {"q": "apt", "actors": [], "campaigns": [],
                                "iocs": [], "cases": [], "total": 0})

    app = _client(session, _User(PERMISSION))
    with TestClient(app) as client:
        body = client.get("/ui/threat-intel/unified-search?q=apt").text
    assert "No matches for apt" in body
    assert "could not be read" not in body


def test_a_non_dict_search_payload_is_a_failed_search(session, monkeypatch):
    _stub_unified(monkeypatch, ["not", "a", "mapping"])

    app = _client(session, _User(PERMISSION))
    with TestClient(app) as client:
        body = client.get("/ui/threat-intel/unified-search?q=apt").text
    assert "did not complete" in body
    assert "No matches" not in body


def test_a_kev_payload_with_no_results_list_is_not_an_empty_catalog(
        session, monkeypatch):
    """Closes a survivor. `.get("results") or []` turns a payload that
    carries no results key into an empty catalog, which on this panel reads
    as "this CVE is not known to be exploited"."""
    _stub_kev(monkeypatch, {"count": 0, "status": {"loaded": True,
                                                   "catalog_version": "x",
                                                   "count": 1, "age_days": 1}})

    app = _client(session, _User(STORIES_PERMISSION))
    with TestClient(app) as client:
        body = client.get("/ui/threat-intel/kev").text
    assert "cannot read" in body
    assert "No entries in catalog" not in body


def test_a_kev_payload_with_an_empty_results_list_is_an_empty_catalog(
        session, monkeypatch):
    _stub_kev(monkeypatch, {"results": [], "count": 0,
                            "status": {"loaded": True, "catalog_version": "v9",
                                       "count": 1, "age_days": 1}})

    app = _client(session, _User(STORIES_PERMISSION))
    with TestClient(app) as client:
        body = client.get("/ui/threat-intel/kev").text
    assert "No entries in catalog v9" in body
    assert "cannot read" not in body


def test_a_kev_status_that_is_not_a_mapping_is_treated_as_no_status(
        session, monkeypatch):
    """Closes a survivor. Dropping the isinstance check let a list or a
    string reach the template, where `status.get` raises and the whole
    fragment 500s instead of rendering the panel."""
    _stub_kev(monkeypatch, {"results": [], "count": 0, "status": "broken"})

    app = _client(session, _User(STORIES_PERMISSION))
    with TestClient(app) as client:
        r = client.get("/ui/threat-intel/kev")
    assert r.status_code == 200
    assert "No KEV catalog loaded" in r.text
    assert "broken" not in r.text


def test_a_kev_read_that_raises_is_reported_as_a_fault(session, monkeypatch):
    _stub_kev(monkeypatch, RuntimeError("catalog table is gone"))

    app = _client(session, _User(STORIES_PERMISSION))
    with TestClient(app) as client:
        body = client.get("/ui/threat-intel/kev").text
    assert "did not complete" in body
    assert "catalog table is gone" not in body, (
        "the service's own message can carry estate detail"
    )


def test_a_kev_read_that_answers_renders_its_rows(session, monkeypatch):
    _stub_kev(monkeypatch, {
        "results": [_entry()], "count": 1,
        "status": {"loaded": True, "catalog_version": "2026.10.01",
                   "count": 1284, "age_days": 12}})

    app = _client(session, _User(STORIES_PERMISSION))
    with TestClient(app) as client:
        body = client.get("/ui/threat-intel/kev").text
    assert "CVE-2026-8037" in body
    assert "1284" in body
    assert "12 days old" in body
    assert "cannot read" not in body


# ---------------------------------------------------------------------------
# The last six regions: the IOC feed and its sparklines, the Reports tab and
# its drill panel, the technique drill, and the AI briefing.
#
# Written with a route-level test for every context key the module computes,
# rather than discovering the gap by mutation for a ninth time. Each
# template branch is still rendered directly, but no value the module
# chooses is left to a template test alone.
#
# The sharpest defect on this page was in the sparklines. Three outcomes all
# rendered the same em-dash: a failed read, a thrown read, and nothing seen.
# The only thing separating "this indicator has never been seen in your
# estate" from "we could not check" was a tooltip one of them carried.
# ---------------------------------------------------------------------------

SPARK = "_fragments/threat_intel_ioc_spark.html"
IOC_FEED = "_fragments/threat_intel_ioc_feed.html"
REPORTS = "_fragments/threat_intel_reports.html"
REPORT_DRILL = "_fragments/threat_intel_report_drill.html"
TECH_DRILL = "_fragments/threat_intel_technique_drill.html"
AI_BRIEF = "_fragments/threat_intel_ai_brief.html"


def _spark(series, total, **over):
    ctx = {"months": 12, "failed": False, "series": series, "total": total}
    ctx.update(over)
    return render(SPARK, **ctx)


def _feed(indicators, **over):
    ctx = {"configured": True, "failed": False, "error": None,
           "indicators": indicators, "min_score": 75, "label_limit": 3,
           "total": None}
    ctx.update(over)
    return render(IOC_FEED, **ctx)


def _reports(reports, **over):
    ctx = {"configured": True, "failed": False, "error": None,
           "reports": reports, "q": "", "summary_chars": 200, "total": None}
    ctx.update(over)
    return render(REPORTS, **ctx)


def _tech(detail, **over):
    ctx = {"technique_id": "T1059", "failed": False, "error": None,
           "detail": detail, "local_cases": None, "actors": None,
           "local_days": 90}
    ctx.update(over)
    return render(TECH_DRILL, **ctx)


# ---- the sparkline, the sharpest defect ----


def test_a_failed_sightings_read_is_not_the_same_mark_as_no_sightings():
    """The defect, stated as a test. Both rendered '-'; the failure had no
    tooltip and the empty state had one, and that was the whole
    difference."""
    failed = _spark(None, None, failed=True)
    empty = _spark([], 0)
    assert 'role="alert"' in failed
    assert "could not be read" in failed
    # The claim itself, not a phrase that appears inside its own
    # denial: the failure tooltip says "this is not a finding that it
    # has never been seen", so matching that substring failed on the
    # sentence written to prevent exactly this confusion.
    assert "No local sightings" not in failed
    assert 'role="alert"' not in empty
    assert "No local sightings" in empty
    assert failed != empty


def test_a_sightings_payload_with_no_series_is_a_failure_not_an_absence():
    html = _spark(None, 5)
    assert 'role="alert"' in html
    assert "cannot say whether" in html
    assert "No local sightings" not in html


@pytest.mark.parametrize("series,total", [
    ([], 0), ([], None), ([{"month": "2026-01", "count": 0}], 0),
])
def test_nothing_seen_is_a_genuine_answer_and_says_so(series, total):
    """A series of all-zero buckets and no buckets at all are the same
    finding, and both are answers rather than failures."""
    html = _spark(series, total)
    assert "No local sightings in the last 12 months" in html
    assert 'role="alert"' not in html


def test_a_sparkline_puts_its_total_in_a_title_child_not_an_attribute():
    """`<svg title="...">` does nothing. SVG needs a <title> child, so the
    old sightings total was never readable on hover."""
    html = _spark([{"month": "2026-01", "count": 3},
                   {"month": "2026-02", "count": 6}], 9)
    assert "<svg" in html
    assert "<title>9 local sightings in the last 12 months</title>" in html
    assert 'title="9 local sightings' not in html
    assert 'aria-label="9 local sightings' in html


def test_the_tallest_sparkline_bar_is_the_peak_month():
    html = _spark([{"month": "2026-01", "count": 2},
                   {"month": "2026-02", "count": 8}], 10)
    assert html.count("<rect") == 2
    assert "var(--ion-cyan, #6de4ff)" in html, "the peak month is highlighted"
    assert "<title>2026-02: 8</title>" in html


def test_a_zero_month_draws_no_bar():
    """A bar of zero height is not drawn, which the page had right: an empty
    month is a gap in the series, not a one-pixel mark."""
    html = _spark([{"month": "2026-01", "count": 0},
                   {"month": "2026-02", "count": 4}], 4)
    assert html.count("<rect") == 1


# ---- the IOC feed ----


def test_an_unscored_indicator_is_not_painted_as_a_low_score():
    """`i.score || 0` sent an unscored indicator through the colour bands as
    a zero and gave it the resting grey a genuinely low score gets."""
    row = {"ioc_type": "ipv4-addr", "ioc_value": "1.2.3.4"}
    unscored = _feed([dict(row, score=None)])
    low = _feed([dict(row, score=10)])
    high = _feed([dict(row, score=95)])
    assert "records no score" in unscored
    assert "var(--danger)" not in unscored
    assert "var(--text-secondary)" in low
    assert "var(--danger)" in high


def test_each_feed_row_loads_its_own_sightings_cell():
    html = _feed([{"ioc_type": "ipv4-addr", "ioc_value": "1.2.3.4"}])
    assert "/ui/threat-intel/ioc-spark?value=1.2.3.4" in html
    assert 'hx-trigger="load"' in html


def test_a_feed_label_can_be_a_mapping_or_a_bare_string():
    """Both shapes come out of OpenCTI depending on the query, which is what
    `l.value || l` handled."""
    html = _feed([{"ioc_value": "x", "ioc_type": "t",
                   "labels": [{"value": "ransomware"}, "apt"]}])
    assert "ransomware" in html
    assert ">apt<" in html


def test_the_feed_empty_state_names_the_threshold_it_applied():
    html = _feed([], min_score=90)
    assert "score of 90" in html
    assert "could not be read" not in html


def test_an_unconfigured_feed_is_not_an_empty_feed():
    html = _feed(None, configured=False)
    assert "not configured" in html
    assert "No indicators" not in html


# ---- the reports tab ----


def test_the_reports_empty_state_says_whether_a_filter_was_responsible():
    """The page said "No reports match the filter" or "No reports
    available", which was the right distinction and is kept."""
    filtered = _reports([], q="solar", total=25)
    unfiltered = _reports([], q="")
    assert "No reports match solar" in filtered
    assert "clearing the filter" in filtered
    assert "No reports available" in unfiltered
    assert "match" not in unfiltered


def test_a_report_with_no_name_is_still_listed():
    html = _reports([{"id": "1", "name": None, "description": "d"}])
    assert "Untitled" in html
    assert "None" not in html


def test_a_long_report_description_is_cut_with_an_ellipsis():
    html = _reports([{"id": "1", "name": "r", "description": "x" * 400}],
                    summary_chars=200)
    assert "&hellip;" in html or "…" in html
    assert "x" * 201 not in html


# ---- the technique drill ----


def test_a_failed_technique_read_lists_what_is_not_known():
    html = _tech(None, failed=True, error="OpenCTIError")
    assert "could not be read" in html
    assert "not which tactics" in html
    assert "No cases triggered" not in html
    assert "OpenCTIError" in html


def test_a_missing_local_case_list_is_a_failure_not_a_quiet_estate():
    """`d.local_cases.length` raised on a payload without the key and the
    whole panel became "Failed: TypeError". Each section answers for
    itself now."""
    html = _tech({"technique_id": "T1059", "name": "Command Line"},
                 local_cases=None, actors=[])
    assert "local case lookup did not answer" in html
    assert "No cases triggered this technique" not in html


def test_no_local_case_having_triggered_a_technique_says_so():
    html = _tech({"technique_id": "T1059"}, local_cases=[], actors=[])
    assert "No cases triggered this technique in the last 90 days" in html
    assert "did not answer" not in html


def test_an_opencti_actor_error_is_worded_differently_from_no_actors():
    """The page had this right and it is kept: an errored lookup and an
    empty result are different, and the empty one says the lookup may not be
    supported by this OpenCTI build."""
    errored = _tech({"technique_id": "T1059", "actors_error": "timeout"},
                    local_cases=[], actors=[])
    empty = _tech({"technique_id": "T1059"}, local_cases=[], actors=[])
    assert "OpenCTI lookup unavailable: timeout" in errored
    assert "not supported by this OpenCTI service build" in empty
    assert "lookup unavailable" not in empty


def test_the_technique_heading_swaps_out_of_band():
    html = _tech({"technique_id": "T1059", "name": "Command Line"},
                 local_cases=[], actors=[])
    assert 'id="ti-drill-title"' in html
    assert 'hx-swap-oob="innerHTML"' in html
    assert "T1059" in html
    assert "Command Line" in html


def test_a_failed_technique_read_still_replaces_the_previous_heading():
    """Otherwise the previous technique's title sits above a failure message
    about a different one."""
    html = _tech(None, failed=True)
    assert 'hx-swap-oob="innerHTML"' in html
    assert "could not be read" in html


def test_a_subtechnique_links_to_its_parent_as_a_button():
    """The page used <a href="javascript:void(0)">, a dead link in the
    accessibility tree."""
    html = _tech({"technique_id": "T1059.001", "is_subtechnique": True,
                  "parent_id": "T1059"}, local_cases=[], actors=[])
    assert "javascript:void(0)" not in html
    assert "<button" in html
    assert "tiCloseAndDrillTechnique" in html


# ---- the report drill ----


def test_a_failed_report_read_lists_what_is_not_known():
    html = render(REPORT_DRILL, configured=True, failed=True, error="E",
                  report=None, indicator_limit=10)
    assert "could not be read" in html
    assert "not its content" in html
    assert "No content available" not in html


def test_a_report_opencti_holds_nothing_in_says_so():
    html = render(REPORT_DRILL, configured=True, failed=False, error=None,
                  report={"name": "Thin report"}, indicator_limit=10)
    assert "No content available for this report" in html
    assert "could not be read" not in html


def test_a_report_assessed_at_zero_confidence_shows_that_figure():
    zero = render(REPORT_DRILL, configured=True, failed=False, error=None,
                  report={"name": "r", "confidence": 0}, indicator_limit=10)
    missing = render(REPORT_DRILL, configured=True, failed=False, error=None,
                     report={"name": "r", "confidence": None},
                     indicator_limit=10)
    assert "Confidence: 0%" in zero
    assert "Confidence" not in missing


def test_a_report_drill_renders_every_section_the_endpoint_returns():
    html = render(REPORT_DRILL, configured=True, failed=False, error=None,
                  indicator_limit=10,
                  report={
                      "name": "SolarWinds", "body": "A supply chain attack.",
                      "types": ["threat-report"], "source": "Mandiant",
                      "confidence": 80,
                      "labels": [{"value": "apt"}],
                      "related_actors": [{"name": "APT29",
                                          "aliases": ["Cozy Bear"]}],
                      "related_ttps": [{"mitre_id": "T1195", "name": "Supply Chain"}],
                      "related_malware": [{"name": "SUNBURST"}],
                      "related_vulns": [{"name": "CVE-2020-10148"}],
                      "related_countries": ["United States"],
                      "related_sectors": ["Government"],
                      "related_indicators": [{"pattern": "[file:hashes.'SHA-256' = 'x']"}],
                  })
    for expected in ("SolarWinds", "A supply chain attack.", "Mandiant",
                     "Confidence: 80%", "apt", "APT29", "Cozy Bear",
                     "T1195", "SUNBURST", "CVE-2020-10148",
                     "United States", "Government", "SHA-256"):
        assert expected in html, expected


def test_a_ttp_without_a_mitre_id_is_not_offered_as_a_drill_control():
    """The drill endpoint keys on the MITRE id, so a technique without one
    cannot be drilled into. It renders as text rather than a control that
    cannot work."""
    html = render(REPORT_DRILL, configured=True, failed=False, error=None,
                  indicator_limit=10,
                  report={"name": "r", "related_ttps": [
                      {"mitre_id": "T1195", "name": "Supply Chain"},
                      {"name": "Unmapped"}]})
    assert html.count("tiCloseAndDrillTechnique") == 1
    assert "Unmapped" in html


# ---- the AI briefing ----


def test_the_markdown_stripping_matches_what_the_page_did():
    from ion.web.ui.threat_intel import brief_paragraphs

    text = ("## Heading\n\n**Bold** and *italic* text.\n\n"
            "- a bullet\n\n1. numbered\n\n```\ncode\n```\n\nLast para.")
    paras = brief_paragraphs(text)
    joined = " ".join(paras)
    assert "##" not in joined
    assert "**" not in joined
    assert "Bold and italic text." in joined
    assert "a bullet" in joined
    assert "numbered" in joined
    assert "code" not in joined
    assert "Last para." in paras[-1]


def test_a_non_string_summary_gives_no_paragraphs_rather_than_raising():
    from ion.web.ui.threat_intel import brief_paragraphs

    assert brief_paragraphs(None) == []
    assert brief_paragraphs({"not": "a string"}) == []
    assert brief_paragraphs(42) == []


def test_a_newline_inside_a_paragraph_becomes_a_space():
    from ion.web.ui.threat_intel import brief_paragraphs

    assert brief_paragraphs("one\ntwo\n\nthree") == ["one two", "three"]


def test_a_failed_briefing_says_it_concluded_nothing():
    html = render(AI_BRIEF, failed=True, error="AI service not available",
                  summary=None, model=None, paragraphs=[])
    assert "could not be generated" in html
    assert "AI service not available" in html
    assert "says nothing about the current threat landscape" in flat(html)
    assert 'role="alert"' in html
    assert ">Retry<" in html


def test_a_briefing_that_came_back_empty_is_not_a_failure():
    html = render(AI_BRIEF, failed=False, error=None, summary="", model=None,
                  paragraphs=[])
    assert "No summary was generated" in html
    assert 'role="alert"' not in html
    assert ">Generate<" in html


def test_a_briefing_renders_its_paragraphs_and_names_its_model():
    html = render(AI_BRIEF, failed=False, error=None, summary="x",
                  model="llama3", paragraphs=["First.", "Second."])
    assert "<p class=\"mt-3 first:mt-0\">First.</p>" in html
    assert "Second." in html
    assert "Model: llama3" in html
    assert ">Regenerate<" in html


def test_the_model_line_is_hidden_when_no_model_was_reported():
    html = render(AI_BRIEF, failed=False, error=None, summary="x", model=None,
                  paragraphs=["p"])
    line = html[html.index('id="ai-brief-model"'):]
    line = line[:line.index("</div>")]
    assert "hidden" in line


# ---- the routes, one per context key the module computes ----


FINAL_PATHS = [
    "/ui/threat-intel/ioc-feed",
    "/ui/threat-intel/ioc-spark?value=1.2.3.4",
    "/ui/threat-intel/reports",
    "/ui/threat-intel/report-drill?report_id=x",
    "/ui/threat-intel/technique-drill?technique_id=T1059",
]


@pytest.mark.parametrize("path", FINAL_PATHS)
def test_a_final_fragment_refuses_a_caller_with_no_permissions(session, path):
    app = _client(session, _User())
    with TestClient(app) as client:
        assert client.get(path).status_code == 403


@pytest.mark.parametrize("path", FINAL_PATHS)
def test_a_final_fragment_answers_a_reader_with_something(session, path):
    app = _client(session, _User(PERMISSION))
    with TestClient(app) as client:
        r = client.get(path)
    assert r.status_code == 200
    assert r.text.strip(), "a blank panel is what the old code did on failure"


def test_the_ai_brief_is_a_post_gated_on_observable_read(session):
    """POST /api/threat-landscape/ai-summary is a POST because generating a
    briefing costs a model call, and it carries observable:read."""
    app = _client(session, _User())
    with TestClient(app) as client:
        assert client.post("/ui/threat-intel/ai-brief").status_code == 403
        assert client.get("/ui/threat-intel/ai-brief").status_code == 405
    app = _client(session, _User(PERMISSION))
    with TestClient(app) as client:
        assert client.post("/ui/threat-intel/ai-brief").status_code == 200


def test_the_sparkline_route_rejects_a_value_shorter_than_the_endpoint_takes(
        session):
    """GET /api/threat-intel/ioc-sightings bounds value at min_length=2, so
    the fragment must not be looser than the endpoint it mirrors."""
    import inspect
    from ion.web.threat_intel_api import ioc_sightings

    bound = inspect.signature(ioc_sightings).parameters["value"].default
    floor = next(m.min_length for m in bound.metadata
                 if hasattr(m, "min_length"))
    app = _client(session, _User(PERMISSION))
    with TestClient(app) as client:
        assert client.get("/ui/threat-intel/ioc-spark?value=a").status_code == 422
    assert floor == 2


def test_the_sparkline_route_reads_the_real_local_tables(session, monkeypatch):
    """Closes the gap before mutation finds it: `_rows(payload, "series")`
    and the total are module computations no template test reaches.

    Unlike everything else in this stage the sightings read is local-DB
    only, so it answers on a deployment with no OpenCTI.
    """
    import ion.web.threat_intel_api as api

    monkeypatch.setattr(api, "ioc_sightings", lambda **kw: {
        "series": [{"month": "2026-01", "count": 3}], "total_sightings": 3})

    app = _client(session, _User(PERMISSION))
    with TestClient(app) as client:
        body = client.get("/ui/threat-intel/ioc-spark?value=1.2.3.4").text
    assert "<svg" in body
    assert "2026-01: 3" in body


def test_a_sightings_payload_with_no_series_reaches_the_failure_branch(
        session, monkeypatch):
    import ion.web.threat_intel_api as api

    monkeypatch.setattr(api, "ioc_sightings", lambda **kw: {"total_sightings": 5})

    app = _client(session, _User(PERMISSION))
    with TestClient(app) as client:
        body = client.get("/ui/threat-intel/ioc-spark?value=1.2.3.4").text
    assert 'role="alert"' in body
    assert "No local sightings" not in body


def test_a_sightings_read_that_raises_is_reported_as_a_failure(session,
                                                              monkeypatch):
    import ion.web.threat_intel_api as api

    def boom(**kw):
        raise RuntimeError("sightings table is gone")

    monkeypatch.setattr(api, "ioc_sightings", boom)

    app = _client(session, _User(PERMISSION))
    with TestClient(app) as client:
        body = client.get("/ui/threat-intel/ioc-spark?value=1.2.3.4").text
    assert "could not be read" in body
    assert "sightings table is gone" not in body


def test_the_reports_filter_runs_on_the_server_over_what_was_read(
        session, monkeypatch):
    """Closes the gap before mutation finds it: the filter and `total` are
    module computations. The endpoint takes no search parameter, so the
    filter is a substring match over the rows it returned, and `total`
    reports how many were read before filtering."""
    import ion.web.threat_landscape_api as api
    import ion.services.opencti_service as octi

    class _Svc:
        is_configured = True

    monkeypatch.setattr(octi, "get_opencti_service", lambda: _Svc())

    async def answer(**kw):
        return {"reports": [{"id": "1", "name": "SolarWinds brief"},
                            {"id": "2", "name": "Unrelated"}]}

    monkeypatch.setattr(api, "get_recent_reports", answer)

    app = _client(session, _User(PERMISSION))
    with TestClient(app) as client:
        filtered = client.get("/ui/threat-intel/reports?q=solar").text
        everything = client.get("/ui/threat-intel/reports").text
    assert "SolarWinds brief" in filtered
    assert "Unrelated" not in filtered
    assert "SolarWinds brief" in everything
    assert "Unrelated" in everything


def test_a_reports_payload_with_no_list_is_a_failure_not_an_empty_tab(
        session, monkeypatch):
    import ion.web.threat_landscape_api as api
    import ion.services.opencti_service as octi

    class _Svc:
        is_configured = True

    monkeypatch.setattr(octi, "get_opencti_service", lambda: _Svc())

    async def answer(**kw):
        return {"detail": "Not authenticated"}

    monkeypatch.setattr(api, "get_recent_reports", answer)

    app = _client(session, _User(PERMISSION))
    with TestClient(app) as client:
        body = client.get("/ui/threat-intel/reports").text
    assert "cannot read" in body
    assert "No reports available" not in body


def test_the_technique_drill_splits_its_two_lists_at_the_route(session,
                                                              monkeypatch):
    """Closes the gap before mutation finds it: `local_cases` and `actors`
    are computed with `_rows` in the module, and the template renders
    whichever it is handed."""
    import ion.web.threat_intel_api as api

    monkeypatch.setattr(api, "technique_drill", lambda **kw: {
        "technique_id": "T1059", "name": "Command Line",
        "local_cases": [{"id": 1, "case_number": "CASE-0001",
                         "title": "t", "severity": "high"}],
        # No `actors` key at all, which is the case the unguarded
        # `.length` raised on.
    })

    app = _client(session, _User(PERMISSION))
    with TestClient(app) as client:
        body = client.get(
            "/ui/threat-intel/technique-drill?technique_id=T1059").text
    assert "CASE-0001" in body
    assert "actor lookup did not answer" in body
    assert "No actors mapped" not in body


def test_a_non_mapping_technique_payload_is_a_failure(session, monkeypatch):
    import ion.web.threat_intel_api as api

    monkeypatch.setattr(api, "technique_drill", lambda **kw: ["not", "a", "map"])

    app = _client(session, _User(PERMISSION))
    with TestClient(app) as client:
        body = client.get(
            "/ui/threat-intel/technique-drill?technique_id=T1059").text
    assert "could not be read" in body


def test_the_ai_brief_route_strips_markdown_and_names_the_model(
        session, monkeypatch):
    """Closes the gap before mutation finds it: `paragraphs` and `model` are
    module computations."""
    import ion.web.threat_landscape_api as api

    async def answer(**kw):
        return {"summary": "## Title\n\n**Bold** text.\n\nSecond para.",
                "model": "llama3"}

    monkeypatch.setattr(api, "ai_threat_summary", answer)

    app = _client(session, _User(PERMISSION))
    with TestClient(app) as client:
        body = client.post("/ui/threat-intel/ai-brief").text
    assert "Bold text." in body
    assert "Second para." in body
    assert "##" not in body
    assert "Model: llama3" in body


def test_the_ai_brief_route_reports_an_http_detail_when_the_service_gives_one(
        session, monkeypatch):
    """The endpoint raises HTTPException with a message meant for a caller
    to read, such as its 503 when Ollama is unavailable. The class name is
    the fallback, not the first choice."""
    import ion.web.threat_landscape_api as api
    from fastapi import HTTPException

    async def boom(**kw):
        raise HTTPException(status_code=503, detail="AI service not available")

    monkeypatch.setattr(api, "ai_threat_summary", boom)

    app = _client(session, _User(PERMISSION))
    with TestClient(app) as client:
        body = client.post("/ui/threat-intel/ai-brief").text
    assert "AI service not available" in body
    assert "HTTPException" not in body


# ---- the page shell, now complete ----


def test_the_page_builds_no_markup_in_javascript_at_all():
    """This is the whole point of the conversion. The redesign's `server`
    column passes when a template contains no innerHTML,
    insertAdjacentHTML or outerHTML, because markup built from strings in
    JavaScript cannot be restyled from markup and a stylesheet sweep
    silently fails to reach it."""
    script = _script()
    for pattern in ("innerHTML =", "insertAdjacentHTML", "outerHTML ="):
        assert pattern not in script, pattern


def test_the_page_carries_no_hand_rolled_escaping_or_date_formatting():
    """escapeHtml, formatDate and esc existed only because the markup was
    assembled here. Jinja escapes, and the ts macro decides how a timestamp
    is shown, including whether it can be localised at all."""
    script = _script()
    for gone in ("function escapeHtml", "function formatDate", "function esc("):
        assert gone not in script, gone


@pytest.mark.parametrize("target,url", [
    ("ioc-body", "/ui/threat-intel/ioc-feed"),
    ("ti-reports-list", "/ui/threat-intel/reports"),
])
def test_each_final_region_pulls_its_markup_from_its_fragment(target, url):
    page = _page()
    block = page[page.index(f'id="{target}"'):]
    block = block[:block.index(">") + 500]
    assert url in block


def test_the_drill_panels_are_revealed_with_classes_not_inline_styles():
    """The panels are hidden by a class and the old code set an inline
    display that outranked it, leaving an inline style on the element for
    every later read to contend with."""
    script = _script()
    assert "tiShowPanel" in script
    assert "classList.remove('hidden')" in script
    assert "style.display" not in script


def test_the_drill_panels_fetch_their_bodies_through_htmx():
    script = _script()
    assert "htmx.ajax('GET', '/ui/threat-intel/technique-drill'" in script
    assert "htmx.ajax('GET', '/ui/threat-intel/report-drill'" in script


def test_the_ioc_threshold_and_report_filter_travel_with_their_requests():
    page = _page()
    assert 'name="min_score"' in page
    assert 'hx-include="#ti-ioc-min-score"' in page
    assert 'id="ti-report-filter" name="q"' in page


def test_the_limits_are_the_ones_the_page_asked_for():
    from ion.web.ui.threat_intel import (
        IOC_FEED_LIMIT, IOC_LABEL_LIMIT, REPORT_INDICATOR_LIMIT,
        REPORT_LIMIT, REPORT_SUMMARY_CHARS, SPARK_MONTHS,
        TECHNIQUE_LOCAL_DAYS,
    )

    assert IOC_FEED_LIMIT == 50
    assert IOC_LABEL_LIMIT == 3
    assert SPARK_MONTHS == 12
    assert REPORT_LIMIT == 25
    assert REPORT_SUMMARY_CHARS == 200
    assert REPORT_INDICATOR_LIMIT == 10
    assert TECHNIQUE_LOCAL_DAYS == 90


# ---------------------------------------------------------------------------
# Two survivors from the final pass, and what they corrected about the rule
#
# The rule written down after eight rounds was: for every context key the
# module computes, drive the route rather than only rendering the template.
# It was applied here in advance and still let two through, because a test
# per key is not enough. It has to be per key PER BRANCH.
#
#   * `local_cases` dropping `rows` for `.get(k) or []` survived because the
#     route test supplied a payload where that key was PRESENT. The
#     difference between the two only shows when the key is absent, and that
#     case was covered for `actors` and not for its sibling.
#
#   * The shared drill helper's isinstance check survived because the
#     non-mapping test drove the technique drill, which has its own separate
#     check. The shared helper is reached only by the report drill.
#
# Both gaps are closed below, and both are the sibling of a case that was
# already covered.
# ---------------------------------------------------------------------------


def test_a_missing_local_case_key_reaches_the_failure_branch(session, monkeypatch):
    """Closes a survivor. The sibling of
    test_the_technique_drill_splits_its_two_lists_at_the_route, which
    supplied local_cases and omitted actors. This omits local_cases, which
    is the only state where `rows` and `.get(k) or []` differ."""
    import ion.web.threat_intel_api as api

    monkeypatch.setattr(api, "technique_drill", lambda **kw: {
        "technique_id": "T1059", "name": "Command Line",
        "actors": [{"name": "APT29"}],
        # No `local_cases` key.
    })

    app = _client(session, _User(PERMISSION))
    with TestClient(app) as client:
        body = client.get(
            "/ui/threat-intel/technique-drill?technique_id=T1059").text
    assert "local case lookup did not answer" in body
    assert "No cases triggered this technique" not in body
    assert "APT29" in body, "the list that did arrive still renders"


def test_an_empty_local_case_list_is_still_an_empty_result(session, monkeypatch):
    """The other side, so the pair pins `rows` from both directions for this
    key as well as for actors."""
    import ion.web.threat_intel_api as api

    monkeypatch.setattr(api, "technique_drill", lambda **kw: {
        "technique_id": "T1059", "local_cases": [], "actors": [],
    })

    app = _client(session, _User(PERMISSION))
    with TestClient(app) as client:
        body = client.get(
            "/ui/threat-intel/technique-drill?technique_id=T1059").text
    assert "No cases triggered this technique in the last 90 days" in body
    assert "did not answer" not in body


def test_a_non_mapping_report_payload_is_rejected_by_the_shared_helper(
        session, monkeypatch):
    """Closes a survivor. The technique drill has its own isinstance check
    and was tested; the shared _report_or_technique helper is reached only
    by the report drill, and dropping its check let a list reach the
    template where `report.get` is undefined and every section skipped, so
    the panel claimed the report held nothing."""
    import ion.web.threat_landscape_api as api
    import ion.services.opencti_service as octi

    class _Svc:
        is_configured = True

    monkeypatch.setattr(octi, "get_opencti_service", lambda: _Svc())

    async def answer(**kw):
        return ["not", "a", "mapping"]

    monkeypatch.setattr(api, "get_report_detail", answer)

    app = _client(session, _User(PERMISSION))
    with TestClient(app) as client:
        body = client.get("/ui/threat-intel/report-drill?report_id=x").text
    assert "could not be read" in body
    assert "No content available" not in body


def test_a_report_the_helper_accepts_renders_its_sections(session, monkeypatch):
    """The other side of the same check, so a mutation that always rejects
    is caught as well as one that always accepts."""
    import ion.web.threat_landscape_api as api
    import ion.services.opencti_service as octi

    class _Svc:
        is_configured = True

    monkeypatch.setattr(octi, "get_opencti_service", lambda: _Svc())

    async def answer(**kw):
        return {"name": "SolarWinds", "body": "A supply chain attack."}

    monkeypatch.setattr(api, "get_report_detail", answer)

    app = _client(session, _User(PERMISSION))
    with TestClient(app) as client:
        body = client.get("/ui/threat-intel/report-drill?report_id=x").text
    assert "SolarWinds" in body
    assert "A supply chain attack." in body
    assert "could not be read" not in body


# ---------------------------------------------------------------------------
# The third survivor of the final mutation pass.
#
# test_the_ioc_threshold_and_report_filter_travel_with_their_requests asserts
# that `hx-include="#ti-ioc-min-score"` appears in the page. Three elements
# carry it: the select, the Refresh button, and the #ioc-body tbody. Removing
# it from any one of them leaves the other two, so the substring still
# matches and that assertion cannot fail for this defect. It looked like
# coverage and was not.
#
# The tbody is the one that matters most. It loads on `ti-show`, so without
# the include, opening the panel renders an unfiltered table underneath a
# control that reads "Score >= 75", while a later change or Refresh does
# send the threshold. The panel would agree with its own control only after
# the reader touched it.
#
# Asserted per element rather than per file, so it fails whichever of the
# three loses the attribute, and so a fourth requester added later has to
# carry the threshold as well.
# ---------------------------------------------------------------------------


def test_every_ioc_feed_request_on_the_page_sends_the_threshold():
    page = _page()
    requesters = re.findall(
        r'<[a-z][a-z0-9]*[^>]*hx-get="/ui/threat-intel/ioc-feed"[^>]*>', page)
    assert len(requesters) == 3, (
        "expected the select, the Refresh button and the #ioc-body tbody; "
        f"found {len(requesters)}. A new requester needs the threshold too."
    )
    for tag in requesters:
        assert 'hx-include="#ti-ioc-min-score"' in flat(tag), (
            "this element asks for the feed without sending the threshold, "
            f"so its render ignores the control: {flat(tag)[:200]}"
        )


def test_the_feed_body_loads_on_show_rather_than_on_page_load():
    """The reason the tbody's include is load-bearing. It fires on `ti-show`,
    which is the panel opening, so its request is the first render the reader
    sees and the one most likely to disagree with the control."""
    page = _page()
    body = page[page.index('<tbody id="ioc-body"'):]
    body = body[:body.index(">") + 1]
    assert 'hx-trigger="ti-show"' in flat(body)
    assert 'hx-include="#ti-ioc-min-score"' in flat(body)
