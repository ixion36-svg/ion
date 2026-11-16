"""The /log-sources body fragment: the replacement for six innerHTML writes.

log_sources.html fetched /api/log-sources, then /api/log-sources/health, and
built the Elasticsearch banner, six summary tiles and the per-source cards
from JavaScript string concatenation, with a hand-rolled `lsEsc()` and an
`lsFmtTime()` that turned a timestamp into "3h ago".

The page answers one question, "is telemetry arriving", so almost every test
here exists because the JavaScript gave three different silences one
rendering:

  * a source that has never reported anything, which is a misconfiguration,
  * a source that reported zero events in the window, which may be normal,
  * a source whose status ION could not read, which is a monitoring gap.

`lsFmtTime(null)` printed the word "never" for the first and the third,
`_check_source`'s error path hands the second's rendering a hard-coded
`event_count_24h: 0`, and `${summary.healthy_pct||0}%` printed a confident
"0%" for the `check_all` branch that returns no counts at all.

The dev database has no log sources, so an empty render would prove nothing
about the cards or the tiles. Every case below either renders the fragment
with fixture data or calls the route with its reads stubbed, and each is one
the old JavaScript either got right and must keep, or got wrong.
"""
from __future__ import annotations

import asyncio
import logging
import re
from pathlib import Path
from typing import Any

import pytest

from ion.models.log_source import LogSourceCategory
from ion.web.templating import make_templates
from ion.web.ui import log_sources as page
from ion.web.ui.log_sources import (
    REPORT_ACTIVE,
    REPORT_NEVER,
    REPORT_QUIET,
    REPORT_UNREADABLE,
    report_state,
    source_rows,
    stat_views,
)

FRAGMENT = "_fragments/log_sources.html"

PAGE_TEMPLATE = (
    Path(page.__file__).resolve().parents[1] / "templates" / "log_sources.html"
)

#: What log_source_service._summarize really returns, which is the only
#: shape in which every tile is measured.
SUMMARY = {
    "total": 4, "healthy_pct": 75, "healthy_count": 2, "stale_count": 1,
    "silent_count": 1, "never_count": 0, "error_count": 0,
}

#: What check_all returns when no source is enabled. Five of the six tile
#: keys are simply absent, and the JavaScript rendered them as six zeros
#: including "Healthy 0%".
SUMMARY_NOT_COMPUTED = {"total": 0}


def _source(**over: Any) -> dict:
    """One entry in the shape log_source_service.check_all returns."""
    base = {
        "id": 3,
        "name": "Sysmon (Windows endpoints)",
        "status": "healthy",
        "last_event_at": "2026-10-12T09:14:00+00:00",
        "total_events": 91204,
        "event_count_24h": 4120,
        "expected_interval_minutes": 15,
        "criticality": "high",
        "category": "endpoint",
        "owner": "Platform team",
    }
    base.update(over)
    return base


def render(
    sources: list[dict] | None = (),
    summary: dict | None = None,
    registry_count: int | None = 1,
    es_configured: bool | None = True,
    none_enabled: bool = False,
) -> str:
    """The fragment, rendered the way the route renders it.

    `sources=None` is the unreadable health check and `registry_count=None`
    the unreadable registry, which is the route's own contract: None is a
    read that did not complete, and a list is one that did.
    """
    env = make_templates().env
    return env.get_template(FRAGMENT).render(
        registry_count=registry_count,
        rows=None if sources is None else source_rows(list(sources)),
        tiles=stat_views(summary),
        es_configured=es_configured,
        none_enabled=none_enabled,
        S_NEVER=REPORT_NEVER,
        S_QUIET=REPORT_QUIET,
        S_UNREADABLE=REPORT_UNREADABLE,
        S_ACTIVE=REPORT_ACTIVE,
    )


def flat(html: str) -> str:
    """The markup with its whitespace collapsed.

    The template wraps its sentences, so a prose assertion against the raw
    string matches only by accident. One earlier conversion wrote three such
    assertions and all three were vacuous.
    """
    return re.sub(r"\s+", " ", html)


def page_source() -> str:
    return PAGE_TEMPLATE.read_text(encoding="utf-8")


def fragment_source() -> str:
    return (PAGE_TEMPLATE.parent / "_fragments" / "log_sources.html").read_text(
        encoding="utf-8"
    )


def page_scripts() -> str:
    """Only the page's inline JavaScript, which is what the column measures."""
    return "".join(
        m.group(1) for m in
        re.finditer(r"<script(?![^>]*src=)[^>]*>(.*?)</script>", page_source(),
                    re.S)
    )


def page_code() -> str:
    """The page's JavaScript with its `//` comments removed.

    The comments name what was deleted and why, so a test looking for a
    deleted identifier would otherwise be satisfied by the sentence saying
    it is gone.
    """
    return re.sub(r"(?m)^\s*//.*$", "", page_scripts())


def stat_values(html: str) -> list[str]:
    return re.findall(r'<div class="stat-value[^"]*">([^<]*)</div>', html)


def card(html: str) -> str:
    """The first source card, so a row assertion cannot be satisfied by the
    banner or a tile note elsewhere in the fragment."""
    start = html.index("ls-card")
    return html[start:]


# ---------------------------------------------------------------------------
# Registration and permission
# ---------------------------------------------------------------------------


def _route():
    import ion.web.ui as ui

    for r in ui.router.routes:
        if r.path == "/ui/log-sources":
            return r
    raise AssertionError("the log_sources fragment route is not mounted")


def _dependency_calls(route) -> list:
    out, stack = [], list(route.dependant.dependencies)
    while stack:
        dep = stack.pop()
        if dep.call is not None:
            out.append(dep.call)
        stack.extend(dep.dependencies)
    return out


def _required_permissions(route) -> set[str]:
    """The permission strings closed over by require_permission dependencies."""
    found = set()
    for fn in _dependency_calls(route):
        if not getattr(fn, "__qualname__", "").startswith("require_permission."):
            continue
        cells = dict(zip(fn.__code__.co_freevars,
                         (c.cell_contents for c in (fn.__closure__ or ()))))
        name = cells.get("permission_name")
        if name:
            found.add(name)
    return found


def test_the_module_exposes_a_mounted_router():
    """Discovery means nothing announces itself, so check it is really there.

    An unmounted fragment 404s, and on this page that leaves the spinner or
    an error where the ingestion health of the whole estate should be.
    """
    assert _route() is not None


def test_the_fragment_permission_matches_the_json_endpoints():
    """The fragment must never be a softer way in than the API it mirrors.

    Read off the two log_source_api routes it reuses rather than restated,
    so tightening or widening those permissions fails here instead of
    quietly leaving the fragment behind.
    """
    from ion.web.log_source_api import router as api_router

    mirrored = {"/log-sources", "/log-sources/health"}
    api_perms = set()
    for route in api_router.routes:
        if route.path in mirrored and "GET" in route.methods:
            api_perms |= _required_permissions(route)

    assert api_perms == {"alert:read"}, api_perms
    assert _required_permissions(_route()) == api_perms


def test_the_fragment_does_not_use_a_redirecting_page_dependency():
    """require_page_permission redirects to /login, and htmx would swap that
    login form into the middle of the dashboard."""
    for call in _dependency_calls(_route()):
        name = getattr(call, "__qualname__", "")
        assert "require_page_permission" not in name
        assert "require_page_auth" not in name


# ---------------------------------------------------------------------------
# The three silences, which the JavaScript had one rendering for
# ---------------------------------------------------------------------------


def test_report_state_names_the_four_readings():
    assert report_state(_source()) == REPORT_ACTIVE
    assert report_state(_source(status="never", last_event_at=None,
                                event_count_24h=0)) == REPORT_NEVER
    assert report_state(_source(status="stale",
                                event_count_24h=0)) == REPORT_QUIET
    assert report_state(_source(status="error",
                                event_count_24h=0)) == REPORT_UNREADABLE


def test_an_error_status_is_unreadable_rather_than_a_measured_zero():
    """log_source_service._check_source returns `event_count_24h: 0` on its
    error path, a hard zero for a window it never queried. Reading the count
    before the status is how a failed Elasticsearch query becomes the
    sentence "zero events in the last 24 hours"."""
    assert report_state(_source(status="error", last_event_at=None,
                                event_count_24h=0)) == REPORT_UNREADABLE


def test_a_count_of_none_is_unreadable_rather_than_zero():
    """The cached branch of check_all copies `last_event_count` straight out
    of the row, where NULL means no check has ever recorded a count. `is
    None`, never truthiness, because 0 there means a check recorded zero."""
    assert report_state(_source(event_count_24h=None)) == REPORT_UNREADABLE
    assert report_state(_source(status=None)) == REPORT_UNREADABLE


def test_a_quiet_window_is_not_a_source_that_never_reported():
    """A source with a recorded last event and nothing in the window has
    reported before, so it is quiet rather than unconfigured. For a
    quarterly audit feed an empty 24-hour window is the expected reading."""
    assert report_state(_source(status="silent", event_count_24h=0,
                                last_event_at="2026-09-01T00:00:00+00:00")) \
        == REPORT_QUIET


def test_a_count_above_zero_outranks_a_never_status():
    """The two fields disagree, and showing the count makes the disagreement
    visible instead of asserting nothing has ever arrived."""
    assert report_state(_source(status="never", event_count_24h=12)) \
        == REPORT_ACTIVE


def test_a_source_that_never_reported_says_so():
    """The JavaScript printed the word "never" here, the same word it printed
    for a source whose health query failed. "Never reported" is a claim about
    the source and is worth making when it is true."""
    html = card(render([_source(status="never", last_event_at=None,
                                event_count_24h=0)], SUMMARY))
    assert "Never reported" in html
    assert "Unknown" not in html


def test_an_unreadable_source_says_unknown_and_prints_no_zero():
    """Both fields of an errored source are unobtained, so neither gets a
    figure. The JavaScript printed "never" and a hard 0 side by side, which
    together read as a shipper that was configured wrong rather than a check
    that failed."""
    html = card(render([_source(status="error", last_event_at=None,
                                event_count_24h=0)], SUMMARY))
    assert "Unknown" in html
    assert "Never reported" not in html
    assert ">0<" not in html
    assert "This is not zero events." in flat(html)


def test_a_quiet_window_prints_its_zero_and_says_what_it_covers():
    """Zero is a measurement. The window was queried and held nothing, which
    is not the same claim as the source never having reported and not the
    same as the count being unread."""
    html = card(render([_source(status="silent", event_count_24h=0,
                                last_event_at="2026-09-01T00:00:00+00:00")],
                       SUMMARY))
    assert ">0<" in html
    assert "a quiet window may be normal for it" in flat(html)
    assert "Never reported" not in html
    assert "Unknown" not in html


def test_the_three_silences_do_not_share_a_rendering():
    """The one assertion that holds the whole page together: render each of
    the three and check no two produce the same words."""
    never = card(render([_source(status="never", last_event_at=None,
                                 event_count_24h=0)], SUMMARY))
    quiet = card(render([_source(status="silent", event_count_24h=0,
                                 last_event_at="2026-09-01T00:00:00+00:00")],
                        SUMMARY))
    unread = card(render([_source(status="error", last_event_at=None,
                                  event_count_24h=0)], SUMMARY))
    assert never != quiet != unread
    assert "Never reported" in never
    assert "Never reported" not in quiet and "Never reported" not in unread
    assert "Unknown" in unread
    assert "Unknown" not in never and "Unknown" not in quiet


def test_a_reported_timestamp_is_a_time_element_not_a_server_format():
    """`lsFmtTime` computed "3h ago" against whichever clock ran it. A server
    knows only its own, so the macro emits <time> and
    static/js/local-time.js rewrites the text after the swap."""
    html = render([_source(last_event_at="2026-10-12T09:14:00+00:00")],
                  SUMMARY)
    assert '<time datetime="2026-10-12T09:14:00+00:00"' in html


def test_a_reporting_source_with_no_timestamp_is_not_the_epoch():
    """Events are on record for this source, so a missing `last_event_at` is
    a gap in the record. The `ts` macro renders the fallback, never
    1970."""
    html = card(render([_source(event_count_24h=7, last_event_at=None)],
                       SUMMARY))
    assert "No timestamp recorded" in html
    assert "1970" not in html
    assert "Never reported" not in html


def test_a_stale_timestamp_is_rendered_as_a_measurement():
    """A stale source has reported, and when it did is the most useful thing
    on the card. It gets the real <time>, and the pill carries the
    staleness."""
    html = card(render([_source(status="stale", event_count_24h=2,
                                last_event_at="2026-10-11T02:00:00+00:00")],
                       SUMMARY))
    assert '<time datetime="2026-10-11T02:00:00+00:00"' in html
    assert ">stale<" in html


# ---------------------------------------------------------------------------
# The summary tiles
# ---------------------------------------------------------------------------


def test_stat_views_measures_zero_but_not_none():
    """`is not none`, never truthiness. Zero silent sources is the all-clear
    this page exists to show."""
    measured = {t["label"]: t["measured"] for t in stat_views(SUMMARY)}
    assert measured["Silent"] is True
    assert measured["Never Seen"] is True, "a measured zero is measured"
    assert all(t["measured"] is False for t in stat_views(None))
    assert all(t["measured"] is False
               for t in stat_views({"healthy_pct": None, "silent_count": None}))


def test_a_measured_zero_prints_zero_and_says_what_it_covers():
    html = render([_source()], SUMMARY)
    assert "0" in stat_values(html)
    assert "Zero means every check completed" in flat(html)
    assert "Unknown" not in stat_values(html)


def test_a_summary_with_no_counts_in_it_says_unknown_not_zero_percent():
    """check_all returns `{"total": 0}` when no source is enabled, so five of
    the six keys are absent. `${summary.healthy_pct||0}%` rendered that as a
    confident "0%" beside five more confident zeros."""
    html = render([], SUMMARY_NOT_COMPUTED, none_enabled=True,
                  es_configured=False)
    assert stat_values(html) == ["Unknown"] * 6
    assert "0%" not in html
    assert "This is not zero." in html


# ---------------------------------------------------------------------------
# An empty estate, an unenabled one, and an unreadable one
# ---------------------------------------------------------------------------


def test_an_empty_registry_offers_the_seed_rather_than_claiming_silence():
    html = render(registry_count=0)
    assert "No log sources yet" in html
    assert 'data-click-action="lsSeedDefaults"' in html
    assert "could not be read" not in html
    assert "stat-value" not in html


def test_an_unreadable_registry_is_not_an_empty_one():
    """"Nothing is configured" and "we could not look" lead to opposite
    actions, and the second also means ION cannot say whether anything is
    arriving. So the failure branch prints no card and no tile."""
    html = render(registry_count=None)
    assert "could not be read" in html
    assert "unknown rather than zero" in flat(html)
    assert "No log sources yet" not in html
    assert stat_values(html) == []


def test_an_unreadable_health_check_keeps_the_registry_size():
    """An empty grid would read as "no telemetry is arriving", which is the
    opposite instruction to "we do not know whether it is"."""
    html = render(None, SUMMARY_NOT_COMPUTED, registry_count=8)
    assert "The health check could not be run" in flat(html)
    assert "ION expects 8 sources" in flat(html)
    assert "this is not a report that none of them is sending" in flat(html)
    assert "ls-card" not in html


def test_no_source_enabled_is_not_an_elasticsearch_problem():
    """check_all returns es_configured False on the no-enabled-sources path
    without ever reading the ES config, so the JavaScript told an operator
    to go and configure Elasticsearch when every source was switched off."""
    html = flat(render([], SUMMARY_NOT_COMPUTED, registry_count=5,
                       es_configured=False, none_enabled=True))
    assert "No log source is enabled." in html
    assert "5 sources are registered" in html
    assert "it says ION was not asked to look" in html
    assert "Elasticsearch not configured" not in html


def test_a_cached_read_says_the_figures_are_not_live():
    html = flat(render([_source()], SUMMARY, es_configured=False))
    assert "Elasticsearch not configured" in html
    assert "only known to have been healthy when that check ran" in html


def test_a_live_read_shows_no_banner():
    """The positive control. Without it every banner assertion above would
    pass on a fragment that always warns."""
    html = flat(render([_source()], SUMMARY, es_configured=True))
    assert "Elasticsearch not configured" not in html
    assert "No log source is enabled" not in html
    assert "Unknown whether this is a live read" not in html


def test_an_unknown_elasticsearch_state_is_not_reported_as_cached():
    """Three states, not two. A truthiness test folds None into "cached",
    and None is the case where ION does not know which of the two it has."""
    html = flat(render([_source()], SUMMARY, es_configured=None))
    assert "Unknown whether this is a live read" in html
    assert "Elasticsearch not configured" not in html


# ---------------------------------------------------------------------------
# The route, which is what actually selects those states
# ---------------------------------------------------------------------------


class _BrokenSession:
    """A session whose every query raises, which is what a dropped database
    connection looks like from inside the route."""

    def execute(self, *a: Any, **k: Any):
        raise RuntimeError("database is gone")


def _request():
    from starlette.requests import Request

    return Request({
        "type": "http", "method": "GET", "path": "/ui/log-sources",
        "headers": [], "query_string": b"", "root_path": "",
    })


def _call(session: Any = None) -> str:
    """The route, awaited. Rendering the template with `registry_count=None`
    by hand would never prove the route selects that state."""
    response = asyncio.run(page.log_sources_fragment(_request(), session=session))
    return response.body.decode("utf-8")


def _async(value: Any):
    async def stub(*a: Any, **k: Any):
        if isinstance(value, Exception):
            raise value
        return value
    return stub


def test_the_route_renders_the_registry_failure_when_the_list_read_raises():
    body = _call(_BrokenSession())
    assert "could not be read" in body
    assert "ls-card" not in body
    assert "stat-value" not in body


def test_the_route_renders_the_health_failure_when_the_check_raises(monkeypatch):
    """A failure-state test that renders the template with the failure flag
    set never proves the route picks that state, so the reads are stubbed and
    the route is called."""
    monkeypatch.setattr(page.log_source_service, "list_sources",
                        lambda *a, **k: [_source(), _source(id=4)])
    monkeypatch.setattr(page.log_source_service, "check_all",
                        _async(RuntimeError("elasticsearch is gone")))

    body = flat(_call())
    assert "The health check could not be run" in body
    assert "ION expects 2 sources" in body
    assert "ls-card" not in body


def test_the_route_does_not_run_the_health_check_on_an_empty_registry(monkeypatch):
    """The JavaScript's own short circuit. A health query per source against
    an estate ION knows is empty is work with no reading in it."""
    called: list[int] = []

    async def record(*a: Any, **k: Any):
        called.append(1)
        return {"sources": [], "summary": {}, "es_configured": True}

    monkeypatch.setattr(page.log_source_service, "list_sources",
                        lambda *a, **k: [])
    monkeypatch.setattr(page.log_source_service, "check_all", record)

    body = _call()
    assert "No log sources yet" in body
    assert called == []


def test_the_route_reports_an_unenabled_estate_rather_than_an_es_problem(monkeypatch):
    """The exact payload check_all returns on that path, through the route."""
    monkeypatch.setattr(page.log_source_service, "list_sources",
                        lambda *a, **k: [_source(), _source(id=4),
                                         _source(id=5)])
    monkeypatch.setattr(page.log_source_service, "check_all",
                        _async({"sources": [], "summary": {"total": 0},
                                "es_configured": False}))

    body = flat(_call())
    assert "No log source is enabled." in body
    assert "3 sources are registered" in body
    assert "Elasticsearch not configured" not in body
    assert "Nothing was checked" in body


def test_the_route_passes_an_absent_es_flag_through_as_unknown(monkeypatch):
    monkeypatch.setattr(page.log_source_service, "list_sources",
                        lambda *a, **k: [_source()])
    monkeypatch.setattr(page.log_source_service, "check_all",
                        _async({"sources": [_source()], "summary": SUMMARY}))

    body = flat(_call())
    assert "Unknown whether this is a live read" in body
    assert "Elasticsearch not configured" not in body


def test_a_failed_read_is_logged_with_its_traceback(caplog):
    """The fragment answers 200 with honest wording, so the exception is the
    only record that anything broke. Without `logger.exception` a database
    that has stopped answering looks to the operator like a page saying
    "could not be read" for no reason anyone can find."""
    with caplog.at_level(logging.ERROR, logger="ion.web.ui.log_sources"):
        _call(_BrokenSession())
    records = [r for r in caplog.records if r.name == "ion.web.ui.log_sources"]
    assert records, "the failure was swallowed"
    assert all(r.exc_info for r in records), "logged without a traceback"


def test_a_failed_health_check_is_logged_with_its_traceback(monkeypatch, caplog):
    monkeypatch.setattr(page.log_source_service, "list_sources",
                        lambda *a, **k: [_source()])
    monkeypatch.setattr(page.log_source_service, "check_all",
                        _async(RuntimeError("elasticsearch is gone")))
    with caplog.at_level(logging.ERROR, logger="ion.web.ui.log_sources"):
        _call()
    records = [r for r in caplog.records if r.name == "ion.web.ui.log_sources"]
    assert records, "the failure was swallowed"
    assert all(r.exc_info for r in records), "logged without a traceback"


def test_the_route_reuses_the_service_functions_the_json_endpoints_call(monkeypatch):
    """Not a second implementation of either read. Both JSON routes call
    these two functions, so the page and the API cannot disagree about what
    is registered or what is arriving."""
    seen: list[str] = []

    def list_stub(*a: Any, **k: Any):
        seen.append("list_sources")
        return [_source()]

    async def check_stub(*a: Any, **k: Any):
        seen.append("check_all")
        return {"sources": [_source()], "summary": SUMMARY,
                "es_configured": True}

    monkeypatch.setattr(page.log_source_service, "list_sources", list_stub)
    monkeypatch.setattr(page.log_source_service, "check_all", check_stub)

    _call()
    assert seen == ["list_sources", "check_all"]


# ---------------------------------------------------------------------------
# Escaping, enums, sorting and the styling hooks the stylesheet targets
# ---------------------------------------------------------------------------


def test_jinja_escapes_what_the_hand_rolled_esc_used_to():
    """A source name and an owner are free text typed into the new-source
    form, and the category and owner were interpolated straight into the
    card by `lsEsc`."""
    html = render([_source(name="<script>alert(1)</script>",
                           owner='"><script>alert(2)</script>')], SUMMARY)
    assert "<script>alert" not in html
    assert "&lt;script&gt;" in html


def test_a_category_from_the_orm_renders_its_value_not_its_repr():
    """`category` is a String column today, but it is validated against
    LogSourceCategory and written from its members, and
    `str(LogSourceCategory.OS)` on Python 3.12 is "LogSourceCategory.OS".
    The JavaScript got the value for free because it read JSON."""
    html = render([_source(category=LogSourceCategory.OS)], SUMMARY)
    assert "LogSourceCategory" not in html
    assert ">os &middot;" in html or "os &middot;" in html


def test_an_unknown_status_gets_a_pill_rather_than_no_class():
    row = source_rows([_source(status="throttled")])[0]
    assert row["badge"] == "badge-ghost"


def test_the_cards_keep_the_class_the_stylesheet_targets():
    """frontend/ion-pages.css styles `#ls-content .ls-card.healthy` and its
    four siblings, a five-colour left stripe that is the fastest read on the
    page. The conversion moves the markup, so the hook has to arrive with
    it."""
    html = render([_source(status="silent", event_count_24h=0)], SUMMARY)
    assert "ls-card silent" in html
    assert "badge badge-error" in html


def test_the_blind_spots_sort_first():
    """The JavaScript's own order: silent and never-seen before stale,
    errors, and the healthy ones. A page about blind spots that buries them
    on the third screen is not reporting them."""
    rows = source_rows([
        _source(id=1, status="healthy"),
        _source(id=2, status="never", last_event_at=None, event_count_24h=0),
        _source(id=3, status="silent", event_count_24h=0),
        _source(id=4, status="error", event_count_24h=0),
        _source(id=5, status="stale", event_count_24h=1),
    ])
    assert [r["status"] for r in rows] == [
        "silent", "never", "stale", "error", "healthy",
    ]


def test_an_unknown_status_sorts_last_rather_than_among_the_blind_spots():
    rows = source_rows([_source(id=1, status="throttled"),
                        _source(id=2, status="healthy")])
    assert [r["status"] for r in rows] == ["healthy", "throttled"]


def test_a_missing_window_says_unknown_rather_than_zero_minutes():
    """`${s.expected_interval_minutes||0}m` printed "0m", a baseline of zero
    minutes, which would make every source silent by definition."""
    html = card(render([_source(expected_interval_minutes=None)], SUMMARY))
    assert "0m" not in html
    assert "Unknown" in html

    measured = card(render([_source(expected_interval_minutes=15)], SUMMARY))
    assert ">15m<" in measured


def test_source_rows_does_not_mutate_the_payload():
    """The dicts come from check_all, which is also what the JSON endpoint
    returns, so display fields must land on a copy."""
    source = _source()
    rows = source_rows([source])
    assert rows[0]["report"] == REPORT_ACTIVE
    assert "report" not in source
    assert "badge" not in source


# ---------------------------------------------------------------------------
# What is left in the page
# ---------------------------------------------------------------------------


def test_the_page_builds_no_markup_in_javascript():
    """The measurement the redesign's `server` column makes, asserted here so
    the page cannot regress without this file failing."""
    js = page_scripts()
    assert not re.search(r"innerHTML\s*\+?=", js)
    assert "insertAdjacentHTML" not in js
    assert not re.search(r"outerHTML\s*\+?=", js)


def test_the_page_holds_an_htmx_slot_rather_than_a_renderer():
    assert 'hx-get="/ui/log-sources"' in page_source()
    assert 'hx-trigger="load' in page_source()
    code = page_code()
    for gone in ("lsRender", "lsLoad", "lsCache", "lsRefresh"):
        assert gone not in code, f"{gone} is still in the page"


def test_the_page_formats_no_timestamp_and_escapes_nothing_by_hand():
    code = page_code()
    assert "lsEsc" not in code
    assert "lsFmtTime" not in code
    assert "toLocaleString" not in code


def test_the_controls_stay_outside_the_swap_target():
    """A Refresh inside the fragment is removed by any render that omits it,
    so a failed read would take away the control that retries it."""
    src = page_source()
    slot = src[src.index('<div id="ls-content"'):]
    for control in ('id="ls-refresh"', 'data-click-action="lsNewSource"'):
        assert control in src
        assert control not in slot, f"{control} is inside the swap target"


def test_refresh_and_a_write_reload_through_the_one_request():
    """Refresh, a save, a delete and a seed all mean "reload the body", and
    there is one definition of that: the hx-get on #ls-content."""
    src = page_source()
    assert "click from:#ls-refresh" in src
    assert "log-sources:changed from:body" in src
    code = page_code()
    assert "log-sources:changed" in code
    # Every write path goes through it rather than re-rendering by hand.
    assert code.count("lsReload()") >= 3


def test_the_page_writes_no_htmx_error_handler_of_its_own():
    """static/js/htmx-errors.js is the one definition of what a failed
    fragment request means. A per-page listener is one copy per page of a
    decision about an expired session."""
    code = page_code()
    assert "htmx:responseError" not in code
    assert "htmx:afterRequest" not in code
    assert "htmx:beforeSwap" not in code


@pytest.mark.parametrize("template", ["page", "fragment"])
def test_no_htmx_feature_that_compiles_a_string(template):
    """ION serves `script-src 'self' 'nonce-...'` with no `unsafe-eval`, so
    anything htmx hands to `Function()` throws and the feature silently does
    nothing. One converted page shipped a dead Enter key this way."""
    src = page_source() if template == "page" else fragment_source()
    assert "hx-on" not in src
    assert "js:" not in src
    assert not re.search(r"hx-trigger=\"[^\"]*\[", src)
    assert not re.search(r"hx-vals=\"\s*js:", src)


@pytest.mark.parametrize("template", ["page", "fragment"])
def test_no_button_hands_lsopenform_an_event_as_a_source(template):
    """The delegated dispatcher calls an action with (event, dataset) when
    there is no data-args, and lsOpenForm read its first argument as the
    source to edit. A MouseEvent is truthy, so "+ New Source" opened the form
    titled "Edit Log Source" with "undefined" in every field and in the
    hidden id, and saving sent PATCH /api/log-sources/undefined."""
    src = page_source() if template == "page" else fragment_source()
    assert 'data-click-action="lsOpenForm"' not in src
    assert 'data-click-action="lsNewSource"' in src
    if template == "page":
        assert "function lsNewSource()" in src
