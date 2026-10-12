"""The /canaries grid fragment: the replacement for three innerHTML writes.

canaries.html fetched /api/canaries, /api/canaries/stats and
/api/canaries/hits in parallel and built the summary tiles, the
planted-canary table and the recent-hits list from JavaScript string
concatenation, with a hand-rolled `esc()` and a `toLocaleString()`
formatter.

A canary is a deception asset, so the figures on this page are security
claims, and most of these tests exist because the JavaScript's `||` made
three different claims look identical:

  * a canary that has fired zero times in its life,
  * zero hits inside the 24-hour window, which says nothing about its life,
  * a count ION could not read at all.

The dev database has no canaries, so an empty render would prove nothing
about the table or the hit log. Every case below renders the fragment
directly with fixture data, and each is one the old JavaScript either got
right and must keep, or got wrong.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

import pytest

from ion.models.canary import CanaryStatus, CanaryType
from ion.web.templating import make_templates
from ion.web.ui import canaries as page
from ion.web.ui.canaries import (
    HIT_FIRED,
    HIT_NEVER,
    HIT_UNREADABLE,
    HITS_LIMIT,
    canary_rows,
    hit_rows,
    hit_state,
    stat_views,
)

FRAGMENT = "_fragments/canaries.html"

PAGE_TEMPLATE = (
    Path(page.__file__).resolve().parents[1] / "templates" / "canaries.html"
)

STATS = {"total": 3, "active": 2, "burned": 1, "fired": 1, "hits_24h": 0}


def _canary(**over: Any) -> dict:
    """One row in the shape Canary.to_dict() returns."""
    base = {
        "id": 7,
        "name": "HR salary spreadsheet decoy",
        "canary_type": "aws_key",
        "value": r"C:\HR\Salaries_2026.xlsx",
        "status": "active",
        "location": "DC01 file share",
        "tags": ["hr"],
        "high_confidence": True,
        "hit_count": 0,
        "last_hit_at": None,
    }
    base.update(over)
    return base


def render(
    canaries: list[dict] | None = None,
    stats: dict | None = None,
    # () rather than None, so a case about the table gets an empty hit log
    # and has to ask for the unreadable one explicitly.
    hits: list[dict] | None = (),
    stats_failed: bool = False,
) -> str:
    """The fragment, rendered the way the route renders it.

    `canaries=None` and `hits=None` are the unreadable states, which is the
    route's own contract: None is a read that failed and [] is a read that
    found nothing.
    """
    source = canaries or []
    env = make_templates().env
    return env.get_template(FRAGMENT).render(
        rows=None if canaries is None else canary_rows(source),
        tiles=stat_views(stats),
        stats_failed=stats_failed,
        hits=None if hits is None else hit_rows(hits, source),
        hits_limit=HITS_LIMIT,
        S_NEVER=HIT_NEVER,
        S_FIRED=HIT_FIRED,
        S_UNREADABLE=HIT_UNREADABLE,
    )


def page_source() -> str:
    return PAGE_TEMPLATE.read_text(encoding="utf-8")


def page_scripts() -> str:
    """Only the page's inline JavaScript, which is what the column measures."""
    return "".join(
        m.group(1) for m in
        re.finditer(r"<script(?![^>]*src=)[^>]*>(.*?)</script>", page_source(),
                    re.S)
    )


def page_code() -> str:
    """The page's JavaScript with its `//` comments removed.

    The comments name what was deleted and why, and a test looking for a
    deleted identifier would otherwise be satisfied by the sentence saying it
    is gone. Only line comments are stripped, which is all this file uses.
    """
    return re.sub(r"(?m)^\s*//.*$", "", page_scripts())


def stat_values(html: str) -> list[str]:
    return re.findall(r'<div class="stat-value[^"]*">([^<]*)</div>', html)


# ---------------------------------------------------------------------------
# Registration and permission
# ---------------------------------------------------------------------------


def _route():
    import ion.web.ui as ui

    for r in ui.router.routes:
        if r.path == "/ui/canaries":
            return r
    raise AssertionError("the canaries fragment route is not mounted")


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

    An unmounted fragment 404s, and a 404 here leaves the page's spinner or,
    with the global handler, an error where a grid should be. Either way the
    page stops reporting what is planted.
    """
    assert _route() is not None


def test_the_fragment_permission_matches_the_json_endpoints():
    """The fragment must never be a softer way in than the API it mirrors.

    Read off the three canary_api routes it reuses rather than restated, so
    tightening or widening those permissions fails here instead of silently
    leaving the fragment behind. This one matters more than most: the table
    carries the literal canary values, which is exactly what an intruder
    needs in order to avoid tripping them.
    """
    from ion.web.canary_api import router as api_router

    mirrored = {"/canaries", "/canaries/stats", "/canaries/hits"}
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
# The three hit readings, which the JavaScript had one rendering for
# ---------------------------------------------------------------------------


def test_hit_state_names_the_three_readings():
    assert hit_state(_canary(hit_count=0, last_hit_at=None)) == HIT_NEVER
    assert hit_state(_canary(hit_count=4)) == HIT_FIRED
    assert hit_state(_canary(hit_count=None)) == HIT_UNREADABLE


def test_a_count_of_zero_with_a_timestamp_is_not_reported_as_never():
    """The two fields disagree, so the row shows the timestamp rather than
    asserting the decoy was never touched."""
    assert hit_state(_canary(hit_count=0, last_hit_at="2026-10-11T22:14:00")) \
        == HIT_FIRED


def test_a_canary_that_never_fired_says_so():
    """The JavaScript printed "-" here, the same "-" it printed for a canary
    that had fired but recorded no timestamp. "Never fired" is a claim about
    the asset and is worth making when it is true."""
    html = render([_canary(hit_count=0, last_hit_at=None)], STATS)
    assert "Never fired" in html
    assert "Unknown" not in html


def test_an_unreadable_hit_count_says_unknown_rather_than_zero():
    """`${ca.hit_count||0}` printed 0 for a count it never read, which on a
    deception asset is the claim "nothing has touched this decoy".

    Zero is a measurement and None is not, so the two cannot share a
    rendering. The cell says Unknown and no 0 appears in the row.
    """
    html = render([_canary(hit_count=None, last_hit_at=None)], STATS)
    row = html[html.index("<tbody>"):html.index("</tbody>")]
    assert "Unknown" in row
    assert "Never fired" not in row
    assert ">0<" not in row


def test_an_unreadable_hit_count_is_not_rendered_as_a_clean_row():
    """`(ca.hit_count||0) > 0` decided the fired stripe, so an unread count
    got the row styling of a canary known not to have fired. Neither claim is
    available, so the row carries neither."""
    unread = render([_canary(hit_count=None)], STATS)
    assert 'class="fired"' not in unread
    assert "Unknown" in unread

    fired = render([_canary(hit_count=2, last_hit_at="2026-10-11T22:14:00")],
                   STATS)
    assert 'class="fired"' in fired, "the positive control: a fired row is marked"


def test_a_fired_canary_with_no_timestamp_says_unknown_not_never():
    """Hits are on record, so the missing timestamp is a gap in the record.
    The JavaScript's `canFmtTime(null)` returned "-" and lost the
    difference."""
    html = render([_canary(hit_count=3, last_hit_at=None)], STATS)
    assert "Unknown" in html
    assert "Never fired" not in html
    assert ">3<" in html


def test_a_fired_canary_emits_a_time_element_rather_than_a_server_format():
    """`toLocaleString()` was the viewer's clock. A server knows only its
    own, so the macro emits <time> and static/js/local-time.js rewrites the
    text after the swap."""
    html = render([_canary(hit_count=3, last_hit_at="2026-10-11T22:14:00")],
                  STATS)
    assert '<time datetime="2026-10-11T22:14:00"' in html


# ---------------------------------------------------------------------------
# The summary tiles
# ---------------------------------------------------------------------------


def test_zero_in_the_window_is_a_measurement_and_prints_zero():
    """`hits_24h` of 0 means the window was read and held nothing. It prints
    0, and the tile says what that zero covers, because "no hits in 24 hours"
    is not "no canary has ever fired"."""
    html = render([_canary()], STATS)
    assert "0" in stat_values(html)
    assert "empty window" in html
    assert "Unknown" not in stat_values(html)


def test_stat_views_measures_zero_but_not_none():
    """`is not none`, never truthiness. The whole tile row is figures whose
    interesting value is 0."""
    measured = {t["label"]: t["measured"] for t in stat_views(STATS)}
    assert measured["Hits (24h)"] is True
    assert all(t["measured"] is False for t in stat_views(None))
    assert all(t["measured"] is False
               for t in stat_views({"total": None, "hits_24h": None}))


def test_an_unread_summary_says_unknown_and_prints_no_figure():
    """`${stats.total||0}` printed a confident 0 for a figure the page never
    obtained. The tiles say Unknown and the table below is still rendered,
    because the two reads are separate."""
    html = render([_canary()], stats=None, stats_failed=True)
    assert stat_values(html) == ["Unknown"] * 5
    assert "This is not zero." in html
    assert "Planted Canaries (1)" in html, "a failed summary keeps the table"


# ---------------------------------------------------------------------------
# The hit log, which the JavaScript rendered only when it was non-empty
# ---------------------------------------------------------------------------


def test_an_empty_hit_log_says_so_rather_than_rendering_nothing():
    """`if (hits.length)` emitted the card only when there were hits, so an
    empty log and an unread one both showed nothing at all, and nothing at
    all reads as "no canary has fired"."""
    html = render([_canary()], STATS, hits=[])
    assert "No canary hits recorded." in html
    assert "could not be read" not in html


def test_an_unread_hit_log_is_not_an_empty_one():
    html = render([_canary()], STATS, hits=None)
    assert "could not be read" in html
    assert "No canary hits recorded." not in html
    assert "Planted Canaries (1)" in html, "a failed hit log keeps the table"


def test_a_full_hit_page_says_it_may_be_truncated():
    """The count in the heading was `hits.length`, which at the limit reads
    as "20 hits exist" when it means "the most recent 20"."""
    hits = [{"canary_id": 7, "detected_at": None, "snippet": None}] * HITS_LIMIT
    html = render([_canary()], STATS, hits=hits)
    assert f"most recent {HITS_LIMIT}, there may be more" in html
    assert f"Recent Hits ({HITS_LIMIT})" not in html


def test_a_hit_naming_a_canary_that_is_gone_still_renders():
    """Dropping the row would remove evidence that something fired."""
    rows = hit_rows([{"canary_id": 99, "detected_at": None, "snippet": None}],
                    [_canary(id=7)])
    assert rows[0]["name"] == "Canary #99"


def test_a_hit_renders_its_snippet_in_the_class_the_stylesheet_caps():
    html = render([_canary()], STATS,
                  hits=[{"canary_id": 7, "detected_at": "2026-10-11T22:14:00",
                         "snippet": "svc_backup_old logged on from 10.1.1.9"}])
    assert "can-hit-snippet" in html
    assert "svc_backup_old logged on from 10.1.1.9" in html


# ---------------------------------------------------------------------------
# A failed registry read
# ---------------------------------------------------------------------------


def test_a_failed_registry_read_says_so_and_prints_no_figures():
    """"Nothing planted" and "we could not look" lead to opposite actions,
    and on this page the second one also means ION cannot say whether a decoy
    was touched. So the failure branch prints no table and no tile."""
    html = render(None, stats=None, hits=None, stats_failed=True)
    assert "could not be read" in html
    assert "unknown rather than zero" in html
    assert "No canaries planted yet" not in html
    assert "Planted Canaries" not in html
    assert stat_values(html) == []


class _BrokenSession:
    """A session whose every query raises, which is what a dropped database
    connection looks like from inside the route."""

    def execute(self, *a: Any, **k: Any):
        raise RuntimeError("database is gone")


def _request():
    from starlette.requests import Request

    return Request({
        "type": "http", "method": "GET", "path": "/ui/canaries",
        "headers": [], "query_string": b"", "root_path": "",
    })


def test_the_route_renders_the_failure_branch_when_the_registry_read_raises():
    body = page.canaries_fragment(
        _request(), session=_BrokenSession(),
    ).body.decode("utf-8")
    assert "could not be read" in body
    assert "Planted Canaries" not in body
    assert "stat-value" not in body


def test_a_failed_read_is_logged_with_its_traceback(caplog):
    """The fragment answers 200 with honest wording, so the exception is the
    only record that anything broke. Logged with `logger.exception`, or a
    database that has stopped answering looks to the operator like a page
    saying "could not be read" for no reason anyone can find."""
    with caplog.at_level(logging.ERROR, logger="ion.web.ui.canaries"):
        page.canaries_fragment(_request(), session=_BrokenSession())
    records = [r for r in caplog.records if r.name == "ion.web.ui.canaries"]
    assert records, "the failure was swallowed"
    assert all(r.exc_info for r in records), "logged without a traceback"


def test_the_route_keeps_the_table_when_only_the_stats_read_raises(monkeypatch):
    """Promise.all made one failing fetch fatal to all three regions: a
    failing /stats left the page with a red line and no table, so an analyst
    lost the list of what is planted over a summary figure."""
    def boom(*a: Any, **k: Any):
        raise RuntimeError("stats unavailable")

    monkeypatch.setattr(page.canary_service, "list_canaries",
                        lambda *a, **k: [_canary()])
    monkeypatch.setattr(page.canary_service, "stats", boom)
    monkeypatch.setattr(page.canary_service, "list_hits", lambda *a, **k: [])

    body = page.canaries_fragment(_request(), session=None).body.decode("utf-8")
    assert "Planted Canaries (1)" in body
    assert stat_values(body) == ["Unknown"] * 5
    assert "could not be read" in body


def test_the_route_keeps_the_table_when_only_the_hits_read_raises(monkeypatch):
    def boom(*a: Any, **k: Any):
        raise RuntimeError("hit log unavailable")

    monkeypatch.setattr(page.canary_service, "list_canaries",
                        lambda *a, **k: [_canary()])
    monkeypatch.setattr(page.canary_service, "stats", lambda *a, **k: STATS)
    monkeypatch.setattr(page.canary_service, "list_hits", boom)

    body = page.canaries_fragment(_request(), session=None).body.decode("utf-8")
    assert "Planted Canaries (1)" in body
    assert "No canary hits recorded." not in body
    assert "could not be read" in body


def test_the_route_asks_for_the_hit_window_the_page_showed(monkeypatch):
    """`?limit=20` was in the JavaScript. If the fragment asked for more, the
    heading's truncation note would be wrong about what it is showing."""
    seen: dict = {}

    def record(session, limit=None, **k: Any):
        seen["limit"] = limit
        return []

    monkeypatch.setattr(page.canary_service, "list_canaries",
                        lambda *a, **k: [])
    monkeypatch.setattr(page.canary_service, "stats", lambda *a, **k: STATS)
    monkeypatch.setattr(page.canary_service, "list_hits", record)

    page.canaries_fragment(_request(), session=None)
    assert seen["limit"] == HITS_LIMIT


# ---------------------------------------------------------------------------
# Escaping, enums, and the styling hooks the stylesheet targets
# ---------------------------------------------------------------------------


def test_jinja_escapes_what_the_hand_rolled_esc_used_to():
    """The canary value is attacker-adjacent by construction: it is the
    string ION searches alert text for, so it can be anything. It was
    interpolated twice, into the cell and into the title attribute."""
    html = render([_canary(name="<script>alert(1)</script>",
                           value='"><script>alert(2)</script>')], STATS)
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
    assert 'title="&#34;&gt;&lt;script&gt;' in html


def test_a_status_from_the_orm_renders_its_value_not_its_repr():
    """The status column is a String today, but it is written from
    CanaryStatus members, and `str(CanaryStatus.BURNED)` on Python 3.12 is
    "CanaryStatus.BURNED". That would print the class name into the pill and
    miss the badge lookup, which the JavaScript got right for free because it
    read JSON."""
    html = render([_canary(status=CanaryStatus.BURNED,
                           canary_type=CanaryType.AWS_KEY)], STATS)
    assert "CanaryStatus" not in html
    assert "CanaryType" not in html
    assert ">burned<" in html
    assert "badge-error" in html, "the badge lookup needs the plain value"
    assert "aws key" in html


def test_an_unknown_status_gets_a_pill_rather_than_no_class():
    row = canary_rows([_canary(status="quarantined")])[0]
    assert row["badge"] == "badge-ghost"


def test_the_rows_keep_the_classes_the_stylesheet_targets():
    """frontend/ion-pages.css styles `#can-content tr.fired`, `.can-value`
    and the dimmed `.badge.inactive`. The conversion moves the markup, so
    those hooks have to arrive with it or the page silently loses the
    styling."""
    html = render([_canary(status="inactive", hit_count=1,
                           last_hit_at="2026-10-11T22:14:00")], STATS)
    assert 'class="fired"' in html
    assert 'class="can-value"' in html
    assert "badge badge-ghost inactive" in html


def test_canary_rows_does_not_mutate_the_payload():
    """The dicts are Canary.to_dict(), the JSON endpoint's own shape, so the
    display fields must land on a copy."""
    source = _canary()
    rows = canary_rows([source])
    assert rows[0]["hit_state"] == HIT_NEVER
    assert "hit_state" not in source
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
    assert 'hx-get="/ui/canaries"' in page_source()
    assert 'hx-trigger="load' in page_source()
    code = page_code()
    assert "canRender" not in code
    assert "canCache" not in code
    assert "canRefresh" not in code


def test_the_page_formats_no_timestamp_and_escapes_nothing_by_hand():
    code = page_code()
    assert "toLocaleString" not in code
    assert "canEsc" not in code


def test_the_controls_stay_outside_the_swap_target():
    """A Refresh inside the fragment is removed by any render that omits it,
    so a failed read would take away the control that retries it."""
    src = page_source()
    slot = src[src.index('<div id="can-content"'):]
    for control in ('id="can-scan"', 'id="can-refresh"',
                    'data-click-action="canNewCanary"'):
        assert control in src
        assert control not in slot, f"{control} is inside the swap target"


def test_refresh_and_a_write_reload_through_the_one_request():
    """Refresh, a save, a delete and a scan all mean "reload the grid", and
    there is one definition of that: the hx-get on the slot."""
    src = page_source()
    assert "click from:#can-refresh" in src
    assert "canaries:changed from:body" in src
    assert "canaries:changed" in page_code()


def test_the_page_writes_no_htmx_error_handler_of_its_own():
    """static/js/htmx-errors.js is the one definition of what a failed
    fragment request means. A per-page listener is one copy per page of a
    decision about an expired session."""
    code = page_code()
    assert "htmx:responseError" not in code
    assert "htmx:afterRequest" not in code


@pytest.mark.parametrize("template", ["page", "fragment"])
def test_no_button_hands_canopenform_an_event_as_a_canary(template):
    """The delegated dispatcher calls an action with (event, dataset) when
    there is no data-args, and canOpenForm read its first argument as the
    canary to edit. A MouseEvent is truthy, so "+ New Canary" opened the form
    titled "Edit Canary" with "undefined" in every field and in the hidden
    id, and saving sent PATCH /api/canaries/undefined."""
    if template == "page":
        src = page_source()
        assert "function canNewCanary()" in src
    else:
        src = (PAGE_TEMPLATE.parent / "_fragments" / "canaries.html").read_text(
            encoding="utf-8"
        )
    assert 'data-click-action="canOpenForm"' not in src
    assert 'data-click-action="canNewCanary"' in src
