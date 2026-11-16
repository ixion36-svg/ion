"""The entity timeline fragment.

This page reconstructs what happened to a host, a user or an IOC, so the
two failure modes that matter most are a timeline that reads as empty when
the read failed, and a timestamp presented on a clock it was never on.

Every source feeding this page stores a naive `DateTime` defaulting to the
database's `func.now()`, so the whole timeline is on one clock and the
fragment labels all of it server time. A page that localised some rows and
left others would present two clocks as one sequence.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

import pytest
from starlette.requests import Request

from ion.web.templating import make_templates
from ion.web.ui.entity_timeline import (
    SEVERITY_CLASS,
    entity_timeline_fragment,
    event_timestamp,
    parse_sources,
    present_event,
    source_pills,
    visible_meta,
)

FRAGMENT = "_fragments/entity_timeline.html"


def render(**ctx) -> str:
    ctx.setdefault("state", "ok")
    ctx.setdefault("q", "10.0.0.5")
    ctx.setdefault("entity_type", "ip")
    ctx.setdefault("hours", 168)
    ctx.setdefault("active_sources", [])
    ctx.setdefault("events", [])
    ctx.setdefault("pills", [])
    ctx.setdefault("total_events", 0)
    ctx.setdefault("sources_count", 0)
    ctx.setdefault("shown_count", len(ctx["events"]))
    env = make_templates().env
    return env.get_template(FRAGMENT).render(**ctx)


def _event(**over) -> dict:
    base = present_event({
        "source": "case",
        "severity": "high",
        "status": "open",
        "title": "Case CASE-1: Suspicious logon",
        "detail": "Repeated failures from 10.0.0.5",
        "timestamp": "2026-10-05T14:22:31.481920",
        "meta": {"case_number": "CASE-1"},
    })
    base.update(over)
    return base


def _request() -> Request:
    return Request({
        "type": "http",
        "method": "GET",
        "path": "/ui/entity-timeline",
        "headers": [],
        "query_string": b"",
    })


class _ThreatLevel(str, Enum):
    HIGH = "high"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# The four states, which are four different claims
# ---------------------------------------------------------------------------


def test_nothing_searched_yet_invites_a_search():
    html = render(state="prompt")
    assert "Search for any entity" in html
    assert "No events found" not in html


def test_an_unreadable_timeline_is_not_an_empty_one():
    """The single most misleading thing this page could say is that no
    events were found, when the truth is that it could not look."""
    html = render(state="failed", q="10.0.0.5")
    assert "could not be read" in html
    assert "not an empty timeline" in html
    assert "No events found" not in html


def test_a_failed_read_names_what_was_searched():
    """The heading has to hold a value that exists when there is no payload,
    or the error branch reads as a generic failure of the whole page."""
    assert "10.0.0.5" in render(state="failed", q="10.0.0.5")


def test_a_failed_read_renders_no_filters_and_no_timeline():
    html = render(state="failed")
    assert "et-filters" not in html
    assert "et-timeline" not in html


def test_an_entity_with_no_events_says_so_and_keeps_its_header():
    html = render(state="ok", events=[], pills=[], total_events=0)
    assert "No events found for this entity in the selected time window" in html
    assert "et-entity-value" in html


# ---------------------------------------------------------------------------
# Counts. Zero is a measurement
# ---------------------------------------------------------------------------


def test_zero_events_is_rendered_as_zero():
    """`{% if total_events %}` renders a searched-and-found-nothing entity
    with no count at all, which reads as a broken header rather than a
    result."""
    assert "0 events found" in render(total_events=0, sources_count=0)


def test_a_missing_count_says_it_is_unavailable_rather_than_zero():
    html = render(total_events=None, sources_count=None)
    assert "Event count unavailable" in html
    assert "0 events found" not in html


def test_zero_sources_is_rendered_as_zero():
    assert "across 0 sources" in render(total_events=0, sources_count=0)


@pytest.mark.parametrize("n,expected", [(1, "1 event found"), (2, "2 events found")])
def test_the_event_count_is_pluralised(n, expected):
    assert expected in render(total_events=n)


@pytest.mark.parametrize("n,expected", [(1, "across 1 source"), (3, "across 3 sources")])
def test_the_source_count_is_pluralised(n, expected):
    assert expected in render(sources_count=n)


def test_a_capped_result_says_how_many_it_is_showing():
    """The service counts every match and returns at most 200, so the header
    can claim more events than the rows below it. The page used to show 200
    rows under a header claiming 340 and explain nothing."""
    html = render(events=[_event()], pills=[{"source": "case", "count": 1,
                                             "active": False, "url": "/x"}],
                  total_events=340, shown_count=200)
    assert "Showing the 200 most recent of 340 matching events" in html


def test_an_uncapped_result_adds_no_note():
    html = render(events=[_event()], pills=[{"source": "case", "count": 1,
                                             "active": False, "url": "/x"}],
                  total_events=1, shown_count=1)
    assert "most recent of" not in html


# ---------------------------------------------------------------------------
# Timestamps
# ---------------------------------------------------------------------------


def test_the_timestamp_goes_through_the_time_macro():
    """A server-formatted timestamp would show every viewer outside the
    server's timezone a time that looks authoritative and is wrong."""
    html = render(events=[_event()], pills=[{"source": "case", "count": 1,
                                             "active": False, "url": "/x"}])
    assert 'datetime="2026-10-05T14:22:31.481920"' in html
    assert "data-ts-format" in html


def test_a_naive_timestamp_is_not_localised_and_says_whose_clock_it_is():
    """Every column feeding this page is naive. Localising a zoneless value
    makes the browser read the digits as the viewer's own clock and convert
    out of a zone the value was never in."""
    html = render(events=[_event()], pills=[{"source": "case", "count": 1,
                                             "active": False, "url": "/x"}])
    assert 'data-ts-local="no"' in html
    assert "Server time" in html


def test_an_aware_timestamp_is_localised():
    """Not reachable from today's columns, and asserted anyway: the day a
    source starts storing an offset, this page must put it on the viewer's
    clock rather than silently keep labelling it server time."""
    event = _event(timestamp=event_timestamp("2026-10-05T14:22:31+00:00"))
    html = render(events=[event], pills=[{"source": "case", "count": 1,
                                          "active": False, "url": "/x"}])
    assert 'data-ts-local="yes"' in html


def test_a_missing_timestamp_renders_the_fallback_not_the_epoch():
    event = _event(timestamp=None)
    html = render(events=[event], pills=[{"source": "case", "count": 1,
                                          "active": False, "url": "/x"}])
    assert "No timestamp recorded" in html
    assert "1970" not in html


@pytest.mark.parametrize("raw,aware", [
    ("2026-10-05T14:22:31.481920", False),
    ("2026-10-05T14:22:31+00:00", True),
    ("2026-10-05T14:22:31+10:00", True),
])
def test_parsing_preserves_whether_the_value_carries_a_zone(raw, aware):
    """The parse exists so the macro can format the instant in ION's house
    style. It must not invent a zone, because whether one is present is the
    whole basis for localising or not."""
    parsed = event_timestamp(raw)
    assert isinstance(parsed, datetime)
    assert (parsed.tzinfo is not None) is aware


@pytest.mark.parametrize("raw", [None, ""])
def test_an_absent_timestamp_parses_to_none(raw):
    assert event_timestamp(raw) is None


def test_an_unparseable_timestamp_is_kept_as_itself():
    """A timestamp we cannot read is still evidence of when something
    happened, so it is shown rather than blanked."""
    assert event_timestamp("last Tuesday") == "last Tuesday"


def test_a_real_datetime_passes_through_untouched():
    when = datetime(2026, 10, 5, 14, 22, tzinfo=timezone.utc)
    assert event_timestamp(when) is when


# ---------------------------------------------------------------------------
# SQLEnum columns
# ---------------------------------------------------------------------------


def test_an_enum_severity_renders_its_value_not_its_repr():
    """Observable.threat_level is SQLEnum(ThreatLevel) and the service
    passes the ORM value straight through. The JSON endpoint got the string
    for free; a template renders `_ThreatLevel.HIGH` instead, and the colour
    map still matches because value equality holds, so only the visible text
    is wrong."""
    event = present_event({"source": "observable", "severity": _ThreatLevel.HIGH,
                           "title": "Observable: 10.0.0.5", "timestamp": None,
                           "meta": {}})
    assert event["severity"] == "high"
    assert event["severity_class"] == "sev-high"
    html = render(events=[event], pills=[{"source": "observable", "count": 1,
                                          "active": False, "url": "/x"}])
    assert "_ThreatLevel" not in html
    assert ">high<" in html


def test_an_enum_meta_value_renders_its_value_not_its_repr():
    assert visible_meta({"threat_level": _ThreatLevel.HIGH}) == [
        ("threat_level", "high")
    ]


@pytest.mark.parametrize("severity", ["low", "info", "unknown", None])
def test_only_the_three_mapped_severities_get_a_badge(severity):
    """Ported from the page's inline ternary. Which of this page's four
    severity vocabularies deserves a pill is a visual decision, not a
    port."""
    event = present_event({"source": "audit", "severity": severity,
                           "title": "t", "timestamp": None, "meta": {}})
    assert event["severity_class"] is None
    html = render(events=[event], pills=[{"source": "audit", "count": 1,
                                          "active": False, "url": "/x"}])
    assert "sev-badge" not in html


def test_the_mapped_severities_are_the_three_the_page_had():
    assert set(SEVERITY_CLASS) == {"critical", "high", "medium"}


# ---------------------------------------------------------------------------
# Meta tags
# ---------------------------------------------------------------------------


def test_a_meta_value_of_zero_survives():
    """`sighting_count: 0` is a measurement. A truthiness filter drops it
    and claims the field was never there. The JavaScript got this right with
    `v != null && v !== ''`."""
    assert visible_meta({"sighting_count": 0}) == [("sighting_count", "0")]


def test_a_false_meta_value_survives():
    assert visible_meta({"is_whitelisted": False}) == [("is_whitelisted", "False")]


@pytest.mark.parametrize("value", [None, ""])
def test_an_absent_meta_value_is_dropped(value):
    assert visible_meta({"assigned_to_id": value}) == []


def test_meta_is_capped_so_a_wide_object_cannot_bury_the_title():
    many = {f"k{i}": i for i in range(1, 12)}
    assert len(visible_meta(many)) == 5


def test_a_non_object_meta_is_not_a_crash():
    assert visible_meta("not an object") == []
    assert visible_meta(None) == []


# ---------------------------------------------------------------------------
# The source filter, which used to hide rows the browser already held
# ---------------------------------------------------------------------------


def test_a_pill_is_rendered_per_source_most_frequent_first():
    pills = source_pills(
        [{"source": "audit"}, {"source": "case"}, {"source": "case"}], []
    )
    assert [p["source"] for p in pills] == ["case", "audit"]
    assert [p["count"] for p in pills] == [2, 1]


def test_an_inactive_pill_adds_itself_and_an_active_pill_removes_itself():
    pills = source_pills([{"source": "case"}, {"source": "audit"}], ["case"])
    by_source = {p["source"]: p for p in pills}
    assert by_source["case"]["active"] is True
    assert by_source["case"]["url"] == "/ui/entity-timeline?sources="
    assert by_source["audit"]["active"] is False
    assert by_source["audit"]["url"] == "/ui/entity-timeline?sources=case,audit"


def test_the_all_pill_survives_a_filter_that_matches_nothing():
    """A filter that can hide every row has to keep the control that clears
    it. Otherwise the only way out of an empty view is a page reload, which
    the user has no reason to believe would help."""
    html = render(events=[], active_sources=["enrichment"], shown_count=4,
                  total_events=4,
                  pills=[{"source": "case", "count": 4, "active": False,
                          "url": "/ui/entity-timeline?sources=enrichment,case"}])
    assert "All (4)" in html
    assert "Clear the filter with All" in html
    assert "et-filters" in html


def test_a_filter_matching_nothing_does_not_claim_the_entity_had_no_events():
    html = render(events=[], active_sources=["enrichment"], shown_count=4,
                  total_events=4,
                  pills=[{"source": "case", "count": 4, "active": False,
                          "url": "/x"}])
    assert "No events found for this entity" not in html


def test_the_all_pill_count_agrees_with_the_pills_beside_it():
    html = render(events=[_event()], shown_count=1, total_events=1,
                  pills=[{"source": "case", "count": 1, "active": False,
                          "url": "/x"}])
    assert "All (1)" in html


def test_the_all_pill_is_active_when_no_filter_is_set():
    html = render(events=[_event()], shown_count=1,
                  pills=[{"source": "case", "count": 1, "active": False,
                          "url": "/x"}])
    assert 'class="et-filter active"' in html


def test_the_pills_send_the_search_controls_with_every_request():
    """A pill that dropped the query would search for nothing, and a pill
    that dropped the window would silently widen what is shown."""
    html = render(events=[_event()], shown_count=1,
                  pills=[{"source": "case", "count": 1, "active": False,
                          "url": "/x"}])
    assert html.count('hx-include="#et-query, #et-type, #et-hours"') == 2


@pytest.mark.parametrize("raw,expected", [
    ("", []),
    (None, []),
    ("case", ["case"]),
    ("case, audit ", ["case", "audit"]),
    ("case,case", ["case"]),
    ("case,,audit", ["case", "audit"]),
])
def test_parsing_the_active_filter(raw, expected):
    assert parse_sources(raw) == expected


# ---------------------------------------------------------------------------
# Escaping, which the page did by hand
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("field", ["title", "detail"])
def test_jinja_escapes_event_content(field):
    event = _event(**{field: "<script>alert(1)</script>"})
    html = render(events=[event], pills=[{"source": "case", "count": 1,
                                          "active": False, "url": "/x"}])
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_jinja_escapes_a_meta_value():
    event = _event(meta=[("note", "<script>alert(1)</script>")])
    html = render(events=[event], pills=[{"source": "case", "count": 1,
                                          "active": False, "url": "/x"}])
    assert "<script>alert(1)</script>" not in html


def test_jinja_escapes_the_searched_value_in_every_state():
    """The entity value is user input echoed back, in the header and in the
    failure branch. The page escaped it with a hand-rolled esc()."""
    for state in ("ok", "failed"):
        html = render(state=state, q="<script>alert(1)</script>")
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;" in html


# ---------------------------------------------------------------------------
# The route
# ---------------------------------------------------------------------------


def test_the_fragment_permission_matches_the_json_endpoint_exactly():
    """A fragment must never be a softer way in than the API it mirrors.
    Read off both routes rather than restated, so a change to either side
    fails here."""
    import ion.web.ui as ui
    from ion.web.entity_timeline_api import router as api_router

    def permission(route):
        found = set()
        stack = list(route.dependant.dependencies)
        while stack:
            dep = stack.pop()
            fn = dep.call
            if getattr(fn, "__qualname__", "").startswith("require_permission."):
                cells = dict(zip(fn.__code__.co_freevars,
                                 (c.cell_contents for c in (fn.__closure__ or ()))))
                found.add(cells.get("permission_name"))
            stack.extend(dep.dependencies)
        return found

    fragment = next(r for r in ui.router.routes if r.path == "/ui/entity-timeline")
    api = next(r for r in api_router.routes if r.path.endswith("/search"))
    assert permission(fragment) == permission(api) == {"alert:read"}


def test_a_blank_query_renders_the_prompt_without_touching_the_database():
    """The shell asks for this fragment on load whether or not anything has
    been searched, so the unsearched case must cost no query. A sentinel
    session is passed: any attempt to use it raises."""
    class _Explodes:
        def __getattr__(self, name):
            raise AssertionError(f"the database was used for a blank query: {name}")

    resp = entity_timeline_fragment(
        request=_request(), q="   ", type="auto", hours=168, sources="",
        session=_Explodes(),
    )
    assert resp.status_code == 200
    assert "Search for any entity" in resp.body.decode()


def test_a_failing_read_returns_a_200_fragment_that_says_so(monkeypatch):
    """Not a 500. htmx does not swap a non-2xx response, so a 500 would
    leave the spinner spinning and say nothing at all."""
    import ion.services.entity_timeline_service as svc

    def boom(*a, **kw):
        raise RuntimeError("elasticsearch is down")

    monkeypatch.setattr(svc, "get_entity_timeline", boom)
    resp = entity_timeline_fragment(
        request=_request(), q="10.0.0.5", type="auto", hours=168, sources="",
        session=object(),
    )
    body = resp.body.decode()
    assert resp.status_code == 200
    assert "could not be read" in body
    assert "not an empty timeline" in body
    assert "elasticsearch is down" not in body


def test_the_route_filters_to_the_active_sources(monkeypatch):
    import ion.services.entity_timeline_service as svc

    payload = {
        "entity_value": "10.0.0.5", "entity_type": "ip", "hours": 168,
        "total_events": 2, "sources": ["case", "audit"],
        "events": [
            {"source": "case", "severity": "high", "title": "c",
             "timestamp": "2026-10-05T14:22:31", "meta": {}},
            {"source": "audit", "severity": "info", "title": "a",
             "timestamp": "2026-10-05T13:00:00", "meta": {}},
        ],
    }
    monkeypatch.setattr(svc, "get_entity_timeline", lambda *a, **kw: payload)

    resp = entity_timeline_fragment(
        request=_request(), q="10.0.0.5", type="auto", hours=168,
        sources="audit", session=object(),
    )
    body = resp.body.decode()
    assert "et-source-audit" in body
    assert 'data-source="case"' not in body
    # Both pills still render, so the filter can be widened or cleared.
    assert "All (2)" in body
    assert "et-source-case" in body
