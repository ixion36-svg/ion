"""The morning briefing fragment: what 150 lines of brfRender used to build.

briefing.html assembled the whole briefing from concatenated strings in three
`innerHTML` writes, with a hand-rolled `brfEsc`. That is the shape the
redesign's `server` column exists to remove: markup built in JavaScript
cannot be restyled from the stylesheet, so a sweep of the sheet silently
fails to reach it and still reports success.

These tests render the fragment with fixture payloads rather than against the
dev database, because a dev box with no Elasticsearch, no OpenCTI and no TIDE
renders every card in its offline branch, which proves nothing about the
cards. Each case is one the old JavaScript either got right and has to keep,
or got wrong.
"""
from __future__ import annotations

import pathlib
import re
from typing import Any

import pytest

import ion.web
from ion.web.templating import make_templates
from ion.web.ui.briefing import _fmt_generated, _top_rules

FRAGMENT = "_fragments/briefing.html"
PAGE = pathlib.Path(ion.web.__file__).parent / "templates" / "briefing.html"


def render(b: Any, failed: bool = False, hours: int = 12,
           generated_at: str = "2026-10-12 06:00 UTC") -> str:
    """Render the fragment the way the route composes its context."""
    env = make_templates().env
    return env.get_template(FRAGMENT).render(
        b=b,
        failed=failed,
        hours=hours,
        generated_at=generated_at,
        top_rules=_top_rules(((b or {}).get("es") or {}).get("top_rules")),
    )


_TILE = re.compile(
    r'data-stat="([a-z-]+)".*?class="stat-value[^"]*"[^>]*>(.*?)</div>', re.S)


def tiles(html: str) -> dict[str, str]:
    """Each headline tile's rendered value, keyed by its `data-stat` slug.

    The fragment renders six tiles and four source cards, so a bare `">0<"`
    assertion cannot say which one produced it. The first version of these
    tests asserted globally and passed against a template that was wrong.
    """
    return {m.group(1): m.group(2).strip() for m in _TILE.finditer(html)}


def card(html: str, title: str) -> str:
    """The one source card whose heading names `title`.

    Same reason as `tiles`. Three of the four cards carry a status badge, so
    `">live<"` is in the document whenever any source is up.
    """
    hits = [c for c in html.split('<div class="card bg-base-200 shadow">')
            if title in c]
    assert len(hits) == 1, f"{title} matched {len(hits)} cards"
    return hits[0]


def _briefing(**over: Any) -> dict:
    """The shape briefing_service.build_briefing returns."""
    base = {
        "generated_at": "2026-10-12T06:00:00",
        "window_hours": 12,
        "sources_reached": ["elasticsearch", "tide"],
        "headlines": {
            "alerts_total": 41,
            "cases_opened": 3,
            "cases_closed": 2,
            "open_backlog": 17,
            "actors_tracked": 2,
            "tide_rules_enabled": 1859,
        },
        "es": {
            "enabled": True,
            "total": 41,
            "by_severity": {"critical": 1, "high": 4, "low": 36},
            "top_rules": [{"name": "Suspicious PowerShell", "count": 12}],
        },
        "cases": {
            "opened": 3, "closed": 2, "open_backlog": 17,
            "by_severity": {"high": 1},
            "notable": [{"case_number": "CASE-9", "title": "Beaconing host",
                         "severity": "high", "status": "open"}],
        },
        "opencti": {"enabled": True,
                    "actors": [{"name": "APT29", "aliases": ["Cozy Bear"],
                                "modified": None}]},
        "tide": {"enabled": True, "total_rules": 1859, "enabled_rules": 1859,
                 "mitre_techniques_covered": 212, "quality_avg": 0.61},
        "narrative": None,
    }
    base.update(over)
    return base


# ---------------------------------------------------------------------------
# The headline strip
# ---------------------------------------------------------------------------


def test_the_headline_counts_render():
    """Positive control. Without it every assertion below could be vacuous."""
    assert tiles(render(_briefing())) == {
        "alerts": "41", "cases-opened": "3", "cases-closed": "2",
        "open-backlog": "17", "actors-tracked": "2",
        "tide-rules-live": "1859",
    }


def test_a_zero_tide_rules_live_is_a_measurement_not_a_dash():
    """The clearest regression the old JavaScript carried.

    brfRender wrote `h.tide_rules_enabled || '-'`. A detection estate with
    zero rules enabled is the worst reading that tile can take, and it
    displayed as "not reported", which reads as a plumbing gap rather than
    an alarm. `is not none` is the only correct test for a count.
    """
    h = dict(_briefing()["headlines"], tide_rules_enabled=0)
    assert tiles(render(_briefing(headlines=h)))["tide-rules-live"] == "0"


def test_an_unreported_tide_rules_live_shows_a_dash():
    """The other half of the same guard: None really is unreported.

    _collect_tide leaves `enabled_rules` out when TIDE has no posture stats,
    so the key is genuinely absent rather than zero.
    """
    h = dict(_briefing()["headlines"], tide_rules_enabled=None)
    assert tiles(render(_briefing(headlines=h)))["tide-rules-live"] == "-"


def test_every_zero_headline_renders_zero_rather_than_a_dash():
    h = {k: 0 for k in _briefing()["headlines"]}
    assert set(tiles(render(_briefing(headlines=h))).values()) == {"0"}


# ---------------------------------------------------------------------------
# A source we could not read is not a source that reported nothing
# ---------------------------------------------------------------------------


def test_an_elasticsearch_read_failure_is_not_zero_alerts():
    """_collect_es swallows its exception and returns total 0 with an `error`
    key. The old card ignored `error` entirely, so it printed a green "live"
    badge next to a 0, which is the exact lie the honesty rule exists to
    stop: unmeasured is not zero.
    """
    h = dict(_briefing()["headlines"], alerts_total=0)
    html = render(_briefing(
        headlines=h,
        sources_reached=[],
        es={"enabled": True, "total": 0, "by_severity": {},
            "top_rules": [], "error": "ConnectionTimeout"},
    ))
    assert tiles(html)["alerts"] == "?", "unmeasured must not read as zero"
    alerts = card(html, "Alert Activity")
    assert ">live<" not in alerts, "a failed read must not be badged live"
    assert "read failed" in alerts
    assert "ConnectionTimeout" in alerts
    assert "unknown, not zero" in alerts


def test_an_opencti_read_failure_says_so_rather_than_no_actors():
    html = render(_briefing(
        opencti={"enabled": True, "actors": [], "error": "GraphQLError"},
    ))
    assert tiles(html)["actors-tracked"] == "?"
    actors = card(html, "Threat Actors")
    assert "No actor data available" not in actors
    assert "GraphQLError" in actors


def test_a_tide_read_failure_says_so_rather_than_not_configured():
    html = render(_briefing(tide={"enabled": True, "error": "IOError"}))
    assert tiles(html)["tide-rules-live"] == "?"
    posture = card(html, "Detection Posture")
    assert "TIDE not configured" not in posture
    assert "IOError" in posture


@pytest.mark.parametrize("src,expected,forbidden", [
    ({"enabled": True}, ">live<", "read failed"),
    ({"enabled": False}, ">es offline<", ">live<"),
    ({"enabled": True, "error": "Boom"}, ">read failed<", ">live<"),
])
def test_the_alert_source_badge_has_three_states(src, expected, forbidden):
    """A truthiness badge folds "we could not look" into one of the other
    two, and the old one folded it into "live"."""
    src = dict(src, total=0, by_severity={}, top_rules=[])
    alerts = card(render(_briefing(es=src)), "Alert Activity")
    assert expected in alerts
    assert forbidden not in alerts


# ---------------------------------------------------------------------------
# Severity badges, ported from brfSevKind
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("sev,badge", [
    ("critical", "badge-error"),
    ("high", "badge-warning"),
    ("medium", "badge-info"),
    ("low", "badge-success"),
    ("weird", "badge-ghost"),
    (None, "badge-ghost"),
])
def test_severity_badges_keep_brfsevkind_mapping(sev, badge):
    html = render(_briefing(cases={
        "notable": [{"case_number": "C-1", "title": "t", "severity": sev}],
    }))
    assert badge in card(html, "Case Activity")


# ---------------------------------------------------------------------------
# Top firing rules, three source shapes normalised in one place
# ---------------------------------------------------------------------------


def test_a_rule_that_fired_zero_times_shows_its_zero():
    """brfRender wrote `(r.count) || (r.doc_count) || ''`, so a rule with a
    count of 0 rendered an empty cell indistinguishable from a rule whose
    count the aggregation never returned."""
    alerts = card(render(_briefing(es={
        "enabled": True, "total": 0, "by_severity": {},
        "top_rules": [{"name": "Quiet rule", "count": 0}],
    })), "Alert Activity")
    assert "Quiet rule" in alerts
    assert re.search(r'class="font-mono font-semibold text-primary">0<', alerts)


def test_top_rules_normalises_a_dict_with_count():
    assert _top_rules([{"name": "r1", "count": 5}]) == [
        {"name": "r1", "count": 5}]


def test_top_rules_falls_back_to_doc_count():
    """_collect_es takes `top_rules` from whichever of three ES keys exists,
    so the rows arrive in more than one shape."""
    assert _top_rules([{"name": "r1", "doc_count": 7}]) == [
        {"name": "r1", "count": 7}]


def test_top_rules_accepts_a_bare_rule_name():
    assert _top_rules(["just-a-name"]) == [
        {"name": "just-a-name", "count": None}]


def test_top_rules_keeps_a_zero_count_rather_than_blanking_it():
    assert _top_rules([{"name": "r1", "count": 0}]) == [
        {"name": "r1", "count": 0}]


def test_top_rules_shows_an_unnameable_row_rather_than_dropping_it():
    """The JavaScript fell back to JSON.stringify, so an unexpected row shape
    showed something odd rather than vanishing from the table."""
    out = _top_rules([{"rule_id": 3}])
    assert len(out) == 1
    assert "rule_id" in out[0]["name"]


def test_top_rules_caps_at_six():
    assert len(_top_rules([{"name": f"r{i}"} for i in range(20)])) == 6


@pytest.mark.parametrize("raw", [None, [], ""])
def test_top_rules_is_empty_when_there_is_nothing(raw):
    assert _top_rules(raw) == []


def test_no_firing_rules_says_so_inside_the_card():
    html = render(_briefing(es={"enabled": True, "total": 0,
                                "by_severity": {}, "top_rules": []}))
    assert "No firing rules in window" in card(html, "Alert Activity")


# ---------------------------------------------------------------------------
# The generated stamp
# ---------------------------------------------------------------------------


def test_the_generated_stamp_names_its_zone():
    """build_briefing stores `datetime.utcnow().isoformat()`, which carries no
    offset, so `new Date(iso).toLocaleString()` in the browser read it as
    local time and displayed a stamp wrong by the viewer's UTC offset."""
    assert _fmt_generated("2026-10-12T06:00:00") == "2026-10-12 06:00 UTC"


def test_an_unparseable_generated_stamp_is_shown_raw():
    """The old try/catch returned the raw string, so an odd value was visible
    rather than silently blank."""
    assert _fmt_generated("not a date") == "not a date"


@pytest.mark.parametrize("raw", [None, ""])
def test_a_missing_generated_stamp_shows_a_dash(raw):
    assert _fmt_generated(raw) == "-"


def test_the_window_and_sources_render_in_the_meta_line():
    html = render(_briefing())
    assert "last 12h" in html
    assert "elasticsearch, tide" in html


def test_reaching_no_sources_says_none_rather_than_nothing():
    html = render(_briefing(sources_reached=[]))
    assert "<em>none</em>" in html


# ---------------------------------------------------------------------------
# The AI narrative, and its two absent states
# ---------------------------------------------------------------------------


def test_the_narrative_card_renders_when_ollama_wrote_one():
    html = render(_briefing(narrative="Quiet overnight.", _ai_requested=True))
    assert "Quiet overnight." in html
    assert "AI Briefing" in html


def test_a_requested_narrative_that_never_arrived_warns():
    html = render(_briefing(narrative=None, _ai_requested=True))
    assert "alert-warning" in html
    assert "not reachable" in html


def test_an_unrequested_narrative_offers_the_hint_instead():
    html = render(_briefing(narrative=None))
    assert "alert-info" in html
    assert "alert-warning" not in html
    assert "Generate AI Summary" in html


def test_jinja_escapes_everything_brf_esc_used_to():
    """brfEsc hand-rolled five replacements over every interpolated value.
    Jinja autoescapes, which retires it, and this proves the replacement
    actually escapes rather than assuming it."""
    payload = _briefing(
        narrative='<script>alert(1)</script>',
        opencti={"enabled": True,
                 "actors": [{"name": "<img src=x onerror=1>",
                             "aliases": ["<b>bold</b>"]}]},
        es={"enabled": True, "total": 1, "by_severity": {"<svg>": 1},
            "top_rules": [{"name": "<iframe>", "count": 1}]},
        cases={"notable": [{"case_number": "<a>", "title": "<form>",
                            "severity": "high"}]},
    )
    html = render(payload)
    for raw in ("<script>alert(1)", "<img src=x", "<b>bold</b>", "<svg>",
                "<iframe>", "<a>", "<form>"):
        assert raw not in html, raw
    assert "&lt;script&gt;" in html
    assert "&lt;iframe&gt;" in html


# ---------------------------------------------------------------------------
# Cases and TIDE
# ---------------------------------------------------------------------------


def test_notable_cases_render_their_rows():
    cases = card(render(_briefing()), "Case Activity")
    assert "CASE-9" in cases
    assert "Beaconing host" in cases


def test_no_notable_cases_says_so():
    html = render(_briefing(cases={"notable": []}))
    assert "No notable cases in window" in card(html, "Case Activity")


def test_the_tide_posture_rows_render():
    posture = card(render(_briefing()), "Detection Posture")
    assert "MITRE techniques covered" in posture
    assert ">212<" in posture
    assert ">0.61<" in posture


def test_a_zero_posture_figure_is_a_measurement_not_a_dash():
    """Same guard as the headline tile, one table lower. A quality average of
    0 and one TIDE never reported are different readings."""
    posture = card(render(_briefing(tide={
        "enabled": True, "total_rules": 10, "enabled_rules": 10,
        "mitre_techniques_covered": 0, "quality_avg": 0,
    })), "Detection Posture")
    assert posture.count(">0<") == 2, "both zero figures must render as 0"
    assert ">-<" not in posture


def test_an_unreported_posture_figure_shows_a_dash():
    posture = card(render(_briefing(tide={
        "enabled": True, "total_rules": 10,
    })), "Detection Posture")
    assert posture.count(">-<") == 3


def test_tide_offline_links_to_its_settings():
    posture = card(render(_briefing(tide={"enabled": False})),
                   "Detection Posture")
    assert "TIDE not configured" in posture
    assert "/settings#tide" in posture


# ---------------------------------------------------------------------------
# A failed compose is not a quiet shift
# ---------------------------------------------------------------------------


def test_a_failed_briefing_says_so_rather_than_showing_zeros():
    """build_briefing raising means we could not look. The old page replaced
    the container with the exception message; the fragment keeps the
    distinction and prints no figures at all, because a grid of zeros reads
    as "quiet night" and leads to the opposite action."""
    html = render(None, failed=True)
    assert "could not be composed" in html
    assert "not a quiet shift" in html
    assert "stat-value" not in html, "a failed compose must not print figures"


def test_the_failed_branch_names_the_window_it_could_not_compose():
    """The heading reads the route's `hours`, not `b.window_hours`: the
    payload is None in exactly the case that still has to render."""
    html = render(None, failed=True, hours=72)
    assert "72" in html


def test_the_failed_branch_points_at_the_controls_that_retry():
    """The controls live in the page shell, outside the swap target, so an
    error response can never swap away the button that requests the next
    one. The copy has to say so or the panel reads as terminal."""
    html = render(None, failed=True)
    assert "Refresh" in html


# ---------------------------------------------------------------------------
# The page shell, and the permission the fragment answers on
# ---------------------------------------------------------------------------


def test_the_page_builds_no_markup_of_its_own():
    """The `server` column, asserted here rather than only in the status tool.

    Scoped to inline script bodies, the same scope tools/ui_redesign_status.py
    measures: `hx-swap="innerHTML"` is an htmx attribute naming where the
    server's markup lands, not markup assembled from strings.
    """
    src = PAGE.read_text(encoding="utf-8")
    js = "".join(re.findall(r"<script(?![^>]*src=)[^>]*>(.*?)</script>",
                            src, re.S))
    assert re.search(r"innerHTML\s*\+?=|insertAdjacentHTML|outerHTML\s*\+?=",
                     js) is None
    # Not a vacuous pass: the page carried a 150-line scripts block until
    # this conversion, and the regex above is satisfied by its absence.
    assert "{% block scripts %}" not in src
    for gone in ("brfRender(", "brfEsc(", "brfSevKind(", "brfLoad("):
        assert gone not in src, gone


def test_the_page_requests_the_fragment_on_load():
    src = PAGE.read_text(encoding="utf-8")
    assert 'id="brf-content"' in src
    assert 'hx-get="/ui/briefing"' in src
    assert 'hx-trigger="load"' in src


def test_the_controls_sit_outside_the_swap_target():
    """The escape-hatch guard. If the window select or the buttons rendered
    inside #brf-content, a response would swap away the controls that request
    the next one and leave the page with no way forward but a reload."""
    src = PAGE.read_text(encoding="utf-8")
    target = src.index('id="brf-content"')
    for control in ('id="brf-hours"', ">Refresh<", ">Generate AI Summary<"):
        assert src.index(control) < target, control


def _permission_of(route) -> str | None:
    """The permission string closed over by a require_permission dependency."""
    stack = list(getattr(route.dependant, "dependencies", []))
    while stack:
        dep = stack.pop()
        fn = dep.call
        if getattr(fn, "__qualname__", "").startswith("require_permission."):
            cells = dict(zip(fn.__code__.co_freevars,
                             (c.cell_contents for c in (fn.__closure__ or ()))))
            return cells.get("permission_name")
        stack.extend(dep.dependencies)
    return None


def test_the_fragment_permission_matches_the_json_endpoint_exactly():
    """A fragment must never be a softer way in than the API it mirrors.
    Compared against the live route rather than asserted as a literal, so
    tightening /api/briefing cannot silently leave /ui/briefing open."""
    from ion.web.briefing_api import router as api_router
    from ion.web.ui.briefing import router as ui_router

    api = [_permission_of(r) for r in api_router.routes
           if getattr(r, "dependant", None)]
    ui = [_permission_of(r) for r in ui_router.routes
          if getattr(r, "dependant", None)]
    assert api == ["alert:read"], api
    assert ui == api, (ui, api)


def test_the_fragment_accepts_the_same_window_bounds_as_the_json_endpoint():
    """A fragment that accepted hours=100000 would ask the service for a
    window the JSON endpoint rejects, which is drift in the other
    direction from the permission."""
    import inspect

    from ion.web.briefing_api import briefing_endpoint
    from ion.web.ui.briefing import briefing_fragment

    def bounds(fn, name):
        q = inspect.signature(fn).parameters[name].default
        return (q.default, sorted(repr(m) for m in q.metadata))

    frag, api = bounds(briefing_fragment, "hours"), bounds(
        briefing_endpoint, "hours")
    assert frag == api, (frag, api)
    assert frag[0] == 12
    assert "ge=1" in " ".join(frag[1])
    assert "le=168" in " ".join(frag[1])
