"""The maturity fragments, and the honesty contract they carry.

maturity.html built its whole body with eight `innerHTML` writes fed by 220
lines of inline JavaScript. What moved to Jinja is not only markup. This
page scores the SOC's own maturity on the SOC-CMM 1-to-5 scale, and the
JavaScript collapsed "not assessed" into "assessed badly", or the reverse,
in five places:

  * `scoreColor(null)` fell through every `>=` comparison and returned the
    critical colour, so an unassessed figure was painted the red of a SOC at
    level 1;
  * `a.overall_score * 20` is 0 for null, so an unassessed overall drew the
    same 0% ring a stored 0 draws;
  * `width:${score.pct}%` with a null pct emitted invalid CSS, so the bar
    sat at width 0, which is what 0% looks like;
  * the history table read `(s.business||{}).score||'-'`, which prints a
    domain genuinely scored 0 as the dash that means not assessed, and
    prints a missing domain as the same dash;
  * the level badge ladder ended in `: 'badge-error'`, so an unassessed
    overall wore the error badge.

So most of what is tested here is the difference between a measurement of
zero and an absence of measurement, asserted in both directions, because a
truthiness port fails one direction and a `|| 0` port fails the other. Every
case below was watched failing against the defective form before it was made
to pass.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

import ion.web
from ion.web.templating import make_templates
from ion.web.ui.maturity import (
    MAX_LEVEL,
    SCORE_BANDS,
    UNMEASURED_BADGE,
    UNMEASURED_COLOUR,
    _chrome,
    _levels,
    assessment_view,
    domain_views,
    level_views,
    question_views,
    retired_domain_views,
    ring_pct,
    score_badge,
    score_colour,
)

HISTORY = "_fragments/maturity_history.html"
QUESTIONNAIRE = "_fragments/maturity_questionnaire.html"
RESULT = "_fragments/maturity_result.html"

BAND_COLOURS = [colour for _, colour, _ in SCORE_BANDS]
BAND_BADGES = [badge for _, _, badge in SCORE_BANDS]

PAGE = Path(ion.web.__file__).parent / "templates" / "maturity.html"

#: The ring's own hatch, as it appears in the rendered markup. Asserted on
#: this rather than on a bare "repeating-linear-gradient" search, which also
#: hits the legend's hatch swatch and so would pass whatever the ring did.
HATCHED_RING = 'class="mat-result-ring" data-ion-style="background:repeating'
HATCHED_BAR = "width:100%; background:repeating-linear-gradient"


def _flat(html: str) -> str:
    """Whitespace-normalised, because the templates wrap their sentences."""
    return " ".join(html.split())


def _env():
    return make_templates().env


def _questionnaire() -> dict:
    from ion.services import maturity_service

    return maturity_service.get_questionnaire()


def _domains() -> list[dict]:
    return _questionnaire()["domains"]


def _stored(**over: Any) -> dict:
    """A row shaped like MaturityAssessment.to_dict's return."""
    base: dict[str, Any] = {
        "id": 7,
        "title": "Q4 baseline",
        "scores": {
            d["id"]: {"score": 3, "total": 15, "max": 25, "pct": 60}
            for d in _domains()
        },
        "responses": {},
        "overall_score": 3,
        "overall_level": "Defined",
        "notes": None,
        "created_by_id": 1,
        "created_by_username": "admin",
        "created_at": "2026-10-01T09:41:07",
    }
    base.update(over)
    return base


def render_history(rows: list[dict], **over: Any) -> str:
    """Render through the real view builders, so a break in either fails."""
    domains = _domains()
    context: dict[str, Any] = {
        "failed": False,
        "rows": [assessment_view(r, domains) for r in rows],
        "columns": [{"id": d["id"], "name": d["name"]} for d in domains],
    }
    context.update(over)
    return _env().get_template(HISTORY).render(**context, **_chrome())


def render_result(stored: dict) -> str:
    return _env().get_template(RESULT).render(
        failed=False,
        assessment=assessment_view(stored, _domains()),
        **_chrome(),
    )


def render_questionnaire(domains: list[dict] | None = None) -> str:
    source = _questionnaire()
    return _env().get_template(QUESTIONNAIRE).render(
        failed=False,
        domains=question_views(domains if domains is not None else source["domains"]),
        levels=level_views(source["maturity_levels"]),
        buttons=_levels(),
        **_chrome(),
    )


def render_failed(name: str) -> str:
    blank = {HISTORY: {"rows": [], "columns": []},
             QUESTIONNAIRE: {"domains": [], "levels": [], "buttons": []},
             RESULT: {"assessment": None}}[name]
    return _env().get_template(name).render(failed=True, **blank, **_chrome())


# ---------------------------------------------------------------------------
# The band tables, total over None
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("score,colour", [
    (5, "var(--mitre-covered)"),
    (4, "var(--primary)"),
    (3, "var(--sev-medium)"),
    (2, "var(--sev-high)"),
    (1, "var(--sev-critical)"),
    (0, "var(--sev-critical)"),
])
def test_the_score_bands_keep_their_edges(score, colour):
    assert score_colour(score) == colour


@pytest.mark.parametrize("score,badge", [
    (5, "badge-success"), (4, "badge-info"), (3, "badge-warning"),
    (2, "badge-error"), (1, "badge-error"), (0, "badge-error"),
])
def test_the_badge_bands_keep_their_edges(score, badge):
    assert score_badge(score) == badge


def test_score_colour_is_total_over_none():
    """It returns a colour for None rather than making callers guard.

    That is what makes "an unassessed figure cannot be painted a healthy
    colour" a property of the code rather than of every template branch
    remembering to check. `scoreColor(null)` returned the critical colour,
    because `null >= 2` is false and the ladder ended in a bare return.
    """
    assert score_colour(None) == UNMEASURED_COLOUR
    assert UNMEASURED_COLOUR not in BAND_COLOURS


def test_score_badge_is_total_over_none():
    assert score_badge(None) == UNMEASURED_BADGE
    assert UNMEASURED_BADGE not in BAND_BADGES


def test_a_measured_zero_still_selects_a_band():
    """0 is off the SOC-CMM scale and still a number somebody wrote down."""
    assert score_colour(0) in BAND_COLOURS
    assert score_badge(0) in BAND_BADGES


def test_ring_pct_of_a_measured_zero_is_zero_and_of_an_absence_is_none():
    """The JavaScript's `a.overall_score * 20` is 0 for both."""
    assert ring_pct(0) == 0
    assert ring_pct(None) is None
    assert ring_pct(MAX_LEVEL) == 100


# ---------------------------------------------------------------------------
# The overall score: both directions
# ---------------------------------------------------------------------------


def test_a_zero_overall_score_is_a_measurement_not_an_absence():
    """The direction a truthiness port gets wrong.

    `{% if a.score %}` is false for 0, so an overall genuinely stored as 0
    would report "not assessed" and its ring would be hatched, which claims
    nobody looked.
    """
    html = _flat(render_result(_stored(overall_score=0, overall_level="Initial")))
    assert "conic-gradient(var(--sev-critical) 0%" in html
    assert HATCHED_RING not in html
    assert ">0</div>" in html
    assert "of 5" in html


def test_an_unassessed_overall_is_hatched_not_a_zero_percent_ring():
    """The direction a `|| 0` port gets wrong.

    An unassessed overall must not draw the conic arc at all: a conic
    gradient stopping at 0% is exactly the picture a stored 0 produces.
    """
    html = _flat(render_result(_stored(overall_score=None)))
    assert "conic-gradient" not in html
    assert HATCHED_RING in html
    assert ">n/a</div>" in html
    assert "not assessed" in html
    assert "of 5" not in html


def test_an_unassessed_overall_never_takes_a_band_colour():
    html = render_result(_stored(overall_score=None, overall_level=None,
                                 scores={}))
    assert f"color:{UNMEASURED_COLOUR}" in html
    for colour in BAND_COLOURS:
        assert f"color:{colour}" not in html, f"an unassessed overall took {colour}"


def test_an_unassessed_level_wears_no_band_badge():
    html = _flat(render_history([_stored(overall_score=None, overall_level=None)]))
    assert f'badge {UNMEASURED_BADGE}">not assessed' in html
    for badge in BAND_BADGES:
        assert f"badge {badge}" not in html


def test_a_blank_level_string_is_not_a_maturity_level():
    """An empty `overall_level` is folded to None in the view, so the
    template has one absence to test rather than two."""
    assert assessment_view(_stored(overall_level=""), _domains())["level"] is None
    assert "not assessed" in _flat(render_history([_stored(overall_level="")]))


# ---------------------------------------------------------------------------
# A domain score in the history table: both directions
# ---------------------------------------------------------------------------


def test_a_domain_scored_zero_shows_zero_in_the_history_table():
    """`(s.business||{}).score||'-'` printed this as the not-assessed dash."""
    scores = {d["id"]: {"score": 0, "pct": 0} for d in _domains()}
    html = _flat(render_history([_stored(scores=scores)]))
    assert ">0</span>" in html
    assert "n/a" not in html.split(">n/a mean")[0]


def test_a_domain_missing_from_the_stored_scores_is_not_shown_as_zero():
    html = _flat(render_history([_stored(scores={})]))
    assert ">n/a<" in html
    assert ">0</span>" not in html


def test_an_unassessed_domain_never_takes_a_band_colour():
    html = render_history([_stored(overall_score=None, overall_level=None,
                                   scores={})])
    for colour in BAND_COLOURS:
        assert f"color:{colour}" not in html, f"an unassessed domain took {colour}"


def test_the_history_table_says_what_n_a_means_without_a_hover():
    html = _flat(render_history([_stored()]))
    assert "not the same as a score of 0" in html
    assert "title=" not in html.split("n/a mean")[1][:200]


# ---------------------------------------------------------------------------
# A domain bar in the result panel: both directions, read independently
# ---------------------------------------------------------------------------


def test_a_domain_measured_at_zero_percent_draws_a_real_bar():
    html = _flat(render_result(_stored(
        scores={d["id"]: {"score": 1, "pct": 0} for d in _domains()})))
    assert "width:0%" in html
    assert HATCHED_BAR not in html
    assert ">0%<" in html


def test_an_unassessed_domain_bar_is_hatched_not_a_bar_at_width_zero():
    html = _flat(render_result(_stored(
        scores={d["id"]: {"score": 1, "pct": None} for d in _domains()})))
    assert HATCHED_BAR in html
    assert "width:0%" not in html


def test_the_score_and_the_percentage_are_read_independently():
    """A row holding one and not the other is a real shape, and filling
    either in from the other would be inventing a measurement."""
    [view] = domain_views(_domains()[:1], {"business": {"score": 4}})
    assert view["measured"] is True
    assert view["pct_measured"] is False
    html = _flat(render_result(_stored(scores={"business": {"score": 4}})))
    assert "4/5" in html
    assert HATCHED_BAR in html


def test_a_domain_view_reads_zero_as_measured_and_absent_as_not():
    [measured] = domain_views(_domains()[:1], {"business": {"score": 0, "pct": 0}})
    [absent] = domain_views(_domains()[:1], {})
    assert (measured["measured"], measured["pct_measured"]) == (True, True)
    assert (absent["measured"], absent["pct_measured"]) == (False, False)
    assert absent["present"] is False


# ---------------------------------------------------------------------------
# Ordering, columns, and figures the questionnaire no longer has
# ---------------------------------------------------------------------------


def test_the_table_header_and_the_cells_come_from_one_domain_list():
    """Otherwise a column ends up labelled one domain and filled from
    another, which is the quietest way for this page to lie."""
    domains = _domains()
    view = assessment_view(_stored(), domains)
    assert [d["id"] for d in view["domains"]] == [d["id"] for d in domains]
    html = render_history([_stored()])
    for d in domains:
        assert f"<th>{d['name']}</th>" in html


def test_the_domain_order_is_the_questionnaires_not_the_stored_dicts():
    reversed_scores = {d["id"]: {"score": 3, "pct": 60}
                       for d in reversed(_domains())}
    view = assessment_view(_stored(scores=reversed_scores), _domains())
    assert [d["id"] for d in view["domains"]] == [d["id"] for d in _domains()]


def test_a_scored_domain_the_questionnaire_dropped_is_still_shown():
    """A figure that was measured and stored must not vanish because the
    questionnaire moved on."""
    retired = retired_domain_views(_domains(), {"automation": {"score": 2, "pct": 40}})
    assert [r["id"] for r in retired] == ["automation"]
    assert retired[0]["known"] is False
    html = _flat(render_result(_stored(scores={"automation": {"score": 2, "pct": 40}})))
    assert "automation" in html
    assert "the questionnaire no longer has" in html


def test_the_scale_strip_is_printed_in_level_order():
    levels = level_views({3: {"name": "Defined"}, 1: {"name": "Initial"},
                          2: {"name": "Managed"}})
    assert [lvl["level"] for lvl in levels] == [1, 2, 3]
    html = render_questionnaire()
    assert html.index("Initial") < html.index("Optimising")


def test_the_scale_strip_comes_from_the_services_own_levels():
    """Not from the second copy of the five names the JavaScript hardcoded."""
    from ion.services.maturity_service import MATURITY_LEVELS

    html = render_questionnaire()
    for info in MATURITY_LEVELS.values():
        assert info["name"] in html


# ---------------------------------------------------------------------------
# The live preview takes its colours from the server's band table
# ---------------------------------------------------------------------------


def test_every_domain_average_element_carries_the_band_colours():
    """So the running average a user watches while filling the form cannot
    be coloured from a second copy of SCORE_BANDS in JavaScript."""
    html = render_questionnaire()
    for d in _domains():
        assert f'id="mat-domain-score-{d["id"]}"' in html
    for level in range(1, MAX_LEVEL + 1):
        assert f'data-colour-l{level}="{score_colour(level)}"' in html


def test_the_remaining_inline_javascript_holds_no_colour_table():
    js = _inline_code()
    assert "scoreColor" not in js
    assert "var(--sev-" not in js
    assert "var(--mitre-covered" not in js


# ---------------------------------------------------------------------------
# Timestamps stay on the viewer's clock
# ---------------------------------------------------------------------------


def test_the_date_is_emitted_as_a_time_element_not_a_formatted_string():
    """A server knows only its own clock. Formatting here would show an
    analyst in another timezone the wrong date on every row."""
    html = render_history([_stored(created_at="2026-10-01T09:41:07")])
    assert '<time datetime="2026-10-01T09:41:07"' in html
    assert 'data-ts-format="date"' in html


def test_a_missing_created_at_renders_the_fallback_not_the_epoch():
    html = _flat(render_history([_stored(created_at=None)]))
    assert "1970" not in html
    assert ">-<" in html


# ---------------------------------------------------------------------------
# Stored and configured URLs
# ---------------------------------------------------------------------------


def test_a_javascript_scheme_in_a_related_page_link_is_not_rendered_as_a_link():
    """Jinja escapes characters, not schemes. Nothing stored reaches an href
    on this page, and the one href that exists goes through safe_url anyway
    so that stays true if the questionnaire ever becomes data."""
    html = render_questionnaire([{
        "id": "business", "name": "Business", "description": "d",
        "ion_pages": ["javascript:alert(1)"], "questions": [],
    }])
    assert 'href="javascript:' not in html
    assert "javascript:alert(1)" in html


def test_a_site_relative_related_page_link_survives():
    html = render_questionnaire()
    assert 'href="/compliance"' in html


# ---------------------------------------------------------------------------
# Escaping, which retires the hand-rolled matEsc()
# ---------------------------------------------------------------------------


def test_jinja_escapes_what_the_hand_rolled_matesc_used_to():
    hostile = _stored(
        title="<img src=x onerror=alert(1)>",
        overall_level="<script>alert(2)</script>",
        notes="<svg onload=alert(3)>",
        scores={"<b>retired</b>": {"score": 2, "pct": 40}},
    )
    for html in (render_history([hostile]), render_result(hostile)):
        assert "<script>" not in html
        assert "<img src=x" not in html
        assert "<svg onload" not in html
        assert "&lt;img src=x" in html

    html = render_questionnaire([{
        "id": "x", "name": "<b>name</b>", "description": "<i>d</i>",
        "ion_pages": [], "questions": [
            {"id": "q1", "text": "<script>alert(1)</script>", "guidance": "g"},
        ],
    }])
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


# ---------------------------------------------------------------------------
# A failed read is not empty data, and the route has to select that state
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name,what", [
    (HISTORY, "The assessment history"),
    (QUESTIONNAIRE, "The maturity questionnaire"),
    (RESULT, "This assessment"),
])
def test_a_failed_read_says_so_and_prints_no_figure_at_all(name, what):
    html = _flat(render_failed(name))
    assert f"{what} could not be read" in html
    assert "not a SOC that scores badly" in html
    assert "not a SOC with no assessments" in html
    assert "conic-gradient" not in html
    assert "mat-bar-fill" not in html
    assert "<table" not in html
    assert "mat-q-score" not in html


def _request(path: str):
    from starlette.requests import Request

    return Request({"type": "http", "method": "GET", "path": path,
                    "headers": [], "query_string": b"", "app": None})


def _boom(*args, **kwargs):
    raise RuntimeError("the maturity read exploded")


def test_the_history_route_renders_the_failed_fragment_when_the_read_raises(
        monkeypatch):
    """Rendering the template with failed=True proves the template. Only
    calling the route proves the route selects that state, and a 500 would
    reach htmx as a response it does not swap, leaving the spinner turning."""
    from ion.services import maturity_service
    from ion.web.ui.maturity import maturity_history_fragment

    monkeypatch.setattr(maturity_service, "list_assessments", _boom)
    response = maturity_history_fragment(
        request=_request("/ui/maturity/history"), session=None)

    assert response.status_code == 200
    body = _flat(response.body.decode())
    assert "The assessment history could not be read" in body
    assert "<table" not in body


def test_the_questionnaire_route_renders_the_failed_fragment_when_the_read_raises(
        monkeypatch):
    from ion.services import maturity_service
    from ion.web.ui.maturity import maturity_questionnaire_fragment

    monkeypatch.setattr(maturity_service, "get_questionnaire", _boom)
    response = maturity_questionnaire_fragment(
        request=_request("/ui/maturity/questionnaire"))

    assert response.status_code == 200
    body = _flat(response.body.decode())
    assert "The maturity questionnaire could not be read" in body
    assert "mat-q-score" not in body


def test_the_result_route_renders_the_failed_fragment_when_the_read_raises(
        monkeypatch):
    from ion.services import maturity_service
    from ion.web.ui.maturity import maturity_result_fragment

    monkeypatch.setattr(maturity_service, "get_assessment", _boom)
    response = maturity_result_fragment(
        request=_request("/ui/maturity/assessments/7"),
        assessment_id=7, session=None)

    assert response.status_code == 200
    body = _flat(response.body.decode())
    assert "This assessment could not be read" in body
    assert "conic-gradient" not in body


def test_a_missing_assessment_is_a_404_rather_than_a_rendered_zero(monkeypatch):
    """htmx-errors.js already owns the wording for a 404. A second copy here
    would be a second definition of what a stale id means, and rendering a
    panel of zeros for it would be the worst of the three answers."""
    from fastapi import HTTPException

    from ion.services import maturity_service
    from ion.web.ui.maturity import maturity_result_fragment

    monkeypatch.setattr(maturity_service, "get_assessment",
                        lambda session, assessment_id: None)
    with pytest.raises(HTTPException) as raised:
        maturity_result_fragment(
            request=_request("/ui/maturity/assessments/7"),
            assessment_id=7, session=None)
    assert raised.value.status_code == 404


# ---------------------------------------------------------------------------
# Wiring: the fragments are not a softer way in than the API they mirror
# ---------------------------------------------------------------------------


def _dependency_calls(route) -> list:
    out, stack = [], list(getattr(route.dependant, "dependencies", []))
    while stack:
        dep = stack.pop()
        if dep.call is not None:
            out.append(dep.call)
        stack.extend(dep.dependencies)
    return out


def _permissions(route) -> set[str]:
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


@pytest.mark.parametrize("suffix", [
    "/questionnaire", "/assessments", "/assessments/{assessment_id}",
])
def test_each_fragment_permission_matches_its_json_endpoint_exactly(suffix):
    """Read off both routers rather than asserting a literal, so the test
    fails if either side is changed and the other is not.

    The history fragment mirrors GET /maturity/assessments. The POST and the
    DELETE on that path are gated harder, on alert:triage, and are still
    `fetch` calls in the page for exactly that reason, so only the GET is
    compared here.
    """
    from ion.web.maturity_api import router as api_router
    from ion.web.ui.maturity import router as ui_router

    ui_suffix = {"/assessments": "/history"}.get(suffix, suffix)
    api = [r for r in api_router.routes
           if r.path.endswith(suffix) and "GET" in r.methods]
    ui = [r for r in ui_router.routes if r.path.endswith(ui_suffix)]
    assert len(api) == 1 and len(ui) == 1, (suffix, ui_suffix)

    assert _permissions(ui[0]), "the fragment requires no permission at all"
    assert _permissions(ui[0]) == _permissions(api[0])


def test_every_fragment_route_is_a_read():
    from ion.web.ui.maturity import router as ui_router

    for route in ui_router.routes:
        assert route.methods == {"GET"}, route.path


# ---------------------------------------------------------------------------
# The page shell
# ---------------------------------------------------------------------------


def _page() -> str:
    return PAGE.read_text(encoding="utf-8")


def _inline_js() -> str:
    return "".join(
        m.group(1) for m in re.finditer(
            r"<script(?![^>]*src=)[^>]*>(.*?)</script>", _page(), re.S)
    )


def _inline_code() -> str:
    """The inline JavaScript with its comments removed.

    The page's comment names what the conversion deleted, the way
    response_approvals.html does, so a search for a deleted symbol has to
    read the code rather than the prose about the code. The write regex
    above needs no stripping: it requires an `=`, which prose does not have.
    """
    without_blocks = re.sub(r"/\*.*?\*/", "", _inline_js(), flags=re.S)
    return re.sub(r"(?m)^\s*//.*$", "", without_blocks)


def test_the_page_template_builds_no_markup_in_javascript():
    """The redesign's `server` column, asserted where the work was done.

    Counted inside inline `<script>` blocks only, the same way
    tools/ui_redesign_status.py measures it. A bare search of the file would
    hit `hx-swap="innerHTML"`, which is htmx being told where to put
    server-rendered HTML and is the opposite of the thing being removed.
    """
    writes = re.findall(
        r"innerHTML\s*\+?=|insertAdjacentHTML|outerHTML\s*\+?=", _inline_js())
    assert writes == []
    assert "matEsc" not in _inline_code()


def test_the_page_requests_each_fragment_over_htmx():
    page = _page()
    assert 'hx-get="/ui/maturity/history"' in page
    assert 'hx-get="/ui/maturity/questionnaire"' in page
    assert 'hx-trigger="load"' in page


def test_the_controls_that_retry_sit_outside_the_swap_target():
    """A control inside #mat-content is removed by any render that does not
    include it, so a failed read could take away the only way back."""
    page = _page()
    head, _, tail = page.partition('<div id="mat-content"')
    assert 'hx-get="/ui/maturity/history"' in head
    assert 'hx-get="/ui/maturity/questionnaire"' in head
    assert tail, "the swap target moved or was renamed"


@pytest.mark.parametrize("forbidden", ["hx-on", "js:", "hx-vals", "hx-headers"])
def test_the_page_uses_no_htmx_feature_that_compiles_a_string(forbidden):
    """ION serves `script-src 'self' 'nonce-...'` with no unsafe-eval, so
    anything htmx hands to Function() throws and the feature silently does
    nothing. That is invisible outside a browser console."""
    assert forbidden not in _page()


def test_no_hx_trigger_carries_an_event_filter():
    for value in re.findall(r'hx-trigger="([^"]*)"', _page()):
        assert "[" not in value, value


def test_the_page_writes_no_failure_handler_of_its_own():
    """static/js/htmx-errors.js is the one definition of what a failed
    fragment request means, including what an expired session means."""
    js = _inline_code()
    assert "htmx:responseError" not in js
    assert "htmx:afterRequest" not in js
    assert "/login" not in js
