"""The SOC health scorecard fragment, and the honesty contract it carries.

soc_health.html built the whole scorecard with three `innerHTML` writes fed
by 151 lines of inline JavaScript. What moved to Jinja is not just markup:
soc_health_service deliberately reports an unmeasured figure as None, an
unscorable dimension as score None, and records in `score_basis` what a
score was actually computed from. A Jinja port written with truthiness puts
all of that back to a confident zero, silently, and the page looks fine.

So most of what is tested here is the difference between a measurement of
zero and an absence of measurement. Every case below was watched failing
against a truthiness version of the template or of the view builders before
it was made to pass.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

import ion.web
from ion.web.templating import make_templates
from ion.web.ui.soc_health import (
    GRADE_BANDS,
    UNMEASURED_COLOUR,
    detail_rows,
    dimension_views,
    grade_colour,
    overall_view,
    recommendation_views,
)

FRAGMENT = "_fragments/soc_health_scorecard.html"

BAND_COLOURS = [colour for _, colour in GRADE_BANDS]


def _flat(html: str) -> str:
    """Whitespace-normalised, so an assertion does not encode the indenting."""
    return " ".join(html.split())


def _dim(score: int | None = 70, label: str = "Good",
         details: dict[str, Any] | None = None) -> dict:
    return {"score": score, "label": label, "details": details or {}}


def _card(**over: Any) -> dict:
    """A scorecard payload shaped like get_soc_health_scorecard's return."""
    base: dict[str, Any] = {
        "overall_score": 72,
        "grade": "B",
        "dimensions": {"detection_coverage": _dim()},
        "scored_dimensions": ["detection_coverage"],
        "unavailable_dimensions": [],
        "weight_basis": 1.0,
        "recommendations": [],
    }
    base.update(over)
    return base


def render_card(card: dict) -> str:
    """Render through the real view builders, so a break in either fails."""
    env = make_templates().env
    return env.get_template(FRAGMENT).render(
        failed=False,
        overall=overall_view(card),
        dims=dimension_views(card),
        recommendations=recommendation_views(card),
        measured_swatch=GRADE_BANDS[0][1],
    )


def render_failed() -> str:
    env = make_templates().env
    return env.get_template(FRAGMENT).render(
        failed=True, overall=None, dims=[], recommendations=[],
    )


# ---------------------------------------------------------------------------
# A dimension score: zero is a measurement, None is not
# ---------------------------------------------------------------------------


def test_a_zero_dimension_score_is_a_measurement_not_an_absence():
    """The case a truthiness port gets wrong in the dangerous direction.

    `{% if dim.score %}` is false for 0, so a dimension genuinely measured at
    zero would report "not measured" and be excluded from the reader's
    attention. The template tests `dim.measured`, which the view builder sets
    from `score is not None`.
    """
    html = render_card(_card(dimensions={"detection_coverage": _dim(score=0)}))
    assert ">0<" in html
    assert "sh-basis-measured" in html
    assert "sh-basis-unmeasured" not in html
    assert "sh-dim-bar-fill" in html
    assert "width:0%" in html
    assert "sh-dim-bar-unmeasured" not in html


def test_an_unmeasured_dimension_is_not_rendered_as_zero():
    """The honesty contract in one case.

    An unmeasured dimension must not print 0, must not draw a bar at width 0
    (indistinguishable from a real zero), and must not take a band colour.
    """
    html = render_card(_card(dimensions={"detection_coverage": _dim(score=None,
                                                                   label="Unavailable")}))
    assert ">not measured<" in html
    assert "sh-basis-unmeasured" in html
    assert "sh-dim-bar-unmeasured" in html
    assert "sh-dim-bar-fill" not in html
    assert "width:0%" not in html
    assert ">0<" not in html


def test_an_unmeasured_dimension_never_takes_a_healthy_colour():
    """Asserted on `--dim-color`, which only a dimension card sets.

    A bare substring search would hit the legend's "measured" swatch, which
    carries the top band colour on purpose.
    """
    html = render_card(_card(dimensions={"detection_coverage": _dim(score=None)}))
    assert f"--dim-color:{UNMEASURED_COLOUR}" in html
    for colour in BAND_COLOURS:
        assert f"--dim-color:{colour}" not in html, \
            f"an unmeasured dimension took {colour}"


@pytest.mark.parametrize("score,colour", [
    (100, "var(--mitre-covered)"), (80, "var(--mitre-covered)"),
    (79, "var(--quality-good)"), (65, "var(--quality-good)"),
    (64, "var(--sev-medium)"), (50, "var(--sev-medium)"),
    (49, "var(--sev-high)"), (35, "var(--sev-high)"),
    (34, "var(--sev-critical)"), (0, "var(--sev-critical)"),
])
def test_the_score_bands_keep_their_edges(score, colour):
    assert grade_colour(score) == colour


def test_grade_colour_is_total_over_none():
    """It returns a colour for None rather than making callers guard.

    That is what makes "an unmeasured figure cannot be painted green" a
    property of the code rather than of every branch remembering to check.
    """
    assert grade_colour(None) == UNMEASURED_COLOUR
    assert UNMEASURED_COLOUR not in BAND_COLOURS


def test_the_cards_render_in_the_order_the_page_declares():
    card = _card(dimensions={
        "integration_health": _dim(label="IntegrationCard"),
        "detection_coverage": _dim(label="DetectionCard"),
    })
    html = render_card(card)
    assert html.index("DetectionCard") < html.index("IntegrationCard")


# ---------------------------------------------------------------------------
# The overall grade ring
# ---------------------------------------------------------------------------


def test_a_measured_zero_overall_still_draws_a_measured_ring():
    html = render_card(_card(overall_score=0, grade="F"))
    assert "conic-gradient(var(--sev-critical) 0%" in html
    assert "sh-grade-ring sh-legend-hatch" not in html
    assert "0/100" in html


def test_an_unmeasured_overall_is_hatched_not_a_zero_percent_ring():
    """The one place the old JavaScript still collapsed the two.

    It set `pct = scored ? d.overall_score : 0` and drew the conic gradient
    anyway, so an unmeasured overall produced exactly the ring a measured
    zero produces. The dimension bars had already been given the hatch for
    this reason; the ring had not.
    """
    html = render_card(_card(overall_score=None, grade=None, weight_basis=0.0,
                             unavailable_dimensions=["detection_coverage"]))
    assert "conic-gradient" not in html
    assert "sh-grade-ring sh-legend-hatch" in html
    assert "Not assessed" in html
    assert "0/100" not in html


def test_an_unmeasured_overall_shows_a_dash_for_the_grade_not_none():
    html = render_card(_card(overall_score=None, grade=None,
                             unavailable_dimensions=["detection_coverage"]))
    assert "None" not in html
    assert "—" in html


# ---------------------------------------------------------------------------
# The basis note: what share of the scorecard the grade rests on
# ---------------------------------------------------------------------------


def test_all_five_measured_says_so():
    assert "All five dimensions measured." in render_card(_card())


def test_the_basis_note_names_the_dimensions_that_could_not_be_measured():
    html = _flat(render_card(_card(
        weight_basis=0.85,
        unavailable_dimensions=["knowledge_completeness", "team_readiness"],
    )))
    assert "Weighted over 85% of the scorecard" in html
    assert "2 dimensions could not be measured" in html
    assert "knowledge completeness, team readiness" in html


def test_one_unmeasured_dimension_is_not_pluralised():
    html = _flat(render_card(_card(weight_basis=0.9,
                                   unavailable_dimensions=["team_readiness"])))
    assert "1 dimension could not be measured" in html


def test_a_zero_weight_basis_is_a_measurement_and_prints_zero_percent():
    """Nothing scorable is a real denominator of zero, so it is printed."""
    html = _flat(render_card(_card(
        overall_score=None, grade=None, weight_basis=0.0,
        unavailable_dimensions=["detection_coverage"],
    )))
    assert "Weighted over 0% of the scorecard" in html


def test_a_missing_weight_basis_is_not_printed_as_zero_percent():
    """The JavaScript's `(d.weight_basis || 0) * 100` claimed a denominator
    it had never read. An unrecorded basis and a basis of zero are different
    facts and only one of them is a measurement."""
    html = _flat(render_card(_card(weight_basis=None,
                                   unavailable_dimensions=["team_readiness"])))
    assert "0% of the scorecard" not in html
    assert "was not recorded" in html
    assert overall_view(_card(weight_basis=None))["weight_pct"] is None


# ---------------------------------------------------------------------------
# Detail rows
# ---------------------------------------------------------------------------


def test_a_zero_detail_renders_as_zero():
    html = _flat(render_card(_card(dimensions={
        "operational_efficiency": _dim(score=50, details={"cases_opened_30d": 0}),
    })))
    assert "cases opened 30d:</strong> 0" in html


def test_a_none_detail_is_labelled_unmeasured_rather_than_dropped():
    """The JavaScript skipped a null detail outright.

    Silence reads as "there is nothing to say about this figure" when the
    truth is "nobody obtained it". On operational_efficiency, which never
    reports an unavailable score, the dropped `avg_mttr_hours` row was the
    only place a reader could learn that 30% of the score was a neutral
    stand-in rather than a measurement.
    """
    html = _flat(render_card(_card(dimensions={
        "operational_efficiency": _dim(score=50, details={"avg_mttr_hours": None}),
    })))
    assert "avg mttr hours" in html
    assert "sh-basis-unmeasured\">not measured" in html
    assert "avg mttr hours:</strong> 0" not in html


def test_a_boolean_detail_reads_yes_or_no():
    rows = detail_rows({"tide_available": True, "estimated": False})
    assert rows[0]["value"] == "yes"
    assert rows[1]["value"] == "no"


def test_an_unknown_boolean_detail_is_not_folded_into_no():
    """Three states stay three. A truthiness port turns "nobody checked
    whether TIDE is available" into "TIDE is not available"."""
    [row] = detail_rows({"tide_available": None})
    assert row["measured"] is False
    assert row["value"] is None


def test_a_nested_detail_is_flattened_without_inventing_values():
    [row] = detail_rows({"tide": {"configured": True, "healthy": None}})
    assert row["value"] == "configured: yes, healthy: unknown"
    assert "null" not in row["value"]


def test_an_empty_string_detail_is_dropped_but_a_zero_is_not():
    rows = detail_rows({"reason": "", "covered_techniques": 0})
    assert [r["name"] for r in rows] == ["covered techniques"]


# ---------------------------------------------------------------------------
# Recommendations
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("priority,kind", [
    ("high", "error"), ("medium", "warning"), ("low", "info"),
])
def test_a_ranked_recommendation_keeps_its_severity(priority, kind):
    html = render_card(_card(recommendations=[
        {"area": "Detection Coverage", "message": "do a thing", "priority": priority},
    ]))
    assert f"alert-{kind}" in html
    assert f"badge-{kind}" in html
    assert "sh-rec-unseen" not in html


def test_a_visibility_recommendation_is_not_ranked_against_measured_findings():
    """"ION cannot see this" is not a low-priority improvement. Falling
    through to `alert-info` would file a blind spot alongside findings
    measured against real data."""
    html = render_card(_card(recommendations=[
        {"area": "Detection Coverage", "message": "TIDE could not be read.",
         "priority": "visibility"},
    ]))
    assert "sh-rec-unseen" in html
    assert "sh-badge-unseen" in html
    assert "alert-info" not in html
    assert "alert-error" not in html


def test_no_recommendations_renders_no_empty_card():
    assert "Improvement Recommendations" not in render_card(_card())


# ---------------------------------------------------------------------------
# Escaping, which retires the hand-rolled esc()
# ---------------------------------------------------------------------------


def test_jinja_escapes_what_the_hand_rolled_esc_used_to():
    html = render_card(_card(
        dimensions={"detection_coverage": _dim(
            label="<img src=x onerror=alert(1)>",
            details={"<b>key</b>": "<i>value</i>"},
        )},
        recommendations=[{"area": "<script>alert(1)</script>",
                          "message": "<svg onload=alert(2)>", "priority": "high"}],
    ))
    assert "<script>" not in html
    assert "<img src=x" not in html
    assert "<svg onload" not in html
    assert "&lt;script&gt;" in html
    assert "&lt;img src=x" in html


# ---------------------------------------------------------------------------
# A failed read is not empty data
# ---------------------------------------------------------------------------


def test_a_failed_read_says_so_and_prints_no_figure_at_all():
    html = render_failed()
    assert "could not be computed" in html
    assert "not the same as a SOC that scores badly" in html
    assert "stat-value" not in html
    assert "conic-gradient" not in html
    assert "sh-dims" not in html
    assert "sh-dim-bar" not in html


def test_the_route_renders_the_failed_fragment_when_the_service_raises(monkeypatch):
    """A read that fails must not reach the browser as a 500, which htmx does
    not swap, leaving the page's spinner turning as if it were still loading."""
    from starlette.requests import Request

    import ion.services.soc_health_service as svc
    from ion.web.ui.soc_health import soc_health_scorecard_fragment

    def _boom(session):
        raise RuntimeError("TIDE exploded")

    monkeypatch.setattr(svc, "get_soc_health_scorecard", _boom)
    request = Request({"type": "http", "method": "GET", "path": "/ui/soc-health/scorecard",
                       "headers": [], "query_string": b"", "app": None})
    response = soc_health_scorecard_fragment(request=request, session=None)

    assert response.status_code == 200
    body = response.body.decode()
    assert "could not be computed" in body
    assert "stat-value" not in body


# ---------------------------------------------------------------------------
# Wiring: the fragment is not a softer way in than the API it mirrors
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


def test_the_fragment_permission_matches_the_json_endpoint_exactly():
    """Read off both routers rather than asserting a literal, so the test
    fails if either side is changed and the other is not."""
    from ion.web.soc_health_api import router as api_router
    from ion.web.ui.soc_health import router as ui_router

    api = [r for r in api_router.routes if r.path.endswith("/scorecard")]
    ui = [r for r in ui_router.routes if r.path.endswith("/scorecard")]
    assert len(api) == 1 and len(ui) == 1

    assert _permissions(ui[0]), "the fragment requires no permission at all"
    assert _permissions(ui[0]) == _permissions(api[0])


def test_the_page_template_builds_no_markup_in_javascript():
    """The redesign's `server` column, asserted where the work was done.

    Counted inside inline `<script>` blocks only, the same way
    tools/ui_redesign_status.py measures it. A bare search of the file would
    hit `hx-swap="innerHTML"`, which is htmx being told where to put
    server-rendered HTML and is the opposite of the thing being removed.
    """
    page = (Path(ion.web.__file__).parent / "templates" / "soc_health.html"
            ).read_text(encoding="utf-8")
    inline_js = "".join(
        m.group(1) for m in re.finditer(
            r"<script(?![^>]*src=)[^>]*>(.*?)</script>", page, re.S)
    )
    writes = re.findall(
        r"innerHTML\s*\+?=|insertAdjacentHTML|outerHTML\s*\+?=", inline_js)
    assert writes == []
    assert inline_js.strip() == "", "the page should carry no inline JavaScript"
    assert 'hx-get="/ui/soc-health/scorecard"' in page
    assert 'hx-trigger="load"' in page
