"""The compliance posture fragment, and the honesty contract it carries.

compliance.html built its whole body with four `innerHTML` writes fed by
142 lines of inline JavaScript. What moved to Jinja is not only markup.
This page makes compliance claims, and the two services behind it keep
apart several facts the JavaScript collapsed:

  * compliance_mapping_service reports an unmeasurable control as score
    None and a framework it could not score as overall_score None, so that
    "nobody could measure this" never arrives as "measured at zero";
  * tide_service separates a technique with no rule from one whose rules
    are all switched off, in its own words "so a reader can tell 'nobody
    built this' from 'nobody turned it on'".

The JavaScript painted an unmeasured control's dash in the critical
colour, drew an unmeasured framework's bar in the critical colour at width
0, and put a switched-off rule in the same red badge as a rule nobody
wrote. So most of what is tested here is the difference between a
measurement of zero, a measurement nobody could take, and a gap that is
one switch away from closing.

Every case below was watched failing against a version of the template or
the view builders that collapsed the state it covers. The mutations are
recorded in the conversion report.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
from starlette.requests import Request

import ion.web
from ion.web.templating import make_templates
from ion.web.ui.compliance import (
    CONTROL_STATES,
    FRAGMENT,
    SCORE_BANDS,
    UNMEASURED_COLOUR,
    UNMEASURED_HATCH,
    authored_but_disabled,
    compliance_posture_fragment,
    control_rows,
    control_state,
    framework_card,
    gap_kind,
    legend_for,
    score_colour,
    unmeasured_cards,
)

BAND_COLOURS = [colour for _, colour in SCORE_BANDS]


def _flat(html: str) -> str:
    """Whitespace-normalised, so an assertion does not encode the indenting."""
    return " ".join(html.split())


# ---------------------------------------------------------------------------
# Payload builders, shaped like compliance_mapping_service's return
# ---------------------------------------------------------------------------


def _control(**over: Any) -> dict:
    base: dict[str, Any] = {
        "control_id": "DE.CM-1",
        "name": "Network Monitoring",
        "description": None,
        "score": 100,
        "state": "covered",
        "covered": 2,
        "total": 2,
        "covered_techniques": ["T1071", "T1572"],
        "gap_techniques": [],
    }
    base.update(over)
    return base


def _framework(**over: Any) -> dict:
    base: dict[str, Any] = {
        "framework_id": "nist_csf",
        "framework": "NIST Cybersecurity Framework",
        "version": "1.1",
        "url": "https://www.nist.gov/cyberframework",
        "overall_score": 60,
        "detection_coverage_score": 60,
        "controls": [_control()],
        "summary": {
            "fully_covered": 1, "partial": 1, "no_coverage": 2,
            "not_assessable": 1, "scored_controls": 4, "total_controls": 5,
        },
    }
    base.update(over)
    return base


def _posture(**over: Any) -> dict:
    base: dict[str, Any] = {
        "measure": "detection_coverage",
        "measures": ["Whether at least one enabled detection rule maps to each "
                     "MITRE technique associated with a control."],
        "does_not_measure": ["Whether the control is implemented in the "
                             "organisation."],
        "frameworks": [_framework()],
    }
    base.update(over)
    return base


def render(posture: dict, selected: str | None = "nist_csf",
           authored_off: set[str] | None = frozenset({"T1059"})) -> str:
    """Render through the real view builders, so a break in either fails."""
    frameworks = posture.get("frameworks") or []
    cards = [framework_card(f, selected) for f in frameworks]
    detail = None
    chosen = next(
        (f for f in frameworks if f.get("framework_id") == selected), None)
    if chosen is not None:
        rows = control_rows(chosen, authored_off)
        detail = {"framework": framework_card(chosen, selected),
                  "rows": rows, "legend": legend_for(rows)}
    env = make_templates().env
    return env.get_template(FRAGMENT).render(
        failed=False,
        cards=cards,
        detail=detail,
        selected_missing=bool(selected) and chosen is None and bool(frameworks),
        notice=posture.get("error"),
        availability_note=None,
        measures=posture.get("measures") or [],
        does_not_measure=posture.get("does_not_measure") or [],
        hatch=UNMEASURED_HATCH,
    )


def render_one(control: dict, authored_off: set[str] | None = None,
               **framework_over: Any) -> str:
    """One control, rendered in its framework's drill-in table."""
    return render(
        _posture(frameworks=[_framework(controls=[control], **framework_over)]),
        authored_off=authored_off,
    )


class _Tide:
    """A TIDE service stub that counts how often its coverage is read."""

    def __init__(self, coverage: dict | None, enabled: bool = True) -> None:
        self.enabled = enabled
        self._coverage = coverage
        self.reads = 0

    def get_global_mitre_coverage(self) -> dict | None:
        self.reads += 1
        return self._coverage


def _coverage(enabled: tuple[str, ...] = (),
              inactive: tuple[str, ...] = ()) -> dict:
    """A get_global_mitre_coverage payload with the three states it reports."""
    techniques: dict[str, dict] = {
        tid: {"rule_count": 1, "enabled_rules": 1} for tid in enabled}
    techniques.update(
        {tid: {"rule_count": 2, "enabled_rules": 0} for tid in inactive})
    return {
        "techniques": techniques,
        "covered_techniques": len(enabled),
        "inactive_techniques": list(inactive),
        "blind_spots": [],
        "coverage_basis": "at least one enabled rule",
    }


def _request() -> Request:
    return Request({"type": "http", "method": "GET",
                    "path": "/ui/compliance/posture", "headers": [],
                    "query_string": b"", "app": None})


# ---------------------------------------------------------------------------
# The colour of a figure: no score can pick the unmeasured one
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("score,colour", [
    (100, "var(--mitre-covered)"), (80, "var(--mitre-covered)"),
    (79, "var(--sev-medium)"), (40, "var(--sev-medium)"),
    (39, "var(--sev-critical)"), (0, "var(--sev-critical)"),
])
def test_the_score_bands_keep_their_edges(score, colour):
    assert score_colour(score) == colour


def test_score_colour_is_total_over_none():
    """It returns a colour for None rather than making callers guard.

    That is what makes "an unmeasured figure cannot be painted as a
    measurement" a property of the code rather than of every branch
    remembering to check. The JavaScript's `cmpScoreColor(ctl.score || 0)`
    is the branch that was not remembered: it handed every unmeasured
    control the critical colour.
    """
    assert score_colour(None) == UNMEASURED_COLOUR
    assert UNMEASURED_COLOUR not in BAND_COLOURS


# ---------------------------------------------------------------------------
# State 1 and state 2: a gap nobody wrote, and a gap nobody switched on
# ---------------------------------------------------------------------------


def test_a_gap_with_no_rule_written_reads_as_no_detection_written():
    html = _flat(render_one(
        _control(score=0, state="blind", covered=0, total=1,
                 covered_techniques=[], gap_techniques=["T1200"]),
        authored_off=set(),
    ))
    assert ">no detection written<" in html
    assert ">no rule written:<" in html
    assert "written, not running" not in html


def test_a_gap_whose_rules_are_all_switched_off_says_so():
    """The distinction tide_service keeps and the JavaScript threw away.

    Both are 0% and neither is covered, but one is closed by enabling a
    rule and the other by authoring one. A single red badge for both hides
    the cheaper of the two pieces of work.
    """
    html = _flat(render_one(
        _control(score=0, state="blind", covered=0, total=1,
                 covered_techniques=[], gap_techniques=["T1059"]),
        authored_off={"T1059"},
    ))
    assert ">written, not running<" in html
    assert ">written, not running:<" in html
    assert "no detection written" not in html
    assert "no rule written" not in html


def test_a_sub_technique_is_judged_by_its_parents_rules():
    """TIDE rolls a sub-technique's rules up to the parent, and so does
    _score_framework's covered test. Splitting the gap any other way would
    label it with a reason the percentage beside it disagrees with."""
    html = _flat(render_one(
        _control(score=0, state="blind", covered=0, total=1,
                 covered_techniques=[], gap_techniques=["T1059.007"]),
        authored_off={"T1059"},
    ))
    assert ">written, not running<" in html
    assert "no rule written" not in html


def test_a_mixed_zero_control_shows_both_kinds_of_gap():
    html = _flat(render_one(
        _control(score=0, state="blind", covered=0, total=2,
                 covered_techniques=[], gap_techniques=["T1059", "T1200"]),
        authored_off={"T1059"},
    ))
    assert ">part written, none running<" in html
    assert ">written, not running:<" in html
    assert ">no rule written:<" in html


@pytest.mark.parametrize("authored_off,expected", [
    ({"T1059"}, "written_off"),
    (set(), "not_written"),
    (None, "unknown"),
])
def test_gap_kind_covers_its_three_answers(authored_off, expected):
    assert gap_kind("T1059", authored_off) == expected


# ---------------------------------------------------------------------------
# State 3: unmeasured, which is not a gap and not coverage
# ---------------------------------------------------------------------------


def test_an_unmeasurable_control_is_not_rendered_as_zero():
    html = _flat(render_one(_control(
        control_id="PR.XX-9", name="Policy only", score=None,
        state="not_assessable", covered=0, total=0, covered_techniques=[],
        gap_techniques=[],
        reason="No MITRE techniques are mapped to this control.",
    )))
    assert ">not measurable<" in html
    assert "not measured</span>" in html
    # Visible text, not a `title` attribute. The JavaScript put the reason
    # in one, so the only way to learn why a control could not be scored
    # was to hover it, and nobody hovers a row they have read as a zero.
    assert ">No MITRE techniques are mapped to this control.<" in html
    assert ">0%<" not in html
    assert "0 of 0 techniques" not in html


def test_an_unmeasurable_control_never_takes_a_band_colour():
    """The framework is unmeasured here too, which is the only way nothing
    on the page holds a band colour legitimately and the assertion means
    what it says."""
    html = render_one(_control(score=None, state="not_assessable", covered=0,
                               total=0, covered_techniques=[],
                               gap_techniques=[]),
                      overall_score=None, summary=None)
    assert f"color:{UNMEASURED_COLOUR}" in html
    for colour in BAND_COLOURS:
        assert f"color:{colour}" not in html, \
            f"an unmeasurable control took {colour}"


def test_an_unmeasurable_control_is_hatched():
    """The hatch is the one picture no measurement can produce, so an
    absence of measurement is told apart from a bad one at a glance."""
    html = render_one(_control(score=None, state="not_assessable", covered=0,
                               total=0, covered_techniques=[],
                               gap_techniques=[]))
    assert f"background:{UNMEASURED_HATCH}" in html


def test_a_gap_whose_authoring_was_not_determined_claims_neither_answer():
    """The read that would have said "written" or "not written" failed.

    Defaulting to "no rule written" invents the expensive diagnosis and
    defaulting to "written, not running" invents the cheap one. Neither is
    a measurement, so the row says what it is.
    """
    html = _flat(render_one(
        _control(score=0, state="blind", covered=0, total=1,
                 covered_techniques=[], gap_techniques=["T1059"]),
        authored_off=None,
    ))
    assert "no enabled rule, authoring not determined" in html
    assert "no rule written" not in html
    assert "written, not running" not in html
    assert f"background:{UNMEASURED_HATCH}" in html


@pytest.mark.parametrize("coverage", [
    None, {}, {"techniques": {}}, {"inactive_techniques": None},
])
def test_authored_but_disabled_is_none_when_tide_did_not_say(coverage):
    assert authored_but_disabled(coverage) is None


def test_authored_but_disabled_reads_tides_own_label():
    assert authored_but_disabled(
        _coverage(enabled=("T1071",), inactive=("T1059", "T1204"))
    ) == {"T1059", "T1204"}


def test_an_empty_inactive_list_is_a_measurement_not_an_absence():
    """Nothing switched off is a fact TIDE reported. Folding it into None
    would turn every gap on a healthy tenant into "not determined"."""
    assert authored_but_disabled(_coverage(enabled=("T1071",))) == set()


# ---------------------------------------------------------------------------
# State 4: a measured zero is a measurement
# ---------------------------------------------------------------------------


def test_a_control_measured_at_zero_prints_zero_percent():
    """The case a truthiness port gets wrong in the dangerous direction.

    `{% if row.score %}` is false for 0, so a control genuinely measured at
    zero coverage would report "not measured" and drop out of the reader's
    attention entirely.
    """
    html = _flat(render_one(
        _control(score=0, state="blind", covered=0, total=1,
                 covered_techniques=[], gap_techniques=["T1200"]),
        authored_off=set(),
    ))
    assert ">0%</span>" in html
    assert "not measured</span>" not in html
    assert "0 of 1 techniques" in html
    assert "color:var(--sev-critical)" in html


def test_a_framework_measured_at_zero_draws_a_measured_bar():
    html = render(_posture(frameworks=[_framework(
        overall_score=0,
        controls=[_control(score=0, state="blind", covered=0, total=1,
                           covered_techniques=[], gap_techniques=["T1200"])],
    )]), authored_off=set())
    assert "width:0%; background:var(--sev-critical)" in html
    assert f"width:100%; background:{UNMEASURED_HATCH}" not in html
    assert "0%</div>" in html


def test_an_unmeasured_framework_is_hatched_not_a_zero_width_critical_bar():
    """The collapse the JavaScript made on this card.

    It set `pct = scored ? f.overall_score : 0` and then drew the bar with
    `cmpScoreColor(pct)`, so an unmeasured framework got a critical-coloured
    bar at width 0: the same picture a framework measured at 0% produces.
    """
    html = render(_posture(frameworks=[_framework(
        overall_score=None, summary=None, controls=[])]))
    assert f"width:100%; background:{UNMEASURED_HATCH}" in html
    assert "width:0%" not in html
    assert "background:var(--sev-critical)" not in html
    assert "not measured" in html


def test_a_zero_count_in_the_summary_stays_zero():
    card = framework_card(_framework(summary={
        "fully_covered": 0, "partial": 0, "no_coverage": 4,
        "not_assessable": 0, "scored_controls": 4, "total_controls": 4,
    }), "nist_csf")
    assert card["counted"] is True
    assert card["counts"]["fully_covered"] == 0


def test_a_missing_count_is_not_printed_as_zero():
    """The JavaScript read every count as `s.x || 0`, which prints a
    number it never read as a measured zero."""
    card = framework_card(_framework(summary={"scored_controls": 4}),
                          "nist_csf")
    assert card["counts"]["fully_covered"] is None
    html = _flat(render(_posture(frameworks=[
        _framework(summary={"scored_controls": 4})])))
    assert "an unrecorded number / 4 scored controls" in html
    assert "partial not recorded" in html
    assert "0 partial" not in html


def test_a_framework_with_zero_scored_controls_still_has_a_denominator():
    """Zero scored controls is a count, so the counts line renders. It is
    `scored_controls is not none` that decides, not its truthiness."""
    card = framework_card(_framework(summary={
        "fully_covered": 0, "partial": 0, "no_coverage": 0,
        "not_assessable": 5, "scored_controls": 0, "total_controls": 5,
    }), "nist_csf")
    assert card["counted"] is True


# ---------------------------------------------------------------------------
# State 5: accepted risk, which this page has no input for
# ---------------------------------------------------------------------------


def test_the_page_says_accepted_risk_is_not_an_input():
    """ION holds no record of a reviewed and accepted gap, and the
    posture payload has no field for one. Saying so is the only honest
    rendering: without it a reader may take a gap here for one somebody
    has already accepted, or assume an accepted risk would be flagged as
    such and is therefore absent from the gaps.
    """
    html = _flat(render(_posture()))
    assert "Accepted risk is not an input here" in html
    assert "every gap below is an unexamined gap" in html


# ---------------------------------------------------------------------------
# The legend: a state cannot reach a reader without its meaning
# ---------------------------------------------------------------------------


def test_the_legend_explains_every_state_the_table_shows():
    rows = control_rows(_framework(controls=[
        _control(),
        _control(control_id="A", score=50, state="partial", covered=1, total=2,
                 covered_techniques=["T1071"], gap_techniques=["T1200"]),
        _control(control_id="B", score=0, state="blind", covered=0, total=1,
                 covered_techniques=[], gap_techniques=["T1059"]),
        _control(control_id="C", score=None, state="not_assessable", covered=0,
                 total=0, covered_techniques=[], gap_techniques=[]),
    ]), {"T1059"})
    keys = [state["key"] for state in legend_for(rows)]
    assert keys == ["covered", "partial", "written_off", "unmappable"]

    html = render(_posture(frameworks=[_framework(controls=[
        _control(control_id="C", score=None, state="not_assessable", covered=0,
                 total=0, covered_techniques=[], gap_techniques=[])])]))
    assert CONTROL_STATES["unmappable"]["meaning"] in _flat(html)


def test_the_legend_omits_a_state_no_row_is_in():
    html = _flat(render_one(_control()))
    assert CONTROL_STATES["covered"]["meaning"] in html
    assert CONTROL_STATES["unmappable"]["meaning"] not in html


def test_an_unrecognised_service_state_is_named_rather_than_guessed():
    """A state this page has never seen must not be filed under the one it
    resembles. Naming it keeps the reader from reading a guess."""
    html = _flat(render_one(_control(score=70, state="mostly_fine")))
    assert "state not recognised: mostly_fine" in html
    assert f"background:{UNMEASURED_HATCH}" in html


@pytest.mark.parametrize("service_state,kinds,expected", [
    ("covered", set(), "covered"),
    ("partial", {"not_written"}, "partial"),
    ("not_assessable", set(), "unmappable"),
    ("blind", {"written_off"}, "written_off"),
    ("blind", {"not_written"}, "not_written"),
    ("blind", {"written_off", "not_written"}, "part_written"),
    ("blind", {"unknown"}, "unmeasured_gap"),
    (None, set(), "unrecognised"),
])
def test_control_state_maps_each_case(service_state, kinds, expected):
    assert control_state(service_state, kinds) == expected


def test_every_state_in_the_table_has_words_and_a_meaning():
    for key, state in CONTROL_STATES.items():
        assert state["label"], key
        assert state["meaning"], key
        assert "badge" in state["badge"], key


# ---------------------------------------------------------------------------
# No coverage could be computed at all
# ---------------------------------------------------------------------------


def test_an_unavailable_source_lists_the_frameworks_as_unmeasured():
    """The JavaScript rendered "No framework data." here.

    That reads as though the frameworks were missing. They are hardcoded
    and always present; it is their coverage that is unknown, and the two
    lead to opposite actions.
    """
    from ion.services.compliance_mapping_service import list_frameworks

    cards = unmeasured_cards(list_frameworks())
    env = make_templates().env
    html = _flat(env.get_template(FRAGMENT).render(
        failed=False, cards=cards, detail=None, selected_missing=False,
        notice="TIDE not configured",
        availability_note="TIDE is not configured, so no detection coverage "
                          "could be computed for any framework.",
        measures=[], does_not_measure=[], hatch=UNMEASURED_HATCH,
    ))
    assert "No framework data" not in html
    assert "NIST Cybersecurity Framework" in html
    assert html.count("coverage not measured") == len(cards)
    assert "TIDE not configured" in html
    assert "no detection coverage could be computed" in html
    assert "0%</div>" not in html
    assert "No per-control coverage can be shown" in html
    for colour in BAND_COLOURS:
        assert f"color:{colour}" not in html


def test_an_unmeasured_card_is_not_selectable():
    """There is no per-control measurement to drill into, so the card does
    not offer one. A card that swapped in an empty table would read as a
    framework with no controls."""
    from ion.services.compliance_mapping_service import list_frameworks

    cards = unmeasured_cards(list_frameworks())
    assert all(card["selectable"] is False for card in cards)
    env = make_templates().env
    html = env.get_template(FRAGMENT).render(
        failed=False, cards=cards, detail=None, selected_missing=False,
        notice=None, availability_note=None, measures=[],
        does_not_measure=[], hatch=UNMEASURED_HATCH,
    )
    assert "hx-get=\"/ui/compliance/posture?framework=" not in html
    assert "disabled" in html


def test_a_framework_id_that_is_not_in_the_posture_is_said_out_loud():
    html = _flat(render(_posture(), selected="not_a_framework"))
    assert "That framework is not in this posture" in html
    assert "Select a framework above" not in html


# ---------------------------------------------------------------------------
# A failed read is not empty data, and not a compliant posture
# ---------------------------------------------------------------------------


def test_a_failed_read_says_so_and_prints_no_figure_at_all():
    env = make_templates().env
    html = _flat(env.get_template(FRAGMENT).render(
        failed=True, cards=[], detail=None, selected_missing=False,
        notice=None, availability_note=None, measures=[],
        does_not_measure=[], hatch=UNMEASURED_HATCH,
    ))
    assert "could not be read" in html
    assert "not a compliant posture" in html
    assert "cmp-fw-bar" not in html
    assert "stat-value" not in html
    assert "<table" not in html
    assert "%" not in html


def test_the_route_renders_the_failed_fragment_when_the_service_raises(monkeypatch):
    """A read that fails must not reach the browser as a 500, which htmx
    does not swap, leaving the page's spinner turning as if it were still
    loading."""
    import ion.services.compliance_mapping_service as svc

    def _boom(tide):
        raise RuntimeError("TIDE exploded")

    monkeypatch.setattr(svc, "get_all_postures", _boom)
    response = compliance_posture_fragment(request=_request(), framework=None)

    assert response.status_code == 200
    body = _flat(response.body.decode())
    assert "could not be read" in body
    assert "not a compliant posture" in body
    assert "cmp-fw-bar" not in body


# ---------------------------------------------------------------------------
# Wiring: one service, one TIDE read, the API's own permission
# ---------------------------------------------------------------------------


def test_the_route_renders_what_get_all_postures_returned(monkeypatch):
    """Reuse, asserted where it can fail: the route's content has to come
    from the function the JSON endpoint calls, not from a second
    computation of the same thing."""
    import ion.services.compliance_mapping_service as svc
    import ion.services.tide_service as tide_svc

    monkeypatch.setattr(tide_svc, "get_tide_service",
                        lambda: _Tide(_coverage(enabled=("T1071",))))
    monkeypatch.setattr(svc, "get_all_postures", lambda tide: _posture(
        frameworks=[_framework(framework="Sentinel Of Record")]))

    body = compliance_posture_fragment(
        request=_request(), framework="nist_csf").body.decode()
    assert "Sentinel Of Record" in body
    assert "60%" in body


def test_the_gap_split_comes_from_the_same_tide_read_as_the_score(monkeypatch):
    """One read, shared with the posture service.

    A second round trip would be a second sample: the two could disagree,
    and then a gap would be annotated from data the percentage beside it
    was not computed from.
    """
    import ion.services.tide_service as tide_svc

    tide = _Tide(_coverage(enabled=("T1071", "T1572", "T1573", "T1095",
                                    "T1571"),
                           inactive=("T1204", "T1059")))
    monkeypatch.setattr(tide_svc, "get_tide_service", lambda: tide)

    body = compliance_posture_fragment(
        request=_request(), framework="nist_csf").body.decode()

    assert tide.reads == 1, "TIDE was read more than once"
    flat = _flat(body)
    # DE.CM-1's five techniques are all enabled, DE.CM-5's two have rules
    # that are switched off. Both come out of the real service.
    assert ">covered<" in flat
    assert ">written, not running<" in flat
    assert "DE.CM-5" in flat


def test_an_unconfigured_tide_reaches_the_unmeasured_branch(monkeypatch):
    """Not the failure branch. Nothing broke; nothing was measured."""
    import ion.services.tide_service as tide_svc

    monkeypatch.setattr(tide_svc, "get_tide_service",
                        lambda: _Tide(None, enabled=False))
    body = compliance_posture_fragment(
        request=_request(), framework=None).body.decode()
    assert "TIDE not configured" in body
    assert "could not be read" not in body
    assert "coverage not measured" in body
    assert ">0%<" not in body


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
    from ion.web.compliance_api import router as api_router
    from ion.web.ui.compliance import router as ui_router

    api = [r for r in api_router.routes if r.path == "/compliance/posture"]
    ui = [r for r in ui_router.routes if r.path == "/compliance/posture"]
    assert len(api) == 1 and len(ui) == 1

    assert _permissions(ui[0]), "the fragment requires no permission at all"
    assert _permissions(ui[0]) == _permissions(api[0])


# ---------------------------------------------------------------------------
# Escaping, which retires the hand-rolled esc()
# ---------------------------------------------------------------------------


def test_jinja_escapes_what_the_hand_rolled_esc_used_to():
    html = render(_posture(frameworks=[_framework(
        framework="<script>alert(1)</script>",
        version="<img src=x onerror=alert(1)>",
        controls=[_control(
            control_id="<svg onload=alert(2)>",
            name="<b>name</b>",
            score=None, state="not_assessable", covered=0, total=0,
            covered_techniques=[], gap_techniques=[],
            reason="<iframe src=javascript:alert(3)>",
        )],
    )]))
    assert "<script>" not in html
    assert "<img src=x" not in html
    assert "<svg onload" not in html
    assert "<iframe" not in html
    # Markup in a control name is escaped too. Asserted separately because
    # the payloads above are all on other fields, so a `|safe` on this one
    # would have survived every assertion here.
    assert "<b>name</b>" not in html
    assert "&lt;b&gt;name&lt;/b&gt;" in html
    assert "&lt;script&gt;" in html
    assert "&lt;svg onload" in html


def test_a_technique_id_is_escaped_too():
    html = render_one(
        _control(score=0, state="blind", covered=0, total=1,
                 covered_techniques=[], gap_techniques=["<script>x</script>"]),
        authored_off=set(),
    )
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


def test_a_hostile_spec_url_is_not_rendered_as_a_link():
    """safe_url, not Jinja. Escaping handles characters, not schemes, so
    `javascript:` in that field would render a link that executes."""
    html = render(_posture(frameworks=[
        _framework(url="javascript:alert(1)")]))
    assert "javascript:alert" not in html
    assert "official spec" not in html


def test_a_real_spec_url_still_links():
    html = render(_posture())
    assert 'href="https://www.nist.gov/cyberframework"' in html
    assert "official spec" in html


# ---------------------------------------------------------------------------
# The drill-in URL and the page shell
# ---------------------------------------------------------------------------


def test_the_drill_in_url_is_one_value():
    """Built with `~` rather than template text beside a variable, which
    emits `&amp;` for one ampersand and a bare `&` for the other."""
    html = render(_posture(), selected=None)
    assert 'hx-get="/ui/compliance/posture?framework=nist_csf"' in html
    assert "&amp;framework" not in html


def test_the_selected_card_says_which_one_it_is():
    """Both classes on one element, because `.cmp-fw.selected` is what the
    stylesheet accents and a substring search would pass with them apart."""
    selected = re.compile(r'class="[^"]*\bcmp-fw\b[^"]*\bselected\b')

    html = render(_posture())
    assert 'aria-pressed="true"' in html
    assert selected.search(html)

    none_selected = render(_posture(), selected=None)
    assert 'aria-pressed="true"' not in none_selected
    assert not selected.search(none_selected)


def test_the_page_template_builds_no_markup_in_javascript():
    """The redesign's `server` column, asserted where the work was done.

    Counted inside inline `<script>` blocks only, the same way
    tools/ui_redesign_status.py measures it. A bare search of the file would
    hit `hx-swap="innerHTML"`, which is htmx being told where to put
    server-rendered HTML and is the opposite of the thing being removed.
    """
    page = (Path(ion.web.__file__).parent / "templates" / "compliance.html"
            ).read_text(encoding="utf-8")
    inline_js = "".join(
        m.group(1) for m in re.finditer(
            r"<script(?![^>]*src=)[^>]*>(.*?)</script>", page, re.S)
    )
    writes = re.findall(
        r"innerHTML\s*\+?=|insertAdjacentHTML|outerHTML\s*\+?=", inline_js)
    assert writes == []
    assert inline_js.strip() == "", "the page should carry no inline JavaScript"
    assert 'hx-get="/ui/compliance/posture"' in page
    assert 'hx-trigger="load"' in page


def test_the_refresh_control_lives_outside_the_swap_target():
    """A control inside the fragment is removed by any render that omits
    it, so a failed read could take away the button that would retry."""
    page = (Path(ion.web.__file__).parent / "templates" / "compliance.html"
            ).read_text(encoding="utf-8")
    before, _, after = page.partition('<div id="cmp-content"')
    # The button, not the word: the comment above it also says "Refresh",
    # and an earlier version of this test passed on that comment after the
    # button itself had been moved into the fragment.
    assert ">Refresh</button>" in before
    assert "Refresh" not in after
