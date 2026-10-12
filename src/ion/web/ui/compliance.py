"""The compliance posture scorecard, as one server-rendered fragment.

compliance.html used to fetch /api/compliance/posture and build its whole
body with four `innerHTML` writes fed by 142 lines of inline JavaScript:
the framework cards, the drill-in table of controls, the explanatory
banners and the error state, with a hand-rolled `esc()`. One request
renders all of it here, and Jinja escapes.

What moved is not only markup. This page makes compliance claims, so the
states behind it have to stay apart on the way to the reader:

  * covered, every mapped technique has at least one enabled rule;
  * partial, some do and some do not;
  * zero coverage because no rule was ever written;
  * zero coverage because rules exist and nothing has them switched on;
  * not measurable, because no technique is mapped to the control at all;
  * not measured, because TIDE could not be read.

The JavaScript carried three of those six. It painted an unmeasured
control's dash in the critical colour and drew an unmeasured framework's
bar with the critical colour at width 0, so an absent figure looked like a
measured zero; and it put "written but switched off" in the same red badge
as "nobody wrote one", so the cheap fix and the expensive one looked
identical. compliance_mapping_service separates the first pair and
tide_service.get_global_mitre_coverage separates the second. The facts were
there in both payloads and the view dropped them.

Nothing here is a second opinion about coverage. get_all_postures decides
what is covered, what each control's state is and what the percentages are,
exactly as it does for /api/compliance/posture. This module only subdivides
the gaps that function already reported, using the three-state label TIDE
itself publishes.
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse

from ion.auth.dependencies import require_permission
from ion.web.ui._shared import templates

logger = logging.getLogger(__name__)

router = APIRouter()

FRAGMENT = "_fragments/compliance_posture.html"

#: Lower bound of each score band and the token it paints with, lifted from
#: cmpScoreClass/cmpScoreColor in the JavaScript this replaces. The hardcoded
#: hex fallbacks it carried are gone: every token below has a light-mode
#: value, and a fallback hex does not.
SCORE_BANDS: tuple[tuple[int, str], ...] = (
    (80, "var(--mitre-covered)"),
    (40, "var(--sev-medium)"),
    (0, "var(--sev-critical)"),
)

#: The colour of a figure nobody measured. Deliberately not in SCORE_BANDS:
#: no score can select it, and it can never be read as a band.
UNMEASURED_COLOUR = "var(--text-muted)"

#: The one picture a measurement cannot produce. A bar at width 0 is what a
#: control measured at 0% looks like, so an unmeasured figure gets this
#: instead. Applied through `data-ion-style`, which ion-dynamic-styles.js
#: re-scans after every htmx swap, because this page owns no stylesheet.
UNMEASURED_HATCH = (
    "repeating-linear-gradient(135deg, rgba(145, 158, 171, 0.55) 0 4px, "
    "transparent 4px 9px)"
)

#: Every state one control row can be in: the words it shows, its badge
#: treatment, and what it means to a reader. A table rather than a ladder of
#: ifs, so the states a compliance reader has to tell apart are readable
#: side by side, and so the legend can be generated from the same source the
#: rows are rendered from. A row cannot show a state the legend omits.
#:
#: Neither zero-coverage state is softer than the other: nothing is
#: detecting the control either way, and both score 0. The outline says the
#: rule is written, which is a cheaper fix, not a better posture.
CONTROL_STATES: dict[str, dict[str, Any]] = {
    "covered": {
        "label": "covered",
        "badge": "badge-success",
        "hatched": False,
        "meaning": "Every mapped technique has at least one enabled rule.",
    },
    "partial": {
        "label": "partial",
        "badge": "badge-warning",
        "hatched": False,
        "meaning": "Some mapped techniques have an enabled rule and some have none.",
    },
    "not_written": {
        "label": "no detection written",
        "badge": "badge-error",
        "hatched": False,
        "meaning": (
            "Measured at 0%. No rule exists for any uncovered technique, so "
            "the work is to author detections."
        ),
    },
    "written_off": {
        "label": "written, not running",
        "badge": "badge-error badge-outline",
        "hatched": False,
        "meaning": (
            "Measured at 0%. Rules exist for every uncovered technique and "
            "none of them is enabled, so nothing is detecting this control. "
            "Enabling beats authoring, so this is the cheaper 0%."
        ),
    },
    "part_written": {
        "label": "part written, none running",
        "badge": "badge-error badge-outline",
        "hatched": False,
        "meaning": (
            "Measured at 0%. Some uncovered techniques have a rule that is "
            "switched off and the rest have no rule at all."
        ),
    },
    "unmeasured_gap": {
        "label": "no enabled rule, authoring not determined",
        "badge": "badge-ghost",
        "hatched": True,
        "meaning": (
            "Measured at 0% coverage, but TIDE did not say whether rules "
            "exist and are switched off, so which kind of 0% this is was not "
            "determined."
        ),
    },
    "unmappable": {
        "label": "not measurable",
        "badge": "badge-ghost",
        "hatched": True,
        "meaning": (
            "No MITRE technique is mapped to this control, so detection "
            "coverage cannot be computed for it. This is not a gap and not "
            "coverage, and it is excluded from the percentage."
        ),
    },
    "unrecognised": {
        "label": "state not recognised",
        "badge": "badge-ghost",
        "hatched": True,
        "meaning": (
            "The posture service reported a control state this page does not "
            "know. Read it as unmeasured until someone checks."
        ),
    },
}

#: compliance_mapping_service's own control states, in this page's terms.
#: `blind` is absent on purpose: it is one state covering two different
#: problems, and gap_kind below splits it.
SERVICE_STATES: dict[str, str] = {
    "covered": "covered",
    "partial": "partial",
    "not_assessable": "unmappable",
}

#: Why a mapped technique is not covered: the order the row lists the
#: groups in, the words above each group, and the badge its ids wear.
#: Grouped under words rather than separated by colour alone, because a
#: reader must not have to know a colour code to tell "switched off" from
#: "never written".
GAP_GROUPS: tuple[tuple[str, str, str], ...] = (
    ("written_off", "written, not running", "badge-error badge-outline"),
    ("not_written", "no rule written", "badge-error"),
    ("unknown", "authoring not determined", "badge-ghost"),
)

#: The badge a covered technique wears, and the words above that group.
#: "covered by an enabled rule" rather than "covered", because what this
#: page means by covered is the whole question.
COVERED_GROUP = ("covered by an enabled rule", "badge-success badge-outline")

#: The service's availability codes in the page's words. Both mean the
#: figure is absent. Neither means zero coverage.
AVAILABILITY_NOTES: dict[str, str] = {
    "source_not_configured": (
        "TIDE is not configured, so no detection coverage could be computed "
        "for any framework. This is not a posture of zero coverage: nothing "
        "was measured."
    ),
    "source_returned_no_data": (
        "TIDE is configured but returned no coverage data, so no detection "
        "coverage could be computed for any framework. This is not a posture "
        "of zero coverage: nothing was measured."
    ),
}

#: The counts the summary line reads, every one of them present in the view
#: whether the payload had it or not. A missing count renders as not
#: recorded; `summary.get(k)` keeps it None rather than letting Jinja's
#: Undefined render as an empty string, which would read as a blank figure.
SUMMARY_COUNTS: tuple[str, ...] = (
    "fully_covered", "partial", "no_coverage", "not_assessable",
    "scored_controls", "total_controls",
)

_UNREAD = object()


class SingleCoverageRead:
    """The TIDE service, with its global MITRE coverage read at most once.

    get_all_postures asks TIDE for that coverage to decide what is covered.
    The written-but-switched-off split needs the same read. A second round
    trip would be a second DuckDB query and, worse, a second sample: the two
    could disagree, and then this page would annotate a gap the percentage
    beside it was not computed from. One read, shared, cannot.

    Everything else delegates, so the wrapper stays transparent if the
    posture service starts using another part of the TIDE API.
    """

    def __init__(self, tide: Any) -> None:
        self._tide = tide
        self._coverage: Any = _UNREAD

    def __getattr__(self, name: str) -> Any:
        return getattr(self._tide, name)

    def get_global_mitre_coverage(self) -> Any:
        if self._coverage is _UNREAD:
            self._coverage = self._tide.get_global_mitre_coverage()
        return self._coverage


def score_colour(score: int | None) -> str:
    """The colour a percentage is painted with, total over None.

    Returning a colour for None rather than making each call site guard is
    the point. The JavaScript called `cmpScoreColor(ctl.score || 0)`, which
    handed an unmeasured control the critical colour, and the same `|| 0`
    gave an unmeasured framework a critical-coloured bar. Here there is no
    branch to forget, and no score can select UNMEASURED_COLOUR.
    """
    if score is None:
        return UNMEASURED_COLOUR
    for floor, colour in SCORE_BANDS:
        if score >= floor:
            return colour
    return SCORE_BANDS[-1][1]


def authored_but_disabled(coverage: dict | None) -> set[str] | None:
    """Techniques with a rule written and nothing running it, or None.

    tide_service builds this set itself and keeps it apart from its blind
    spots, in its words, "so a reader can tell 'nobody built this' from
    'nobody turned it on'". Absent that key this returns None and every gap
    renders as authoring-not-determined, because guessing would invent the
    cheaper diagnosis for a control that may have no rule at all.
    """
    if not coverage:
        return None
    inactive = coverage.get("inactive_techniques")
    if inactive is None:
        return None
    return set(inactive)


def gap_kind(technique_id: str, authored_off: set[str] | None) -> str:
    """Why one mapped technique is not covered.

    The parent rollup mirrors _score_framework's own `tid in covered or
    parent in covered`. TIDE rolls a sub-technique's rules up to its parent,
    so a sub-technique is judged by the parent's rules on the covered side;
    judging it any other way here would hand a gap a reason the percentage
    beside it disagrees with.
    """
    if authored_off is None:
        return "unknown"
    if technique_id in authored_off:
        return "written_off"
    if technique_id.split(".")[0] in authored_off:
        return "written_off"
    return "not_written"


def control_state(service_state: object, gap_kinds: set[str]) -> str:
    """One control's state key in CONTROL_STATES.

    The service owns covered, partial and not_assessable. Only `blind` is
    subdivided, and only by the reason its own gap techniques carry.
    """
    mapped = SERVICE_STATES.get(service_state)  # type: ignore[arg-type]
    if mapped:
        return mapped
    if service_state != "blind":
        return "unrecognised"
    if gap_kinds == {"unknown"}:
        return "unmeasured_gap"
    if gap_kinds == {"written_off"}:
        return "written_off"
    if gap_kinds == {"not_written"}:
        return "not_written"
    return "part_written"


def _state_view(key: str, service_state: object) -> dict[str, Any]:
    """A state's words and treatment, carried on the row that shows it.

    Resolved here rather than looked up in the template so a row and the
    legend cannot describe the same state differently.
    """
    state = dict(CONTROL_STATES[key])
    state["key"] = key
    if key == "unrecognised":
        state["label"] = f"state not recognised: {service_state}"
    return state


def control_rows(
    framework: dict, authored_off: set[str] | None
) -> list[dict[str, Any]]:
    """One view dict per control, in the order the framework lists them."""
    rows: list[dict[str, Any]] = []
    for control in framework.get("controls") or []:
        grouped: dict[str, list[str]] = {key: [] for key, _, _ in GAP_GROUPS}
        for technique in control.get("gap_techniques") or []:
            grouped[gap_kind(technique, authored_off)].append(technique)

        service_state = control.get("state")
        key = control_state(
            service_state, {k for k, ids in grouped.items() if ids}
        )
        score = control.get("score")
        rows.append({
            "id": control.get("control_id"),
            "name": control.get("name"),
            "score": score,
            "measured": score is not None,
            "colour": score_colour(score),
            "state": _state_view(key, service_state),
            "reason": control.get("reason"),
            "covered": control.get("covered"),
            "total": control.get("total"),
            "covered_techniques": control.get("covered_techniques") or [],
            "covered_label": COVERED_GROUP[0],
            "covered_badge": COVERED_GROUP[1],
            "gaps": [
                {"label": label, "badge": badge, "techniques": grouped[key_]}
                for key_, label, badge in GAP_GROUPS if grouped[key_]
            ],
        })
    return rows


def legend_for(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The state legend, generated from the states the rows actually show.

    Generated rather than written out, so a state cannot reach a reader
    without its meaning reaching them too, and so the legend carries no
    line for a state this table does not contain.
    """
    shown: dict[str, dict[str, Any]] = {}
    for row in rows:
        shown.setdefault(row["state"]["key"], row["state"])
    return [shown[key] for key in CONTROL_STATES if key in shown]


def _counts(summary: dict | None) -> dict[str, Any]:
    """The summary counts, each present and each None when unrecorded.

    The JavaScript read every one of these as `s.x || 0`, which prints a
    count it never read as a measured zero.
    """
    source = summary or {}
    return {key: source.get(key) for key in SUMMARY_COUNTS}


def framework_card(framework: dict, selected_id: str | None) -> dict[str, Any]:
    """One framework card, scored."""
    score = framework.get("overall_score")
    counts = _counts(framework.get("summary"))
    framework_id = framework.get("framework_id")
    return {
        "id": framework_id,
        "name": framework.get("framework"),
        "version": framework.get("version"),
        "url": framework.get("url"),
        "score": score,
        "measured": score is not None,
        "colour": score_colour(score),
        "counts": counts,
        # The denominator decides whether there are counts to show at all.
        # Checked for None rather than truthiness: a framework with zero
        # scored controls has a denominator, and it is zero.
        "counted": counts["scored_controls"] is not None,
        "selected": framework_id is not None and framework_id == selected_id,
        "selectable": True,
    }


def unmeasured_cards(frameworks: list[dict]) -> list[dict[str, Any]]:
    """A card per framework when no coverage could be computed at all.

    The JavaScript rendered "No framework data." here, which reads as
    though the frameworks themselves were missing. They are hardcoded and
    always present; it is their coverage that is unknown. The cards are not
    selectable because there is no per-control measurement to drill into.
    """
    return [
        {
            "id": framework.get("id"),
            "name": framework.get("name"),
            "version": framework.get("version"),
            "url": framework.get("url"),
            "score": None,
            "measured": False,
            "colour": UNMEASURED_COLOUR,
            "counts": _counts(None),
            "counted": False,
            "control_count": framework.get("control_count"),
            "selected": False,
            "selectable": False,
        }
        for framework in frameworks
    ]


@router.get(
    "/compliance/posture",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission("alert:read"))],
)
def compliance_posture_fragment(
    request: Request,
    framework: str | None = Query(None),
) -> HTMLResponse:
    """The framework cards and, when one is selected, its controls.

    It calls get_all_postures, the function /api/compliance/posture calls,
    so the page and the API cannot disagree about what is covered.
    `alert:read` matches that endpoint exactly; a fragment must not be a
    softer way in than the API it mirrors.

    `framework` is the drill-in, which was `_cmpSelected` in JavaScript.
    The cards re-render with their selection because only this render knows
    which one is open; the page's Refresh button sits outside the swap
    target, so no render here, success or failure, can remove the reader's
    way back.
    """
    from ion.services.compliance_mapping_service import (
        get_all_postures,
        list_frameworks,
    )
    from ion.services.tide_service import get_tide_service

    try:
        source = SingleCoverageRead(get_tide_service())
        posture = get_all_postures(source)
        scored = posture.get("frameworks") or []
        if scored:
            cards = [framework_card(f, framework) for f in scored]
            authored_off = authored_but_disabled(
                source.get_global_mitre_coverage()
            )
        else:
            cards = unmeasured_cards(list_frameworks())
            authored_off = None
    except Exception:
        logger.exception("Compliance posture fragment could not be rendered")
        # A failed read is not a posture of zero coverage, and it is not a
        # compliant one either. The fragment says so and prints no figure.
        return templates.TemplateResponse(
            request=request,
            name=FRAGMENT,
            context={
                "failed": True, "cards": [], "detail": None, "notice": None,
                "availability_note": None, "selected_missing": False,
                "measures": [], "does_not_measure": [],
                "hatch": UNMEASURED_HATCH,
            },
        )

    detail = None
    selected = next(
        (f for f in scored if f.get("framework_id") == framework), None
    )
    if selected is not None:
        rows = control_rows(selected, authored_off)
        detail = {
            "framework": framework_card(selected, framework),
            "rows": rows,
            "legend": legend_for(rows),
        }

    return templates.TemplateResponse(
        request=request,
        name=FRAGMENT,
        context={
            "failed": False,
            "cards": cards,
            "detail": detail,
            # A framework id that is not among the scored ones is said out
            # loud rather than falling through to "nothing selected", which
            # is what the JavaScript's `frameworks.find(...)` did. Only
            # claimed when something was scored: with nothing measured the
            # framework is not missing, its coverage is.
            "selected_missing": (
                bool(framework) and selected is None and bool(scored)
            ),
            "notice": posture.get("error"),
            "availability_note": AVAILABILITY_NOTES.get(
                posture.get("availability")
            ),
            # The service ships the wording of what the figure does and does
            # not mean. Rendering its copy rather than a second one in the
            # template is what keeps the two from drifting.
            "measures": posture.get("measures") or [],
            "does_not_measure": posture.get("does_not_measure") or [],
            "hatch": UNMEASURED_HATCH,
        },
    )
