"""The SOC maturity scorecard, as one server-rendered fragment.

soc_health.html used to fetch /api/soc-health/scorecard and build the whole
page body with `innerHTML`: a conic-gradient grade ring, five dimension
cards, a legend and a recommendations list, 151 lines of inline JavaScript
with a hand-rolled `esc()`. One request renders all of it here, and Jinja
escapes.

The scorecard's contract is that an unmeasured figure is None, an
unavailable dimension reports unavailable rather than a low score, and
`score_basis` records what a score was actually computed from. A port that
leaned on truthiness anywhere would turn every one of those back into a
confident zero, so the colour function is total over None (it cannot return
a healthy colour for an unmeasured score) and the view builders mark each
figure measured or not, rather than leaving the template to infer it.
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.storage.database import get_db_session
from ion.web.ui._shared import templates

logger = logging.getLogger(__name__)

router = APIRouter()

FRAGMENT = "_fragments/soc_health_scorecard.html"

#: Card order and lucide icon, lifted from the JavaScript this replaces.
#: The service returns `dimensions` as a dict, which has no order a reader
#: can rely on, so the order is stated here rather than discovered.
DIMENSIONS: tuple[tuple[str, str], ...] = (
    ("detection_coverage", "shield"),
    ("operational_efficiency", "zap"),
    ("team_readiness", "users"),
    ("knowledge_completeness", "book-open"),
    ("integration_health", "plug"),
)

#: Lower bound of each score band and the CSS custom property it paints
#: with. A table rather than a ladder of ifs so the band edges are readable
#: side by side against GRADE_THRESHOLDS in the service.
GRADE_BANDS: tuple[tuple[int, str], ...] = (
    (80, "var(--mitre-covered)"),
    (65, "var(--quality-good)"),
    (50, "var(--sev-medium)"),
    (35, "var(--sev-high)"),
    (0, "var(--sev-critical)"),
)

#: The colour of a figure nobody measured. Deliberately not in GRADE_BANDS:
#: no score can select it and it can never be read as a grade.
UNMEASURED_COLOUR = "var(--text-muted)"

#: What an overall score means in words, same bands as GRADE_BANDS.
OVERALL_VERDICTS: tuple[tuple[int, str], ...] = (
    (80, "Excellent maturity across all dimensions"),
    (65, "Good maturity with some areas for improvement"),
    (50, "Moderate maturity, several areas need attention"),
    (35, "Below average, significant improvement needed"),
    (0, "Critical, immediate action required across multiple dimensions"),
)

#: Recommendation priority to daisyUI alert/badge suffix. `visibility` is
#: absent on purpose: it is handled as `unseen` below, because a thing ION
#: cannot see is not a ranked finding alongside the ones it measured.
RECOMMENDATION_KINDS = {"high": "error", "medium": "warning"}


def grade_colour(score: int | None) -> str:
    """The colour a score is painted with, total over None.

    Returning a colour for None rather than making every call site guard is
    the point: the template cannot paint an unmeasured dimension green by
    forgetting a branch, because there is no branch to forget.
    """
    if score is None:
        return UNMEASURED_COLOUR
    for floor, colour in GRADE_BANDS:
        if score >= floor:
            return colour
    return GRADE_BANDS[-1][1]


def _verdict(score: int | None) -> str | None:
    if score is None:
        return None
    for floor, words in OVERALL_VERDICTS:
        if score >= floor:
            return words
    return OVERALL_VERDICTS[-1][1]


def _scalar(value: object) -> str:
    """One value inside a nested detail, as text.

    None becomes "unknown", not the string "null". The JavaScript rendered
    a nested null as `String(null)`, which put the literal word "null" on
    the card. No detail nests a None today, so this is a guard rather than
    a fix, but it is the same class of mistake as printing 0.
    """
    if value is None:
        return "unknown"
    if isinstance(value, bool):
        return "yes" if value else "no"
    return str(value)


def _shown(value: object) -> str | None:
    """A detail value as text, or None when the figure was never measured.

    None is returned rather than rendered so the template states
    "not measured" in its own styling. The caller must not substitute a
    default: that is how an unmeasured percentage becomes 0%.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, dict):
        return ", ".join(f"{k}: {_scalar(v)}" for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return ", ".join(_scalar(v) for v in value)
    return str(value)


def detail_rows(details: dict[str, Any] | None) -> list[dict[str, Any]]:
    """A dimension's details as rows, each knowing whether it was measured.

    The JavaScript skipped a null detail outright. That reads as "there is
    nothing to say about this figure" when the truth is "nobody obtained
    it", and on operational_efficiency, which never reports an unavailable
    score, the omitted `avg_mttr_hours` row was the only place a reader
    could have learned that 30% of the score was a neutral stand-in. So a
    None is kept and labelled instead of dropped.

    An empty string is still dropped: that is a field with no content, not
    a measurement that failed.
    """
    rows: list[dict[str, Any]] = []
    for key, value in (details or {}).items():
        if isinstance(value, str) and not value:
            continue
        rows.append({
            "name": key.replace("_", " "),
            "value": _shown(value),
            "measured": value is not None,
        })
    return rows


def dimension_views(card: dict[str, Any]) -> list[dict[str, Any]]:
    """One view dict per dimension card, in the order the page shows them."""
    dimensions = card.get("dimensions") or {}
    views: list[dict[str, Any]] = []
    for key, icon in DIMENSIONS:
        dimension = dimensions.get(key)
        if not dimension:
            continue
        score = dimension.get("score")
        views.append({
            "key": key,
            "icon": icon,
            "label": dimension.get("label"),
            "score": score,
            "measured": score is not None,
            "colour": grade_colour(score),
            "details": detail_rows(dimension.get("details")),
        })
    return views


def overall_view(card: dict[str, Any]) -> dict[str, Any]:
    """The grade ring and the basis note under it.

    `weight_pct` stays None when the service reported no weight basis at
    all. The JavaScript coerced that with `|| 0` and printed "Weighted over
    0% of the scorecard", which claims a denominator it never read. A basis
    of 0.0 is different and does print 0%: that is five dimensions measured
    none of which could be scored, which is a measurement.
    """
    score = card.get("overall_score")
    basis = card.get("weight_basis")
    return {
        "score": score,
        "measured": score is not None,
        "colour": grade_colour(score),
        "grade": card.get("grade"),
        "verdict": _verdict(score),
        "unavailable": [
            name.replace("_", " ")
            for name in (card.get("unavailable_dimensions") or [])
        ],
        "weight_pct": None if basis is None else round(basis * 100),
    }


def recommendation_views(card: dict[str, Any]) -> list[dict[str, Any]]:
    views: list[dict[str, Any]] = []
    for rec in card.get("recommendations") or []:
        priority = rec.get("priority")
        views.append({
            "area": rec.get("area"),
            "message": rec.get("message"),
            "unseen": priority == "visibility",
            "kind": RECOMMENDATION_KINDS.get(priority, "info"),
        })
    return views


@router.get(
    "/soc-health/scorecard",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission("alert:read"))],
)
def soc_health_scorecard_fragment(
    request: Request,
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """The whole scorecard body, as one fragment.

    It calls get_soc_health_scorecard, the function /api/soc-health/scorecard
    calls, so the page and the API cannot disagree about which dimensions
    were measurable. `alert:read` matches that endpoint exactly; a fragment
    must not be a softer way in than the API it mirrors.
    """
    from ion.services.soc_health_service import get_soc_health_scorecard

    try:
        card = get_soc_health_scorecard(session)
    except Exception:
        logger.exception("SOC health scorecard fragment could not be rendered")
        # A failed read is not a SOC that scores zero. The fragment says the
        # read failed and prints no figure at all, because "measured badly"
        # and "we could not look" lead to opposite actions.
        return templates.TemplateResponse(
            request=request,
            name=FRAGMENT,
            context={"failed": True, "overall": None, "dims": [],
                     "recommendations": []},
        )

    return templates.TemplateResponse(
        request=request,
        name=FRAGMENT,
        context={
            "failed": False,
            "overall": overall_view(card),
            "dims": dimension_views(card),
            "recommendations": recommendation_views(card),
            # The legend's "measured" swatch stands for any band colour, so it
            # comes from the band table rather than being written out again in
            # the template, where a change to the bands would leave it stale.
            "measured_swatch": GRADE_BANDS[0][1],
        },
    )
