"""The SOC maturity assessment, as three server-rendered fragments.

maturity.html used to build its whole body with eight `innerHTML` writes fed
by 220 lines of inline JavaScript: the assessment history table, the
questionnaire, the scored result with its conic-gradient ring and per-domain
bars, the empty state, two spinners and two error states, all through a
hand-rolled `matEsc`. Three GET fragments render all of that here, and Jinja
escapes.

What moved is more than markup. This page scores the SOC's own maturity on
the SOC-CMM 1-to-5 scale, and the JavaScript collapsed "not assessed" into
"assessed badly" in five separate places:

  * `scoreColor(s)` fell through every `s >= n` comparison for None and
    returned the critical colour, so an unmeasured score was painted the
    same red as a SOC genuinely sitting at level 1.
  * `const pct = a.overall_score * 20` is 0 for None, so an unmeasured
    overall drew exactly the 0% ring a stored 0 draws.
  * `width:${score.pct}%` with pct None emitted invalid CSS, so the bar sat
    at width 0, which is what a domain measured at 0% looks like.
  * the history table read every domain as `(s.business||{}).score||'-'`.
    That prints a domain genuinely scored 0 as a dash meaning not assessed,
    and prints an absent domain as the same dash, so the two collapse in
    both directions at once.
  * `a.overall_score >= 3 ? 'badge-warning' : 'badge-error'` handed an
    unmeasured overall the error badge.

So `score_colour` and `score_badge` are total over None and cannot return a
band value for it, the view builders mark each figure measured or not rather
than leaving the template to infer it, and an unmeasured figure is drawn
with a hatch, which is the one picture no measurement can produce.

Nothing here is a second opinion about maturity. maturity_service owns the
questionnaire, the scoring and the stored shape, exactly as it does for
/api/maturity/*; this module only decides how each figure is drawn and
whether it was measured at all.

`ui._shared.plain` has no site on this page: MaturityAssessment carries no
SQLEnum column, `overall_level` being a plain String(30) written from
MATURITY_LEVELS.
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.storage.database import get_db_session
from ion.web.ui._shared import templates

logger = logging.getLogger(__name__)

router = APIRouter()

HISTORY_FRAGMENT = "_fragments/maturity_history.html"
QUESTIONNAIRE_FRAGMENT = "_fragments/maturity_questionnaire.html"
RESULT_FRAGMENT = "_fragments/maturity_result.html"

#: The top of the SOC-CMM scale. The ring is drawn as a share of it, so one
#: constant rather than a `* 20` whose 20 nobody can trace.
MAX_LEVEL = 5

#: Lower bound of each band, the colour it paints with and the badge it
#: wears, lifted from `scoreColor` and the `lvlBadge` ladder in the
#: JavaScript this replaces. One table rather than two ladders, because the
#: two had the same edges wherever they disagreed about nothing: a level 2
#: took the high colour and the error badge in both.
#:
#: The floor is 0, not 1, so a stored 0 selects a band and is drawn. 0 is off
#: the SOC-CMM scale but it is still a number somebody wrote down, and the
#: whole point of this module is that it must not look like an absent one.
#:
#: The hex fallbacks the JavaScript carried (`var(--primary,#58a6ff)`) are
#: gone: every token below has a light-mode value and a fallback hex does not.
SCORE_BANDS: tuple[tuple[int, str, str], ...] = (
    (5, "var(--mitre-covered)", "badge-success"),
    (4, "var(--primary)", "badge-info"),
    (3, "var(--sev-medium)", "badge-warning"),
    (2, "var(--sev-high)", "badge-error"),
    (0, "var(--sev-critical)", "badge-error"),
)

#: The colour and badge of a figure nobody assessed. Deliberately not in
#: SCORE_BANDS: no score can select either, so neither can ever be read as a
#: maturity level.
UNMEASURED_COLOUR = "var(--text-muted)"
UNMEASURED_BADGE = "badge-ghost"

#: The one picture a measurement cannot produce. A ring stopping at 0% and a
#: bar at width 0 are what a stored 0 looks like, so an unassessed figure
#: gets this instead. Applied through `data-ion-style`, which
#: ion-dynamic-styles.js re-scans after every htmx swap, because the hatch
#: has no class of its own under `body[data-page="maturity"]` and this
#: conversion does not own the stylesheet.
UNMEASURED_HATCH = (
    "repeating-linear-gradient(135deg, rgba(145, 158, 171, 0.55) 0 4px, "
    "transparent 4px 9px)"
)

#: What "n/a" means, said once and shown as permanent furniture under the
#: history table rather than as a tooltip. A reader must not have to hover to
#: learn that a blank cell is not a zero.
UNMEASURED_NOTE = (
    "n/a means that domain was not assessed. That is not the same as a "
    "score of 0, and a domain scored 0 shows 0."
)


def score_colour(score: int | None) -> str:
    """The colour a maturity score is painted with, total over None.

    Returning a colour for None rather than making each call site guard is
    the point: no template branch can paint an unassessed figure a healthy
    colour by being forgotten, because there is no branch to forget.
    """
    if score is None:
        return UNMEASURED_COLOUR
    for floor, colour, _ in SCORE_BANDS:
        if score >= floor:
            return colour
    return SCORE_BANDS[-1][1]


def score_badge(score: int | None) -> str:
    """The badge a maturity score wears, total over None, same bands."""
    if score is None:
        return UNMEASURED_BADGE
    for floor, _, badge in SCORE_BANDS:
        if score >= floor:
            return badge
    return SCORE_BANDS[-1][2]


def ring_pct(score: int | None) -> int | None:
    """The share of the scale a score fills, or None when unassessed.

    None rather than 0, so the template has to choose the hatch. The
    JavaScript's `a.overall_score * 20` is 0 for None, which is the one
    arithmetic result a stored 0 also produces.
    """
    if score is None:
        return None
    return round(score / MAX_LEVEL * 100)


def _domain_view(domain: dict[str, Any], entry: object) -> dict[str, Any]:
    """One domain's figures, each knowing whether it was assessed.

    `score` and `pct` are read independently. A stored row holding one and
    not the other is a real shape, and substituting either from the other
    would be this module inventing a measurement.
    """
    scored = entry if isinstance(entry, dict) else {}
    score = scored.get("score")
    pct = scored.get("pct")
    return {
        "id": domain.get("id"),
        "name": domain.get("name"),
        "description": domain.get("description"),
        "score": score,
        "measured": score is not None,
        "colour": score_colour(score),
        "badge": score_badge(score),
        "pct": pct,
        "pct_measured": pct is not None,
        # True only when the stored scores carried this domain at all. An
        # absent domain and a domain stored with a null score both render as
        # unassessed, but only the first is the questionnaire having grown a
        # domain since the assessment was taken, which is worth saying.
        "present": isinstance(entry, dict),
        "known": True,
    }


def domain_views(
    domains: list[dict[str, Any]], scores: object
) -> list[dict[str, Any]]:
    """One view per questionnaire domain, in the questionnaire's own order.

    Ordered from `domains` rather than from the stored dict, which has no
    order a reader can rely on, so the history table's header and its cells
    come from one source and cannot drift apart.
    """
    stored = scores if isinstance(scores, dict) else {}
    return [_domain_view(d, stored.get(d.get("id"))) for d in domains]


def retired_domain_views(
    domains: list[dict[str, Any]], scores: object
) -> list[dict[str, Any]]:
    """Scored domains the questionnaire no longer has.

    The history table drops these: its columns are the current questionnaire
    and widening them per row would make the table unreadable. The result
    view shows them, labelled, because a figure that was measured and stored
    must not vanish because the questionnaire moved on. The JavaScript showed
    them in the result too, via `|| {name: domainId}`, and dropped them from
    the history table without saying so.
    """
    stored = scores if isinstance(scores, dict) else {}
    known = {d.get("id") for d in domains}
    return [
        dict(_domain_view({"id": key, "name": key}, entry), known=False)
        for key, entry in stored.items()
        if key not in known
    ]


def assessment_view(
    assessment: dict[str, Any], domains: list[dict[str, Any]]
) -> dict[str, Any]:
    """One stored assessment, scored and drawn.

    Used by both the history table and the result panel, so a row and the
    panel it opens cannot disagree about what was measured.
    """
    score = assessment.get("overall_score")
    scores = assessment.get("scores")
    return {
        "id": assessment.get("id"),
        "title": assessment.get("title"),
        "created_at": assessment.get("created_at"),
        "created_by": assessment.get("created_by_username"),
        "notes": assessment.get("notes"),
        # An empty level is folded to None here so the template has one
        # absence to test. A blank string is not a maturity level either.
        "level": assessment.get("overall_level") or None,
        "score": score,
        "measured": score is not None,
        "colour": score_colour(score),
        "badge": score_badge(score),
        "ring_pct": ring_pct(score),
        "domains": domain_views(domains, scores),
        "retired": retired_domain_views(domains, scores),
    }


def level_views(levels: object) -> list[dict[str, Any]]:
    """The 1-to-5 scale strip above the questionnaire.

    Built from maturity_service's own MATURITY_LEVELS rather than from the
    second copy of the five names the JavaScript hardcoded, and coloured from
    SCORE_BANDS so a level's colour on the strip is the colour the result
    ring paints that same level with.

    Sorted by level rather than taken in dict order: a scale printed out of
    order is worse than no scale.
    """
    source = levels if isinstance(levels, dict) else {}
    out: list[dict[str, Any]] = []
    for key in sorted(source, key=lambda k: int(k)):
        info = source[key] if isinstance(source[key], dict) else {}
        level = int(key)
        out.append({
            "level": level,
            "name": info.get("name"),
            "description": info.get("description"),
            "colour": score_colour(level),
        })
    return out


def question_views(domains: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The questionnaire, one view per domain."""
    return [
        {
            "id": domain.get("id"),
            "name": domain.get("name"),
            "description": domain.get("description"),
            "pages": domain.get("ion_pages") or [],
            "questions": [
                {
                    "id": question.get("id"),
                    "text": question.get("text"),
                    "guidance": question.get("guidance"),
                }
                for question in domain.get("questions") or []
            ],
        }
        for domain in domains
    ]


def _levels() -> list[dict[str, Any]]:
    """Every selectable score with its band colour, for the buttons.

    The colours also go onto each domain's running-average element as
    `data-colour-l1` through `data-colour-l5`. That is what lets the live
    average a user watches while filling the form take its colour from
    SCORE_BANDS rather than from a second copy of the band table in
    JavaScript, which is the duplicate that would keep emitting the old
    colours after a band moved.
    """
    return [
        {"level": n, "colour": score_colour(n)}
        for n in range(1, MAX_LEVEL + 1)
    ]


def _chrome() -> dict[str, Any]:
    """Context every fragment needs, including on its failure branch.

    The hatch and the scale are furniture, not data, so they are present
    whether the read succeeded or not: an error branch that loses them would
    render a legend with no swatch in it.
    """
    return {
        "hatch": UNMEASURED_HATCH,
        "unmeasured_note": UNMEASURED_NOTE,
        "max_level": MAX_LEVEL,
        # The legend's "assessed" swatch stands for any band colour, so it
        # comes from the band table rather than being written out again in
        # the template, where a change to the bands would leave it stale.
        "measured_swatch": SCORE_BANDS[0][1],
    }


@router.get(
    "/maturity/history",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission("alert:read"))],
)
def maturity_history_fragment(
    request: Request,
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """Every stored assessment, newest first, or the empty state.

    It calls maturity_service.list_assessments and get_questionnaire, the
    functions /api/maturity/assessments and /api/maturity/questionnaire call,
    so the table and the API cannot disagree about what was scored or which
    domains exist. `alert:read` matches both endpoints exactly; a fragment
    must not be a softer way in than the API it mirrors.
    """
    from ion.services import maturity_service

    try:
        domains = maturity_service.get_questionnaire()["domains"]
        rows = [
            assessment_view(a, domains)
            for a in maturity_service.list_assessments(session)
        ]
    except Exception:
        logger.exception("Maturity history fragment could not be rendered")
        # A failed read is not a SOC with no assessments and not a SOC that
        # scores badly. The fragment says so and prints no figure at all.
        return templates.TemplateResponse(
            request=request,
            name=HISTORY_FRAGMENT,
            context={"failed": True, "rows": [], "columns": [], **_chrome()},
        )

    return templates.TemplateResponse(
        request=request,
        name=HISTORY_FRAGMENT,
        context={
            "failed": False,
            "rows": rows,
            # The header comes from the same domain list the cells do, so a
            # questionnaire change cannot leave a column labelled one domain
            # and filled from another.
            "columns": [{"id": d.get("id"), "name": d.get("name")}
                        for d in domains],
            **_chrome(),
        },
    )


@router.get(
    "/maturity/questionnaire",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission("alert:read"))],
)
def maturity_questionnaire_fragment(request: Request) -> HTMLResponse:
    """The blank questionnaire, ready to score.

    It calls maturity_service.get_questionnaire, the function
    /api/maturity/questionnaire calls, so the form cannot offer a question
    the scorer does not know about. `alert:read` matches that endpoint
    exactly.

    Submitting is still a `fetch` in the page, because POST
    /api/maturity/assessments takes the scores as nested JSON and is gated on
    `alert:triage`, a stricter permission than this read. It writes no markup:
    on success it re-requests the result fragment through htmx.
    """
    from ion.services import maturity_service

    try:
        questionnaire = maturity_service.get_questionnaire()
        context: dict[str, Any] = {
            "failed": False,
            "domains": question_views(questionnaire["domains"]),
            "levels": level_views(questionnaire.get("maturity_levels")),
            "buttons": _levels(),
        }
    except Exception:
        logger.exception("Maturity questionnaire fragment could not be rendered")
        context = {"failed": True, "domains": [], "levels": [], "buttons": []}

    return templates.TemplateResponse(
        request=request,
        name=QUESTIONNAIRE_FRAGMENT,
        context={**context, **_chrome()},
    )


@router.get(
    "/maturity/assessments/{assessment_id}",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission("alert:read"))],
)
def maturity_result_fragment(
    request: Request,
    assessment_id: int,
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """One stored assessment's scored result: the ring and the domain cards.

    It calls maturity_service.get_assessment, the function
    /api/maturity/assessments/{id} calls, so the panel shows what was stored
    rather than what the submitting browser believed it had sent.
    `alert:read` matches that endpoint exactly.

    A missing assessment raises 404 like the JSON endpoint rather than
    rendering a per-page "not found" panel. static/js/htmx-errors.js already
    owns the wording for a 404 ("This is no longer available. It may have
    been deleted since the page was opened."), and a second copy here would
    be a second definition of what a stale id means.
    """
    from ion.services import maturity_service

    try:
        domains = maturity_service.get_questionnaire()["domains"]
        assessment = maturity_service.get_assessment(session, assessment_id)
    except Exception:
        logger.exception("Maturity result fragment could not be rendered")
        # Not an assessment that scored zero, and not a missing one either.
        return templates.TemplateResponse(
            request=request,
            name=RESULT_FRAGMENT,
            context={"failed": True, "assessment": None, **_chrome()},
        )

    if assessment is None:
        raise HTTPException(status_code=404, detail="Assessment not found")

    return templates.TemplateResponse(
        request=request,
        name=RESULT_FRAGMENT,
        context={
            "failed": False,
            "assessment": assessment_view(assessment, domains),
            **_chrome(),
        },
    )
