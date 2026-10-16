"""DE Metrics: the six summary tiles and the noise-campaign table.

de_metrics.html fetched /api/de/metrics and built the whole body out of
string concatenation at four innerHTML sites (the loading placeholder, the
load-failure alert, the tiles-plus-table body, and the per-campaign
evidence drill-down) with a hand-rolled `deEsc()` and a `deSlug()` to key
the drill rows. All of it is rendered here, and Jinja escapes.

What this page is read for decides what the port must not lose. A detection
engineer reads it to pick the rule costing the most analyst time, so every
figure on it is a measurement somebody acts on:

  * `0 addressable hours` means the FP closures in this window cost nothing
    worth reclaiming. A missing `addressable_hours` means nobody measured
    it. The JavaScript wrote `s.addressable_hours || 0` and printed a
    confident zero for both, which reads as "this estate has no noise".
  * `0%` Bob agreement means Bob was wrong on every alert an analyst
    scored, which is a reason to stop trusting him. No agreement rate means
    nothing was scored. The JavaScript got the text right and the colour
    wrong: `agree.agreement_rate === null` is false for `undefined`, so an
    absent rate fell through to `>= 80 ? ... : 'crit'` and painted
    "not measured" in the same red as "always wrong".
  * A noise trend is three directions, or unmeasured. `s.noise_trend || {}`
    made an absent trend an empty object, which is truthy, so `if(!t)`
    never fired and the tile rendered a bare "▬ " with no word after it.

Three outcomes, three different renders:

  module off   404, no fragment at all. static/js/htmx-errors.js words it.
               Nothing about the estate's detection noise leaks.
  read failed  200 with a fragment that says the read failed. Never a zero
               and never an empty table: "no rule is wasting analyst time"
               and "we could not measure any rule" lead to opposite
               decisions, and one of them is to leave a rule firing.
  no campaigns 200 with the empty state the JavaScript had.

The gates are the ones /api/de/metrics carries, in the same order:

  * ``require_de_module`` first, because the JSON endpoint gets it from
    ``include_router(de_router, ..., dependencies=[Depends(require_de_module)])``
    and router dependencies resolve before route dependencies. With the
    module off the fragment answers 404 before authentication is
    considered, which is the point: a licence-gated deployment looks
    exactly like one where the endpoint does not exist. A 401 would tell an
    unlicensed caller the feature is there and they are merely not signed
    in.
  * ``require_permission("de:read")`` second, the permission the JSON
    endpoint names. Not ``require_page_permission``: that redirects to
    /login, and htmx would swap a login form into the middle of the page.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import get_current_user, require_permission
from ion.licensing.gating import require_de_module
from ion.models.user import User
from ion.storage.database import get_db_session
from ion.web.ui._shared import plain, templates

logger = logging.getLogger(__name__)

router = APIRouter()

FRAGMENT = "_fragments/de_metrics.html"

#: The permission /api/de/metrics names. Spelled once so the fragment cannot
#: drift into being a softer way in than the endpoint it mirrors.
PERMISSION = "de:read"

#: The permission POST /api/de/proposals/draft and POST /api/de/proposals
#: carry. The fragment is gated on PERMISSION, not this: the panel is a
#: read. This only decides whether the Draft proposal button is offered,
#: because a button whose POST is going to answer 403 is a worse answer
#: than no button. The JavaScript offered it to every reader.
PROPOSE_PERMISSION = "de:propose"

#: Emphasis to the class that paints it. "" is the resting colour, which an
#: unmeasured figure keeps: unknown is not an alarm, and it is not good news
#: either. The tile says "unknown" in words instead.
STAT_COLOURS = {
    "crit": "text-error",
    "warn": "text-warning",
    "good": "text-success",
    "": "text-primary",
}

#: Lower bound of a tile's emphasis bands and the emphasis each paints.
#: First match wins, so the strongest band is first. Lifted from the
#: conditional expressions in the six deStat() calls this replaces.
RESTING_BANDS: tuple[tuple[float, str], ...] = ((0.0, ""),)
#: Eight addressable hours is a working day of analyst time.
HOURS_BANDS: tuple[tuple[float, str], ...] = ((8.0, "warn"), (0.0, ""))
#: Any campaign at all is worth looking at; none is the resting state.
COUNT_BANDS: tuple[tuple[float, str], ...] = ((1.0, "warn"), (0.0, ""))
AGREEMENT_BANDS: tuple[tuple[float, str], ...] = (
    (80.0, "good"),
    (60.0, "warn"),
    (0.0, "crit"),
)

#: Direction to the arrow and colour it is shown with. A membership lookup
#: rather than a chain of equality tests, so a direction the service starts
#: emitting that is not in here renders as unmeasured instead of as a bare
#: arrow with no word after it.
TREND_STYLES: dict[str, dict[str, str]] = {
    "rising": {"arrow": "▲", "colour": "text-error"},
    "falling": {"arrow": "▼", "colour": "text-success"},
    "flat": {"arrow": "▬", "colour": "opacity-50"},
}

#: Severity label to the badge that paints it. `high` and `medium` share
#: badge-warning, which is what deSevBadge() did; the port is not the place
#: to change what a severity looks like.
SEVERITY_BADGES: dict[str, str] = {
    "critical": "badge-error",
    "crit": "badge-error",
    "high": "badge-warning",
    "medium": "badge-warning",
    "med": "badge-warning",
    "low": "badge-info",
    "info": "badge-info",
    "informational": "badge-info",
}

#: How many MITRE techniques a row shows, from `.slice(0,6)`. A campaign can
#: union up to 20 and the cell has to stay a cell.
MITRE_SHOWN = 6


def _trim(value: Any) -> Any:
    """A number as the JavaScript printed it.

    The service rounds to one decimal, so a whole value arrives as 12.0.
    JSON made that a JavaScript 12 and the tile read "12"; Python would
    render "12.0". Cosmetic, but the port is meant to be invisible, and a
    reader comparing this page against the JSON should not have to decide
    whether the digits changed meaning. Anything that is not a real number
    passes through untouched, including None and bool.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return value
    return int(value) if float(value) == int(value) else value


def _band(value: Any, bands: tuple[tuple[float, str], ...]) -> str:
    """The emphasis a figure earns, or none at all when it has no figure.

    Anything that is not a real number resolves to the resting emphasis
    rather than falling through the comparisons. This is the defect in
    `agreeCls`: `undefined >= 80` is false, so an unmeasured agreement rate
    reached the last branch and was painted in the same red as a rate
    measured at zero.

    One condition, not a `value is None` check in front of it. A mutation
    pass removed that check and nothing went red, because None is not an int
    or a float either, so the clause was a second way of saying the same
    thing and a reader would have taken it for the only guard on None.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return ""
    for floor, emphasis in bands:
        if float(value) >= floor:
            return emphasis
    return ""


def number_tile(label: str, value: Any,
                bands: tuple[tuple[float, str], ...],
                sub: Optional[str], suffix: str = "") -> dict[str, Any]:
    """One stat tile whose body is a number.

    `value` stays None when the summary did not carry the figure, and the
    template renders "unknown" for it. It is never defaulted to 0: on this
    panel a zero is the finding that there is no noise to reclaim.
    """
    return {
        "kind": "number",
        "label": label,
        "value": _trim(value),
        "suffix": suffix,
        "colour": STAT_COLOURS[_band(value, bands)],
        "sub": sub,
    }


def trend_tile(trend: Any) -> dict[str, Any]:
    """The noise-trend tile: an arrow, the direction, and the delta.

    Unknown when there is no trend block, when it carries no direction, or
    when the direction is not one this page knows how to draw. The
    JavaScript's `!t` guard could not reach any of those, because
    `s.noise_trend || {}` had already turned a missing trend into a truthy
    empty object, so the tile rendered an arrow with nothing after it.

    `delta_pct` is None when the older half of the window had no closures
    at all, which is not a change of 0%: there was nothing to change from.
    The sign is formatted here because it is arithmetic, not markup.
    """
    block = trend if isinstance(trend, dict) else {}
    direction = block.get("direction")
    style = TREND_STYLES.get(direction) if isinstance(direction, str) else None

    delta = block.get("delta_pct")
    shown = None
    if delta is not None and not isinstance(delta, bool) and isinstance(
        delta, (int, float)
    ):
        trimmed = _trim(delta)
        shown = f"+{trimmed}%" if float(delta) > 0 else f"{trimmed}%"

    return {
        "kind": "trend",
        "label": "Noise trend",
        "sub": "recent vs older half",
        "colour": STAT_COLOURS[""],
        "known": style is not None,
        "direction": direction,
        "arrow": style["arrow"] if style else None,
        "arrow_colour": style["colour"] if style else None,
        "delta": shown,
    }


def scored_sub(scored: Any) -> str:
    """The Bob-agreement tile's sub-line.

    `(agree.scored || 0) + ' scored'` printed "0 scored" for a count that
    never arrived, which is the one number on this tile that says whether
    the rate above it means anything.
    """
    if scored is None:
        return "scored count unknown"
    return f"{scored} scored"


def stat_tiles(summary: Any) -> list[dict[str, Any]]:
    """The six tiles, in the order the page shows them.

    One line per tile, which is the list of deStat() calls it replaces.
    """
    data = summary if isinstance(summary, dict) else {}
    agreement = data.get("bob_agreement")
    agreement = agreement if isinstance(agreement, dict) else {}
    return [
        number_tile("Addressable hours", data.get("addressable_hours"),
                    HOURS_BANDS, "reclaimable if resolved"),
        number_tile("FP alerts", data.get("total_fp_alerts"),
                    RESTING_BANDS, "closed as FP/benign"),
        number_tile("Noise campaigns", data.get("campaign_count"),
                    COUNT_BANDS, "rules ≥ min cluster"),
        number_tile("Top campaign", data.get("top_reclaimable_hours"),
                    RESTING_BANDS, data.get("noisiest_rule") or "—"),
        trend_tile(data.get("noise_trend")),
        number_tile("Bob agreement", agreement.get("agreement_rate"),
                    AGREEMENT_BANDS, scored_sub(agreement.get("scored")),
                    suffix="%"),
    ]


def severity_badge(name: Any) -> str:
    """The badge class for a severity label.

    `plain` first: AlertCase.severity is free text out of Elasticsearch
    today, but ION keeps severity as a SQLEnum elsewhere, and a payload
    whose severity mix is keyed by enum members would render
    "Severity.HIGH 4" in the cell while the colour lookup still matched on
    value equality. That is the failure mode two earlier conversions hit,
    and it survives a glance because only the visible text is wrong.
    """
    return SEVERITY_BADGES.get(str(plain(name) or "").lower(), "badge-ghost")


def closure_split(false_positive: Any, benign: Any) -> Optional[str]:
    """The "12 FP + 3 benign" breakdown under an FP-alert count, or None.

    Shown only when there is a benign share to break out, which is what
    `c.benign_true_positive ? ... : ''` did: with no benign closures the
    split would read "12 FP + 0 benign" and restate the number above it.

    Both halves have to be present, because the JavaScript checked only the
    benign one and would have rendered "undefined FP + 3 benign" for a
    campaign missing its false-positive count. Text, not markup: the
    numbers are escaped by the template like anything else.
    """
    if benign is None or not isinstance(benign, (int, float)) or benign <= 0:
        return None
    if false_positive is None or not isinstance(false_positive, (int, float)):
        return None
    return f"{_trim(false_positive)} FP + {_trim(benign)} benign"


def campaign_row(index: int, campaign: Any) -> dict[str, Any]:
    """One noise campaign as the table and its drill-down row need it.

    `index` keys the drill-down row instead of deSlug()'s
    `rule_name.replace(/[^a-zA-Z0-9]/g,'_')`. A slug collapses distinct
    rule names onto one id: "Suspicious PowerShell" and
    "Suspicious-PowerShell" both slugged to the same string, so the
    Evidence button on the second row opened the first row's panel.
    """
    data = campaign if isinstance(campaign, dict) else {}
    mix = data.get("severity_mix")
    mix = mix if isinstance(mix, dict) else {}
    return {
        "index": index,
        "rule_name": data.get("rule_name"),
        "fp_alerts": data.get("fp_alerts"),
        "split": closure_split(data.get("false_positive"),
                               data.get("benign_true_positive")),
        "case_count": data.get("case_count"),
        "cost_hours": _trim(data.get("cost_hours")),
        # Handed to the `ts` macro exactly as the service emitted it.
        # ion.web.templating._ts_parts owns the question of whether a value
        # carries a zone, and parsing here first gave that question a second
        # answer: the parse dropped a "Z" instead of reading it, so a
        # UTC-labelled instant arrived at the macro as a zoneless one, was
        # marked "server time, no timezone", and lost the localisation it had
        # every right to. The service emits naive strings today, so that was
        # latent rather than live, and it was still a second definition of the
        # one decision the macro exists to centralise.
        "first_seen": data.get("first_seen"),
        "last_seen": data.get("last_seen"),
        # `plain` on the label as well as on the badge lookup. The badge
        # kept working on value equality while the cell rendered
        # "Severity.HIGH 20", which is exactly why this one survives a
        # glance: only the visible text is wrong.
        "severity": [
            {"label": plain(label), "count": count,
             "badge": severity_badge(label)}
            for label, count in mix.items()
        ],
        "mitre": list(data.get("mitre_techniques") or [])[:MITRE_SHOWN],
        "signatures": list(data.get("top_signatures") or []),
        "hosts": list(data.get("top_hosts") or []),
        "sample_alert_ids": list(data.get("sample_alert_ids") or []),
    }


def campaign_rows(payload: Any) -> list[dict[str, Any]]:
    """Every campaign as a row, costliest first as the service sorted them."""
    data = payload if isinstance(payload, dict) else {}
    return [campaign_row(i, c)
            for i, c in enumerate(data.get("campaigns") or [])]


@router.get(
    "/de-metrics",
    response_class=HTMLResponse,
    dependencies=[
        Depends(require_de_module),
        Depends(require_permission(PERMISSION)),
    ],
)
def de_metrics_fragment(
    request: Request,
    days: int = Query(90, ge=1, le=365, description="Lookback window in days"),
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """The tiles and the noise-campaign table as one fragment.

    Calls `get_de_metrics`, which is the whole body of GET /api/de/metrics,
    so the page and the API cannot disagree about which rule is costliest
    or what the trend is doing. Nothing was extracted into a `*_payload()`
    helper because there is nothing inline in that route to share: it is
    one call and a return.

    `days` is bounded exactly as that endpoint bounds it, so a window the
    API would refuse is not reachable through the page.
    """
    from ion.services.de_metrics_service import get_de_metrics

    can_propose = bool(
        current_user and current_user.has_permission(PROPOSE_PERMISSION)
    )
    try:
        payload = get_de_metrics(session, days=days)
    except Exception:
        logger.exception("DE metrics fragment could not be rendered")
        # Not an estate with no noise. The fragment says the read failed and
        # prints no figure at all, because "no rule is wasting analyst time"
        # and "we could not measure any rule" lead to opposite decisions.
        # The window comes from the request so the card keeps its heading.
        return templates.TemplateResponse(
            request=request,
            name=FRAGMENT,
            context={
                "failed": True,
                "tiles": [],
                "campaigns": None,
                "period_days": days,
                "minutes_per_alert": None,
                "can_propose": can_propose,
            },
            status_code=200,
        )

    settings = payload.get("settings")
    settings = settings if isinstance(settings, dict) else {}
    # `is None`, not `or`. The window is a number on the card's heading, and
    # `payload.get("period_days") or days` is the same truthiness bug as
    # `|| 0` with the sign flipped: a payload reporting a window of 0 would be
    # relabelled with the window that was asked for instead.
    reported_days = payload.get("period_days")
    return templates.TemplateResponse(
        request=request,
        name=FRAGMENT,
        context={
            "failed": False,
            "tiles": stat_tiles(payload.get("summary")),
            "campaigns": campaign_rows(payload),
            "period_days": days if reported_days is None else reported_days,
            # The rate the addressable hours were costed at. The JavaScript
            # fell back to the literal 10, so a deployment that had set
            # ION_DE_MINUTES_PER_ALERT to 20 was told its hours came from a
            # rate that was not the one used to compute them.
            "minutes_per_alert": _trim(settings.get("minutes_per_alert")),
            "can_propose": can_propose,
        },
    )
