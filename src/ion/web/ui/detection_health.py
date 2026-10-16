"""Per-rule detection health, as two server-rendered fragments.

detection_health.html used to fetch /api/detection-health/metrics and build
the whole body with `innerHTML`: five stat tiles, a per-rule table with two
inline bar charts per row, flag badges, a drill-down row per rule and an
unmapped-alerts note, 133 lines of inline JavaScript with a hand-rolled
`esc()`. A fourth write built the Bob-vs-analyst drill-down. Both are
rendered here, and Jinja escapes.

What this page is read for decides what the port must not lose. An engineer
reads a rule's false-positive rate to decide whether to tune the rule,
disable it, or leave it alone, so the three answers the table can give have
to stay three:

  * a rate of 0 is a measurement and renders a bar at zero width,
  * a rate that could not be computed renders a dash and no bar,
  * a rate computed from too few closures to mean anything says so.

The JavaScript got the first two right (`pct === null || pct === undefined`
in dhPctCell) and the third not at all: a 100% false-positive rate from one
closed alert rendered identically to one from five hundred, while the
service will not flag a rule `noisy` until it has `min_sample` closures. So
a rule the service declined to judge looked, in the one column an engineer
acts on, exactly like a rule it had judged clean.

The red band on the false-positive bar is taken from the same
`noisy_fp_pct` threshold the service flags `noisy` with, rather than the 70
the JavaScript hard-coded, so the bar's colour and the badge beside it
cannot disagree after someone sets ION_DH_NOISY_FP_PCT.
"""
from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import get_current_user, require_permission
from ion.models.user import User
from ion.storage.database import get_db_session
from ion.web.ui._shared import templates

logger = logging.getLogger(__name__)

router = APIRouter()

FRAGMENT = "_fragments/detection_health.html"
DISAGREEMENTS_FRAGMENT = "_fragments/detection_health_disagreements.html"

#: The permission both reads carry. One name, so the two fragments and the
#: two JSON endpoints they mirror cannot drift apart one at a time.
READ_PERMISSION = "security:read"

#: The permission the tuning-proposal POST carries. The fragment is gated on
#: READ_PERMISSION, not this: the panel is a read. This is only what decides
#: whether the Propose tuning button is offered, because a button whose POST
#: is going to answer 403 is a worse answer than no button.
PROPOSE_PERMISSION = "de:propose"

#: Summary key, tile label, and the emphasis a non-zero count earns. Stated
#: here rather than in the template so the reading order of the tiles is one
#: decision, and lifted from the five dhStat() calls it replaces.
SUMMARY_TILES: tuple[tuple[str, str, str], ...] = (
    ("rules_tracked", "Rules Tracked", ""),
    ("total_closed", "Closed Alerts", ""),
    ("noisy_rules", "Noisy Rules", "crit"),
    ("silent_rules", "Silent Rules", "warn"),
    ("decaying_rules", "Decaying Rules", "warn"),
)

#: Emphasis to the class that paints it. "" is the resting colour, which a
#: count of zero keeps: zero noisy rules is good news, not an alarm.
STAT_COLOURS = {"crit": "text-error", "warn": "text-warning", "": "text-primary"}

#: Flag key, badge class and label, in the order the badges are shown.
FLAG_BADGES: tuple[tuple[str, str, str], ...] = (
    ("noisy", "badge-error", "noisy"),
    ("silent", "badge-warning", "silent"),
    ("decaying", "badge-secondary", "decaying"),
)

#: Lower bound of the true-positive-yield bands and the colour each paints.
#: First match wins, so the strictest band is first.
TP_BANDS: tuple[tuple[float, str], ...] = (
    (60.0, "var(--color-success)"),
    (30.0, "var(--color-warning)"),
    (0.0, "var(--color-error)"),
)

#: Where the amber band on the false-positive bar starts. The red band comes
#: from the service's own noisy threshold instead (see fp_bands).
FP_WARN_PCT = 40.0

#: What the service defaults ION_DH_NOISY_FP_PCT to, used only if a payload
#: arrives without its thresholds block.
DEFAULT_NOISY_FP_PCT = 70.0

#: The resting colour. It is what an uncomputed rate resolves to, and the
#: bottom band of every table, so no colour on this panel means "healthy"
#: on its own.
UNMEASURED_COLOUR = "var(--color-base-content)"

#: For a percentage that is shown as a number and never as a bar, so no
#: band of its own. Bob's disagreement rate is the only one.
NEUTRAL_BANDS: tuple[tuple[float, str], ...] = ((0.0, UNMEASURED_COLOUR),)


def fp_bands(noisy_fp_pct: float) -> tuple[tuple[float, str], ...]:
    """False-positive bands, with the red band at the noisy threshold.

    The JavaScript hard-coded 70 here while the service read
    ION_DH_NOISY_FP_PCT for the `noisy` flag, so raising the threshold to 85
    left every rule between 70 and 85 painted red with no badge, and
    lowering it to 50 left flagged rules painted in the resting colour. The
    bar and the badge now answer to one number.
    """
    return (
        (float(noisy_fp_pct), "var(--color-error)"),
        (FP_WARN_PCT, "var(--color-warning)"),
        (0.0, UNMEASURED_COLOUR),
    )


def _band_colour(value: float, bands: tuple[tuple[float, str], ...]) -> str:
    for floor, colour in bands:
        if value >= floor:
            return colour
    return bands[-1][1]


def _trim(value: float) -> float | int:
    """A percentage as the JavaScript printed it.

    The service rounds to one decimal, so a whole percentage arrives as
    70.0. JSON made that a JavaScript 70 and the cell read "70%"; Python
    would render "70.0%". Cosmetic, but the port is supposed to be
    invisible, and a reader comparing the two pages should not have to
    decide whether the digits changed meaning.
    """
    return int(value) if float(value) == int(value) else value


def rate_cell(value: float | None,
              bands: tuple[tuple[float, str], ...]) -> dict[str, Any]:
    """One percentage cell: the number, the bar's width, and its colour.

    `value` stays None when the rate could not be computed, which is what
    the service returns for a rule with no closed alerts, and the template
    renders a dash with no bar for it. A rate of 0.0 is a measurement and
    comes back with a width of 0, so it renders a real bar at zero width.
    Those two are the opposite conclusion about whether to disable a rule,
    which is why neither side of this is allowed to be a truthiness test.

    The colour is total over None and resolves to UNMEASURED_COLOUR, so a
    template that lost its guard would paint an uncomputed rate in the
    resting colour rather than green.
    """
    if value is None:
        return {"value": None, "shown": None, "width": None,
                "colour": UNMEASURED_COLOUR}
    width = max(0.0, min(100.0, float(value)))
    return {
        "value": value,
        "shown": _trim(value),
        "width": _trim(width),
        "colour": _band_colour(float(value), bands),
    }


def stat_tiles(summary: dict[str, Any] | None) -> list[dict[str, Any]]:
    """The five summary tiles.

    A count the summary does not carry stays None and the tile says
    unknown. The JavaScript wrote `s.rules_tracked || 0`, which prints a
    confident zero for a key that never arrived, and on this panel zero
    rules tracked is itself a finding somebody would act on.
    """
    data = summary or {}
    tiles: list[dict[str, Any]] = []
    for key, label, emphasis in SUMMARY_TILES:
        value = data.get(key)
        lit = emphasis if (value is not None and value > 0) else ""
        tiles.append({"label": label, "value": value,
                      "colour": STAT_COLOURS[lit]})
    return tiles


def drill_url(rule_name: str | None, days: int | None) -> str:
    """The drill-down URL for one rule, built as a single value.

    Built here rather than concatenated in the template: a rule name is
    free text out of AlertTriage, so it has to be percent-encoded, and
    assembling `?rule={{ x }}&days={{ n }}` in template text emits the
    literal ampersand bare and the variable's escaped, which is the defect
    the conversion notes warn about.
    """
    params: dict[str, Any] = {"rule": "" if rule_name is None else rule_name}
    if days is not None:
        params["days"] = days
    return "/ui/detection-health/disagreements?" + urlencode(params)


def rule_rows(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """One view dict per table row, worst first as the service sorted them."""
    thresholds = payload.get("thresholds") or {}
    noisy_pct = thresholds.get("noisy_fp_pct")
    bands = fp_bands(DEFAULT_NOISY_FP_PCT if noisy_pct is None else noisy_pct)
    min_sample = thresholds.get("min_sample")
    days = payload.get("period_days")

    rows: list[dict[str, Any]] = []
    for index, rule in enumerate(payload.get("rules") or []):
        flags = rule.get("flags") or {}
        closed = rule.get("closed")
        name = rule.get("rule_name")
        rows.append({
            "index": index,
            "name": name,
            "volume": rule.get("volume"),
            "closed": closed,
            "fp": rate_cell(rule.get("fp_rate"), bands),
            "tp": rate_cell(rule.get("tp_yield"), TP_BANDS),
            # Bob's disagreement rate gets no bar, only a number that opens
            # the drill-down, so it gets no band of its own.
            "bob": rate_cell(rule.get("bob_disagreement_rate"), NEUTRAL_BANDS),
            "drill_url": drill_url(name, days),
            "flags": [
                {"label": label, "badge": badge}
                for key, badge, label in FLAG_BADGES
                if flags.get(key) is True
            ],
            "sparse": is_sparse(closed, min_sample),
        })
    return rows


def is_sparse(closed: int | None, min_sample: int | None) -> bool:
    """Whether this rule has too few closures for the service to judge it.

    The service evaluates `noisy`, `silent` and `decaying` only once a rule
    has `min_sample` closed alerts, so under that line every flag is False
    by construction rather than by measurement. The rates are still
    computed from whatever denominator exists, so one closed alert resolved
    false-positive renders "100%" in the column an engineer uses to decide
    whether to switch the rule off.

    `False` when either number is missing: an unknown denominator is not a
    claim that the sample was adequate, and the empty flags cell already
    says nothing was concluded.
    """
    if closed is None or min_sample is None:
        return False
    return closed < min_sample


def unmapped_note(summary: dict[str, Any] | None) -> int | None:
    """The unmapped-alert count, or None when there is no note to show.

    Zero returns None on purpose. Unlike every other figure on this panel,
    this one is a notice rather than a measurement: "0 alerts lack a
    rule_name" is not information an engineer needs, and the JavaScript's
    `if(s.unmapped_alerts)` suppressed it for the same reason. The count
    not being there at all suppresses it too, which is the part truthiness
    was getting right by accident.
    """
    value = (summary or {}).get("unmapped_alerts")
    if value is None or value <= 0:
        return None
    return value


@router.get(
    "/detection-health/metrics",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(READ_PERMISSION))],
)
def detection_health_metrics_fragment(
    request: Request,
    days: int = Query(90, ge=1, le=365, description="Lookback window in days"),
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """The stat tiles and the per-rule table, as one fragment.

    It calls get_detection_health, the function /api/detection-health/metrics
    calls, so the page and the API cannot disagree about which rules are
    flagged or what counts as noisy. `security:read` matches that endpoint
    exactly; a fragment must not be a softer way in than the API it mirrors.

    `days` is validated with the same bounds as that endpoint, so a window
    the API would refuse is not reachable through the page.
    """
    from ion.services.detection_health_service import get_detection_health

    can_propose = bool(current_user
                       and current_user.has_permission(PROPOSE_PERMISSION))
    try:
        payload = get_detection_health(session, days=days)
    except Exception:
        logger.exception("Detection health fragment could not be rendered")
        # A failed read is not a detection estate with no noisy rules. The
        # fragment says the read failed and prints no figure at all: "every
        # rule is behaving" and "we could not measure any rule" lead to
        # opposite actions, and one of them is to leave a rule firing.
        return templates.TemplateResponse(
            request=request,
            name=FRAGMENT,
            context={"failed": True, "tiles": [], "rows": None,
                     "period_days": days, "min_sample": None,
                     "unmapped": None, "can_propose": can_propose},
            status_code=200,
        )

    summary = payload.get("summary") or {}
    return templates.TemplateResponse(
        request=request,
        name=FRAGMENT,
        context={
            "failed": False,
            "tiles": stat_tiles(summary),
            "rows": rule_rows(payload),
            # The heading's window comes from the payload when there is one
            # and from the request when there is not, so the card keeps a
            # title in both states. `is None`, not `or`: the one number in
            # this file that a truthiness default would reach.
            "period_days": (days if payload.get("period_days") is None
                            else payload["period_days"]),
            "min_sample": (payload.get("thresholds") or {}).get("min_sample"),
            "unmapped": unmapped_note(summary),
            "can_propose": can_propose,
        },
    )


@router.get(
    "/detection-health/disagreements",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(READ_PERMISSION))],
)
def detection_health_disagreements_fragment(
    request: Request,
    rule: str = Query(..., description="Rule name, or (unmapped)"),
    days: int = Query(90, ge=1, le=365),
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """One rule's Bob-vs-analyst disagreements, as the drill-down panel.

    Calls get_rule_disagreements, the function
    /api/detection-health/rules/{rule_name}/disagreements calls, and carries
    that endpoint's `security:read`.

    The rule arrives as a query parameter rather than a path segment because
    a rule name is free text and "(unmapped)" is itself a legal value; a
    path segment would have to survive two layers of encoding to say the
    same thing.
    """
    from ion.services.detection_health_service import get_rule_disagreements

    try:
        payload = get_rule_disagreements(session, rule, days=days)
    except Exception:
        logger.exception("Detection health drill-down could not be rendered "
                         "for rule %r", rule)
        # Not "no disagreements recorded": that reads as Bob and the analyst
        # agreeing on every alert this rule fired.
        return templates.TemplateResponse(
            request=request,
            name=DISAGREEMENTS_FRAGMENT,
            context={"failed": True, "rule": rule, "disagreements": []},
            status_code=200,
        )

    return templates.TemplateResponse(
        request=request,
        name=DISAGREEMENTS_FRAGMENT,
        context={
            "failed": False,
            "rule": payload.get("rule_name") or rule,
            "disagreements": payload.get("disagreements") or [],
        },
    )
