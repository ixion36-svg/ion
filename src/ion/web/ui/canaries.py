"""The canary grid: summary tiles, the planted-canary table and recent hits.

canaries.html fetched /api/canaries, /api/canaries/stats and
/api/canaries/hits in parallel and built all three regions with `innerHTML`,
189 lines of inline JavaScript including a hand-rolled `esc()` and a
`toLocaleString()` date formatter. One request renders them here, and Jinja
escapes.

A canary is a deception asset, so every figure on this page is a security
claim. The JavaScript collapsed three claims into one with `||`:

  * `${stats.hits_24h||0}` printed 0 for a figure it never read.
  * `${ca.hit_count||0}` printed 0 for a count it never read, and
    `(ca.hit_count||0) > 0` then decided the row was clean, which is the
    claim "this decoy has not been touched".
  * a null `last_hit_at` printed "-" whether the canary had never fired or
    had fired with no timestamp recorded.

So the three readings are kept apart here and named: `never` is a canary
that has fired zero times in its life, `fired` is one with recorded hits,
and `unreadable` is one whose count ION could not obtain. The last one is
not a count of zero, the same way the 24h window reading zero is not a
canary that has never fired.

The three reads are also separate on purpose. `Promise.all` meant a failing
/stats took the whole page down to one red line, and a failing /hits would
have done the same. Here the list read failing is fatal to the fragment,
because the table is the page, while stats and hits each degrade to their
own "could not read" state with the rest of the page intact.
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.services import canary_service
from ion.storage.database import get_db_session
from ion.web.ui._shared import plain, templates

logger = logging.getLogger(__name__)

router = APIRouter()

FRAGMENT = "_fragments/canaries.html"

#: How many hits the page shows, which is the `?limit=20` the JavaScript
#: sent. Named because the template has to say "the most recent 20" rather
#: than print a bare count that reads as the total.
HITS_LIMIT = 20

#: A canary has fired zero times in its life. An assertion about the asset,
#: not an absence of data.
HIT_NEVER = "never"
#: A canary has recorded hits.
HIT_FIRED = "fired"
#: ION could not read whether this canary fired. Deliberately not folded in
#: with HIT_NEVER: "clean" and "unknown" lead to opposite actions, and on a
#: deception asset the wrong one is the dangerous one.
HIT_UNREADABLE = "unreadable"

#: The summary tiles, in the order the JavaScript emitted them: label, the
#: key in the stats dict, the colour class, and the sentence under a tile
#: whose zero would otherwise be read as a stronger claim than it is.
STAT_TILES: tuple[tuple[str, str, str, str | None], ...] = (
    ("Total", "total", "text-primary", None),
    ("Active", "active", "text-primary", None),
    (
        "Fired", "fired", "text-warning",
        "Active canaries with at least one hit on record, over their whole "
        "life.",
    ),
    ("Burned", "burned", "text-error", None),
    (
        "Hits (24h)", "hits_24h", "text-error",
        "Hits recorded in the last 24 hours. Zero is an empty window, not a "
        "grid that has never fired.",
    ),
)

#: Status to daisyUI badge class, lifted from the JavaScript's ternary. A
#: status the enum gains later lands on badge-ghost rather than on no class.
STATUS_BADGES = {"active": "badge-success", "burned": "badge-error"}


def hit_state(canary: dict) -> str:
    """Which of the three hit readings this canary is in.

    `hit_count` is a non-nullable column, so an unreadable count is a guard
    rather than an observed row today. It is still the first branch, because
    the JavaScript's `||` turned exactly this case into a confident 0 and a
    row rendered as clean, and a guard that exists is what keeps a future
    nullable read or a partially hydrated dict from printing that claim.

    A count of 0 with a timestamp present is reported as `fired` rather than
    `never`: the two fields disagree, and showing the timestamp makes the
    disagreement visible instead of asserting the canary is untouched.
    """
    count = canary.get("hit_count")
    if count is None:
        return HIT_UNREADABLE
    if count == 0 and canary.get("last_hit_at") is None:
        return HIT_NEVER
    return HIT_FIRED


def canary_rows(canaries: list[dict]) -> list[dict]:
    """One view dict per table row, with its hit reading named.

    Built on a copy: the dicts are `Canary.to_dict()`, the JSON endpoint's
    own shape, and display fields must not leak into it.
    """
    rows: list[dict] = []
    for c in canaries:
        row = dict(c)
        # plain(): `status` and `canary_type` are String columns today, so
        # these carry strings. They are also written from CanaryStatus /
        # CanaryType members, and a single `status=CanaryStatus.BURNED`
        # anywhere upstream would put "CanaryStatus.BURNED" in the pill and
        # miss the colour lookup, which is what two earlier conversions hit.
        row["status"] = plain(c.get("status"))
        row["canary_type"] = plain(c.get("canary_type"))
        row["hit_state"] = hit_state(c)
        row["badge"] = STATUS_BADGES.get(row["status"], "badge-ghost")
        rows.append(row)
    return rows


def stat_views(stats: dict | None) -> list[dict]:
    """One tile per summary figure, each knowing whether it was read.

    `measured` is `is not None`, never truthiness: on this page zero is the
    most interesting measurement there is, because it is what an estate with
    nothing tripped looks like. A failed stats read gives every tile
    `measured: False`, so the tiles say unknown instead of printing the
    `stats.x||0` the JavaScript printed.
    """
    figures = stats or {}
    views: list[dict] = []
    for label, key, colour, note in STAT_TILES:
        value = figures.get(key)
        views.append({
            "label": label,
            "value": value,
            "measured": value is not None,
            "colour": colour,
            "note": note,
        })
    return views


def hit_rows(hits: list[dict], canaries: list[dict]) -> list[dict]:
    """Recent hits with their canary's name resolved.

    The JavaScript built the same id-to-name map and fell back to
    "Canary #id" for a hit whose canary is not in the list. Kept: a hit
    naming a canary that is gone is still a hit, and dropping the row would
    remove evidence that something fired.
    """
    names = {c.get("id"): c.get("name") for c in canaries}
    rows: list[dict] = []
    for h in hits:
        canary_id = h.get("canary_id")
        rows.append({
            "name": names.get(canary_id) or f"Canary #{canary_id}",
            "detected_at": h.get("detected_at"),
            "snippet": h.get("snippet"),
        })
    return rows


@router.get(
    "/canaries",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission("alert:read"))],
)
def canaries_fragment(
    request: Request,
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """The whole canary grid body, as one fragment.

    It calls canary_service.list_canaries, .stats and .list_hits, the three
    functions GET /api/canaries, /api/canaries/stats and /api/canaries/hits
    call, so the page and the API cannot disagree about what is planted or
    what has fired. Nothing sits inline in those routes but a limit clamp,
    so there is no payload helper to extract; the service functions are
    already the one definition.

    `alert:read` matches all three endpoints exactly. A fragment must never
    be a softer way in than the API it mirrors, and the one on this page
    would hand over the literal canary values an attacker needs to avoid
    tripping them.
    """
    # The three state names go to the template rather than being spelled
    # again in it, so the branch a reader sees there is the branch this
    # module decided.
    context: dict[str, Any] = {
        "hits_limit": HITS_LIMIT,
        "S_NEVER": HIT_NEVER,
        "S_FIRED": HIT_FIRED,
        "S_UNREADABLE": HIT_UNREADABLE,
    }

    try:
        canaries = canary_service.list_canaries(session)
    except Exception:
        logger.exception("Canary list could not be read")
        # A failed read is not an empty grid. Nothing else is rendered in
        # this branch: with the list unread, "nothing has fired" is a claim
        # about decoys ION could not even enumerate. `rows=None` is what the
        # template reads as unreadable, so the two cannot disagree.
        context.update({
            "rows": None, "tiles": stat_views(None),
            "stats_failed": True, "hits": None,
        })
        return templates.TemplateResponse(
            request=request, name=FRAGMENT, context=context,
        )

    # Separate try blocks, not one. Promise.all turned a failing /stats into
    # a page with no table on it; here each region reports its own read.
    stats: dict | None
    try:
        stats = canary_service.stats(session)
        stats_failed = False
    except Exception:
        logger.exception("Canary stats could not be read")
        stats, stats_failed = None, True

    # None, not [], so the hits card says the log could not be read rather
    # than "no canary hits recorded".
    hits: list[dict] | None
    try:
        hits = hit_rows(
            canary_service.list_hits(session, limit=HITS_LIMIT), canaries,
        )
    except Exception:
        logger.exception("Canary hits could not be read")
        hits = None

    context.update({
        "rows": canary_rows(canaries),
        "tiles": stat_views(stats),
        "stats_failed": stats_failed,
        "hits": hits,
    })
    return templates.TemplateResponse(
        request=request, name=FRAGMENT, context=context,
    )
