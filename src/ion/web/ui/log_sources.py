"""Log source health: the ingestion summary tiles and the per-source cards.

log_sources.html fetched /api/log-sources and then /api/log-sources/health
and built the whole body with `innerHTML` across six sites, 191 lines of
inline JavaScript including a hand-rolled `lsEsc()` and an `lsFmtTime()`
that turned a timestamp into "3h ago" on the server's reading of the
clock. One request renders it here, and Jinja escapes.

This page answers one question, "is telemetry arriving", so silence is the
thing it must never get wrong. The JavaScript had one rendering for three
different silences:

  * `lsFmtTime(null)` returned the literal word "never" for every source
    with no `last_event_at`. A source whose ES query *failed* has no
    `last_event_at` either, so a monitoring gap printed the words "never"
    and was read as a source that has never been configured to send.
  * `_check_source` returns `event_count_24h: 0` on the error path, a hard
    zero for a window it never queried, and `${s.event_count_24h ?? '-'}`
    printed that 0 as a measurement.
  * `${summary.healthy_pct||0}%` and its five siblings printed 0 for the
    `check_all` branch that returns `{"total": 0}` with no counts in it at
    all, so an estate with nothing enabled rendered as a measured row of
    zeros including "Healthy 0%".

So the readings are kept apart and named here. `REPORT_NEVER` is a source
that has reported nothing in its life, which is a misconfiguration.
`REPORT_QUIET` is a source that has reported before and had zero events in
the window, which may be perfectly normal for a low-volume feed.
`REPORT_UNREADABLE` is a source whose status ION could not obtain, which is
a gap in the monitoring rather than a fact about the source.
`REPORT_ACTIVE` is events in the window.

The two reads are separate on purpose, as are the two emptinesses they can
report. An unread registry is fatal to the fragment, because the registry
is the page. An unread health check leaves the registry count on screen and
says the check failed, because "we do not know whether telemetry is
arriving" is a different instruction to an analyst than "no telemetry is
arriving".
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.services import log_source_service
from ion.storage.database import get_db_session
from ion.web.ui._shared import plain, templates

logger = logging.getLogger(__name__)

router = APIRouter()

FRAGMENT = "_fragments/log_sources.html"

#: The two status strings from log_source_service._classify that this module
#: has to reason about rather than merely display. "error" is the service
#: saying the ES query raised, and "never" is it saying the query came back
#: with no `last_seen` at all.
STATUS_ERROR = "error"
STATUS_NEVER = "never"

#: Nothing has ever arrived from this source. A claim about the source, and
#: on a log source monitor it is the one that means somebody has to go and
#: fix a shipper.
REPORT_NEVER = "never-reported"
#: The source has reported at some point and the window held no events.
#: Deliberately not folded in with REPORT_NEVER: for a quarterly audit feed
#: an empty 24-hour window is the expected reading.
REPORT_QUIET = "quiet"
#: ION could not read this source's status. Not a count of zero and not a
#: source that has never reported: both of those are measurements, and this
#: is the absence of one. Printing either in its place is what tells an
#: analyst the blind spot has been checked.
REPORT_UNREADABLE = "unreadable"
#: Events in the window.
REPORT_ACTIVE = "active"

#: The summary tiles, in the order the JavaScript emitted them: label, the
#: key in the `summary` dict, its colour class, the suffix on the figure,
#: and the sentence under a tile whose zero would otherwise be read as a
#: stronger claim than the figure supports.
STAT_TILES: tuple[tuple[str, str, str, str, str | None], ...] = (
    (
        "Healthy %", "healthy_pct", "text-primary", "%",
        "Share of enabled sources that are not silent and not unseen.",
    ),
    ("Healthy", "healthy_count", "text-success", "", None),
    ("Stale", "stale_count", "text-warning", "", None),
    (
        "Silent", "silent_count", "text-error", "",
        "Enabled sources with no event in three times their expected "
        "window. Zero here is a measured all-clear.",
    ),
    (
        "Never Seen", "never_count", "text-base-content/50", "",
        "Sources ION has never seen an event from. Zero means every source "
        "has reported at least once.",
    ),
    (
        "Errors", "error_count", "text-base-content/50", "",
        "Sources whose health query failed. Zero means every check "
        "completed, not that every source is healthy.",
    ),
)

#: Status to daisyUI badge class, lifted from the JavaScript's ternary
#: chain. A status the service gains later lands on badge-ghost rather than
#: on no class at all.
STATUS_BADGES = {
    "healthy": "badge-success",
    "stale": "badge-warning",
    "silent": "badge-error",
    STATUS_ERROR: "badge-error",
    STATUS_NEVER: "badge-ghost",
}

#: The JavaScript's sort: the blind spots first, then the ones degrading,
#: then the ones working. A status not in the map sorts last rather than
#: silently ahead of "silent".
STATUS_ORDER = {"silent": 0, STATUS_NEVER: 1, "stale": 2, STATUS_ERROR: 3,
                "healthy": 4}


def report_state(source: dict) -> str:
    """Which of the four readings this source's telemetry is in.

    The order of the branches is the whole point. An unreadable status is
    tested first because `_check_source`'s error path fills
    `event_count_24h` with a literal 0, so trusting the count before the
    status is how a failed query becomes the sentence "zero events in the
    last 24 hours".

    A count above zero wins over a `never` status rather than the other way
    round. The two fields disagree there, and showing the count makes the
    disagreement visible instead of asserting that nothing has ever
    arrived.
    """
    status = plain(source.get("status"))
    if status is None or status == STATUS_ERROR:
        return REPORT_UNREADABLE
    count = source.get("event_count_24h")
    # `is None`, never truthiness. The cached branch of check_all copies
    # `last_event_count` straight out of the row, where NULL means no check
    # has ever recorded a count, and 0 means one recorded zero.
    if count is None:
        return REPORT_UNREADABLE
    if count > 0:
        return REPORT_ACTIVE
    if status == STATUS_NEVER and source.get("last_event_at") is None:
        return REPORT_NEVER
    return REPORT_QUIET


def source_rows(sources: list[dict]) -> list[dict]:
    """One view dict per card, with its telemetry reading named.

    Built on a copy: these dicts come from log_source_service.check_all,
    which is also what GET /api/log-sources/health returns, so display
    fields must not leak into them.
    """
    rows: list[dict] = []
    for s in sources:
        row = dict(s)
        # plain(): `category` and `criticality` are String columns today, so
        # these carry strings. `category` is also written from
        # LogSourceCategory members, and one `category=LogSourceCategory.OS`
        # anywhere upstream would print "LogSourceCategory.OS" into the card
        # subtitle while value equality kept everything else working, which
        # is what two earlier conversions hit.
        row["status"] = plain(s.get("status"))
        row["category"] = plain(s.get("category"))
        row["criticality"] = plain(s.get("criticality"))
        row["report"] = report_state(s)
        row["badge"] = STATUS_BADGES.get(row["status"], "badge-ghost")
        rows.append(row)
    rows.sort(key=lambda r: STATUS_ORDER.get(r["status"], len(STATUS_ORDER)))
    return rows


def stat_views(summary: dict | None) -> list[dict]:
    """One tile per summary figure, each knowing whether it was read.

    `measured` is `is not None`, never truthiness. Every figure in this row
    has zero as a real and interesting reading: zero silent sources is the
    all-clear this page exists to show, and it must never share a rendering
    with a figure nobody obtained.

    The unmeasured case is not hypothetical. `check_all` returns
    `{"total": 0}` when no source is enabled, so five of these six keys are
    simply absent from a payload the JavaScript rendered as six zeros.
    """
    figures = summary or {}
    views: list[dict] = []
    for label, key, colour, suffix, note in STAT_TILES:
        value = figures.get(key)
        views.append({
            "label": label,
            "value": value,
            "measured": value is not None,
            "colour": colour,
            "suffix": suffix,
            "note": note,
        })
    return views


@router.get(
    "/log-sources",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission("alert:read"))],
)
async def log_sources_fragment(
    request: Request,
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """The whole log source body, as one fragment.

    It calls log_source_service.list_sources and .check_all, the two
    functions GET /api/log-sources and GET /api/log-sources/health call, so
    the page and the API cannot disagree about what is registered or what
    is arriving. Nothing sits inline in either JSON route but a try/except
    that turns an exception into a 500, so there is no payload helper to
    extract: the service functions are already the one definition.

    `alert:read` matches both endpoints exactly. A fragment must never be a
    softer way in than the API it mirrors.

    `check_all` is awaited because it is async and queries Elasticsearch
    per source, which is also why the shell paints before this request
    returns.
    """
    # The reading names go to the template rather than being spelled again
    # in it, so the branch a reader sees there is the branch this module
    # decided.
    context: dict[str, Any] = {
        "S_NEVER": REPORT_NEVER,
        "S_QUIET": REPORT_QUIET,
        "S_UNREADABLE": REPORT_UNREADABLE,
        "S_ACTIVE": REPORT_ACTIVE,
        # `rows` carries its own unreadable state: None is a health check
        # that did not complete, [] is one that completed over nothing. One
        # value rather than a value plus a `failed` flag, because the two
        # can only disagree in one direction here, and that direction
        # renders "no telemetry is arriving" over a check that never ran.
        "registry_count": None,
        "rows": None,
        "tiles": stat_views(None),
        "es_configured": None,
        "none_enabled": False,
    }

    try:
        registry = log_source_service.list_sources(session)
    except Exception:
        logger.exception("Log source registry could not be read")
        # A failed read is not an empty registry. With the list unread,
        # "no log sources are configured" and "every source is silent" are
        # both unavailable, and the page must not pick one. `registry_count`
        # stays None, which is what the template reads as unreadable.
        return templates.TemplateResponse(
            request=request, name=FRAGMENT, context=context,
        )

    context["registry_count"] = len(registry)
    if not registry:
        # The JavaScript's own short circuit: with nothing registered there
        # is nothing to check, so the health query is not run and the
        # fragment is the seed prompt.
        return templates.TemplateResponse(
            request=request, name=FRAGMENT, context=context,
        )

    try:
        health = await log_source_service.check_all(session)
    except Exception:
        logger.exception("Log source health check could not be run")
        # rows stays None and the registry count stays on screen, so the
        # fragment says the check failed over an estate it can still size.
        # Printing an empty grid here would read as "no telemetry is
        # arriving", which is the opposite instruction.
        return templates.TemplateResponse(
            request=request, name=FRAGMENT, context=context,
        )

    checked = health.get("sources") or []
    context.update({
        "rows": source_rows(checked),
        "tiles": stat_views(health.get("summary")),
        # Three states, not two. True is a live read, False is the cached
        # snapshot, and None is a payload that did not say, which decides
        # how every figure below should be read.
        "es_configured": health.get("es_configured"),
        # check_all returns es_configured False on the no-enabled-sources
        # path without ever looking at the ES config, so the registry being
        # non-empty while the checked set is empty is its own reading and
        # not an Elasticsearch problem.
        "none_enabled": not checked,
    })
    return templates.TemplateResponse(
        request=request, name=FRAGMENT, context=context,
    )
