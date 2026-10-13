"""Threat Intel: the watchlist, its match alerts, and the attack stories.

Three of the eight tabs on threat_intel.html. The page is a tabbed shell
with eight independent panels, so it converts a panel at a time; these
three come first because every defect measured on the page lives in them.

What the page did, and why each of these is not a cosmetic port:

  * `loadWatches`, `loadMatches` and `refreshWatchedIds` all read with
    `fetch(url).then(r => r.json())` and no `r.ok` check, then destructured
    `data.watches || []`. A refusal or a fault answers with
    `{"detail": ...}`, which carries neither key, so the page fell through
    to its empty state. A failed watchlist read rendered "No active
    watches. Search for actors or campaigns and add them." and a failed
    match read rendered "No match alerts." The second sentence is what an
    analyst reads before concluding that nothing on their watchlist has
    fired, which is the opposite of what a failed read means.

  * `refreshWatchedIds` asked for `?limit=1000`. GET /watches bounds limit
    at `le=500`, so that request answers 422 on every call, measured live.
    The body is still JSON, so nothing threw, `data.watches` was undefined,
    and `watchedIds` was an empty set permanently. The watched state on
    every actor and campaign search result was therefore always wrong, and
    had been for as long as the limit said 1000.

  * The watchlist offered a Remove button on every row, and the actor and
    campaign panels offered Add to watchlist. All three call endpoints that
    require `observable:enrich`. The page is gated on `observable:read` and
    never checked, so a read-only analyst was offered three controls that
    answer 403 on click. Withheld here instead, which is what
    security_dashboard does with Block and Unblock.

  * GET /api/attack-stories answers 200 with `{"enabled": false, "error":
    ...}` when Elasticsearch is not configured or the read raises; it is
    not an error status. The page did `d.stories || []` and rendered "No
    attack stories: alerts did not correlate into multi-step patterns over
    the selected window." Measured live on this deployment, where that
    endpoint returns exactly that disabled payload. So a switched-off
    correlation engine was reported to the analyst as a clean result, with
    the service's own explanation of why it was off thrown away. Three
    outcomes are rendered here: correlation unavailable with the reason,
    correlation ran and found nothing, and stories.

Why the stories fragment is gated on `alert:read` and the other two on
`observable:read`: those are the permissions the endpoints they mirror
carry, read off the route table rather than assumed from the page. The page
itself is `observable:read`, which does not imply `alert:read`, so the
Stories and KEV tabs are reachable by someone who can never load them. The
shell withholds the tab rather than offering a 403; a fragment must match
the permission of the API it mirrors and never be a softer way in.
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import get_current_user, require_permission
from ion.models.user import User
from ion.storage.database import get_db_session
from ion.web.ui._shared import templates

logger = logging.getLogger(__name__)

router = APIRouter()

WATCHLIST_FRAGMENT = "_fragments/threat_intel_watchlist.html"
MATCHES_FRAGMENT = "_fragments/threat_intel_matches.html"
STORIES_FRAGMENT = "_fragments/threat_intel_stories.html"

#: The permission the watch and match reads name. Spelled once so these
#: fragments cannot drift into being a softer way in than the endpoints.
PERMISSION = "observable:read"

#: What POST /watches and DELETE /watches/{id} require. The watchlist
#: fragment is gated on PERMISSION, because listing watches is a read. This
#: only decides whether Remove is offered, and whether the page is told it
#: may offer Add on the actor and campaign panels.
MANAGE_PERMISSION = "observable:enrich"

#: What GET /api/attack-stories requires. Not PERMISSION: the correlation
#: engine reads alerts, and this page's own permission does not imply it.
STORIES_PERMISSION = "alert:read"

#: The cap GET /watches declares with `le=500`. The page asked for 1000 and
#: got a 422 every time. Asking for the endpoint's own maximum is the
#: honest version of "all of them"; if an estate ever holds more watches
#: than this, the fix is paging rather than a larger number, and it belongs
#: with the actor and campaign panels that consume the set.
WATCH_LIMIT = 500

#: Rows the matches table shows, from the page's `?limit=50`.
MATCH_LIMIT = 50

#: Rows the Overview tab's copy of the matches table shows, from its own
#: `?limit=10`. Same fragment, different limit, so there is one definition
#: of what a match row looks like rather than two.
OVERVIEW_MATCH_LIMIT = 10

#: Entries the Overview tab's actor and IOC cards show, from the page's
#: `.slice(0, 5)` on both.
OVERVIEW_CARD_ROWS = 5

#: What the Overview tab's recently-active widget asks for, from the page's
#: `?days=30&top_n=8`.
RECENT_DAYS = 30
RECENT_TOP_N = 8


def _rows(payload: Any, key: str) -> list[dict] | None:
    """The list under `key`, or None when the payload is not that shape.

    None is the third outcome and the whole point of this helper. The
    JavaScript wrote `data[key] || []`, which turns a refusal, a validation
    error and a genuinely empty collection into the same empty list, and
    the three render as the same sentence. A caller that gets None here has
    to say the read failed; it cannot accidentally say "none found".
    """
    if not isinstance(payload, dict):
        return None
    rows = payload.get(key)
    if not isinstance(rows, list):
        return None
    return rows


@router.get(
    "/threat-intel/watchlist",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))],
)
def threat_intel_watchlist_fragment(
    request: Request,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """The watchlist table.

    Reads through ThreatIntelService.get_watches and serialises with the
    same `_watch_to_dict` GET /api/threat-intel/watches uses, so the row a
    reader sees and the row the JSON reports cannot disagree about a
    country flag or a match count. That function is private to the API
    module by name, and importing it is still better than defining a second
    notion of a watch row here: the duplicate is the drift this package
    exists to remove.
    """
    from ion.services.threat_intel_service import ThreatIntelService
    from ion.web.threat_intel_api import _watch_to_dict

    # Derived, never restated. A reader without observable:enrich is shown
    # the table and no Remove control, rather than a control that answers
    # 403 after they have decided to use it.
    can_manage = bool(
        current_user and current_user.has_permission(MANAGE_PERMISSION)
    )

    try:
        items, total = ThreatIntelService(session).get_watches(limit=WATCH_LIMIT)
        watches = [_watch_to_dict(w) for w in items]
    except Exception:
        logger.exception("Threat intel watchlist fragment could not be rendered")
        return templates.TemplateResponse(
            request=request,
            name=WATCHLIST_FRAGMENT,
            context={"failed": True, "watches": None, "total": None,
                     "can_manage": can_manage, "limit": WATCH_LIMIT},
            status_code=200,
        )

    return templates.TemplateResponse(
        request=request,
        name=WATCHLIST_FRAGMENT,
        context={"failed": False, "watches": watches, "total": total,
                 "can_manage": can_manage, "limit": WATCH_LIMIT},
    )


@router.get(
    "/threat-intel/matches",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))],
)
def threat_intel_matches_fragment(
    request: Request,
    unread_only: bool = Query(False),
    limit: int = Query(MATCH_LIMIT, ge=1, le=200),
    show_type: bool = Query(False),
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """The match-alert table, optionally filtered to unread.

    `unread_only` is the page's Show Unread toggle and `limit` lets the
    Overview tab's copy ask for its own ten rows. Both are bounded exactly
    as GET /api/threat-intel/matches bounds them, so a filter or a page size
    the API would refuse is not reachable through the page.

    One fragment serves both tables. The page had renderMatchRows building
    the Overview copy and loadMatches building the Watchlist copy, two
    definitions of a match row that had already drifted: the Overview copy
    took a showType argument and rendered an extra column.
    """
    from ion.services.threat_intel_service import ThreatIntelService
    from ion.web.threat_intel_api import _match_to_dict

    try:
        items, total = ThreatIntelService(session).get_matches(
            unread_only=unread_only, limit=limit
        )
        matches = [_match_to_dict(m) for m in items]
    except Exception:
        logger.exception("Threat intel matches fragment could not be rendered")
        return templates.TemplateResponse(
            request=request,
            name=MATCHES_FRAGMENT,
            context={"failed": True, "matches": None, "total": None,
                     "unread_only": unread_only, "show_type": show_type},
            status_code=200,
        )

    return templates.TemplateResponse(
        request=request,
        name=MATCHES_FRAGMENT,
        context={"failed": False, "matches": matches, "total": total,
                 "unread_only": unread_only, "show_type": show_type},
    )


@router.get(
    "/threat-intel/stories",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(STORIES_PERMISSION))],
)
async def threat_intel_stories_fragment(
    request: Request,
    hours: int = Query(24, ge=1, le=168),
) -> HTMLResponse:
    """Attack stories for the selected window.

    Calls the same body GET /api/attack-stories runs, so the narrative on
    the page and the narrative in the JSON are one computation.

    Four outcomes, where the page had two:

      unavailable  the payload says `enabled` is false and carries the
                   reason. Elasticsearch not configured, or the read
                   raised. Rendered as unavailable with the reason shown,
                   never as an absence of attack patterns.
      failed       this fragment itself raised. Same reasoning, different
                   cause, and worth distinguishing because one is the
                   correlation service reporting on itself and the other is
                   not.
      none         correlation ran over the window and nothing reached the
                   minimum alert count. The only case where "no attack
                   stories" is true.
      stories      the narratives.
    """
    from ion.services.attack_story_service import build_attack_stories
    from ion.services.elasticsearch_service import ElasticsearchService

    def answer(ctx: dict) -> HTMLResponse:
        return templates.TemplateResponse(
            request=request, name=STORIES_FRAGMENT,
            context={"hours": hours, **ctx}, status_code=200,
        )

    es = ElasticsearchService()
    if not es.is_configured:
        # `es.is_configured`, not `not es`. The endpoint wrote the latter,
        # and ElasticsearchService defines neither __bool__ nor __len__, so
        # an instance is always truthy and that guard never fired once.
        # Measured: bool(ElasticsearchService()) is True while
        # .is_configured is False on this deployment. The endpoint
        # therefore called get_alerts against an unconfigured service,
        # which raised, and answered {"enabled": false, "error":
        # "ElasticsearchError"} through safe_error, where it meant to say
        # the integration was not configured. Fixed in attack_story_api.py
        # in the same change so the page and the JSON still agree.
        #
        # is_configured is a property, so it is read and not called. Calling
        # it raises TypeError: 'bool' object is not callable, which reads
        # like a shadowed attribute and sends you looking in the wrong file.
        return answer({"enabled": False, "stories": None, "failed": False,
                       "error": "Elasticsearch not configured"})

    try:
        alerts = await es.get_alerts(hours=hours, limit=500)
        payload = build_attack_stories(
            [a.to_dict() for a in alerts], min_alerts=2, time_window_hours=hours
        )
    except Exception:
        logger.exception("Attack stories fragment could not be rendered")
        return answer({"enabled": True, "stories": None, "error": None,
                       "failed": True})

    # `is False`, not falsy. A payload that omits `enabled` entirely is a
    # successful correlation result; only an explicit false means the
    # service is reporting itself off.
    if isinstance(payload, dict) and payload.get("enabled") is False:
        return answer({"enabled": False, "stories": None, "failed": False,
                       "error": payload.get("error")})

    return answer({
        "enabled": True,
        "failed": False,
        "error": None,
        "stories": _rows(payload, "stories"),
        "kill_chain_order": _rows(payload, "kill_chain_order") or [],
    })


# ---------------------------------------------------------------------------
# The Overview tab
#
# Five regions the page built in JavaScript, each with its own failure
# behaviour and none of them honest:
#
#   * loadOverview's catch was console.error and rendered nothing. The four
#     stat tiles kept the dash they ship with, so a failed read looked like
#     a page still loading. The figures went in with textContent and no
#     guard, so a payload missing a key printed "undefined" into the tile.
#   * loadOverviewActors and loadOverviewIOCs both ended in "Actors
#     unavailable, OpenCTI not configured?" and the same for IOCs. A guess,
#     punctuated with a question mark, rendered in the same muted grey as
#     the empty state, while the 503 that caused it carries the exact
#     reason: "OpenCTI integration is not configured". Both cards now
#     separate not-configured from a failed read and say which it was.
#   * loadRecentlyActive did `if (!r.ok) return;`, a silent return that left
#     both its panels showing the hardcoded "Loading..." from the shell
#     forever. That is the worst of the three, because a permanent loading
#     state reads as work in progress rather than as a failure.
#   * renderMatchRows built the Overview's copy of the match table, a second
#     definition of a match row that had already drifted from the
#     Watchlist's: it took a showType argument and rendered an extra
#     column. The matches fragment serves both now.
# ---------------------------------------------------------------------------

STATS_FRAGMENT = "_fragments/threat_intel_overview_stats.html"
RECENT_FRAGMENT = "_fragments/threat_intel_recently_active.html"
ACTORS_FRAGMENT = "_fragments/threat_intel_landscape_actors.html"
IOCS_FRAGMENT = "_fragments/threat_intel_landscape_iocs.html"


@router.get(
    "/threat-intel/overview-stats",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))],
)
def threat_intel_overview_stats_fragment(
    request: Request,
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """The four watch-and-match tiles, and the unread badge on the tab.

    Calls get_overview_stats, which is the whole body of GET
    /api/threat-intel/overview, so the tiles and the JSON cannot disagree.

    The badge swaps out of band, because it lives in the tab strip rather
    than in this fragment's target and no second read knows the count.
    """
    from ion.services.threat_intel_service import ThreatIntelService

    try:
        stats = ThreatIntelService(session).get_overview_stats()
    except Exception:
        logger.exception("Threat intel overview stats could not be rendered")
        return templates.TemplateResponse(
            request=request, name=STATS_FRAGMENT,
            context={"failed": True, "stats": None}, status_code=200,
        )

    return templates.TemplateResponse(
        request=request, name=STATS_FRAGMENT,
        context={"failed": False,
                 "stats": stats if isinstance(stats, dict) else None},
    )


@router.get(
    "/threat-intel/recently-active",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))],
)
def threat_intel_recently_active_fragment(
    request: Request,
    hide_rule_observables: bool = Query(True),
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """Observables and MITRE techniques seen most in recent case activity.

    One read answers both lists, so they are one fragment. A state where the
    observables rendered and the techniques still showed "Loading..." was
    reachable before only because the silent return left whichever panel the
    script had not reached yet.

    `hide_rule_observables` is the page's checkbox. `days` and `top_n` are
    fixed at the values the page asked for rather than exposed, because
    nothing on the page changes them.
    """
    from ion.web.threat_intel_api import recently_active

    try:
        payload = recently_active(
            days=RECENT_DAYS, top_n=RECENT_TOP_N,
            hide_rule_observables=hide_rule_observables,
            session=session, user=None,
        )
    except Exception:
        logger.exception("Threat intel recently-active could not be rendered")
        return templates.TemplateResponse(
            request=request, name=RECENT_FRAGMENT,
            context={"failed": True, "observables": None, "techniques": None,
                     "days": RECENT_DAYS},
            status_code=200,
        )

    # `_rows`, so a payload carrying neither list reaches the template as
    # None and says the read failed, rather than as [] saying there has been
    # no activity. The page did `d.observables.length` with no guard at all,
    # which raises on a payload missing the key.
    return templates.TemplateResponse(
        request=request, name=RECENT_FRAGMENT,
        context={
            "failed": False,
            "observables": _rows(payload, "observables"),
            "techniques": _rows(payload, "techniques"),
            "days": (payload or {}).get("time_window_days") or RECENT_DAYS,
        },
    )


async def _landscape(request: Request, fragment: str, rows_key: str,
                     fetch, label: str) -> HTMLResponse:
    """Shared body for the two OpenCTI-backed Overview cards.

    Three outcomes, and the first is the one the page guessed at.
    get_opencti_service().is_configured is the same check
    /api/threat-landscape/overview and /ioc-feed make before raising their
    503, so not-configured is reported as the fact it is instead of as a
    question. is_configured is a property on this service too, so it is read
    and not called.
    """
    from ion.services.opencti_service import get_opencti_service

    def answer(ctx: dict) -> HTMLResponse:
        return templates.TemplateResponse(
            request=request, name=fragment,
            context={"rows": None, "configured": True, "failed": False,
                     "error": None, "limit": OVERVIEW_CARD_ROWS, **ctx},
            status_code=200,
        )

    service = get_opencti_service()
    if not service.is_configured:
        return answer({"configured": False})

    try:
        payload = await fetch(service)
    except Exception as exc:
        logger.exception("Threat intel %s card could not be rendered", label)
        # The class name only. The service's own messages can carry estate
        # detail and this card renders for anyone with observable:read.
        return answer({"failed": True, "error": type(exc).__name__})

    rows = _rows(payload, rows_key)
    return answer({"rows": None if rows is None else rows[:OVERVIEW_CARD_ROWS]})


@router.get(
    "/threat-intel/landscape-actors",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))],
)
async def threat_intel_landscape_actors_fragment(request: Request) -> HTMLResponse:
    """Top tracked actors, from the read GET /api/threat-landscape/overview
    performs."""
    return await _landscape(
        request, ACTORS_FRAGMENT, "actors",
        lambda s: s.get_threat_landscape_overview(), "actors",
    )


@router.get(
    "/threat-intel/landscape-iocs",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))],
)
async def threat_intel_landscape_iocs_fragment(
    request: Request,
    min_score: int = Query(75, ge=0, le=100),
) -> HTMLResponse:
    """Highest-scoring recent indicators, from the read GET
    /api/threat-landscape/ioc-feed performs.

    `min_score` keeps the page's 75 as its default and is bounded as that
    endpoint bounds it.
    """
    from ion.web.threat_landscape_api import get_ioc_feed

    async def fetch(_service):
        return await get_ioc_feed(
            limit=OVERVIEW_CARD_ROWS, min_score=min_score, user=None
        )

    return await _landscape(request, IOCS_FRAGMENT, "indicators", fetch, "iocs")
