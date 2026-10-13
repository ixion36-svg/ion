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


# ---------------------------------------------------------------------------
# The Actors and Campaigns tabs
#
# searchActors and searchCampaigns both read with
# `fetch(url).then(r => r.json())` and no r.ok check, then branched on
# `data.detail` and rendered it into the ti-empty class, which is the
# no-results styling. So a 503 from an unconfigured OpenCTI, a 403, and a
# genuine zero-match search were three different facts rendered in one
# voice. A reader searching an unconfigured estate was told their search
# found nothing.
#
# toggleActorDetail and toggleCampaignDetail had the sharper version of the
# same bug. They tested each of four sections for content and fell through
# to "No additional detail available." A refusal body carries none of those
# sections, so a failed detail read claimed OpenCTI holds nothing on the
# actor in front of you.
#
# watchActor did not read r.ok either, and reported "Added to watchlist"
# after a 403.
#
# The result tables also kept the whole result set on a DOM property,
# container._actors, and addressed rows by index into it. Each detail row
# now fetches itself by entity id, so there is no array to stay in step
# with and no index to go stale when a search is re-run.
# ---------------------------------------------------------------------------

ACTOR_RESULTS_FRAGMENT = "_fragments/threat_intel_actor_results.html"
CAMPAIGN_RESULTS_FRAGMENT = "_fragments/threat_intel_campaign_results.html"
ENTITY_DETAIL_FRAGMENT = "_fragments/threat_intel_entity_detail.html"

#: Results a search asks OpenCTI for, from the page's `&first=30`.
SEARCH_FIRST = 30

#: Columns each result table declares, so a detail row spans its parent.
#: Actors carry an origin and a type list that campaigns do not.
ACTOR_COLUMNS = 9
CAMPAIGN_COLUMNS = 7


def _watched_ids(session) -> set:
    """OpenCTI ids already on the watchlist.

    The page kept this in a module-level `watchedIds` set refreshed by
    refreshWatchedIds, which asked for `?limit=1000` against an endpoint
    bounded at 500 and so answered 422 on every call. The set was therefore
    always empty and every result rendered as not-watched. Read here
    instead, per request, from the same service the watch list uses.

    A failure returns an empty set rather than raising, because not knowing
    which entities are watched must not take the search results away. The
    cost of being wrong is a Watch button on an entity already watched,
    which the POST answers with the existing row.
    """
    from ion.services.threat_intel_service import ThreatIntelService

    try:
        items, _ = ThreatIntelService(session).get_watches(limit=WATCH_LIMIT)
        return {w.opencti_id for w in items if w.opencti_id}
    except Exception:
        logger.exception("Could not read the watchlist for search results")
        return set()


async def _entity_search(request: Request, fragment: str, rows_key: str,
                         q: str, session: Session, current_user: User,
                         search):
    """Shared body for the actor and campaign searches.

    Four outcomes. `configured` comes from the same is_configured property
    /api/threat-intel/actors checks through get_opencti_service, so an
    unconfigured estate is reported as a deployment fact rather than as a
    search that matched nothing.
    """
    from ion.services.opencti_service import get_opencti_service

    can_manage = bool(
        current_user and current_user.has_permission(MANAGE_PERMISSION)
    )

    def answer(ctx: dict) -> HTMLResponse:
        return templates.TemplateResponse(
            request=request, name=fragment,
            context={"q": q, "configured": True, "failed": False,
                     "error": None, rows_key: None, "can_manage": can_manage,
                     "watched_ids": set(), **ctx},
            status_code=200,
        )

    service = get_opencti_service()
    if not service.is_configured:
        return answer({"configured": False})

    try:
        payload = await search(service)
    except Exception as exc:
        logger.exception("Threat intel %s search could not be rendered", rows_key)
        # The class name only: the service's messages can carry estate
        # detail and this renders for anyone with observable:read.
        return answer({"failed": True, "error": type(exc).__name__})

    return answer({
        rows_key: _rows(payload, rows_key),
        "watched_ids": _watched_ids(session),
    })


@router.get(
    "/threat-intel/actor-search",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))],
)
async def threat_intel_actor_search_fragment(
    request: Request,
    q: str = Query("", max_length=200),
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """Threat-actor search results.

    An empty `q` renders the resting prompt rather than searching for
    nothing, which is what `if (!q) return;` did, except that the page then
    left whatever was already on screen in place.
    """
    from ion.web.threat_intel_api import search_actors

    if not q.strip():
        return templates.TemplateResponse(
            request=request, name=ACTOR_RESULTS_FRAGMENT,
            context={"q": "", "configured": True, "failed": False,
                     "error": None, "actors": [], "can_manage": False,
                     "watched_ids": set(), "prompt": True},
        )

    async def search(_service):
        return await search_actors(search=q, first=SEARCH_FIRST, user=None)

    return await _entity_search(
        request, ACTOR_RESULTS_FRAGMENT, "actors", q.strip(), session,
        current_user, search,
    )


@router.get(
    "/threat-intel/campaign-search",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))],
)
async def threat_intel_campaign_search_fragment(
    request: Request,
    q: str = Query("", max_length=200),
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """Campaign search results."""
    from ion.web.threat_intel_api import search_campaigns

    if not q.strip():
        return templates.TemplateResponse(
            request=request, name=CAMPAIGN_RESULTS_FRAGMENT,
            context={"q": "", "configured": True, "failed": False,
                     "error": None, "campaigns": [], "can_manage": False,
                     "watched_ids": set(), "prompt": True},
        )

    async def search(_service):
        return await search_campaigns(search=q, first=SEARCH_FIRST, user=None)

    return await _entity_search(
        request, CAMPAIGN_RESULTS_FRAGMENT, "campaigns", q.strip(), session,
        current_user, search,
    )


async def _entity_detail(request: Request, columns: int, fetch) -> HTMLResponse:
    """Shared body for both detail rows.

    Four outcomes, where the page had two and the second was a lie: a
    refusal body carries no description, campaigns, ttps or indicators, so
    every section was skipped and the row said "No additional detail
    available."
    """
    from ion.services.opencti_service import get_opencti_service

    def answer(ctx: dict) -> HTMLResponse:
        return templates.TemplateResponse(
            request=request, name=ENTITY_DETAIL_FRAGMENT,
            context={"columns": columns, "configured": True, "failed": False,
                     "detail": None, **ctx},
            status_code=200,
        )

    service = get_opencti_service()
    if not service.is_configured:
        return answer({"configured": False})

    try:
        detail = await fetch(service)
    except Exception:
        logger.exception("Threat intel entity detail could not be rendered")
        return answer({"failed": True})

    # A dict or nothing. `_rows` is for lists; here the shape itself is the
    # payload, and anything that is not a mapping cannot be read as detail.
    return answer({"detail": detail if isinstance(detail, dict) else None})


@router.get(
    "/threat-intel/actor-detail",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))],
)
async def threat_intel_actor_detail_fragment(
    request: Request,
    entity_id: str = Query(..., min_length=1, max_length=400),
    entity_class: str = Query("threat_actor", max_length=64),
) -> HTMLResponse:
    """One actor's detail row.

    `entity_class` is the same parameter GET
    /api/threat-intel/actors/{entity_id} takes, with the same default, and
    it decides which OpenCTI lookup path is used. The page read it off the
    entity it had in its own array; it travels in the URL now.
    """
    from ion.web.threat_intel_api import get_actor_detail

    async def fetch(_service):
        return await get_actor_detail(
            entity_id=entity_id, entity_class=entity_class, user=None
        )

    return await _entity_detail(request, ACTOR_COLUMNS, fetch)


@router.get(
    "/threat-intel/campaign-detail",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))],
)
async def threat_intel_campaign_detail_fragment(
    request: Request,
    entity_id: str = Query(..., min_length=1, max_length=400),
) -> HTMLResponse:
    """One campaign's detail row."""
    from ion.web.threat_intel_api import get_campaign_detail

    async def fetch(_service):
        return await get_campaign_detail(entity_id=entity_id, user=None)

    return await _entity_detail(request, CAMPAIGN_COLUMNS, fetch)


# ---------------------------------------------------------------------------
# The global search bar and the KEV Catalog tab
#
# tiUnifiedSearch rendered both of its failures into the ti-empty class,
# which is the no-results styling, so "Search failed: HTTP 403" and "no
# matches" looked alike. It also printed `${d.total}` unguarded, so a
# payload without a total read "undefined results", and it read
# `d.actors.length` on all four kinds without a guard.
#
# Those four accesses are a fragility rather than a live bug: the endpoint
# pre-seeds all four keys and wraps each source in its own try/except, so
# they are always present. That same best-effort design is the real defect
# and it belongs to the endpoint, not to this page: a source that fails
# contributes an empty list and a debug log, so a reader cannot tell "OpenCTI
# matched no actors" from "OpenCTI was down". Filed separately, because
# fixing it changes the JSON contract.
#
# kevSearch was the best-written region on this page and most of it is
# carried over unchanged, including two judgements worth keeping: the empty
# state names which catalog found nothing, because a bare "no results"
# invites the reader to conclude the CVE is safe; and "ransomware: unknown"
# is worded as CISA not having established use rather than as having ruled
# it out. Its one defect is the same as the search bar's: the catch rendered
# into ti-empty, so a failed lookup read as an empty catalog.
# ---------------------------------------------------------------------------

UNIFIED_FRAGMENT = "_fragments/threat_intel_unified_search.html"
KEV_FRAGMENT = "_fragments/threat_intel_kev.html"

#: What GET /api/threat-intel/unified-search asks each source for, from the
#: page's `&limit_per_kind=8`.
UNIFIED_PER_KIND = 8

#: The shortest term the search endpoint accepts, from its `min_length=2`.
#: The page had `if (q.length < 2) return;`, which silently did nothing and
#: left whatever was on screen in place.
UNIFIED_MIN_CHARS = 2

#: Rows the KEV table shows, from the page's `limit: '50'`.
KEV_LIMIT = 50

#: The four kinds the search bar groups its results under, in the order the
#: page showed them, with the heading each carried.
UNIFIED_KINDS = (
    ("actors", "Threat Actors"),
    ("campaigns", "Campaigns"),
    ("iocs", "IOCs"),
    ("cases", "Cases"),
)


@router.get(
    "/threat-intel/unified-search",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))],
)
async def threat_intel_unified_search_fragment(
    request: Request,
    q: str = Query("", max_length=200),
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """The global search bar's grouped results.

    A term shorter than the endpoint's minimum renders a prompt saying so,
    rather than returning and leaving stale results from a previous search
    on screen, which is what `if (q.length < 2) return;` did.
    """
    from ion.web.threat_intel_api import unified_search

    term = q.strip()

    def answer(ctx: dict) -> HTMLResponse:
        return templates.TemplateResponse(
            request=request, name=UNIFIED_FRAGMENT,
            context={"q": term, "failed": False, "error": None,
                     "too_short": False, "groups": None, "total": None,
                     "kinds": UNIFIED_KINDS, "min_chars": UNIFIED_MIN_CHARS,
                     **ctx},
            status_code=200,
        )

    if len(term) < UNIFIED_MIN_CHARS:
        return answer({"too_short": True})

    try:
        payload = await unified_search(
            q=term, limit_per_kind=UNIFIED_PER_KIND, session=session, user=None
        )
    except Exception:
        logger.exception("Threat intel unified search could not be rendered")
        return answer({"failed": True})

    if not isinstance(payload, dict):
        return answer({"failed": True})

    # One list per kind, each through `_rows`, so a payload that stops
    # carrying one of them reaches the template as None and that group says
    # so rather than reading as a source with no matches.
    return answer({
        "groups": {key: _rows(payload, key) for key, _ in UNIFIED_KINDS},
        "total": payload.get("total"),
    })


@router.get(
    "/threat-intel/kev",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(STORIES_PERMISSION))],
)
def threat_intel_kev_fragment(
    request: Request,
    q: str = Query("", max_length=200),
    ransomware_only: bool = Query(False),
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """The KEV catalog table, and the catalog status bar out of band.

    Gated on alert:read, which is what /api/kev requires, and not on this
    page's own observable:read. The tab is withheld from a viewer without
    it; this is the second gate, so a direct request cannot reach what the
    tab does not offer.

    One read answers both regions: GET /api/kev returns the status block
    alongside the results, which is why the page called kevRenderStatus with
    `data.status` rather than reading /kev/status separately. The status bar
    swaps out of band for the same reason it did there.
    """
    from ion.web.kev_api import kev_search

    def answer(ctx: dict) -> HTMLResponse:
        return templates.TemplateResponse(
            request=request, name=KEV_FRAGMENT,
            context={"q": q.strip(), "ransomware_only": ransomware_only,
                     "failed": False, "results": None, "status": None, **ctx},
            status_code=200,
        )

    try:
        payload = kev_search(
            q=q.strip(), ransomware_only=ransomware_only, limit=KEV_LIMIT,
            session=session,
        )
    except Exception:
        logger.exception("Threat intel KEV fragment could not be rendered")
        return answer({"failed": True})

    status = payload.get("status") if isinstance(payload, dict) else None
    return answer({
        "results": _rows(payload, "results"),
        "status": status if isinstance(status, dict) else None,
    })


# ---------------------------------------------------------------------------
# The last six regions: the IOC feed and its sparklines, the Reports tab and
# its drill panel, the ATT&CK technique drill, and the AI briefing.
#
# The sharpest defect on the page was in the sparklines. Three outcomes all
# rendered the same em-dash:
#
#     if (!r.ok) { spark.innerHTML = '-' }        a refused or failed read
#     catch { spark.innerHTML = '-' }             a thrown read
#     '-' with title="No local sightings..."      nothing seen
#
# The only thing separating "this indicator has never been seen in your
# estate" from "we could not check" was a tooltip that one of them happened
# to carry. For an analyst triaging an indicator those are opposite
# conclusions. The old SVG also put the sightings total in a `title`
# attribute on the <svg> element, which is not how SVG tooltips work, so
# that number was never readable on hover either.
#
# Elsewhere: `i.score || 0` painted an unscored indicator with the resting
# grey a genuinely low score gets; `d.local_cases.length` and
# `d.actors.length` were read without a guard in the technique drill, so a
# payload omitting either key raised into the catch and the whole panel
# became "Failed: TypeError"; and the reports filter ran in the browser over
# the 25 rows the endpoint returns, which is kept but moved to the server so
# the empty state can say whether a filter was responsible.
# ---------------------------------------------------------------------------

IOC_FEED_FRAGMENT = "_fragments/threat_intel_ioc_feed.html"
IOC_SPARK_FRAGMENT = "_fragments/threat_intel_ioc_spark.html"
REPORTS_FRAGMENT = "_fragments/threat_intel_reports.html"
REPORT_DRILL_FRAGMENT = "_fragments/threat_intel_report_drill.html"
TECHNIQUE_DRILL_FRAGMENT = "_fragments/threat_intel_technique_drill.html"
AI_BRIEF_FRAGMENT = "_fragments/threat_intel_ai_brief.html"

#: Rows the IOC feed asks for, from the page's `?limit=50`.
IOC_FEED_LIMIT = 50

#: Labels a feed row shows, from the page's `.slice(0, 3)`.
IOC_LABEL_LIMIT = 3

#: Months of local sightings a sparkline covers, from the page's
#: `&months=12`.
SPARK_MONTHS = 12

#: Reports the tab asks for, from the page's `?limit=25`.
REPORT_LIMIT = 25

#: Characters of a report description the card shows, from the page's
#: `.slice(0, 200)`.
REPORT_SUMMARY_CHARS = 200

#: Indicators the report drill lists, from the page's `.slice(0, 10)`. The
#: endpoint already caps its own list at 20.
REPORT_INDICATOR_LIMIT = 10

#: The window the technique drill reports local cases over. The endpoint
#: fixes it at 90 days and the page's heading said so.
TECHNIQUE_LOCAL_DAYS = 90

#: Markdown the AI briefing strips before rendering as paragraphs, in the
#: order the page applied it. Headings, bold, italics, bullets, ordered-list
#: numbers, and fenced code blocks.
_MARKDOWN_STRIPS: tuple[tuple[str, str], ...] = (
    (r"^#{1,4}\s+", ""),
    (r"\*\*(.+?)\*\*", r"\1"),
    (r"\*(.+?)\*", r"\1"),
    (r"^[-*]\s+", ""),
    (r"^\d+\.\s+", ""),
    (r"```[\s\S]*?```", ""),
)


def brief_paragraphs(summary: object) -> list[str]:
    """An AI summary as paragraphs, with its light markdown removed.

    The same six substitutions the page applied, then a split on blank
    lines, then newlines inside a paragraph collapsed to spaces. Jinja
    escapes each paragraph when it renders, which is the order the page used
    too: strip, escape, split.

    Anything that is not a string gives no paragraphs, so the template's
    no-summary branch handles it rather than this raising.
    """
    import re

    if not isinstance(summary, str):
        return []
    text = summary
    for pattern, repl in _MARKDOWN_STRIPS:
        text = re.sub(pattern, repl, text, flags=re.MULTILINE)
    return [
        " ".join(part.strip().split())
        for part in re.split(r"\n\n+", text)
        if part.strip()
    ]


async def _landscape_list(request: Request, fragment: str, rows_key: str,
                          fetch, label: str, extra: dict,
                          match=None) -> HTMLResponse:
    """Shared body for the two full-length OpenCTI-backed lists.

    Separate from `_landscape`, which serves the Overview cards and trims to
    five rows. These are whole tabs and keep every row the endpoint
    returned.

    `match`, when given, filters the rows and `total` reports how many were
    read before filtering, so an empty result can say whether the filter was
    responsible rather than implying the source had nothing.
    """
    from ion.services.opencti_service import get_opencti_service

    def answer(ctx: dict) -> HTMLResponse:
        return templates.TemplateResponse(
            request=request, name=fragment,
            context={rows_key: None, "configured": True, "failed": False,
                     "error": None, "total": None, **extra, **ctx},
            status_code=200,
        )

    service = get_opencti_service()
    if not service.is_configured:
        return answer({"configured": False})

    try:
        payload = await fetch(service)
    except Exception as exc:
        logger.exception("Threat intel %s could not be rendered", label)
        return answer({"failed": True, "error": type(exc).__name__})

    rows = _rows(payload, rows_key)
    if rows is None:
        return answer({rows_key: None})
    return answer({
        rows_key: [r for r in rows if match(r)] if match else rows,
        "total": len(rows),
    })


@router.get(
    "/threat-intel/ioc-feed",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))],
)
async def threat_intel_ioc_feed_fragment(
    request: Request,
    min_score: int = Query(0, ge=0, le=100),
) -> HTMLResponse:
    """The IOC Feed table.

    Each row's sightings cell fetches itself from
    /ui/threat-intel/ioc-spark, which is the shape the page had: it rendered
    the table and then filled the cells, so the first paint is not blocked
    by one request per row.
    """
    from ion.web.threat_landscape_api import get_ioc_feed

    async def fetch(_service):
        return await get_ioc_feed(
            limit=IOC_FEED_LIMIT, min_score=min_score, user=None
        )

    return await _landscape_list(
        request, IOC_FEED_FRAGMENT, "indicators", fetch, "ioc-feed",
        {"min_score": min_score, "label_limit": IOC_LABEL_LIMIT},
    )


@router.get(
    "/threat-intel/ioc-spark",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))],
)
def threat_intel_ioc_spark_fragment(
    request: Request,
    value: str = Query(..., min_length=2, max_length=512),
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """One indicator's local sightings over the last year.

    Reads the same local tables GET /api/threat-intel/ioc-sightings reads,
    so a cell and the JSON agree about how often an indicator has been seen.
    No OpenCTI, so this answers on a deployment where the feed itself does
    not.
    """
    from ion.web.threat_intel_api import ioc_sightings

    def answer(ctx: dict) -> HTMLResponse:
        return templates.TemplateResponse(
            request=request, name=IOC_SPARK_FRAGMENT,
            context={"months": SPARK_MONTHS, "failed": False,
                     "series": None, "total": None, **ctx},
            status_code=200,
        )

    try:
        payload = ioc_sightings(
            value=value, months=SPARK_MONTHS, session=session, user=None
        )
    except Exception:
        logger.exception("Threat intel sightings sparkline could not be read")
        return answer({"failed": True})

    return answer({
        "series": _rows(payload, "series"),
        # `is not none` is not enough here: the template treats a falsy
        # total as nothing seen, which is right, and only a non-number needs
        # to become None so it cannot be rendered.
        "total": (payload or {}).get("total_sightings")
        if isinstance(payload, dict) else None,
    })


@router.get(
    "/threat-intel/reports",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))],
)
async def threat_intel_reports_fragment(
    request: Request,
    q: str = Query("", max_length=200),
) -> HTMLResponse:
    """The Reports tab's card list, optionally filtered.

    The filter is a substring match over the reports the endpoint returns,
    because GET /api/threat-landscape/reports takes no search parameter. It
    ran in the browser before; running it here changes nothing about which
    reports match and lets the empty state say whether the filter was
    responsible.
    """
    from ion.web.threat_landscape_api import get_recent_reports

    term = q.strip()

    async def fetch(_service):
        return await get_recent_reports(limit=REPORT_LIMIT, user=None)

    return await _landscape_list(
        request, REPORTS_FRAGMENT, "reports", fetch, "reports",
        {"q": term, "summary_chars": REPORT_SUMMARY_CHARS},
        # The filter is a substring match over what the endpoint returned,
        # because it takes no search parameter. `total` is how many were
        # read, so the empty state can say that clearing the filter helps.
        match=(lambda r: term.lower() in (r.get("name") or "").lower())
        if term else None,
    )


async def _report_or_technique(request: Request, fragment: str, key: str,
                               fetch, extra: dict) -> HTMLResponse:
    """Shared body for the two drill panels.

    Both slide over the page, both swap a heading out of band, and both have
    the same four outcomes: OpenCTI unconfigured, the read failing, the read
    answering with something unreadable, and the detail.
    """
    from ion.services.opencti_service import get_opencti_service

    def answer(ctx: dict) -> HTMLResponse:
        return templates.TemplateResponse(
            request=request, name=fragment,
            context={"configured": True, "failed": False, "error": None,
                     key: None, **extra, **ctx},
            status_code=200,
        )

    service = get_opencti_service()
    if not service.is_configured:
        return answer({"configured": False})

    try:
        detail = await fetch(service)
    except Exception as exc:
        logger.exception("Threat intel %s drill could not be rendered", key)
        return answer({"failed": True, "error": type(exc).__name__})

    return answer({key: detail if isinstance(detail, dict) else None})


@router.get(
    "/threat-intel/report-drill",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))],
)
async def threat_intel_report_drill_fragment(
    request: Request,
    report_id: str = Query(..., min_length=1, max_length=400),
) -> HTMLResponse:
    """One report's detail."""
    from ion.web.threat_landscape_api import get_report_detail

    async def fetch(_service):
        return await get_report_detail(report_id=report_id, user=None)

    return await _report_or_technique(
        request, REPORT_DRILL_FRAGMENT, "report", fetch,
        {"indicator_limit": REPORT_INDICATOR_LIMIT},
    )


@router.get(
    "/threat-intel/technique-drill",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))],
)
async def threat_intel_technique_drill_fragment(
    request: Request,
    technique_id: str = Query(..., min_length=1, max_length=64),
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """One ATT&CK technique: its tactics, the local cases that triggered it,
    and the actors OpenCTI maps to it.

    Unlike the report drill this reads local case data as well as OpenCTI,
    so it is useful on a deployment with no OpenCTI: the endpoint reports
    its own OpenCTI failure in an `actors_error` field and the fragment
    words that separately from an empty actor list. The two sections answer
    for themselves, which is what the unguarded `.length` reads prevented.
    """
    from ion.web.threat_intel_api import technique_drill

    def answer(ctx: dict) -> HTMLResponse:
        return templates.TemplateResponse(
            request=request, name=TECHNIQUE_DRILL_FRAGMENT,
            context={"technique_id": technique_id, "failed": False,
                     "error": None, "detail": None, "local_cases": None,
                     "actors": None, "local_days": TECHNIQUE_LOCAL_DAYS,
                     **ctx},
            status_code=200,
        )

    try:
        # Not awaited: technique_drill is a sync def, unlike most of the
        # handlers in that module.
        detail = technique_drill(
            technique_id=technique_id, session=session, user=None
        )
    except Exception as exc:
        logger.exception("Threat intel technique drill could not be rendered")
        return answer({"failed": True, "error": type(exc).__name__})

    if not isinstance(detail, dict):
        return answer({"failed": True})

    return answer({
        "detail": detail,
        "local_cases": _rows(detail, "local_cases"),
        "actors": _rows(detail, "actors"),
    })


@router.post(
    "/threat-intel/ai-brief",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))],
)
async def threat_intel_ai_brief_fragment(request: Request) -> HTMLResponse:
    """The AI threat briefing.

    A POST, because POST /api/threat-landscape/ai-summary is one: generating
    a briefing costs a model call. csrf.js attaches the token, and the
    fragment is gated on the same observable:read that endpoint carries.

    The button label and the model line swap out of band, because both sit
    outside this fragment's target and both are part of the panel's state.
    """
    from ion.web.threat_landscape_api import ai_threat_summary

    def answer(ctx: dict) -> HTMLResponse:
        return templates.TemplateResponse(
            request=request, name=AI_BRIEF_FRAGMENT,
            context={"failed": False, "error": None, "summary": None,
                     "model": None, "paragraphs": [], **ctx},
            status_code=200,
        )

    try:
        payload = await ai_threat_summary(user=None)
    except Exception as exc:
        logger.exception("Threat intel AI briefing could not be generated")
        # A detail if the service raised an HTTPException with one, because
        # that is the message the endpoint means a caller to read, and the
        # class name otherwise.
        detail = getattr(exc, "detail", None)
        return answer({"failed": True,
                       "error": detail if isinstance(detail, str)
                       else type(exc).__name__})

    if not isinstance(payload, dict):
        return answer({"failed": True})

    summary = payload.get("summary")
    return answer({
        "summary": summary,
        "model": payload.get("model"),
        "paragraphs": brief_paragraphs(summary),
    })
