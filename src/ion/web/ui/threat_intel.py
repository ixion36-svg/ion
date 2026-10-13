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
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """The match-alert table, optionally filtered to unread.

    `unread_only` is the page's Show Unread toggle and is bounded exactly as
    GET /api/threat-intel/matches bounds it, so a filter the API would
    refuse is not reachable through the page.
    """
    from ion.services.threat_intel_service import ThreatIntelService
    from ion.web.threat_intel_api import _match_to_dict

    try:
        items, total = ThreatIntelService(session).get_matches(
            unread_only=unread_only, limit=MATCH_LIMIT
        )
        matches = [_match_to_dict(m) for m in items]
    except Exception:
        logger.exception("Threat intel matches fragment could not be rendered")
        return templates.TemplateResponse(
            request=request,
            name=MATCHES_FRAGMENT,
            context={"failed": True, "matches": None, "total": None,
                     "unread_only": unread_only},
            status_code=200,
        )

    return templates.TemplateResponse(
        request=request,
        name=MATCHES_FRAGMENT,
        context={"failed": False, "matches": matches, "total": total,
                 "unread_only": unread_only},
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
