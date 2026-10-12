"""A threat actor's profile, rendered on the server.

threat_intel_actor.html wrote ten innerHTML sites from 91 dense lines of
JavaScript: the aliases line, the description in three variants, the local
case list, the TTP chips and the campaign list, each with its own empty
state.

The page already knew that an OpenCTI lookup can fail, and said so in the
description. It then rendered "No TTPs surfaced by OpenCTI for this actor"
and "No campaigns linked to this actor in OpenCTI" from the same failed
lookup, so a failure reported itself once and claimed an absence twice.
Everything OpenCTI supplies now says the lookup failed when it failed.
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.storage.database import get_db_session
from ion.web.ui._shared import plain, templates

logger = logging.getLogger(__name__)

router = APIRouter()

# The severity words the stylesheet has a `sev-` rule for. The JavaScript
# built `sev-${c.severity}` from the column, so a value outside this set
# produced a class with no rule and an unstyled chip, silently.
KNOWN_SEVERITIES = ("critical", "high", "medium", "low", "info")

# OpenCTI can return a long tail. The page showed 30 and said nothing about
# the rest, so a reader could not tell a complete list from a truncated one.
TTP_LIMIT = 30


def alias_list(raw: object) -> list[str]:
    """Aliases as a list, however OpenCTI returned them.

    The JavaScript accepted a list or a bare string and treated anything
    else as none, which is right: an alias that is neither is not something
    to render, and guessing would put a dict's repr on the page.
    """
    if isinstance(raw, (list, tuple)):
        return [str(a) for a in raw if a]
    if isinstance(raw, str) and raw:
        return [raw]
    return []


def case_rows(cases: list[dict] | None) -> list[dict]:
    """The local case feed, with each severity resolved to a known class."""
    out = []
    for c in cases or []:
        severity = str(plain(c.get("severity")) or "").lower()
        out.append({
            "id": c.get("id"),
            "case_number": c.get("case_number"),
            "title": c.get("title"),
            "severity": severity,
            # A severity the stylesheet has no rule for gets the neutral
            # class and keeps its own word as the label, so an unexpected
            # value is visible rather than unstyled.
            "severity_class": (
                f"sev-{severity}" if severity in KNOWN_SEVERITIES else "sev-info"
            ),
            "severity_known": severity in KNOWN_SEVERITIES,
            "created_at": c.get("created_at"),
        })
    return out


def ttp_chips(actor: dict[str, Any] | None) -> tuple[list[dict], int]:
    """The actor's techniques, and how many were left out.

    Returns the chips and the number not shown, so the template can say the
    list is truncated. The page cut at 30 and said nothing, so a reader had
    no way to tell a complete list from a clipped one.
    """
    ttps = (actor or {}).get("ttps") or []
    chips = [
        {
            "id": str(t.get("mitre_id") or t.get("id") or ""),
            "name": str(t.get("name") or ""),
        }
        for t in ttps
        if isinstance(t, dict)
    ]
    shown = chips[:TTP_LIMIT]
    return shown, max(0, len(chips) - len(shown))


@router.get(
    "/threat-intel/actors/{entity_id}",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission("observable:read"))],
)
async def threat_intel_actor_fragment(
    request: Request,
    entity_id: str,
    entity_class: str = Query("intrusion_set"),
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """The whole actor profile as one fragment.

    `observable:read` matches /api/threat-intel/actors/{id}/profile exactly.

    It calls actor_profile_payload, the function that endpoint now calls
    too, so the OpenCTI fan-out, the alias-derived case search and the
    180-day window have one definition rather than two.
    """
    from ion.web.threat_intel_api import actor_profile_payload

    try:
        payload = await actor_profile_payload(entity_id, entity_class, session)
    except Exception:
        logger.exception("Threat actor fragment could not be rendered")
        # Distinct from either half failing: nothing was read at all, so
        # the fragment must not render an actor, a case list or an empty
        # state for either.
        return templates.TemplateResponse(
            request=request,
            name="_fragments/threat_intel_actor.html",
            context={"failed": True, "entity_id": entity_id, "actor": None,
                     "actor_error": None, "cases_error": None, "cases": [],
                     "aliases": [], "ttps": [], "ttps_hidden": 0,
                     "campaigns": []},
        )

    actor = payload.get("actor") or {}
    ttps, ttps_hidden = ttp_chips(actor)
    return templates.TemplateResponse(
        request=request,
        name="_fragments/threat_intel_actor.html",
        context={
            "failed": False,
            "entity_id": payload.get("entity_id") or entity_id,
            "actor": actor or None,
            "actor_error": payload.get("actor_error"),
            "cases_error": payload.get("cases_error"),
            "cases": case_rows(payload.get("recent_cases")),
            "aliases": alias_list(actor.get("aliases")),
            "ttps": ttps,
            "ttps_hidden": ttps_hidden,
            "campaigns": [c for c in (actor.get("campaigns") or [])
                          if isinstance(c, dict)],
        },
    )
