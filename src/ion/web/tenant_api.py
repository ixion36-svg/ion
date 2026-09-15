"""Tenant listing and the estate switcher.

Two endpoints, both about *which* estate the analyst is looking at — never about
what they may do there. Switching cannot widen access: the same resolver runs on
every subsequent request and refuses a tenant the user is not entitled to, so a
forged cookie buys nothing a legitimate switch would not have given.

The selection lives in a cookie rather than a session row so no schema change is
needed and it survives naturally across page loads. It is untrusted input and
treated as such on every request.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ion.auth.dependencies import TENANT_COOKIE, get_current_user
from ion.models.user import User
from ion.services.tenant_service import (
    accessible_tenants,
    multi_tenant_enabled,
    resolve_tenant_for_user,
)
from ion.storage.database import get_db_session

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/tenants", tags=["tenants"])

# A year: the selection is a preference, not a credential, and re-choosing an
# estate on every session would be noise. Cleared by switching, not by expiry.
_COOKIE_MAX_AGE = 365 * 24 * 3600


class TenantInfo(BaseModel):
    id: int
    slug: str
    name: str
    is_default: bool


class TenantState(BaseModel):
    """What the header toggle needs to render itself."""

    enabled: bool = Field(description="Multi-tenancy is on for this deployment")
    # False for an analyst bound to one estate: they see which, and no control.
    can_switch: bool
    active: Optional[TenantInfo] = None
    available: List[TenantInfo] = []


class SwitchRequest(BaseModel):
    slug: str = Field(min_length=1, max_length=64)


def _info(tenant) -> TenantInfo:
    return TenantInfo(
        id=tenant.id, slug=tenant.slug, name=tenant.name, is_default=tenant.is_default
    )


@router.get("", response_model=TenantState)
def get_tenant_state(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db_session),
) -> TenantState:
    """The estates this analyst may view, and which one is active."""
    if not multi_tenant_enabled():
        return TenantState(enabled=False, can_switch=False)

    available = accessible_tenants(db, current_user)
    requested = request.cookies.get(TENANT_COOKIE)
    active = resolve_tenant_for_user(db, current_user, requested)

    return TenantState(
        enabled=True,
        can_switch=len(available) > 1,
        active=_info(active) if active else None,
        available=[_info(t) for t in available],
    )


@router.post("/switch", response_model=TenantState)
def switch_tenant(
    payload: SwitchRequest,
    request: Request,
    response: Response,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db_session),
) -> TenantState:
    """Point this analyst at another estate.

    Refused rather than silently ignored when the tenant is not one of theirs,
    so a switch that appears to succeed always did.
    """
    if not multi_tenant_enabled():
        raise HTTPException(status_code=404, detail="Multi-tenancy is not enabled")

    allowed = {t.slug: t for t in accessible_tenants(db, current_user)}
    chosen = allowed.get(payload.slug)
    if chosen is None:
        logger.warning(
            "tenant: user %s tried to switch to %r, which is not theirs",
            current_user.id,
            payload.slug,
        )
        raise HTTPException(status_code=403, detail="Not an available estate")

    response.set_cookie(
        TENANT_COOKIE,
        chosen.slug,
        max_age=_COOKIE_MAX_AGE,
        httponly=False,  # the header toggle reads it to render the active estate
        samesite="strict",
        secure=_cookie_secure(request),
        path="/",
    )
    logger.info("tenant: user %s switched to %s", current_user.id, chosen.slug)

    return TenantState(
        enabled=True,
        can_switch=len(allowed) > 1,
        active=_info(chosen),
        available=[_info(t) for t in allowed.values()],
    )


def _cookie_secure(request: Request) -> bool:
    """Match the session cookie's Secure flag rather than hard-coding it.

    Secure when configured OR when the request is HTTPS (direct scheme or
    ``X-Forwarded-Proto`` behind a TLS terminator) — the same rule as the
    session cookie in api.py, so the tenant cookie is not the one cookie left
    without Secure on an HTTPS deployment that never set ION_COOKIE_SECURE. A
    Secure cookie is never returned over plain HTTP, so a dev box still works.
    """
    try:
        from ion.core.config import get_config

        scheme = request.headers.get("X-Forwarded-Proto", request.url.scheme)
        return bool(get_config().cookie_secure) or scheme == "https"
    except Exception:  # pragma: no cover
        return True
