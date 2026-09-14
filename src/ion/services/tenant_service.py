"""Resolving which tenant a request acts for, and the default tenant.

Two rules govern everything here.

**Off means unchanged.** With ``multi_tenant`` off there is one implicit tenant
and its connection is the process-wide ES/Kibana config, so a single-estate
deploy behaves exactly as it did before this module existed.

**Unresolved is not unrestricted.** A user bound to a tenant gets that tenant. A
platform user (``users.tenant_id IS NULL``) gets whichever tenant they selected,
and nothing at all until they select one. Failing to resolve a tenant must show
no data; it must never fall back to showing all of it.

The selection a platform user makes arrives as a request header or query
parameter, which is caller-controlled — so it is validated against the tenant
table and against the caller's own right to cross tenants before it is trusted.
"""

from __future__ import annotations

import logging
import re
from typing import List, Optional

from sqlalchemy.orm import Session

from ion.core.tenant_context import set_tenant_id
from ion.models.tenant import TENANT_SLUG_PATTERN, Tenant

logger = logging.getLogger(__name__)

DEFAULT_TENANT_SLUG = "default"
_SLUG_RE = re.compile(TENANT_SLUG_PATTERN)


def multi_tenant_enabled() -> bool:
    try:
        from ion.core.config import get_config

        return bool(getattr(get_config(), "multi_tenant", False))
    except Exception:
        logger.debug("tenant: config unavailable, assuming single-tenant", exc_info=True)
        return False


def valid_slug(slug: str) -> bool:
    return bool(slug) and bool(_SLUG_RE.match(slug))


def get_default_tenant(db: Session) -> Optional[Tenant]:
    """The estate ION serves when no tenant is selected."""
    return (
        db.query(Tenant)
        .filter(Tenant.is_default.is_(True), Tenant.is_active.is_(True))
        .first()
    )


def ensure_default_tenant(db: Session) -> Tenant:
    """Create the default tenant if it does not exist. Idempotent.

    Its connection columns are left blank on purpose, so it inherits the
    process-wide ES/Kibana config — that is what makes enabling multi-tenancy on
    an existing deploy a no-op until a second tenant is actually added.
    """
    existing = (
        db.query(Tenant)
        .filter(Tenant.slug == DEFAULT_TENANT_SLUG)
        .first()
    )
    if existing:
        if not existing.is_default:
            existing.is_default = True
            db.commit()
        return existing

    tenant = Tenant(
        slug=DEFAULT_TENANT_SLUG,
        name="Default",
        description=(
            "The estate this instance served before multi-tenancy. Connection "
            "fields are blank so it inherits the process-wide ES/Kibana config."
        ),
        is_active=True,
        is_default=True,
    )
    db.add(tenant)
    db.commit()
    db.refresh(tenant)
    logger.info("Created default tenant (id=%s)", tenant.id)
    return tenant


def list_tenants(db: Session, *, active_only: bool = True) -> List[Tenant]:
    q = db.query(Tenant)
    if active_only:
        q = q.filter(Tenant.is_active.is_(True))
    return q.order_by(Tenant.is_default.desc(), Tenant.name.asc()).all()


def get_tenant(db: Session, tenant_id: int) -> Optional[Tenant]:
    return (
        db.query(Tenant)
        .filter(Tenant.id == tenant_id, Tenant.is_active.is_(True))
        .first()
    )


def get_tenant_by_slug(db: Session, slug: str) -> Optional[Tenant]:
    if not valid_slug(slug):
        return None
    return (
        db.query(Tenant)
        .filter(Tenant.slug == slug, Tenant.is_active.is_(True))
        .first()
    )


def accessible_tenants(db: Session, user) -> List[Tenant]:
    """Tenants this user may act for.

    A tenant-bound user has exactly one, and it is theirs whether or not it is
    still active — an inactive tenant yields an empty list rather than promoting
    them to seeing everything.
    """
    bound = getattr(user, "tenant_id", None)
    if bound is not None:
        tenant = get_tenant(db, bound)
        return [tenant] if tenant else []
    return list_tenants(db, active_only=True)


def resolve_tenant_for_user(
    db: Session, user, requested: Optional[str] = None
) -> Optional[Tenant]:
    """The tenant a request should act for, or None if it may act for none.

    ``requested`` is a caller-supplied slug or id and is therefore untrusted: a
    tenant-bound user asking for somebody else's tenant is refused and left with
    their own, never given the one they asked for.
    """
    bound = getattr(user, "tenant_id", None)

    if bound is not None:
        tenant = get_tenant(db, bound)
        if requested and tenant and requested not in (tenant.slug, str(tenant.id)):
            logger.warning(
                "tenant: user %s is bound to %s and requested %r — refused",
                getattr(user, "id", "?"),
                tenant.slug,
                requested,
            )
        return tenant

    # Platform user: honour an explicit selection, else the default.
    if requested:
        chosen = get_tenant_by_slug(db, requested)
        if chosen is None and str(requested).isdigit():
            chosen = get_tenant(db, int(requested))
        if chosen is not None:
            return chosen
        logger.warning("tenant: no active tenant matches %r", requested)
        return None

    return get_default_tenant(db)


def bind_request_tenant(db: Session, user, requested: Optional[str] = None):
    """Resolve and install the active tenant. Returns (tenant, reset_token).

    Callers must reset the token when the request ends; ``tenant_scope`` is the
    better choice anywhere a ``with`` block fits.
    """
    tenant = resolve_tenant_for_user(db, user, requested)
    token = set_tenant_id(tenant.id if tenant else None)
    return tenant, token
