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
import os
import re
from typing import List, Optional

from sqlalchemy.orm import Session

from ion.core.tenant_context import (
    reset_tenant_connection,
    reset_tenant_id,
    set_tenant_connection,
    set_tenant_id,
)
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


def _platform_global(user) -> bool:
    """Whether this user may act across every estate.

    ``tenant_id IS NULL`` alone must not grant that: every user that predates
    multi-tenancy is NULL, so an upgrade that enables the flag would otherwise
    hand each of them every client estate. Platform-global therefore also
    requires the admin role; a NULL non-admin stays on the default estate until
    an admin binds them.
    """
    if getattr(user, "tenant_id", None) is not None:
        return False
    try:
        return bool(user.is_admin)
    except Exception:  # noqa: BLE001 — a user object without roles is not global
        return False


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
    if not _platform_global(user):
        default = get_default_tenant(db)
        return [default] if default else []
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

    if not _platform_global(user):
        # NULL tenant_id without the admin role: a pre-tenancy analyst. They
        # get the default estate only; anything else needs an admin to set
        # users.tenant_id.
        default = get_default_tenant(db)
        if requested and default and requested not in (default.slug, str(default.id)):
            logger.warning(
                "tenant: user %s is not platform-global and requested %r — refused",
                getattr(user, "id", "?"),
                requested,
            )
        return default

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


# ION_TENANT_<SLUG>_<SUFFIX> -> the key the ES/Kibana config dicts use.
_ES_ENV_KEYS = {
    "ES_URL": "url",
    "ES_USERNAME": "username",
    "ES_PASSWORD": "password",
    "ES_API_KEY": "api_key",
    "ES_ALERT_INDEX": "alert_index",
    "ES_CASE_INDEX": "case_index",
    "ES_VERIFY_SSL": "verify_ssl",
}
_KIBANA_ENV_KEYS = {
    "KIBANA_URL": "url",
    "KIBANA_USERNAME": "username",
    "KIBANA_PASSWORD": "password",
    "KIBANA_SPACE": "space_id",
    "KIBANA_VERIFY_SSL": "verify_ssl",
}
_BOOL_KEYS = {"verify_ssl"}


def _read_env_section(prefix: str, mapping: dict) -> dict:
    """Collect one tenant's settings from the environment.

    Unset and empty variables are omitted rather than returned blank, so a
    tenant that specifies only a URL inherits the rest from the process config
    instead of blanking a working connection with empty strings.
    """
    out: dict = {}
    for suffix, key in mapping.items():
        raw = os.environ.get(f"{prefix}_{suffix}", "").strip()
        if not raw:
            continue
        if key in _BOOL_KEYS:
            lowered = raw.lower()
            if lowered in ("true", "1", "yes"):
                out[key] = True
            elif lowered in ("false", "0", "no"):
                out[key] = False
            else:
                # An unrecognized value inherits rather than parsing as False:
                # the only bool key is verify_ssl, where False silently
                # disables TLS verification for this tenant's cluster.
                logger.warning(
                    "tenant: %s_%s=%r is not a boolean; inheriting the process value",
                    prefix, suffix, raw,
                )
            continue
        out[key] = raw
    return out


def tenant_connection(tenant: Optional[Tenant]) -> Optional[dict]:
    """The ES/Kibana overlay for a tenant, or None to use the process config.

    Read from ``ION_TENANT_<SLUG>_*``. Resolved once when the tenant is bound
    and carried in the request context, because ``ElasticsearchService()`` is
    constructed at ~30 call sites and reads its config on each construction.

    A tenant with no variables set returns None and therefore inherits the
    process-wide estate, which is what makes the default tenant a no-op.
    """
    if tenant is None or not multi_tenant_enabled():
        return None
    prefix = tenant.env_prefix
    es = _read_env_section(prefix, _ES_ENV_KEYS)
    kibana = _read_env_section(prefix, _KIBANA_ENV_KEYS)
    if not es and not kibana:
        return None
    return {"es": es, "kibana": kibana}


def tenant_env_vars(tenant: Tenant) -> List[str]:
    """Every variable name this tenant reads. For docs and admin diagnostics."""
    prefix = tenant.env_prefix
    return [f"{prefix}_{s}" for s in (*_ES_ENV_KEYS, *_KIBANA_ENV_KEYS)]


def bind_request_tenant(db: Session, user, requested: Optional[str] = None):
    """Resolve and install the active tenant. Returns (tenant, reset_tokens).

    Callers must reset the tokens when the request ends; ``tenant_scope`` is the
    better choice anywhere a ``with`` block fits.
    """
    tenant = resolve_tenant_for_user(db, user, requested)
    tokens = (
        set_tenant_id(tenant.id if tenant else None),
        set_tenant_connection(tenant_connection(tenant)),
    )
    return tenant, tokens


def unbind_request_tenant(tokens) -> None:
    """Restore whatever was active before :func:`bind_request_tenant`."""
    id_token, conn_token = tokens
    reset_tenant_connection(conn_token)
    reset_tenant_id(id_token)
