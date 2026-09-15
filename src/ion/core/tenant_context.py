"""The tenant the current request is acting for.

A ContextVar rather than a parameter threaded through every call: ION has 935
routes and the services beneath them are reached from background loops as well
as request handlers, so passing a tenant explicitly everywhere would be a
change to nearly every signature and would still miss the paths that forget.

Reading this does **not** make a query safe. It supplies the value a query
filters on; nothing here enforces that the filter was written. In this phase
nothing filters ION's own Postgres rows by tenant at all: isolation applies
only to which Elasticsearch/Kibana a request talks to, via the connection
overlay below. Phase 2 adds ``tenant_id`` columns and Postgres row-level
security so that a missing filter fails closed.

Background loops have no request and therefore no ambient tenant, and in this
phase none sets one: every loop talks to the process-wide (default) estate, so
secondary tenants get no background processing yet. :func:`tenant_scope` exists
for the phase-2 loop wiring — a loop that leaves the context unset gets
``None``, which the ES/Kibana overlay resolves to the default estate.
"""

from __future__ import annotations

import contextvars
from contextlib import contextmanager
from typing import Iterator, Optional

# None means "no tenant resolved". It is never a wildcard.
_tenant_id_var: contextvars.ContextVar[Optional[int]] = contextvars.ContextVar(
    "ion_tenant_id", default=None
)

# A platform user (users.tenant_id IS NULL) acting deliberately across tenants —
# support and oversight. Separate from _tenant_id_var so that "no tenant" can
# never be mistaken for "all tenants": crossing the boundary has to be asked for.
_cross_tenant_var: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "ion_cross_tenant", default=False
)

# The active tenant's Elasticsearch and Kibana settings, as
# ``{"es": {...}, "kibana": {...}}``. Carried here, resolved once when the
# tenant is bound, because ``ElasticsearchService()`` is constructed at ~30 call
# sites and reads its config on every construction — a database lookup there
# would put a query in front of every ES call.
_tenant_conn_var: contextvars.ContextVar[Optional[dict]] = contextvars.ContextVar(
    "ion_tenant_conn", default=None
)


def current_tenant_connection() -> Optional[dict]:
    """Connection overlay for the active tenant, or None to use process config."""
    return _tenant_conn_var.get()


def current_tenant_id() -> Optional[int]:
    """The tenant this request acts for, or None when none is resolved."""
    return _tenant_id_var.get()


def is_cross_tenant() -> bool:
    """True when a platform user has explicitly asked to span tenants."""
    return _cross_tenant_var.get()


def set_tenant_id(tenant_id: Optional[int]) -> contextvars.Token:
    """Set the active tenant, returning the token needed to restore it."""
    return _tenant_id_var.set(tenant_id)


def reset_tenant_id(token: contextvars.Token) -> None:
    _tenant_id_var.reset(token)


def set_tenant_connection(connection: Optional[dict]) -> contextvars.Token:
    return _tenant_conn_var.set(connection)


def reset_tenant_connection(token: contextvars.Token) -> None:
    _tenant_conn_var.reset(token)


@contextmanager
def tenant_scope(
    tenant_id: Optional[int],
    *,
    connection: Optional[dict] = None,
    cross_tenant: bool = False,
) -> Iterator[Optional[int]]:
    """Run a block as one tenant, restoring the previous one afterwards.

    Use for background-loop iterations and anywhere a service acts for a tenant
    other than the request's. Restores on exception, so a failed iteration
    cannot leak its tenant into the next one.

    ``connection`` carries that tenant's Elasticsearch/Kibana settings. A scope
    entered without one talks to the process-wide estate, which for a background
    loop iterating tenants would mean querying the wrong cluster — so pass it
    whenever the block does anything with Elastic.
    """
    token = _tenant_id_var.set(tenant_id)
    cross_token = _cross_tenant_var.set(cross_tenant)
    conn_token = _tenant_conn_var.set(connection)
    try:
        yield tenant_id
    finally:
        _tenant_id_var.reset(token)
        _cross_tenant_var.reset(cross_token)
        _tenant_conn_var.reset(conn_token)


@contextmanager
def cross_tenant_scope() -> Iterator[None]:
    """Deliberately span tenants, for platform-level reads only.

    Narrow and explicit on purpose: every use is a place where the isolation
    guarantee is being set aside, and should read that way at the call site.
    """
    token = _cross_tenant_var.set(True)
    try:
        yield
    finally:
        _cross_tenant_var.reset(token)
