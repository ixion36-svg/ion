"""The tenant the current request is acting for.

A ContextVar rather than a parameter threaded through every call: ION has 935
routes and the services beneath them are reached from background loops as well
as request handlers, so passing a tenant explicitly everywhere would be a
change to nearly every signature and would still miss the paths that forget.

Reading this does **not** make a query safe. It supplies the value a query
filters on; nothing here enforces that the filter was written. Enforcement is
Postgres row-level security, which fails closed when a filter is missing.

Background loops have no request and therefore no ambient tenant. They must set
one per iteration with :func:`tenant_scope` — a loop that leaves the context
unset gets ``None``, which every scoped query must treat as "no rows", never as
"all rows". That asymmetry is the whole safety property: forgetting to set a
tenant hides data, it does not leak it.
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


@contextmanager
def tenant_scope(
    tenant_id: Optional[int], *, cross_tenant: bool = False
) -> Iterator[Optional[int]]:
    """Run a block as one tenant, restoring the previous one afterwards.

    Use for background-loop iterations and anywhere a service acts for a tenant
    other than the request's. Restores on exception, so a failed iteration
    cannot leak its tenant into the next one.
    """
    token = _tenant_id_var.set(tenant_id)
    cross_token = _cross_tenant_var.set(cross_tenant)
    try:
        yield tenant_id
    finally:
        _tenant_id_var.reset(token)
        _cross_tenant_var.reset(cross_token)


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
