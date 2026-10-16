"""Server-rendered HTML fragments for htmx.

The redesign's `server` column passes when a template contains no
`innerHTML`. The reason is not taste: a thing built from strings in
JavaScript cannot be restyled from markup, so every such site is a place a
sweep of the stylesheet silently fails to reach.

This package is where the replacements live. A page keeps its shell in its
own template and pulls its data-driven parts from `/ui/...` with `hx-get`,
so the markup has one definition, in Jinja, on the server.

Why `/ui` and not `/api`:

  * `/api` is a JSON contract. Other things consume it, including the MCP
    surface and the tests, and adding HTML responses to it would make
    "what does this endpoint return" depend on the caller.
  * A fragment is a view, versioned with the template it belongs to, not
    with the API.

Why `require_permission` rather than `require_page_permission`: the page
dependency redirects to /login when a session has expired, and htmx would
swap a login page into the middle of a dashboard. A 403 is not swapped by
default, so the stale content stays and the user sees no lie.

Each endpoint reuses the same service function its JSON counterpart calls,
so the two cannot drift apart.

One module per page, discovered rather than listed. A module list would be
a line that every one of the remaining conversions has to edit, which is
the one thing that makes independent work conflict. Dropping a module in
the package is the whole registration step.

The loader is deliberately strict. It does not swallow ImportError: a
fragment module that cannot be imported takes the app down at startup
rather than quietly serving nothing, because a 404 on a fragment shows the
user an empty panel that looks like an absence of data. Same reason a
module without a `router` is an error and not a skip.
"""
from __future__ import annotations

import importlib
import pkgutil

from fastapi import APIRouter

router = APIRouter(prefix="/ui", tags=["ui-fragments"])


def _page_modules(search_path: list[str] | None = None) -> list[str]:
    """Every fragment module in a package directory, underscore names excluded.

    `_shared` and any other helper are private by that convention. Sorted so
    the mounted route order does not depend on filesystem order.
    """
    return sorted(
        m.name
        for m in pkgutil.iter_modules(search_path or __path__)
        if not m.name.startswith("_")
    )


def mount_page_modules(
    target: APIRouter,
    search_path: list[str] | None = None,
    package: str | None = None,
) -> list[str]:
    """Import each page module and include its router. Returns the names.

    The arguments exist so this can be tested against a throwaway package
    rather than against the live one. The first version of its test planted
    a probe module in ion/web/ui itself and reimported, which is a race:
    another process starting a server inside that window imports a package
    containing a deliberately broken module and dies at startup. A guard
    that breaks the thing it guards during a parallel run is not a guard.

    It refuses rather than skips. A module that cannot be imported, or that
    defines no `router`, takes the app down at startup instead of quietly
    serving nothing, because a 404 on a fragment renders an empty panel that
    reads to the user as "no data" rather than "not wired up".
    """
    package = package or __name__
    names = _page_modules(search_path)
    for name in names:
        mod = importlib.import_module(f"{package}.{name}")
        page_router = getattr(mod, "router", None)
        if page_router is None:
            raise ImportError(
                f"{package}.{name} defines no `router`. Every fragment module "
                "must expose one, or its endpoints are silently unreachable."
            )
        target.include_router(page_router)
    return names


mount_page_modules(router)

__all__ = ["router", "mount_page_modules", "_page_modules"]
