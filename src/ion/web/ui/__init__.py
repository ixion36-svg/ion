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

One module per page, rather than one growing file. 35 pages at the size of
the first two is around 2,000 lines, and more to the point a single file is
a serialization point: the conversions are independent work, and a file
every one of them edits is a file every one of them conflicts in. The
module list below is the only shared line, and it is append-only.
"""
from __future__ import annotations

from fastapi import APIRouter

from ion.web.ui import bob_eval, service_accounts

router = APIRouter(prefix="/ui", tags=["ui-fragments"])

for _page in (service_accounts, bob_eval):
    router.include_router(_page.router)

__all__ = ["router"]
