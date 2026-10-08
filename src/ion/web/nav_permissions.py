"""Navigation visibility derived from what the routes actually enforce.

Review §23 credits ION with "permission-sensitive visibility", which is true
of about a fifth of the navigation. The header carries 55 links. Twelve are
hidden by a hand-written list of element ids in ``app.js``::

    const grcItems = [
        ['nav-grc-compliance',  perms.has('alert:read')],
        ['nav-grc-servicedesk', perms.has('system:settings')],
        ...
    ];

while the permission each page requires is declared on the route. Two lists,
maintained by hand, in different languages, that have to agree — and a link
added without an id and without a matching JS entry shows to everyone and
hands them a 403.

The routes were never unsafe; they enforce regardless of what the menu
shows. This is a usability and trust defect, not a security one. It is still
worth fixing, because a menu full of links that fail is a menu people stop
reading.

So the second list goes away. :func:`page_permission_map` walks the live
FastAPI routes and reads the permission each page dependency recorded on
itself (see ``PAGE_PERMISSION_ATTR``). A page added tomorrow is covered
without anyone remembering to edit a list, which is the only version of this
that stays true.
"""

from __future__ import annotations

import logging
from typing import Dict, Iterable, List, Set

from ion.auth.dependencies import PAGE_PERMISSION_ATTR

logger = logging.getLogger(__name__)

#: Navigation targets open to any signed-in user, with the reason each one
#: is here. Deliberately short: an exemption per link would make the
#: coverage check meaningless, so anything added needs a reason that is not
#: "the test failed".
EXEMPT_PATHS: Dict[str, str] = {
    # Every entry here is a nav target whose route does NOT declare a
    # permission -- verified by test_nothing_is_both_mapped_and_exempt, which
    # caught nine wrong guesses in the first draft of this list. The derived
    # map is authoritative; this only names what it has nothing to say about.
    #
    # Deliberately short: an exemption per link would make the coverage check
    # meaningless, so anything added needs a reason that is not "the test
    # failed".
    "/": "The dashboard. Every signed-in user lands here.",
    "/guide": "Training material. Withholding it helps nobody.",
    "/workforce": (
        "A person's own onboarding. Hiding it from someone with no "
        "permissions hides it from exactly the people being onboarded, "
        "who need it to earn any."
    ),
    "/soc-roles": "Role reference documentation.",
    "/scheduler": "Guarded by require_page_auth: signed in is the bar.",
    "/alert-prompts": "Guarded by require_page_auth.",
    "/case-grouper": "Guarded by require_page_auth.",
    "/gitlab": "Guarded by require_page_auth.",
    "/investigation-memory": "Guarded by require_page_auth.",
    "/investigation-queue": "Guarded by require_page_auth.",
    "/network-map": "Guarded by require_page_auth.",
    "/stories": "Guarded by require_page_auth.",
}


def _iter_page_routes() -> Iterable[tuple[str, str]]:
    """``(path, permission)`` for every registered page route that declares one.

    Imported lazily: ``ion.web.server`` builds the app at import time and
    importing it at module scope here would make this module unimportable
    from inside the server's own startup.
    """
    from ion.web.server import app

    for route in app.routes:
        path = getattr(route, "path", None)
        if not path or "{" in path:
            # Parameterised routes are not navigation targets.
            continue

        dependant = getattr(route, "dependant", None)
        candidates = []
        if dependant is not None:
            candidates.append(getattr(dependant, "call", None))
            for sub in getattr(dependant, "dependencies", []) or []:
                candidates.append(getattr(sub, "call", None))

        for candidate in candidates:
            permission = getattr(candidate, PAGE_PERMISSION_ATTR, None)
            if permission:
                yield path, permission
                break


def page_permission_map() -> Dict[str, str]:
    """``{path: permission}`` for every page that requires one.

    Read off the routes, so it cannot disagree with what the route enforces.
    """
    found: Dict[str, str] = {}
    for path, permission in _iter_page_routes():
        normalised = path if path == "/" else path.rstrip("/")
        found[normalised] = permission
    return dict(sorted(found.items()))


def visible_nav_paths(permissions: Set[str] | Iterable[str]) -> List[str]:
    """Which navigation targets a holder of ``permissions`` should be shown.

    Exempt paths are always included. Everything else needs its declared
    permission. An unknown permission unlocks nothing, which is what makes
    this safe to drive from a client-supplied set — though the routes
    enforce independently either way, so this is about not showing a link
    that will fail rather than about access control.
    """
    held = set(permissions or ())
    visible = list(EXEMPT_PATHS)
    for path, permission in page_permission_map().items():
        if permission in held:
            visible.append(path)
    return sorted(set(visible))


def nav_permission_payload() -> Dict[str, object]:
    """What the client needs to hide links it should not offer."""
    mapping = page_permission_map()
    return {
        "pages": mapping,
        "exempt": sorted(EXEMPT_PATHS),
        "count": len(mapping),
    }


__all__ = [
    "EXEMPT_PATHS",
    "page_permission_map",
    "visible_nav_paths",
    "nav_permission_payload",
]
