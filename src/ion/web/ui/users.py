"""The user and role administration table for /users.

users.html built the whole table out of template literals and wrote it into
`#users-tbody` with innerHTML at five sites, plus a sixth that wrote the role
picker into both modals, across 301 lines of inline JavaScript.

Four things here are not a straight port.

The action buttons. The page rendered Edit, Reset Password and Delete on
every row for every viewer. Delete on the viewer's own row is refused
outright by `DELETE /api/users/{user_id}`, so the only way to learn the rule
was to click it and read the error. It is derived from the rule rather than
restated: the refusal comes from `api.user_delete_refusal`, the one
definition the route itself now calls.

The viewer's permissions. The page is behind `user:read`, but Edit and Reset
Password need `user:update`, Delete needs `user:delete` and New User needs
`user:create`. A viewer holding only `user:read` was shown all four. The
fragment asks the viewer for each permission and renders only the controls
that viewer could actually use.

The role picker. `loadRoles()` called `renderRoleCheckboxes()` only inside
`if (response.ok)`, so a failed read left both pickers as empty `<div>`s
with nothing said about it. An empty Roles fieldset and a role list that
could not be read are opposite instructions to an administrator creating an
account, and the catch only reached `console.error`. The picker fragment
says which it is.

The permission count. `(role.permissions || []).length` printed "0
permissions" for a role whose permission list never arrived, which on a
role-assignment widget is the most consequential figure on the page read
confidently out of nothing.

The `safe_url` filter has no site on this page. Every URL the fragments emit
is a literal path plus an integer primary key; nothing here is a URL read
out of a column.
"""
from __future__ import annotations

import logging
from typing import Any, Literal

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.models.user import User
from ion.storage.database import get_db_session
from ion.web.api import (
    roles_list_payload,
    user_delete_refusal,
    users_list_payload,
)
from ion.web.ui._shared import plain, templates

logger = logging.getLogger(__name__)

router = APIRouter()

FRAGMENT = "_fragments/users.html"
ROLES_FRAGMENT = "_fragments/users_role_options.html"

#: The permission `GET /api/users` and `GET /api/roles` both carry. Spelled
#: once so the two fragments cannot drift from each other or from the API.
_READ_PERM = "user:read"

#: What Edit, Reset Password, Delete and New User are really gated on, read
#: off the routes in ion.web.api. A viewer without these must not be shown
#: the control: on this page a button is a claim about what the viewer may
#: do, and the only way to test that claim used to be to make the change.
_UPDATE_PERM = "user:update"
_DELETE_PERM = "user:delete"
_CREATE_PERM = "user:create"

#: Presentation for the role picker, moved off the page. Icons are written as
#: escapes rather than the numeric character references the JavaScript used,
#: because Jinja autoescapes an `&` and would render `&amp;#9881;`.
ROLE_META: dict[str, dict[str, str]] = {
    "admin": {"tier": "Admin", "color": "#f87171", "icon": "⚙",
              "short": "Full system access"},
    "analyst": {"tier": "L1", "color": "#6de4ff", "icon": "\U0001f50e",
                "short": "Alert triage & case creation"},
    "senior_analyst": {"tier": "L2", "color": "#6de4ff", "icon": "\U0001f50d",
                       "short": "Case closure & enrichment"},
    "principal_analyst": {"tier": "L3", "color": "#6de4ff",
                          "icon": "\U0001f3af",
                          "short": "Playbooks, forensics & security"},
    "lead": {"tier": "Lead", "color": "#a78bfa", "icon": "\U0001f465",
             "short": "Team oversight & operations"},
    "forensic": {"tier": "DFIR", "color": "#f59e0b", "icon": "\U0001f575",
                 "short": "Evidence & forensic investigations"},
    "soc_engineer": {"tier": "Eng L1", "color": "#22c55e",
                     "icon": "\U0001f527",
                     "short": "Log onboarding & tooling"},
    "senior_engineer": {"tier": "Eng L2", "color": "#22c55e",
                        "icon": "⚙",
                        "short": "Detection engineering & pipelines"},
    "platform_engineer": {"tier": "Eng L3", "color": "#22c55e",
                          "icon": "\U0001f3d7",
                          "short": "Infrastructure & architecture"},
    "engineering": {"tier": "Eng", "color": "#22c55e", "icon": "\U0001f6e0",
                    "short": "Full engineering access"},
}

_UNKNOWN_ROLE_META = {"tier": "?", "color": "#64748b", "icon": "■"}

#: Capability areas, in the order the page listed them. A prefix match means
#: "holds at least one permission in this area"; the two bare names are whole
#: permissions rather than families.
_CAPABILITY_PREFIXES: tuple[tuple[str, str], ...] = (
    ("Alerts", "alert:"),
    ("Cases", "case:"),
    ("Observables", "observable:"),
    ("Playbooks", "playbook:"),
    ("Forensics", "forensic:"),
    ("Integrations", "integration:"),
    ("Security", "security:"),
    ("System", "system:"),
)
_CAPABILITY_EXACT: tuple[tuple[str, str], ...] = (
    ("AI", "ai:chat"),
    ("Discover", "discover:read"),
)

#: Which container each picker renders into, and the `name` its checkboxes
#: carry. A literal mapping rather than interpolating the query value, so the
#: fragment cannot be asked to emit an attribute of the caller's choosing.
ROLE_GROUPS: dict[str, str] = {
    "new": "new-user-roles",
    "edit": "edit-user-roles",
}


def _text(raw: object) -> str | None:
    """A column's value as a plain string, enum member or not.

    None survives as None, because a missing display name is not the string
    "None" and the template has to be able to tell the two apart.

    Nothing on `User` is `SQLEnum` today: `employment_type` is the one column
    with a closed value set and it is `String(20)`. The unwrap still goes
    through `ui._shared.plain`, because tightening that column later would
    otherwise start rendering "EmploymentType.CONTRACTOR" into the markup
    while every string comparison kept working, which is the trap two earlier
    conversions hit.
    """
    value = plain(raw)
    if value is None:
        return None
    return str(value)


def _identifier(raw: object) -> str | None:
    """An optional identifier column, with the empty string folded into None.

    The opposite call to the one a number gets, and deliberately so. A
    measured 0 is a value, which is why every count on these pages is tested
    with `is not none`. An identifier is not a measurement: `update_user`
    normalises a blank `elastic_uid` to NULL on the way in with
    `value or None`, so "" and NULL are one state in the column and reach
    here as two. Telling them apart in the template would colour an empty
    cell as though a UID had been resolved.
    """
    value = _text(raw)
    if value == "":
        return None
    return value


def _capabilities(permissions: list[str] | None) -> list[str]:
    """The capability pills for a role, in the page's own order."""
    perms = permissions or []
    caps = [
        label for label, prefix in _CAPABILITY_PREFIXES
        if any(p.startswith(prefix) for p in perms)
    ]
    caps.extend(label for label, name in _CAPABILITY_EXACT if name in perms)
    return caps


def _role_view(entry: dict) -> dict[str, Any]:
    """One role widget, with its metadata and permission count resolved."""
    name = _text(entry.get("name")) or ""
    meta = ROLE_META.get(name)
    if meta is None:
        meta = dict(_UNKNOWN_ROLE_META)
        meta["short"] = _text(entry.get("description")) or ""

    permissions = entry.get("permissions")
    return {
        "name": name,
        # The JavaScript did name.replace(/_/g, ' ') for the visible label and
        # kept the underscored name as the checkbox value. Both are needed:
        # the value is what PUT /api/users/{id}/roles matches on.
        "label": name.replace("_", " "),
        "tier": meta["tier"],
        "color": meta["color"],
        "icon": meta["icon"],
        "short": meta["short"],
        "caps": _capabilities(permissions),
        # `is not none`, not len(permissions or []): a role with no
        # permissions is a measurement, and a role whose permission list is
        # missing is not the same claim as a role that grants nothing. The
        # JavaScript's `(role.permissions || []).length` printed 0 for both.
        "permission_count": None if permissions is None else len(permissions),
    }


def _row_view(
    entry: dict,
    *,
    viewer_id: object,
    can_update: bool,
    can_delete: bool,
) -> dict[str, Any]:
    """One table row, with its buttons decided before the markup sees it.

    `user_delete_refusal` is the predicate `DELETE /api/users/{user_id}`
    itself calls, so this cannot keep offering Delete after the route stops
    accepting it, nor withhold it for a rule the route does not have.

    There is no last-administrator rule and no protected-admin rule anywhere
    in the user service, so none is invented here. A button withheld for a
    rule the server does not enforce is the same defect in the other
    direction.
    """
    user_id = entry.get("id")
    delete_refusal = user_delete_refusal(user_id, viewer_id)

    return {
        "id": user_id,
        "username": _text(entry.get("username")),
        "email": _text(entry.get("email")),
        "display_name": _identifier(entry.get("display_name")),
        # None when the payload carries no roles key at all. `[]` means the
        # user holds no role, which is a different claim and the template
        # words it differently.
        "roles": entry.get("roles"),
        "elastic_uid": _identifier(entry.get("elastic_uid")),
        "elastic_username": _identifier(entry.get("elastic_username")),
        "keycloak_sub": _identifier(entry.get("keycloak_sub")),
        # Two-state on purpose, where a count would be three. `is_active` is
        # a non-nullable Boolean column, so there is no unmeasured case for a
        # third branch to report, and a raw row or a round trip through JSON
        # hands back 1 rather than True, which `is true` would read as
        # disabled. The guard that this stays two-state is on the payload:
        # the key is always set, so None never reaches the template.
        "is_active": entry.get("is_active"),
        "last_login": entry.get("last_login"),
        "delete_refusal": delete_refusal,
        # An id of None cannot be addressed by any of the three endpoints, so
        # a button for it would be dead. `is not None` rather than
        # truthiness: user 0 is a user.
        "show_edit": can_update and user_id is not None,
        "show_reset": can_update and user_id is not None,
        "show_delete": (
            can_delete and user_id is not None and delete_refusal is None
        ),
    }


@router.get("/users", response_class=HTMLResponse)
def users_fragment(
    request: Request,
    include_inactive: bool = False,
    user: User = Depends(require_permission(_READ_PERM)),
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """The user table as one fragment.

    The permission is the one `GET /api/users` carries, so the fragment is
    neither a softer nor a harder way in than the endpoint it mirrors.
    `require_permission` rather than `require_page_permission`: the page
    dependency redirects to /login and htmx would swap a password box into
    the middle of the table.

    `user` is used rather than ignored. Which buttons a row may show depends
    on who is looking, both for the self-delete rule and for the three write
    permissions, so the row cannot be rendered without knowing the viewer.
    """
    # Resolved before the try, so a permission lookup can never be reported
    # as a user list that could not be read.
    can_update = user.has_permission(_UPDATE_PERM)
    can_delete = user.has_permission(_DELETE_PERM)
    chrome = {
        "can_update": can_update,
        "can_delete": can_delete,
        "can_create": user.has_permission(_CREATE_PERM),
        "include_inactive": include_inactive,
    }

    try:
        rows = [
            _row_view(
                entry,
                viewer_id=user.id,
                can_update=can_update,
                can_delete=can_delete,
            )
            for entry in users_list_payload(
                session, include_inactive=include_inactive
            )
        ]
    except Exception:
        logger.exception("Users fragment could not be rendered")
        # An empty estate and an unreadable one lead to opposite actions
        # here: "no users" would read as an account database that has been
        # emptied, which on an identity page is an incident. Never render one
        # as the other, and never print a count for a read that failed.
        return templates.TemplateResponse(
            request=request,
            name=FRAGMENT,
            context={"rows": None, "failed": True, **chrome},
        )

    return templates.TemplateResponse(
        request=request,
        name=FRAGMENT,
        context={"rows": rows, "failed": False, **chrome},
    )


@router.get("/users/role-options", response_class=HTMLResponse)
def users_role_options_fragment(
    request: Request,
    group: Literal["new", "edit"] = "new",
    user: User = Depends(require_permission(_READ_PERM)),
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """The role picker for one of the two user modals.

    Replaces the sixth innerHTML site, which rendered the same widget list
    into both modals from one `/api/roles` fetch. The permission is the one
    `GET /api/roles` carries; that endpoint is deliberately gated on
    `user:read` rather than something softer, because it returns the full
    role-to-permission map.

    Each modal asks for its own copy, because the two pickers live in
    different places in the document and carry different field names. One
    request fanned out with an out-of-band swap would make the response's
    meaning depend on which container asked for it.
    """
    field_name = ROLE_GROUPS[group]

    try:
        roles = [_role_view(entry) for entry in roles_list_payload(session)]
    except Exception:
        logger.exception("Role options fragment could not be rendered")
        return templates.TemplateResponse(
            request=request,
            name=ROLES_FRAGMENT,
            context={"roles": None, "failed": True, "field_name": field_name},
        )

    return templates.TemplateResponse(
        request=request,
        name=ROLES_FRAGMENT,
        context={"roles": roles, "failed": False, "field_name": field_name},
    )
