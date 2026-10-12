"""The signed-in user's own account card, and the Elastic lookup result.

profile.html built four blocks of markup with innerHTML: the account
information grid, its load-failure message, and the two outcomes of the
Elastic UID lookup. Those are what moved here.

What did not move is the change-password form and the identity-mapping
inputs. A server-rendered form means the server echoing field values back
into markup, which is exactly wrong for a password box, and for the identity
inputs it would put the Save control inside a swap target where a failed
render can take it away. The page keeps a narrow `/api/auth/me` fetch that
assigns `.value` and nothing else, so no entry field's value is ever
server-rendered and every control stays outside every swap target.

Keeping that fetch has a second, sharper reason. A user flagged
`must_change_password` is refused everything outside
``_PWD_CHANGE_ALLOWED_PREFIXES`` in ion/auth/dependencies.py, and
`/api/auth/me` is on that list while `/ui/profile` is not. So the one user
who must reach this page keeps the password notice and the form, and loses
only the account card, which degrades honestly through
static/js/htmx-errors.js. Closing that gap is a one-line addition to that
tuple and it is not this module's file to edit; it is in the report.

Two shared helpers have no site on this page, which is worth saying rather
than leaving as an omission a reader has to notice:

* ``ui._shared.plain`` unwraps SQLEnum columns. Nothing rendered here is
  one. Every field comes off ``User``, whose columns are String, Boolean,
  Integer and DateTime, and roles and permissions arrive as ``.name``
  strings.
* ``|safe_url`` guards a stored URL. This page renders no stored URL. The
  only links in the fragments are literals in the template text.

There is likewise no number on this page to apply ``is not none`` to. ION's
``User`` has no password-age or password-changed column, so the rule's usual
site does not exist. Where the distinction does bite is the collections and
the optional strings, and those are guarded that way below and in the
templates: a role list that is empty is not a role list that is missing.
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import get_current_user
from ion.models.user import User
from ion.storage.database import get_db_session
from ion.web.ui._shared import templates

logger = logging.getLogger(__name__)

router = APIRouter()

ACCOUNT_FRAGMENT = "_fragments/profile_account.html"
RESOLVE_FRAGMENT = "_fragments/profile_resolve.html"


@router.get("/profile", response_class=HTMLResponse)
def profile_fragment(
    request: Request,
    current_user: User = Depends(get_current_user),
) -> HTMLResponse:
    """The Account Information card body: who the caller is signed in as.

    Replaces two innerHTML sites in profile.html, the six-field grid and the
    "Error loading profile" message it fell back to.

    It calls ``api.current_user_payload``, the same function GET
    /api/auth/me calls, rather than rebuilding the dict. The part that
    matters is the permission set: it unions over ``effective_roles``, which
    focus mode filters, so a second copy reading ``roles`` would list
    permissions the session does not currently carry.

    The caller can only ever see their own row. ``get_current_user``
    resolves the ``User`` from the session cookie, ``current_user_payload``
    reads attributes of that object and queries nothing, and this route
    declares no path or query parameter at all, so there is no input through
    which another account could be named. There is no object-level check to
    mirror here because there is no object to choose.

    The dependency is bare ``get_current_user``, which is what all five
    endpoints this page talks to require: reading and editing your own
    account needs no permission beyond being signed in, so there is no
    ``require_permission`` to mirror and a named one here would make the
    fragment stricter than its API rather than equal to it. Unauthenticated
    gets 401 rather than the /login redirect a page dependency would give,
    because htmx must never swap a login form into a page the user is
    reading.
    """
    from ion.web.api import current_user_payload

    try:
        payload = current_user_payload(current_user)
        # The JavaScript sorted this before joining, and an unsorted
        # permission list is unreadable at the lengths ION's roles produce.
        # Inside the try: a payload missing the key is a read that did not
        # give us what we asked for, which is the failure branch, not a 500.
        permissions = sorted(payload["permissions"])
    except Exception:
        logger.exception("Profile fragment could not be rendered")
        # A failed read is not an account with no email and no roles. The
        # fragment says which it is, because "you have no roles" and "we
        # could not look" lead to opposite actions.
        return templates.TemplateResponse(
            request=request,
            name=ACCOUNT_FRAGMENT,
            context={"user": None, "last_login": None, "permissions": None,
                     "failed": True},
            status_code=200,
        )

    return templates.TemplateResponse(
        request=request,
        name=ACCOUNT_FRAGMENT,
        context={
            "user": payload,
            # The instant, not the payload's ISO string. The `ts` macro
            # formats a datetime as "YYYY-MM-DD HH:MM" and can say whose
            # clock it is on; handed the string it can only echo the raw
            # ISO text back, microseconds and all.
            "last_login": current_user.last_login,
            "permissions": permissions,
            "failed": False,
        },
    )


@router.post("/profile/resolve-elastic", response_class=HTMLResponse)
def profile_resolve_elastic_fragment(
    request: Request,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """The Elastic UID lookup result, replacing the other two innerHTML sites.

    It calls ``api.resolve_elastic_payload``, the same function POST
    /api/auth/profile/resolve-elastic calls, so the candidate order and the
    Kibana-not-configured gate have one definition. That function scopes its
    write to ``id=current_user.id``, so this cannot resolve or overwrite
    anybody else's identity mapping.

    Three outcomes, not two. The lookup matched; the lookup ran and found no
    exact match, which means the user has no Elastic identity under the
    names tried; or the lookup itself failed, which says nothing about
    whether they have one. The JavaScript this replaces collapsed the third
    into a toast and left the result box empty, so a Kibana outage read as
    "no such user".

    On a match the response carries ``HX-Trigger: profile:changed``, which
    the page listens for to re-read the identity fields, because the UID
    this wrote lives in an input the page owns rather than in this fragment.
    """
    from ion.web.api import resolve_elastic_payload

    context: dict[str, Any] = {"result": None, "lookup_error": None}
    try:
        payload = resolve_elastic_payload(current_user, session)
    except HTTPException as exc:
        # The configured-ness gate, raised by the shared function. Its own
        # wording is better than anything restated here: it names Kibana.
        context["lookup_error"] = str(exc.detail)
        return templates.TemplateResponse(
            request=request, name=RESOLVE_FRAGMENT, context=context,
            status_code=200,
        )
    except Exception:
        logger.exception("Elastic UID lookup could not be completed")
        context["lookup_error"] = (
            "The Elastic lookup could not be completed."
        )
        return templates.TemplateResponse(
            request=request, name=RESOLVE_FRAGMENT, context=context,
            status_code=200,
        )

    context["result"] = payload
    resolved = payload.get("resolved") is True
    headers = {"HX-Trigger": "profile:changed"} if resolved else None
    return templates.TemplateResponse(
        request=request, name=RESOLVE_FRAGMENT, context=context,
        headers=headers,
    )
