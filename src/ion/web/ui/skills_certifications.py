"""Suggested certificates for where somebody is and where they are going.

Served as a fragment rather than built on the training page, because that
page renders through the generated `training-node-N` templates that
tools/ produce from its markup. Adding a block there means hand-writing
entries into a generated file, which the next regeneration would argue
with. A fragment has its own template and nothing generates it.

Scoped to the caller throughout: the service reads their career goal and
their own recorded certificates, and resolves nobody else's. The gate
matches the JSON route it mirrors, /api/skills/suggested-certifications,
which is the same `alert:read` the rest of the skills own-data routes
use -- a softer gate here would be a way to read somebody's assessment
context without the permission the API asks for.
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from ion.auth.dependencies import get_db_session, require_permission
from ion.models.user import User
from ion.web.ui._shared import render_view

logger = logging.getLogger(__name__)

router = APIRouter()

FRAGMENT = "_fragments/skills_suggested_certifications.html"


@router.get("/skills/suggested-certifications")
def suggested_certifications_fragment(
    request: Request,
    session: Session = Depends(get_db_session),
    user: User = Depends(require_permission("alert:read")),
):
    """The caller's suggested certificates, current role and next."""
    from ion.services.role_skills_service import suggested_certifications

    view: dict[str, Any] = {
        "failed": False, "has_goal": False, "current": None, "target": None,
        "same_role": False, "caveat": "",
    }
    try:
        view.update(suggested_certifications(session, user.id))
    except Exception:
        logger.exception("Suggested certifications could not be built")
        # Not an empty list of suggestions: the read failed, so "nothing
        # suggested" would be a claim this does not get to make.
        view["failed"] = True

    return render_view(request, FRAGMENT, view)
