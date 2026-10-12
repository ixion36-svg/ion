"""One template's version history: the list, and the detail modal.

versions.html built the version list out of string concatenation and wrote
it into `#versions-list` at three sites, and built the detail modal's meta
bar at two more.

Three things the JavaScript got wrong, which are the substance of this
conversion rather than the move itself.

`loadVersions()` put `v.message` into innerHTML with no escapeHtml while
escaping the checkpoint name on the line above, so the message was a
stored-XSS sink reachable from `PUT /api/templates/{id}`.

A template that does not exist and a database that will not answer both
rendered "Failed to load versions". The JSON endpoint separates them as 404
against 500, and one wording for both sends an operator looking for an
outage that is a mistyped id.

`formatDate()` was `toLocaleDateString` over a naive stamp, so the column
read the stored digits as the viewer's own clock and converted out of a zone
the value was never in. The `ts` macro leaves that decision to
ion.web.templating._ts_parts and static/js/local-time.js.

Neither `ui._shared.plain` nor the `safe_url` filter has a site here.
TemplateVersion carries no SQLEnum column, every one of its fields is
Integer, Text, Boolean or DateTime, so nothing arrives as an enum member;
and the only URLs on the page are the two built from the template id and a
version number below, which are integers from the path rather than values
out of a column.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.core.exceptions import TemplateNotFoundError, VersionNotFoundError
from ion.services.version_service import VersionService
from ion.storage.database import get_db_session
from ion.web.ui._shared import templates

logger = logging.getLogger(__name__)

router = APIRouter()

LIST_TEMPLATE = "_fragments/versions_list.html"
DETAIL_TEMPLATE = "_fragments/versions_detail.html"

#: The permission on every /api/templates/{id}/versions* read. Named once so
#: the three fragments below cannot drift apart from each other either.
READ = "template:read"

# What guards the template id, in full: this permission, plus the existence
# check inside the service. A Template carries no owner, no tenant and no
# collection ACL, so a user who can read template 5 can read template 6's
# history on the API exactly as they can here. The fragment mirrors that
# rather than inventing a scope the API does not enforce, because a fragment
# that disagrees with its endpoint about the same row is the worse failure:
# whichever is wrong, nothing in a diff shows which.


@router.get(
    "/templates/{template_id}/versions",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(READ))],
)
def versions_list_fragment(
    request: Request,
    template_id: int,
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """One template's version history, rows and all.

    It calls VersionService.list_versions, which is what
    /api/templates/{template_id}/versions calls, rather than querying the
    version table itself. That function is also where the template's
    existence is checked, so a fragment with its own query could answer for
    a template the API reports as 404.

    Three outcomes, not two. A template that does not exist, a database that
    will not answer, and a template whose history is empty are three
    different claims, and the JSON endpoint separates the first two as 404
    against 500.
    """
    rows = None
    try:
        rows = VersionService(session).list_versions(template_id)
        state = "ok"
    except TemplateNotFoundError:
        # Not worth a traceback: a mistyped id is not an outage, and the JSON
        # endpoint answers it with a 404 rather than a 500.
        state = "missing"
    except Exception:
        logger.exception(
            "version history for template %s could not be rendered", template_id
        )
        state = "failed"

    # template_id goes in separately because the missing and failed branches
    # render with no rows to read it off.
    return templates.TemplateResponse(
        request=request,
        name=LIST_TEMPLATE,
        context={"rows": rows, "state": state, "template_id": template_id},
    )


@router.get(
    "/templates/{template_id}/versions/{version_number}",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(READ))],
)
def version_detail_fragment(
    request: Request,
    template_id: int,
    version_number: int,
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """One version, as the body of the detail modal.

    Mirrors /api/templates/{template_id}/versions/{version_number}, through
    the same VersionService.get_version, which is also the only existence
    check that endpoint has: it looks a version up by (template_id,
    version_number) and raises VersionNotFoundError when the pair has no
    row, so an unknown template id lands in the same branch as an unknown
    version. The 404 the JSON endpoint returns for either becomes the
    missing state here.
    """
    version, rollback_to = None, None
    try:
        version = VersionService(session).get_version(template_id, version_number)
        state, rollback_to = "ok", version_number
    except (VersionNotFoundError, TemplateNotFoundError):
        state = "missing"
    except Exception:
        logger.exception(
            "version %s of template %s could not be rendered",
            version_number, template_id,
        )
        state = "failed"

    return templates.TemplateResponse(
        request=request,
        name=DETAIL_TEMPLATE,
        context={
            "kind": "version",
            "state": state,
            "version": version,
            "version_number": version_number,
            "rollback_to": rollback_to,
            "template_id": template_id,
        },
    )


@router.get(
    "/templates/{template_id}/versions/diff/{from_version}/{to_version}",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(READ))],
)
def version_diff_fragment(
    request: Request,
    template_id: int,
    from_version: int,
    to_version: int,
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """Two versions compared, as the body of the same modal.

    Mirrors /api/templates/{template_id}/diff/{from_version}/{to_version}
    through the same VersionService.diff_versions. The route is under
    .../versions/diff/... rather than its own top-level path so that one
    prefix carries one permission and the list fragment can build both of
    its URLs off one base. It cannot collide with the detail route above:
    that one is a single path segment where this is three.

    Rollback offers the later of the pair, which is what showDiff() set
    `currentVersionNum` to. Rolling a comparison back to the version on its
    left would undo the change being read.
    """
    diff, rollback_to = None, None
    try:
        diff = VersionService(session).diff_versions(
            template_id, from_version, to_version
        )
        state, rollback_to = "ok", to_version
    except (VersionNotFoundError, TemplateNotFoundError):
        state = "missing"
    except Exception:
        logger.exception(
            "diff of versions %s..%s of template %s could not be rendered",
            from_version, to_version, template_id,
        )
        state = "failed"

    return templates.TemplateResponse(
        request=request,
        name=DETAIL_TEMPLATE,
        context={
            "kind": "diff",
            "state": state,
            "diff": diff,
            "from_version": from_version,
            "to_version": to_version,
            "version_number": None,
            "rollback_to": rollback_to,
            "template_id": template_id,
        },
    )
