"""Documents: the library list.

Stage one of documents.html. The page has 28 DOM write sites, and this
takes the one that matters most: the document list, which is the whole
browsing surface and the place every control on the page is reached from.
The version history, the rendered-document modal and the folder tree are
later stages.

What the JavaScript did, measured by reading it, and why each is not a
cosmetic port:

  * **The Delete button was on every row.** `DELETE /api/documents/{id}`
    gates on `document:read`, which everyone holds, and that is deliberate:
    the real rule is ownership and the handler enforces it against the row
    it just loaded, your own document or anyone's with `document:delete`.
    Its docstring cites the v0.20.1 workbench TOCTOU lesson for why the
    check lives there. So the gate is right and the page never asked the
    question: a reader who owns nothing was shown Delete on every row and
    got a 403 from each one. `may_delete` is computed here, from the same
    two facts the handler uses.

  * ``data-args='[${d.id}, ${JSON.stringify(d.name)}]'``. JSON.stringify
    escapes `"` and leaves `'` alone, and the attribute is single quoted,
    so a document called `Bob's SOP` closed the attribute early,
    event-delegation.js threw on the fragment, logged, and returned. The
    control looked live and did nothing. Document names are free text, so
    this was not hypothetical.

  * ``${d.collection_id || 'null'}``. A document in no folder and one whose
    folder id the payload did not carry became the same argument.

  * `(d.current_version || 1)` printed "v1" for a document whose version
    was missing, which is a confident claim about which revision is on
    screen.

  * `d.output_format` and `d.source_template_version` were interpolated
    unguarded, so a payload missing either printed "undefined" in a badge.

  * `formatDate` in static/js/app.js is `new Date(iso).toLocaleDateString()`
    over `isoformat()` of a naive UTC column, so every date on this page
    was the viewer's local reading of a UTC value. The helper is shared, so
    several pages inherit it; this one stops guessing and names the zone.

  * The folder badge came from `allCollections.find(...)`, a second read, so
    a failed collections read removed every folder badge and the rows said
    nothing about it. The documents payload already carries
    `collection_name`, so the badge no longer depends on that read at all.

Three outcomes, never two. The list could not be read, the library is
empty, and there are documents. "No documents found" and "we could not read
your library" lead to opposite actions.

This reads through RenderService.list_documents, the function GET
/api/documents calls, rather than through the endpoint itself. The endpoint
is the usual choice on this project, and here it cannot be: its response
does not carry `created_by_id`, so a fragment built from it could not tell
whether to offer Delete. The rows are otherwise the rows the JSON reports.
"""
from __future__ import annotations

import logging
from datetime import timezone
from typing import Any, Optional, TypedDict

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import get_current_user, require_permission
from ion.models.user import User
from ion.storage.database import get_db_session
from ion.web.ui._shared import parse_instant, plain, render_view

logger = logging.getLogger(__name__)

router = APIRouter()

FRAGMENT = "_fragments/documents_list.html"

#: What GET /api/documents and the page route both require.
PERMISSION = "document:read"

#: What lets an account delete a document it does not own. Not PERMISSION:
#: the delete endpoint's gate is document:read and the ownership check runs
#: in the handler, so this is the other half of the same rule.
DELETE_ANY = "document:delete"

#: What GET /api/collections requires. Not PERMISSION, and that is the
#: point: an account may read documents and not the folder hierarchy they
#: sit in, so the folder dimension of the filter is withheld rather than
#: silently answered wrong.
FOLDER_PERMISSION = "template:read"


class DocumentRow(TypedDict):
    """One row of the library.

    `version` and `template_version` are None when the payload carried no
    readable number, where the page printed v1 and the word undefined.
    `may_delete` answers the question the delete endpoint will ask.
    """

    id: Any
    name: Optional[str]
    output_format: Optional[str]
    doc_type: Optional[str]
    folder: Optional[str]
    collection_id: Any
    status: Optional[str]
    tags: list[str]
    version: Optional[int]
    template_id: Any
    template_version: Optional[int]
    archived: bool
    when: Optional[str]
    may_delete: bool


class DocumentsView(TypedDict):
    """`rows` is None when the read failed or answered something that is not
    a list. [] is an empty library.

    `folder_filter` says what happened to the folder dimension, which is the
    only one this route cannot always answer. GET /api/collections requires
    `template:read`, not `document:read`, so a reader who can see documents
    may not be allowed the folder hierarchy at all. The page asked for it,
    logged the refusal to the console and carried on, so the folder filter
    quietly did nothing and the rows said nothing about it.

    "applied"   the subtree was resolved and the filter is in the result
    "none"      no folder was asked for
    "withheld"  the viewer may not read collections
    "failed"    the read was attempted and did not answer
    """

    rows: Optional[list[DocumentRow]]
    folder_filter: str


def _number(value: Any) -> Optional[int]:
    """An int, or None for anything that is not one.

    bool is excluded before the check because True is an int in Python and
    "version 1" is not what it means.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def instant_label(value: Any) -> Optional[str]:
    """`2026-09-01 10:30 UTC`, or None when there is no usable timestamp.

    The zone is named because the column is naive UTC and the page was
    presenting it as local time. An aware value is converted, not
    relabelled.
    """
    parsed = parse_instant(value)
    if parsed is None:
        return None
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def may_delete(document: Any, user: Any) -> bool:
    """The question DELETE /api/documents/{id} asks of the loaded row.

    Owner, or an account holding document:delete. A document with no owner
    predates `created_by_id` and goes to the second branch, because unowned
    work is not everyone's to delete.
    """
    owner = getattr(document, "created_by_id", None)
    if owner is not None and user is not None and owner == getattr(
            user, "id", None):
        return True
    return bool(user is not None and user.has_permission(DELETE_ANY))


def _tags(document: Any) -> list[str]:
    raw = getattr(document, "tags", None)
    if not isinstance(raw, list):
        return []
    names = []
    for tag in raw:
        name = plain(getattr(tag, "name", tag))
        if name:
            names.append(str(name))
    return names


def document_row(document: Any, user: Any) -> Optional[DocumentRow]:
    """One row, or None for an entry that is not a document at all.

    A single bad entry drops out and its neighbours still render.
    """
    doc_id = getattr(document, "id", None)
    if doc_id is None:
        return None
    name = plain(getattr(document, "name", None))
    fmt = plain(getattr(document, "output_format", None))
    collection = getattr(document, "collection", None)
    folder = plain(getattr(collection, "name", None)) if collection else None
    status = plain(getattr(document, "status", None))
    template = getattr(document, "source_template", None)
    doc_type = plain(getattr(template, "document_type", None)) if template \
        else None
    return {
        "id": doc_id,
        "name": str(name) if name is not None else None,
        "output_format": str(fmt) if fmt is not None else None,
        "doc_type": str(doc_type) if doc_type is not None else None,
        "folder": str(folder) if folder is not None else None,
        "collection_id": getattr(document, "collection_id", None),
        "status": str(status) if status is not None else None,
        "tags": _tags(document),
        "version": _number(getattr(document, "current_version", None)),
        "template_id": getattr(document, "source_template_id", None),
        "template_version": _number(
            getattr(document, "source_template_version", None)),
        "archived": status == "archived",
        "when": instant_label(getattr(document, "created_at", None)),
        "may_delete": may_delete(document, user),
    }


#: The folder value meaning "documents in no folder at all", from the
#: page's own `selectedFolderId === 'uncategorized'`.
UNFILED = "uncategorized"


def subtree(collections: Any, root: Any) -> Optional[set]:
    """Every collection id at or under `root`, or None when the hierarchy is
    not readable.

    The page walked this client-side in `isInFolderOrSubfolder`, over the
    `/api/collections?flat=true` payload. Cycles cannot happen in the data
    but are survived anyway, because a parent pointing back up its own
    chain would otherwise hang the request rather than fail it.
    """
    if not isinstance(collections, list):
        return None
    children: dict = {}
    for item in collections:
        parent = item.get("parent_id") if isinstance(item, dict) else \
            getattr(item, "parent_id", None)
        ident = item.get("id") if isinstance(item, dict) else \
            getattr(item, "id", None)
        if ident is None:
            continue
        children.setdefault(parent, []).append(ident)
    found, queue = set(), [root]
    while queue:
        current = queue.pop()
        if current in found:
            continue
        found.add(current)
        queue.extend(children.get(current, []))
    return found


def matches(row: DocumentRow, *, search: str, fmt: str,
            status: str, tag: str, folder_ids: Optional[set],
            unfiled: bool) -> bool:
    """The five filter dimensions, as filterDocuments applied them.

    `d.name.toLowerCase()` threw on a document with no name, which took the
    whole list down through loadDocuments' catch and read as "Failed to
    load documents". A row with no name simply does not match a search here.
    """
    if search:
        name = (row["name"] or "").lower()
        if search not in name:
            return False
    if fmt and row["output_format"] != fmt:
        return False
    if status and row["status"] != status:
        return False
    if tag and tag not in row["tags"]:
        return False
    if unfiled:
        return row["collection_id"] is None
    if folder_ids is not None and row["collection_id"] not in folder_ids:
        return False
    return True


def documents_view(documents: Any, user: Any, *, search: str = "",
                   fmt: str = "", status: str = "", tag: str = "",
                   folder: Optional[str] = None,
                   collections: Any = "not-read",
                   may_read_folders: bool = True) -> DocumentsView:
    """The service's answer as the list's model.

    A result that is not a list is the failed outcome. The endpoint returns
    a bare list rather than an object, so there is no key to look under and
    `_shared.rows` does not apply.

    The filter runs here rather than in the browser, so it covers the whole
    library instead of whatever the page had loaded.
    """
    if not isinstance(documents, list):
        return {"rows": None, "folder_filter": "none"}

    unfiled = folder == UNFILED
    folder_ids: Optional[set] = None
    state = "none"
    if folder and not unfiled:
        if not may_read_folders:
            state = "withheld"
        else:
            try:
                root = int(folder)
            except (TypeError, ValueError):
                state = "failed"
            else:
                folder_ids = subtree(collections, root)
                state = "applied" if folder_ids is not None else "failed"
    elif unfiled:
        state = "applied"

    rows = []
    for raw in documents:
        row = document_row(raw, user)
        if row is None:
            continue
        if matches(row, search=search.lower(), fmt=fmt, status=status,
                   tag=tag, folder_ids=folder_ids, unfiled=unfiled):
            rows.append(row)
    if documents and not rows and not any(
            (search, fmt, status, tag, folder)):
        # Nothing matched and nothing was asked for, so every row was
        # unreadable rather than filtered out.
        return {"rows": None, "folder_filter": state}
    return {"rows": rows, "folder_filter": state}


@router.get(
    "/documents/list",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))],
)
def documents_list_fragment(
    request: Request,
    search: str = "",
    format: str = "",
    status: str = "",
    tag: str = "",
    folder: str = "",
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> Response:
    """The document library, filtered.

    The five parameters are the five controls the page filtered with, by the
    names those controls carry, so the page can hand them over as a form.
    The filter ran in the browser over `allDocuments`, which GET
    /api/documents caps, so it searched whatever had been loaded and
    presented the result as the library. It runs here now, over all of it.

    `format` shadows the builtin deliberately: it is the query parameter's
    name, taken from the control's id, and the shadowing is contained to
    this signature.

    Synchronous: list_documents is one query through the repository and the
    session is open on this thread.
    """
    from ion.services.render_service import RenderService

    try:
        documents = RenderService(session).list_documents()
    except Exception:
        logger.exception("Documents fragment could not list documents")
        documents = None

    # Only read the hierarchy when a folder subtree actually has to be
    # resolved, and only when this account may. GET /api/collections
    # requires template:read, which document:read does not imply.
    collections: Any = None
    may_read_folders = bool(
        current_user and current_user.has_permission(FOLDER_PERMISSION))
    if folder and folder != UNFILED and may_read_folders:
        try:
            from ion.services.template_service import TemplateService

            collections = [
                {"id": c.id, "parent_id": c.parent_id}
                for c in TemplateService(session).list_collections()
            ]
        except Exception:
            logger.exception(
                "Documents fragment could not read the folder hierarchy")
            collections = None

    return render_view(request, FRAGMENT, documents_view(
        documents, current_user, search=search, fmt=format, status=status,
        tag=tag, folder=folder or None, collections=collections,
        may_read_folders=may_read_folders))


# ---------------------------------------------------------------------------
# Version history
# ---------------------------------------------------------------------------
#
# GET /api/documents/{id}/versions (document:read) lists the amendments.
# loadVersions wrote four times: loading, empty, the table, and the catch,
# so a failed read and an empty history were already distinct. The rest
# was defects:
#
#   * Revert was offered on every version that was not current. POST
#     /api/documents/{id}/revert/{n} requires document:update, which
#     document:read does not imply, so a reader got a button that answered
#     403. The same shape as the Delete control on the library list.
#   * `data-args='[${v.version_number}]'` by interpolation.
#   * `v.amendment_reason || '-'` printed one dash for an amendment nobody
#     explained and the same dash for a field the payload did not carry.
#   * formatDate again, so the dates were the viewer's local reading of a
#     naive UTC column.
#   * `isCurrent` compared against `currentDocVersion`, a page variable set
#     when the modal opened, where the document row holds the fact.

VERSIONS_FRAGMENT = "_fragments/documents_versions.html"

#: What POST /api/documents/{id}/revert/{n} requires. Not PERMISSION: the
#: history is readable by anyone who can read the document, and reverting
#: it is not.
REVERT = "document:update"


class VersionRow(TypedDict):
    """One amendment.

    `number` is whatever the payload carried, so the argument the dispatcher
    parses is honest about a version number that is not a number. `reason`
    and `author` are None when nothing was recorded, which the template
    words rather than printing a dash that meant two things.
    """

    number: Any
    reason: Optional[str]
    author: Optional[str]
    when: Optional[str]
    is_current: bool
    may_revert: bool


class VersionsView(TypedDict):
    """`rows` is None when the document or its history could not be read."""

    rows: Optional[list[VersionRow]]


def version_row(version: Any, *, current: Optional[int],
                may_revert: bool) -> Optional[VersionRow]:
    """One row, or None for an entry with no version number at all."""
    number = getattr(version, "version_number", None)
    if number is None:
        return None
    reason = plain(getattr(version, "amendment_reason", None))
    author = plain(getattr(version, "amended_by", None))
    is_current = current is not None and number == current
    return {
        "number": number,
        "reason": str(reason) if reason else None,
        "author": str(author) if author else None,
        "when": instant_label(getattr(version, "created_at", None)),
        "is_current": is_current,
        # Reverting to the version you are already on is not an action.
        "may_revert": may_revert and not is_current,
    }


def versions_view(versions: Any, *, current: Any,
                  may_revert: bool) -> VersionsView:
    """The repository's answer as the history's model."""
    if not isinstance(versions, list):
        return {"rows": None}
    rows = [r for r in (version_row(v, current=_number(current),
                                    may_revert=may_revert)
                        for v in versions) if r is not None]
    if versions and not rows:
        return {"rows": None}
    return {"rows": rows}


@router.get(
    "/documents/{document_id}/versions",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))],
)
def documents_versions_fragment(
    request: Request,
    document_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> Response:
    """The version history table.

    Reads through the same repository the endpoint uses, which also gives
    the document's current version: the page compared against a variable it
    had set when the modal opened, and a stale one would have marked the
    wrong row as current.
    """
    from ion.storage.document_repository import DocumentRepository

    current: Any = None
    try:
        repo = DocumentRepository(session)
        document = repo.get_by_id(document_id)
        if document is None:
            # The endpoint raises 404 here, and a document we cannot read is
            # not a document with no history.
            versions: Any = None
        else:
            current = getattr(document, "current_version", None)
            versions = repo.list_versions(document_id)
    except Exception:
        logger.exception(
            "Documents fragment could not read versions for %s", document_id)
        versions = None

    may_revert = bool(
        current_user and current_user.has_permission(REVERT))
    return render_view(request, VERSIONS_FRAGMENT, versions_view(
        versions, current=current, may_revert=may_revert))
