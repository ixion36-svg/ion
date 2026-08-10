"""v0.79.0 — everyone can add documents; you can only delete your own.

Before this, ``document:delete`` was a blunt role permission: admin,
engineering and platform_engineer could delete **anything**, and the other
seven roles could delete **nothing** — not even a document they had just
uploaded themselves. The library is shared, so the rule people actually
expect is ownership: add freely, remove your own work, leave everyone else's
alone.

That rule needs three things, and these tests pin all three:

  1. ``Document.created_by_id`` exists and is stamped on every create path.
     A create path that forgets it produces a document its own author cannot
     delete.
  2. The ownership check runs **inside the endpoint, against the row it just
     loaded**, before the delete. An ownership rule enforced in the caller or
     hidden in the UI is not enforced (the v0.20.1 workbench TOCTOU lesson).
  3. Deletes are audited — who removed what, and under which authority
     (owner, or a ``document:delete`` holder acting over someone else's work).

The ~600 documents that predate the column have ``created_by_id = None``.
They are owned by nobody, so they must NOT become deletable by everybody —
they stay behind ``document:delete``. That is the direction that fails safe,
and `test_legacy_unowned_document_is_not_everyones_to_delete` pins it.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

API = Path("src/ion/web/api.py")


@pytest.fixture(scope="module")
def api_src() -> str:
    return API.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def delete_fn(api_src: str) -> str:
    """The body of delete_document, decorator included."""
    start = api_src.index('@router.delete("/documents/{document_id}")')
    rest = api_src[start:]
    # next top-level decorator ends the function
    nxt = rest.index("\n@router.", 10)
    return rest[:nxt]


# ── the column exists and means what we think ────────────────────────────


def test_document_has_an_owner_column():
    from ion.models.document import Document

    col = Document.__table__.columns.get("created_by_id")
    assert col is not None, "Document.created_by_id is missing"
    assert col.nullable, "legacy documents have no author — the column must be nullable"
    assert [fk.target_fullname for fk in col.foreign_keys] == ["users.id"]


def test_owner_column_has_a_migration():
    """create_all() only creates missing TABLES, never missing columns — an
    existing deploy gets the column only if something ALTERs the table."""
    db = Path("src/ion/storage/database.py").read_text(encoding="utf-8")
    assert '_add_column_tolerant(engine, "documents", "created_by_id"' in db


# ── every create path stamps the author ──────────────────────────────────


@pytest.mark.parametrize("marker", [
    "async def upload_document",
    "async def render_template",
    "async def batch_render_template",
])
def test_create_paths_stamp_the_author(marker, api_src):
    """A create path that forgets this produces a document its own author
    cannot delete — the exact failure this feature exists to prevent."""
    start = api_src.index(marker)
    body = api_src[start:]
    body = body[:body.index("\n@router.")]
    assert "created_by_id" in body, f"{marker} does not stamp created_by_id"
    assert "current_user" in body, f"{marker} has no current_user to attribute to"


# ── the delete rule ──────────────────────────────────────────────────────


def test_delete_is_not_gated_on_document_delete_alone(delete_fn):
    """The endpoint gate must be the one everybody holds, or an analyst can
    never reach the ownership branch at all."""
    assert 'require_permission("document:read")' in delete_fn
    assert 'dependencies=[Depends(require_permission("document:delete"))]' not in delete_fn


def test_ownership_is_checked_before_the_delete(delete_fn):
    """TOCTOU: the check must sit between loading the row and deleting it —
    not in the caller, not in the template."""
    check_at = delete_fn.index("created_by_id")
    delete_at = delete_fn.index("services.render.delete_document")
    assert check_at < delete_at, "the delete happens before ownership is established"

    raise_at = delete_fn.index("status_code=403")
    assert raise_at < delete_at, "the 403 is raised after the row is already gone"


def test_owner_or_document_delete_holder_may_delete(delete_fn):
    assert "is_owner" in delete_fn
    assert 'has_permission("document:delete")' in delete_fn
    assert re.search(r"if not \(is_owner or may_delete_any\)", delete_fn), \
        "the two branches are not combined as owner-OR-privileged"


def test_legacy_unowned_document_is_not_everyones_to_delete(delete_fn):
    """created_by_id is None for ~600 pre-existing documents. `None == None`
    would make every one of them everyone's to delete; the guard must require
    a real owner id before calling someone the owner."""
    assert "owner_id is not None and owner_id == current_user.id" in delete_fn


# ── the audit trail ──────────────────────────────────────────────────────


def test_delete_is_audited_with_who_and_under_what_authority(delete_fn):
    assert 'action="document_delete"' in delete_fn
    assert "user_id=current_user.id" in delete_fn
    assert 'resource_type="document"' in delete_fn
    # which of the two branches allowed it — an admin deleting someone else's
    # document is a different event from an author tidying up their own
    assert "'owner' if is_owner else 'document:delete'" in delete_fn


def test_audit_failure_cannot_undo_the_delete(delete_fn):
    """The delete is already committed when the audit row is written. If the
    audit write throws, it must be logged, not raised — otherwise a logging
    fault surfaces as a failed delete that actually happened."""
    audit_at = delete_fn.index('action="document_delete"')
    tail = delete_fn[audit_at:]
    assert "except Exception:" in tail
    assert "non-fatal" in tail


def test_document_create_is_audited(api_src):
    start = api_src.index("async def upload_document")
    body = api_src[start:]
    body = body[:body.index("\n@router.")]
    assert 'action="document_create"' in body
