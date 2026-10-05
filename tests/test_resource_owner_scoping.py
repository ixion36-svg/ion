"""Possessing an id is not authorization: notes folders and doc-analysis jobs.

Two entry points assigned or returned another user's resource on the strength
of an id alone. Notes could be filed into a foreign folder by create/update
(the dedicated move endpoint checked, the other two did not), and the
document-analysis job read returned any job to any ``ai:chat`` holder.

These pin the owner check on every path that assigns ``folder_id`` and on the
job read, including the cases that must still be allowed: an owned folder, an
explicit uncategorize, and the owner's own job.
"""

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from ion.models.base import Base
from ion.models.note_folder import NoteFolder
from ion.models.service_desk import DocAnalysisJob
from ion.models.user import User
from ion.services import large_doc_service as lds
from ion.web.notes_api import (
    NoteCreate,
    NoteMove,
    NoteUpdate,
    create_note,
    move_note,
    update_note,
)


@pytest.fixture
def session():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    s.add_all([
        User(id=1, username="alice", email="alice@x.y", password_hash="x"),
        User(id=2, username="bob", email="bob@x.y", password_hash="x"),
    ])
    # Folder 10 is Bob's; folder 11 is Alice's own.
    s.add_all([
        NoteFolder(id=10, user_id=2, name="bob-private"),
        NoteFolder(id=11, user_id=1, name="alice-own"),
    ])
    s.commit()
    yield s
    s.close()


class _Alice:
    id = 1


# ── notes: every folder_id assignment is owner-checked ──────────────────────

def test_create_rejects_foreign_folder(session):
    with pytest.raises(HTTPException) as caught:
        create_note(NoteCreate(title="n", folder_id=10), user=_Alice(), session=session)
    assert caught.value.status_code == 404


def test_create_accepts_own_folder(session):
    note = create_note(NoteCreate(title="n", folder_id=11), user=_Alice(), session=session)
    assert note["folder_id"] == 11 and note["user_id"] == 1


def test_create_accepts_no_folder(session):
    note = create_note(NoteCreate(title="n"), user=_Alice(), session=session)
    assert note["folder_id"] is None


def test_update_rejects_foreign_folder(session):
    note = create_note(NoteCreate(title="n"), user=_Alice(), session=session)
    with pytest.raises(HTTPException) as caught:
        update_note(note["id"], NoteUpdate(folder_id=10), user=_Alice(), session=session)
    assert caught.value.status_code == 404
    session.rollback()
    assert session.get(NoteFolder, 10).notes == []


def test_update_accepts_own_folder(session):
    note = create_note(NoteCreate(title="n"), user=_Alice(), session=session)
    updated = update_note(note["id"], NoteUpdate(folder_id=11), user=_Alice(), session=session)
    assert updated["folder_id"] == 11


def test_move_rejects_foreign_folder(session):
    note = create_note(NoteCreate(title="n"), user=_Alice(), session=session)
    with pytest.raises(HTTPException) as caught:
        move_note(note["id"], NoteMove(folder_id=10), user=_Alice(), session=session)
    assert caught.value.status_code == 404


def test_move_uncategorize_still_allowed(session):
    note = create_note(NoteCreate(title="n", folder_id=11), user=_Alice(), session=session)
    moved = move_note(note["id"], NoteMove(folder_id=None), user=_Alice(), session=session)
    assert moved["folder_id"] is None


# ── document analysis: the job read is owner-scoped ─────────────────────────

def _job(session, job_id, owner):
    session.add(DocAnalysisJob(
        id=job_id, created_by_id=owner, status="done",
        filename="private.txt", result_md="owner-only analysis",
    ))
    session.commit()


def test_job_read_allows_owner(session):
    _job(session, "a" * 32, owner=1)
    job = lds.get_job(session, "a" * 32, 1)
    assert job is not None and job["result"]["result"] == "owner-only analysis"


def test_job_read_denies_other_user(session):
    _job(session, "a" * 32, owner=1)
    assert lds.get_job(session, "a" * 32, 2) is None


def test_job_read_denies_unowned_job(session):
    """created_by_id is nullable; an orphaned job is readable by nobody."""
    _job(session, "b" * 32, owner=None)
    assert lds.get_job(session, "b" * 32, 1) is None


def test_job_read_missing_id_is_none(session):
    assert lds.get_job(session, "c" * 32, 1) is None
