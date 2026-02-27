"""Notes API endpoints for the analyst notepad."""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ixion.auth.dependencies import get_current_user, get_db_session
from ixion.models.user import User
from ixion.storage.analyst_note_repository import AnalystNoteRepository

router = APIRouter(tags=["notes"])
logger = logging.getLogger(__name__)


# =============================================================================
# Pydantic Models
# =============================================================================


class NoteCreate(BaseModel):
    title: str = "Untitled"
    content: Optional[str] = None
    content_html: Optional[str] = None
    color: Optional[str] = None
    folder_id: Optional[int] = None


class NoteUpdate(BaseModel):
    title: Optional[str] = None
    content: Optional[str] = None
    content_html: Optional[str] = None
    color: Optional[str] = None
    folder_id: Optional[int] = None


class FolderCreate(BaseModel):
    name: str
    parent_id: Optional[int] = None
    icon: Optional[str] = None


class FolderUpdate(BaseModel):
    name: Optional[str] = None
    icon: Optional[str] = None


class NoteMove(BaseModel):
    folder_id: Optional[int] = None


# =============================================================================
# Folder Endpoints
# =============================================================================


@router.get("/folders")
def list_folders(
    user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """List all folders for the current user as a tree structure."""
    repo = AnalystNoteRepository(session)
    folders = repo.list_folders(user.id)

    # Build tree: return root folders with nested children
    folder_map = {f.id: f.to_dict() for f in folders}
    # Add children arrays
    for f in folder_map.values():
        f["children"] = []

    roots = []
    for f in folders:
        d = folder_map[f.id]
        if f.parent_id and f.parent_id in folder_map:
            folder_map[f.parent_id]["children"].append(d)
        else:
            roots.append(d)

    return roots


@router.post("/folders", status_code=201)
def create_folder(
    body: FolderCreate,
    user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Create a new folder."""
    repo = AnalystNoteRepository(session)
    # Validate parent exists and belongs to user
    if body.parent_id is not None:
        parent = repo.get_folder_by_id(body.parent_id, user.id)
        if not parent:
            raise HTTPException(status_code=404, detail="Parent folder not found")
    folder = repo.create_folder(
        user_id=user.id,
        name=body.name,
        parent_id=body.parent_id,
        icon=body.icon,
    )
    session.commit()
    return folder.to_dict()


@router.put("/folders/{folder_id}")
def update_folder(
    folder_id: int,
    body: FolderUpdate,
    user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Rename or update a folder."""
    repo = AnalystNoteRepository(session)
    folder = repo.get_folder_by_id(folder_id, user.id)
    if not folder:
        raise HTTPException(status_code=404, detail="Folder not found")
    repo.update_folder(folder, name=body.name, icon=body.icon)
    session.commit()
    return folder.to_dict()


@router.delete("/folders/{folder_id}", status_code=204)
def delete_folder(
    folder_id: int,
    user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Delete a folder. Notes in it are moved to uncategorized."""
    repo = AnalystNoteRepository(session)
    folder = repo.get_folder_by_id(folder_id, user.id)
    if not folder:
        raise HTTPException(status_code=404, detail="Folder not found")
    repo.delete_folder(folder)
    session.commit()
    return None


# =============================================================================
# Note Endpoints
# =============================================================================


@router.get("")
def list_notes(
    folder_id: Optional[int] = Query(None),
    uncategorized: bool = Query(False),
    user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """List notes for the current user, optionally filtered by folder."""
    repo = AnalystNoteRepository(session)
    if uncategorized:
        notes = repo.list_uncategorized(user.id)
    elif folder_id is not None:
        notes = repo.list_for_user(user.id, folder_id=folder_id)
    else:
        notes = repo.list_for_user(user.id)
    return [n.to_dict() for n in notes]


@router.get("/search")
def search_notes(
    q: str = Query(..., min_length=1),
    folder_id: Optional[int] = Query(None),
    user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Search notes by title or content, optionally within a folder."""
    repo = AnalystNoteRepository(session)
    notes = repo.search(q, user.id, folder_id=folder_id)
    return [n.to_dict() for n in notes]


@router.post("", status_code=201)
def create_note(
    body: NoteCreate,
    user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Create a new note."""
    repo = AnalystNoteRepository(session)
    note = repo.create(
        user_id=user.id,
        title=body.title,
        content=body.content,
        content_html=body.content_html,
        color=body.color,
        folder_id=body.folder_id,
    )
    session.commit()
    return note.to_dict()


@router.get("/{note_id}")
def get_note(
    note_id: int,
    user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Get a single note by ID."""
    repo = AnalystNoteRepository(session)
    note = repo.get_by_id(note_id, user.id)
    if not note:
        raise HTTPException(status_code=404, detail="Note not found")
    return note.to_dict()


@router.put("/{note_id}")
def update_note(
    note_id: int,
    body: NoteUpdate,
    user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Update a note (auto-save target)."""
    repo = AnalystNoteRepository(session)
    note = repo.get_by_id(note_id, user.id)
    if not note:
        raise HTTPException(status_code=404, detail="Note not found")
    # Use sentinel for folder_id so we can distinguish "not provided" from "set to null"
    folder_id = ... if body.folder_id is None and "folder_id" not in body.model_fields_set else body.folder_id
    repo.update(
        note,
        title=body.title,
        content=body.content,
        content_html=body.content_html,
        color=body.color,
        folder_id=folder_id,
    )
    session.commit()
    return note.to_dict()


@router.put("/{note_id}/move")
def move_note(
    note_id: int,
    body: NoteMove,
    user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Move a note to a folder (or uncategorize with folder_id=null)."""
    repo = AnalystNoteRepository(session)
    note = repo.get_by_id(note_id, user.id)
    if not note:
        raise HTTPException(status_code=404, detail="Note not found")
    # Validate folder exists if provided
    if body.folder_id is not None:
        folder = repo.get_folder_by_id(body.folder_id, user.id)
        if not folder:
            raise HTTPException(status_code=404, detail="Folder not found")
    repo.move_note_to_folder(note, body.folder_id)
    session.commit()
    return note.to_dict()


@router.post("/{note_id}/pin")
def toggle_pin(
    note_id: int,
    user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Toggle the pinned status of a note."""
    repo = AnalystNoteRepository(session)
    note = repo.get_by_id(note_id, user.id)
    if not note:
        raise HTTPException(status_code=404, detail="Note not found")
    repo.toggle_pin(note)
    session.commit()
    return note.to_dict()


@router.delete("/{note_id}", status_code=204)
def delete_note(
    note_id: int,
    user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Delete a note."""
    repo = AnalystNoteRepository(session)
    note = repo.get_by_id(note_id, user.id)
    if not note:
        raise HTTPException(status_code=404, detail="Note not found")
    repo.delete(note)
    session.commit()
    return None
