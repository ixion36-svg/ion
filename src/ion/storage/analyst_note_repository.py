"""Repository for AnalystNote and NoteFolder operations."""

from typing import Optional, List
from sqlalchemy import select, or_
from sqlalchemy.orm import Session, joinedload

from ion.models.analyst_note import AnalystNote
from ion.models.note_folder import NoteFolder


class AnalystNoteRepository:
    """Repository for AnalystNote CRUD operations."""

    def __init__(self, session: Session):
        self.session = session

    # ── Note CRUD ──────────────────────────────────────────────────────

    def create(
        self,
        user_id: int,
        title: str = "Untitled",
        content: str | None = None,
        content_html: str | None = None,
        color: str | None = None,
        folder_id: int | None = None,
    ) -> AnalystNote:
        """Create a new analyst note."""
        note = AnalystNote(
            user_id=user_id,
            title=title,
            content=content,
            content_html=content_html,
            color=color,
            folder_id=folder_id,
        )
        self.session.add(note)
        self.session.flush()
        return note

    def get_by_id(self, note_id: int, user_id: int) -> Optional[AnalystNote]:
        """Get a note by ID, scoped to user."""
        stmt = select(AnalystNote).where(
            AnalystNote.id == note_id,
            AnalystNote.user_id == user_id,
        )
        return self.session.execute(stmt).scalar_one_or_none()

    def list_for_user(
        self, user_id: int, folder_id: int | None = None
    ) -> List[AnalystNote]:
        """List notes for a user, optionally filtered by folder.

        If folder_id is provided, returns notes in that folder.
        If folder_id is not provided, returns all notes.
        """
        stmt = (
            select(AnalystNote)
            .where(AnalystNote.user_id == user_id)
        )
        if folder_id is not None:
            stmt = stmt.where(AnalystNote.folder_id == folder_id)
        stmt = stmt.order_by(
            AnalystNote.is_pinned.desc(), AnalystNote.updated_at.desc()
        )
        return list(self.session.execute(stmt).scalars().all())

    def list_uncategorized(self, user_id: int) -> List[AnalystNote]:
        """List notes with no folder assigned."""
        stmt = (
            select(AnalystNote)
            .where(AnalystNote.user_id == user_id)
            .where(AnalystNote.folder_id.is_(None))
            .order_by(AnalystNote.is_pinned.desc(), AnalystNote.updated_at.desc())
        )
        return list(self.session.execute(stmt).scalars().all())

    def update(
        self,
        note: AnalystNote,
        title: str | None = None,
        content: str | None = None,
        content_html: str | None = None,
        color: str | None = None,
        folder_id: int | None = ...,
    ) -> AnalystNote:
        """Update a note's fields. Pass folder_id=None to uncategorize."""
        if title is not None:
            note.title = title
        if content is not None:
            note.content = content
        if content_html is not None:
            note.content_html = content_html
        if color is not None:
            note.color = color
        if folder_id is not ...:
            note.folder_id = folder_id
        self.session.flush()
        return note

    def toggle_pin(self, note: AnalystNote) -> AnalystNote:
        """Toggle the pinned status of a note."""
        note.is_pinned = not note.is_pinned
        self.session.flush()
        return note

    def delete(self, note: AnalystNote) -> None:
        """Delete a note."""
        self.session.delete(note)
        self.session.flush()

    def search(
        self, query: str, user_id: int, folder_id: int | None = None
    ) -> List[AnalystNote]:
        """Search notes by title or HTML content, optionally within a folder."""
        pattern = f"%{query}%"
        stmt = (
            select(AnalystNote)
            .where(AnalystNote.user_id == user_id)
            .where(
                or_(
                    AnalystNote.title.ilike(pattern),
                    AnalystNote.content_html.ilike(pattern),
                )
            )
        )
        if folder_id is not None:
            stmt = stmt.where(AnalystNote.folder_id == folder_id)
        stmt = stmt.order_by(
            AnalystNote.is_pinned.desc(), AnalystNote.updated_at.desc()
        )
        return list(self.session.execute(stmt).scalars().all())

    def move_note_to_folder(
        self, note: AnalystNote, folder_id: int | None
    ) -> AnalystNote:
        """Move a note to a folder (or uncategorize with None)."""
        note.folder_id = folder_id
        self.session.flush()
        return note

    # ── Folder CRUD ────────────────────────────────────────────────────

    def create_folder(
        self,
        user_id: int,
        name: str,
        parent_id: int | None = None,
        icon: str | None = None,
    ) -> NoteFolder:
        """Create a new note folder."""
        folder = NoteFolder(
            user_id=user_id,
            name=name,
            parent_id=parent_id,
            icon=icon,
        )
        self.session.add(folder)
        self.session.flush()
        return folder

    def get_folder_by_id(
        self, folder_id: int, user_id: int
    ) -> Optional[NoteFolder]:
        """Get a folder by ID, scoped to user."""
        stmt = (
            select(NoteFolder)
            .options(joinedload(NoteFolder.children), joinedload(NoteFolder.notes))
            .where(NoteFolder.id == folder_id, NoteFolder.user_id == user_id)
        )
        return self.session.execute(stmt).unique().scalar_one_or_none()

    def list_folders(self, user_id: int) -> List[NoteFolder]:
        """List all folders for a user with eager-loaded children and note counts."""
        stmt = (
            select(NoteFolder)
            .options(joinedload(NoteFolder.children), joinedload(NoteFolder.notes))
            .where(NoteFolder.user_id == user_id)
            .order_by(NoteFolder.name)
        )
        return list(self.session.execute(stmt).unique().scalars().all())

    def list_root_folders(self, user_id: int) -> List[NoteFolder]:
        """List root-level folders (no parent) for a user."""
        stmt = (
            select(NoteFolder)
            .options(joinedload(NoteFolder.children), joinedload(NoteFolder.notes))
            .where(NoteFolder.user_id == user_id, NoteFolder.parent_id.is_(None))
            .order_by(NoteFolder.name)
        )
        return list(self.session.execute(stmt).unique().scalars().all())

    def rename_folder(self, folder: NoteFolder, name: str) -> NoteFolder:
        """Rename a folder."""
        folder.name = name
        self.session.flush()
        return folder

    def update_folder(
        self,
        folder: NoteFolder,
        name: str | None = None,
        icon: str | None = None,
        parent_id: int | None = ...,
    ) -> NoteFolder:
        """Update folder fields."""
        if name is not None:
            folder.name = name
        if icon is not None:
            folder.icon = icon
        if parent_id is not ...:
            folder.parent_id = parent_id
        self.session.flush()
        return folder

    def delete_folder(self, folder: NoteFolder) -> None:
        """Delete a folder, moving its notes to uncategorized."""
        # Move all notes in this folder to uncategorized
        for note in folder.notes:
            note.folder_id = None
        # Move child folders to the parent (or root)
        for child in folder.children:
            child.parent_id = folder.parent_id
        self.session.delete(folder)
        self.session.flush()
