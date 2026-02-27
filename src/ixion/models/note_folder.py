"""NoteFolder model for organizing analyst notes into folders."""

from typing import Optional, List, TYPE_CHECKING
from sqlalchemy import (
    ForeignKey,
    Integer,
    String,
    Index,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ixion.models.base import Base, TimestampMixin

if TYPE_CHECKING:
    from ixion.models.user import User
    from ixion.models.analyst_note import AnalystNote


class NoteFolder(Base, TimestampMixin):
    """Folder for organizing analyst notes. User-scoped with self-referential hierarchy."""

    __tablename__ = "note_folders"
    __table_args__ = (
        Index("ix_note_folders_user_id", "user_id"),
        Index("ix_note_folders_parent_id", "user_id", "parent_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    icon: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    parent_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("note_folders.id"), nullable=True
    )

    # Self-referential relationships for folder hierarchy
    parent: Mapped[Optional["NoteFolder"]] = relationship(
        "NoteFolder", remote_side=[id], back_populates="children"
    )
    children: Mapped[List["NoteFolder"]] = relationship(
        "NoteFolder", back_populates="parent", cascade="all, delete-orphan"
    )

    # Relationships
    user: Mapped["User"] = relationship("User", foreign_keys=[user_id])
    notes: Mapped[List["AnalystNote"]] = relationship(
        "AnalystNote", back_populates="folder"
    )

    def __repr__(self) -> str:
        return f"<NoteFolder(id={self.id}, name='{self.name}', user_id={self.user_id})>"

    def to_dict(self) -> dict:
        """Convert to dictionary for API responses."""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "name": self.name,
            "icon": self.icon,
            "parent_id": self.parent_id,
            "children_count": len(self.children) if self.children else 0,
            "notes_count": len(self.notes) if self.notes else 0,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
