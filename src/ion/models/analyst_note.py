"""AnalystNote model for personal note-taking."""

from datetime import datetime
from typing import Optional, TYPE_CHECKING
from sqlalchemy import (
    ForeignKey,
    Integer,
    String,
    Text,
    Boolean,
    DateTime,
    Index,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ion.models.base import Base, TimestampMixin

if TYPE_CHECKING:
    from ion.models.user import User
    from ion.models.note_folder import NoteFolder


class AnalystNote(Base, TimestampMixin):
    """Personal analyst note with rich-text content."""

    __tablename__ = "analyst_notes"
    __table_args__ = (
        Index("ix_analyst_notes_user_id", "user_id"),
        Index("ix_analyst_notes_pinned", "user_id", "is_pinned"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=False
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False, default="Untitled")
    content: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    content_html: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_pinned: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    color: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    folder_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("note_folders.id"), nullable=True
    )

    # Relationships
    user: Mapped["User"] = relationship("User", foreign_keys=[user_id])
    folder: Mapped[Optional["NoteFolder"]] = relationship(
        "NoteFolder", back_populates="notes"
    )

    def __repr__(self) -> str:
        return f"<AnalystNote(id={self.id}, title='{self.title}', user_id={self.user_id})>"

    def to_dict(self) -> dict:
        """Convert to dictionary for API responses."""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "title": self.title,
            "content": self.content,
            "content_html": self.content_html,
            "is_pinned": self.is_pinned,
            "color": self.color,
            "folder_id": self.folder_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
