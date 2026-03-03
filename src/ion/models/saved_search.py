"""SavedSearch model for saving and sharing Elasticsearch queries."""

from datetime import datetime
from enum import Enum
from typing import Optional, TYPE_CHECKING
from sqlalchemy import (
    Column,
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
from sqlalchemy.types import JSON

from ion.models.base import Base, TimestampMixin

if TYPE_CHECKING:
    from ion.models.user import User


class SearchType(str, Enum):
    """Types of saved searches."""

    DISCOVER = "discover"
    IOC_HUNT = "ioc_hunt"


class SavedSearch(Base, TimestampMixin):
    """SavedSearch model for persisting Elasticsearch queries."""

    __tablename__ = "saved_searches"
    __table_args__ = (
        Index("ix_saved_searches_created_by", "created_by_id"),
        Index("ix_saved_searches_shared", "is_shared"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    search_type: Mapped[str] = mapped_column(
        String(50), nullable=False, default=SearchType.DISCOVER.value
    )
    search_params: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_by_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=False
    )
    is_shared: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_favorite: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    execution_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_executed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime, nullable=True
    )

    # Relationships
    created_by: Mapped["User"] = relationship("User", foreign_keys=[created_by_id])

    def __repr__(self) -> str:
        return f"<SavedSearch(id={self.id}, name='{self.name}', type='{self.search_type}')>"

    def to_dict(self) -> dict:
        """Convert to dictionary for API responses."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "search_type": self.search_type,
            "search_params": self.search_params,
            "created_by_id": self.created_by_id,
            "created_by_username": self.created_by.username if self.created_by else None,
            "is_shared": self.is_shared,
            "is_favorite": self.is_favorite,
            "execution_count": self.execution_count,
            "last_executed_at": (
                self.last_executed_at.isoformat() if self.last_executed_at else None
            ),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
