"""TemplateVersion model for version control."""

from datetime import datetime
from typing import Optional, TYPE_CHECKING
from sqlalchemy import Column, ForeignKey, Integer, String, Text, Boolean, DateTime, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ion.models.base import Base

if TYPE_CHECKING:
    from ion.models.template import Template


class TemplateVersion(Base):
    """Version model for tracking template changes."""

    __tablename__ = "template_versions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    template_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("templates.id"), nullable=False
    )
    version_number: Mapped[int] = mapped_column(Integer, nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    diff: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_checkpoint: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    checkpoint_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    author: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), nullable=False
    )

    # Relationships
    template: Mapped["Template"] = relationship("Template", back_populates="versions")

    def __repr__(self) -> str:
        checkpoint_str = f", checkpoint='{self.checkpoint_name}'" if self.is_checkpoint else ""
        return f"<TemplateVersion(id={self.id}, template_id={self.template_id}, v{self.version_number}{checkpoint_str})>"
