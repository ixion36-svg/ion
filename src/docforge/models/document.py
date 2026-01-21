"""Document model for rendered documents."""

from datetime import datetime
from typing import Optional, List, TYPE_CHECKING
from sqlalchemy import Column, ForeignKey, Integer, String, Text, DateTime, Boolean, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from docforge.models.base import Base

if TYPE_CHECKING:
    from docforge.models.template import Template


class Document(Base):
    """Document model for storing rendered documents."""

    __tablename__ = "documents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    source_template_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("templates.id"), nullable=True
    )
    source_template_version: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    rendered_content: Mapped[str] = mapped_column(Text, nullable=False)
    input_data: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON string
    output_format: Mapped[str] = mapped_column(String(50), nullable=False, default="markdown")
    output_path: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    current_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="active")  # active, archived
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), onupdate=func.now(), nullable=False
    )

    # Relationships
    source_template: Mapped[Optional["Template"]] = relationship(
        "Template", back_populates="documents"
    )
    versions: Mapped[List["DocumentVersion"]] = relationship(
        "DocumentVersion", back_populates="document", cascade="all, delete-orphan",
        order_by="desc(DocumentVersion.version_number)"
    )

    def __repr__(self) -> str:
        return f"<Document(id={self.id}, name='{self.name}', v{self.current_version})>"


class DocumentVersion(Base):
    """Version history for documents."""

    __tablename__ = "document_versions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    document_id: Mapped[int] = mapped_column(Integer, ForeignKey("documents.id"), nullable=False)
    version_number: Mapped[int] = mapped_column(Integer, nullable=False)
    rendered_content: Mapped[str] = mapped_column(Text, nullable=False)
    input_data: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    amendment_reason: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    amended_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), nullable=False
    )

    # Relationships
    document: Mapped["Document"] = relationship("Document", back_populates="versions")

    def __repr__(self) -> str:
        return f"<DocumentVersion(document_id={self.document_id}, v{self.version_number})>"
