"""Template, Tag, Variable, and Collection models."""

from datetime import datetime
from typing import Optional, List
from sqlalchemy import (
    Column,
    ForeignKey,
    Integer,
    String,
    Text,
    Boolean,
    Table,
    DateTime,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from docforge.models.base import Base, TimestampMixin


# Many-to-many association table for Template <-> Tag
template_tags = Table(
    "template_tags",
    Base.metadata,
    Column("template_id", Integer, ForeignKey("templates.id"), primary_key=True),
    Column("tag_id", Integer, ForeignKey("tags.id"), primary_key=True),
)


class Collection(Base, TimestampMixin):
    """Collection/Folder model for grouping templates and documents.

    Supports hierarchical folder structure with parent/child relationships.
    """

    __tablename__ = "collections"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    icon: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)  # emoji or icon name
    parent_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("collections.id"), nullable=True
    )

    # Self-referential relationships for folder hierarchy
    parent: Mapped[Optional["Collection"]] = relationship(
        "Collection", remote_side=[id], back_populates="children"
    )
    children: Mapped[List["Collection"]] = relationship(
        "Collection", back_populates="parent", cascade="all, delete-orphan"
    )

    # Relationships to templates and documents
    templates: Mapped[List["Template"]] = relationship(
        "Template", back_populates="collection"
    )
    documents: Mapped[List["Document"]] = relationship(
        "Document", back_populates="collection"
    )

    @property
    def full_path(self) -> str:
        """Get the full path including parent folders."""
        if self.parent:
            return f"{self.parent.full_path}/{self.name}"
        return self.name

    def __repr__(self) -> str:
        return f"<Collection(id={self.id}, name='{self.name}', parent_id={self.parent_id})>"


class Template(Base, TimestampMixin):
    """Template model for storing document templates."""

    __tablename__ = "templates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    content: Mapped[str] = mapped_column(Text, nullable=False, default="")
    format: Mapped[str] = mapped_column(String(50), nullable=False, default="markdown")
    variables_schema: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    folder_path: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    current_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    collection_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("collections.id"), nullable=True
    )

    # Relationships
    collection: Mapped[Optional["Collection"]] = relationship(
        "Collection", back_populates="templates"
    )
    tags: Mapped[List["Tag"]] = relationship(
        "Tag", secondary=template_tags, back_populates="templates"
    )
    variables: Mapped[List["Variable"]] = relationship(
        "Variable", back_populates="template", cascade="all, delete-orphan"
    )
    versions: Mapped[List["TemplateVersion"]] = relationship(
        "TemplateVersion", back_populates="template", cascade="all, delete-orphan"
    )
    documents: Mapped[List["Document"]] = relationship(
        "Document", back_populates="source_template"
    )

    def __repr__(self) -> str:
        return f"<Template(id={self.id}, name='{self.name}', format='{self.format}')>"


class Tag(Base):
    """Tag model for categorizing templates."""

    __tablename__ = "tags"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)

    # Relationships
    templates: Mapped[List["Template"]] = relationship(
        "Template", secondary=template_tags, back_populates="tags"
    )

    def __repr__(self) -> str:
        return f"<Tag(id={self.id}, name='{self.name}')>"


class Variable(Base):
    """Variable model for template variables."""

    __tablename__ = "variables"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    template_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("templates.id"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    var_type: Mapped[str] = mapped_column(String(50), nullable=False, default="string")
    required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    default_value: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    template: Mapped["Template"] = relationship("Template", back_populates="variables")

    def __repr__(self) -> str:
        return f"<Variable(id={self.id}, name='{self.name}', type='{self.var_type}')>"


# Forward reference imports for type hints
from docforge.models.version import TemplateVersion
from docforge.models.document import Document
