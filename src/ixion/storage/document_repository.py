"""Repository for Document operations."""

from typing import Optional, List
from sqlalchemy import select
from sqlalchemy.orm import Session

from ixion.models.document import Document, DocumentVersion


class DocumentRepository:
    """Repository for Document CRUD operations."""

    def __init__(self, session: Session):
        self.session = session

    def create(
        self,
        name: str,
        rendered_content: str,
        output_format: str = "markdown",
        source_template_id: int | None = None,
        source_template_version: int | None = None,
        input_data: str | None = None,
        output_path: str | None = None,
    ) -> Document:
        """Create a new document with initial version."""
        document = Document(
            name=name,
            rendered_content=rendered_content,
            output_format=output_format,
            source_template_id=source_template_id,
            source_template_version=source_template_version,
            input_data=input_data,
            output_path=output_path,
            current_version=1,
            status="active",
        )
        self.session.add(document)
        self.session.flush()

        # Create initial version record
        version = DocumentVersion(
            document_id=document.id,
            version_number=1,
            rendered_content=rendered_content,
            input_data=input_data,
            amendment_reason="Initial version",
            amended_by=None,
        )
        self.session.add(version)
        self.session.flush()

        return document

    def get_by_id(self, document_id: int) -> Optional[Document]:
        """Get a document by ID."""
        stmt = select(Document).where(Document.id == document_id)
        return self.session.execute(stmt).scalar_one_or_none()

    def get_by_name(self, name: str) -> Optional[Document]:
        """Get a document by name."""
        stmt = select(Document).where(Document.name == name)
        return self.session.execute(stmt).scalar_one_or_none()

    def list_all(
        self,
        source_template_id: int | None = None,
        output_format: str | None = None,
        include_archived: bool = False,
    ) -> List[Document]:
        """List all documents with optional filters."""
        stmt = select(Document)

        if not include_archived:
            stmt = stmt.where(Document.status == "active")
        if source_template_id:
            stmt = stmt.where(Document.source_template_id == source_template_id)
        if output_format:
            stmt = stmt.where(Document.output_format == output_format)

        stmt = stmt.order_by(Document.updated_at.desc())
        return list(self.session.execute(stmt).scalars().all())

    def update(
        self,
        document: Document,
        name: str | None = None,
        rendered_content: str | None = None,
        output_format: str | None = None,
        input_data: str | None = None,
        output_path: str | None = None,
    ) -> Document:
        """Update a document (without versioning - use amend for versioned updates)."""
        if name is not None:
            document.name = name
        if rendered_content is not None:
            document.rendered_content = rendered_content
        if output_format is not None:
            document.output_format = output_format
        if input_data is not None:
            document.input_data = input_data
        if output_path is not None:
            document.output_path = output_path
        self.session.flush()
        return document

    def amend(
        self,
        document: Document,
        rendered_content: str,
        input_data: str | None = None,
        amendment_reason: str | None = None,
        amended_by: str | None = None,
    ) -> Document:
        """Create an amendment (new version) of a document."""
        # Increment version
        new_version = document.current_version + 1

        # Create version record for the amendment
        version = DocumentVersion(
            document_id=document.id,
            version_number=new_version,
            rendered_content=rendered_content,
            input_data=input_data,
            amendment_reason=amendment_reason,
            amended_by=amended_by,
        )
        self.session.add(version)

        # Update document with new content
        document.rendered_content = rendered_content
        document.input_data = input_data
        document.current_version = new_version

        self.session.flush()
        return document

    def get_version(self, document_id: int, version_number: int) -> Optional[DocumentVersion]:
        """Get a specific version of a document."""
        stmt = select(DocumentVersion).where(
            DocumentVersion.document_id == document_id,
            DocumentVersion.version_number == version_number
        )
        return self.session.execute(stmt).scalar_one_or_none()

    def list_versions(self, document_id: int) -> List[DocumentVersion]:
        """List all versions of a document."""
        stmt = (
            select(DocumentVersion)
            .where(DocumentVersion.document_id == document_id)
            .order_by(DocumentVersion.version_number.desc())
        )
        return list(self.session.execute(stmt).scalars().all())

    def archive(self, document: Document) -> Document:
        """Archive a document."""
        document.status = "archived"
        self.session.flush()
        return document

    def restore(self, document: Document) -> Document:
        """Restore an archived document."""
        document.status = "active"
        self.session.flush()
        return document

    def revert_to_version(
        self,
        document: Document,
        version_number: int,
        amended_by: str | None = None,
    ) -> Document:
        """Revert document to a previous version (creates new version with old content)."""
        version = self.get_version(document.id, version_number)
        if not version:
            raise ValueError(f"Version {version_number} not found")

        return self.amend(
            document=document,
            rendered_content=version.rendered_content,
            input_data=version.input_data,
            amendment_reason=f"Reverted to version {version_number}",
            amended_by=amended_by,
        )

    def delete(self, document: Document) -> None:
        """Delete a document and all its versions."""
        self.session.delete(document)
        self.session.flush()

    def list_by_template(self, template_id: int) -> List[Document]:
        """List all documents generated from a specific template."""
        stmt = (
            select(Document)
            .where(Document.source_template_id == template_id)
            .where(Document.status == "active")
            .order_by(Document.created_at.desc())
        )
        return list(self.session.execute(stmt).scalars().all())
