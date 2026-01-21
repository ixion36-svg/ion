"""Business logic for rendering operations."""

import json
from typing import Optional, Any
from pathlib import Path
from sqlalchemy.orm import Session

from docforge.models.template import Template
from docforge.models.document import Document
from docforge.storage.template_repository import TemplateRepository
from docforge.storage.document_repository import DocumentRepository
from docforge.engine.renderer import TemplateRenderer
from docforge.engine.data_loader import DataLoader
from docforge.plugins import PluginRegistry
from docforge.core.exceptions import TemplateNotFoundError, RenderError


class RenderService:
    """Service for template rendering business logic."""

    def __init__(self, session: Session):
        self.session = session
        self.template_repo = TemplateRepository(session)
        self.document_repo = DocumentRepository(session)
        self.renderer = TemplateRenderer()
        self.data_loader = DataLoader()
        self.plugin_registry = PluginRegistry()

    def preview(
        self,
        template_id: int,
        data: dict[str, Any] | None = None,
        data_file: Path | None = None,
    ) -> str:
        """Preview rendered template without saving."""
        template = self.template_repo.get_by_id(template_id)
        if not template:
            raise TemplateNotFoundError(template_id)

        # Load data
        if data_file:
            data = self.data_loader.load(data_file)
        elif data is None:
            data = {}

        # Render
        return self.renderer.render(template.content, data)

    def render(
        self,
        template_id: int,
        data: dict[str, Any] | None = None,
        data_file: Path | None = None,
        output_format: str | None = None,
        output_path: Path | None = None,
        document_name: str | None = None,
        save_document: bool = True,
    ) -> tuple[str, Optional[Document]]:
        """Render a template and optionally save as a document."""
        template = self.template_repo.get_by_id(template_id)
        if not template:
            raise TemplateNotFoundError(template_id)

        # Load data
        if data_file:
            data = self.data_loader.load(data_file)
        elif data is None:
            data = {}

        # Determine output format
        if output_format is None:
            output_format = template.format

        # Render with Jinja2
        rendered_content = self.renderer.render(template.content, data)

        # Apply format plugin if converting
        if output_format != template.format:
            plugin = self.plugin_registry.get_plugin(output_format)
            if plugin:
                rendered_content = plugin.convert(rendered_content, template.format)

        # Write to file if output path specified
        if output_path:
            plugin = self.plugin_registry.get_plugin(output_format)
            if plugin:
                plugin.write(rendered_content, output_path)
            else:
                output_path.write_text(rendered_content, encoding="utf-8")

        # Save document record
        document = None
        if save_document:
            doc_name = document_name or f"{template.name}_rendered"
            document = self.document_repo.create(
                name=doc_name,
                rendered_content=rendered_content,
                output_format=output_format,
                source_template_id=template.id,
                source_template_version=template.current_version,
                input_data=json.dumps(data) if data else None,
                output_path=str(output_path) if output_path else None,
            )

        return rendered_content, document

    def render_string(
        self,
        template_content: str,
        data: dict[str, Any] | None = None,
    ) -> str:
        """Render a template string without database operations."""
        if data is None:
            data = {}
        return self.renderer.render(template_content, data)

    def get_document(self, document_id: int) -> Optional[Document]:
        """Get a document by ID."""
        return self.document_repo.get_by_id(document_id)

    def list_documents(
        self,
        template_id: int | None = None,
        output_format: str | None = None,
    ) -> list[Document]:
        """List documents with optional filters."""
        return self.document_repo.list_all(
            source_template_id=template_id, output_format=output_format
        )

    def regenerate_document(
        self,
        document_id: int,
        data: dict[str, Any] | None = None,
        output_path: Path | None = None,
    ) -> Document:
        """Regenerate a document using stored input data or new data."""
        document = self.document_repo.get_by_id(document_id)
        if not document:
            raise RenderError(f"Document with ID {document_id} not found")

        if not document.source_template_id:
            raise RenderError("Document has no source template", document_id)

        template = self.template_repo.get_by_id(document.source_template_id)
        if not template:
            raise RenderError(
                f"Source template {document.source_template_id} not found",
                document.source_template_id,
            )

        # Use provided data or load from document
        if data is None and document.input_data:
            data = json.loads(document.input_data)
        elif data is None:
            data = {}

        # Render
        rendered_content = self.renderer.render(template.content, data)

        # Apply format plugin if needed
        if document.output_format != template.format:
            plugin = self.plugin_registry.get_plugin(document.output_format)
            if plugin:
                rendered_content = plugin.convert(rendered_content, template.format)

        # Update output path
        final_output_path = output_path or (
            Path(document.output_path) if document.output_path else None
        )

        # Write to file
        if final_output_path:
            plugin = self.plugin_registry.get_plugin(document.output_format)
            if plugin:
                plugin.write(rendered_content, final_output_path)
            else:
                final_output_path.write_text(rendered_content, encoding="utf-8")

        # Update document
        return self.document_repo.update(
            document,
            rendered_content=rendered_content,
            input_data=json.dumps(data) if data else None,
            output_path=str(final_output_path) if final_output_path else None,
        )

    def delete_document(self, document_id: int) -> None:
        """Delete a document."""
        document = self.document_repo.get_by_id(document_id)
        if document:
            self.document_repo.delete(document)
