"""Business logic for rendering operations."""

import csv
import json
from dataclasses import dataclass, field
from io import StringIO
from typing import Optional, Any, List
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


@dataclass
class ValidationError:
    """Represents a single validation error."""
    field: str
    message: str
    error_type: str  # "missing", "type_mismatch", "invalid_value"


@dataclass
class ValidationResult:
    """Result of validating data against a template."""
    is_valid: bool
    errors: List[ValidationError] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def add_error(self, field: str, message: str, error_type: str) -> None:
        self.errors.append(ValidationError(field, message, error_type))
        self.is_valid = False

    def add_warning(self, message: str) -> None:
        self.warnings.append(message)


@dataclass
class BatchRenderResult:
    """Result of a single item in batch rendering."""
    index: int
    success: bool
    content: Optional[str] = None
    document_id: Optional[int] = None
    document_name: Optional[str] = None
    error: Optional[str] = None
    validation_errors: List[ValidationError] = field(default_factory=list)


@dataclass
class BatchRenderSummary:
    """Summary of batch rendering operation."""
    total: int
    successful: int
    failed: int
    results: List[BatchRenderResult] = field(default_factory=list)


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

            # Auto-assign to same collection as template if template has one
            if template.collection_id:
                document.collection_id = template.collection_id
            else:
                # Try to find a matching collection from template tags
                from docforge.storage.collection_repository import CollectionRepository
                collection_repo = CollectionRepository(self.document_repo.session)
                for tag in template.tags:
                    matching_collection = collection_repo.get_by_name(tag.name)
                    if matching_collection:
                        document.collection_id = matching_collection.id
                        break

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

    # =========================================================================
    # Data Validation
    # =========================================================================

    def validate_data(
        self,
        template_id: int,
        data: dict[str, Any],
    ) -> ValidationResult:
        """Validate input data against a template's variable schema.

        Checks:
        - Required variables are present
        - Variable types match expected types
        - No unknown variables (warning only)

        Args:
            template_id: Template to validate against
            data: Input data dictionary

        Returns:
            ValidationResult with is_valid flag and any errors/warnings
        """
        template = self.template_repo.get_by_id(template_id)
        if not template:
            raise TemplateNotFoundError(template_id)

        result = ValidationResult(is_valid=True)

        # Get defined variables from template
        defined_vars = {v.name: v for v in template.variables}

        # Also extract variables from template content
        extracted_vars = self.renderer.extract_variables(template.content)

        # Check for required variables
        for var_name, var in defined_vars.items():
            if var.required and var_name not in data:
                # Check if there's a default value
                if var.default_value is None:
                    result.add_error(
                        var_name,
                        f"Required variable '{var_name}' is missing",
                        "missing"
                    )

        # Check for variables in template content that aren't provided
        for var_name in extracted_vars:
            if var_name not in data and var_name not in defined_vars:
                # Variable used in template but not defined and not in data
                result.add_warning(
                    f"Variable '{var_name}' used in template but not provided"
                )

        # Type validation for provided data
        for var_name, value in data.items():
            if var_name in defined_vars:
                var = defined_vars[var_name]
                type_error = self._validate_type(var_name, value, var.var_type)
                if type_error:
                    result.add_error(var_name, type_error, "type_mismatch")
            elif var_name not in extracted_vars:
                # Data provided for variable not in template
                result.add_warning(
                    f"Variable '{var_name}' provided but not used in template"
                )

        return result

    def _validate_type(
        self, var_name: str, value: Any, expected_type: str
    ) -> Optional[str]:
        """Validate a value against an expected type.

        Returns error message if invalid, None if valid.
        """
        if value is None:
            return None  # None is allowed for optional fields

        type_checks = {
            "string": lambda v: isinstance(v, str),
            "text": lambda v: isinstance(v, str),
            "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
            "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
            "float": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
            "boolean": lambda v: isinstance(v, bool),
            "bool": lambda v: isinstance(v, bool),
            "list": lambda v: isinstance(v, list),
            "array": lambda v: isinstance(v, list),
            "dict": lambda v: isinstance(v, dict),
            "object": lambda v: isinstance(v, dict),
            "date": lambda v: isinstance(v, str),  # Dates typically come as strings
            "datetime": lambda v: isinstance(v, str),
        }

        check_fn = type_checks.get(expected_type.lower())
        if check_fn and not check_fn(value):
            actual_type = type(value).__name__
            return f"Expected {expected_type}, got {actual_type}"

        return None

    def render_with_validation(
        self,
        template_id: int,
        data: dict[str, Any] | None = None,
        data_file: Path | None = None,
        output_format: str | None = None,
        output_path: Path | None = None,
        document_name: str | None = None,
        save_document: bool = True,
        strict: bool = False,
    ) -> tuple[str, Optional[Document], ValidationResult]:
        """Render a template with data validation.

        Args:
            template_id: Template to render
            data: Input data
            data_file: File to load data from
            output_format: Output format
            output_path: File to write output to
            document_name: Name for saved document
            save_document: Whether to save as document
            strict: If True, refuse to render if validation fails

        Returns:
            Tuple of (rendered_content, document, validation_result)
        """
        # Load data
        if data_file:
            data = self.data_loader.load(data_file)
        elif data is None:
            data = {}

        # Validate
        validation = self.validate_data(template_id, data)

        if strict and not validation.is_valid:
            raise RenderError(
                f"Validation failed: {', '.join(e.message for e in validation.errors)}"
            )

        # Render
        content, document = self.render(
            template_id=template_id,
            data=data,
            output_format=output_format,
            output_path=output_path,
            document_name=document_name,
            save_document=save_document,
        )

        return content, document, validation

    # =========================================================================
    # Batch Rendering
    # =========================================================================

    def batch_render(
        self,
        template_id: int,
        data_list: List[dict[str, Any]],
        output_format: str | None = None,
        document_name_field: str | None = None,
        document_name_prefix: str | None = None,
        save_documents: bool = True,
        validate: bool = True,
        stop_on_error: bool = False,
    ) -> BatchRenderSummary:
        """Render multiple documents from a list of data dictionaries.

        Args:
            template_id: Template to render
            data_list: List of data dictionaries, one per document
            output_format: Output format for all documents
            document_name_field: Field in data to use as document name
            document_name_prefix: Prefix for auto-generated document names
            save_documents: Whether to save documents to database
            validate: Whether to validate data before rendering
            stop_on_error: Whether to stop on first error

        Returns:
            BatchRenderSummary with results for each item
        """
        template = self.template_repo.get_by_id(template_id)
        if not template:
            raise TemplateNotFoundError(template_id)

        summary = BatchRenderSummary(
            total=len(data_list),
            successful=0,
            failed=0,
        )

        prefix = document_name_prefix or f"{template.name}_batch"

        for i, data in enumerate(data_list):
            result = BatchRenderResult(index=i, success=False)

            try:
                # Validate if requested
                if validate:
                    validation = self.validate_data(template_id, data)
                    if not validation.is_valid:
                        result.validation_errors = validation.errors
                        result.error = "; ".join(e.message for e in validation.errors)
                        summary.failed += 1
                        summary.results.append(result)
                        if stop_on_error:
                            break
                        continue

                # Determine document name
                if document_name_field and document_name_field in data:
                    doc_name = str(data[document_name_field])
                else:
                    doc_name = f"{prefix}_{i + 1}"

                # Render
                content, document = self.render(
                    template_id=template_id,
                    data=data,
                    output_format=output_format,
                    document_name=doc_name,
                    save_document=save_documents,
                )

                result.success = True
                result.content = content
                result.document_name = doc_name
                if document:
                    result.document_id = document.id
                summary.successful += 1

            except Exception as e:
                result.error = str(e)
                summary.failed += 1
                if stop_on_error:
                    summary.results.append(result)
                    break

            summary.results.append(result)

        return summary

    def batch_render_from_file(
        self,
        template_id: int,
        data_file: Path,
        output_format: str | None = None,
        document_name_field: str | None = None,
        document_name_prefix: str | None = None,
        save_documents: bool = True,
        validate: bool = True,
        stop_on_error: bool = False,
    ) -> BatchRenderSummary:
        """Render multiple documents from a CSV or JSON file.

        For CSV: Each row becomes a document, headers become variable names.
        For JSON: Expects an array of objects, each object becomes a document.

        Args:
            template_id: Template to render
            data_file: Path to CSV or JSON file
            output_format: Output format for all documents
            document_name_field: Field in data to use as document name
            document_name_prefix: Prefix for auto-generated document names
            save_documents: Whether to save documents to database
            validate: Whether to validate data before rendering
            stop_on_error: Whether to stop on first error

        Returns:
            BatchRenderSummary with results for each item
        """
        # Load data from file
        data_list = self._load_batch_data(data_file)

        return self.batch_render(
            template_id=template_id,
            data_list=data_list,
            output_format=output_format,
            document_name_field=document_name_field,
            document_name_prefix=document_name_prefix,
            save_documents=save_documents,
            validate=validate,
            stop_on_error=stop_on_error,
        )

    def _load_batch_data(self, data_file: Path) -> List[dict[str, Any]]:
        """Load batch data from a CSV or JSON file.

        Args:
            data_file: Path to data file

        Returns:
            List of data dictionaries
        """
        suffix = data_file.suffix.lower()

        if suffix == ".json":
            with open(data_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    return data
                elif isinstance(data, dict) and "data" in data:
                    # Support {"data": [...]} format
                    return data["data"]
                else:
                    raise RenderError(
                        "JSON file must contain an array or {\"data\": [...]}"
                    )

        elif suffix == ".csv":
            with open(data_file, "r", encoding="utf-8", newline="") as f:
                reader = csv.DictReader(f)
                return list(reader)

        else:
            raise RenderError(f"Unsupported batch file format: {suffix}")
