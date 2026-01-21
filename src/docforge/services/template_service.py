"""Business logic for template operations."""

from typing import Optional, List
from sqlalchemy.orm import Session

from docforge.models.template import Template, Tag, Variable
from docforge.storage.template_repository import TemplateRepository
from docforge.storage.version_repository import VersionRepository
from docforge.core.exceptions import TemplateNotFoundError, ValidationError


class TemplateService:
    """Service for template business logic."""

    def __init__(self, session: Session):
        self.session = session
        self.template_repo = TemplateRepository(session)
        self.version_repo = VersionRepository(session)

    def create_template(
        self,
        name: str,
        content: str = "",
        format: str = "markdown",
        description: str | None = None,
        folder_path: str | None = None,
        tags: list[str] | None = None,
    ) -> Template:
        """Create a new template with initial version."""
        # Validate name
        if not name or not name.strip():
            raise ValidationError("name", "Template name cannot be empty")

        # Check for duplicate name
        existing = self.template_repo.get_by_name(name)
        if existing:
            raise ValidationError("name", f"Template with name '{name}' already exists")

        # Create template
        template = self.template_repo.create(
            name=name,
            content=content,
            format=format,
            description=description,
            folder_path=folder_path,
        )

        # Add tags
        if tags:
            for tag_name in tags:
                self.template_repo.add_tag(template, tag_name)

        # Create initial version
        self.version_repo.create(
            template_id=template.id,
            version_number=1,
            content=content,
            message="Initial version",
        )

        return template

    def get_template(self, template_id: int) -> Template:
        """Get a template by ID."""
        template = self.template_repo.get_by_id(template_id)
        if not template:
            raise TemplateNotFoundError(template_id)
        return template

    def get_template_by_name(self, name: str) -> Optional[Template]:
        """Get a template by name."""
        return self.template_repo.get_by_name(name)

    def list_templates(
        self,
        format: str | None = None,
        folder_path: str | None = None,
        tags: list[str] | None = None,
    ) -> List[Template]:
        """List all templates with optional filters."""
        return self.template_repo.list_all(
            format=format, folder_path=folder_path, tag_names=tags
        )

    def search_templates(self, query: str) -> List[Template]:
        """Search templates by name, description, or content."""
        return self.template_repo.search(query)

    def update_template(
        self,
        template_id: int,
        name: str | None = None,
        content: str | None = None,
        format: str | None = None,
        description: str | None = None,
        folder_path: str | None = None,
        create_version: bool = True,
        version_message: str | None = None,
    ) -> Template:
        """Update a template, optionally creating a new version."""
        template = self.get_template(template_id)

        # Check name uniqueness if changing
        if name and name != template.name:
            existing = self.template_repo.get_by_name(name)
            if existing:
                raise ValidationError("name", f"Template with name '{name}' already exists")

        # Store old content for diff
        old_content = template.content

        # Update template
        template = self.template_repo.update(
            template,
            name=name,
            content=content,
            format=format,
            description=description,
            folder_path=folder_path,
        )

        # Create version if content changed
        if create_version and content is not None and content != old_content:
            from docforge.diff.differ import VersionDiffer

            differ = VersionDiffer()
            diff = differ.compute_diff(old_content, content)

            template.current_version += 1
            self.version_repo.create(
                template_id=template.id,
                version_number=template.current_version,
                content=content,
                diff=diff,
                message=version_message or "Updated template",
            )

        return template

    def delete_template(self, template_id: int) -> None:
        """Delete a template and all its versions."""
        template = self.get_template(template_id)
        self.template_repo.delete(template)

    def add_tag(self, template_id: int, tag_name: str) -> Tag:
        """Add a tag to a template."""
        template = self.get_template(template_id)
        return self.template_repo.add_tag(template, tag_name)

    def remove_tag(self, template_id: int, tag_name: str) -> None:
        """Remove a tag from a template."""
        template = self.get_template(template_id)
        self.template_repo.remove_tag(template, tag_name)

    def list_tags(self) -> List[Tag]:
        """List all tags."""
        return self.template_repo.list_tags()

    def set_variables(
        self, template_id: int, variables: list[dict]
    ) -> List[Variable]:
        """Set variables for a template (replaces existing)."""
        template = self.get_template(template_id)
        self.template_repo.clear_variables(template)

        result = []
        for var_data in variables:
            variable = self.template_repo.add_variable(
                template=template,
                name=var_data["name"],
                var_type=var_data.get("var_type", "string"),
                required=var_data.get("required", True),
                default_value=var_data.get("default_value"),
                description=var_data.get("description"),
            )
            result.append(variable)

        return result
