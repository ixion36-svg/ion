"""Business logic for template operations."""

from typing import Optional, List
from sqlalchemy.orm import Session

from ixion.models.template import Template, Tag, Variable, Collection
from ixion.storage.template_repository import TemplateRepository
from ixion.storage.version_repository import VersionRepository
from ixion.storage.collection_repository import CollectionRepository
from ixion.core.exceptions import TemplateNotFoundError, ValidationError


class CollectionNotFoundError(Exception):
    """Raised when a collection is not found."""

    def __init__(self, collection_id: int):
        self.collection_id = collection_id
        super().__init__(f"Collection with ID {collection_id} not found")


class TemplateService:
    """Service for template business logic."""

    def __init__(self, session: Session):
        self.session = session
        self.template_repo = TemplateRepository(session)
        self.version_repo = VersionRepository(session)
        self.collection_repo = CollectionRepository(session)

    def create_template(
        self,
        name: str,
        content: str = "",
        format: str = "markdown",
        description: str | None = None,
        folder_path: str | None = None,
        tags: list[str] | None = None,
        collection_id: int | None = None,
        document_type: str | None = None,
    ) -> Template:
        """Create a new template with initial version."""
        # Validate name
        if not name or not name.strip():
            raise ValidationError("name", "Template name cannot be empty")

        # Check for duplicate name
        existing = self.template_repo.get_by_name(name)
        if existing:
            raise ValidationError("name", f"Template with name '{name}' already exists")

        # Validate collection exists if specified
        if collection_id is not None:
            collection = self.collection_repo.get_by_id(collection_id)
            if not collection:
                raise CollectionNotFoundError(collection_id)

        # Create template
        template = self.template_repo.create(
            name=name,
            content=content,
            format=format,
            description=description,
            folder_path=folder_path,
        )

        # Set document type if specified
        if document_type is not None:
            template.document_type = document_type

        # Set collection if specified
        if collection_id is not None:
            template.collection_id = collection_id

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
        collection_id: int | None = None,
        document_type: str | None = None,
    ) -> List[Template]:
        """List all templates with optional filters."""
        return self.template_repo.list_all(
            format=format, folder_path=folder_path, tag_names=tags,
            collection_id=collection_id, document_type=document_type,
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
        version_author: str | None = None,
        document_type: str | None = None,
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

        # Update document type if provided
        if document_type is not None:
            template.document_type = document_type

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
            from ixion.diff.differ import VersionDiffer

            differ = VersionDiffer()
            diff = differ.compute_diff(old_content, content)

            template.current_version += 1
            self.version_repo.create(
                template_id=template.id,
                version_number=template.current_version,
                content=content,
                diff=diff,
                message=version_message or "Updated template",
                author=version_author,
            )

        return template

    def delete_template(self, template_id: int) -> None:
        """Delete a template and all its versions."""
        template = self.get_template(template_id)
        self.template_repo.delete(template)

    def add_tag(self, template_id: int, tag_name: str, auto_assign_folder: bool = True) -> Tag:
        """Add a tag to a template.

        If auto_assign_folder is True and the tag name matches a collection name,
        the template will automatically be assigned to that collection.
        """
        template = self.get_template(template_id)
        tag = self.template_repo.add_tag(template, tag_name)

        # Auto-assign to folder if tag matches a collection name
        if auto_assign_folder and not template.collection_id:
            matching_collection = self.collection_repo.get_by_name(tag_name)
            if matching_collection:
                template.collection_id = matching_collection.id

        return tag

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

    # =========================================================================
    # Collection management methods
    # =========================================================================

    def create_collection(
        self,
        name: str,
        description: str | None = None,
        icon: str | None = None,
        parent_id: int | None = None,
    ) -> Collection:
        """Create a new collection/folder."""
        if not name or not name.strip():
            raise ValidationError("name", "Folder name cannot be empty")

        # Check for duplicate names within the same parent
        existing = self.collection_repo.get_by_name_and_parent(name, parent_id)
        if existing:
            raise ValidationError("name", f"Folder with name '{name}' already exists in this location")

        # Validate parent exists if specified
        if parent_id is not None:
            parent = self.collection_repo.get_by_id(parent_id)
            if not parent:
                raise ValidationError("parent_id", "Parent folder not found")

        return self.collection_repo.create(
            name=name,
            description=description,
            icon=icon,
            parent_id=parent_id,
        )

    def get_collection(self, collection_id: int) -> Collection:
        """Get a collection by ID."""
        collection = self.collection_repo.get_by_id(collection_id)
        if not collection:
            raise CollectionNotFoundError(collection_id)
        return collection

    def get_collection_by_name(self, name: str) -> Optional[Collection]:
        """Get a collection by name."""
        return self.collection_repo.get_by_name(name)

    def list_collections(self) -> List[Collection]:
        """List all collections."""
        return self.collection_repo.list_all()

    def update_collection(
        self,
        collection_id: int,
        name: str | None = None,
        description: str | None = None,
        icon: str | None = None,
        parent_id: int | None = None,
    ) -> Collection:
        """Update a collection/folder."""
        collection = self.get_collection(collection_id)

        # Determine target parent
        target_parent_id = parent_id if parent_id is not None else collection.parent_id

        # Check name uniqueness if changing name or parent
        if name and name != collection.name:
            existing = self.collection_repo.get_by_name_and_parent(name, target_parent_id)
            if existing and existing.id != collection_id:
                raise ValidationError("name", f"Folder with name '{name}' already exists in this location")

        # Prevent circular references
        if parent_id is not None and parent_id != collection.parent_id:
            if parent_id == collection_id:
                raise ValidationError("parent_id", "A folder cannot be its own parent")
            # Check if parent_id is a descendant of collection_id
            if self._is_descendant(parent_id, collection_id):
                raise ValidationError("parent_id", "Cannot move a folder into its own subfolder")

        return self.collection_repo.update(
            collection,
            name=name,
            description=description,
            icon=icon,
            parent_id=parent_id,
        )

    def _is_descendant(self, potential_descendant_id: int, ancestor_id: int) -> bool:
        """Check if potential_descendant is a descendant of ancestor."""
        current = self.collection_repo.get_by_id(potential_descendant_id)
        while current:
            if current.parent_id == ancestor_id:
                return True
            if current.parent_id is None:
                break
            current = self.collection_repo.get_by_id(current.parent_id)
        return False

    def delete_collection(self, collection_id: int) -> None:
        """Delete a collection (templates are unlinked, not deleted)."""
        collection = self.get_collection(collection_id)
        self.collection_repo.delete(collection)

    def add_template_to_collection(self, template_id: int, collection_id: int) -> None:
        """Add a template to a collection."""
        template = self.get_template(template_id)
        collection = self.get_collection(collection_id)
        self.collection_repo.add_template(collection, template)

    def remove_template_from_collection(self, template_id: int) -> None:
        """Remove a template from its collection."""
        template = self.get_template(template_id)
        self.collection_repo.remove_template(template)
