"""Repository for Template operations."""

from typing import Optional, List
from sqlalchemy import select, or_
from sqlalchemy.orm import Session, joinedload

from docforge.models.template import Template, Tag, Variable


class TemplateRepository:
    """Repository for Template CRUD operations."""

    def __init__(self, session: Session):
        self.session = session

    def create(
        self,
        name: str,
        content: str = "",
        format: str = "markdown",
        description: str | None = None,
        folder_path: str | None = None,
        variables_schema: str | None = None,
    ) -> Template:
        """Create a new template."""
        template = Template(
            name=name,
            content=content,
            format=format,
            description=description,
            folder_path=folder_path,
            variables_schema=variables_schema,
            current_version=1,
        )
        self.session.add(template)
        self.session.flush()
        return template

    def get_by_id(self, template_id: int) -> Optional[Template]:
        """Get a template by ID."""
        stmt = (
            select(Template)
            .options(joinedload(Template.tags), joinedload(Template.variables))
            .where(Template.id == template_id)
        )
        return self.session.execute(stmt).unique().scalar_one_or_none()

    def get_by_name(self, name: str) -> Optional[Template]:
        """Get a template by name."""
        stmt = (
            select(Template)
            .options(joinedload(Template.tags), joinedload(Template.variables))
            .where(Template.name == name)
        )
        return self.session.execute(stmt).unique().scalar_one_or_none()

    def list_all(
        self,
        format: str | None = None,
        folder_path: str | None = None,
        tag_names: list[str] | None = None,
    ) -> List[Template]:
        """List all templates with optional filters."""
        stmt = select(Template).options(
            joinedload(Template.tags), joinedload(Template.variables)
        )

        if format:
            stmt = stmt.where(Template.format == format)
        if folder_path:
            stmt = stmt.where(Template.folder_path == folder_path)
        if tag_names:
            stmt = stmt.join(Template.tags).where(Tag.name.in_(tag_names))

        stmt = stmt.order_by(Template.name)
        return list(self.session.execute(stmt).unique().scalars().all())

    def search(self, query: str) -> List[Template]:
        """Search templates by name, description, or content."""
        pattern = f"%{query}%"
        stmt = (
            select(Template)
            .options(joinedload(Template.tags), joinedload(Template.variables))
            .where(
                or_(
                    Template.name.ilike(pattern),
                    Template.description.ilike(pattern),
                    Template.content.ilike(pattern),
                )
            )
            .order_by(Template.name)
        )
        return list(self.session.execute(stmt).unique().scalars().all())

    def update(
        self,
        template: Template,
        name: str | None = None,
        content: str | None = None,
        format: str | None = None,
        description: str | None = None,
        folder_path: str | None = None,
        variables_schema: str | None = None,
    ) -> Template:
        """Update a template."""
        if name is not None:
            template.name = name
        if content is not None:
            template.content = content
        if format is not None:
            template.format = format
        if description is not None:
            template.description = description
        if folder_path is not None:
            template.folder_path = folder_path
        if variables_schema is not None:
            template.variables_schema = variables_schema
        self.session.flush()
        return template

    def delete(self, template: Template) -> None:
        """Delete a template."""
        self.session.delete(template)
        self.session.flush()

    def add_tag(self, template: Template, tag_name: str) -> Tag:
        """Add a tag to a template."""
        tag = self.session.execute(
            select(Tag).where(Tag.name == tag_name)
        ).scalar_one_or_none()

        if tag is None:
            tag = Tag(name=tag_name)
            self.session.add(tag)

        if tag not in template.tags:
            template.tags.append(tag)
        self.session.flush()
        return tag

    def remove_tag(self, template: Template, tag_name: str) -> None:
        """Remove a tag from a template."""
        tag = self.session.execute(
            select(Tag).where(Tag.name == tag_name)
        ).scalar_one_or_none()

        if tag and tag in template.tags:
            template.tags.remove(tag)
            self.session.flush()

    def add_variable(
        self,
        template: Template,
        name: str,
        var_type: str = "string",
        required: bool = True,
        default_value: str | None = None,
        description: str | None = None,
    ) -> Variable:
        """Add a variable to a template."""
        variable = Variable(
            template_id=template.id,
            name=name,
            var_type=var_type,
            required=required,
            default_value=default_value,
            description=description,
        )
        self.session.add(variable)
        self.session.flush()
        return variable

    def clear_variables(self, template: Template) -> None:
        """Remove all variables from a template."""
        template.variables.clear()
        self.session.flush()

    def list_tags(self) -> List[Tag]:
        """List all tags."""
        stmt = select(Tag).order_by(Tag.name)
        return list(self.session.execute(stmt).scalars().all())
