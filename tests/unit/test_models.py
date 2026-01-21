"""Tests for SQLAlchemy models."""

import pytest
from datetime import datetime

from docforge.models.template import Template, Tag, Variable
from docforge.models.version import TemplateVersion
from docforge.models.document import Document


class TestTemplateModel:
    """Tests for Template model."""

    def test_create_template(self, session):
        """Test creating a basic template."""
        template = Template(
            name="Test Template",
            content="Hello {{ name }}",
            format="markdown",
        )
        session.add(template)
        session.commit()

        assert template.id is not None
        assert template.name == "Test Template"
        assert template.content == "Hello {{ name }}"
        assert template.format == "markdown"
        assert template.current_version == 1

    def test_template_with_tags(self, session):
        """Test template with tags."""
        template = Template(name="Tagged Template", content="")
        tag1 = Tag(name="work")
        tag2 = Tag(name="formal")

        template.tags.append(tag1)
        template.tags.append(tag2)

        session.add(template)
        session.commit()

        assert len(template.tags) == 2
        assert {t.name for t in template.tags} == {"work", "formal"}

    def test_template_with_variables(self, session):
        """Test template with variables."""
        template = Template(name="Template with Vars", content="")
        session.add(template)
        session.commit()

        var = Variable(
            template_id=template.id,
            name="username",
            var_type="string",
            required=True,
        )
        session.add(var)
        session.commit()

        assert len(template.variables) == 1
        assert template.variables[0].name == "username"


class TestTemplateVersionModel:
    """Tests for TemplateVersion model."""

    def test_create_version(self, session):
        """Test creating a version."""
        template = Template(name="Versioned Template", content="v1")
        session.add(template)
        session.commit()

        version = TemplateVersion(
            template_id=template.id,
            version_number=1,
            content="v1",
            message="Initial version",
        )
        session.add(version)
        session.commit()

        assert version.id is not None
        assert version.version_number == 1
        assert version.is_checkpoint is False

    def test_checkpoint_version(self, session):
        """Test creating a checkpoint."""
        template = Template(name="CP Template", content="")
        session.add(template)
        session.commit()

        version = TemplateVersion(
            template_id=template.id,
            version_number=1,
            content="",
            is_checkpoint=True,
            checkpoint_name="v1.0",
        )
        session.add(version)
        session.commit()

        assert version.is_checkpoint is True
        assert version.checkpoint_name == "v1.0"


class TestDocumentModel:
    """Tests for Document model."""

    def test_create_document(self, session):
        """Test creating a document."""
        document = Document(
            name="Test Document",
            rendered_content="Hello World",
            output_format="text",
        )
        session.add(document)
        session.commit()

        assert document.id is not None
        assert document.name == "Test Document"
        assert document.rendered_content == "Hello World"

    def test_document_with_template_reference(self, session):
        """Test document with template reference."""
        template = Template(name="Source Template", content="")
        session.add(template)
        session.commit()

        document = Document(
            name="Generated Doc",
            rendered_content="Content",
            source_template_id=template.id,
            source_template_version=1,
        )
        session.add(document)
        session.commit()

        assert document.source_template_id == template.id
        assert document.source_template.name == "Source Template"
