"""Tests for service layer."""

import pytest

from ion.services.template_service import TemplateService
from ion.services.version_service import VersionService
from ion.services.render_service import RenderService
from ion.core.exceptions import (
    TemplateNotFoundError,
    VersionNotFoundError,
    ValidationError,
)


class TestTemplateService:
    """Tests for TemplateService."""

    @pytest.fixture
    def service(self, session):
        return TemplateService(session)

    def test_create_template(self, service, session):
        """Test creating a template."""
        template = service.create_template(
            name="Test Template",
            content="Hello {{ name }}",
            format="markdown",
            description="A test template",
        )
        session.commit()

        assert template.id is not None
        assert template.name == "Test Template"
        assert template.current_version == 1

    def test_create_template_with_tags(self, service, session):
        """Test creating a template with tags."""
        template = service.create_template(
            name="Tagged Template",
            content="",
            tags=["work", "formal"],
        )
        session.commit()

        assert len(template.tags) == 2
        assert {t.name for t in template.tags} == {"work", "formal"}

    def test_create_duplicate_name_fails(self, service, session):
        """Test that duplicate names are rejected."""
        service.create_template(name="Unique", content="")
        session.commit()

        with pytest.raises(ValidationError):
            service.create_template(name="Unique", content="")

    def test_get_template(self, service, session):
        """Test getting a template by ID."""
        created = service.create_template(name="Get Test", content="")
        session.commit()

        retrieved = service.get_template(created.id)
        assert retrieved.name == "Get Test"

    def test_get_nonexistent_template(self, service):
        """Test getting a nonexistent template."""
        with pytest.raises(TemplateNotFoundError):
            service.get_template(99999)

    def test_update_template_content(self, service, session):
        """Test updating template content creates a version."""
        template = service.create_template(name="Update Test", content="v1")
        session.commit()

        updated = service.update_template(
            template.id,
            content="v2",
            version_message="Updated content",
        )
        session.commit()

        assert updated.content == "v2"
        assert updated.current_version == 2

    def test_delete_template(self, service, session):
        """Test deleting a template."""
        template = service.create_template(name="Delete Test", content="")
        session.commit()
        template_id = template.id

        service.delete_template(template_id)
        session.commit()

        with pytest.raises(TemplateNotFoundError):
            service.get_template(template_id)

    def test_search_templates(self, service, session):
        """Test searching templates."""
        service.create_template(name="Invoice Template", content="invoice content")
        service.create_template(name="Letter Template", content="letter content")
        service.create_template(name="Report", content="report invoice data")
        session.commit()

        results = service.search_templates("invoice")
        assert len(results) == 2


class TestVersionService:
    """Tests for VersionService."""

    @pytest.fixture
    def template_service(self, session):
        return TemplateService(session)

    @pytest.fixture
    def version_service(self, session):
        return VersionService(session)

    def test_list_versions(self, template_service, version_service, session):
        """Test listing versions."""
        template = template_service.create_template(name="Version Test", content="v1")
        session.commit()

        # Update to create more versions
        template_service.update_template(template.id, content="v2")
        template_service.update_template(template.id, content="v3")
        session.commit()

        versions = version_service.list_versions(template.id)
        assert len(versions) == 3

    def test_create_checkpoint(self, template_service, version_service, session):
        """Test creating a checkpoint."""
        template = template_service.create_template(name="CP Test", content="content")
        session.commit()

        checkpoint = version_service.create_checkpoint(
            template.id,
            checkpoint_name="v1.0",
            message="First release",
        )
        session.commit()

        assert checkpoint.is_checkpoint is True
        assert checkpoint.checkpoint_name == "v1.0"

    def test_diff_versions(self, template_service, version_service, session):
        """Test getting diff between versions."""
        template = template_service.create_template(name="Diff Test", content="line1\nline2")
        session.commit()

        template_service.update_template(template.id, content="line1\nline2\nline3")
        session.commit()

        diff = version_service.diff_versions(template.id, 1, 2)
        assert "+line3" in diff

    def test_rollback(self, template_service, version_service, session):
        """Test rolling back to a previous version."""
        template = template_service.create_template(name="Rollback Test", content="original")
        session.commit()

        template_service.update_template(template.id, content="modified")
        session.commit()

        rolled_back = version_service.rollback(template.id, 1)
        session.commit()

        assert rolled_back.content == "original"
        assert rolled_back.current_version == 3  # Rollback creates new version


class TestRenderService:
    """Tests for RenderService."""

    @pytest.fixture
    def template_service(self, session):
        return TemplateService(session)

    @pytest.fixture
    def render_service(self, session):
        return RenderService(session)

    def test_preview(self, template_service, render_service, session):
        """Test previewing a template."""
        template = template_service.create_template(
            name="Preview Test",
            content="Hello {{ name }}!",
        )
        session.commit()

        result = render_service.preview(template.id, data={"name": "World"})
        assert result == "Hello World!"

    def test_render_with_document_save(
        self, template_service, render_service, session
    ):
        """Test rendering and saving a document."""
        template = template_service.create_template(
            name="Render Test",
            content="Hello {{ name }}!",
        )
        session.commit()

        content, document = render_service.render(
            template.id,
            data={"name": "World"},
            document_name="Test Output",
        )
        session.commit()

        assert content == "Hello World!"
        assert document is not None
        assert document.name == "Test Output"
        assert document.source_template_id == template.id

    def test_render_string(self, render_service):
        """Test rendering a template string directly."""
        result = render_service.render_string(
            "{{ greeting }}, {{ name }}!",
            {"greeting": "Hi", "name": "User"},
        )
        assert result == "Hi, User!"
