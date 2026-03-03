"""Business logic for version control operations."""

from typing import Optional, List
from sqlalchemy.orm import Session

from ion.models.template import Template
from ion.models.version import TemplateVersion
from ion.storage.template_repository import TemplateRepository
from ion.storage.version_repository import VersionRepository
from ion.diff.differ import VersionDiffer
from ion.core.exceptions import (
    TemplateNotFoundError,
    VersionNotFoundError,
    ValidationError,
)
from ion.core.config import get_config


class VersionService:
    """Service for version control business logic."""

    def __init__(self, session: Session):
        self.session = session
        self.template_repo = TemplateRepository(session)
        self.version_repo = VersionRepository(session)
        self.differ = VersionDiffer()

    def get_version(
        self, template_id: int, version_number: int
    ) -> TemplateVersion:
        """Get a specific version of a template."""
        version = self.version_repo.get_by_version_number(template_id, version_number)
        if not version:
            raise VersionNotFoundError(template_id, version_number)
        return version

    def get_latest_version(self, template_id: int) -> Optional[TemplateVersion]:
        """Get the latest version of a template."""
        return self.version_repo.get_latest(template_id)

    def list_versions(
        self,
        template_id: int,
        checkpoints_only: bool = False,
        limit: int | None = None,
    ) -> List[TemplateVersion]:
        """List versions for a template."""
        # Verify template exists
        template = self.template_repo.get_by_id(template_id)
        if not template:
            raise TemplateNotFoundError(template_id)

        return self.version_repo.list_for_template(
            template_id, checkpoints_only=checkpoints_only, limit=limit
        )

    def create_checkpoint(
        self,
        template_id: int,
        checkpoint_name: str,
        message: str | None = None,
    ) -> TemplateVersion:
        """Create a named checkpoint for the current version."""
        # Verify template exists
        template = self.template_repo.get_by_id(template_id)
        if not template:
            raise TemplateNotFoundError(template_id)

        # Check for duplicate checkpoint name
        existing = self.version_repo.get_checkpoint_by_name(template_id, checkpoint_name)
        if existing:
            raise ValidationError(
                "checkpoint_name",
                f"Checkpoint '{checkpoint_name}' already exists for this template",
            )

        # Get current version
        current = self.version_repo.get_latest(template_id)
        if not current:
            raise VersionNotFoundError(template_id, 1)

        # Mark as checkpoint
        return self.version_repo.mark_as_checkpoint(
            current, checkpoint_name, message
        )

    def diff_versions(
        self,
        template_id: int,
        from_version: int,
        to_version: int,
    ) -> str:
        """Get diff between two versions."""
        from_ver = self.get_version(template_id, from_version)
        to_ver = self.get_version(template_id, to_version)

        return self.differ.compute_diff(from_ver.content, to_ver.content)

    def rollback(
        self,
        template_id: int,
        to_version: int,
        message: str | None = None,
    ) -> Template:
        """Rollback template to a previous version."""
        # Verify template exists
        template = self.template_repo.get_by_id(template_id)
        if not template:
            raise TemplateNotFoundError(template_id)

        # Get target version
        target = self.get_version(template_id, to_version)

        # Get current content for diff
        current_content = template.content

        # Update template content
        template.content = target.content
        template.current_version += 1

        # Create new version with rollback info
        diff = self.differ.compute_diff(current_content, target.content)
        self.version_repo.create(
            template_id=template_id,
            version_number=template.current_version,
            content=target.content,
            diff=diff,
            message=message or f"Rollback to version {to_version}",
        )

        self.session.flush()
        return template

    def prune_versions(
        self,
        template_id: int,
        keep_count: int | None = None,
        keep_checkpoints: bool = True,
    ) -> int:
        """Delete old versions, keeping recent ones and optionally checkpoints."""
        # Verify template exists
        template = self.template_repo.get_by_id(template_id)
        if not template:
            raise TemplateNotFoundError(template_id)

        if keep_count is None:
            keep_count = get_config().max_versions_to_keep

        return self.version_repo.delete_old_versions(
            template_id, keep_count, keep_checkpoints
        )

    def get_checkpoint_by_name(
        self, template_id: int, checkpoint_name: str
    ) -> Optional[TemplateVersion]:
        """Get a checkpoint by name."""
        return self.version_repo.get_checkpoint_by_name(template_id, checkpoint_name)

    def count_versions(self, template_id: int) -> int:
        """Count versions for a template."""
        return self.version_repo.count_for_template(template_id)
