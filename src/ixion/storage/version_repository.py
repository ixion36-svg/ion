"""Repository for TemplateVersion operations."""

from typing import Optional, List
from sqlalchemy import select, desc
from sqlalchemy.orm import Session

from ixion.models.version import TemplateVersion


class VersionRepository:
    """Repository for TemplateVersion CRUD operations."""

    def __init__(self, session: Session):
        self.session = session

    def create(
        self,
        template_id: int,
        version_number: int,
        content: str,
        diff: str | None = None,
        is_checkpoint: bool = False,
        checkpoint_name: str | None = None,
        author: str | None = None,
        message: str | None = None,
    ) -> TemplateVersion:
        """Create a new version."""
        version = TemplateVersion(
            template_id=template_id,
            version_number=version_number,
            content=content,
            diff=diff,
            is_checkpoint=is_checkpoint,
            checkpoint_name=checkpoint_name,
            author=author,
            message=message,
        )
        self.session.add(version)
        self.session.flush()
        return version

    def get_by_id(self, version_id: int) -> Optional[TemplateVersion]:
        """Get a version by ID."""
        stmt = select(TemplateVersion).where(TemplateVersion.id == version_id)
        return self.session.execute(stmt).scalar_one_or_none()

    def get_by_version_number(
        self, template_id: int, version_number: int
    ) -> Optional[TemplateVersion]:
        """Get a specific version of a template."""
        stmt = select(TemplateVersion).where(
            TemplateVersion.template_id == template_id,
            TemplateVersion.version_number == version_number,
        )
        return self.session.execute(stmt).scalar_one_or_none()

    def get_latest(self, template_id: int) -> Optional[TemplateVersion]:
        """Get the latest version of a template."""
        stmt = (
            select(TemplateVersion)
            .where(TemplateVersion.template_id == template_id)
            .order_by(desc(TemplateVersion.version_number))
            .limit(1)
        )
        return self.session.execute(stmt).scalar_one_or_none()

    def list_for_template(
        self,
        template_id: int,
        checkpoints_only: bool = False,
        limit: int | None = None,
    ) -> List[TemplateVersion]:
        """List versions for a template."""
        stmt = select(TemplateVersion).where(
            TemplateVersion.template_id == template_id
        )

        if checkpoints_only:
            stmt = stmt.where(TemplateVersion.is_checkpoint == True)

        stmt = stmt.order_by(desc(TemplateVersion.version_number))

        if limit:
            stmt = stmt.limit(limit)

        return list(self.session.execute(stmt).scalars().all())

    def get_checkpoint_by_name(
        self, template_id: int, checkpoint_name: str
    ) -> Optional[TemplateVersion]:
        """Get a checkpoint by name."""
        stmt = select(TemplateVersion).where(
            TemplateVersion.template_id == template_id,
            TemplateVersion.checkpoint_name == checkpoint_name,
        )
        return self.session.execute(stmt).scalar_one_or_none()

    def mark_as_checkpoint(
        self,
        version: TemplateVersion,
        checkpoint_name: str,
        message: str | None = None,
    ) -> TemplateVersion:
        """Mark a version as a checkpoint."""
        version.is_checkpoint = True
        version.checkpoint_name = checkpoint_name
        if message:
            version.message = message
        self.session.flush()
        return version

    def delete(self, version: TemplateVersion) -> None:
        """Delete a version."""
        self.session.delete(version)
        self.session.flush()

    def delete_old_versions(
        self, template_id: int, keep_count: int, keep_checkpoints: bool = True
    ) -> int:
        """Delete old versions, keeping the most recent ones and optionally checkpoints."""
        # Get all versions ordered by version number
        all_versions = self.list_for_template(template_id)

        # Separate checkpoints and regular versions
        checkpoints = [v for v in all_versions if v.is_checkpoint]
        regular = [v for v in all_versions if not v.is_checkpoint]

        # Determine which to delete
        to_delete = []
        if keep_checkpoints:
            # Keep all checkpoints, only prune regular versions
            if len(regular) > keep_count:
                to_delete = regular[keep_count:]
        else:
            # Prune all versions
            if len(all_versions) > keep_count:
                to_delete = all_versions[keep_count:]

        for version in to_delete:
            self.delete(version)

        return len(to_delete)

    def count_for_template(self, template_id: int) -> int:
        """Count versions for a template."""
        stmt = select(TemplateVersion).where(
            TemplateVersion.template_id == template_id
        )
        return len(list(self.session.execute(stmt).scalars().all()))
