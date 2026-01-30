"""Bidirectional sync service for Kibana Cases."""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from ixion.services.kibana_cases_service import get_kibana_cases_service
from ixion.models.alert_triage import AlertCase, CaseNote
from ixion.models.user import User
from ixion.storage.database import get_session_factory, get_engine

logger = logging.getLogger(__name__)


class KibanaSyncService:
    """Service to sync comments bidirectionally between IXION and Kibana."""

    def __init__(self):
        self.kibana_service = get_kibana_cases_service()
        self._running = False
        self._task: Optional[asyncio.Task] = None

    async def sync_case_comments(self, session: Session, case: AlertCase) -> int:
        """Sync comments from Kibana to IXION for a specific case.

        Returns number of new comments synced.
        """
        if not case.kibana_case_id or not self.kibana_service.enabled:
            return 0

        synced = 0
        try:
            # Get comments from Kibana
            kibana_comments = self.kibana_service.get_case_comments(case.kibana_case_id)

            # Get existing note contents to avoid duplicates
            # Separate Kibana-synced notes from user notes
            all_notes = {n.content for n in case.notes}
            kibana_synced_notes = {n.content for n in case.notes if n.content.startswith("[From Kibana")}

            # Get or create a system user for Kibana-synced comments
            system_user = session.query(User).filter_by(username="kibana_sync").first()
            if not system_user:
                system_user = session.query(User).filter_by(username="admin").first()

            for comment in kibana_comments:
                # Only sync user comments (not alert attachments)
                if comment.get("type") != "user":
                    continue

                comment_text = comment.get("comment", "")
                created_by = comment.get("created_by", {}).get("username", "unknown")
                created_at_str = comment.get("created_at")
                comment_id = comment.get("id", "")

                # Skip if this looks like a comment we sent TO Kibana (has username prefix)
                if comment_text.startswith("**") and ":**" in comment_text[:50]:
                    continue

                # Format the comment with Kibana attribution
                formatted_content = f"[From Kibana - {created_by}] {comment_text}"

                # Check if we already have this exact formatted comment
                if formatted_content in all_notes:
                    continue

                # Check for partial match only in Kibana-synced notes (to handle formatting changes)
                if any(comment_text in note for note in kibana_synced_notes):
                    continue

                # Create new note
                note = CaseNote(
                    case_id=case.id,
                    user_id=system_user.id if system_user else 1,
                    content=formatted_content,
                )

                # Try to preserve original timestamp
                if created_at_str:
                    try:
                        note.created_at = datetime.fromisoformat(
                            created_at_str.replace("Z", "+00:00")
                        )
                    except (ValueError, TypeError):
                        pass

                session.add(note)
                synced += 1
                logger.info(f"Synced comment from Kibana to case {case.case_number}")

            if synced > 0:
                session.commit()

        except Exception as e:
            logger.error(f"Error syncing comments for case {case.case_number}: {e}")
            session.rollback()

        return synced

    async def sync_all_cases(self) -> dict:
        """Sync comments for all cases that have Kibana links."""
        if not self.kibana_service.enabled:
            return {"synced": 0, "cases": 0, "error": "Kibana not enabled"}

        engine = get_engine()
        factory = get_session_factory(engine)
        session = factory()

        try:
            # Get all cases with Kibana IDs
            cases = session.query(AlertCase).filter(
                AlertCase.kibana_case_id.isnot(None)
            ).all()

            total_synced = 0
            cases_processed = 0

            for case in cases:
                synced = await self.sync_case_comments(session, case)
                total_synced += synced
                cases_processed += 1

            return {
                "synced": total_synced,
                "cases": cases_processed,
            }
        finally:
            session.close()

    async def sync_case_status_from_kibana(self, session: Session, case: AlertCase) -> bool:
        """Sync case status from Kibana to IXION.

        Returns True if status was updated.
        """
        if not case.kibana_case_id or not self.kibana_service.enabled:
            return False

        try:
            kibana_case = self.kibana_service.get_case(case.kibana_case_id)
            if not kibana_case:
                return False

            kibana_status = kibana_case.get("status")

            # Map Kibana status to IXION status
            status_map = {
                "open": "open",
                "in-progress": "in_progress",
                "closed": "closed",
            }

            ixion_status = status_map.get(kibana_status)
            if not ixion_status:
                return False

            current_status = case.status.value if hasattr(case.status, "value") else case.status

            if current_status != ixion_status:
                case.status = ixion_status
                case.kibana_case_version = kibana_case.get("version")
                session.commit()
                logger.info(f"Synced status from Kibana for case {case.case_number}: {ixion_status}")
                return True

            return False

        except Exception as e:
            logger.error(f"Error syncing status for case {case.case_number}: {e}")
            return False

    async def _background_sync_loop(self, interval_seconds: int = 60):
        """Background loop to periodically sync from Kibana."""
        logger.info(f"Starting Kibana sync background task (interval: {interval_seconds}s)")

        while self._running:
            try:
                result = await self.sync_all_cases()
                if result.get("synced", 0) > 0:
                    logger.info(f"Kibana sync: {result['synced']} comments synced from {result['cases']} cases")
            except Exception as e:
                logger.error(f"Error in Kibana sync loop: {e}")

            await asyncio.sleep(interval_seconds)

    def start_background_sync(self, interval_seconds: int = 60):
        """Start the background sync task."""
        if self._running:
            return

        self._running = True
        self._task = asyncio.create_task(self._background_sync_loop(interval_seconds))

    def stop_background_sync(self):
        """Stop the background sync task."""
        self._running = False
        if self._task:
            self._task.cancel()
            self._task = None


# Singleton instance
_sync_service: Optional[KibanaSyncService] = None


def get_kibana_sync_service() -> KibanaSyncService:
    """Get the singleton Kibana sync service instance."""
    global _sync_service
    if _sync_service is None:
        _sync_service = KibanaSyncService()
    return _sync_service
