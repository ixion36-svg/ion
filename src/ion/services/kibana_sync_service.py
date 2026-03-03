"""Bidirectional sync service for Kibana Cases."""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, List, Any

from sqlalchemy import or_, and_
from sqlalchemy.orm import Session, joinedload

from ion.services.kibana_cases_service import get_kibana_cases_service
from ion.services.elasticsearch_service import ElasticsearchService
from ion.services.case_description import build_case_description
from ion.services.observable_extractor import extract_observables_from_raw
from ion.models.alert_triage import AlertCase, AlertTriage, AlertTriageStatus, Note, NoteEntityType
from ion.models.user import User
from ion.storage.database import get_session_factory, get_engine

logger = logging.getLogger(__name__)


class KibanaSyncService:
    """Service to sync comments bidirectionally between ION and Kibana."""

    def __init__(self):
        self.kibana_service = get_kibana_cases_service()
        self._running = False
        self._task: Optional[asyncio.Task] = None

    async def sync_case_comments(self, session: Session, case: AlertCase) -> int:
        """Sync comments from Kibana to ION for a specific case.

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
                note = Note(
                    entity_type=NoteEntityType.CASE,
                    entity_id=str(case.id),
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
        """Sync case status from Kibana to ION.

        Returns True if status was updated.
        """
        if not case.kibana_case_id or not self.kibana_service.enabled:
            return False

        try:
            kibana_case = self.kibana_service.get_case(case.kibana_case_id)
            if not kibana_case:
                return False

            kibana_status = kibana_case.get("status")

            # Map Kibana status to ION status
            status_map = {
                "open": "open",
                "in-progress": "in_progress",
                "closed": "closed",
            }

            ion_status = status_map.get(kibana_status)
            if not ion_status:
                return False

            current_status = case.status.value if hasattr(case.status, "value") else case.status

            if current_status != ion_status:
                case.status = ion_status
                case.kibana_case_version = kibana_case.get("version")
                session.commit()
                logger.info(f"Synced status from Kibana for case {case.case_number}: {ion_status}")
                return True

            return False

        except Exception as e:
            logger.error(f"Error syncing status for case {case.case_number}: {e}")
            return False

    async def sync_case_status_to_kibana(self, session: Session, case: AlertCase) -> bool:
        """Sync case status from ION to Kibana.

        Returns True if Kibana was updated.
        """
        if not case.kibana_case_id or not self.kibana_service.enabled:
            return False

        try:
            # Get current Kibana case to check status and get version
            kibana_case = self.kibana_service.get_case(case.kibana_case_id)
            if not kibana_case:
                return False

            kibana_status = kibana_case.get("status")
            kibana_version = kibana_case.get("version")

            # Map ION status to Kibana status
            status_map = {
                "open": "open",
                "in_progress": "in-progress",
                "resolved": "closed",
                "closed": "closed",
            }

            ion_status = case.status.value if hasattr(case.status, "value") else case.status
            target_kibana_status = status_map.get(ion_status)

            if not target_kibana_status:
                return False

            # Only update if different
            if kibana_status != target_kibana_status:
                result = self.kibana_service.update_case(
                    case_id=case.kibana_case_id,
                    version=kibana_version,
                    status=target_kibana_status,
                )
                if result:
                    case.kibana_case_version = result.get("version")
                    session.commit()
                    logger.info(f"Synced status to Kibana for case {case.case_number}: {target_kibana_status}")
                    return True

            return False

        except Exception as e:
            logger.error(f"Error syncing status to Kibana for case {case.case_number}: {e}")
            return False

    async def sync_all_case_statuses(self, session: Session) -> dict:
        """Bidirectional sync of case statuses between ION and Kibana.

        Uses last-update-wins strategy based on updated_at timestamps.
        Returns dict with sync statistics.
        """
        if not self.kibana_service.enabled:
            return {"from_kibana": 0, "to_kibana": 0, "error": "Kibana not enabled"}

        from_kibana = 0
        to_kibana = 0

        try:
            # Get all cases with Kibana IDs
            cases = session.query(AlertCase).filter(
                AlertCase.kibana_case_id.isnot(None)
            ).all()

            for case in cases:
                try:
                    kibana_case = self.kibana_service.get_case(case.kibana_case_id)
                    if not kibana_case:
                        continue

                    # Parse timestamps
                    kibana_updated = kibana_case.get("updated_at") or kibana_case.get("created_at")
                    ion_updated = case.updated_at or case.created_at

                    # Convert Kibana timestamp to datetime for comparison
                    if kibana_updated:
                        from datetime import datetime
                        kibana_dt = datetime.fromisoformat(kibana_updated.replace("Z", "+00:00"))
                        # Make ion_updated timezone-aware if needed
                        if ion_updated.tzinfo is None:
                            from datetime import timezone
                            ion_updated = ion_updated.replace(tzinfo=timezone.utc)

                        # Last update wins
                        if kibana_dt > ion_updated:
                            if await self.sync_case_status_from_kibana(session, case):
                                from_kibana += 1
                        else:
                            if await self.sync_case_status_to_kibana(session, case):
                                to_kibana += 1
                    else:
                        # No Kibana timestamp, sync from ion
                        if await self.sync_case_status_to_kibana(session, case):
                            to_kibana += 1

                except Exception as e:
                    logger.warning(f"Error syncing status for case {case.case_number}: {e}")
                    continue

            return {"from_kibana": from_kibana, "to_kibana": to_kibana}

        except Exception as e:
            logger.error(f"Error in bidirectional status sync: {e}")
            return {"from_kibana": from_kibana, "to_kibana": to_kibana, "error": str(e)}

    async def import_cases_from_kibana(self, session: Session) -> dict:
        """Import cases created in Kibana that don't exist in ION.

        Imports the case with attached alerts, extracting observables and
        building evidence summary to match ION's case format.

        Returns dict with import statistics.
        """
        if not self.kibana_service.enabled:
            return {"imported": 0, "skipped": 0, "error": "Kibana not enabled"}

        imported = 0
        skipped = 0
        errors = []

        try:
            # Get all cases from Kibana
            kibana_cases = self.kibana_service.list_cases(per_page=100)
            cases_list = kibana_cases.get("cases", [])

            # Get existing Kibana case IDs in ION
            existing_kibana_ids = {
                c.kibana_case_id for c in session.query(AlertCase.kibana_case_id).filter(
                    AlertCase.kibana_case_id.isnot(None)
                ).all()
            }

            # Get admin user for case creation
            admin_user = session.query(User).filter_by(username="admin").first()
            if not admin_user:
                return {"imported": 0, "skipped": 0, "error": "No admin user found"}

            # Generate next case number
            max_case = session.query(AlertCase).order_by(AlertCase.id.desc()).first()
            next_num = (max_case.id + 1) if max_case else 1

            # Get elasticsearch service for fetching alert details
            es_service = ElasticsearchService()

            for kibana_case in cases_list:
                kibana_id = kibana_case.get("id")

                # Skip if already exists in ION
                if kibana_id in existing_kibana_ids:
                    skipped += 1
                    continue

                # Skip if this case was created by ION (has ion tag or CASE- prefix)
                tags = kibana_case.get("tags", [])
                title = kibana_case.get("title", "")
                if "ion" in tags or title.startswith("[CASE-"):
                    skipped += 1
                    continue

                try:
                    # Map Kibana severity to ION
                    severity_map = {
                        "low": "low",
                        "medium": "medium",
                        "high": "high",
                        "critical": "critical",
                    }
                    severity = severity_map.get(
                        kibana_case.get("severity", "medium"), "medium"
                    )

                    # Map Kibana status to ION
                    status_map = {
                        "open": "open",
                        "in-progress": "in_progress",
                        "closed": "closed",
                    }
                    status = status_map.get(
                        kibana_case.get("status", "open"), "open"
                    )

                    # Get attached alerts from Kibana case
                    kibana_alerts = self.kibana_service.get_case_alerts(kibana_id)
                    alert_ids = [a["id"] for a in kibana_alerts]
                    alert_index = kibana_alerts[0]["index"] if kibana_alerts else None

                    # Fetch full alert data from Elasticsearch
                    source_alert_ids = []
                    evidence_parts = []
                    affected_hosts = set()
                    affected_users = set()
                    triggered_rules = set()
                    observables = []
                    seen_observables = set()

                    if alert_ids and es_service:
                        try:
                            es_alerts = await es_service.get_alerts_by_ids(alert_ids, alert_index)

                            for alert in es_alerts:
                                source_alert_ids.append(alert.id)

                                # Build evidence summary
                                evidence_parts.append(
                                    f"Alert \"{alert.title}\" triggered at {alert.timestamp.strftime('%d/%m/%Y, %H:%M:%S')}. "
                                    f"Severity: {alert.severity}."
                                )

                                # Extract hosts and users
                                if alert.host:
                                    affected_hosts.add(alert.host)
                                if alert.user:
                                    affected_users.add(alert.user)

                                # Extract rule name
                                if alert.rule_name:
                                    triggered_rules.add(alert.rule_name)

                                # Extract observables from raw data
                                if alert.raw_data:
                                    extracted = extract_observables_from_raw(alert.raw_data)
                                    for obs in extracted:
                                        key = (obs["type"], obs["value"])
                                        if key not in seen_observables:
                                            seen_observables.add(key)
                                            observables.append(obs)

                        except Exception as e:
                            logger.warning(f"Could not fetch alerts from ES for case {kibana_id}: {e}")

                    # Build standardized description from alert data
                    hosts_list = list(affected_hosts) if affected_hosts else None
                    users_list = list(affected_users) if affected_users else None
                    rules_list = list(triggered_rules) if triggered_rules else None
                    evidence = " ".join(evidence_parts) if evidence_parts else None

                    # Overwrite with standardized format (drop original Kibana description)
                    formatted_description = build_case_description(
                        description="",
                        affected_hosts=hosts_list,
                        affected_users=users_list,
                        evidence_summary=evidence,
                        observables=observables if observables else None,
                        alert_ids=source_alert_ids if source_alert_ids else None,
                        triggered_rules=rules_list,
                    )

                    # Build title from alert data (rule name or alert title), matching ION native style
                    standardized_title = title  # fallback to Kibana title
                    if triggered_rules:
                        standardized_title = next(iter(triggered_rules))
                    elif source_alert_ids and es_alerts:
                        first_alert = es_alerts[0]
                        if first_alert.title:
                            standardized_title = first_alert.title

                    # Create ION case with standardized title and description
                    case_number = f"CASE-{next_num:04d}"
                    new_case = AlertCase(
                        case_number=case_number,
                        title=standardized_title,
                        description=formatted_description,
                        status=status,
                        severity=severity,
                        created_by_id=admin_user.id,
                        kibana_case_id=kibana_id,
                        kibana_case_version=kibana_case.get("version"),
                        source_alert_ids=source_alert_ids if source_alert_ids else None,
                        evidence_summary=evidence,
                        affected_hosts=hosts_list,
                        affected_users=users_list,
                        triggered_rules=rules_list,
                        observables=observables if observables else None,
                    )

                    session.add(new_case)
                    session.flush()  # Get the ID

                    # Link alerts to case via AlertTriage (matches native case creation)
                    for alert_id in source_alert_ids:
                        triage = session.query(AlertTriage).filter_by(es_alert_id=alert_id).first()
                        if not triage:
                            triage = AlertTriage(
                                es_alert_id=alert_id,
                                status=AlertTriageStatus.INVESTIGATING,
                            )
                            session.add(triage)
                            session.flush()
                        triage.case_id = new_case.id

                    # Push standardized description back to Kibana
                    kibana_version = kibana_case.get("version")
                    if kibana_version:
                        try:
                            updated = self.kibana_service.update_case(
                                case_id=kibana_id,
                                version=kibana_version,
                                title=f"[{case_number}] {standardized_title}",
                                description=formatted_description,
                            )
                            if updated:
                                new_case.kibana_case_version = updated.get("version")
                        except Exception as e:
                            logger.warning(f"Failed to push formatted description back to Kibana case {kibana_id}: {e}")

                    # Import user comments from Kibana (not alert attachments)
                    comments = self.kibana_service.get_case_comments(kibana_id)
                    for comment in comments:
                        if comment.get("type") != "user":
                            continue

                        comment_text = comment.get("comment", "")
                        created_by = comment.get("created_by", {}).get("username", "unknown")

                        note = Note(
                            entity_type=NoteEntityType.CASE,
                            entity_id=str(new_case.id),
                            user_id=admin_user.id,
                            content=f"[From Kibana - {created_by}] {comment_text}",
                        )

                        created_at_str = comment.get("created_at")
                        if created_at_str:
                            try:
                                note.created_at = datetime.fromisoformat(
                                    created_at_str.replace("Z", "+00:00")
                                )
                            except (ValueError, TypeError):
                                pass

                        session.add(note)

                    next_num += 1
                    imported += 1
                    logger.info(
                        f"Imported case from Kibana: {case_number} "
                        f"(Kibana ID: {kibana_id}, Alerts: {len(source_alert_ids)}, "
                        f"Observables: {len(observables)})"
                    )

                except Exception as e:
                    errors.append(f"Failed to import {kibana_id}: {str(e)}")
                    logger.error(f"Error importing case {kibana_id}: {e}")

            session.commit()

        except Exception as e:
            logger.error(f"Error importing cases from Kibana: {e}")
            session.rollback()
            return {"imported": 0, "skipped": skipped, "error": str(e)}

        return {
            "imported": imported,
            "skipped": skipped,
            "errors": errors if errors else None,
        }

    async def get_unimported_kibana_cases(self) -> list:
        """Get list of Kibana cases that haven't been imported to ION."""
        if not self.kibana_service.enabled:
            return []

        engine = get_engine()
        factory = get_session_factory(engine)
        session = factory()

        try:
            # Get all cases from Kibana
            kibana_cases = self.kibana_service.list_cases(per_page=100)
            cases_list = kibana_cases.get("cases", [])

            # Get existing Kibana case IDs in ION
            existing_kibana_ids = {
                c.kibana_case_id for c in session.query(AlertCase.kibana_case_id).filter(
                    AlertCase.kibana_case_id.isnot(None)
                ).all()
            }

            unimported = []
            for kibana_case in cases_list:
                kibana_id = kibana_case.get("id")
                title = kibana_case.get("title", "")
                tags = kibana_case.get("tags", [])

                # Skip if already exists or was created by ION
                if kibana_id in existing_kibana_ids:
                    continue
                if "ion" in tags or title.startswith("[CASE-"):
                    continue

                unimported.append({
                    "id": kibana_id,
                    "title": title,
                    "status": kibana_case.get("status"),
                    "severity": kibana_case.get("severity"),
                    "created_at": kibana_case.get("created_at"),
                    "created_by": kibana_case.get("created_by", {}).get("username"),
                    "comment_count": kibana_case.get("totalComment", 0),
                    "alert_count": kibana_case.get("totalAlerts", 0),
                })

            return unimported

        finally:
            session.close()

    async def export_cases_to_kibana(self, session: Session) -> dict:
        """Export ION cases that don't have a Kibana link to Kibana.

        Creates cases in Kibana for any ION case where kibana_case_id is NULL,
        then updates the ION record with the Kibana case ID.

        Returns dict with export statistics.
        """
        if not self.kibana_service.enabled:
            return {"exported": 0, "error": "Kibana not enabled"}

        exported = 0
        errors = []

        try:
            # Find ION cases without a Kibana link, or partially failed exports
            unlinked_cases = session.query(AlertCase).filter(
                or_(
                    AlertCase.kibana_case_id.is_(None),
                    and_(
                        AlertCase.kibana_case_id.isnot(None),
                        AlertCase.kibana_case_version.is_(None),
                    ),
                )
            ).all()

            if not unlinked_cases:
                return {"exported": 0}

            for case in unlinked_cases:
                try:
                    # Map ION severity to Kibana severity
                    severity = case.severity or "medium"
                    if severity not in ("low", "medium", "high", "critical"):
                        severity = "medium"

                    # Build description using shared formatter
                    description = build_case_description(
                        description=case.description or "",
                        affected_hosts=case.affected_hosts,
                        affected_users=case.affected_users,
                        evidence_summary=case.evidence_summary,
                        observables=case.observables,
                        alert_ids=case.source_alert_ids,
                        triggered_rules=case.triggered_rules,
                    )

                    title = f"[{case.case_number}] {case.title}"

                    if case.kibana_case_id:
                        # Partial failure retry — fetch current version, then update
                        existing = self.kibana_service.get_case(case.kibana_case_id)
                        if existing and existing.get("version"):
                            kibana_result = self.kibana_service.update_case(
                                case_id=case.kibana_case_id,
                                version=existing["version"],
                                title=title,
                                description=description,
                                severity=severity,
                                tags=["ion", f"case:{case.case_number}"],
                            )
                        else:
                            # Kibana case not found — clear stale ID and create fresh
                            case.kibana_case_id = None
                            kibana_result = self.kibana_service.create_case(
                                title=title,
                                description=description,
                                severity=severity,
                                tags=["ion", f"case:{case.case_number}"],
                            )
                    else:
                        # Create new case in Kibana with ion tag to prevent re-import
                        kibana_result = self.kibana_service.create_case(
                            title=title,
                            description=description,
                            severity=severity,
                            tags=["ion", f"case:{case.case_number}"],
                        )

                    if kibana_result:
                        # Link ION case to Kibana
                        case.kibana_case_id = kibana_result.get("id")
                        case.kibana_case_version = kibana_result.get("version")
                        session.flush()

                        # Export ION notes as Kibana comments
                        try:
                            notes = session.query(Note).options(
                                joinedload(Note.user)
                            ).filter(
                                Note.entity_type == NoteEntityType.CASE,
                                Note.entity_id == str(case.id),
                            ).order_by(Note.created_at).all()

                            for note in notes:
                                # Skip notes that came from Kibana originally
                                if note.content.startswith("[From Kibana"):
                                    continue

                                username = note.user.username if note.user else "unknown"
                                comment_text = f"**{username}:** {note.content}"
                                self.kibana_service.add_comment(
                                    case_id=case.kibana_case_id,
                                    comment=comment_text,
                                )
                        except Exception as e:
                            logger.warning(
                                f"Could not export notes for case {case.case_number}: {e}"
                            )

                        # Sync status to Kibana
                        await self.sync_case_status_to_kibana(session, case)

                        exported += 1
                        logger.info(
                            f"Exported case to Kibana: {case.case_number} -> {case.kibana_case_id}"
                        )
                    else:
                        errors.append(f"Kibana API returned None for {case.case_number}")

                except Exception as e:
                    errors.append(f"Failed to export {case.case_number}: {str(e)}")
                    logger.error(f"Error exporting case {case.case_number} to Kibana: {e}")

            session.commit()

        except Exception as e:
            logger.error(f"Error exporting cases to Kibana: {e}")
            session.rollback()
            return {"exported": 0, "error": str(e)}

        return {
            "exported": exported,
            "errors": errors if errors else None,
        }

    async def _background_sync_loop(self, interval_seconds: int = 60):
        """Background loop to periodically sync between ION and Kibana."""
        logger.info(f"Starting Kibana sync background task (interval: {interval_seconds}s)")

        while self._running:
            try:
                engine = get_engine()
                factory = get_session_factory(engine)
                session = factory()
                try:
                    # Import new cases created in Kibana
                    import_result = await self.import_cases_from_kibana(session)
                    if import_result.get("imported", 0) > 0:
                        logger.info(f"Kibana sync: {import_result['imported']} cases imported from Kibana")

                    # Export ION cases to Kibana
                    export_result = await self.export_cases_to_kibana(session)
                    if export_result.get("exported", 0) > 0:
                        logger.info(f"Kibana sync: {export_result['exported']} cases exported to Kibana")

                    # Bidirectional status sync (last-update-wins)
                    status_result = await self.sync_all_case_statuses(session)
                    if status_result.get("from_kibana", 0) > 0 or status_result.get("to_kibana", 0) > 0:
                        logger.info(
                            f"Kibana sync: status synced - {status_result['from_kibana']} from Kibana, "
                            f"{status_result['to_kibana']} to Kibana"
                        )
                finally:
                    session.close()

                # Sync comments for existing linked cases
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


def reset_kibana_sync_service():
    """Reset the singleton Kibana sync service instance."""
    global _sync_service
    if _sync_service is not None:
        _sync_service.stop_background_sync()
        _sync_service = None
