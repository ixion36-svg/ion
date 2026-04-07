"""Bulk alert and case operations for SOC workflow acceleration."""

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, func, and_
from sqlalchemy.orm import Session

from ion.models.alert_triage import (
    AlertTriage,
    AlertCase,
    AlertTriageStatus,
    AlertCaseStatus,
)

logger = logging.getLogger(__name__)


def bulk_acknowledge_alerts(
    session: Session,
    alert_ids: list[str],
    analyst_id: int,
) -> dict:
    """Set status to 'acknowledged' for multiple alerts by ES alert ID.

    Skips alerts that are already acknowledged or closed.
    Returns counts of processed, skipped, and any error messages.
    """
    processed = 0
    skipped = 0
    errors: list[str] = []

    for es_id in alert_ids:
        try:
            stmt = select(AlertTriage).where(AlertTriage.es_alert_id == es_id)
            triage = session.execute(stmt).scalar_one_or_none()

            if triage is None:
                # Create a triage entry if one doesn't exist yet
                triage = AlertTriage(
                    es_alert_id=es_id,
                    status=AlertTriageStatus.ACKNOWLEDGED,
                    assigned_to_id=analyst_id,
                )
                session.add(triage)
                processed += 1
                continue

            if triage.status in (AlertTriageStatus.ACKNOWLEDGED, AlertTriageStatus.CLOSED):
                skipped += 1
                continue

            triage.status = AlertTriageStatus.ACKNOWLEDGED
            if triage.assigned_to_id is None:
                triage.assigned_to_id = analyst_id
            processed += 1

        except Exception as exc:
            logger.warning("bulk_acknowledge error for %s: %s", es_id, exc)
            errors.append(f"{es_id}: {exc}")

    session.commit()
    logger.info(
        "bulk_acknowledge_alerts: processed=%d skipped=%d errors=%d",
        processed, skipped, len(errors),
    )
    return {"processed": processed, "skipped": skipped, "errors": errors}


def bulk_close_alerts(
    session: Session,
    alert_ids: list[str],
    analyst_id: int,
    closure_reason: str = "false_positive",
) -> dict:
    """Close multiple alerts by ES alert ID.

    For each alert that has a linked case, the case is also closed if all of
    its triage entries are now closed.
    Returns counts of processed, skipped, and any error messages.
    """
    processed = 0
    skipped = 0
    errors: list[str] = []
    cases_to_check: set[int] = set()

    for es_id in alert_ids:
        try:
            stmt = select(AlertTriage).where(AlertTriage.es_alert_id == es_id)
            triage = session.execute(stmt).scalar_one_or_none()

            if triage is None:
                # Create a closed triage entry
                triage = AlertTriage(
                    es_alert_id=es_id,
                    status=AlertTriageStatus.CLOSED,
                    assigned_to_id=analyst_id,
                )
                session.add(triage)
                processed += 1
                continue

            if triage.status == AlertTriageStatus.CLOSED:
                skipped += 1
                continue

            triage.status = AlertTriageStatus.CLOSED
            if triage.assigned_to_id is None:
                triage.assigned_to_id = analyst_id

            if triage.case_id is not None:
                cases_to_check.add(triage.case_id)

            processed += 1

        except Exception as exc:
            logger.warning("bulk_close error for %s: %s", es_id, exc)
            errors.append(f"{es_id}: {exc}")

    # Close parent cases whose triage entries are now all closed
    for case_id in cases_to_check:
        try:
            case = session.get(AlertCase, case_id)
            if case is None or case.status == AlertCaseStatus.CLOSED:
                continue

            # Check if every triage entry on this case is closed
            stmt = (
                select(func.count(AlertTriage.id))
                .where(
                    and_(
                        AlertTriage.case_id == case_id,
                        AlertTriage.status != AlertTriageStatus.CLOSED,
                    )
                )
            )
            still_open = session.execute(stmt).scalar() or 0

            if still_open == 0:
                case.status = AlertCaseStatus.CLOSED
                case.closure_reason = closure_reason
                case.closed_by_id = analyst_id
                case.closed_at = datetime.now(timezone.utc)
                logger.info("Auto-closed case %s (all alerts closed)", case.case_number)

        except Exception as exc:
            logger.warning("Error closing case %d: %s", case_id, exc)
            errors.append(f"case-{case_id}: {exc}")

    session.commit()
    logger.info(
        "bulk_close_alerts: processed=%d skipped=%d errors=%d",
        processed, skipped, len(errors),
    )
    return {"processed": processed, "skipped": skipped, "errors": errors}


def bulk_assign_alerts(
    session: Session,
    alert_ids: list[str],
    analyst_id: int,
) -> dict:
    """Assign multiple alerts to a specific analyst by ES alert ID.

    Creates triage entries for alerts that don't have one yet.
    Returns counts of processed, skipped, and any error messages.
    """
    processed = 0
    skipped = 0
    errors: list[str] = []

    for es_id in alert_ids:
        try:
            stmt = select(AlertTriage).where(AlertTriage.es_alert_id == es_id)
            triage = session.execute(stmt).scalar_one_or_none()

            if triage is None:
                triage = AlertTriage(
                    es_alert_id=es_id,
                    status=AlertTriageStatus.OPEN,
                    assigned_to_id=analyst_id,
                )
                session.add(triage)
                processed += 1
                continue

            if triage.assigned_to_id == analyst_id:
                skipped += 1
                continue

            triage.assigned_to_id = analyst_id
            processed += 1

        except Exception as exc:
            logger.warning("bulk_assign error for %s: %s", es_id, exc)
            errors.append(f"{es_id}: {exc}")

    session.commit()
    logger.info(
        "bulk_assign_alerts: processed=%d skipped=%d errors=%d",
        processed, skipped, len(errors),
    )
    return {"processed": processed, "skipped": skipped, "errors": errors}
