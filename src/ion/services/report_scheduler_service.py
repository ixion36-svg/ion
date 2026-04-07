"""Scheduled report generation service.

Manages recurring report schedules (daily, weekly, monthly) and
triggers the appropriate report service when a report is due.
"""

import json
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, func, and_
from sqlalchemy.orm import Session

from ion.models.sla import ScheduledReport

logger = logging.getLogger(__name__)

# Valid report types and their required service calls
REPORT_TYPES = ("executive", "soc_health", "shift_handover", "compliance")
SCHEDULE_TYPES = ("daily", "weekly", "monthly")


def _parse_json(raw: str | None, fallback=None):
    """Safely parse a JSON text column."""
    if not raw:
        return fallback
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return fallback


def _report_to_dict(report: ScheduledReport) -> dict:
    """Serialise a ScheduledReport row to a plain dict."""
    return {
        "id": report.id,
        "name": report.name,
        "report_type": report.report_type,
        "schedule": report.schedule,
        "day_of_week": report.day_of_week,
        "day_of_month": report.day_of_month,
        "time_utc": report.time_utc,
        "is_active": report.is_active,
        "created_by_id": report.created_by_id,
        "last_run_at": report.last_run_at.isoformat() if report.last_run_at else None,
        "last_result": _parse_json(report.last_result),
        "recipients": _parse_json(report.recipients, []),
        "config": _parse_json(report.config, {}),
        "created_at": report.created_at.isoformat() if report.created_at else None,
    }


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------

def get_scheduled_reports(session: Session) -> list[dict]:
    """Return all scheduled reports."""
    rows = session.execute(
        select(ScheduledReport).order_by(ScheduledReport.name)
    ).scalars().all()
    return [_report_to_dict(r) for r in rows]


def create_scheduled_report(
    session: Session,
    name: str,
    report_type: str,
    schedule: str,
    created_by_id: int,
    time_utc: str = "08:00",
    day_of_week: int | None = None,
    day_of_month: int | None = None,
    recipients: list | None = None,
    config: dict | None = None,
) -> dict:
    """Create a new scheduled report.

    Args:
        session: Database session.
        name: Human-readable report name.
        report_type: One of ``executive``, ``soc_health``,
            ``shift_handover``, ``compliance``.
        schedule: One of ``daily``, ``weekly``, ``monthly``.
        created_by_id: User ID of the creator.
        time_utc: Time of day in ``HH:MM`` (UTC).
        day_of_week: 0=Monday, used when *schedule* is ``weekly``.
        day_of_month: 1-28, used when *schedule* is ``monthly``.
        recipients: List of user IDs to receive the report.
        config: Report-specific parameters (e.g. ``{"days": 7}``).

    Returns:
        Dict representation of the created report.
    """
    report = ScheduledReport(
        name=name,
        report_type=report_type,
        schedule=schedule,
        time_utc=time_utc,
        day_of_week=day_of_week,
        day_of_month=day_of_month,
        is_active=True,
        created_by_id=created_by_id,
        recipients=json.dumps(recipients or []),
        config=json.dumps(config or {}),
    )
    session.add(report)
    session.commit()
    session.refresh(report)
    return _report_to_dict(report)


def update_scheduled_report(
    session: Session,
    report_id: int,
    **kwargs,
) -> dict:
    """Update fields on an existing scheduled report.

    Accepts any column name as a keyword argument.  JSON columns
    (``recipients``, ``config``, ``last_result``) are automatically
    serialised if passed as Python objects.

    Returns:
        Updated report dict, or ``None`` if not found.
    """
    report = session.get(ScheduledReport, report_id)
    if report is None:
        return None

    json_fields = {"recipients", "config", "last_result"}
    for key, value in kwargs.items():
        if not hasattr(report, key):
            continue
        if key in json_fields and not isinstance(value, str):
            value = json.dumps(value)
        setattr(report, key, value)

    session.commit()
    session.refresh(report)
    return _report_to_dict(report)


def delete_scheduled_report(session: Session, report_id: int) -> bool:
    """Delete a scheduled report by ID.

    Returns:
        ``True`` if deleted, ``False`` if not found.
    """
    report = session.get(ScheduledReport, report_id)
    if report is None:
        return False
    session.delete(report)
    session.commit()
    return True


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------

def run_report_now(session: Session, report_id: int) -> dict:
    """Manually trigger a scheduled report.

    Dispatches to the appropriate report-generation service based on
    ``report_type``, updates ``last_run_at`` and ``last_result``.

    Returns:
        Dict with ``report_id``, ``report_type``, ``status``, and the
        generated ``data``.  On failure ``status`` is ``"error"`` and
        ``error`` contains the message.
    """
    report = session.get(ScheduledReport, report_id)
    if report is None:
        return {"error": "Report not found", "status": "error"}

    config = _parse_json(report.config, {})
    now = datetime.now(timezone.utc)

    try:
        data = _dispatch_report(session, report.report_type, config)
        result = {"status": "success", "generated_at": now.isoformat()}
        report.last_run_at = now
        report.last_result = json.dumps(result)
        session.commit()
        return {
            "report_id": report.id,
            "report_type": report.report_type,
            "status": "success",
            "data": data,
        }
    except Exception as exc:
        logger.exception("Failed to run report %s (%s)", report.id, report.name)
        result = {"status": "error", "error": str(exc), "at": now.isoformat()}
        report.last_run_at = now
        report.last_result = json.dumps(result)
        session.commit()
        return {
            "report_id": report.id,
            "report_type": report.report_type,
            "status": "error",
            "error": str(exc),
        }


def _dispatch_report(session: Session, report_type: str, config: dict) -> dict:
    """Call the correct report service for the given type."""
    if report_type == "executive":
        from ion.services.executive_report_service import generate_executive_report
        return generate_executive_report(session, days=config.get("days", 7))

    if report_type == "soc_health":
        from ion.services.soc_health_service import get_soc_health_scorecard
        return get_soc_health_scorecard(session)

    if report_type == "shift_handover":
        from ion.services.shift_handover_service import generate_shift_report
        return generate_shift_report(session, hours=config.get("hours", 8))

    if report_type == "compliance":
        from ion.services.compliance_mapping_service import get_compliance_posture
        from ion.services.tide_service import get_tide_service
        return get_compliance_posture(get_tide_service())

    raise ValueError(f"Unknown report_type: {report_type}")


# ---------------------------------------------------------------------------
# Scheduler helpers
# ---------------------------------------------------------------------------

def get_due_reports(session: Session) -> list[dict]:
    """Return active scheduled reports that are currently due.

    A report is "due" when enough time has passed since its last run
    (or it has never run):

    * **daily** — last run was before today's scheduled time.
    * **weekly** — last run was more than ~7 days ago *and* today
      matches the configured day of week.
    * **monthly** — last run was more than ~28 days ago *and* today
      matches the configured day of month.
    """
    now = datetime.now(timezone.utc)
    today = now.date()

    rows = session.execute(
        select(ScheduledReport).where(ScheduledReport.is_active == True)  # noqa: E712
    ).scalars().all()

    due = []
    for report in rows:
        if _is_due(report, now, today):
            due.append(_report_to_dict(report))

    return due


def _is_due(report: ScheduledReport, now: datetime, today) -> bool:
    """Determine whether a single report is currently due."""
    # Parse the target time for today
    try:
        hh, mm = (report.time_utc or "08:00").split(":")
        target_time = now.replace(hour=int(hh), minute=int(mm), second=0, microsecond=0)
    except (ValueError, AttributeError):
        target_time = now.replace(hour=8, minute=0, second=0, microsecond=0)

    # Must be past the target time
    if now < target_time:
        return False

    # Never run — always due (as long as day/schedule matches)
    never_run = report.last_run_at is None

    if report.schedule == "daily":
        if never_run:
            return True
        last = report.last_run_at
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        return last.date() < today

    if report.schedule == "weekly":
        if today.weekday() != (report.day_of_week or 0):
            return False
        if never_run:
            return True
        last = report.last_run_at
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        return (now - last) >= timedelta(days=6)

    if report.schedule == "monthly":
        if today.day != (report.day_of_month or 1):
            return False
        if never_run:
            return True
        last = report.last_run_at
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        return (now - last) >= timedelta(days=25)

    return False
