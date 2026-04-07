"""Analyze playbook execution effectiveness."""

from __future__ import annotations

import logging
from typing import Optional

from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

# Graceful model imports — the schema may not be fully migrated yet.
try:
    from ion.models.playbook import Playbook, PlaybookExecution, PlaybookStep
except ImportError:
    Playbook = None  # type: ignore[assignment,misc]
    PlaybookExecution = None  # type: ignore[assignment,misc]
    PlaybookStep = None  # type: ignore[assignment,misc]


def _empty_result() -> dict:
    """Return the analytics dict when no data is available."""
    return {
        "total_playbooks": 0,
        "active_playbooks": 0,
        "total_executions": 0,
        "playbooks": [],
        "never_executed": [],
        "most_used": None,
        "fastest": None,
    }


def get_playbook_analytics(session: Session) -> dict:
    """Compute per-playbook execution statistics.

    Args:
        session: An active SQLAlchemy session.

    Returns:
        A dict containing aggregate and per-playbook metrics including
        completion rates, average durations, and lists of unused playbooks.
    """

    if Playbook is None or PlaybookExecution is None:
        logger.warning("Playbook models not available — returning empty analytics")
        return _empty_result()

    try:
        playbooks = session.query(Playbook).order_by(Playbook.name).all()
    except Exception:
        logger.exception("Failed to query playbooks")
        return _empty_result()

    total_playbooks: int = len(playbooks)
    active_playbooks: int = sum(1 for p in playbooks if p.is_active)

    all_executions: list = []
    try:
        all_executions = session.query(PlaybookExecution).all()
    except Exception:
        logger.exception("Failed to query playbook executions")

    total_executions: int = len(all_executions)

    # Build lookup: playbook_id -> list of executions
    exec_by_pb: dict[int, list] = {}
    for ex in all_executions:
        exec_by_pb.setdefault(ex.playbook_id, []).append(ex)

    playbook_stats: list[dict] = []
    never_executed: list[dict] = []
    most_used_name: Optional[str] = None
    most_used_count: int = 0
    fastest_name: Optional[str] = None
    fastest_avg: Optional[float] = None

    for pb in playbooks:
        execs = exec_by_pb.get(pb.id, [])
        exec_count = len(execs)

        if exec_count == 0:
            never_executed.append({"id": pb.id, "name": pb.name})
            playbook_stats.append({
                "id": pb.id,
                "name": pb.name,
                "execution_count": 0,
                "completion_rate": 0.0,
                "avg_duration_hours": None,
                "last_executed": None,
            })
            continue

        # Completion rate
        completed = sum(1 for e in execs if e.status == "completed")
        completion_rate = round((completed / exec_count) * 100, 1)

        # Average duration (only for executions with both timestamps)
        durations: list[float] = []
        for e in execs:
            if e.started_at and e.completed_at:
                delta = (e.completed_at - e.started_at).total_seconds()
                if delta >= 0:
                    durations.append(delta / 3600.0)
        avg_duration: Optional[float] = (
            round(sum(durations) / len(durations), 2) if durations else None
        )

        # Last executed
        latest = max(
            (e.started_at for e in execs if e.started_at),
            default=None,
        )

        playbook_stats.append({
            "id": pb.id,
            "name": pb.name,
            "execution_count": exec_count,
            "completion_rate": completion_rate,
            "avg_duration_hours": avg_duration,
            "last_executed": latest.isoformat() if latest else None,
        })

        # Track most used
        if exec_count > most_used_count:
            most_used_count = exec_count
            most_used_name = pb.name

        # Track fastest (only if we have duration data)
        if avg_duration is not None:
            if fastest_avg is None or avg_duration < fastest_avg:
                fastest_avg = avg_duration
                fastest_name = pb.name

    return {
        "total_playbooks": total_playbooks,
        "active_playbooks": active_playbooks,
        "total_executions": total_executions,
        "playbooks": playbook_stats,
        "never_executed": never_executed,
        "most_used": most_used_name,
        "fastest": fastest_name,
    }
