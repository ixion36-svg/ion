"""Daily-work activity reader.

Builds the hybrid timeline for the daily-work feature by unioning:
  - MANUAL entries (``WorkLogEntry`` rows the analyst logged), and
  - AUTO events DERIVED at read time from existing ION tables — case
    opens/closes (``AlertCase``), Bob/analyst investigations
    (``Investigation``), and a curated slice of the ``AuditLog`` (labs/training).

Nothing here writes auto events to a table; they are computed per request, so
the timeline always reflects current data and we don't duplicate state.

Each timeline item is a plain dict:
    {"time": "14:32", "ts": <datetime>, "type": <slug>, "text": <str>,
     "source": "auto"|"logged", "ref": <optional id str>}

Every source is wrapped in try/except so one failing source degrades that
slice rather than breaking the page.
"""

from __future__ import annotations

import logging
from datetime import date, datetime, time
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from ion.models.alert_triage import AlertCase
from ion.models.investigation import Investigation
from ion.models.user import AuditLog, User
from ion.models.worklog import WorkLogEntry, WorkTaskType, seed_default_task_types

logger = logging.getLogger(__name__)

# AuditLog actions worth surfacing on a work timeline (auth noise excluded).
_AUDIT_WORK_ACTIONS = {
    "lab_launch": ("training", "Started a lab"),
    "lab_complete": ("training", "Completed a lab"),
    "worklog_entry_created": (None, None),  # already captured as a manual entry
}


def _day_bounds(day: date) -> tuple[datetime, datetime]:
    """Naive [start, end) datetimes for a calendar day."""
    start = datetime.combine(day, time.min)
    end = datetime.combine(day, time.max)
    return start, end


def _hm(ts: Optional[datetime]) -> str:
    return ts.strftime("%H:%M") if ts else "--:--"


def _in_day(ts: Optional[datetime], start: datetime, end: datetime) -> bool:
    if ts is None:
        return False
    # Compare on naive wall-clock; tz-aware values (Investigation) are reduced
    # to naive by dropping tzinfo so the comparison doesn't raise.
    if ts.tzinfo is not None:
        ts = ts.replace(tzinfo=None)
    return start <= ts <= end


def get_task_types(session: Session) -> List[Dict[str, Any]]:
    """Active task types for the quick-add chips, seeding defaults if empty."""
    seed_default_task_types(session)
    rows = (
        session.query(WorkTaskType)
        .filter(WorkTaskType.is_active.is_(True))
        .order_by(WorkTaskType.sort_order, WorkTaskType.label)
        .all()
    )
    return [t.to_dict() for t in rows]


def _manual_items(session: Session, user_id: int, start, end) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    try:
        rows = (
            session.query(WorkLogEntry)
            .filter(WorkLogEntry.user_id == user_id)
            .filter(WorkLogEntry.logged_at >= start, WorkLogEntry.logged_at <= end)
            .all()
        )
        for r in rows:
            out.append({
                "time": _hm(r.logged_at), "ts": r.logged_at, "type": r.task_type,
                "text": r.text, "source": "logged", "ref": None,
            })
    except Exception as e:  # noqa: BLE001
        logger.warning("worklog manual source failed: %s", e)
    return out


def _case_items(session: Session, user_id: int, start, end) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    try:
        opened = (
            session.query(AlertCase)
            .filter(AlertCase.created_by_id == user_id)
            .filter(AlertCase.created_at >= start, AlertCase.created_at <= end)
            .all()
        )
        for c in opened:
            label = getattr(c, "title", None) or f"case #{c.id}"
            out.append({"time": _hm(c.created_at), "ts": c.created_at, "type": "triaged",
                        "text": f"Opened {label}", "source": "auto", "ref": str(c.id)})
        closed = (
            session.query(AlertCase)
            .filter(AlertCase.closed_by_id == user_id)
            .filter(AlertCase.closed_at.isnot(None))
            .filter(AlertCase.closed_at >= start, AlertCase.closed_at <= end)
            .all()
        )
        for c in closed:
            label = getattr(c, "title", None) or f"case #{c.id}"
            reason = getattr(c, "closure_reason", None)
            suffix = f" as {str(reason).replace('_', ' ')}" if reason else ""
            out.append({"time": _hm(c.closed_at), "ts": c.closed_at, "type": "closed",
                        "text": f"Closed {label}{suffix}", "source": "auto", "ref": str(c.id)})
    except Exception as e:  # noqa: BLE001
        logger.warning("worklog case source failed: %s", e)
    return out


def _investigation_items(session: Session, user_id: int, start, end) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    try:
        rows = (
            session.query(Investigation)
            .filter(Investigation.created_by == user_id)
            .filter(Investigation.created_at >= start, Investigation.created_at <= end)
            .all()
        )
        for inv in rows:
            verdict = getattr(inv, "verdict", None)
            txt = "Ran an investigation" + (f" — verdict: {verdict}" if verdict else "")
            out.append({"time": _hm(inv.created_at), "ts": inv.created_at, "type": "playbook",
                        "text": txt, "source": "auto", "ref": str(getattr(inv, "id", "") or "")})
    except Exception as e:  # noqa: BLE001
        logger.warning("worklog investigation source failed: %s", e)
    return out


def _audit_items(session: Session, user_id: int, start, end) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    try:
        rows = (
            session.query(AuditLog)
            .filter(AuditLog.user_id == user_id)
            .filter(AuditLog.timestamp >= start, AuditLog.timestamp <= end)
            .filter(AuditLog.action.in_([a for a, (t, _) in _AUDIT_WORK_ACTIONS.items() if t]))
            .all()
        )
        for r in rows:
            mapped = _AUDIT_WORK_ACTIONS.get(r.action)
            if not mapped or not mapped[0]:
                continue
            typ, label = mapped
            out.append({"time": _hm(r.timestamp), "ts": r.timestamp, "type": typ,
                        "text": r.details or label, "source": "auto", "ref": None})
    except Exception as e:  # noqa: BLE001
        logger.warning("worklog audit source failed: %s", e)
    return out


def get_day_activity(session: Session, user_id: int, day: date) -> Dict[str, Any]:
    """Full hybrid timeline + derived summary for one user on one day."""
    start, end = _day_bounds(day)
    items: List[Dict[str, Any]] = []
    items += _manual_items(session, user_id, start, end)
    items += _case_items(session, user_id, start, end)
    items += _investigation_items(session, user_id, start, end)
    items += _audit_items(session, user_id, start, end)

    items.sort(key=lambda x: x["ts"] or start, reverse=True)

    # Derived summary (no time-tracking — "active span" is first→last activity).
    closed = sum(1 for i in items if i["type"] == "closed")
    triaged = sum(1 for i in items if i["type"] == "triaged")
    logged = sum(1 for i in items if i["source"] == "logged")
    cases_touched = len({i["ref"] for i in items if i["type"] in ("triaged", "closed") and i["ref"]})
    span = ""
    ts_list = [i["ts"].replace(tzinfo=None) if i["ts"] and i["ts"].tzinfo else i["ts"]
               for i in items if i["ts"]]
    if len(ts_list) >= 2:
        delta = max(ts_list) - min(ts_list)
        mins = int(delta.total_seconds() // 60)
        span = f"{mins // 60}h {mins % 60:02d}m"

    return {
        "date": day.isoformat(),
        "items": [{k: v for k, v in i.items() if k != "ts"} for i in items],
        "summary": {
            "active_span": span or "—",
            "triaged": triaged,
            "cases_touched": cases_touched,
            "closed": closed,
            "logged": logged,
            "total": len(items),
        },
    }


def add_entry(session: Session, user_id: int, task_type: str, text: str) -> WorkLogEntry:
    """Create a manual work-log entry. Caller commits."""
    entry = WorkLogEntry(user_id=user_id, task_type=task_type, text=text)
    session.add(entry)
    session.flush()
    return entry


def get_team_today(session: Session, day: date) -> List[Dict[str, Any]]:
    """Per-analyst snapshot for the Team Day board: today's counts, last-active,
    and current open case. Supportive framing (handover & balancing), so the
    caller decides which flags to surface."""
    start, end = _day_bounds(day)
    out: List[Dict[str, Any]] = []
    try:
        users = session.query(User).filter(User.is_active.is_(True)).all()
    except Exception as e:  # noqa: BLE001
        logger.warning("worklog team users query failed: %s", e)
        return out

    for u in users:
        day_act = get_day_activity(session, u.id, day)
        items = day_act["items"]
        if not items:
            continue  # only surface analysts with activity today
        # current open case assigned to them (most recent)
        now_text = None
        try:
            oc = (
                session.query(AlertCase)
                .filter(AlertCase.assigned_to_id == u.id)
                .filter(AlertCase.closed_at.is_(None))
                .order_by(AlertCase.updated_at.desc())
                .first()
            )
            if oc:
                now_text = getattr(oc, "title", None) or f"case #{oc.id}"
        except Exception:  # noqa: BLE001
            pass
        last = items[0]["time"] if items else "—"
        out.append({
            "user_id": u.id,
            "name": getattr(u, "display_name", None) or u.username,
            "initials": "".join(p[0] for p in (getattr(u, "display_name", None) or u.username).split()[:2]).upper(),
            "now": now_text,
            "counts": day_act["summary"],
            "last_active": last,
        })
    out.sort(key=lambda r: r["counts"]["total"], reverse=True)
    return out
