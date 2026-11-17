"""Server-side case listing: pagination, filtering and sorting (stage 5).

    "Add server pagination, compact list summaries and concurrent-edit
    conflict detection." — review 2026-10-08 §2

``GET /api/cases`` did this::

    cases = query.order_by(AlertCase.created_at.desc()).all()

Every case, with three relationships eager-loaded each, serialised in full,
on every page load — and the browser then filtered and sorted the whole set.
That is fine at fifty cases and a page that never loads at fifty thousand.
The failure mode is the worst kind: it degrades gradually with use, so it
breaks first for the SOCs that have used ION most.

Decisions worth keeping in view:

**``total`` is a COUNT over the same filters**, not the length of the page.
Without it a truncated list reports "showing 50 of 50" and nobody can tell
there are another twelve hundred behind it.

**Severity sorts by rank, not alphabetically.** A plain string sort gives
``critical, high, low, medium`` — ``low`` above ``medium``, which is wrong
in a way nobody notices until they are triaging by it. An unrecognised or
missing severity sorts *last*, so a typo cannot outrank ``critical``.

**Unknown sort fields and statuses are refused, not ignored.** Quietly
falling back to a different order or dropping a filter means the caller
believes it got what it asked for. It is also how an ORDER BY injection
would arrive, so the whitelist is the security boundary as well as the
usability one.

**Every sort carries ``id`` as a tiebreak.** Equal sort keys with no
tiebreak let the database return rows in any order per query, so paging
could repeat or skip rows — intermittently, which is the hardest kind of
bug to be told about.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

from sqlalchemy import String, case, cast, func, or_, select
from sqlalchemy.orm import Session

from ion.models.alert_triage import AlertCase, AlertCaseStatus, AlertTriage, Note, NoteEntityType

logger = logging.getLogger(__name__)


class CaseQueryError(Exception):
    """A case query was refused as malformed."""


#: Generous but finite. Unbounded is the defect being fixed; a default that
#: covers the common SOC's open-case count keeps the page feeling the same.
DEFAULT_LIMIT = 100

#: Hard ceiling, so one request cannot ask for the old behaviour back.
MAX_LIMIT = 500

#: Sortable columns. A whitelist rather than a passthrough: this value
#: reaches ORDER BY.
SORTABLE_FIELDS = (
    "created_at",
    "updated_at",
    "case_number",
    "severity",
    "status",
    "title",
    "last_activity",
)

#: Triage order, highest first. The string column sorts alphabetically,
#: which is not this.
_SEVERITY_RANK = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}

#: Below every known severity, so an unrecognised or NULL value sorts last
#: in descending order rather than above `critical`.
_UNRANKED = -1


def _severity_rank_expr():
    """A CASE expression mapping severity to its triage rank."""
    return case(
        {k: v for k, v in _SEVERITY_RANK.items()},
        value=func.lower(AlertCase.severity),
        else_=_UNRANKED,
    )


def _last_activity_expr():
    """The latest of the case row's own update, its newest note and its
    newest alert change.

    `updated_at` alone misses a note: adding one inserts into `notes` and
    leaves the case row untouched. Written as a CASE rather than GREATEST
    because SQLite's multi-argument max() is NULL when any argument is.
    """
    note_at = (
        select(func.max(Note.created_at))
        .where(Note.entity_type == NoteEntityType.CASE,
               Note.entity_id == cast(AlertCase.id, String))
        .correlate(AlertCase)
        .scalar_subquery()
    )
    alert_at = (
        select(func.max(AlertTriage.updated_at))
        .where(AlertTriage.case_id == AlertCase.id)
        .correlate(AlertCase)
        .scalar_subquery()
    )
    own = AlertCase.updated_at
    note = func.coalesce(note_at, own)
    alert = func.coalesce(alert_at, own)
    return case(
        ((note > own) & (note >= alert), note),
        (alert > own, alert),
        else_=own,
    )


def _valid_statuses() -> dict:
    """Accepted status values, upper-cased, mapped to the enum member."""
    out = {}
    for member in AlertCaseStatus:
        out[member.value.upper()] = member
        out[member.name.upper()] = member
    return out


def _escape_like(term: str) -> str:
    r"""Escape LIKE wildcards so a search term is matched literally.

    ``%`` and ``_`` are wildcards in LIKE. A user searching for ``svc_backup``
    means an underscore, not "any character", and a bare ``%`` must match
    nothing rather than everything. Backslash is escaped first or it would
    escape the escapes.
    """
    return (
        term.replace("\\", "\\\\")
        .replace("%", "\\%")
        .replace("_", "\\_")
    )


def _apply_filters(
    stmt,
    *,
    status: Optional[str],
    severity: Optional[str],
    assigned_to_id: Optional[int],
    unassigned: bool,
    q: Optional[str],
    active_since: Optional[datetime] = None,
):
    """Add the WHERE clauses. Shared by the page and the count."""
    if status:
        statuses = _valid_statuses()
        key = str(status).strip().upper()
        if key not in statuses:
            raise CaseQueryError(
                f"unknown status '{status}'; expected one of "
                + ", ".join(sorted({m.value for m in AlertCaseStatus}))
            )
        stmt = stmt.where(AlertCase.status == statuses[key])

    if severity:
        stmt = stmt.where(
            func.lower(AlertCase.severity) == str(severity).strip().lower()
        )

    if unassigned and assigned_to_id is not None:
        raise CaseQueryError(
            "unassigned and assigned_to_id cannot both be set; they cannot "
            "both hold, and preferring one would hide the mistake"
        )
    if unassigned:
        stmt = stmt.where(AlertCase.assigned_to_id.is_(None))
    elif assigned_to_id is not None:
        stmt = stmt.where(AlertCase.assigned_to_id == assigned_to_id)

    if q and str(q).strip():
        term = f"%{_escape_like(str(q).strip())}%"
        stmt = stmt.where(
            or_(
                AlertCase.title.ilike(term, escape="\\"),
                AlertCase.case_number.ilike(term, escape="\\"),
            )
        )

    if active_since is not None:
        stmt = stmt.where(_last_activity_expr() >= active_since)

    return stmt


def _order_by(sort: str, order: str):
    """ORDER BY terms, always ending with a deterministic tiebreak."""
    if sort not in SORTABLE_FIELDS:
        raise CaseQueryError(
            f"cannot sort by '{sort}'; expected one of "
            + ", ".join(SORTABLE_FIELDS)
        )
    direction = str(order).strip().lower()
    if direction not in ("asc", "desc"):
        raise CaseQueryError(
            f"unknown order '{order}'; expected 'asc' or 'desc'"
        )

    if sort == "severity":
        primary = _severity_rank_expr()
    elif sort == "last_activity":
        primary = _last_activity_expr()
    else:
        primary = getattr(AlertCase, sort)

    primary = primary.desc() if direction == "desc" else primary.asc()
    # The tiebreak follows the requested direction so a reversed sort is the
    # exact reverse, and ties cannot drift between pages.
    tiebreak = AlertCase.id.desc() if direction == "desc" else AlertCase.id.asc()
    if sort == "last_activity":
        # A queue: closed cases sink below live ones whatever their activity.
        return [(AlertCase.status == AlertCaseStatus.CLOSED).asc(), primary, tiebreak]
    return [primary, tiebreak]


def _summary(row) -> dict:
    """A compact list row.

    Deliberately excludes ``description``, ``evidence_summary`` and
    ``closure_notes``: a list of 500 cases that shipped every narrative
    field would transfer megabytes to render a table. The detail endpoint
    serves those.
    """
    case_row, assignee_name, alert_count, last_activity = row
    status = case_row.status
    return {
        "id": case_row.id,
        "case_number": case_row.case_number,
        "title": case_row.title,
        "status": status.value if hasattr(status, "value") else status,
        "severity": case_row.severity,
        "created_at": (
            case_row.created_at.isoformat() if case_row.created_at else None
        ),
        "updated_at": (
            case_row.updated_at.isoformat() if case_row.updated_at else None
        ),
        "closed_at": case_row.closed_at.isoformat() if case_row.closed_at else None,
        "last_activity_at": last_activity.isoformat() if last_activity else None,
        # A 50-character enum value, not a narrative field. The alerts page
        # badges a closed case with it (TP, FP, BTP ...) and had keyed that
        # badge on a field this row never carried, so it never rendered.
        "closure_reason": case_row.closure_reason,
        "assigned_to_id": case_row.assigned_to_id,
        "assigned_to": assignee_name,
        "alert_count": int(alert_count or 0),
        "kibana_case_id": case_row.kibana_case_id,
        "dfir_iris_case_id": case_row.dfir_iris_case_id,
    }


def list_cases_page(
    session: Session,
    *,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    assigned_to_id: Optional[int] = None,
    unassigned: bool = False,
    q: Optional[str] = None,
    active_since: Optional[datetime] = None,
    sort: str = "created_at",
    order: str = "desc",
    limit: int = DEFAULT_LIMIT,
    offset: int = 0,
) -> dict:
    """One page of cases, with the true count of matching rows.

    Args:
        session: Database session.
        status: Case status to filter on. Refused if unknown.
        severity: Severity to filter on, case-insensitive.
        assigned_to_id: Restrict to one assignee.
        unassigned: Restrict to cases with no assignee. Mutually exclusive
            with ``assigned_to_id``.
        q: Substring match on title or case number. Wildcards are literal.
        active_since: Only cases whose last activity (see
            ``_last_activity_expr``) is at or after this naive-UTC instant.
        sort: One of :data:`SORTABLE_FIELDS`.
        order: ``asc`` or ``desc``.
        limit: Page size, capped at :data:`MAX_LIMIT`.
        offset: Rows to skip.

    Returns:
        ``{"cases", "total", "limit", "offset", "returned", "has_more",
        "sort", "order"}``

    Raises:
        CaseQueryError: On a malformed filter, sort or window.
    """
    try:
        limit = int(limit)
        offset = int(offset)
    except (TypeError, ValueError) as exc:
        raise CaseQueryError("limit and offset must be integers") from exc

    if limit <= 0:
        raise CaseQueryError("limit must be a positive number of rows")
    if offset < 0:
        raise CaseQueryError("offset cannot be negative")
    limit = min(limit, MAX_LIMIT)

    from ion.models.user import User

    filters = dict(
        status=status, severity=severity, assigned_to_id=assigned_to_id,
        unassigned=unassigned, q=q, active_since=active_since,
    )

    # The count runs over the same filters, so "showing 50 of 1,284 matching"
    # is accurate rather than a count of everything.
    total = session.execute(
        _apply_filters(select(func.count(AlertCase.id)), **filters)
    ).scalar() or 0

    # alert_count as a correlated scalar rather than loading triage_entries:
    # the old code eager-loaded every alert on every case to call len() on
    # them, which is the single biggest cost in the old endpoint.
    alert_count = (
        select(func.count(AlertTriage.id))
        .where(AlertTriage.case_id == AlertCase.id)
        .correlate(AlertCase)
        .scalar_subquery()
    )

    stmt = (
        select(AlertCase, User.username, alert_count, _last_activity_expr())
        .outerjoin(User, AlertCase.assigned_to_id == User.id)
    )
    stmt = _apply_filters(stmt, **filters)
    stmt = stmt.order_by(*_order_by(sort, order)).limit(limit).offset(offset)

    rows = session.execute(stmt).all()
    cases = [_summary(r) for r in rows]

    return {
        "cases": cases,
        "total": int(total),
        "limit": limit,
        "offset": offset,
        "returned": len(cases),
        "has_more": offset + len(cases) < int(total),
        "sort": sort,
        "order": str(order).strip().lower(),
    }


def case_facets(session: Session) -> dict:
    """Counts for the filter bar, without fetching any rows.

    The page used to derive these by counting the full client-side array,
    which only worked because the full array was being shipped. They are
    aggregate queries now.
    """
    by_status: dict[str, int] = {}
    for status, count in session.execute(
        select(AlertCase.status, func.count(AlertCase.id)).group_by(AlertCase.status)
    ).all():
        key = status.value if hasattr(status, "value") else str(status)
        by_status[key] = int(count)

    by_severity: dict[str, int] = {}
    for severity, count in session.execute(
        select(AlertCase.severity, func.count(AlertCase.id))
        .group_by(AlertCase.severity)
    ).all():
        by_severity[severity or "unknown"] = int(count)

    unassigned = session.execute(
        select(func.count(AlertCase.id)).where(AlertCase.assigned_to_id.is_(None))
    ).scalar() or 0

    total = session.execute(select(func.count(AlertCase.id))).scalar() or 0

    return {
        "total": int(total),
        "by_status": by_status,
        "by_severity": by_severity,
        "unassigned": int(unassigned),
        "sortable_fields": list(SORTABLE_FIELDS),
        "max_limit": MAX_LIMIT,
        "default_limit": DEFAULT_LIMIT,
    }


def inbox_counts(session: Session, *, user_id: Optional[int],
                 active_since: datetime) -> dict:
    """The case inbox's chip counts, in one pass over the table.

    Each is a count of every case the chip would show on its own, not of
    the current page. ``mine`` is None when there is no user id to own
    anything, rather than a zero that reads as "you own nothing".
    """
    def total(condition):
        return func.coalesce(func.sum(case((condition, 1), else_=0)), 0)

    row = session.execute(select(
        total(_last_activity_expr() >= active_since),
        total(AlertCase.assigned_to_id == user_id) if user_id is not None else func.count(AlertCase.id),
        total(AlertCase.assigned_to_id.is_(None)),
        total(func.lower(AlertCase.severity) == "critical"),
        total(AlertCase.status == AlertCaseStatus.CLOSED),
    )).one()
    changed, mine, unassigned, critical, closed = (int(v or 0) for v in row)
    return {
        "changed": changed,
        "mine": mine if user_id is not None else None,
        "unassigned": unassigned,
        "critical": critical,
        "closed": closed,
    }


def case_activity(session: Session, case_ids: list[int]) -> dict[int, dict]:
    """For each case: its first affected host, its newest note and its
    newest alert change, as the inbox's one-line "latest activity" reads
    them.

    Batched for a page of ids so a list of fifty is three queries, not a
    hundred and fifty. The two "newest" reads are window functions so only
    one row per case leaves the database.
    """
    from ion.models.user import User

    if not case_ids:
        return {}
    out: dict[int, dict] = {
        cid: {"host": None, "note": None, "alert": None} for cid in case_ids
    }
    for cid, hosts in session.execute(
        select(AlertCase.id, AlertCase.affected_hosts).where(AlertCase.id.in_(case_ids))
    ).all():
        first = next((h for h in hosts if isinstance(h, str) and h), None) if isinstance(hosts, list) else None
        out[cid]["host"] = first

    keys = [str(cid) for cid in case_ids]
    rank = func.row_number().over(partition_by=Note.entity_id,
                                  order_by=(Note.created_at.desc(), Note.id.desc())).label("rank")
    notes = (
        select(Note.entity_id, Note.content, Note.created_at, User.username, rank)
        .outerjoin(User, Note.user_id == User.id)
        .where(Note.entity_type == NoteEntityType.CASE, Note.entity_id.in_(keys))
        .subquery()
    )
    for entity_id, content, at, username, _ in session.execute(
        select(notes).where(notes.c.rank == 1)
    ).all():
        cid = int(entity_id)
        out[cid]["note"] = {"at": at.isoformat() if at else None, "user": username, "content": content}

    rank = func.row_number().over(partition_by=AlertTriage.case_id,
                                  order_by=(AlertTriage.updated_at.desc(), AlertTriage.id.desc())).label("rank")
    alerts = (
        select(AlertTriage.case_id, AlertTriage.rule_name, AlertTriage.status,
               AlertTriage.created_at, AlertTriage.updated_at, rank)
        .where(AlertTriage.case_id.in_(case_ids))
        .subquery()
    )
    for cid, rule, status, created, updated, _ in session.execute(
        select(alerts).where(alerts.c.rank == 1)
    ).all():
        out[cid]["alert"] = {
            "at": updated.isoformat() if updated else None,
            "linked": created is not None and updated is not None and (updated - created).total_seconds() < 60,
            "rule": rule,
            "status": status.value if hasattr(status, "value") else status,
        }
    return out


__all__ = [
    "CaseQueryError",
    "DEFAULT_LIMIT",
    "MAX_LIMIT",
    "SORTABLE_FIELDS",
    "list_cases_page",
    "case_facets",
    "inbox_counts",
    "case_activity",
]
