"""Service-desk service — bug reports → GitLab, CAB change requests, and the
CHANGELOG delta used to auto-populate a version-upgrade change request.

GitLab creation is always best-effort: the local record is committed first, and
a GitLab failure (unconfigured / unreachable) is recorded on the row rather than
raising, so the workflow never depends on GitLab being up.
"""

from __future__ import annotations

import logging
import re
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from ion.models.service_desk import (
    BugReport,
    BugReportStatus,
    ChangeRequest,
    ChangeRequestStatus,
)

logger = logging.getLogger(__name__)


def _ion_version() -> str:
    try:
        import ion
        return ion.__version__
    except Exception:  # noqa: BLE001
        return "unknown"


def _now() -> datetime:
    # Naive UTC to match the TimestampMixin columns (DateTime without tz).
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ── CHANGELOG parsing ────────────────────────────────────────────────────────
_CHANGELOG_HEADING = re.compile(r"^##\s+v?(\d+\.\d+\.\d+)\b.*$")


def _find_changelog() -> Optional[str]:
    """Locate CHANGELOG.md (repo root in dev, CWD in container). Returns text or None."""
    candidates = [
        Path(__file__).resolve().parents[3] / "CHANGELOG.md",  # src/ion/services → repo root
        Path.cwd() / "CHANGELOG.md",
        Path("/app/CHANGELOG.md"),
    ]
    for p in candidates:
        try:
            if p.is_file():
                return p.read_text(encoding="utf-8")
        except Exception:  # noqa: BLE001
            continue
    return None


def _version_tuple(v: str) -> Optional[Tuple[int, ...]]:
    try:
        return tuple(int(x) for x in str(v).strip().lstrip("v").split(".")[:3])
    except (TypeError, ValueError):
        return None


def _parse_changelog_sections(text: str) -> List[Tuple[str, str]]:
    """Split a changelog into [(version, section_markdown), …] in file order."""
    sections: List[Tuple[str, str]] = []
    cur_ver: Optional[str] = None
    cur_lines: List[str] = []
    for line in text.splitlines():
        m = _CHANGELOG_HEADING.match(line.strip())
        if m:
            if cur_ver is not None:
                sections.append((cur_ver, "\n".join(cur_lines).strip()))
            cur_ver = m.group(1)
            cur_lines = [line]
        elif cur_ver is not None:
            cur_lines.append(line)
    if cur_ver is not None:
        sections.append((cur_ver, "\n".join(cur_lines).strip()))
    return sections


def changelog_between(current: Optional[str], target: Optional[str], text: Optional[str] = None) -> str:
    """Return the concatenated CHANGELOG sections for versions in
    (current, target] — i.e. everything the upgrade introduces. Best-effort:
    returns '' when the changelog can't be found/parsed, and falls back to the
    target's own section when version math doesn't line up.
    """
    if text is None:
        text = _find_changelog()
    if not text:
        return ""
    sections = _parse_changelog_sections(text)
    if not sections:
        return ""
    ct, tt = _version_tuple(current or ""), _version_tuple(target or "")
    picked: List[str] = []
    if ct and tt:
        for ver, body in sections:
            vt = _version_tuple(ver)
            if vt and ct < vt <= tt:
                picked.append(body)
    if not picked:
        # Fall back to the target's own section if present.
        for ver, body in sections:
            if target and _version_tuple(ver) == tt:
                picked.append(body)
                break
    return "\n\n".join(picked).strip()


# ── references ───────────────────────────────────────────────────────────────
def next_cr_reference(session: Session) -> str:
    last = session.query(ChangeRequest).order_by(ChangeRequest.id.desc()).first()
    n = 1 if not last else last.id + 1
    return f"CR-{n:04d}"


# ── GitLab issue bodies ──────────────────────────────────────────────────────
def bug_issue_body(br: BugReport, reporter: Optional[str]) -> str:
    parts = [
        f"**Reported by:** {reporter or 'unknown'}",
        f"**Severity:** {br.severity}",
        f"**Component:** {br.component or '—'}",
        f"**ION version:** {br.ion_version or '—'}",
        f"**Page:** {br.page_url or '—'}",
        "",
        "### Description",
        br.description or "—",
    ]
    if br.steps_to_reproduce:
        parts += ["", "### Steps to reproduce", br.steps_to_reproduce]
    parts += ["", "_Filed from the ION portal bug-report form._"]
    return "\n".join(parts)


def cab_markdown(cr: ChangeRequest) -> str:
    """The full CAB submission view — also used as the linked GitLab issue body."""
    def _sec(label: str, val: Optional[str]) -> str:
        return f"### {label}\n{val.strip() if val else '—'}"

    window = "—"
    if cr.scheduled_start or cr.scheduled_end:
        window = f"{cr.scheduled_start or '?'} → {cr.scheduled_end or '?'}"
    lines = [
        f"# Change Request {cr.reference} — {cr.title}",
        "",
        f"- **Type:** {cr.change_type}",
        f"- **Version:** {cr.current_version or '—'} → {cr.target_version or '—'}",
        f"- **Risk:** {cr.risk_level}",
        f"- **Status:** {cr.status}",
        f"- **Planned change date:** {cr.planned_date.isoformat() if cr.planned_date else '—'}",
        f"- **Maintenance window:** {window}",
        f"- **Requested by:** {cr.requested_by.username if cr.requested_by else '—'}",
        "",
        _sec("Justification", cr.justification),
        "",
        _sec("What is changing (from CHANGELOG)", cr.changes),
        "",
        _sec("Impact", cr.impact),
        "",
        _sec("Affected systems", cr.affected_systems),
        "",
        _sec("Implementation plan", cr.implementation_plan),
        "",
        _sec("Backout / rollback plan", cr.backout_plan),
        "",
        _sec("Test / validation plan", cr.test_plan),
    ]
    return "\n".join(lines)


def default_backout_plan(current: Optional[str]) -> str:
    return (
        f"Roll back by redeploying the previous ION image tag "
        f"(`ixion36/ion:{current or 'PREVIOUS'}`): set `ION_VERSION={current or 'PREVIOUS'}` "
        f"and `docker compose up -d`. The database schema is additive across this "
        f"upgrade (new tables/columns only), so the prior image runs against the "
        f"current database without migration. Verify login + dashboard load post-rollback."
    )


# ── bug reports ──────────────────────────────────────────────────────────────
async def create_bug_report(session: Session, user_id: Optional[int], data: Dict[str, Any]) -> BugReport:
    br = BugReport(
        title=(data.get("title") or "").strip()[:300],
        description=(data.get("description") or "").strip(),
        steps_to_reproduce=(data.get("steps_to_reproduce") or "").strip() or None,
        component=(data.get("component") or "").strip()[:120] or None,
        severity=(data.get("severity") or "medium"),
        ion_version=_ion_version(),
        page_url=(data.get("page_url") or "").strip()[:500] or None,
        status=BugReportStatus.OPEN,
        reported_by_id=user_id,
    )
    session.add(br)
    session.commit()
    session.refresh(br)

    # Best-effort GitLab issue.
    try:
        from ion.services.gitlab_service import get_gitlab_service
        gl = get_gitlab_service()
        if gl.is_configured:
            reporter = br.reported_by.username if br.reported_by else None
            issue = await gl.create_issue(
                title=f"[ION Bug] {br.title}",
                description=bug_issue_body(br, reporter),
                labels=["bug", "ion-portal"],
            )
            br.gitlab_issue_iid = issue.iid
            br.gitlab_issue_url = issue.web_url
            br.gitlab_state = issue.state
            br.gitlab_synced_at = _now()
            br.gitlab_error = None
        else:
            br.gitlab_error = "GitLab not configured"
    except Exception as exc:  # noqa: BLE001
        logger.warning("bug-report: GitLab issue creation failed: %s", exc)
        br.gitlab_error = f"{type(exc).__name__}: {exc}"[:300]
    session.commit()
    session.refresh(br)
    return br


async def sync_bug_report(session: Session, br: BugReport) -> BugReport:
    """Pull the linked GitLab issue's state into the local record."""
    if not br.gitlab_issue_iid:
        return br
    try:
        from ion.services.gitlab_service import get_gitlab_service
        gl = get_gitlab_service()
        if not gl.is_configured:
            br.gitlab_error = "GitLab not configured"
            session.commit()
            return br
        issue = await gl.get_issue(br.gitlab_issue_iid)
        br.gitlab_state = issue.state
        br.gitlab_synced_at = _now()
        br.gitlab_error = None
        # Reflect GitLab state into the local status without clobbering a manual
        # IN_PROGRESS: closed → resolved; reopened → open.
        if issue.state == "closed" and br.status != BugReportStatus.CLOSED.value:
            br.status = BugReportStatus.RESOLVED
        elif issue.state == "opened" and br.status == BugReportStatus.RESOLVED.value:
            br.status = BugReportStatus.OPEN
    except Exception as exc:  # noqa: BLE001
        logger.warning("bug-report: GitLab sync failed: %s", exc)
        br.gitlab_error = f"{type(exc).__name__}: {exc}"[:300]
    session.commit()
    session.refresh(br)
    return br


# ── change requests ──────────────────────────────────────────────────────────
async def create_change_request(
    session: Session,
    user_id: Optional[int],
    data: Dict[str, Any],
    *,
    create_gitlab: bool = True,
) -> ChangeRequest:
    current = _ion_version()
    ctype = (data.get("change_type") or "ION version upgrade").strip()[:80]
    tv = (data.get("target_version") or "").strip()[:40] or None
    is_upgrade = ctype == "ION version upgrade"
    default_title = f"Upgrade ION to {tv or '?'}" if is_upgrade else ctype
    cr = ChangeRequest(
        reference=next_cr_reference(session),
        title=(data.get("title") or "").strip()[:300] or default_title,
        change_type=ctype,
        current_version=current,
        target_version=tv,
        justification=(data.get("justification") or "").strip() or None,
        changes=(data.get("changes") or "").strip() or None,
        risk_level=(data.get("risk_level") or "medium"),
        impact=(data.get("impact") or "").strip() or None,
        affected_systems=(data.get("affected_systems") or "").strip() or None,
        implementation_plan=(data.get("implementation_plan") or "").strip() or None,
        backout_plan=(data.get("backout_plan") or "").strip() or default_backout_plan(current),
        test_plan=(data.get("test_plan") or "").strip() or None,
        scheduled_start=_parse_dt(data.get("scheduled_start")),
        scheduled_end=_parse_dt(data.get("scheduled_end")),
        planned_date=_parse_date(data.get("planned_date")),
        status=ChangeRequestStatus.DRAFT,
        requested_by_id=user_id,
    )
    # Auto-fill the "what's changing" section from the changelog delta if blank
    # (only meaningful for an ION version upgrade).
    if is_upgrade and not cr.changes and cr.target_version:
        delta = changelog_between(current, cr.target_version)
        if delta:
            cr.changes = delta[:20000]
    session.add(cr)
    session.commit()
    session.refresh(cr)

    if create_gitlab:
        try:
            from ion.services.gitlab_service import get_gitlab_service
            gl = get_gitlab_service()
            if gl.is_configured:
                issue = await gl.create_issue(
                    title=f"[CAB] {cr.reference}: {cr.title}",
                    description=cab_markdown(cr),
                    labels=["change-request", "cab", "ion-upgrade"],
                )
                cr.gitlab_issue_iid = issue.iid
                cr.gitlab_issue_url = issue.web_url
                cr.gitlab_error = None
            else:
                cr.gitlab_error = "GitLab not configured"
        except Exception as exc:  # noqa: BLE001
            logger.warning("change-request: GitLab issue creation failed: %s", exc)
            cr.gitlab_error = f"{type(exc).__name__}: {exc}"[:300]
        session.commit()
        session.refresh(cr)
    return cr


def _parse_dt(val: Any) -> Optional[datetime]:
    if not val:
        return None
    try:
        s = str(val).replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        return dt.replace(tzinfo=None) if dt.tzinfo else dt
    except (TypeError, ValueError):
        return None


def _parse_date(val: Any) -> Optional[date]:
    """Parse a date-only string (``YYYY-MM-DD`` from an <input type="date">)."""
    if not val:
        return None
    try:
        return date.fromisoformat(str(val)[:10])
    except (TypeError, ValueError):
        return None


# action → (allowed_from_status_values, new_status)
_S = ChangeRequestStatus
_TRANSITIONS: Dict[str, Tuple[set, ChangeRequestStatus]] = {
    "submit": ({_S.DRAFT.value}, _S.SUBMITTED),
    "approve": ({_S.SUBMITTED.value}, _S.APPROVED),
    "reject": ({_S.SUBMITTED.value}, _S.REJECTED),
    "schedule": ({_S.APPROVED.value}, _S.SCHEDULED),
    "implement": ({_S.APPROVED.value, _S.SCHEDULED.value}, _S.IMPLEMENTED),
    "close": ({_S.IMPLEMENTED.value}, _S.CLOSED),
    "cancel": ({_S.DRAFT.value, _S.SUBMITTED.value, _S.APPROVED.value, _S.SCHEDULED.value}, _S.CANCELLED),
}

# Transitions that record a reviewer decision (who/when + notes).
_DECISION_ACTIONS = {"approve", "reject", "cancel"}


def transition_change_request(
    session: Session,
    cr: ChangeRequest,
    action: str,
    user_id: Optional[int],
    notes: Optional[str] = None,
    *,
    scheduled_start: Any = None,
    scheduled_end: Any = None,
) -> ChangeRequest:
    """Apply a status transition. Raises ValueError on an unknown action or an
    illegal source state (the API maps that to 409)."""
    spec = _TRANSITIONS.get(action)
    if not spec:
        raise ValueError(f"Unknown change-request action '{action}'")
    allowed_from, new_status = spec
    current = cr.status.value if isinstance(cr.status, ChangeRequestStatus) else str(cr.status)
    if current not in allowed_from:
        raise ValueError(f"Cannot '{action}' a change request in status '{current}'")

    cr.status = new_status
    if action in _DECISION_ACTIONS:
        cr.decided_by_id = user_id
        cr.decided_at = _now()
        if notes:
            cr.decision_notes = notes
    if action == "schedule":
        if scheduled_start is not None:
            cr.scheduled_start = _parse_dt(scheduled_start)
        if scheduled_end is not None:
            cr.scheduled_end = _parse_dt(scheduled_end)
    if action == "implement":
        cr.implemented_at = _now()
    session.commit()
    session.refresh(cr)
    return cr
