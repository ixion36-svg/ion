"""Tuning-request lifecycle + GitLab ticket mirroring.

The DB row is authoritative; the GitLab issue is a best-effort mirror so the
detection team can work from their own tracker. Every mirror call is wrapped —
GitLab being down/unconfigured never blocks an analyst's request or a DE's
decision, it just leaves ``gitlab_issue_iid`` empty (retryable by re-mirroring
later if ever needed).

Status flow: open → triaged → linked (proposal drafted) → closed.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from ion.models.tuning_request import (
    TUNING_REQUEST_REASONS,
    TuningRequest,
)
from ion.models.user import AuditLog

logger = logging.getLogger(__name__)

_REASON_LABELS = {
    "false_positive": "False positive",
    "noisy": "Too noisy",
    "threshold": "Threshold wrong",
    "duplicate": "Duplicate detection",
    "other": "Other",
}


def _collect_evidence(session, rule_name: str) -> Dict[str, Any]:
    """FP-closure counts for the rule (7d/30d) — snapshot by value at submit
    time so the ticket stays meaningful after the noise moves."""
    try:
        from ion.services.de_metrics_service import fp_alerts_for_rule

        now = datetime.now(timezone.utc).replace(tzinfo=None)
        return {
            "fp_alerts_7d": fp_alerts_for_rule(session, rule_name, now - timedelta(days=7), now),
            "fp_alerts_30d": fp_alerts_for_rule(session, rule_name, now - timedelta(days=30), now),
            "collected_at": now.isoformat(),
        }
    except Exception as exc:  # noqa: BLE001
        logger.debug("tuning request: evidence collection failed: %s", exc)
        return {}


def _issue_markdown(req: TuningRequest, requested_by: str) -> str:
    ev = req.evidence_json or {}
    from ion.core.config import get_config

    base = get_config().base_url.rstrip("/")
    lines = [
        f"## Tuning request — `{req.rule_name}`",
        "",
        f"- **Reason:** {_REASON_LABELS.get(req.reason, req.reason)}",
        f"- **Requested by:** {requested_by} (via ION)",
        f"- **ION request:** {base}/de (Tuning Requests queue, TR-{req.id})",
    ]
    if req.rule_id:
        lines.append(f"- **Rule id:** `{req.rule_id}`")
    if ev.get("fp_alerts_7d") is not None:
        lines.append(
            f"- **FP/benign closures:** {ev.get('fp_alerts_7d')} in 7d · "
            f"{ev.get('fp_alerts_30d')} in 30d"
        )
    if req.example_alert_ids:
        ids = ", ".join(f"`{a}`" for a in req.example_alert_ids[:5])
        lines.append(f"- **Example alerts:** {ids}")
    if req.details:
        lines += ["", "### Analyst's description", "", req.details]
    lines += [
        "",
        "---",
        "_Raised from ION alert triage. Decisions land back on this issue "
        "when the linked detection proposal is decided._",
    ]
    return "\n".join(lines)


async def _mirror_create(req: TuningRequest, requested_by: str) -> None:
    """Best-effort GitLab issue creation; mutates req in place on success."""
    try:
        from ion.services.gitlab_service import get_gitlab_service

        svc = get_gitlab_service()
        if not svc.is_configured:
            return
        issue = await svc.create_issue(
            title=f"[tuning] {req.rule_name}"[:250],
            description=_issue_markdown(req, requested_by),
            labels=["ion", "tuning-request", req.reason],
        )
        req.gitlab_issue_iid = getattr(issue, "iid", None)
        req.gitlab_issue_url = getattr(issue, "web_url", None)
    except Exception as exc:  # noqa: BLE001
        logger.warning("tuning request %s: GitLab mirror failed: %s", req.id, exc)


async def _mirror_comment(req: TuningRequest, body: str, close: bool = False) -> None:
    """Best-effort comment (and optional close) on the mirrored issue."""
    if not req.gitlab_issue_iid:
        return
    try:
        from ion.services.gitlab_service import get_gitlab_service

        svc = get_gitlab_service()
        if not svc.is_configured:
            return
        await svc.add_issue_comment(req.gitlab_issue_iid, body)
        if close:
            await svc.close_issue(req.gitlab_issue_iid)
    except Exception as exc:  # noqa: BLE001
        logger.warning("tuning request %s: GitLab comment failed: %s", req.id, exc)


async def create_request(
    session,
    user,
    *,
    rule_name: str,
    rule_id: Optional[str] = None,
    reason: str = "other",
    details: Optional[str] = None,
    example_alert_ids: Optional[List[str]] = None,
) -> TuningRequest:
    if reason not in TUNING_REQUEST_REASONS:
        raise ValueError(f"Invalid reason {reason!r}")
    req = TuningRequest(
        rule_name=rule_name.strip()[:512],
        rule_id=(rule_id or "").strip()[:256] or None,
        reason=reason,
        details=(details or "").strip() or None,
        example_alert_ids=[str(a) for a in (example_alert_ids or [])[:5]],
        evidence_json=_collect_evidence(session, rule_name),
        status="open",
        requested_by_id=user.id,
    )
    session.add(req)
    session.flush()
    session.add(AuditLog(
        user_id=user.id, action="tuning_request_created",
        resource_type="tuning_request", resource_id=req.id,
        details=f"{req.rule_name} — {reason}",
    ))
    session.commit()

    await _mirror_create(req, requested_by=user.username)
    if req.gitlab_issue_iid:
        session.commit()
    return req


async def triage_request(session, user, req: TuningRequest) -> TuningRequest:
    if req.status not in ("open",):
        raise ValueError(f"Cannot triage a {req.status} request")
    req.status = "triaged"
    req.triaged_by_id = user.id
    session.add(AuditLog(
        user_id=user.id, action="tuning_request_triaged",
        resource_type="tuning_request", resource_id=req.id, details=req.rule_name,
    ))
    session.commit()
    await _mirror_comment(req, f"Triaged by {user.username} (ION).")
    return req


async def link_proposal(session, user, req: TuningRequest, proposal_id: int) -> TuningRequest:
    if req.status == "closed":
        raise ValueError("Cannot link a proposal to a closed request")
    req.status = "linked"
    req.proposal_id = proposal_id
    if req.triaged_by_id is None:
        req.triaged_by_id = user.id
    session.add(AuditLog(
        user_id=user.id, action="tuning_request_linked",
        resource_type="tuning_request", resource_id=req.id,
        details=f"{req.rule_name} → proposal {proposal_id}",
    ))
    session.commit()
    await _mirror_comment(
        req, f"Detection proposal DP-{proposal_id:04d} drafted from this request by {user.username} (ION)."
    )
    return req


async def close_request(session, user, req: TuningRequest, resolution: str) -> TuningRequest:
    if req.status == "closed":
        raise ValueError("Request is already closed")
    req.status = "closed"
    req.resolution = (resolution or "").strip() or None
    session.add(AuditLog(
        user_id=user.id, action="tuning_request_closed",
        resource_type="tuning_request", resource_id=req.id,
        details=f"{req.rule_name} — {req.resolution or 'no resolution text'}",
    ))
    session.commit()
    await _mirror_comment(
        req,
        f"Closed by {user.username} (ION): {req.resolution or 'no resolution text'}",
        close=True,
    )
    return req
