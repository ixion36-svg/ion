"""The knowledge review inbox (review 2026-10-08 §8, stage 4).

    "a common review inbox for expired assumptions, stale FP signatures,
    contradictory human outcomes and repeated uncertainty. Every explanation
    should have evidence, scope, an owner and a review lifecycle."

ION accumulated four kinds of decaying knowledge and surfaced none of them as
work:

``expired_quirk``
    A lapsed quirk stops annotating silently. Nobody is told that an
    explanation the SOC relied on has gone quiet.
``stale_fp_signature``
    An FP signature that is lapsed, ungoverned, unverified or nearly due.
    Detectable since the governance work; this is where it appears.
``contradictory_outcome``
    The same alert closed benign once and as a true positive another time.
    One of those two calls was wrong and nothing was looking.
``repeated_uncertainty``
    A prompt Bob keeps abstaining on is a prompt that needs changing, not a
    queue that needs draining.

Two rules the whole module obeys:

**Every rate carries its denominator, and a thin sample raises nothing.** A
100% abstention rate over two alerts is not a finding. The review names this
failure repeatedly in other modules, so an item is only raised above
:data:`MIN_UNCERTAINTY_SAMPLE`, and the thresholds are returned with the
payload so a reader can see what bar was applied.

**Every item names an owner and an action.** An inbox of observations nobody
owns becomes another dashboard. ``owner`` may be ``None`` — some knowledge
genuinely has no recorded author — but the field is always present and the
item still appears, because unowned decaying knowledge is a worse problem
than owned decaying knowledge, not a reason to hide it.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Sequence

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ion.models.ai_feedback import AIFeedback
from ion.models.system_quirk import SystemQuirk, SystemQuirkStatus
from ion.models.user import User
from ion.storage import investigation_memory_repository as fp_repo

logger = logging.getLogger(__name__)

#: The four kinds, in the order the inbox presents them. The order is the
#: priority: a lapsed quirk has already stopped working, whereas repeated
#: uncertainty is a trend.
REVIEW_KINDS = (
    "expired_quirk",
    "contradictory_outcome",
    "stale_fp_signature",
    "repeated_uncertainty",
)

_KIND_RANK = {kind: i for i, kind in enumerate(REVIEW_KINDS)}

#: Default lookback for the outcome-based checks.
DEFAULT_WINDOW_DAYS = 90

#: Minimum closures for a prompt before its abstention rate means anything.
MIN_UNCERTAINTY_SAMPLE = 10

#: Abstention rate at or above which a prompt is raised.
UNCERTAINTY_RATE = 0.4


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _usernames(session: Session, ids: Sequence[Optional[int]]) -> dict:
    """Resolve user ids to usernames in one query.

    One query rather than per-item lookups: the inbox is rendered on a page
    load and an N+1 over a long backlog is a slow page for no reason.
    """
    wanted = {i for i in ids if i}
    if not wanted:
        return {}
    rows = session.execute(
        select(User.id, User.username).where(User.id.in_(wanted))
    ).all()
    return {row[0]: row[1] for row in rows}


# ---------------------------------------------------------------------------
# Expired quirks
# ---------------------------------------------------------------------------

def _expired_quirks(session: Session, now: datetime) -> list[dict]:
    """Active quirks whose review date has passed.

    Only ``ACTIVE`` ones. A reverted quirk was deliberately withdrawn, and a
    pending one never took effect — neither has *stopped* doing something,
    which is what makes an expired quirk worth chasing.
    """
    rows = session.execute(
        select(SystemQuirk)
        .where(SystemQuirk.status == SystemQuirkStatus.ACTIVE)
        .order_by(SystemQuirk.review_date.asc())
    ).scalars().all()

    lapsed = []
    for quirk in rows:
        review = _aware(quirk.review_date)
        if review is None or review > now:
            continue
        lapsed.append((quirk, review))

    owners = _usernames(session, [q.raised_by_id for q, _ in lapsed])

    items = []
    for quirk, review in lapsed:
        days = int((now - review).total_seconds() // 86400)
        items.append(
            {
                "kind": "expired_quirk",
                "title": f"Quirk has lapsed: {quirk.title}",
                "why": (
                    f"The review date passed {days} day(s) ago, so this quirk "
                    "has stopped annotating alerts. The explanation it carried "
                    "is no longer reaching analysts."
                ),
                "action": (
                    "Re-verify it with a new review date if it is still true, "
                    "or revert it if the behaviour has gone away."
                ),
                "owner": owners.get(quirk.raised_by_id),
                "owner_id": quirk.raised_by_id,
                "evidence": {
                    "quirk_id": quirk.id,
                    "review_date": review.isoformat(),
                    "days_lapsed": days,
                    # The quirk's own fields: `annotation` is what
                    # analysts were being shown, `justification` is why.
                    "annotation": quirk.annotation,
                    "justification": quirk.justification,
                    "verified_by_id": quirk.verified_by_id,
                },
                "link": f"/de-quirks?quirk={quirk.id}",
                "_sort": (-days, quirk.id),
            }
        )
    return items


# ---------------------------------------------------------------------------
# Stale FP signatures
# ---------------------------------------------------------------------------

def _stale_fp_signatures(session: Session, now: datetime, limit: int) -> list[dict]:
    """FP signatures that need a decision, straight from the governance list."""
    rows = fp_repo.list_fps_needing_review(session, limit=limit, now=now)
    owners = _usernames(session, [r["recorded_by"] for r in rows])

    items = []
    for rank, fp in enumerate(rows):
        scope = fp.get("rule_id") or fp.get("rule_name") or fp.get("alert_signature")
        items.append(
            {
                "kind": "stale_fp_signature",
                "title": f"FP signature needs review: {scope or 'unscoped'}",
                "why": fp["reason_for_review"],
                "action": (
                    "Confirm the pattern is still benign and set a new review "
                    "date, or delete the signature."
                ),
                "owner": owners.get(fp["recorded_by"]),
                "owner_id": fp["recorded_by"],
                "evidence": {
                    "fp_id": fp["id"],
                    "governance_state": fp["governance_state"],
                    "review_category": fp["review_category"],
                    "review_date": fp["review_date"],
                    # How much this signature is actually hiding is the
                    # deciding fact for whether to keep it.
                    "hit_count": fp["hit_count"],
                    "last_matched_at": fp["last_matched_at"],
                    "reason": fp["reason"],
                    "scope": {
                        "rule_id": fp["rule_id"],
                        "rule_name": fp["rule_name"],
                        "alert_signature": fp["alert_signature"],
                        "host_pattern": fp["host_pattern"],
                        "user_pattern": fp["user_pattern"],
                    },
                },
                "link": f"/investigation-memory?fp={fp['id']}",
                # The governance list is already worst-first; keep that order.
                "_sort": (rank, fp["id"]),
            }
        )
    return items


# ---------------------------------------------------------------------------
# Contradictory human outcomes
# ---------------------------------------------------------------------------

def _contradictory_outcomes(
    session: Session, now: datetime, window_days: int
) -> list[dict]:
    """The same alert closed with two different human verdicts.

    Grouped on ``alert_id``, and rows without one are skipped: grouping on
    NULL would collapse every unrelated anonymous closure into a single
    bogus item.

    Two closures of the *same* alert disagreeing is a genuine conflict — one
    of the two calls was wrong. Two different alerts disagreeing is just two
    alerts.
    """
    since = now - timedelta(days=window_days)

    rows = session.execute(
        select(AIFeedback)
        .where(
            AIFeedback.alert_id.isnot(None),
            AIFeedback.created_at >= since.replace(tzinfo=None),
        )
        .order_by(AIFeedback.id.asc())
    ).scalars().all()

    grouped: dict[str, list[AIFeedback]] = {}
    for row in rows:
        grouped.setdefault(row.alert_id, []).append(row)

    conflicts = {
        alert_id: group
        for alert_id, group in grouped.items()
        if len({r.human_verdict for r in group if r.human_verdict}) > 1
    }

    owners = _usernames(
        session,
        [r.human_closed_by_id for group in conflicts.values() for r in group],
    )

    items = []
    for alert_id, group in conflicts.items():
        verdicts = sorted({r.human_verdict for r in group if r.human_verdict})
        closures = [
            {
                "feedback_id": r.id,
                "human_verdict": r.human_verdict,
                "closed_by": owners.get(r.human_closed_by_id),
                "closed_by_id": r.human_closed_by_id,
                "case_id": r.case_id,
                "closed_at": _aware(r.created_at).isoformat() if r.created_at else None,
                "delta_reason": r.delta_reason,
            }
            for r in group
        ]
        latest = max(
            (_aware(r.created_at) for r in group if r.created_at),
            default=now,
        )
        items.append(
            {
                "kind": "contradictory_outcome",
                "title": f"Alert {alert_id} was closed two different ways",
                "why": (
                    "Human closures disagree: "
                    + ", ".join(verdicts)
                    + ". One of these calls was wrong, and whichever it was, "
                      "the knowledge derived from it is wrong too."
                ),
                "action": (
                    "Decide which closure stands, correct the other, and check "
                    "whether an FP signature or quirk was created from the "
                    "wrong one."
                ),
                # Deliberately the latest closer: they made the call that is
                # currently standing, so the question lands with them.
                "owner": closures[-1]["closed_by"],
                "owner_id": closures[-1]["closed_by_id"],
                "evidence": {
                    "alert_id": alert_id,
                    "verdicts": verdicts,
                    "closure_count": len(closures),
                    "closures": closures,
                },
                "link": f"/alerts?alert={alert_id}",
                "_sort": (-latest.timestamp(), alert_id),
            }
        )
    return items


# ---------------------------------------------------------------------------
# Repeated uncertainty
# ---------------------------------------------------------------------------

def _repeated_uncertainty(
    session: Session, now: datetime, window_days: int
) -> list[dict]:
    """Prompts Bob keeps abstaining on.

    ``auto_escalated`` is the circuit breaker firing: Bob's confidence was
    below threshold, so no verdict was written and a human had to resolve it
    manually. A high rate of that for one prompt is a prompt problem.

    Rows with no template are skipped — there is no prompt to go and change,
    so there is no action to offer.

    Nothing is raised below :data:`MIN_UNCERTAINTY_SAMPLE` closures, however
    bad the ratio. A rate without a denominator is the error this review
    keeps naming, and 100% of two alerts is not a finding.
    """
    since = (now - timedelta(days=window_days)).replace(tzinfo=None)

    rows = session.execute(
        select(
            AIFeedback.alert_prompt_template_id,
            func.count(AIFeedback.id),
            func.sum(
                func.cast(AIFeedback.auto_escalated, func.count().type)
            ),
        )
        .where(
            AIFeedback.alert_prompt_template_id.isnot(None),
            AIFeedback.created_at >= since,
        )
        .group_by(AIFeedback.alert_prompt_template_id)
    ).all()

    items = []
    for template_id, total, abstentions in rows:
        total = int(total or 0)
        abstentions = int(abstentions or 0)
        if total < MIN_UNCERTAINTY_SAMPLE:
            continue
        rate = abstentions / total if total else 0.0
        if rate < UNCERTAINTY_RATE:
            continue

        items.append(
            {
                "kind": "repeated_uncertainty",
                "title": (
                    f"Prompt {template_id} abstained on "
                    f"{abstentions} of {total} alerts"
                ),
                "why": (
                    f"Bob's confidence fell below threshold on {rate:.0%} of "
                    f"the last {total} closures for this prompt, so a human "
                    "had to resolve each one manually. That is a prompt that "
                    "cannot answer the alerts it is being given."
                ),
                "action": (
                    "Review the prompt against the abstained samples and "
                    "propose a change, then replay the cohort before "
                    "approving it."
                ),
                # A prompt is owned by whoever maintains it, which ION does
                # not record on the template, so this is left unowned rather
                # than attributed to the last closer -- they did not write it.
                "owner": None,
                "owner_id": None,
                "evidence": {
                    "template_id": template_id,
                    "abstentions": abstentions,
                    "sample_size": total,
                    "abstention_rate": round(rate, 4),
                    "window_days": window_days,
                    "min_sample_size": MIN_UNCERTAINTY_SAMPLE,
                    "threshold_rate": UNCERTAINTY_RATE,
                },
                "link": f"/alert-prompts?template={template_id}",
                "_sort": (-rate, template_id),
            }
        )
    return items


# ---------------------------------------------------------------------------
# The inbox
# ---------------------------------------------------------------------------

def review_inbox(
    session: Session,
    kinds: Optional[Sequence[str]] = None,
    window_days: int = DEFAULT_WINDOW_DAYS,
    limit: int = 100,
    now: Optional[datetime] = None,
) -> dict:
    """Everything decaying that needs a human decision, worst first.

    Args:
        session: Database session.
        kinds: Restrict to these kinds. Defaults to all of
            :data:`REVIEW_KINDS`.
        window_days: Lookback for the outcome-based checks.
        limit: Cap on returned items. ``total`` stays the true count, so a
            capped inbox does not understate the backlog.
        now: Reference time, for tests.

    Returns:
        ``{"as_of", "items", "total", "by_kind", "thresholds", "window_days"}``
    """
    reference = now or _now()
    wanted = tuple(kinds) if kinds else REVIEW_KINDS
    unknown = [k for k in wanted if k not in REVIEW_KINDS]
    if unknown:
        raise ValueError(f"unknown review kind(s): {', '.join(unknown)}")

    items: list[dict] = []
    if "expired_quirk" in wanted:
        items += _expired_quirks(session, reference)
    if "stale_fp_signature" in wanted:
        items += _stale_fp_signatures(session, reference, limit=500)
    if "contradictory_outcome" in wanted:
        items += _contradictory_outcomes(session, reference, window_days)
    if "repeated_uncertainty" in wanted:
        items += _repeated_uncertainty(session, reference, window_days)

    # Kind first (the declared priority), then each kind's own ordering.
    items.sort(key=lambda i: (_KIND_RANK[i["kind"]], i["_sort"]))

    # Zero, not absent: a missing key reads as "not measured".
    by_kind = {kind: 0 for kind in REVIEW_KINDS}
    for item in items:
        by_kind[item["kind"]] += 1

    for item in items:
        item.pop("_sort", None)

    return {
        "as_of": reference.isoformat(),
        "window_days": window_days,
        "items": items[:limit],
        # The true backlog, not the page.
        "total": len(items),
        "by_kind": by_kind,
        "thresholds": {
            "min_sample_size": MIN_UNCERTAINTY_SAMPLE,
            "abstention_rate": UNCERTAINTY_RATE,
            "fp_review_warning_days": fp_repo.FP_REVIEW_WARNING_DAYS,
        },
    }


def review_summary(
    session: Session,
    window_days: int = DEFAULT_WINDOW_DAYS,
    now: Optional[datetime] = None,
) -> dict:
    """Counts only, for a dashboard tile. No item bodies."""
    inbox = review_inbox(session, window_days=window_days, limit=0, now=now)
    return {
        "as_of": inbox["as_of"],
        "window_days": window_days,
        "total": inbox["total"],
        "by_kind": inbox["by_kind"],
        "thresholds": inbox["thresholds"],
    }


__all__ = [
    "REVIEW_KINDS",
    "DEFAULT_WINDOW_DAYS",
    "MIN_UNCERTAINTY_SAMPLE",
    "UNCERTAINTY_RATE",
    "review_inbox",
    "review_summary",
]
