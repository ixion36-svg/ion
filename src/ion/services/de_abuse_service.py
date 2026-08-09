"""DE abuse monitor — roadmap §4 control #7 (the detective control).

Controls 1–6 are *preventive*: separation of duties, no-silencing, scope caps,
mandatory expiry, full audit, and no silent model drift. They stop a single actor
abusing the DE module. They do NOT catch two-person **collusion** (SoD only
requires the second signer to differ, not to be independent), sustained
high-volume gaming, or a technically-valid-but-over-broad "blanket" quirk.

This module adds the missing detective layer: a strictly **read-only** scan over
the DE domain tables (`system_quirks`, `bob_tuning_proposals`) — which already
carry raiser/verifier and drafter/approver attribution on each row — that surfaces:

  * ``collusion_pair``   — the same (raiser→verifier) or (drafter→approver) pair
                           recurring above a threshold inside the window;
  * ``high_volume_actor``— a user whose raise/verify/approve count is unusually high;
  * ``broad_scope_quirk``— an active quirk whose scope is broad enough to act like a
                           blanket suppression of a rule family.

It mutates nothing and writes no audit rows — it only reports. Output is meant for
an oversight reviewer (``de:verify``), who decides what, if anything, to do.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from ion.models.bob_tuning_proposal import BobTuningProposal, BobTuningProposalStatus
from ion.models.system_quirk import SystemQuirk, SystemQuirkStatus


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _scope_size(q: SystemQuirk) -> Dict[str, int]:
    rules = len(q.scope_rules or [])
    total = (
        rules
        + len(q.scope_hosts or [])
        + len(q.scope_users or [])
        + len(q.scope_ips or [])
        + len(q.scope_observables or [])
    )
    return {"rules": rules, "total": total}


def scan_abuse(
    session: Session,
    days: int = 90,
    *,
    min_pair_count: int = 3,
    high_pair_count: int = 6,
    max_actions_per_user: int = 25,
    max_scope_breadth: int = 25,
    max_scope_rules: int = 10,
) -> Dict[str, Any]:
    """Read-only scan for DE abuse patterns. Returns a report dict; mutates nothing.

    Thresholds are parameters so an operator can tune sensitivity per deployment.
    """
    since = _now() - timedelta(days=days)
    signals: List[Dict[str, Any]] = []

    # ── load the window (read-only) ──────────────────────────────────────────
    quirks = list(session.execute(select(SystemQuirk)).scalars().all())
    bob = list(session.execute(select(BobTuningProposal)).scalars().all())

    # ── collusion pairs ──────────────────────────────────────────────────────
    # A pair is (actor_a, actor_b) unordered; we key on the two distinct signers
    # of the same artifact. Quirk: raiser→verifier (verified in window). Bob:
    # drafter→approver (decided in window).
    def _pair_key(a: int, b: int) -> tuple:
        return (a, b) if a <= b else (b, a)

    quirk_pairs: Counter = Counter()
    for q in quirks:
        if (
            q.raised_by_id is not None
            and q.verified_by_id is not None
            and q.raised_by_id != q.verified_by_id
            and q.verified_at is not None
            and q.verified_at >= since
        ):
            quirk_pairs[_pair_key(q.raised_by_id, q.verified_by_id)] += 1

    bob_pairs: Counter = Counter()
    for p in bob:
        if (
            p.created_by_id is not None
            and p.decided_by_id is not None
            and p.created_by_id != p.decided_by_id
            and p.status in (BobTuningProposalStatus.APPROVED, BobTuningProposalStatus.REVERTED)
            and p.decided_at is not None
            and p.decided_at >= since
        ):
            bob_pairs[_pair_key(p.created_by_id, p.decided_by_id)] += 1

    for domain, pairs in (("quirk", quirk_pairs), ("bob", bob_pairs)):
        for (a, b), count in sorted(pairs.items(), key=lambda kv: -kv[1]):
            if count >= min_pair_count:
                signals.append({
                    "type": "collusion_pair",
                    "domain": domain,
                    "actor_a_id": a,
                    "actor_b_id": b,
                    "count": count,
                    "severity": "high" if count >= high_pair_count else "medium",
                    "description": (
                        f"users {a} and {b} co-signed {count} {domain} decisions in "
                        f"{days}d — separation of duties is satisfied but the same pair "
                        f"recurs; check for collusion / rubber-stamping"
                    ),
                })

    # ── high-volume actors ───────────────────────────────────────────────────
    volume: Dict[tuple, int] = defaultdict(int)
    for q in quirks:
        if q.created_at is not None and q.created_at >= since and q.raised_by_id is not None:
            volume[(q.raised_by_id, "raise")] += 1
        if q.verified_at is not None and q.verified_at >= since and q.verified_by_id is not None:
            volume[(q.verified_by_id, "verify")] += 1
    for p in bob:
        if (
            p.decided_at is not None and p.decided_at >= since
            and p.decided_by_id is not None
            and p.status in (BobTuningProposalStatus.APPROVED, BobTuningProposalStatus.REVERTED)
        ):
            volume[(p.decided_by_id, "approve")] += 1

    for (user_id, action), count in sorted(volume.items(), key=lambda kv: -kv[1]):
        if count > max_actions_per_user:
            signals.append({
                "type": "high_volume_actor",
                "user_id": user_id,
                "action": action,
                "count": count,
                "severity": "medium",
                "description": (
                    f"user {user_id} performed {count} '{action}' actions in {days}d "
                    f"(> {max_actions_per_user}) — unusual volume, review for gaming"
                ),
            })

    # ── broad-scope (blanket) quirks ─────────────────────────────────────────
    now = _now()
    for q in quirks:
        if q.status != SystemQuirkStatus.ACTIVE:
            continue
        if q.review_date is not None and q.review_date <= now:  # lapsed → inert
            continue
        size = _scope_size(q)
        if size["rules"] > max_scope_rules or size["total"] > max_scope_breadth:
            signals.append({
                "type": "broad_scope_quirk",
                "quirk_id": q.id,
                "title": q.title,
                "rule_count": size["rules"],
                "scope_total": size["total"],
                "severity": "high" if size["rules"] > 2 * max_scope_rules else "medium",
                "description": (
                    f"active quirk #{q.id} scopes {size['rules']} rules / {size['total']} "
                    f"entities — broad enough to blanket a rule family; confirm it isn't "
                    f"masking real detections"
                ),
            })

    by_sev: Counter = Counter(s["severity"] for s in signals)
    return {
        "window_days": days,
        "generated_at": _now().isoformat(),
        "thresholds": {
            "min_pair_count": min_pair_count,
            "high_pair_count": high_pair_count,
            "max_actions_per_user": max_actions_per_user,
            "max_scope_breadth": max_scope_breadth,
            "max_scope_rules": max_scope_rules,
        },
        "signals": signals,
        "summary": {
            "total": len(signals),
            "by_severity": {"high": by_sev.get("high", 0),
                            "medium": by_sev.get("medium", 0),
                            "low": by_sev.get("low", 0)},
        },
    }
