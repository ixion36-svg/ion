"""Adaptive lab grading service (v0.23.0).

Evaluates rubric criteria against the ``audit_logs`` table for a lab
session, persists per-criterion results, and rolls up to a session score.

Design pivot
------------
Learner actions during a lab go to the regular audit surfaces (alert read,
case update, observable create) without a lab back-reference. This service
back-correlates by materialised row id: ``lab_session_fixtures`` knows
which alert_triage/alert_cases/observables rows belong to a session, so a
criterion of the form "viewed alert X" matches an ``audit_logs`` row where
``action = 'alert_view'`` AND ``resource_id`` is one of the session's
materialised alert_triage ids AND the audit row's ``timestamp`` lies
inside the session window.

Criterion kinds
---------------
``viewed_alert`` (v0.23.0) — config: ``{}``. Awards full points the
first time any audit row with action='alert_view' lands on any of the
session's materialised alert_triage rows.

``linked_to_case`` (v0.24.0) — config: ``{"min_alerts": int = 2}``.
Awards full points the first time at least ``min_alerts`` of the
session's materialised alert_triage rows are observed as linked to the
SAME case via the ``alert_linked`` audit event. The audit event was
introduced in v0.24.0 at the two case-link write sites in
``ion.web.api`` (case-create loop and PUT triage); its ``details``
column carries the target ``case_id`` as JSON, which the evaluator
groups by to ensure the alerts converge on a single case rather than
being scattered across multiple.

``observable_created`` (v0.25.0) — config:
``{"min_count": int = 1, "types": Optional[list[str]] = None}``.
Awards full points the first time at least ``min_count`` audit rows
with ``action='observable_linked'`` exist for the session user during
the session window. If ``types`` is supplied, only rows whose
``details["observable_type"]`` is in the list count toward the total.
The ``observable_linked`` audit event is emitted by ION's two extract
endpoints (``/observables/extract-from-alert/{id}`` and
``/observables/extract-from-case/{id}``) since v0.25.0, one row per
new ObservableLink created. Unlike ``viewed_alert`` /
``linked_to_case``, this evaluator does NOT scope by session fixtures
— the L1 M5 lab grades "did the learner create any observables during
the session window", not "did they create observables tied to a
specific alert".

``case_closed_with_reason`` (v0.25.0) — config:
``{"required_reasons": list[str], "min_count": int = 1}``.
Awards full points the first time at least ``min_count`` audit rows
with ``action='case_closed'`` exist for the session user during the
session window, where the row's ``details["closure_reason"]`` is in
``required_reasons``. The ``case_closed`` audit event is emitted by
``ion.web.api.update_case`` since v0.25.0 on OPEN→CLOSED transitions.
``required_reasons`` values must be lowercase ``CaseClosureReason``
enum values (e.g. ``"true_positive"``).

Future kinds: ``regex_in_analyst_notes``, ``mitre_technique_tagged``.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Optional

from sqlalchemy import text
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


# ── Criterion evaluators ─────────────────────────────────────────────────


def _materialised_ids_for_session(
    session: Session, *, session_id: int, target_table: str
) -> list[int]:
    """Return the materialised_row_ids of a session's fixtures in a given target table."""
    rows = session.execute(
        text(
            "SELECT materialised_row_id FROM lab_session_fixtures "
            "WHERE session_id = :sid AND materialised_table = :tbl"
        ),
        {"sid": session_id, "tbl": target_table},
    ).fetchall()
    return [int(r[0]) for r in rows]


def _evaluate_viewed_alert(
    session: Session,
    *,
    session_id: int,
    user_id: int,
    started_at,
    config: dict[str, Any],
) -> tuple[bool, Optional[int]]:
    """Return (matched, audit_log_id_of_match).

    Match if any audit_logs row exists with:
        action='alert_view'
        resource_type='alert_triage'
        resource_id IN (session's materialised alert_triage ids)
        user_id = the session owner
        timestamp >= session.started_at
    """
    triage_ids = _materialised_ids_for_session(
        session, session_id=session_id, target_table="alert_triage"
    )
    if not triage_ids:
        return False, None

    placeholders = ", ".join(f":id_{i}" for i in range(len(triage_ids)))
    params = {
        "uid": user_id,
        "since": started_at,
    }
    for i, tid in enumerate(triage_ids):
        params[f"id_{i}"] = tid

    row = session.execute(
        text(
            "SELECT id FROM audit_logs "
            "WHERE action = 'alert_view' "
            "  AND resource_type = 'alert_triage' "
            f"  AND resource_id IN ({placeholders}) "
            "  AND user_id = :uid "
            "  AND timestamp >= :since "
            "ORDER BY id ASC LIMIT 1"
        ),
        params,
    ).fetchone()
    if row is None:
        return False, None
    return True, int(row[0])


def _evaluate_linked_to_case(
    session: Session,
    *,
    session_id: int,
    user_id: int,
    started_at,
    config: dict[str, Any],
) -> tuple[bool, Optional[int]]:
    """Return (matched, audit_log_id_of_earliest_matching_row).

    Match when ``min_alerts`` (default 2) of the session's materialised
    alert_triage rows are linked to the same case during the session
    window. The audit rows we read here are emitted by ION's two
    case-link write sites (case-create loop and PUT triage) since
    v0.24.0; each row's ``details`` column carries the target ``case_id``
    as JSON so we can group by it and require convergence on one case
    rather than crediting the learner for scattering alerts.
    """
    min_alerts = int(config.get("min_alerts", 2))

    triage_ids = _materialised_ids_for_session(
        session, session_id=session_id, target_table="alert_triage"
    )
    if len(triage_ids) < min_alerts:
        return False, None

    placeholders = ", ".join(f":id_{i}" for i in range(len(triage_ids)))
    params = {
        "uid": user_id,
        "since": started_at,
    }
    for i, tid in enumerate(triage_ids):
        params[f"id_{i}"] = tid

    rows = session.execute(
        text(
            "SELECT id, resource_id, details FROM audit_logs "
            "WHERE action = 'alert_linked' "
            "  AND resource_type = 'alert_triage' "
            f"  AND resource_id IN ({placeholders}) "
            "  AND user_id = :uid "
            "  AND timestamp >= :since "
            "ORDER BY id ASC"
        ),
        params,
    ).fetchall()
    if not rows:
        return False, None

    # Group by the target case_id parsed out of details JSON. The first
    # case_id that accumulates ``min_alerts`` distinct materialised
    # alert_triage ids wins, and the matched audit_log id is the earliest
    # row that contributed to that group.
    per_case_alerts: dict[int, set[int]] = {}
    per_case_earliest_audit: dict[int, int] = {}
    for audit_id, resource_id, details_raw in rows:
        if details_raw is None:
            continue
        try:
            details = (
                details_raw
                if isinstance(details_raw, dict)
                else json.loads(details_raw)
            )
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        case_id = details.get("case_id")
        if case_id is None:
            continue
        try:
            case_id = int(case_id)
        except (TypeError, ValueError):
            continue
        bucket = per_case_alerts.setdefault(case_id, set())
        bucket.add(int(resource_id))
        per_case_earliest_audit.setdefault(case_id, int(audit_id))
        if len(bucket) >= min_alerts:
            return True, per_case_earliest_audit[case_id]

    return False, None


def _evaluate_observable_created(
    session: Session,
    *,
    session_id: int,  # noqa: ARG001 — kept for signature parity
    user_id: int,
    started_at,
    config: dict[str, Any],
) -> tuple[bool, Optional[int]]:
    """Return (matched, audit_log_id_of_earliest_qualifying_row).

    Match when at least ``min_count`` (default 1) audit rows with
    ``action='observable_linked'`` exist for ``user_id`` during the
    session window. If ``types`` is configured, only rows whose
    ``details["observable_type"]`` is in the list count.

    See module docstring for full semantics.
    """
    min_count = int(config.get("min_count", 1))
    types_filter = config.get("types")
    if types_filter is not None:
        # Coerce to a normalised string set for membership checks.
        types_filter = {str(t) for t in types_filter}

    rows = session.execute(
        text(
            "SELECT id, details FROM audit_logs "
            "WHERE action = 'observable_linked' "
            "  AND user_id = :uid "
            "  AND timestamp >= :since "
            "ORDER BY id ASC"
        ),
        {"uid": user_id, "since": started_at},
    ).fetchall()
    if not rows:
        return False, None

    qualifying = 0
    earliest_audit_id: Optional[int] = None
    for audit_id, details_raw in rows:
        if types_filter is not None:
            # Parse details JSON and check the observable_type field.
            if details_raw is None:
                continue
            try:
                details = (
                    details_raw
                    if isinstance(details_raw, dict)
                    else json.loads(details_raw)
                )
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
            if str(details.get("observable_type", "")) not in types_filter:
                continue
        qualifying += 1
        if earliest_audit_id is None:
            earliest_audit_id = int(audit_id)
        if qualifying >= min_count:
            return True, earliest_audit_id
    return False, None


def _evaluate_case_closed_with_reason(
    session: Session,
    *,
    session_id: int,  # noqa: ARG001 — kept for signature parity
    user_id: int,
    started_at,
    config: dict[str, Any],
) -> tuple[bool, Optional[int]]:
    """Return (matched, audit_log_id_of_earliest_qualifying_row).

    Match when at least ``min_count`` (default 1) audit rows with
    ``action='case_closed'`` exist for ``user_id`` during the session
    window, where ``details["closure_reason"]`` is in
    ``required_reasons``.

    ``required_reasons`` must be specified (a rubric author who wanted
    to match any close would set min_count and an exhaustive reasons
    list). If absent or empty, the evaluator never matches — defensive
    choice rather than implicitly accepting all closures.
    """
    required_reasons = config.get("required_reasons") or []
    required_set = {str(r) for r in required_reasons}
    if not required_set:
        return False, None
    min_count = int(config.get("min_count", 1))

    rows = session.execute(
        text(
            "SELECT id, details FROM audit_logs "
            "WHERE action = 'case_closed' "
            "  AND user_id = :uid "
            "  AND timestamp >= :since "
            "ORDER BY id ASC"
        ),
        {"uid": user_id, "since": started_at},
    ).fetchall()
    if not rows:
        return False, None

    qualifying = 0
    earliest_audit_id: Optional[int] = None
    for audit_id, details_raw in rows:
        if details_raw is None:
            continue
        try:
            details = (
                details_raw
                if isinstance(details_raw, dict)
                else json.loads(details_raw)
            )
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        reason = details.get("closure_reason")
        if reason is None or str(reason) not in required_set:
            continue
        qualifying += 1
        if earliest_audit_id is None:
            earliest_audit_id = int(audit_id)
        if qualifying >= min_count:
            return True, earliest_audit_id
    return False, None


# Registry: criterion_kind → evaluator callable
# Each evaluator returns (matched: bool, matched_audit_log_id: Optional[int]).
_EVALUATORS = {
    "viewed_alert": _evaluate_viewed_alert,
    "linked_to_case": _evaluate_linked_to_case,
    "observable_created": _evaluate_observable_created,
    "case_closed_with_reason": _evaluate_case_closed_with_reason,
}


# ── Public API ───────────────────────────────────────────────────────────


def grade_session(session: Session, *, session_id: int) -> dict[str, Any]:
    """Evaluate all rubric criteria for a session and persist results.

    Returns a summary dict::

        {
            "session_id": int,
            "score": int | None,          # 0-100 percent, NULL if no rubric
            "points_earned": int,
            "points_max": int,
            "criteria": [
                {"rubric_id": int, "kind": str, "matched": bool,
                 "points_earned": int, "points_max": int}
            ],
        }

    Idempotent: re-grading the same session updates existing
    lab_criterion_results rows in place (one row per (session, rubric))
    rather than appending.
    """
    sess_row = session.execute(
        text(
            "SELECT enrollment_id, lesson_id, started_at FROM lab_sessions "
            "WHERE id = :sid"
        ),
        {"sid": session_id},
    ).fetchone()
    if sess_row is None:
        raise ValueError(f"Lab session {session_id} not found")
    enrollment_id, lesson_id, started_at = sess_row[0], sess_row[1], sess_row[2]

    # Resolve user_id from enrollment (audit_logs is keyed by user_id, not enrollment).
    user_row = session.execute(
        text("SELECT user_id FROM course_enrolments WHERE id = :eid"),
        {"eid": enrollment_id},
    ).fetchone()
    if user_row is None:
        raise ValueError(f"Enrollment {enrollment_id} not found")
    user_id = int(user_row[0])

    rubric_rows = session.execute(
        text(
            "SELECT id, criterion_kind, criterion_config, points "
            "FROM lab_rubrics WHERE lesson_id = :lid "
            "ORDER BY sort_order, id"
        ),
        {"lid": lesson_id},
    ).fetchall()

    points_earned_total = 0
    points_max_total = 0
    criteria_summary: list[dict[str, Any]] = []

    for rubric_id, kind, cfg_raw, points in rubric_rows:
        points_max_total += int(points)
        cfg: dict[str, Any] = (
            cfg_raw if isinstance(cfg_raw, dict) else json.loads(cfg_raw or "{}")
        )
        evaluator = _EVALUATORS.get(kind)
        if evaluator is None:
            logger.warning(
                "grade_session: unknown criterion_kind '%s' on rubric %d — skipping",
                kind, rubric_id,
            )
            matched, audit_id = False, None
            notes = f"unknown criterion_kind '{kind}'"
        else:
            try:
                matched, audit_id = evaluator(
                    session,
                    session_id=session_id,
                    user_id=user_id,
                    started_at=started_at,
                    config=cfg,
                )
                notes = None
            except Exception as exc:  # pragma: no cover — defensive
                logger.exception("grade_session: evaluator '%s' raised", kind)
                matched, audit_id = False, None
                notes = f"evaluator error: {exc}"

        criterion_earned = int(points) if matched else 0
        points_earned_total += criterion_earned

        # Upsert by (session_id, rubric_id) — unique constraint enforces shape.
        existing = session.execute(
            text(
                "SELECT id FROM lab_criterion_results "
                "WHERE session_id = :sid AND rubric_id = :rid"
            ),
            {"sid": session_id, "rid": rubric_id},
        ).fetchone()
        if existing is None:
            session.execute(
                text(
                    "INSERT INTO lab_criterion_results "
                    "(session_id, rubric_id, points_earned, points_max, "
                    " matched, matched_audit_log_id, notes) "
                    "VALUES (:sid, :rid, :pe, :pm, :matched, :aud, :notes)"
                ),
                {
                    "sid": session_id, "rid": rubric_id,
                    "pe": criterion_earned, "pm": int(points),
                    "matched": matched, "aud": audit_id, "notes": notes,
                },
            )
        else:
            session.execute(
                text(
                    "UPDATE lab_criterion_results SET "
                    "  points_earned = :pe, points_max = :pm, "
                    "  matched = :matched, matched_audit_log_id = :aud, "
                    "  notes = :notes, evaluated_at = CURRENT_TIMESTAMP "
                    "WHERE id = :id"
                ),
                {
                    "pe": criterion_earned, "pm": int(points),
                    "matched": matched, "aud": audit_id, "notes": notes,
                    "id": existing[0],
                },
            )

        criteria_summary.append({
            "rubric_id": int(rubric_id),
            "kind": kind,
            "matched": matched,
            "points_earned": criterion_earned,
            "points_max": int(points),
        })

    if points_max_total > 0:
        score = round(100 * points_earned_total / points_max_total)
    else:
        score = None

    return {
        "session_id": session_id,
        "score": score,
        "points_earned": points_earned_total,
        "points_max": points_max_total,
        "criteria": criteria_summary,
    }
