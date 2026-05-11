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

Criterion kinds (v0.23.0)
-------------------------
``viewed_alert`` — config: ``{}``. Awards full points the first time any
audit row with action='alert_view' lands on any of the session's
materialised alert_triage rows.

The kind registry below is deliberately extensible: v0.24.0 adds
linked_to_case, observable_created, case_closed_with_reason, etc.
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


# Registry: criterion_kind → evaluator callable
# Each evaluator returns (matched: bool, matched_audit_log_id: Optional[int]).
_EVALUATORS = {
    "viewed_alert": _evaluate_viewed_alert,
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
