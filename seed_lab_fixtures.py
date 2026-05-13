"""Seed example lab_fixtures rows for the L1 Module-2 LAB lesson (v0.21.0).

Picks the lesson titled "LAB — Read your first alert in /alerts" from the L1
course (L1 Module 2, order 9) and inserts 3 fixture rows:

  1. An alert_triage row — mimics a Mimikatz lsass dump alert.
  2. An alert_triage row — mimics a base64-encoded PowerShell execution alert.
  3. An alert_cases row — a pre-built case linking the two alerts.

Run after seed_courses.py:

    python seed_courses.py
    python seed_lab_fixtures.py

Idempotent: re-running detects existing fixtures and skips them.
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

# Ensure src/ is on the path when running directly.
_SRC = Path(__file__).resolve().parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from sqlalchemy import text

from ion.storage.database import get_engine

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# The three fixture payloads to register.
# `target_table` must be in the allowed set in lab_fixture_service.py.
_FIXTURES = [
    {
        "fixture_kind": "alert",
        "target_table": "alert_triage",
        "payload": {
            "es_alert_id": "lab-fixture-mimikatz-001",
            # v0.30.0: SQLEnum(native_enum=False) stores the enum NAME
            # ('OPEN', uppercase) — same dialect-binding pattern that
            # bit v0.23.2's case-close test and Bug 3's SELECT. Materialisation
            # via raw SQL in lab_fixture_service._insert_row passes the
            # payload through unchanged, so the value MUST be the NAME.
            "status": "OPEN",
            "priority": "high",
            "source_system": "elastic",
            "rule_name": "Credential Dumping via LSASS Memory (Lab fixture)",
            "analyst_notes": "LAB FIXTURE — do not close outside training.",
            "mitre_techniques": json.dumps(["T1003.001"]),
            "created_at": "2026-01-01 00:00:00",
            "updated_at": "2026-01-01 00:00:00",
        },
    },
    {
        "fixture_kind": "alert",
        "target_table": "alert_triage",
        "payload": {
            "es_alert_id": "lab-fixture-powershell-encoded-001",
            "status": "OPEN",
            "priority": "medium",
            "source_system": "elastic",
            "rule_name": "Suspicious Base64-Encoded PowerShell (Lab fixture)",
            "analyst_notes": "LAB FIXTURE — do not close outside training.",
            "mitre_techniques": json.dumps(["T1059.001"]),
            "created_at": "2026-01-01 00:00:00",
            "updated_at": "2026-01-01 00:00:00",
        },
    },
    # v0.24.0: the L1 M2 lab now grades the learner on linking the two
    # seeded alerts into a single case via the linked_to_case rubric
    # criterion. The pre-seeded case description used to assert the
    # alerts were already linked to it (they weren't — neither alert
    # fixture's payload sets case_id) which was misleading. We keep the
    # case as a pre-seeded TARGET the learner can pick when linking,
    # rather than removing it (creating-from-scratch adds friction that
    # isn't the point of THIS lab). Description updated to reflect the
    # new task.
    {
        "fixture_kind": "alert_case",
        "target_table": "alert_cases",
        "payload": {
            "case_number": "LAB-CASE-0001",
            "title": "Lab fixture case — Credential access chain",
            "description": (
                "Auto-seeded for L1 Module 2 lab exercise. "
                "Link the two open alerts to this case as part of the lab task."
            ),
            "status": "OPEN",
            "severity": "high",
            "created_by_id": 1,
            "created_at": "2026-01-01 00:00:00",
            "updated_at": "2026-01-01 00:00:00",
        },
    },
]


def seed_lab_fixtures() -> None:
    engine = get_engine()
    with engine.connect() as conn:
        # Resolve the target lesson: L1 course, module order=2, lesson order=9.
        row = conn.execute(text("""
            SELECT l.id
            FROM lessons l
            JOIN course_modules m ON m.id = l.module_id
            JOIN courses c ON c.id = m.course_id
            WHERE c.level = 'L1'
              -- v0.30.0: SQLEnum(native_enum=False) stores the enum NAME
              -- ('LAB', uppercase), not the value. Same dialect-binding
              -- pattern that bit v0.23.2's case-close test. Pre-fix this
              -- silently filtered to zero matches and inserted no fixtures.
              AND UPPER(l.lesson_type) = 'LAB'
              AND l.title LIKE '%Read your first alert%'
            LIMIT 1
        """)).fetchone()

        if row is None:
            logger.error(
                "Could not find L1 LAB lesson 'Read your first alert in /alerts'. "
                "Run seed_courses.py first."
            )
            return

        lesson_id = row[0]
        logger.info("Target lesson_id=%d", lesson_id)

        existing_count = conn.execute(
            text("SELECT COUNT(*) FROM lab_fixtures WHERE lesson_id = :lid"),
            {"lid": lesson_id},
        ).scalar()

        if existing_count and existing_count > 0:
            logger.info(
                "lab_fixtures already seeded for lesson %d (%d rows). Skipping.",
                lesson_id, existing_count,
            )
            return

        conn.execute(text("BEGIN"))
        try:
            for fix in _FIXTURES:
                payload_val = json.dumps(fix["payload"])
                conn.execute(
                    text(
                        "INSERT INTO lab_fixtures "
                        "(lesson_id, fixture_kind, payload, target_table, created_at) "
                        "VALUES (:lid, :kind, :payload, :tbl, CURRENT_TIMESTAMP)"
                    ),
                    {
                        "lid": lesson_id,
                        "kind": fix["fixture_kind"],
                        "payload": payload_val,
                        "tbl": fix["target_table"],
                    },
                )
                logger.info("Inserted fixture: %s → %s", fix["fixture_kind"], fix["target_table"])
            conn.execute(text("COMMIT"))
        except Exception as exc:
            conn.execute(text("ROLLBACK"))
            logger.error("Failed to seed lab fixtures: %s", exc)
            raise

    logger.info("Seeded %d lab fixtures for lesson_id=%d", len(_FIXTURES), lesson_id)


if __name__ == "__main__":
    seed_lab_fixtures()
