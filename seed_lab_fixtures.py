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

from ion.storage.database import get_engine, get_session

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
            "status": "open",
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
            "status": "open",
            "priority": "medium",
            "source_system": "elastic",
            "rule_name": "Suspicious Base64-Encoded PowerShell (Lab fixture)",
            "analyst_notes": "LAB FIXTURE — do not close outside training.",
            "mitre_techniques": json.dumps(["T1059.001"]),
            "created_at": "2026-01-01 00:00:00",
            "updated_at": "2026-01-01 00:00:00",
        },
    },
    {
        "fixture_kind": "alert_case",
        "target_table": "alert_cases",
        "payload": {
            "case_number": "LAB-CASE-0001",
            "title": "Lab fixture case — Credential access chain",
            "description": "Auto-seeded for L1 Module 2 lab exercise. Investigate the two open alerts linked to this case.",
            "status": "open",
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
              AND l.lesson_type = 'lab'
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
