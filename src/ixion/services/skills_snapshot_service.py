"""Daily snapshot service for skills assessment aggregation."""

import logging
from datetime import date

from sqlalchemy import func
from sqlalchemy.orm import Session

from ixion.models.skills import AssessmentSnapshot, SkillAssessment

logger = logging.getLogger(__name__)

TARGET_LEVEL = 3  # "Intermediate" — users at or above count as covered


def create_daily_snapshot(session: Session) -> int:
    """Create aggregate snapshot rows for today if they don't already exist.

    Returns the number of snapshot rows inserted.
    """
    today = date.today()

    # Check if snapshot already exists for today
    existing = (
        session.query(AssessmentSnapshot)
        .filter(AssessmentSnapshot.snapshot_date == today)
        .first()
    )
    if existing:
        logger.debug("Skills snapshot already exists for %s, skipping", today)
        return 0

    # Aggregate all assessments by skill_key
    results = (
        session.query(
            SkillAssessment.skill_key,
            func.avg(SkillAssessment.rating).label("avg_prof"),
            func.count(SkillAssessment.user_id).label("num_assessors"),
        )
        .group_by(SkillAssessment.skill_key)
        .all()
    )

    if not results:
        logger.debug("No skill assessments found, skipping snapshot")
        return 0

    # For coverage count, we need per-skill count of users >= TARGET_LEVEL
    coverage_results = (
        session.query(
            SkillAssessment.skill_key,
            func.count(SkillAssessment.user_id).label("coverage"),
        )
        .filter(SkillAssessment.rating >= TARGET_LEVEL)
        .group_by(SkillAssessment.skill_key)
        .all()
    )
    coverage_map = {r.skill_key: r.coverage for r in coverage_results}

    count = 0
    for row in results:
        session.add(
            AssessmentSnapshot(
                snapshot_date=today,
                skill_key=row.skill_key,
                avg_proficiency=round(float(row.avg_prof), 2),
                num_assessors=row.num_assessors,
                coverage_count=coverage_map.get(row.skill_key, 0),
            )
        )
        count += 1

    session.commit()
    logger.info("Created %d skills snapshot rows for %s", count, today)
    return count
