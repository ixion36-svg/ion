"""Skills assessment API endpoints (SOC-CMM aligned)."""

import logging
from datetime import date, datetime, timedelta
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from ion.auth.dependencies import get_current_user, get_db_session, require_permission
from ion.models.skills import (
    AssessmentReviewCycle, AssessmentSnapshot, KnowledgeArticle,
    SOCCMMAssessment, SkillAssessment, TeamCertification,
    TeamScheduleEntry, TrainingPlan, TrainingPlanItem, UserCareerGoal,
)
from ion.models.user import Role, User

router = APIRouter(tags=["skills"])
logger = logging.getLogger(__name__)


# =============================================================================
# Pydantic Models
# =============================================================================


class SkillRating(BaseModel):
    skill_key: str
    rating: int = Field(ge=1, le=5)
    notes: Optional[str] = None


class AssessmentBulkSave(BaseModel):
    assessments: List[SkillRating]


class CareerGoalSave(BaseModel):
    current_role: str
    target_role: str


class SkillRatingResponse(BaseModel):
    skill_key: str
    rating: int
    notes: Optional[str] = None


class CareerGoalResponse(BaseModel):
    current_role: str
    target_role: str


class TeamMemberSkills(BaseModel):
    user_id: int
    username: str
    display_name: Optional[str] = None
    skills: dict  # skill_key -> rating


class SnapshotPoint(BaseModel):
    date: str
    skill_key: str
    avg_proficiency: float
    num_assessors: int
    coverage_count: int


class TeamOverviewResponse(BaseModel):
    members: List[TeamMemberSkills]
    snapshots: List[SnapshotPoint]


class DepartureSkillImpact(BaseModel):
    skill_key: str
    severity: str  # "critical", "warning", "ok"
    coverage_before: int
    coverage_after: int
    only_assessor: bool


class DepartureImpactResponse(BaseModel):
    user_id: int
    username: str
    impacts: List[DepartureSkillImpact]
    readiness_before: float
    readiness_after: float


# =============================================================================
# Endpoints
# =============================================================================


@router.get("/assessment")
def get_assessment(
    current_user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
):
    """Get current user's skill assessment ratings + review cycle status."""
    rows = (
        session.query(SkillAssessment)
        .filter(SkillAssessment.user_id == current_user.id)
        .all()
    )

    # Get review cycle
    cycle = (
        session.query(AssessmentReviewCycle)
        .filter(AssessmentReviewCycle.user_id == current_user.id)
        .first()
    )

    review = None
    if cycle:
        now = datetime.utcnow()
        is_overdue = now >= cycle.next_review_at
        days_until = max(0, (cycle.next_review_at - now).days) if not is_overdue else 0
        review = {
            "submitted_at": cycle.submitted_at.isoformat(),
            "next_review_at": cycle.next_review_at.isoformat(),
            "is_locked": cycle.is_locked and not is_overdue,
            "is_overdue": is_overdue,
            "days_until_review": days_until,
        }

    return {
        "assessments": [
            {"skill_key": r.skill_key, "rating": r.rating, "notes": r.notes}
            for r in rows
        ],
        "review": review,
    }


@router.post("/assessment")
def save_assessment(
    payload: AssessmentBulkSave,
    current_user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
):
    """Bulk upsert skill assessment ratings for current user."""
    # Check review cycle lock
    cycle = (
        session.query(AssessmentReviewCycle)
        .filter(AssessmentReviewCycle.user_id == current_user.id)
        .first()
    )
    if cycle and cycle.is_locked:
        now = datetime.utcnow()
        if now < cycle.next_review_at:
            raise HTTPException(
                status_code=403,
                detail="Assessment is locked until next review cycle. Use 'Edit Assessment' to unlock.",
            )
        # Auto-unlock if overdue
        cycle.is_locked = False

    for item in payload.assessments:
        existing = (
            session.query(SkillAssessment)
            .filter(
                SkillAssessment.user_id == current_user.id,
                SkillAssessment.skill_key == item.skill_key,
            )
            .first()
        )
        if existing:
            existing.rating = item.rating
            existing.notes = item.notes
        else:
            session.add(
                SkillAssessment(
                    user_id=current_user.id,
                    skill_key=item.skill_key,
                    rating=item.rating,
                    notes=item.notes,
                )
            )
    session.commit()
    return {"status": "ok", "saved": len(payload.assessments)}


@router.get("/career-goal")
def get_career_goal(
    current_user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
):
    """Get current user's career goal (current + target role)."""
    goal = (
        session.query(UserCareerGoal)
        .filter(UserCareerGoal.user_id == current_user.id)
        .first()
    )
    if not goal:
        return {"current_role": None, "target_role": None}
    return {"current_role": goal.current_role, "target_role": goal.target_role}


@router.post("/career-goal")
def save_career_goal(
    payload: CareerGoalSave,
    current_user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
):
    """Save current user's career goal."""
    existing = (
        session.query(UserCareerGoal)
        .filter(UserCareerGoal.user_id == current_user.id)
        .first()
    )
    if existing:
        existing.current_role = payload.current_role
        existing.target_role = payload.target_role
    else:
        session.add(
            UserCareerGoal(
                user_id=current_user.id,
                current_role=payload.current_role,
                target_role=payload.target_role,
            )
        )
    session.commit()
    return {"status": "ok"}


# =============================================================================
# Assessment Review Cycle
# =============================================================================

REVIEW_CYCLE_DAYS = 90  # 3 months


@router.post("/assessment/submit")
def submit_assessment(
    current_user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
):
    """Submit assessment and lock it for 3 months until the next review cycle."""
    # Must have at least some ratings
    count = (
        session.query(func.count(SkillAssessment.id))
        .filter(SkillAssessment.user_id == current_user.id)
        .scalar()
    )
    if not count:
        raise HTTPException(status_code=400, detail="Rate at least one skill before submitting.")

    now = datetime.utcnow()
    next_review = now + timedelta(days=REVIEW_CYCLE_DAYS)

    cycle = (
        session.query(AssessmentReviewCycle)
        .filter(AssessmentReviewCycle.user_id == current_user.id)
        .first()
    )
    if cycle:
        cycle.submitted_at = now
        cycle.next_review_at = next_review
        cycle.is_locked = True
    else:
        cycle = AssessmentReviewCycle(
            user_id=current_user.id,
            submitted_at=now,
            next_review_at=next_review,
            is_locked=True,
        )
        session.add(cycle)

    session.commit()
    return {
        "status": "ok",
        "submitted_at": cycle.submitted_at.isoformat(),
        "next_review_at": cycle.next_review_at.isoformat(),
        "is_locked": True,
    }


@router.post("/assessment/unlock")
def unlock_assessment(
    current_user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
):
    """Unlock assessment for early editing (before review cycle is due)."""
    cycle = (
        session.query(AssessmentReviewCycle)
        .filter(AssessmentReviewCycle.user_id == current_user.id)
        .first()
    )
    if not cycle:
        return {"status": "ok", "is_locked": False}

    cycle.is_locked = False
    session.commit()
    return {"status": "ok", "is_locked": False}


@router.get("/team-overview")
def get_team_overview(
    current_user: User = Depends(require_permission("security:read")),
    session: Session = Depends(get_db_session),
):
    """Get team skills heatmap data + coverage metrics + weekly snapshots (lead+)."""
    # Get all users who have at least one assessment
    assessed_user_ids = (
        session.query(SkillAssessment.user_id)
        .distinct()
        .all()
    )
    assessed_user_ids = [uid for (uid,) in assessed_user_ids]

    members = []
    for uid in assessed_user_ids:
        user = session.query(User).filter(User.id == uid).first()
        if not user or not user.is_active:
            continue
        ratings = (
            session.query(SkillAssessment)
            .filter(SkillAssessment.user_id == uid)
            .all()
        )
        skills_map = {r.skill_key: r.rating for r in ratings}
        # Get career goal for this user
        goal = (
            session.query(UserCareerGoal)
            .filter(UserCareerGoal.user_id == uid)
            .first()
        )
        members.append({
            "user_id": user.id,
            "username": user.username,
            "display_name": user.display_name or user.username,
            "roles": [r.name for r in user.roles],
            "current_role": goal.current_role if goal else None,
            "target_role": goal.target_role if goal else None,
            "skills": skills_map,
        })

    # Get last 8 weekly snapshots
    eight_weeks_ago = date.today() - timedelta(weeks=8)
    snapshots = (
        session.query(AssessmentSnapshot)
        .filter(AssessmentSnapshot.snapshot_date >= eight_weeks_ago)
        .order_by(AssessmentSnapshot.snapshot_date)
        .all()
    )
    snapshot_data = [
        {
            "date": str(s.snapshot_date),
            "skill_key": s.skill_key,
            "avg_proficiency": round(s.avg_proficiency, 2),
            "num_assessors": s.num_assessors,
            "coverage_count": s.coverage_count,
        }
        for s in snapshots
    ]

    return {"members": members, "snapshots": snapshot_data}


@router.get("/team-overview/departure-impact")
def get_departure_impact(
    user_id: int = Query(..., description="User ID to simulate departure"),
    current_user: User = Depends(require_permission("security:read")),
    session: Session = Depends(get_db_session),
):
    """Simulate impact if a team member leaves — skills at risk (lead+)."""
    target_user = session.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")

    # Get the departing user's ratings
    departing_ratings = (
        session.query(SkillAssessment)
        .filter(SkillAssessment.user_id == user_id)
        .all()
    )
    departing_skills = {r.skill_key: r.rating for r in departing_ratings}

    if not departing_skills:
        return {
            "user_id": user_id,
            "username": target_user.username,
            "impacts": [],
            "readiness_before": 0,
            "readiness_after": 0,
        }

    # Get all assessments for skills the departing user has rated
    all_assessments = (
        session.query(SkillAssessment)
        .filter(SkillAssessment.skill_key.in_(list(departing_skills.keys())))
        .all()
    )

    # Group by skill_key
    skill_users = {}  # skill_key -> list of (user_id, rating)
    for a in all_assessments:
        if a.skill_key not in skill_users:
            skill_users[a.skill_key] = []
        skill_users[a.skill_key].append((a.user_id, a.rating))

    TARGET_LEVEL = 3  # "Intermediate" is the coverage threshold
    impacts = []
    total_coverage_before = 0
    total_coverage_after = 0
    total_skills = 0

    for skill_key, user_ratings in skill_users.items():
        total_skills += 1
        coverage_before = sum(1 for _, r in user_ratings if r >= TARGET_LEVEL)
        coverage_after = sum(
            1 for uid, r in user_ratings if uid != user_id and r >= TARGET_LEVEL
        )
        total_coverage_before += min(coverage_before, 1)
        total_coverage_after += min(coverage_after, 1)

        only_assessor = len(user_ratings) == 1 and user_ratings[0][0] == user_id

        if coverage_after == 0 and coverage_before > 0:
            severity = "critical"
        elif coverage_after == 1 and coverage_before > 1:
            severity = "warning"
        else:
            severity = "ok"

        impacts.append({
            "skill_key": skill_key,
            "severity": severity,
            "coverage_before": coverage_before,
            "coverage_after": coverage_after,
            "only_assessor": only_assessor,
        })

    # Sort: critical first, then warning, then ok
    severity_order = {"critical": 0, "warning": 1, "ok": 2}
    impacts.sort(key=lambda x: severity_order.get(x["severity"], 3))

    readiness_before = (total_coverage_before / total_skills * 100) if total_skills else 0
    readiness_after = (total_coverage_after / total_skills * 100) if total_skills else 0

    return {
        "user_id": user_id,
        "username": target_user.username,
        "impacts": impacts,
        "readiness_before": round(readiness_before, 1),
        "readiness_after": round(readiness_after, 1),
    }


# =============================================================================
# Team Schedule Endpoints
# =============================================================================

VALID_STATUSES = {"working", "leave", "sick", "training", "off"}
VALID_SHIFTS = {"day", "night", "early", "late", None}


class ScheduleEntrySave(BaseModel):
    user_id: int
    date: str  # YYYY-MM-DD
    status: str
    shift: Optional[str] = None
    notes: Optional[str] = None


class ScheduleBulkSave(BaseModel):
    entries: List[ScheduleEntrySave]


@router.get("/schedule")
def get_schedule(
    month: str = Query(..., description="Month in YYYY-MM format"),
    current_user: User = Depends(require_permission("security:read")),
    session: Session = Depends(get_db_session),
):
    """Get team schedule for a given month (lead+)."""
    try:
        year, mon = month.split("-")
        year, mon = int(year), int(mon)
        start = date(year, mon, 1)
        if mon == 12:
            end = date(year + 1, 1, 1)
        else:
            end = date(year, mon + 1, 1)
    except (ValueError, IndexError):
        raise HTTPException(status_code=400, detail="Invalid month format, use YYYY-MM")

    rows = (
        session.query(TeamScheduleEntry)
        .filter(TeamScheduleEntry.date >= start, TeamScheduleEntry.date < end)
        .order_by(TeamScheduleEntry.date)
        .all()
    )

    # Get all team members (users with assessments)
    assessed_ids = [
        uid for (uid,) in session.query(SkillAssessment.user_id).distinct().all()
    ]
    members = []
    for uid in assessed_ids:
        user = session.query(User).filter(User.id == uid).first()
        if user and user.is_active:
            members.append({
                "user_id": user.id,
                "username": user.username,
                "display_name": user.display_name or user.username,
            })

    entries = [
        {
            "user_id": r.user_id,
            "date": str(r.date),
            "status": r.status,
            "shift": r.shift,
            "notes": r.notes,
        }
        for r in rows
    ]

    return {"month": month, "members": members, "entries": entries}


@router.post("/schedule")
def save_schedule(
    payload: ScheduleBulkSave,
    current_user: User = Depends(require_permission("security:read")),
    session: Session = Depends(get_db_session),
):
    """Bulk upsert team schedule entries (lead+)."""
    saved = 0
    for item in payload.entries:
        if item.status not in VALID_STATUSES:
            continue
        try:
            entry_date = date.fromisoformat(item.date)
        except ValueError:
            continue

        existing = (
            session.query(TeamScheduleEntry)
            .filter(
                TeamScheduleEntry.user_id == item.user_id,
                TeamScheduleEntry.date == entry_date,
            )
            .first()
        )
        if existing:
            existing.status = item.status
            existing.shift = item.shift
            existing.notes = item.notes
        else:
            session.add(
                TeamScheduleEntry(
                    user_id=item.user_id,
                    date=entry_date,
                    status=item.status,
                    shift=item.shift,
                    notes=item.notes,
                )
            )
        saved += 1
    session.commit()
    return {"status": "ok", "saved": saved}


@router.delete("/schedule")
def delete_schedule_entry(
    user_id: int = Query(...),
    entry_date: str = Query(..., alias="date", description="YYYY-MM-DD"),
    current_user: User = Depends(require_permission("security:read")),
    session: Session = Depends(get_db_session),
):
    """Delete a schedule entry (lead+). Reverts cell to default (working)."""
    try:
        d = date.fromisoformat(entry_date)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid date format")

    row = (
        session.query(TeamScheduleEntry)
        .filter(TeamScheduleEntry.user_id == user_id, TeamScheduleEntry.date == d)
        .first()
    )
    if row:
        session.delete(row)
        session.commit()
    return {"status": "ok"}


# =============================================================================
# SOC-CMM People Domain Maturity Assessment (lead+)
# =============================================================================

CMM_ASPECTS = ["employees", "roles", "people_mgmt", "knowledge_mgmt", "training"]


class CMMRatingSave(BaseModel):
    aspect: str
    rating: int = Field(ge=0, le=5)
    target_rating: int = Field(ge=0, le=5, default=3)
    notes: Optional[str] = None


class CMMBulkSave(BaseModel):
    assessments: List[CMMRatingSave]


@router.get("/cmm-assessment")
def get_cmm_assessment(
    current_user: User = Depends(require_permission("security:read")),
    session: Session = Depends(get_db_session),
):
    """Get SOC-CMM People Domain maturity ratings."""
    rows = session.query(SOCCMMAssessment).all()
    return {
        "assessments": [
            {
                "aspect": r.aspect,
                "rating": r.rating,
                "target_rating": r.target_rating,
                "notes": r.notes,
                "assessed_by_id": r.assessed_by_id,
                "assessed_date": str(r.assessed_date) if r.assessed_date else None,
            }
            for r in rows
        ]
    }


@router.post("/cmm-assessment")
def save_cmm_assessment(
    payload: CMMBulkSave,
    current_user: User = Depends(require_permission("security:read")),
    session: Session = Depends(get_db_session),
):
    """Save SOC-CMM People Domain maturity ratings (lead+)."""
    for item in payload.assessments:
        if item.aspect not in CMM_ASPECTS:
            continue
        existing = (
            session.query(SOCCMMAssessment)
            .filter(SOCCMMAssessment.aspect == item.aspect)
            .first()
        )
        if existing:
            existing.rating = item.rating
            existing.target_rating = item.target_rating
            existing.notes = item.notes
            existing.assessed_by_id = current_user.id
            existing.assessed_date = date.today()
        else:
            session.add(
                SOCCMMAssessment(
                    aspect=item.aspect,
                    rating=item.rating,
                    target_rating=item.target_rating,
                    notes=item.notes,
                    assessed_by_id=current_user.id,
                    assessed_date=date.today(),
                )
            )
    session.commit()
    return {"status": "ok", "saved": len(payload.assessments)}


# =============================================================================
# Team Certifications (lead+)
# =============================================================================


class CertSave(BaseModel):
    user_id: int
    cert_name: str
    issuing_body: Optional[str] = None
    obtained_date: Optional[str] = None  # YYYY-MM-DD
    expiry_date: Optional[str] = None
    status: str = "active"
    notes: Optional[str] = None


@router.get("/certifications")
def get_certifications(
    current_user: User = Depends(require_permission("security:read")),
    session: Session = Depends(get_db_session),
):
    """Get all team certifications (lead+)."""
    rows = session.query(TeamCertification).order_by(TeamCertification.user_id).all()
    return {
        "certifications": [
            {
                "id": r.id,
                "user_id": r.user_id,
                "cert_name": r.cert_name,
                "issuing_body": r.issuing_body,
                "obtained_date": str(r.obtained_date) if r.obtained_date else None,
                "expiry_date": str(r.expiry_date) if r.expiry_date else None,
                "status": r.status,
                "notes": r.notes,
            }
            for r in rows
        ]
    }


@router.post("/certifications")
def save_certification(
    payload: CertSave,
    current_user: User = Depends(require_permission("security:read")),
    session: Session = Depends(get_db_session),
):
    """Add or update a team certification (lead+)."""
    obtained = date.fromisoformat(payload.obtained_date) if payload.obtained_date else None
    expiry = date.fromisoformat(payload.expiry_date) if payload.expiry_date else None
    session.add(
        TeamCertification(
            user_id=payload.user_id,
            cert_name=payload.cert_name,
            issuing_body=payload.issuing_body,
            obtained_date=obtained,
            expiry_date=expiry,
            status=payload.status,
            notes=payload.notes,
        )
    )
    session.commit()
    return {"status": "ok"}


@router.delete("/certifications/{cert_id}")
def delete_certification(
    cert_id: int,
    current_user: User = Depends(require_permission("security:read")),
    session: Session = Depends(get_db_session),
):
    """Delete a certification record."""
    row = session.query(TeamCertification).filter(TeamCertification.id == cert_id).first()
    if row:
        session.delete(row)
        session.commit()
    return {"status": "ok"}


# =============================================================================
# Knowledge Management (lead+)
# =============================================================================


class KnowledgeSave(BaseModel):
    capability_key: str
    doc_status: str = "undocumented"  # undocumented, basic, comprehensive
    has_runbooks: bool = False
    has_procedures: bool = False
    knowledge_sharing: str = "siloed"  # siloed, shared, trained
    spof_risk: bool = True
    owner_user_id: Optional[int] = None
    notes: Optional[str] = None


class TrainingPlanCreate(BaseModel):
    name: str
    target_role: Optional[str] = None
    notes: Optional[str] = None


class TrainingPlanUpdate(BaseModel):
    name: Optional[str] = None
    target_role: Optional[str] = None
    status: Optional[str] = None  # draft, active, completed, archived
    notes: Optional[str] = None


class TrainingPlanItemCreate(BaseModel):
    cert_name: str
    provider: Optional[str] = None
    price: float = 0
    difficulty: Optional[str] = None
    funding_type: str = "tbd"  # company, self, split, tbd
    priority: int = 0
    target_date: Optional[str] = None  # YYYY-MM-DD
    notes: Optional[str] = None


class TrainingPlanItemUpdate(BaseModel):
    status: Optional[str] = None  # planned, in_progress, completed, skipped
    funding_type: Optional[str] = None
    priority: Optional[int] = None
    target_date: Optional[str] = None
    notes: Optional[str] = None


class TrainingPlanItemBulkAdd(BaseModel):
    items: List[TrainingPlanItemCreate]


class KnowledgeBulkSave(BaseModel):
    articles: List[KnowledgeSave]


@router.get("/knowledge")
def get_knowledge(
    current_user: User = Depends(require_permission("security:read")),
    session: Session = Depends(get_db_session),
):
    """Get knowledge documentation status for all capabilities."""
    rows = session.query(KnowledgeArticle).all()
    return {
        "articles": [
            {
                "capability_key": r.capability_key,
                "doc_status": r.doc_status,
                "has_runbooks": r.has_runbooks,
                "has_procedures": r.has_procedures,
                "knowledge_sharing": r.knowledge_sharing,
                "spof_risk": r.spof_risk,
                "owner_user_id": r.owner_user_id,
                "notes": r.notes,
            }
            for r in rows
        ]
    }


@router.post("/knowledge")
def save_knowledge(
    payload: KnowledgeBulkSave,
    current_user: User = Depends(require_permission("security:read")),
    session: Session = Depends(get_db_session),
):
    """Bulk upsert knowledge documentation status (lead+)."""
    for item in payload.articles:
        existing = (
            session.query(KnowledgeArticle)
            .filter(KnowledgeArticle.capability_key == item.capability_key)
            .first()
        )
        if existing:
            existing.doc_status = item.doc_status
            existing.has_runbooks = item.has_runbooks
            existing.has_procedures = item.has_procedures
            existing.knowledge_sharing = item.knowledge_sharing
            existing.spof_risk = item.spof_risk
            existing.owner_user_id = item.owner_user_id
            existing.notes = item.notes
        else:
            session.add(
                KnowledgeArticle(
                    capability_key=item.capability_key,
                    doc_status=item.doc_status,
                    has_runbooks=item.has_runbooks,
                    has_procedures=item.has_procedures,
                    knowledge_sharing=item.knowledge_sharing,
                    spof_risk=item.spof_risk,
                    owner_user_id=item.owner_user_id,
                    notes=item.notes,
                )
            )
    session.commit()
    return {"status": "ok", "saved": len(payload.articles)}


# =============================================================================
# Training Plans (any authenticated user)
# =============================================================================


def _plan_to_dict(plan: TrainingPlan, items: list) -> dict:
    """Serialize a training plan with its items."""
    item_list = []
    for it in items:
        item_list.append({
            "id": it.id,
            "cert_name": it.cert_name,
            "provider": it.provider,
            "price": it.price,
            "difficulty": it.difficulty,
            "status": it.status,
            "funding_type": it.funding_type,
            "priority": it.priority,
            "target_date": str(it.target_date) if it.target_date else None,
            "completed_at": it.completed_at.isoformat() if it.completed_at else None,
            "notes": it.notes,
        })
    total_cost = sum(it.price for it in items)
    completed = sum(1 for it in items if it.status == "completed")
    return {
        "id": plan.id,
        "name": plan.name,
        "target_role": plan.target_role,
        "status": plan.status,
        "notes": plan.notes,
        "created_at": plan.created_at.isoformat() if plan.created_at else None,
        "updated_at": plan.updated_at.isoformat() if plan.updated_at else None,
        "items": item_list,
        "total_cost": total_cost,
        "completed_count": completed,
        "total_count": len(item_list),
    }


@router.get("/training-plans")
def get_training_plans(
    current_user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
):
    """Get all training plans for the current user."""
    plans = (
        session.query(TrainingPlan)
        .filter(TrainingPlan.user_id == current_user.id)
        .order_by(TrainingPlan.created_at.desc())
        .all()
    )
    result = []
    for plan in plans:
        items = (
            session.query(TrainingPlanItem)
            .filter(TrainingPlanItem.plan_id == plan.id)
            .order_by(TrainingPlanItem.priority, TrainingPlanItem.id)
            .all()
        )
        result.append(_plan_to_dict(plan, items))
    return {"plans": result}


@router.get("/training-plans/forecast")
def get_training_forecast(
    current_user: User = Depends(require_permission("security:read")),
    session: Session = Depends(get_db_session),
):
    """Get aggregate training cost forecast across all users' plans (lead+)."""
    # Get all active/draft plans (not archived)
    plans = (
        session.query(TrainingPlan)
        .filter(TrainingPlan.status.in_(["draft", "active"]))
        .all()
    )

    user_forecasts = []
    totals = {"total": 0, "company": 0, "self": 0, "split": 0, "tbd": 0}
    by_emp_type = {}  # emp_type -> {total, company, self, split, tbd, headcount}

    for plan in plans:
        user = session.query(User).filter(User.id == plan.user_id).first()
        if not user or not user.is_active:
            continue
        items = (
            session.query(TrainingPlanItem)
            .filter(TrainingPlanItem.plan_id == plan.id, TrainingPlanItem.status != "skipped")
            .all()
        )
        plan_total = sum(it.price for it in items)
        plan_company = sum(it.price for it in items if it.funding_type == "company")
        plan_self = sum(it.price for it in items if it.funding_type == "self")
        plan_split = sum(it.price for it in items if it.funding_type == "split")
        plan_tbd = sum(it.price for it in items if it.funding_type == "tbd")
        completed = sum(1 for it in items if it.status == "completed")

        emp_type = getattr(user, "employment_type", None) or "cs"

        user_forecasts.append({
            "user_id": user.id,
            "username": user.username,
            "display_name": user.display_name or user.username,
            "employment_type": emp_type,
            "plan_id": plan.id,
            "plan_name": plan.name,
            "plan_status": plan.status,
            "target_role": plan.target_role,
            "total_cost": plan_total,
            "company_cost": plan_company,
            "self_cost": plan_self,
            "split_cost": plan_split,
            "tbd_cost": plan_tbd,
            "item_count": len(items),
            "completed_count": completed,
        })
        totals["total"] += plan_total
        totals["company"] += plan_company
        totals["self"] += plan_self
        totals["split"] += plan_split
        totals["tbd"] += plan_tbd

        # Aggregate by employment type
        if emp_type not in by_emp_type:
            by_emp_type[emp_type] = {"total": 0, "company": 0, "self": 0, "split": 0, "tbd": 0, "headcount": 0, "certs": 0}
        by_emp_type[emp_type]["total"] += plan_total
        by_emp_type[emp_type]["company"] += plan_company
        by_emp_type[emp_type]["self"] += plan_self
        by_emp_type[emp_type]["split"] += plan_split
        by_emp_type[emp_type]["tbd"] += plan_tbd
        by_emp_type[emp_type]["headcount"] += 1
        by_emp_type[emp_type]["certs"] += len(items)

    return {
        "forecasts": user_forecasts,
        "totals": totals,
        "by_employment_type": by_emp_type,
        "plan_count": len(user_forecasts),
    }


@router.post("/training-plans")
def create_training_plan(
    payload: TrainingPlanCreate,
    current_user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
):
    """Create a new training plan."""
    # Check for duplicate name
    existing = (
        session.query(TrainingPlan)
        .filter(TrainingPlan.user_id == current_user.id, TrainingPlan.name == payload.name)
        .first()
    )
    if existing:
        raise HTTPException(status_code=409, detail="A plan with this name already exists")
    plan = TrainingPlan(
        user_id=current_user.id,
        name=payload.name,
        target_role=payload.target_role,
        notes=payload.notes,
    )
    session.add(plan)
    session.commit()
    session.refresh(plan)
    return _plan_to_dict(plan, [])


@router.put("/training-plans/{plan_id}")
def update_training_plan(
    plan_id: int,
    payload: TrainingPlanUpdate,
    current_user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
):
    """Update a training plan's metadata."""
    plan = (
        session.query(TrainingPlan)
        .filter(TrainingPlan.id == plan_id, TrainingPlan.user_id == current_user.id)
        .first()
    )
    if not plan:
        raise HTTPException(status_code=404, detail="Training plan not found")
    if payload.name is not None:
        plan.name = payload.name
    if payload.target_role is not None:
        plan.target_role = payload.target_role
    if payload.status is not None:
        if payload.status not in ("draft", "active", "completed", "archived"):
            raise HTTPException(status_code=400, detail="Invalid status")
        plan.status = payload.status
    if payload.notes is not None:
        plan.notes = payload.notes
    session.commit()
    items = (
        session.query(TrainingPlanItem)
        .filter(TrainingPlanItem.plan_id == plan.id)
        .order_by(TrainingPlanItem.priority, TrainingPlanItem.id)
        .all()
    )
    return _plan_to_dict(plan, items)


@router.delete("/training-plans/{plan_id}")
def delete_training_plan(
    plan_id: int,
    current_user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
):
    """Delete a training plan and all its items."""
    plan = (
        session.query(TrainingPlan)
        .filter(TrainingPlan.id == plan_id, TrainingPlan.user_id == current_user.id)
        .first()
    )
    if not plan:
        raise HTTPException(status_code=404, detail="Training plan not found")
    session.query(TrainingPlanItem).filter(TrainingPlanItem.plan_id == plan_id).delete()
    session.delete(plan)
    session.commit()
    return {"status": "ok"}


@router.post("/training-plans/{plan_id}/items")
def add_plan_items(
    plan_id: int,
    payload: TrainingPlanItemBulkAdd,
    current_user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
):
    """Add certifications/items to a training plan."""
    plan = (
        session.query(TrainingPlan)
        .filter(TrainingPlan.id == plan_id, TrainingPlan.user_id == current_user.id)
        .first()
    )
    if not plan:
        raise HTTPException(status_code=404, detail="Training plan not found")
    # Get current max priority
    max_pri = (
        session.query(func.max(TrainingPlanItem.priority))
        .filter(TrainingPlanItem.plan_id == plan_id)
        .scalar()
    ) or 0
    added = 0
    for item in payload.items:
        # Skip duplicates within the same plan
        exists = (
            session.query(TrainingPlanItem)
            .filter(
                TrainingPlanItem.plan_id == plan_id,
                TrainingPlanItem.cert_name == item.cert_name,
            )
            .first()
        )
        if exists:
            continue
        max_pri += 1
        target_d = date.fromisoformat(item.target_date) if item.target_date else None
        session.add(TrainingPlanItem(
            plan_id=plan_id,
            cert_name=item.cert_name,
            provider=item.provider,
            price=item.price,
            difficulty=item.difficulty,
            funding_type=item.funding_type,
            priority=max_pri,
            target_date=target_d,
            notes=item.notes,
        ))
        added += 1
    session.commit()
    items = (
        session.query(TrainingPlanItem)
        .filter(TrainingPlanItem.plan_id == plan.id)
        .order_by(TrainingPlanItem.priority, TrainingPlanItem.id)
        .all()
    )
    return _plan_to_dict(plan, items)


@router.put("/training-plans/{plan_id}/items/{item_id}")
def update_plan_item(
    plan_id: int,
    item_id: int,
    payload: TrainingPlanItemUpdate,
    current_user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
):
    """Update a single training plan item (status, funding, etc.)."""
    plan = (
        session.query(TrainingPlan)
        .filter(TrainingPlan.id == plan_id, TrainingPlan.user_id == current_user.id)
        .first()
    )
    if not plan:
        raise HTTPException(status_code=404, detail="Training plan not found")
    item = (
        session.query(TrainingPlanItem)
        .filter(TrainingPlanItem.id == item_id, TrainingPlanItem.plan_id == plan_id)
        .first()
    )
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    if payload.status is not None:
        if payload.status not in ("planned", "in_progress", "completed", "skipped"):
            raise HTTPException(status_code=400, detail="Invalid item status")
        item.status = payload.status
        if payload.status == "completed":
            item.completed_at = datetime.utcnow()
        elif payload.status != "completed":
            item.completed_at = None
    if payload.funding_type is not None:
        item.funding_type = payload.funding_type
    if payload.priority is not None:
        item.priority = payload.priority
    if payload.target_date is not None:
        item.target_date = date.fromisoformat(payload.target_date) if payload.target_date else None
    if payload.notes is not None:
        item.notes = payload.notes
    session.commit()
    items = (
        session.query(TrainingPlanItem)
        .filter(TrainingPlanItem.plan_id == plan.id)
        .order_by(TrainingPlanItem.priority, TrainingPlanItem.id)
        .all()
    )
    return _plan_to_dict(plan, items)


@router.delete("/training-plans/{plan_id}/items/{item_id}")
def delete_plan_item(
    plan_id: int,
    item_id: int,
    current_user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
):
    """Remove a single item from a training plan."""
    plan = (
        session.query(TrainingPlan)
        .filter(TrainingPlan.id == plan_id, TrainingPlan.user_id == current_user.id)
        .first()
    )
    if not plan:
        raise HTTPException(status_code=404, detail="Training plan not found")
    item = (
        session.query(TrainingPlanItem)
        .filter(TrainingPlanItem.id == item_id, TrainingPlanItem.plan_id == plan_id)
        .first()
    )
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    session.delete(item)
    session.commit()
    items = (
        session.query(TrainingPlanItem)
        .filter(TrainingPlanItem.plan_id == plan.id)
        .order_by(TrainingPlanItem.priority, TrainingPlanItem.id)
        .all()
    )
    return _plan_to_dict(plan, items)
