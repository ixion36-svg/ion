"""Analytics Engine API router for ION."""

from typing import Optional

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ion.models.analytics import AnalyticsJob, AnalyticsSnapshot
from ion.models.user import User
from ion.auth.dependencies import get_current_user, require_permission
from ion.services.analytics_engine import get_analytics_engine
from ion.web.api import get_db_session

from datetime import datetime, timedelta

router = APIRouter(tags=["analytics"])


class AnalyticsJobUpdate(BaseModel):
    enabled: Optional[bool] = None
    schedule_minutes: Optional[int] = None


@router.get("/jobs")
async def list_analytics_jobs(
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """List all analytics jobs with their latest results."""
    jobs = session.query(AnalyticsJob).order_by(AnalyticsJob.job_type).all()
    return {
        "jobs": [
            {
                "job_type": j.job_type,
                "display_name": j.display_name,
                "description": j.description,
                "enabled": j.enabled,
                "schedule_minutes": j.schedule_minutes,
                "last_run_at": j.last_run_at.isoformat() if j.last_run_at else None,
                "next_run_at": j.next_run_at.isoformat() if j.next_run_at else None,
                "last_duration_ms": j.last_duration_ms,
                "last_error": j.last_error,
                "run_count": j.run_count,
                "has_results": j.last_result is not None,
            }
            for j in jobs
        ]
    }


@router.get("/jobs/{job_type}")
async def get_analytics_job(
    job_type: str,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Get a single analytics job with its full latest result."""
    job = session.query(AnalyticsJob).filter_by(job_type=job_type).first()
    if not job:
        raise HTTPException(status_code=404, detail=f"Job not found: {job_type}")

    return {
        "job_type": job.job_type,
        "display_name": job.display_name,
        "description": job.description,
        "enabled": job.enabled,
        "schedule_minutes": job.schedule_minutes,
        "last_run_at": job.last_run_at.isoformat() if job.last_run_at else None,
        "next_run_at": job.next_run_at.isoformat() if job.next_run_at else None,
        "last_duration_ms": job.last_duration_ms,
        "last_error": job.last_error,
        "run_count": job.run_count,
        "result": job.last_result,
    }


@router.post("/jobs/{job_type}/run")
async def run_analytics_job(
    job_type: str,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Manually trigger an analytics job."""
    engine = get_analytics_engine()
    result = engine.run_job_now(session, job_type)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return {"job_type": job_type, "result": result, "message": "Job completed"}


@router.patch("/jobs/{job_type}")
async def update_analytics_job(
    job_type: str,
    data: AnalyticsJobUpdate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Update an analytics job's schedule or enabled state."""
    job = session.query(AnalyticsJob).filter_by(job_type=job_type).first()
    if not job:
        raise HTTPException(status_code=404, detail=f"Job not found: {job_type}")

    if data.enabled is not None:
        job.enabled = data.enabled
    if data.schedule_minutes is not None:
        if data.schedule_minutes < 5:
            raise HTTPException(status_code=400, detail="Minimum schedule is 5 minutes")
        job.schedule_minutes = data.schedule_minutes
        # Recalculate next run
        if job.last_run_at:
            job.next_run_at = job.last_run_at + timedelta(minutes=data.schedule_minutes)

    session.commit()
    return {"message": "Job updated", "job_type": job_type, "enabled": job.enabled, "schedule_minutes": job.schedule_minutes}


@router.get("/snapshots/{job_type}")
async def get_analytics_snapshots(
    job_type: str,
    days: int = 7,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Get historical snapshots for a job (for trend charts)."""
    cutoff = datetime.utcnow() - timedelta(days=days)
    snapshots = session.query(AnalyticsSnapshot).filter(
        AnalyticsSnapshot.job_type == job_type,
        AnalyticsSnapshot.created_at >= cutoff,
    ).order_by(AnalyticsSnapshot.created_at).all()

    return {
        "job_type": job_type,
        "snapshots": [
            {
                "data": s.snapshot_data,
                "created_at": s.created_at.isoformat(),
            }
            for s in snapshots
        ],
        "count": len(snapshots),
    }


@router.get("/dashboard")
async def get_analytics_dashboard(
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Get aggregated dashboard data from all analytics jobs."""
    jobs = session.query(AnalyticsJob).all()

    dashboard = {}
    summary = {
        "entities_at_risk": 0,
        "repeat_offenders": 0,
        "noisy_rules": 0,
        "stale_cases": 0,
        "stale_alerts": 0,
        "mttr_hours": None,
        "observable_velocity": 0,
    }

    for job in jobs:
        r = job.last_result or {}
        dashboard[job.job_type] = {
            "display_name": job.display_name,
            "enabled": job.enabled,
            "last_run_at": job.last_run_at.isoformat() if job.last_run_at else None,
            "last_duration_ms": job.last_duration_ms,
            "last_error": job.last_error,
            "run_count": job.run_count,
            "result": r,
        }

        # Extract summary stats
        if job.job_type == "entity_risk_score":
            summary["entities_at_risk"] = r.get("total_scored", 0)
        elif job.job_type == "repeat_offenders":
            summary["repeat_offenders"] = r.get("total_flagged", 0)
        elif job.job_type == "rule_noise":
            summary["noisy_rules"] = len([
                rule for rule in r.get("rules", [])
                if rule.get("fp_ratio", 0) > 0.5
            ])
        elif job.job_type == "case_metrics":
            summary["mttr_hours"] = r.get("mttr_hours")
        elif job.job_type == "stale_investigations":
            summary["stale_cases"] = r.get("total_stale_cases", 0)
            summary["stale_alerts"] = r.get("total_stale_alerts", 0)
        elif job.job_type == "observable_velocity":
            summary["observable_velocity"] = r.get("velocity_7d", 0)

    return {"jobs": dashboard, "summary": summary}
