"""CyAB (Cyber Assurance Baseline) API — systems, data sources, snapshots."""

import json
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ion.auth.dependencies import get_current_user, require_permission
from ion.core.config import get_elasticsearch_config
from ion.core.safe_errors import safe_error
from ion.models.cyab import (
    SYSTEM_ICONS,
    CyabAssessment,
    CyabDataSource,
    CyabSnapshot,
    CyabSystem,
    CyabSystemAssessment,
)
from ion.models.user import User
from ion.services import cyab_assessment_service
from ion.services.cyab_assessment_questions import (
    SCHEMA_VERSION as ASSESSMENT_SCHEMA_VERSION,
)
from ion.services.cyab_assessment_questions import (
    get_org_questions,
    get_system_questions,
)
from ion.services.elasticsearch_service import ElasticsearchService
from ion.services.tide_service import get_tide_service
from ion.web.api import get_db_session

router = APIRouter()

# Reuse the same templates dir — importing server.templates would loop.
_TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=_TEMPLATES_DIR)


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------

class SystemCreateRequest(BaseModel):
    name: str
    department: str
    department_lead: Optional[str] = None
    soc_team: Optional[str] = "Security Operations Center"
    soc_lead: Optional[str] = None
    reference: Optional[str] = None
    version: Optional[str] = "1.0"
    status: Optional[str] = "DRAFT"
    icon: Optional[str] = "monitor"
    tags: Optional[List[str]] = None
    review_cadence_days: Optional[int] = 90
    next_review_date: Optional[str] = None
    sign_dept_name: Optional[str] = None
    sign_dept_date: Optional[str] = None
    sign_soc_name: Optional[str] = None
    sign_soc_date: Optional[str] = None


class SystemUpdateRequest(BaseModel):
    name: Optional[str] = None
    department: Optional[str] = None
    department_lead: Optional[str] = None
    soc_team: Optional[str] = None
    soc_lead: Optional[str] = None
    reference: Optional[str] = None
    version: Optional[str] = None
    status: Optional[str] = None
    icon: Optional[str] = None
    tags: Optional[List[str]] = None
    review_cadence_days: Optional[int] = None
    next_review_date: Optional[str] = None
    sign_dept_name: Optional[str] = None
    sign_dept_date: Optional[str] = None
    sign_soc_name: Optional[str] = None
    sign_soc_date: Optional[str] = None


class DataSourceRequest(BaseModel):
    name: str
    data_source_type: Optional[str] = None
    icon: Optional[str] = None
    sal_tier: Optional[str] = "SAL-2"
    uptime_target: Optional[str] = None
    max_latency: Optional[str] = None
    retention: Optional[str] = None
    p1_sla: Optional[str] = None
    field_mapping: Optional[dict] = None
    field_mapping_score: Optional[int] = 0
    mandatory_score: Optional[int] = 0
    readiness_score: Optional[int] = 0
    risk_rating: Optional[str] = None
    sal_compliance: Optional[str] = None
    field_notes: Optional[str] = None
    use_case_status: Optional[str] = None
    use_case_review_date: Optional[str] = None
    use_case_gaps: Optional[str] = None
    use_case_remediation: Optional[str] = None
    tide_system_id: Optional[str] = None
    data_namespace: Optional[str] = None


class DataSourceUpdateRequest(BaseModel):
    name: Optional[str] = None
    data_source_type: Optional[str] = None
    icon: Optional[str] = None
    sal_tier: Optional[str] = None
    uptime_target: Optional[str] = None
    max_latency: Optional[str] = None
    retention: Optional[str] = None
    p1_sla: Optional[str] = None
    field_mapping: Optional[dict] = None
    field_mapping_score: Optional[int] = None
    mandatory_score: Optional[int] = None
    readiness_score: Optional[int] = None
    risk_rating: Optional[str] = None
    sal_compliance: Optional[str] = None
    field_notes: Optional[str] = None
    use_case_status: Optional[str] = None
    use_case_review_date: Optional[str] = None
    use_case_gaps: Optional[str] = None
    use_case_remediation: Optional[str] = None
    tide_system_id: Optional[str] = None
    data_namespace: Optional[str] = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_date(val: Optional[str]) -> Optional[date]:
    if not val:
        return None
    try:
        return date.fromisoformat(val)
    except (ValueError, TypeError):
        return None


def _parse_json(val: Optional[str]):
    if not val:
        return None
    try:
        return json.loads(val)
    except (ValueError, TypeError):
        return None


def _ds_to_dict(ds: CyabDataSource) -> dict:
    return {
        "id": ds.id,
        "system_id": ds.system_id,
        "name": ds.name,
        "data_source_type": ds.data_source_type,
        "icon": ds.icon,
        "sal_tier": ds.sal_tier,
        "uptime_target": ds.uptime_target,
        "max_latency": ds.max_latency,
        "retention": ds.retention,
        "p1_sla": ds.p1_sla,
        "field_mapping": _parse_json(ds.field_mapping),
        "field_mapping_score": ds.field_mapping_score,
        "mandatory_score": ds.mandatory_score,
        "readiness_score": ds.readiness_score,
        "risk_rating": ds.risk_rating,
        "sal_compliance": ds.sal_compliance,
        "field_notes": ds.field_notes,
        "use_case_status": ds.use_case_status,
        "use_case_review_date": ds.use_case_review_date.isoformat() if ds.use_case_review_date else None,
        "use_case_gaps": ds.use_case_gaps,
        "use_case_remediation": ds.use_case_remediation,
        "tide_system_id": ds.tide_system_id,
        "data_namespace": ds.data_namespace,
        "created_at": ds.created_at.isoformat() if ds.created_at else None,
        "updated_at": ds.updated_at.isoformat() if ds.updated_at else None,
    }


def _snap_to_dict(s: CyabSnapshot) -> dict:
    return {
        "id": s.id,
        "system_id": s.system_id,
        "data_source_id": s.data_source_id,
        "snapshot_date": s.snapshot_date.isoformat() if s.snapshot_date else None,
        "readiness_score": s.readiness_score,
        "field_mapping_score": s.field_mapping_score,
        "mandatory_score": s.mandatory_score,
        "risk_rating": s.risk_rating,
        "sal_compliance": s.sal_compliance,
        "status": s.status,
        "total_data_sources": s.total_data_sources,
        "notes": s.notes,
        "created_at": s.created_at.isoformat() if s.created_at else None,
    }


def _system_to_dict(s: CyabSystem, include_sources: bool = False) -> dict:
    d = {
        "id": s.id,
        "name": s.name,
        "department": s.department,
        "department_lead": s.department_lead,
        "soc_team": s.soc_team,
        "soc_lead": s.soc_lead,
        "reference": s.reference,
        "version": s.version,
        "status": s.status,
        "icon": s.icon or "monitor",
        "tags": _parse_json(s.tags) or [],
        "readiness_score": s.readiness_score,
        "field_mapping_score": s.field_mapping_score,
        "mandatory_score": s.mandatory_score,
        "risk_rating": s.risk_rating,
        "sal_compliance": s.sal_compliance,
        "review_cadence_days": s.review_cadence_days,
        "next_review_date": s.next_review_date.isoformat() if s.next_review_date else None,
        "last_reviewed_date": s.last_reviewed_date.isoformat() if s.last_reviewed_date else None,
        "sign_dept_name": s.sign_dept_name,
        "sign_dept_date": s.sign_dept_date.isoformat() if s.sign_dept_date else None,
        "sign_soc_name": s.sign_soc_name,
        "sign_soc_date": s.sign_soc_date.isoformat() if s.sign_soc_date else None,
        "created_by": s.created_by,
        "created_at": s.created_at.isoformat() if s.created_at else None,
        "updated_at": s.updated_at.isoformat() if s.updated_at else None,
        "data_source_count": len(s.data_sources) if s.data_sources else 0,
    }
    if include_sources:
        d["data_sources"] = [_ds_to_dict(ds) for ds in (s.data_sources or [])]
    return d


def _recalc_system_aggregates(sys: CyabSystem):
    """Recalculate aggregate scores from data sources."""
    sources = sys.data_sources or []
    if not sources:
        sys.readiness_score = 0
        sys.field_mapping_score = 0
        sys.mandatory_score = 0
        sys.risk_rating = None
        sys.sal_compliance = None
        return
    n = len(sources)
    sys.readiness_score = round(sum(ds.readiness_score for ds in sources) / n)
    sys.field_mapping_score = round(sum(ds.field_mapping_score for ds in sources) / n)
    sys.mandatory_score = round(sum(ds.mandatory_score for ds in sources) / n)
    # Worst risk across sources
    risk_order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
    worst_risk = max(sources, key=lambda ds: risk_order.get((ds.risk_rating or "").upper(), 0))
    sys.risk_rating = worst_risk.risk_rating
    # SAL compliance: FAIL if any source fails
    sys.sal_compliance = "FAIL" if any(ds.sal_compliance == "FAIL" for ds in sources) else "PASS"


def _create_snapshot(session: Session, sys: CyabSystem, notes: str = None, ds_id: int = None):
    """Create a point-in-time snapshot."""
    snap = CyabSnapshot(
        system_id=sys.id,
        data_source_id=ds_id,
        snapshot_date=date.today(),
        readiness_score=sys.readiness_score,
        field_mapping_score=sys.field_mapping_score,
        mandatory_score=sys.mandatory_score,
        risk_rating=sys.risk_rating,
        sal_compliance=sys.sal_compliance,
        status=sys.status,
        total_data_sources=len(sys.data_sources) if sys.data_sources else 0,
        notes=notes,
    )
    session.add(snap)


# ---------------------------------------------------------------------------
# System routes
# ---------------------------------------------------------------------------

@router.get("/icons")
async def list_icons():
    """Available system icons."""
    return SYSTEM_ICONS


@router.get("/systems", dependencies=[Depends(require_permission("alert:read"))])
async def list_systems(
    session: Session = Depends(get_db_session),
):
    systems = session.execute(
        select(CyabSystem).order_by(CyabSystem.department, CyabSystem.name)
    ).scalars().all()
    return [_system_to_dict(s) for s in systems]


@router.get("/dashboard", dependencies=[Depends(require_permission("alert:read"))])
async def dashboard_metrics(
    session: Session = Depends(get_db_session),
):
    # signoffs_this_week — count CyabSnapshot rows in the last 7 days.
    week_ago = datetime.utcnow() - timedelta(days=7)
    signoffs_this_week = session.execute(
        select(func.count(CyabSnapshot.id))
        .where(CyabSnapshot.created_at >= week_ago)
    ).scalar() or 0

    systems = session.execute(select(CyabSystem)).scalars().all()
    total = len(systems)
    if total == 0:
        return {
            "total_systems": 0, "total_data_sources": 0,
            "avg_readiness": 0, "avg_field_mapping": 0,
            "sal_compliance_pass": 0, "sal_compliance_fail": 0,
            "risk_high": 0, "risk_medium": 0, "risk_low": 0,
            "due_for_review": 0, "overdue": 0,
            "by_department": [], "by_sal_tier": {}, "by_status": {},
            "signoffs_this_week": int(signoffs_this_week),
        }

    today = date.today()
    total_ds = sum(len(s.data_sources) for s in systems)
    avg_readiness = round(sum(s.readiness_score for s in systems) / total)
    avg_fm = round(sum(s.field_mapping_score for s in systems) / total)
    sal_pass = sum(1 for s in systems if s.sal_compliance == "PASS")
    risk_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for s in systems:
        r = (s.risk_rating or "").upper()
        if r in risk_counts:
            risk_counts[r] += 1
    due = sum(1 for s in systems if s.next_review_date and s.next_review_date <= today + timedelta(days=14))
    overdue = sum(1 for s in systems if s.next_review_date and s.next_review_date < today)

    dept_map = {}
    for s in systems:
        d = s.department or "Unknown"
        if d not in dept_map:
            dept_map[d] = {"department": d, "count": 0, "total_readiness": 0, "ds_count": 0}
        dept_map[d]["count"] += 1
        dept_map[d]["total_readiness"] += s.readiness_score
        dept_map[d]["ds_count"] += len(s.data_sources)
    dept_list = []
    for d in dept_map.values():
        d["avg_readiness"] = round(d["total_readiness"] / d["count"]) if d["count"] else 0
        del d["total_readiness"]
        dept_list.append(d)
    dept_list.sort(key=lambda x: x["avg_readiness"])

    # Collect SAL tiers from data sources
    sal_counts = {}
    for s in systems:
        for ds in s.data_sources:
            t = ds.sal_tier or "SAL-2"
            sal_counts[t] = sal_counts.get(t, 0) + 1

    status_counts = {}
    for s in systems:
        st = s.status or "DRAFT"
        status_counts[st] = status_counts.get(st, 0) + 1

    return {
        "total_systems": total, "total_data_sources": total_ds,
        "avg_readiness": avg_readiness, "avg_field_mapping": avg_fm,
        "sal_compliance_pass": sal_pass, "sal_compliance_fail": total - sal_pass,
        "risk_high": risk_counts["HIGH"], "risk_medium": risk_counts["MEDIUM"], "risk_low": risk_counts["LOW"],
        "due_for_review": due, "overdue": overdue,
        "by_department": dept_list, "by_sal_tier": sal_counts, "by_status": status_counts,
        "signoffs_this_week": int(signoffs_this_week),
    }


@router.get("/due-reviews", dependencies=[Depends(require_permission("alert:read"))])
async def due_reviews(session: Session = Depends(get_db_session)):
    today = date.today()
    cutoff = today + timedelta(days=30)
    systems = session.execute(
        select(CyabSystem).where(CyabSystem.next_review_date <= cutoff)
        .order_by(CyabSystem.next_review_date)
    ).scalars().all()
    result = []
    for s in systems:
        d = _system_to_dict(s)
        d["is_overdue"] = s.next_review_date < today if s.next_review_date else False
        d["days_until_review"] = (s.next_review_date - today).days if s.next_review_date else None
        result.append(d)
    return result


@router.post("/systems", dependencies=[Depends(require_permission("alert:read"))])
async def create_system(
    req: SystemCreateRequest,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    sys = CyabSystem(
        name=req.name, department=req.department, department_lead=req.department_lead,
        soc_team=req.soc_team, soc_lead=req.soc_lead, version=req.version,
        status=req.status or "DRAFT", icon=req.icon or "monitor",
        tags=json.dumps(req.tags) if req.tags else None,
        review_cadence_days=req.review_cadence_days or 90,
        sign_dept_name=req.sign_dept_name, sign_soc_name=req.sign_soc_name,
        sign_dept_date=_parse_date(req.sign_dept_date),
        sign_soc_date=_parse_date(req.sign_soc_date),
        created_by=current_user.id,
    )
    if req.next_review_date:
        sys.next_review_date = _parse_date(req.next_review_date)
    else:
        sys.next_review_date = date.today() + timedelta(days=sys.review_cadence_days)

    if not req.reference:
        count = session.execute(select(func.count(CyabSystem.id))).scalar() or 0
        sys.reference = f"SOC-SLA-{date.today().year}-{count + 1:03d}"
    else:
        sys.reference = req.reference

    session.add(sys)
    session.commit()
    session.refresh(sys)
    return _system_to_dict(sys, include_sources=True)


@router.get("/systems/{system_id}", dependencies=[Depends(require_permission("alert:read"))])
async def get_system(system_id: int, session: Session = Depends(get_db_session)):
    sys = session.get(CyabSystem, system_id)
    if not sys:
        raise HTTPException(status_code=404, detail="CyAB system not found")
    return _system_to_dict(sys, include_sources=True)


@router.get("/systems/{system_id}/data-health", dependencies=[Depends(require_permission("alert:read"))])
async def get_data_health(system_id: int, session: Session = Depends(get_db_session)):
    """Aggregate Data Health signals for a system."""
    from ion.services import cyab_data_health_service as dh
    return {
        "system_id":                  system_id,
        "ingestion_freshness":        dh.ingestion_freshness(session, system_id),
        "field_mapping_completeness": dh.field_mapping_completeness(session, system_id),
        "coverage_rollup":            dh.coverage_rollup(session, system_id),
        "reconciliation":             dh.reconciliation_panel(session, system_id),
    }


@router.get("/systems/{system_id}/alert-rollup", dependencies=[Depends(require_permission("alert:read"))])
async def get_system_alert_rollup(
    system_id: int,
    hours: int = 168,
    session: Session = Depends(get_db_session),
):
    """Return alert counts for this CyAB system, scoped to its data sources' namespaces.

    Pulls the namespaces the system owns, queries ES for matching alerts in
    the last `hours` (default 7d), returns total + status + severity breakdowns.
    """
    sys = session.get(CyabSystem, system_id)
    if not sys:
        raise HTTPException(status_code=404, detail="CyAB system not found")

    namespaces = [
        ds.data_namespace for ds in sys.data_sources
        if ds.data_namespace
    ]
    if not namespaces:
        return {
            "system_id": system_id,
            "namespaces": [],
            "total": 0,
            "by_status": {},
            "by_severity": {},
            "by_namespace": {},
            "hours": hours,
            "message": "No data namespaces configured on this system's data sources",
        }

    config = get_elasticsearch_config()
    if not config.get("enabled"):
        return {
            "system_id": system_id,
            "namespaces": namespaces,
            "total": 0,
            "by_status": {},
            "by_severity": {},
            "by_namespace": {},
            "hours": hours,
            "message": "Elasticsearch integration is not enabled",
        }

    es = ElasticsearchService()
    if not es.is_configured:
        return {
            "system_id": system_id,
            "namespaces": namespaces,
            "total": 0,
            "by_status": {},
            "by_severity": {},
            "by_namespace": {},
            "hours": hours,
            "message": "Elasticsearch is not configured",
        }

    try:
        rollup = await es.get_alert_rollup_for_namespaces(namespaces, hours=hours)
    except Exception as e:
        return {
            "system_id": system_id,
            "namespaces": namespaces,
            "total": 0,
            "by_status": {},
            "by_severity": {},
            "by_namespace": {},
            "hours": hours,
            "error": safe_error(e, "alert_rollup"),
        }

    return {
        "system_id": system_id,
        "namespaces": namespaces,
        **rollup,
    }


@router.put("/systems/{system_id}", dependencies=[Depends(require_permission("alert:read"))])
async def update_system(
    system_id: int, req: SystemUpdateRequest,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    sys = session.get(CyabSystem, system_id)
    if not sys:
        raise HTTPException(status_code=404, detail="CyAB system not found")

    data = req.model_dump(exclude_none=True)
    for f in ["name", "department", "department_lead", "soc_team", "soc_lead",
              "reference", "version", "status", "icon", "review_cadence_days",
              "sign_dept_name", "sign_soc_name"]:
        if f in data:
            setattr(sys, f, data[f])
    if "tags" in data:
        sys.tags = json.dumps(data["tags"]) if data["tags"] else None
    for df in ["next_review_date", "sign_dept_date", "sign_soc_date"]:
        if df in data:
            setattr(sys, df, _parse_date(data[df]))
    if "review_cadence_days" in data and "next_review_date" not in data:
        base = sys.last_reviewed_date or date.today()
        sys.next_review_date = base + timedelta(days=sys.review_cadence_days)

    # Take a snapshot on status change
    old_status = sys.status
    session.commit()
    session.refresh(sys)
    if "status" in data and data["status"] != old_status:
        _create_snapshot(session, sys, notes=f"Status changed to {data['status']}")
        session.commit()

    return _system_to_dict(sys, include_sources=True)


@router.delete("/systems/{system_id}", dependencies=[Depends(require_permission("case:close"))])
async def delete_system(system_id: int, session: Session = Depends(get_db_session)):
    sys = session.get(CyabSystem, system_id)
    if not sys:
        raise HTTPException(status_code=404, detail="CyAB system not found")
    # Clear snapshot FK references to data sources before cascade delete
    from sqlalchemy import update
    session.execute(
        update(CyabSnapshot)
        .where(CyabSnapshot.system_id == system_id)
        .values(data_source_id=None)
    )
    session.delete(sys)
    session.commit()
    return {"ok": True, "deleted": system_id}


@router.post("/systems/{system_id}/mark-reviewed", dependencies=[Depends(require_permission("alert:read"))])
async def mark_reviewed(
    system_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    sys = session.get(CyabSystem, system_id)
    if not sys:
        raise HTTPException(status_code=404, detail="CyAB system not found")
    sys.last_reviewed_date = date.today()
    sys.next_review_date = date.today() + timedelta(days=sys.review_cadence_days)
    _create_snapshot(session, sys, notes="Quarterly review completed")
    session.commit()
    session.refresh(sys)
    return _system_to_dict(sys, include_sources=True)


# ---------------------------------------------------------------------------
# Data source routes
# ---------------------------------------------------------------------------

@router.get("/systems/{system_id}/sources", dependencies=[Depends(require_permission("alert:read"))])
async def list_data_sources(system_id: int, session: Session = Depends(get_db_session)):
    sys = session.get(CyabSystem, system_id)
    if not sys:
        raise HTTPException(status_code=404, detail="CyAB system not found")
    return [_ds_to_dict(ds) for ds in sys.data_sources]


@router.post("/systems/{system_id}/sources", dependencies=[Depends(require_permission("alert:read"))])
async def create_data_source(
    system_id: int, req: DataSourceRequest,
    session: Session = Depends(get_db_session),
):
    sys = session.get(CyabSystem, system_id)
    if not sys:
        raise HTTPException(status_code=404, detail="CyAB system not found")

    ds = CyabDataSource(
        system_id=system_id, name=req.name,
        data_source_type=req.data_source_type, icon=req.icon,
        sal_tier=req.sal_tier or "SAL-2",
        uptime_target=req.uptime_target, max_latency=req.max_latency,
        retention=req.retention, p1_sla=req.p1_sla,
        field_mapping=json.dumps(req.field_mapping) if req.field_mapping else None,
        field_mapping_score=req.field_mapping_score or 0,
        mandatory_score=req.mandatory_score or 0,
        readiness_score=req.readiness_score or 0,
        risk_rating=req.risk_rating, sal_compliance=req.sal_compliance,
        field_notes=req.field_notes, use_case_status=req.use_case_status,
        use_case_review_date=_parse_date(req.use_case_review_date),
        use_case_gaps=req.use_case_gaps, use_case_remediation=req.use_case_remediation,
        tide_system_id=req.tide_system_id,
        # ES data_stream.namespace is always lowercase — normalise on save
        # so CyAB-to-ES matching never fails on case mismatch.
        data_namespace=(req.data_namespace or "").strip().lower() or None,
    )
    session.add(ds)
    session.flush()

    # Recalculate system aggregates
    session.refresh(sys)
    _recalc_system_aggregates(sys)
    _create_snapshot(session, sys, notes=f"Data source added: {req.name}", ds_id=ds.id)
    session.commit()
    session.refresh(ds)
    # Drop the alert→system resolver cache so the new mapping appears immediately
    from ion.services.system_resolver_service import invalidate as _invalidate_resolver
    _invalidate_resolver()
    return _ds_to_dict(ds)


@router.get("/sources/{source_id}", dependencies=[Depends(require_permission("alert:read"))])
async def get_data_source(source_id: int, session: Session = Depends(get_db_session)):
    ds = session.get(CyabDataSource, source_id)
    if not ds:
        raise HTTPException(status_code=404, detail="Data source not found")
    return _ds_to_dict(ds)


@router.put("/sources/{source_id}", dependencies=[Depends(require_permission("alert:read"))])
async def update_data_source(
    source_id: int, req: DataSourceUpdateRequest,
    session: Session = Depends(get_db_session),
):
    ds = session.get(CyabDataSource, source_id)
    if not ds:
        raise HTTPException(status_code=404, detail="Data source not found")

    data = req.model_dump(exclude_none=True)
    # Normalise namespace to lowercase (ES enforces lowercase).
    if "data_namespace" in data and data["data_namespace"]:
        data["data_namespace"] = data["data_namespace"].strip().lower()
    for f in ["name", "data_source_type", "icon", "sal_tier", "uptime_target",
              "max_latency", "retention", "p1_sla", "field_mapping_score",
              "mandatory_score", "readiness_score", "risk_rating", "sal_compliance",
              "field_notes", "use_case_status", "use_case_gaps", "use_case_remediation",
              "tide_system_id", "data_namespace"]:
        if f in data:
            setattr(ds, f, data[f])
    if "field_mapping" in data:
        ds.field_mapping = json.dumps(data["field_mapping"]) if data["field_mapping"] else None
    if "use_case_review_date" in data:
        ds.use_case_review_date = _parse_date(data["use_case_review_date"])

    # Recalculate parent system aggregates
    sys = ds.system
    session.flush()
    session.refresh(sys)
    _recalc_system_aggregates(sys)
    _create_snapshot(session, sys, notes=f"Data source updated: {ds.name}", ds_id=ds.id)
    session.commit()
    session.refresh(ds)
    # Drop the alert→system resolver cache (data_namespace/tide_system_id may have changed)
    from ion.services.system_resolver_service import invalidate as _invalidate_resolver
    _invalidate_resolver()
    return _ds_to_dict(ds)


@router.delete("/sources/{source_id}", dependencies=[Depends(require_permission("case:close"))])
async def delete_data_source(source_id: int, session: Session = Depends(get_db_session)):
    ds = session.get(CyabDataSource, source_id)
    if not ds:
        raise HTTPException(status_code=404, detail="Data source not found")
    sys = ds.system
    name = ds.name
    # Clear snapshot FK references to this data source
    from sqlalchemy import update
    session.execute(
        update(CyabSnapshot)
        .where(CyabSnapshot.data_source_id == source_id)
        .values(data_source_id=None)
    )
    session.delete(ds)
    session.flush()
    session.refresh(sys)
    _recalc_system_aggregates(sys)
    _create_snapshot(session, sys, notes=f"Data source removed: {name}")
    session.commit()
    # Drop the alert→system resolver cache (mapping no longer exists)
    from ion.services.system_resolver_service import invalidate as _invalidate_resolver
    _invalidate_resolver()
    return {"ok": True, "deleted": source_id}


# ---------------------------------------------------------------------------
# History / Snapshots
# ---------------------------------------------------------------------------

@router.get("/systems/{system_id}/history", dependencies=[Depends(require_permission("alert:read"))])
async def get_system_history(system_id: int, session: Session = Depends(get_db_session)):
    sys = session.get(CyabSystem, system_id)
    if not sys:
        raise HTTPException(status_code=404, detail="CyAB system not found")
    snaps = session.execute(
        select(CyabSnapshot).where(CyabSnapshot.system_id == system_id)
        .order_by(CyabSnapshot.snapshot_date.desc(), CyabSnapshot.id.desc())
    ).scalars().all()
    return [_snap_to_dict(s) for s in snaps]


# ---------------------------------------------------------------------------
# TIDE integration endpoints
# ---------------------------------------------------------------------------

@router.get("/tide/status", dependencies=[Depends(require_permission("alert:read"))])
def tide_status():
    """Check TIDE connection and return basic stats."""
    svc = get_tide_service()
    return svc.test_connection()


@router.get("/tide/mitre-coverage", dependencies=[Depends(require_permission("alert:read"))])
def tide_global_mitre_coverage():
    """Get global MITRE ATT&CK coverage from TIDE (all systems combined)."""
    svc = get_tide_service()
    result = svc.get_global_mitre_coverage()
    if result is None:
        return {"enabled": False}
    result["enabled"] = True
    return result


@router.get("/tide/systems", dependencies=[Depends(require_permission("alert:read"))])
def tide_systems():
    """List all systems from TIDE."""
    svc = get_tide_service()
    return svc.get_systems()


@router.get("/tide/systems/{system_id}", dependencies=[Depends(require_permission("alert:read"))])
def tide_system_detail(system_id: str):
    """Get TIDE system with its applied detection rules."""
    svc = get_tide_service()
    detail = svc.get_system_detail(system_id)
    if not detail:
        raise HTTPException(status_code=404, detail="TIDE system not found")
    return detail


@router.get("/tide/systems/{system_id}/mitre", dependencies=[Depends(require_permission("alert:read"))])
def tide_system_mitre(system_id: str):
    """Get MITRE ATT&CK coverage for a TIDE system."""
    svc = get_tide_service()
    return svc.get_mitre_coverage(system_id)


@router.get("/tide/systems/{system_id}/use-cases", dependencies=[Depends(require_permission("alert:read"))])
def tide_system_use_cases(system_id: str):
    """Per-use-case (TIDE playbook) detection coverage scoped to one system.

    For each TIDE playbook, walks each step's MITRE techniques and checks
    whether any rule applied to THIS system covers them. Used by the CyAB
    review document and the inline coverage panel.
    """
    svc = get_tide_service()
    if not svc.enabled:
        raise HTTPException(status_code=503, detail="TIDE not configured")
    result = svc.get_system_use_case_coverage(system_id)
    if result is None:
        raise HTTPException(status_code=502, detail="Failed to query TIDE")
    return result


@router.get("/tide/rules", dependencies=[Depends(require_permission("alert:read"))])
def tide_rules(search: str = "", limit: int = 50):
    """Search TIDE detection rules."""
    svc = get_tide_service()
    return svc.get_detection_rules(search=search, limit=min(limit, 200))


@router.get("/tide/systems/{system_id}/alerts", dependencies=[Depends(require_permission("alert:read"))])
async def tide_system_alerts(system_id: str, namespace: str = "", hours: int = 168):
    """Cross-reference TIDE detection rules with ES alerts for a namespace.

    Elasticsearch data_stream.namespace is always lowercase (ES enforces this).
    CyAB data sources may store the namespace with mixed case (e.g. 'EndpointFleet').
    We normalise to lowercase before querying so the match always works.

    Returns which TIDE rules are actively firing (have matching alerts),
    which are silent, and overall alert statistics.
    """
    from ion.services.elasticsearch_service import ElasticsearchService

    # 1. Get TIDE system's applied detection rules
    tide_svc = get_tide_service()
    detail = tide_svc.get_system_detail(system_id)
    if not detail:
        raise HTTPException(status_code=404, detail="TIDE system not found")

    tide_rules_map = {}
    for d in (detail.get("detections") or []):
        rule_name = (d.get("name") or "").strip()
        if rule_name:
            tide_rules_map[rule_name.lower()] = d

    # Normalise to lowercase — ES data_stream.namespace is always lowercase
    # but CyAB data sources may store mixed case (e.g. "EndpointFleet").
    namespace = (namespace or "").strip().lower()

    if not namespace:
        return {
            "error": "No namespace specified — set the data namespace on this data source to map alerts",
            "tide_rules": len(tide_rules_map),
            "firing_rules": [],
            "silent_rules": list(tide_rules_map.values()),
            "unmatched_alerts": [],
            "alert_stats": {},
        }

    # 2. Query ES for alerts matching this namespace
    es = ElasticsearchService()
    if not es.is_configured:
        return {
            "error": "Elasticsearch not configured",
            "tide_rules": len(tide_rules_map),
            "firing_rules": [],
            "silent_rules": list(tide_rules_map.values()),
            "unmatched_alerts": [],
            "alert_stats": {},
        }

    # Fast-fail if the ES circuit breaker is open (avoids noisy connection
    # errors in the system logs when ES is known to be offline).
    from ion.core.circuit_breaker import es_breaker
    if not es_breaker.can_execute():
        return {
            "error": "Elasticsearch temporarily unavailable (circuit breaker open)",
            "tide_rules": len(tide_rules_map),
            "firing_rules": [],
            "silent_rules": list(tide_rules_map.values()),
            "unmatched_alerts": [],
            "alert_stats": {},
        }

    query = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": f"now-{hours}h", "lte": "now"}}},
                    {"term": {"data_stream.namespace": namespace}},
                ],
                "must_not": [
                    {"term": {"kibana.alert.building_block_type": "default"}}
                ]
            }
        },
        "aggs": {
            "by_rule": {
                "terms": {"field": "kibana.alert.rule.name", "size": 500},
                "aggs": {
                    "by_severity": {
                        "terms": {"field": "kibana.alert.severity", "size": 5}
                    },
                    "by_status": {
                        "terms": {"field": "kibana.alert.workflow_status", "size": 5}
                    },
                    "latest": {
                        "max": {"field": "@timestamp"}
                    },
                    "by_mitre": {
                        "terms": {"field": "threat.technique.id", "size": 20}
                    }
                }
            },
            "total_by_severity": {
                "terms": {"field": "kibana.alert.severity", "size": 10}
            },
            "total_by_status": {
                "terms": {"field": "kibana.alert.workflow_status", "size": 10}
            },
            "over_time": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": "6h" if hours <= 168 else "1d",
                    "min_doc_count": 0,
                    "extended_bounds": {"min": f"now-{hours}h", "max": "now"}
                }
            }
        }
    }

    try:
        pattern = es.alert_index
        encoded = pattern.replace(",", "%2C")
        result = await es._request("POST", f"/{encoded}/_search", json=query)
    except Exception as e:
        return {
            "error": f"ES query failed: {safe_error(e, 'cyab_es_query')}",
            "tide_rules": len(tide_rules_map),
            "firing_rules": [],
            "silent_rules": list(tide_rules_map.values()),
            "unmatched_alerts": [],
            "alert_stats": {},
        }

    total = result.get("hits", {}).get("total", {})
    if isinstance(total, dict):
        total = total.get("value", 0)

    aggs = result.get("aggregations", {})
    rule_buckets = aggs.get("by_rule", {}).get("buckets", [])

    # 3. Cross-reference: match ES alert rule names to TIDE rule names
    firing_rules = []
    matched_tide_keys = set()
    unmatched_alerts = []

    for b in rule_buckets:
        alert_rule = b["key"]
        alert_count = b["doc_count"]
        severity_map = {sb["key"]: sb["doc_count"] for sb in b.get("by_severity", {}).get("buckets", [])}
        status_map = {sb["key"]: sb["doc_count"] for sb in b.get("by_status", {}).get("buckets", [])}
        latest = b.get("latest", {}).get("value_as_string")
        mitre_ids = [mb["key"] for mb in b.get("by_mitre", {}).get("buckets", [])]

        tide_key = alert_rule.strip().lower()
        if tide_key in tide_rules_map:
            tide_rule = tide_rules_map[tide_key]
            matched_tide_keys.add(tide_key)
            firing_rules.append({
                "rule_name": alert_rule,
                "alert_count": alert_count,
                "severity": severity_map,
                "status": status_map,
                "latest_alert": latest,
                "mitre_ids": mitre_ids,
                "tide_rule_id": tide_rule.get("rule_id"),
                "tide_severity": tide_rule.get("severity"),
                "tide_enabled": tide_rule.get("enabled"),
                "tide_quality": tide_rule.get("quality_score"),
                "matched": True,
            })
        else:
            unmatched_alerts.append({
                "rule_name": alert_rule,
                "alert_count": alert_count,
                "severity": severity_map,
                "status": status_map,
                "latest_alert": latest,
                "mitre_ids": mitre_ids,
                "matched": False,
            })

    # 4. Silent rules — TIDE rules that have no matching alerts
    silent_rules = []
    for key, rule in tide_rules_map.items():
        if key not in matched_tide_keys:
            silent_rules.append(rule)

    # Sort: firing by count desc, silent by severity
    firing_rules.sort(key=lambda r: r["alert_count"], reverse=True)
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    silent_rules.sort(key=lambda r: sev_order.get((r.get("severity") or "low").lower(), 5))

    # Overall stats
    total_severity = {sb["key"]: sb["doc_count"] for sb in aggs.get("total_by_severity", {}).get("buckets", [])}
    total_status = {sb["key"]: sb["doc_count"] for sb in aggs.get("total_by_status", {}).get("buckets", [])}
    timeline = [{"timestamp": tb["key_as_string"], "count": tb["doc_count"]}
                for tb in aggs.get("over_time", {}).get("buckets", [])]

    return {
        "namespace": namespace,
        "hours": hours,
        "total_alerts": total,
        "tide_rules": len(tide_rules_map),
        "firing_count": len(firing_rules),
        "silent_count": len(silent_rules),
        "unmatched_count": len(unmatched_alerts),
        "firing_rules": firing_rules,
        "silent_rules": silent_rules,
        "unmatched_alerts": unmatched_alerts,
        "alert_stats": {
            "severity": total_severity,
            "status": total_status,
            "timeline": timeline,
        },
    }


# ---------------------------------------------------------------------------
# Detection Engineering endpoints (TIDE-powered, snapshot-backed)
#
# Every DE endpoint first checks for a pre-built snapshot in PostgreSQL
# (populated by the TIDE background sync worker). If a fresh snapshot
# exists, the response is instant (<10 ms from Postgres). If no
# snapshot exists (first startup, or sync disabled), it falls back to
# a live TIDE query.
# ---------------------------------------------------------------------------

def _snapshot_or_live(session: Session, snapshot_key: str, live_fn, live_kwargs: dict = {}):
    """Try the snapshot cache first. Fall back to a live TIDE query."""
    from ion.services.tide_sync_service import get_snapshot
    cached = get_snapshot(session, snapshot_key)
    if cached is not None:
        return cached
    # No snapshot — fall through to live TIDE query.
    return live_fn(**live_kwargs)


@router.get("/tide/de/spaces", dependencies=[Depends(require_permission("alert:read"))])
def tide_de_spaces():
    """List available SIEM spaces from TIDE detection_rules.

    Returns the distinct space values and rule counts so the UI can
    offer a space selector dropdown. The currently active space is
    also included.
    """
    svc = get_tide_service()
    if not svc.enabled:
        return {"spaces": [], "active": "default"}
    spaces = svc.get_available_spaces()
    return {"spaces": spaces, "active": svc.space}


@router.post("/tide/de/spaces/{space}", dependencies=[Depends(require_permission("alert:read"))])
def tide_de_set_space(space: str):
    """Switch the active TIDE space filter.

    All subsequent TIDE queries will filter by this space value.
    """
    svc = get_tide_service()
    if not svc.enabled:
        return {"ok": False, "error": "TIDE not configured"}
    svc.set_space(space)
    return {"ok": True, "active": space}


@router.get("/tide/de/sync-status", dependencies=[Depends(require_permission("alert:read"))])
def tide_de_sync_status(session: Session = Depends(get_db_session)):
    """Return the health / freshness of the TIDE snapshot cache."""
    from ion.services.tide_sync_service import get_sync_status
    return get_sync_status(session)


@router.post("/tide/de/sync-now", dependencies=[Depends(require_permission("integration:manage"))])
def tide_de_sync_now(session: Session = Depends(get_db_session)):
    """Manually trigger an immediate TIDE sync (admin/engineering only)."""
    from ion.services.tide_sync_service import sync_all
    return sync_all(session)


@router.get("/tide/de/systems", dependencies=[Depends(require_permission("alert:read"))])
def tide_de_systems(session: Session = Depends(get_db_session)):
    """List all TIDE systems (for dropdown selectors)."""
    return _snapshot_or_live(session, "systems", get_tide_service().get_systems)


@router.get("/tide/de/posture", dependencies=[Depends(require_permission("alert:read"))])
def tide_de_posture(session: Session = Depends(get_db_session)):
    """Detection posture overview — totals, severity, quality, coverage."""
    result = _snapshot_or_live(session, "posture", get_tide_service().get_posture_stats)
    if result is None:
        return {"enabled": False}
    if isinstance(result, dict):
        result["enabled"] = True
    return result


@router.get("/tide/de/disabled-critical", dependencies=[Depends(require_permission("alert:read"))])
def tide_de_disabled_critical(session: Session = Depends(get_db_session)):
    """Disabled critical/high severity rules."""
    return _snapshot_or_live(session, "disabled_critical", get_tide_service().get_disabled_critical_high)


@router.get("/tide/de/use-cases", dependencies=[Depends(require_permission("alert:read"))])
def tide_de_use_cases(session: Session = Depends(get_db_session)):
    """TIDE playbooks (use cases) with steps + per-technique detection coverage."""
    return _snapshot_or_live(session, "use_cases", get_tide_service().get_playbooks_with_kill_chains)


# Deprecated alias — kept for backwards compatibility with older clients.
@router.get("/tide/de/kill-chains", dependencies=[Depends(require_permission("alert:read"))])
def tide_de_kill_chains_alias(session: Session = Depends(get_db_session)):
    """Deprecated: use /tide/de/use-cases. Same response shape."""
    return _snapshot_or_live(session, "use_cases", get_tide_service().get_playbooks_with_kill_chains)


@router.get("/tide/de/navigator-layer", dependencies=[Depends(require_permission("alert:read"))])
def tide_de_navigator_layer():
    """Export the live TIDE coverage as a MITRE ATT&CK Navigator layer file.

    Returns a downloadable JSON layer compatible with
    https://mitre-attack.github.io/attack-navigator/. Each technique is
    annotated with the number of enabled / total TIDE rules and a heat-map
    colour. Auditors and red teams can drop the file straight into Navigator.
    """
    import json
    from datetime import datetime

    from fastapi.responses import Response

    svc = get_tide_service()
    if not svc.enabled:
        raise HTTPException(status_code=503, detail="TIDE not configured")

    coverage = svc.get_global_mitre_coverage()
    if not coverage:
        raise HTTPException(status_code=502, detail="TIDE returned no coverage data")

    techniques_data = coverage.get("techniques", {}) or {}

    # Score: 0 (blind) → 4 (excellent). Used as Navigator's `score`.
    def _score(rule_count: int, enabled: int) -> int:
        if enabled <= 0:
            return 0
        if rule_count >= 5 and enabled >= 3:
            return 4
        if rule_count >= 3 and enabled >= 2:
            return 3
        if enabled >= 1:
            return 2
        return 1

    nav_techniques = []
    for tid, info in techniques_data.items():
        if not isinstance(info, dict):
            continue
        rule_count = int(info.get("rule_count") or 0)
        enabled_rules = int(info.get("enabled_rules") or 0)
        sev = info.get("severity") or {}
        comment_parts = [
            f"{enabled_rules}/{rule_count} enabled rules",
        ]
        if sev:
            sev_summary = ", ".join(
                f"{k}:{v}" for k, v in sev.items() if v
            )
            if sev_summary:
                comment_parts.append(sev_summary)
        systems = info.get("systems") or []
        if systems:
            comment_parts.append(
                f"systems: {', '.join(s.get('name', '') for s in systems[:3])}"
                + (" ..." if len(systems) > 3 else "")
            )
        nav_techniques.append({
            "techniqueID": tid,
            "score": _score(rule_count, enabled_rules),
            "comment": " · ".join(comment_parts),
            "enabled": True,
            "metadata": [
                {"name": "rule_count", "value": str(rule_count)},
                {"name": "enabled_rules", "value": str(enabled_rules)},
                {"name": "avg_quality", "value": str(info.get("avg_quality") or "")},
            ],
        })

    layer = {
        "name": f"ION TIDE Coverage ({svc.space})",
        "versions": {
            "attack": "14",
            "navigator": "5.0.0",
            "layer": "4.5",
        },
        "domain": "enterprise-attack",
        "description": (
            f"Live coverage from ION at {datetime.utcnow().isoformat()}Z. "
            f"{len(nav_techniques)} techniques mapped from TIDE space '{svc.space}'."
        ),
        "filters": {
            "platforms": [
                "Windows", "Linux", "macOS", "Network", "PRE", "Containers",
                "Office 365", "SaaS", "Google Workspace", "IaaS", "Azure AD",
            ],
        },
        "sorting": 0,
        "layout": {"layout": "side", "showName": True, "showID": False},
        "hideDisabled": False,
        "techniques": nav_techniques,
        "gradient": {
            "colors": ["#ff6666", "#ffe766", "#8ec843"],
            "minValue": 0,
            "maxValue": 4,
        },
        "legendItems": [
            {"label": "Blind", "color": "#ff6666"},
            {"label": "Partial", "color": "#ffe766"},
            {"label": "Covered", "color": "#8ec843"},
        ],
        "metadata": [
            {"name": "Source", "value": "ION Detection Engineering"},
            {"name": "Space", "value": svc.space},
        ],
    }

    body = json.dumps(layer, indent=2)
    filename = f"ion-tide-coverage-{svc.space}-{datetime.utcnow().strftime('%Y%m%d')}.json"
    return Response(
        content=body,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.get("/tide/de/rules", dependencies=[Depends(require_permission("alert:read"))])
def tide_de_rules(search: str = "", severity: str = "", enabled: str = "",
                  offset: int = 0, limit: int = 50):
    """Paginated detection rule browser."""
    svc = get_tide_service()
    return svc.get_rules_paginated(
        search=search, severity=severity, enabled=enabled,
        offset=offset, limit=min(limit, 200),
    )


@router.get("/tide/de/gaps", dependencies=[Depends(require_permission("alert:read"))])
def tide_de_gaps(session: Session = Depends(get_db_session)):
    """Gap analysis — blind spots by tactic, unmapped rules, quick wins."""
    result = _snapshot_or_live(session, "gaps", get_tide_service().get_gaps_analysis)
    if result is None:
        return {"enabled": False}
    if isinstance(result, dict):
        result["enabled"] = True
    return result


class ReadinessReportRequest(BaseModel):
    system_id: Optional[str] = None  # TIDE system UUID or CyAB int ID
    actor_id: str
    actor_type: str = "threat_actor"
    generate_ai: bool = False


@router.post("/tide/de/system-readiness", dependencies=[Depends(require_permission("alert:read"))])
async def tide_de_system_readiness(req: ReadinessReportRequest, session: Session = Depends(get_db_session)):
    """Per-system detection readiness against a specific threat actor.

    Cross-references CyAB system → TIDE applied rules → actor TTPs from OpenCTI.
    """
    from ion.services.opencti_service import get_opencti_service

    tide_svc = get_tide_service()
    if not tide_svc.enabled:
        return {"enabled": False, "error": "TIDE not configured"}

    opencti = get_opencti_service()
    if not opencti.is_configured:
        return {"enabled": False, "error": "OpenCTI not configured"}

    # 1. Get actor detail from OpenCTI
    try:
        actor = await opencti.get_entity_detail(req.actor_id, req.actor_type)
    except Exception as e:
        return {"enabled": True, "error": f"OpenCTI failed: {safe_error(e, 'cyab_opencti')}"}
    if not actor:
        raise HTTPException(status_code=404, detail="Threat actor not found")

    ttps = actor.get("ttps", [])
    ttp_map = {}
    for t in ttps:
        mid = t.get("mitre_id") or ""
        if mid:
            ttp_map[mid] = t
            parent = mid.split(".")[0]
            if parent != mid:
                ttp_map.setdefault(parent, t)

    # 2. Get TIDE global coverage for fallback
    global_cov = tide_svc.get_global_mitre_coverage()
    global_techs = global_cov.get("techniques", {}) if global_cov else {}

    # 3. If a system is specified, get per-system TIDE rules
    #    Accepts either a TIDE system UUID or a CyAB integer system ID
    system_info = None
    system_rules = []
    system_technique_ids = set()
    if req.system_id:
        # Try as TIDE system UUID first
        tide_detail = tide_svc.get_system_detail(req.system_id)
        if tide_detail:
            system_info = {"name": tide_detail["name"], "classification": tide_detail.get("classification", "")}
            for d in (tide_detail.get("detections") or []):
                system_rules.append(d)
                for mid in (d.get("mitre_ids") or []):
                    system_technique_ids.add(mid)
                    system_technique_ids.add(mid.split(".")[0])
        else:
            # Fall back to CyAB system ID (integer)
            try:
                cyab_id = int(req.system_id)
                cyab_sys = session.get(CyabSystem, cyab_id)
            except (ValueError, TypeError):
                cyab_sys = None
            if cyab_sys:
                system_info = _system_to_dict(cyab_sys, include_sources=True)
                for ds in (cyab_sys.data_sources or []):
                    if ds.tide_system_id:
                        detail = tide_svc.get_system_detail(ds.tide_system_id)
                        if detail:
                            for d in (detail.get("detections") or []):
                                system_rules.append(d)
                                for mid in (d.get("mitre_ids") or []):
                                    system_technique_ids.add(mid)
                                    system_technique_ids.add(mid.split(".")[0])

    # 4. Build readiness matrix
    coverage_matrix = []
    covered_count = 0
    gap_count = 0
    for mid, ttp in ttp_map.items():
        if "." in mid:
            continue  # skip sub-technique duplicates, use parent

        parent = mid.split(".")[0]
        # Check system-specific coverage first, then global
        if req.system_id and system_rules:
            has_rules = parent in system_technique_ids or mid in system_technique_ids
            matching_rules = [r for r in system_rules
                              if mid in (r.get("mitre_ids") or [])
                              or parent in (r.get("mitre_ids") or [])]
            rule_count = len(matching_rules)
            enabled_count = sum(1 for r in matching_rules if r.get("enabled"))
        else:
            gt = global_techs.get(parent) or global_techs.get(mid)
            has_rules = gt is not None and gt.get("rule_count", 0) > 0
            rule_count = gt["rule_count"] if gt else 0
            enabled_count = gt.get("enabled_rules", 0) if gt else 0
            matching_rules = []

        entry = {
            "mitre_id": mid,
            "name": ttp.get("name", ""),
            "covered": has_rules,
            "rule_count": rule_count,
            "enabled_rules": enabled_count,
        }
        if has_rules:
            covered_count += 1
        else:
            gap_count += 1
        coverage_matrix.append(entry)

    coverage_matrix.sort(key=lambda x: (not x["covered"], x["mitre_id"]))
    total_ttps = covered_count + gap_count
    readiness_pct = round(covered_count / total_ttps * 100) if total_ttps else 0

    # 5. Optional AI-generated content
    ai_summary = None
    ai_recommendations = None
    if req.generate_ai:
        try:
            from ion.services.ollama_service import get_ollama_service
            ollama = get_ollama_service()
            if ollama.is_available:
                actor_name = actor.get("name", "Unknown")
                sys_name = system_info["name"] if system_info else "All Systems"
                gap_names = [e["mitre_id"] + " " + e["name"] for e in coverage_matrix if not e["covered"]]

                summary_prompt = (
                    f"Write a concise executive summary (3-4 sentences) for a detection readiness assessment. "
                    f"The organisation is assessing detection coverage against threat actor '{actor_name}'. "
                    f"System: '{sys_name}'. "
                    f"Coverage: {covered_count}/{total_ttps} TTPs ({readiness_pct}%). "
                    f"Detection gaps: {', '.join(gap_names[:10])}. "
                    f"Write in a professional, formal tone suitable for a security report. No markdown."
                )
                ai_summary = await ollama.generate(summary_prompt, temperature=0.4)

                rec_prompt = (
                    f"Write 3-5 prioritised recommendations to improve detection coverage against '{actor_name}'. "
                    f"Current coverage is {readiness_pct}% ({covered_count}/{total_ttps} TTPs). "
                    f"Key gaps: {', '.join(gap_names[:8])}. "
                    f"Focus on actionable steps: enabling disabled rules, writing new detections, deploying sensors. "
                    f"Write as numbered list in professional tone. No markdown formatting."
                )
                ai_recommendations = await ollama.generate(rec_prompt, temperature=0.4)
        except Exception as e:
            ai_summary = f"AI generation failed: {safe_error(e, 'cyab_ai_summary')}"

    return {
        "enabled": True,
        "actor": {
            "id": actor.get("id"),
            "name": actor.get("name"),
            "description": (actor.get("description") or "")[:500],
            "aliases": actor.get("aliases") or [],
            "labels": actor.get("labels") or [],
        },
        "system": system_info,
        "readiness_pct": readiness_pct,
        "covered_count": covered_count,
        "gap_count": gap_count,
        "total_ttps": total_ttps,
        "coverage_matrix": coverage_matrix,
        "ai_summary": ai_summary,
        "ai_recommendations": ai_recommendations,
    }


@router.post("/tide/de/readiness-pdf", dependencies=[Depends(require_permission("alert:read"))])
async def tide_de_readiness_pdf(req: ReadinessReportRequest, session: Session = Depends(get_db_session)):
    """Generate a professional PDF report for threat actor detection readiness."""
    import html as html_mod

    from fastapi.responses import Response

    # Reuse the readiness computation
    req.generate_ai = True  # Always generate AI content for PDF
    data = await tide_de_system_readiness(req, session)
    if not data.get("enabled"):
        raise HTTPException(status_code=400, detail=data.get("error", "Not configured"))

    actor = data["actor"]
    system = data.get("system")
    matrix = data["coverage_matrix"]
    # Wrap html.escape so it accepts ints/None and always returns a string,
    # making it impossible for raw values from `req`/OpenCTI/TIDE to land in
    # the HTML output without being escaped first.
    def h(v) -> str:
        return html_mod.escape("" if v is None else str(v), quote=True)

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M")
    sys_name = system["name"] if system else "All Systems (Global)"

    # Coerce numeric width through int() so it can never be poisoned upstream.
    readiness_width = max(0, min(100, int(data.get('readiness_pct') or 0)))

    # Build HTML body — every interpolated value goes through h()
    body = f"""
    <h2>Executive Summary</h2>
    <p>{h(data.get('ai_summary') or 'AI summary not available.')}</p>

    <div class="readiness-gauge">
        <h3>Overall Readiness: {h(data['readiness_pct'])}%</h3>
        <div class="gauge-bar">
            <div class="gauge-fill" style="width:{readiness_width}%"></div>
        </div>
        <table class="pdf-meta">
            <tr><td>Covered Techniques</td><td>{h(data['covered_count'])} of {h(data['total_ttps'])}</td></tr>
            <tr><td>Detection Gaps</td><td>{h(data['gap_count'])}</td></tr>
        </table>
    </div>

    <h2>Threat Actor Profile</h2>
    <table class="pdf-meta">
        <tr><td>Name</td><td><strong>{h(actor['name'])}</strong></td></tr>
        <tr><td>Aliases</td><td>{h(', '.join(actor.get('aliases', [])[:8]) or 'None known')}</td></tr>
        <tr><td>Known TTPs</td><td>{h(data['total_ttps'])}</td></tr>
    </table>
    {f'<p>{h(actor.get("description", ""))}</p>' if actor.get('description') else ''}

    <h2>System Under Assessment</h2>
    <table class="pdf-meta">
        <tr><td>System</td><td><strong>{h(sys_name)}</strong></td></tr>
    """
    if system:
        body += f"""
        <tr><td>Department</td><td>{h(system.get('department', '-'))}</td></tr>
        <tr><td>Status</td><td>{h(system.get('status', '-'))}</td></tr>
        <tr><td>Data Sources</td><td>{h(system.get('data_source_count', 0))}</td></tr>
        <tr><td>Readiness Score</td><td>{h(system.get('readiness_score', 0))}%</td></tr>
        """
    body += "</table>"

    # Coverage matrix
    body += """
    <h2>Detection Coverage Matrix</h2>
    <table>
        <thead>
            <tr>
                <th>MITRE ID</th>
                <th>Technique</th>
                <th>Status</th>
                <th>Rules</th>
                <th>Enabled</th>
            </tr>
        </thead>
        <tbody>
    """
    for entry in matrix:
        status_cls = "covered" if entry["covered"] else "gap"
        status_text = "COVERED" if entry["covered"] else "GAP"
        status_color = "#2e7d32" if entry["covered"] else "#c62828"
        body += f"""
        <tr>
            <td><code>{h(entry['mitre_id'])}</code></td>
            <td>{h(entry['name'])}</td>
            <td style="color:{status_color};font-weight:bold">{status_text}</td>
            <td style="text-align:center">{h(entry['rule_count'])}</td>
            <td style="text-align:center">{h(entry['enabled_rules'])}</td>
        </tr>
        """
    body += "</tbody></table>"

    # Gap analysis
    gaps = [e for e in matrix if not e["covered"]]
    if gaps:
        body += "<h2>Detection Gaps — Priority Actions Required</h2>"
        body += '<table><thead><tr><th>MITRE ID</th><th>Technique</th></tr></thead><tbody>'
        for g in gaps:
            body += f'<tr><td><code>{h(g["mitre_id"])}</code></td><td>{h(g["name"])}</td></tr>'
        body += "</tbody></table>"

    # AI recommendations
    if data.get("ai_recommendations"):
        body += f"""
        <h2>Recommendations</h2>
        <p>{h(data['ai_recommendations'])}</p>
        """

    body += f"""
    <div style="margin-top:2em;padding-top:1em;border-top:1px solid #ddd;font-size:8pt;color:#888">
        Report generated by ION Detection Engineering &bull; {now_str} &bull;
        Data sources: TIDE, OpenCTI, CyAB
    </div>
    """

    # Add extra CSS for the gauge
    gauge_css = """
    .readiness-gauge { margin: 1em 0; }
    .gauge-bar { height: 20px; background: #e0e0e0; border-radius: 10px; overflow: hidden; margin: 8px 0; }
    .gauge-fill { height: 100%; border-radius: 10px; }
    """
    readiness = data["readiness_pct"]
    if readiness >= 75:
        gauge_css += ".gauge-fill { background: #2e7d32; }"
    elif readiness >= 50:
        gauge_css += ".gauge-fill { background: #f57f17; }"
    else:
        gauge_css += ".gauge-fill { background: #c62828; }"

    # Build full HTML document
    from ion.services.pdf_export_service import PDF_CSS

    custom_css = PDF_CSS + gauge_css
    # Add screen-friendly overrides for HTML fallback
    screen_css = """
    @media screen {
        body { max-width: 900px; margin: 0 auto; padding: 20px 40px; background: #fff; }
        .pdf-header h1 { font-size: 1.6em; }
        @page { margin: 0; }
    }
    """
    full_html = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Detection Readiness — {h(actor['name'])}</title>
<style>{custom_css}{screen_css}</style></head>
<body>
<span class="pdf-title">Detection Readiness Assessment</span>
<div class="pdf-header">
    <h1 style="border:none;margin:0;padding:0;">Detection Readiness Assessment</h1>
    <p class="pdf-subtitle">{h(actor['name'])} vs {h(sys_name)} &bull; {now_str} &bull; ION</p>
</div>
{body}
</body></html>"""

    # Try PDF first, fall back to HTML
    try:
        import re as _re

        from weasyprint import HTML as WpHTML
        pdf_bytes = WpHTML(string=full_html).write_pdf()
        # Strict ASCII slug for the filename so an attacker-controlled actor
        # name can't inject CRLF / quotes into the Content-Disposition header.
        slug = _re.sub(r"[^A-Za-z0-9._-]+", "_", actor.get("name") or "report").strip("_")[:60] or "report"
        filename = f"readiness_{slug}_{now_str[:10]}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "X-Content-Type-Options": "nosniff",
            },
        )
    except (ImportError, OSError):
        # WeasyPrint not available — return printable HTML with a strict CSP
        # so that even if a sanitization regression slipped through, the
        # browser will refuse to execute inline scripts in the report body.
        return Response(
            content=full_html,
            media_type="text/html",
            headers={
                "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src data:",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
            },
        )


@router.get("/tide/de/actor-readiness", dependencies=[Depends(require_permission("alert:read"))])
async def tide_de_actor_readiness(search: str = "", first: int = 15):
    """Threat Actor Detection Readiness — cross-reference OpenCTI actors with TIDE coverage.

    For each threat actor, shows which of their known TTPs have TIDE rules
    and which are blind spots.
    """
    from ion.services.opencti_service import get_opencti_service

    tide_svc = get_tide_service()
    if not tide_svc.enabled:
        return {"enabled": False, "error": "TIDE not configured"}

    opencti = get_opencti_service()
    if not opencti.is_configured:
        return {"enabled": False, "error": "OpenCTI not configured"}

    # 1. Get global TIDE MITRE coverage (cached-friendly)
    tide_coverage = tide_svc.get_global_mitre_coverage()
    if not tide_coverage:
        return {"enabled": False, "error": "Failed to fetch TIDE coverage"}
    tide_techs = tide_coverage.get("techniques", {})

    # 2. Search threat actors in OpenCTI
    try:
        actors_result = await opencti.search_threat_actors(search=search, first=min(first, 30))
    except Exception as e:
        return {"enabled": True, "error": f"OpenCTI query failed: {safe_error(e, 'cyab_actors')}", "actors": []}

    actors = actors_result.get("actors", [])

    # 3. For each actor, fetch TTPs and compute readiness
    readiness_list = []
    for actor in actors:
        try:
            entity_type = actor.get("entity_type", "threat_actor")
            detail = await opencti.get_entity_detail(actor["id"], entity_type)
            ttps = detail.get("ttps", [])
        except Exception:
            ttps = []

        # Map TTPs to TIDE coverage
        total_ttps = len(ttps)
        covered = []
        gaps = []
        for ttp in ttps:
            mitre_id = ttp.get("mitre_id") or ""
            parent_id = mitre_id.split(".")[0] if mitre_id else ""
            tide_info = tide_techs.get(parent_id) or tide_techs.get(mitre_id)

            entry = {
                "mitre_id": mitre_id,
                "name": ttp.get("name", ""),
            }
            if tide_info and tide_info.get("rule_count", 0) > 0:
                entry["rule_count"] = tide_info["rule_count"]
                entry["enabled_rules"] = tide_info.get("enabled_rules", 0)
                entry["avg_quality"] = tide_info.get("avg_quality", 0)
                covered.append(entry)
            else:
                gaps.append(entry)

        readiness_pct = round(len(covered) / total_ttps * 100) if total_ttps else 0

        readiness_list.append({
            "id": actor["id"],
            "name": actor.get("name", ""),
            "description": (actor.get("description") or "")[:200],
            "aliases": actor.get("aliases") or [],
            "entity_type": actor.get("entity_type", "threat_actor"),
            "confidence": actor.get("confidence"),
            "labels": actor.get("labels") or [],
            "country_code": actor.get("country_code"),
            "country_name": actor.get("country_name", ""),
            "country_flag": actor.get("country_flag", ""),
            "total_ttps": total_ttps,
            "covered_count": len(covered),
            "gap_count": len(gaps),
            "readiness_pct": readiness_pct,
            "covered": covered,
            "gaps": gaps,
        })

    # Sort by total TTPs descending (most active actors first)
    readiness_list.sort(key=lambda a: a["total_ttps"], reverse=True)

    return {
        "enabled": True,
        "actors": readiness_list,
        "tide_total_techniques": tide_coverage.get("total_techniques", 0),
        "tide_covered_techniques": tide_coverage.get("covered_techniques", 0),
    }


@router.get("/tide/de/kill-chain-alerts", dependencies=[Depends(require_permission("alert:read"))])
async def tide_de_kill_chain_alerts(hours: int = 24):
    """Kill Chain Progression Detection — detect multi-step attack sequences on hosts.

    Cross-references TIDE playbook kill chain steps with ES alerts grouped by host.
    Flags hosts where multiple sequential kill chain steps have fired.
    """
    from ion.services.elasticsearch_service import ElasticsearchService

    tide_svc = get_tide_service()
    if not tide_svc.enabled:
        return {"enabled": False, "error": "TIDE not configured"}

    es = ElasticsearchService()
    if not es.is_configured:
        return {"enabled": False, "error": "Elasticsearch not configured"}

    # 1. Get TIDE playbooks with kill chain steps
    playbooks = tide_svc.get_playbooks_with_kill_chains()
    if not playbooks:
        return {"enabled": True, "progressions": [], "playbooks": []}

    # Collect all technique IDs from all playbooks (include sub-technique wildcards)
    all_technique_ids = set()
    for pb in playbooks:
        for step in pb.get("steps", []):
            all_technique_ids.update(step.get("techniques", []))

    if not all_technique_ids:
        return {"enabled": True, "progressions": [], "playbooks": playbooks}

    # 2. Query ES for alerts matching any kill chain technique, grouped by host
    # Use wildcard matching so T1003 matches T1003.001, T1003.006, etc.
    hours = min(hours, 168)

    # Build should clauses: exact match OR prefix match for sub-techniques
    technique_should = []
    for tid in all_technique_ids:
        technique_should.append({"term": {"threat.technique.id": tid}})
        technique_should.append({"prefix": {"threat.technique.id": f"{tid}."}})

    query = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": f"now-{hours}h", "lte": "now"}}},
                    {"bool": {"should": technique_should, "minimum_should_match": 1}},
                ],
                "must_not": [
                    {"term": {"kibana.alert.building_block_type": "default"}}
                ]
            }
        },
        "aggs": {
            "by_host": {
                "terms": {
                    "field": "host.name",
                    "size": 100,
                    "min_doc_count": 1,
                },
                "aggs": {
                    "by_technique": {
                        "terms": {"field": "threat.technique.id", "size": 50},
                        "aggs": {
                            "latest": {"max": {"field": "@timestamp"}},
                            "earliest": {"min": {"field": "@timestamp"}},
                            "by_rule": {
                                "terms": {"field": "kibana.alert.rule.name", "size": 5}
                            },
                            "by_severity": {
                                "terms": {"field": "kibana.alert.severity", "size": 5}
                            }
                        }
                    },
                    "latest_alert": {"max": {"field": "@timestamp"}},
                    "earliest_alert": {"min": {"field": "@timestamp"}},
                }
            }
        }
    }

    try:
        pattern = es.alert_index
        encoded = pattern.replace(",", "%2C")
        result = await es._request("POST", f"/{encoded}/_search", json=query)
    except Exception as e:
        return {"enabled": True, "error": f"ES query failed: {safe_error(e, 'cyab_progressions')}", "progressions": []}

    aggs = result.get("aggregations", {})
    host_buckets = aggs.get("by_host", {}).get("buckets", [])

    # 3. For each host, check kill chain progression against each playbook
    progressions = []
    for hb in host_buckets:
        hostname = hb["key"]
        host_techniques = {}
        for tb in hb.get("by_technique", {}).get("buckets", []):
            tid = tb["key"]
            host_techniques[tid] = {
                "count": tb["doc_count"],
                "latest": tb.get("latest", {}).get("value_as_string"),
                "earliest": tb.get("earliest", {}).get("value_as_string"),
                "rules": [rb["key"] for rb in tb.get("by_rule", {}).get("buckets", [])],
                "severity": {sb["key"]: sb["doc_count"]
                             for sb in tb.get("by_severity", {}).get("buckets", [])},
            }

        # Check each playbook
        for pb in playbooks:
            steps = pb.get("steps", [])
            if not steps:
                continue

            matched_steps = []
            for step in steps:
                step_techs = step.get("techniques", [])
                # Check if any of this step's techniques fired on this host
                # Match both exact (T1003) and sub-techniques (T1003.001)
                matching_tech = None
                for tid in step_techs:
                    if tid in host_techniques:
                        matching_tech = tid
                        break
                    # Check sub-technique match: T1003 matches T1003.001
                    for alert_tid in host_techniques:
                        if alert_tid.startswith(tid + ".") or tid.startswith(alert_tid + "."):
                            matching_tech = alert_tid
                            break
                    if matching_tech:
                        break
                matched_steps.append({
                    "order": step["order"],
                    "name": step["name"],
                    "tactic": step.get("tactic"),
                    "techniques": step_techs,
                    "fired": matching_tech is not None,
                    "matched_technique": matching_tech,
                    "alert_data": host_techniques.get(matching_tech) if matching_tech else None,
                })

            fired_count = sum(1 for s in matched_steps if s["fired"])
            if fired_count >= 2:  # At least 2 steps = noteworthy
                # Determine severity based on progression
                total_steps = len(steps)
                pct_complete = round(fired_count / total_steps * 100)
                if pct_complete >= 75:
                    severity = "critical"
                elif pct_complete >= 50:
                    severity = "high"
                else:
                    severity = "medium"

                progressions.append({
                    "host": hostname,
                    "playbook_name": pb["name"],
                    "playbook_id": pb["id"],
                    "total_steps": total_steps,
                    "fired_steps": fired_count,
                    "pct_complete": pct_complete,
                    "severity": severity,
                    "steps": matched_steps,
                    "latest_alert": hb.get("latest_alert", {}).get("value_as_string"),
                    "earliest_alert": hb.get("earliest_alert", {}).get("value_as_string"),
                })

    # Sort by severity then pct_complete
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    progressions.sort(key=lambda p: (sev_order.get(p["severity"], 9), -p["pct_complete"]))

    return {
        "enabled": True,
        "hours": hours,
        "progressions": progressions,
        "total_hosts_checked": len(host_buckets),
        "playbook_count": len(playbooks),
    }


@router.get("/tide/de/execution", dependencies=[Depends(require_permission("alert:read"))])
async def tide_de_execution(hours: int = 168):
    """Execution metrics — cross-reference TIDE rules with ES alert data.

    Returns firing/silent/noisy rules, volume trends, and efficacy stats.
    """
    from ion.services.elasticsearch_service import ElasticsearchService

    es = ElasticsearchService()
    if not es.is_configured:
        return {"enabled": False, "error": "Elasticsearch not configured"}

    tide_svc = get_tide_service()
    if not tide_svc.enabled:
        return {"enabled": False, "error": "TIDE not configured"}

    # 1. Fetch all TIDE rules (enabled ones) for cross-referencing
    tide_rules_result = tide_svc.get_rules_paginated(limit=2000)
    tide_rules_by_name: dict[str, dict] = {}
    tide_enabled_names: set[str] = set()
    for r in tide_rules_result.get("rows", []):
        name_lower = (r.get("name") or "").strip().lower()
        if name_lower:
            tide_rules_by_name[name_lower] = r
            if r.get("enabled"):
                tide_enabled_names.add(name_lower)

    # 2. Query ES for alert aggregation by rule
    hours = min(hours, 720)  # Cap at 30 days
    interval = "6h" if hours <= 168 else "1d"

    query = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": f"now-{hours}h", "lte": "now"}}},
                ],
                "must_not": [
                    {"term": {"kibana.alert.building_block_type": "default"}}
                ]
            }
        },
        "aggs": {
            "by_rule": {
                "terms": {"field": "kibana.alert.rule.name", "size": 1000},
                "aggs": {
                    "by_severity": {
                        "terms": {"field": "kibana.alert.severity", "size": 5}
                    },
                    "by_status": {
                        "terms": {"field": "kibana.alert.workflow_status", "size": 5}
                    },
                    "latest": {
                        "max": {"field": "@timestamp"}
                    },
                    "earliest": {
                        "min": {"field": "@timestamp"}
                    },
                    "by_mitre": {
                        "terms": {"field": "threat.technique.id", "size": 20}
                    }
                }
            },
            "total_by_severity": {
                "terms": {"field": "kibana.alert.severity", "size": 10}
            },
            "total_by_status": {
                "terms": {"field": "kibana.alert.workflow_status", "size": 10}
            },
            "over_time": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": interval,
                    "min_doc_count": 0,
                    "extended_bounds": {"min": f"now-{hours}h", "max": "now"}
                }
            },
            "by_severity_over_time": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": interval,
                    "min_doc_count": 0,
                    "extended_bounds": {"min": f"now-{hours}h", "max": "now"}
                },
                "aggs": {
                    "sev": {"terms": {"field": "kibana.alert.severity", "size": 5}}
                }
            }
        }
    }

    try:
        pattern = es.alert_index
        encoded = pattern.replace(",", "%2C")
        result = await es._request("POST", f"/{encoded}/_search", json=query)
    except Exception as e:
        return {"enabled": True, "error": f"ES query failed: {safe_error(e, 'cyab_rules')}", "rules": [], "summary": {}}

    total_alerts = result.get("hits", {}).get("total", {})
    if isinstance(total_alerts, dict):
        total_alerts = total_alerts.get("value", 0)

    aggs = result.get("aggregations", {})
    rule_buckets = aggs.get("by_rule", {}).get("buckets", [])

    # 3. Cross-reference ES rules with TIDE rules
    firing_rules = []
    matched_tide_keys = set()

    for b in rule_buckets:
        rule_name = b["key"]
        alert_count = b["doc_count"]
        severity_map = {sb["key"]: sb["doc_count"] for sb in b.get("by_severity", {}).get("buckets", [])}
        status_map = {sb["key"]: sb["doc_count"] for sb in b.get("by_status", {}).get("buckets", [])}
        latest = b.get("latest", {}).get("value_as_string")
        earliest = b.get("earliest", {}).get("value_as_string")
        mitre_ids = [mb["key"] for mb in b.get("by_mitre", {}).get("buckets", [])]

        # Calculate FP-like rate: closed alerts / total (rough proxy)
        closed = status_map.get("closed", 0)
        acked = status_map.get("acknowledged", 0)
        open_count = status_map.get("open", 0)
        fp_rate = round(closed / alert_count * 100, 1) if alert_count else 0

        # Match to TIDE
        tide_key = rule_name.strip().lower()
        tide_rule = tide_rules_by_name.get(tide_key)
        matched_tide_keys.add(tide_key)

        entry = {
            "rule_name": rule_name,
            "alert_count": alert_count,
            "severity": severity_map,
            "status": status_map,
            "open": open_count,
            "acknowledged": acked,
            "closed": closed,
            "close_rate": fp_rate,
            "latest_alert": latest,
            "earliest_alert": earliest,
            "mitre_ids": mitre_ids,
            "in_tide": tide_rule is not None,
            "tide_severity": tide_rule.get("severity") if tide_rule else None,
            "tide_enabled": tide_rule.get("enabled") if tide_rule else None,
            "tide_quality": tide_rule.get("quality_score") if tide_rule else None,
        }
        firing_rules.append(entry)

    # Sort by alert count descending
    firing_rules.sort(key=lambda r: r["alert_count"], reverse=True)

    # 4. Noisy rules: high volume + high close rate (>70% closed with >10 alerts)
    noisy_rules = [r for r in firing_rules if r["alert_count"] >= 10 and r["close_rate"] >= 70]
    noisy_rules.sort(key=lambda r: r["alert_count"], reverse=True)

    # 5. Silent rules: enabled in TIDE but NOT firing in ES
    silent_rules = []
    for name_lower, rule in tide_rules_by_name.items():
        if name_lower not in matched_tide_keys and rule.get("enabled"):
            silent_rules.append({
                "rule_name": rule["name"],
                "tide_severity": rule.get("severity"),
                "tide_quality": rule.get("quality_score"),
                "mitre_ids": rule.get("mitre_ids") or [],
            })
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    silent_rules.sort(key=lambda r: sev_order.get((r.get("tide_severity") or "low").lower(), 5))

    # 6. Global stats
    total_severity = {sb["key"]: sb["doc_count"] for sb in aggs.get("total_by_severity", {}).get("buckets", [])}
    total_status = {sb["key"]: sb["doc_count"] for sb in aggs.get("total_by_status", {}).get("buckets", [])}
    timeline = [{"timestamp": tb["key_as_string"], "count": tb["doc_count"]}
                for tb in aggs.get("over_time", {}).get("buckets", [])]

    # Severity over time
    sev_timeline = []
    for tb in aggs.get("by_severity_over_time", {}).get("buckets", []):
        entry = {"timestamp": tb["key_as_string"]}
        for sb in tb.get("sev", {}).get("buckets", []):
            entry[sb["key"]] = sb["doc_count"]
        sev_timeline.append(entry)

    # Summary
    unique_rules = len(rule_buckets)
    avg_per_rule = round(total_alerts / unique_rules, 1) if unique_rules else 0

    return {
        "enabled": True,
        "hours": hours,
        "summary": {
            "total_alerts": total_alerts,
            "unique_rules_firing": unique_rules,
            "avg_alerts_per_rule": avg_per_rule,
            "tide_matched": sum(1 for r in firing_rules if r["in_tide"]),
            "tide_unmatched": sum(1 for r in firing_rules if not r["in_tide"]),
            "silent_enabled_rules": len(silent_rules),
            "noisy_rules": len(noisy_rules),
            "severity": total_severity,
            "status": total_status,
        },
        "top_firing": firing_rules[:50],
        "noisy_rules": noisy_rules[:20],
        "silent_rules": silent_rules[:50],
        "timeline": timeline,
        "severity_timeline": sev_timeline,
    }


@router.get("/namespaces", dependencies=[Depends(require_permission("alert:read"))])
async def list_namespaces():
    """List all data_stream.namespace values from ES for auto-suggestion."""
    from ion.services.elasticsearch_service import ElasticsearchService

    es = ElasticsearchService()
    if not es.is_configured:
        return []

    query = {
        "size": 0,
        "aggs": {
            "namespaces": {
                "terms": {"field": "data_stream.namespace", "size": 100}
            }
        }
    }
    try:
        pattern = es.alert_index
        encoded = pattern.replace(",", "%2C")
        result = await es._request("POST", f"/{encoded}/_search", json=query)
        buckets = result.get("aggregations", {}).get("namespaces", {}).get("buckets", [])
        return [{"namespace": b["key"], "count": b["doc_count"]} for b in buckets]
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Data source templates, clone, and bulk apply
# ---------------------------------------------------------------------------

@router.get("/templates", dependencies=[Depends(require_permission("alert:read"))])
def list_ds_templates():
    """List available data source templates for quick creation."""
    from ion.services.cyab_templates import list_templates
    return {"templates": list_templates()}


@router.get("/templates/{template_id}", dependencies=[Depends(require_permission("alert:read"))])
def get_ds_template(template_id: str):
    """Get a fully expanded template with pre-filled fields + field mapping."""
    from ion.services.cyab_templates import get_template
    t = get_template(template_id)
    if not t:
        raise HTTPException(status_code=404, detail=f"Template not found: {template_id}")
    return t


@router.post("/systems/{system_id}/data-sources/from-template", dependencies=[Depends(require_permission("alert:read"))])
def create_ds_from_template(
    system_id: int,
    template_id: str,
    session: Session = Depends(get_db_session),
):
    """Create a new data source pre-filled from a template.

    The data source is created with all template fields populated. The user
    can then edit it to customise namespace, TIDE system link, etc.
    """
    from ion.services.cyab_templates import get_template

    sys = session.get(CyabSystem, system_id)
    if not sys:
        raise HTTPException(status_code=404, detail="System not found")

    t = get_template(template_id)
    if not t:
        raise HTTPException(status_code=404, detail=f"Template not found: {template_id}")

    import json as _json
    ds = CyabDataSource(
        system_id=system_id,
        name=t["name"],
        data_source_type=t["data_source_type"],
        icon=t["icon"],
        sal_tier=t["sal_tier"],
        uptime_target=t["uptime_target"],
        max_latency=t["max_latency"],
        retention=t["retention"],
        p1_sla=t["p1_sla"],
        field_mapping=_json.dumps(t["field_mapping"]),
        field_mapping_score=t["field_mapping_score"],
        mandatory_score=t["mandatory_score"],
        readiness_score=t["readiness_score"],
        field_notes=t["field_notes"],
    )
    session.add(ds)
    session.flush()
    session.refresh(sys)
    _recalc_system_aggregates(sys)
    _create_snapshot(session, sys, notes=f"Data source from template: {t['name']}", ds_id=ds.id)
    session.commit()
    session.refresh(ds)
    return _ds_to_dict(ds)


@router.post("/data-sources/{ds_id}/clone", dependencies=[Depends(require_permission("alert:read"))])
def clone_data_source(
    ds_id: int,
    session: Session = Depends(get_db_session),
):
    """Clone an existing data source — copies all config fields except namespace + TIDE link."""
    original = session.get(CyabDataSource, ds_id)
    if not original:
        raise HTTPException(status_code=404, detail="Data source not found")

    clone = CyabDataSource(
        system_id=original.system_id,
        name=f"{original.name} (copy)",
        data_source_type=original.data_source_type,
        icon=original.icon,
        sal_tier=original.sal_tier,
        uptime_target=original.uptime_target,
        max_latency=original.max_latency,
        retention=original.retention,
        p1_sla=original.p1_sla,
        field_mapping=original.field_mapping,
        field_mapping_score=original.field_mapping_score,
        mandatory_score=original.mandatory_score,
        readiness_score=original.readiness_score,
        field_notes=original.field_notes,
        # Intentionally blank — user must set for their specific deployment
        tide_system_id=None,
        data_namespace=None,
        use_case_status=None,
    )
    session.add(clone)
    session.flush()
    sys = session.get(CyabSystem, original.system_id)
    if sys:
        session.refresh(sys)
        _recalc_system_aggregates(sys)
        _create_snapshot(session, sys, notes=f"Cloned data source: {original.name}", ds_id=clone.id)
    session.commit()
    session.refresh(clone)
    return _ds_to_dict(clone)


class BulkApplyRequest(BaseModel):
    ds_ids: list[int]
    sal_tier: Optional[str] = None
    uptime_target: Optional[str] = None
    max_latency: Optional[str] = None
    retention: Optional[str] = None
    p1_sla: Optional[str] = None


@router.post("/data-sources/bulk-apply", dependencies=[Depends(require_permission("alert:read"))])
def bulk_apply_settings(
    req: BulkApplyRequest,
    session: Session = Depends(get_db_session),
):
    """Apply the same SAL / retention / latency settings to multiple data sources at once."""
    if not req.ds_ids:
        raise HTTPException(status_code=400, detail="No data source IDs provided")

    fields = req.model_dump(exclude_none=True, exclude={"ds_ids"})
    if not fields:
        raise HTTPException(status_code=400, detail="No fields to apply")

    updated = 0
    touched_systems: set[int] = set()
    for ds_id in req.ds_ids:
        ds = session.get(CyabDataSource, ds_id)
        if not ds:
            continue
        for k, v in fields.items():
            setattr(ds, k, v)
        touched_systems.add(ds.system_id)
        updated += 1

    for sid in touched_systems:
        sys = session.get(CyabSystem, sid)
        if sys:
            session.refresh(sys)
            _recalc_system_aggregates(sys)

    session.commit()
    return {"updated": updated, "fields_applied": list(fields.keys())}


# ===========================================================================
# v0.10.15 — Assessment questionnaire endpoints
#
# Two granularities (mirrors the model layer):
#   /api/cyab/assessment            org-wide questionnaire
#   /api/cyab/systems/{sid}/assessment   per-system questionnaire
#
# Both immutable + versioned: every POST creates a new row. The frontend
# resubmits a fresh assessment rather than editing an existing one.
# ===========================================================================


class AssessmentSubmit(BaseModel):
    responses: dict
    notes: Optional[str] = None


def _serialise_assessment(row, include_results: bool = True) -> dict:
    """Serialise a CyabAssessment / CyabSystemAssessment row for the API."""
    out = {
        "id": row.id,
        "schema_version": row.schema_version,
        "submitted_by": row.submitted_by,
        "submitted_at": row.submitted_at.isoformat() if row.submitted_at else None,
        "notes": row.notes,
        "responses": cyab_assessment_service.parse_json_field(row.responses_json) or {},
    }
    if include_results:
        out["computed_profile"] = cyab_assessment_service.parse_json_field(
            row.computed_profile_json
        )
        out["ranked_use_cases"] = cyab_assessment_service.parse_json_field(
            row.ranked_use_cases_json
        ) or []
        out["ranked_actors"] = cyab_assessment_service.parse_json_field(
            row.ranked_actors_json
        ) or []
    if hasattr(row, "system_id"):
        out["system_id"] = row.system_id
        out["org_assessment_id"] = getattr(row, "org_assessment_id", None)
    return out


@router.get("/assessment/questions")
def get_assessment_questions(
    current_user: User = Depends(get_current_user),
):
    """Return the org-wide + per-system question schemas.

    Schema version is included so the frontend can warn if it loaded a
    different revision than the server is now serving.
    """
    return {
        "schema_version": ASSESSMENT_SCHEMA_VERSION,
        "org_questions": get_org_questions(),
        "system_questions": get_system_questions(),
    }


def _latest_org_assessment(session: Session) -> Optional[CyabAssessment]:
    """Return the most recent org-wide assessment row (or None)."""
    return (
        session.query(CyabAssessment)
        .order_by(CyabAssessment.id.desc())
        .first()
    )


def _resolve_playbooks() -> List[dict]:
    """Pull TIDE playbooks for scoring. Empty list on TIDE failure — the
    scorer copes (returns an empty ranking)."""
    try:
        svc = get_tide_service()
        if not svc.enabled:
            return []
        return svc.get_playbooks_with_kill_chains() or []
    except Exception as exc:
        logger_msg = f"TIDE playbook fetch failed: {exc}"
        # Use safe_error so we don't leak internals into the response
        # if a downstream call eventually surfaces this.
        try:
            from logging import getLogger
            getLogger(__name__).warning(logger_msg)
        except Exception:
            pass
        return []


@router.post("/assessment")
def submit_org_assessment(
    body: AssessmentSubmit,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Persist a new org-wide assessment + compute ranked results.

    Always creates a new row — assessments are immutable. Past submissions
    are kept for trending. The newest is what the per-system overlay
    inherits as the "current org profile".
    """
    responses = body.responses or {}
    playbooks = _resolve_playbooks()
    result = cyab_assessment_service.rank_for_assessment(
        responses=responses,
        playbooks=playbooks,
    )

    row = CyabAssessment(
        schema_version=ASSESSMENT_SCHEMA_VERSION,
        submitted_by=current_user.id if current_user else None,
        responses_json=json.dumps(responses, default=str),
        computed_profile_json=json.dumps(result["computed_profile"], default=str),
        ranked_use_cases_json=json.dumps(result["ranked_use_cases"], default=str),
        ranked_actors_json=json.dumps(result["ranked_actors"], default=str),
        notes=body.notes or None,
    )
    session.add(row)
    session.commit()
    session.refresh(row)
    return _serialise_assessment(row)


@router.get("/assessment")
def list_org_assessments(
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
    limit: int = 20,
):
    """List org-wide assessments newest-first (no result blob — just
    metadata + responses, so the trending UI can diff)."""
    rows = (
        session.query(CyabAssessment)
        .order_by(CyabAssessment.id.desc())
        .limit(limit)
        .all()
    )
    return {
        "assessments": [_serialise_assessment(r, include_results=False) for r in rows],
        "count": len(rows),
    }


@router.get("/assessment/latest")
def get_latest_org_assessment(
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Convenience: return the most recent org-wide assessment with
    results, or 204 when none has been submitted."""
    row = _latest_org_assessment(session)
    if not row:
        return {"assessment": None}
    return {"assessment": _serialise_assessment(row)}


@router.get("/assessment/{assessment_id}")
def get_org_assessment(
    assessment_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    row = session.get(CyabAssessment, assessment_id)
    if not row:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return _serialise_assessment(row)


@router.post("/systems/{system_id}/assessment")
def submit_system_assessment(
    system_id: int,
    body: AssessmentSubmit,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Persist a new per-system assessment + compute results overlaying
    the latest org-wide profile."""
    sys = session.get(CyabSystem, system_id)
    if not sys:
        raise HTTPException(status_code=404, detail="System not found")

    org_row = _latest_org_assessment(session)
    org_responses = (
        cyab_assessment_service.parse_json_field(org_row.responses_json) or {}
        if org_row else {}
    )
    sys_responses = body.responses or {}

    playbooks = _resolve_playbooks()
    result = cyab_assessment_service.rank_for_assessment(
        responses=org_responses,
        playbooks=playbooks,
        sys_responses=sys_responses,
    )

    row = CyabSystemAssessment(
        system_id=system_id,
        org_assessment_id=org_row.id if org_row else None,
        schema_version=ASSESSMENT_SCHEMA_VERSION,
        submitted_by=current_user.id if current_user else None,
        responses_json=json.dumps(sys_responses, default=str),
        computed_profile_json=json.dumps(result["computed_profile"], default=str),
        ranked_use_cases_json=json.dumps(result["ranked_use_cases"], default=str),
        ranked_actors_json=json.dumps(result["ranked_actors"], default=str),
        notes=body.notes or None,
    )
    session.add(row)
    session.commit()
    session.refresh(row)
    return _serialise_assessment(row)


@router.get("/systems/{system_id}/assessment")
def list_system_assessments(
    system_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
    limit: int = 10,
):
    """List per-system assessments newest-first (latest carries the
    current ranking shown on the system detail page)."""
    rows = (
        session.query(CyabSystemAssessment)
        .filter(CyabSystemAssessment.system_id == system_id)
        .order_by(CyabSystemAssessment.id.desc())
        .limit(limit)
        .all()
    )
    return {
        "assessments": [_serialise_assessment(r) for r in rows],
        "count": len(rows),
    }


@router.get("/systems/{system_id}/assessment/latest")
def get_latest_system_assessment(
    system_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    row = (
        session.query(CyabSystemAssessment)
        .filter(CyabSystemAssessment.system_id == system_id)
        .order_by(CyabSystemAssessment.id.desc())
        .first()
    )
    if not row:
        return {"assessment": None}
    return {"assessment": _serialise_assessment(row)}


# ===========================================================================
# v0.10.17 — Onboarding wizard: full system creation in one transaction
#
# POST /api/cyab/onboarding accepts a single JSON body that fully describes
# a new CyAB system: identity, contacts, governance, an inline per-system
# assessment, and a list of data sources to create from templates.
#
# Everything happens in one transaction — if any step fails the whole
# onboarding rolls back. On success, the returned payload links to the
# new system + its computed ranked use cases so the UI lands on the
# detail page with the assessment already wired up.
# ===========================================================================


class OnboardingDataSource(BaseModel):
    """One data-source request inside the onboarding payload.

    `template_id` is the id from the cyab_templates catalogue (sysmon,
    windows-security, firewall, etc). Optional `name_override`,
    `tide_system_id`, and `data_namespace` let the wizard customise
    per-source settings during creation.
    """
    template_id: str
    name_override: Optional[str] = None
    tide_system_id: Optional[str] = None
    data_namespace: Optional[str] = None


class OnboardingRequest(BaseModel):
    # Step 1 — identity
    name: str
    department: str
    reference: Optional[str] = None
    version: Optional[str] = "1.0"
    status: Optional[str] = "DRAFT"
    icon: Optional[str] = "monitor"
    tags: Optional[List[str]] = None
    business_unit: Optional[str] = None
    data_classification: Optional[str] = None

    # Step 2 — contacts
    department_lead: Optional[str] = None
    dept_lead_email: Optional[str] = None
    dept_lead_phone: Optional[str] = None
    dept_deputy_name: Optional[str] = None
    dept_deputy_email: Optional[str] = None
    soc_team: Optional[str] = "Security Operations Center"
    soc_lead: Optional[str] = None
    soc_lead_email: Optional[str] = None
    soc_analyst_owner: Optional[str] = None
    stakeholder_distribution: Optional[str] = None
    ir_runbook_url: Optional[str] = None

    # Step 3 — system assessment (8 questions)
    assessment_responses: Optional[dict] = None

    # Step 4 — data sources
    data_sources: List[OnboardingDataSource] = []

    # Step 5 — governance / SLA defaults (applied when individual
    # data-source overrides aren't set)
    sal_tier: Optional[str] = "SAL-2"
    review_cadence_days: Optional[int] = 90
    next_review_date: Optional[str] = None

    # Step 6 — sign-off (optional; system stays DRAFT if not signed)
    sign_dept_name: Optional[str] = None
    sign_dept_date: Optional[str] = None
    sign_soc_name: Optional[str] = None
    sign_soc_date: Optional[str] = None


@router.post("/onboarding")
def onboarding_create(
    body: OnboardingRequest,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Create a CyAB system + data sources + per-system assessment in one
    transaction. Returns the new system's id and computed ranked use cases.

    Roll-back semantics: any failure (including TIDE unreachable) does NOT
    block the system create — it just yields an empty ranked-use-cases
    list. Caller can re-run the assessment later from the system detail.
    """
    from ion.services.cyab_templates import get_template

    # ── 1. CyabSystem ──────────────────────────────────────────────────────
    # Auto-reference if not supplied — same SOC-SLA-{year}-{count} pattern as
    # the simple New System path (kept for parity).
    ref = body.reference
    if not ref:
        last = (
            session.query(CyabSystem)
            .order_by(CyabSystem.id.desc())
            .first()
        )
        next_num = (last.id + 1) if last else 1
        ref = f"SOC-SLA-{datetime.utcnow().year}-{next_num:03d}"

    next_review = None
    if body.next_review_date:
        next_review = _parse_date(body.next_review_date)
    elif body.review_cadence_days:
        next_review = (datetime.utcnow().date() + timedelta(days=body.review_cadence_days))

    sys = CyabSystem(
        name=body.name,
        department=body.department,
        department_lead=body.department_lead,
        soc_team=body.soc_team,
        soc_lead=body.soc_lead,
        reference=ref,
        version=body.version or "1.0",
        status=body.status or "DRAFT",
        icon=body.icon or "monitor",
        tags=json.dumps(body.tags) if body.tags else None,
        business_unit=body.business_unit,
        data_classification=body.data_classification,
        dept_lead_email=body.dept_lead_email,
        dept_lead_phone=body.dept_lead_phone,
        dept_deputy_name=body.dept_deputy_name,
        dept_deputy_email=body.dept_deputy_email,
        soc_lead_email=body.soc_lead_email,
        soc_analyst_owner=body.soc_analyst_owner,
        stakeholder_distribution=body.stakeholder_distribution,
        ir_runbook_url=body.ir_runbook_url,
        sal_tier=body.sal_tier or "SAL-2",
        review_cadence_days=body.review_cadence_days or 90,
        next_review_date=next_review,
        sign_dept_name=body.sign_dept_name,
        sign_dept_date=_parse_date(body.sign_dept_date) if body.sign_dept_date else None,
        sign_soc_name=body.sign_soc_name,
        sign_soc_date=_parse_date(body.sign_soc_date) if body.sign_soc_date else None,
        created_by=current_user.id if current_user else None,
    )
    session.add(sys)
    session.flush()  # get sys.id for FK references

    # ── 2. CyabDataSource[] from templates ─────────────────────────────────
    created_ds_count = 0
    for ds_req in (body.data_sources or []):
        tpl = get_template(ds_req.template_id)
        if not tpl:
            # Skip unknown templates rather than fail the whole onboarding —
            # a missing template id (typo, removed) shouldn't blow away
            # the rest of a wizard submission.
            continue
        ds = CyabDataSource(
            system_id=sys.id,
            name=ds_req.name_override or tpl["name"],
            data_source_type=tpl["data_source_type"],
            icon=tpl["icon"],
            sal_tier=tpl.get("sal_tier") or sys.sal_tier,
            uptime_target=tpl.get("uptime_target"),
            max_latency=tpl.get("max_latency"),
            retention=tpl.get("retention"),
            p1_sla=tpl.get("p1_sla"),
            field_mapping=json.dumps(tpl["field_mapping"]),
            field_mapping_score=tpl["field_mapping_score"],
            mandatory_score=tpl["mandatory_score"],
            readiness_score=tpl["readiness_score"],
            field_notes=tpl.get("field_notes"),
            tide_system_id=ds_req.tide_system_id,
            data_namespace=ds_req.data_namespace,
        )
        session.add(ds)
        created_ds_count += 1
    session.flush()
    session.refresh(sys)
    # Recompute aggregate scores from the freshly-added sources.
    _recalc_system_aggregates(sys)

    # ── 3. CyabSystemAssessment + scoring ──────────────────────────────────
    # Latest org-wide assessment is the baseline; this system's responses
    # overlay on top of it.
    org_row = _latest_org_assessment(session)
    org_responses = (
        cyab_assessment_service.parse_json_field(org_row.responses_json) or {}
        if org_row else {}
    )
    sys_responses = body.assessment_responses or {}

    playbooks = _resolve_playbooks()
    scoring_result = cyab_assessment_service.rank_for_assessment(
        responses=org_responses,
        playbooks=playbooks,
        sys_responses=sys_responses,
    )

    asmt_row = CyabSystemAssessment(
        system_id=sys.id,
        org_assessment_id=org_row.id if org_row else None,
        schema_version=ASSESSMENT_SCHEMA_VERSION,
        submitted_by=current_user.id if current_user else None,
        responses_json=json.dumps(sys_responses, default=str),
        computed_profile_json=json.dumps(scoring_result["computed_profile"], default=str),
        ranked_use_cases_json=json.dumps(scoring_result["ranked_use_cases"], default=str),
        ranked_actors_json=json.dumps(scoring_result["ranked_actors"], default=str),
        notes=f"Captured during onboarding wizard for system #{sys.id}",
    )
    session.add(asmt_row)

    # Initial snapshot — gives the trend chart something to show on day one.
    _create_snapshot(session, sys, notes="Initial onboarding snapshot")

    session.commit()
    session.refresh(sys)
    session.refresh(asmt_row)

    return {
        "system_id": sys.id,
        "system_reference": sys.reference,
        "data_sources_created": created_ds_count,
        "assessment_id": asmt_row.id,
        "ranked_use_cases": scoring_result["ranked_use_cases"],
        "ranked_actors": scoring_result["ranked_actors"],
    }


# ---------------------------------------------------------------------------
# Scoping live-counter endpoint
# ---------------------------------------------------------------------------

@router.post("/scoping/score")
async def scoping_score(request: Request):
    """Compute scoping scores from form-encoded answers, return HTMX partial.

    `?summary=1` returns the full summary view; otherwise just the counter.
    Anonymous endpoint (matches the page).
    """
    from ion.services import cyab_scoping_engine

    raw = await request.form()
    answers: dict = {}
    for key in raw.keys():
        vals = raw.getlist(key)
        if not vals:
            continue
        # Drop empty placeholder selections
        vals = [v for v in vals if v != ""]
        if not vals:
            continue
        # Single-select questions arrive as a one-item list; flatten unless
        # multiple values were posted (multi-select).
        answers[key] = vals if len(vals) > 1 else vals[0]

    scores = cyab_scoping_engine.score_answers(answers)
    summary_mode = request.query_params.get("summary") == "1"

    template_name = (
        "cyab/_scoping_summary.html" if summary_mode
        else "cyab/_scoping_counter.html"
    )
    return templates.TemplateResponse(
        request=request,
        name=template_name,
        context={
            "scores": scores,
            "answers": answers,
            "summary_text": cyab_scoping_engine.summary_text(scores),
        },
    )


@router.post("/scoping/pdf")
async def scoping_pdf_proxy(request: Request):
    """Render the scoping summary as a PDF (HTML fallback if WeasyPrint missing)."""
    from ion.services import cyab_scoping_engine

    raw = await request.form()
    answers: dict = {}
    for key in raw.keys():
        vals = [v for v in raw.getlist(key) if v != ""]
        if not vals:
            continue
        answers[key] = vals if len(vals) > 1 else vals[0]

    scores = cyab_scoping_engine.score_answers(answers)
    full_html = _render_scoping_pack_pdf_html(scores, answers)
    try:
        from weasyprint import HTML as WpHTML
        pdf_bytes = WpHTML(string=full_html).write_pdf()
        filename = f"scoping_pack_{date.today().isoformat()}.pdf"
        from fastapi.responses import Response as _Resp
        return _Resp(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "X-Content-Type-Options": "nosniff",
            },
        )
    except (ImportError, OSError):
        from fastapi.responses import Response as _Resp
        return _Resp(
            content=full_html,
            media_type="text/html",
            headers={
                "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src data:",
                "X-Content-Type-Options": "nosniff",
            },
        )


# ---------------------------------------------------------------------------
# Onboarding wizard — Step 2 live counter (shared engine)
# ---------------------------------------------------------------------------
#
# `POST /api/cyab/onboard/score` is the wizard counterpart of
# `/api/cyab/scoping/score`. It deliberately reuses the SAME
# ``cyab_scoping_engine.score_answers`` and renders the SAME
# ``cyab/_scoping_counter.html`` partial so the live counter (use cases /
# threat-actor matches / MITRE coverage) is identical on both surfaces —
# the spec calls this "engine architecture: scope for all".
#
# Kept anonymous (no auth dependency) to match the scoping page; the
# wizard's own page handler enforces ``alert:read``, so reaching this
# endpoint from the form already implies the user is authenticated.


@router.post("/onboard/score")
async def onboard_score(request: Request):
    """Live-counter endpoint for the wizard's Step 2 (intake).

    Reuses the same ``cyab_scoping_engine.score_answers`` as
    /cyab/scoping. Returns the counter partial as HTML for HTMX swap.
    """
    from ion.services import cyab_scoping_engine

    raw = await request.form()
    answers: dict = {}
    for key in raw.keys():
        vals = [v for v in raw.getlist(key) if v != ""]
        if not vals:
            continue
        # Single-select arrives as a one-item list; flatten unless this
        # is a multi-select with multiple values (matches /scoping/score).
        answers[key] = vals if len(vals) > 1 else vals[0]

    scores = cyab_scoping_engine.score_answers(answers)
    return templates.TemplateResponse(
        request=request,
        name="cyab/_scoping_counter.html",
        context={
            "scores": scores,
            "answers": answers,
            "summary_text": cyab_scoping_engine.summary_text(scores),
        },
    )


# ---------------------------------------------------------------------------
# Convert-to-system: stash scoping answers in session, redirect to wizard
# ---------------------------------------------------------------------------

from fastapi.responses import RedirectResponse


@router.post(
    "/scoping/convert",
    dependencies=[Depends(require_permission("alert:read"))],
)
async def scoping_convert(request: Request):
    """Stash the scoping answers in session, then 303-redirect to the wizard.

    The wizard's Step 1 handler (Sub-plan B) reads `request.session.get(
    'scoping_prefill')` and prefills its form fields. If session middleware
    isn't wired yet, falls back to query-string encoding.
    """
    raw = await request.form()
    answers: dict = {}
    for key in raw.keys():
        vals = [v for v in raw.getlist(key) if v != ""]
        if not vals:
            continue
        answers[key] = vals if len(vals) > 1 else vals[0]

    try:
        request.session["scoping_prefill"] = answers
        target = "/cyab/onboard?from_scoping=1"
    except (AssertionError, AttributeError):
        # No SessionMiddleware mounted — fall back to query string. URL-encode
        # the answers as a JSON blob inside one query param to avoid expanding
        # multi-value lists into the URL surface.
        from urllib.parse import quote
        target = "/cyab/onboard?from_scoping=1&answers=" + quote(json.dumps(answers))

    return RedirectResponse(url=target, status_code=303)


# ---------------------------------------------------------------------------
# Sub-plan C / Task 8 — Fleet coverage matrix
# ---------------------------------------------------------------------------

def _worst_sla(statuses: list) -> str:
    """Reduce per-source SLA pills into one cell colour for the system row."""
    order = {"red": 3, "amber": 2, "fresh": 1, "unknown": 0}
    if not statuses:
        return "unknown"
    worst = max(statuses, key=lambda s: order.get(s, 0))
    return {"red": "red", "amber": "amber", "fresh": "green", "unknown": "unknown"}[worst]


def _pct_to_status(pct, green_at: float, amber_at: float) -> str:
    """Map a 0..1 ratio to a green/amber/red/unknown pill."""
    if pct is None:
        return "unknown"
    if pct >= green_at:
        return "green"
    if pct >= amber_at:
        return "amber"
    return "red"


def _coverage_pcts(coverage_rollup_result: dict) -> dict:
    """Average intake/detection/audit pct across a system's sub-profiles.

    ``cyab_subprofile_service.system_coverage`` returns a list of sub-profile
    dicts; for the fleet matrix we need a single intake/detection/audit
    figure per system. Returns None for any dimension with no sub-profiles
    so the cell can render as 'unknown' rather than a misleading 0%.
    """
    subs = (coverage_rollup_result or {}).get("subprofiles") or []
    if not subs:
        return {"intake_pct": None, "detection_pct": None, "audit_pct": None}
    intake = sum(s["intake"]["pct"] for s in subs) / len(subs) / 100.0
    det = sum(s["detection"]["pct"] for s in subs) / len(subs) / 100.0
    aud = sum(s["audit"]["pct"] for s in subs) / len(subs) / 100.0
    return {"intake_pct": intake, "detection_pct": det, "audit_pct": aud}


@router.get(
    "/coverage/matrix",
    dependencies=[Depends(require_permission("alert:read"))],
)
async def coverage_matrix(
    pillar: Optional[str] = None,
    owner: Optional[str] = None,
    any_red: int = 0,
):
    """Fleet x dimensions matrix.

    Rows = CyabSystem rows (filtered by pillar/owner). Columns = the 7
    data-health dimensions. Each cell carries a status pill the UI colours
    green/amber/red/unknown plus a deep-link tab target for the per-system
    page. The aggregates strip is computed once per request.

    The CyabSystem model exposes the system owner via
    ``soc_analyst_owner``; the response uses ``owner`` as the public alias.
    ``business_unit`` doubles as the pillar proxy on the wire.

    The session is built inside the function (dynamic import) rather than
    via ``Depends(get_db_session)`` so the test harness's monkeypatch of
    ``ion.storage.database.get_engine`` is observed regardless of import
    order across the suite — same pattern as other CyAB page handlers.
    """
    return _build_coverage_matrix(pillar=pillar, owner=owner, any_red=any_red)


def _build_coverage_matrix(
    pillar: Optional[str] = None,
    owner: Optional[str] = None,
    any_red: int = 0,
    session: Optional[Session] = None,
) -> dict:
    """Pure helper that builds the matrix payload.

    Accepts an optional ``session`` so callers (the page handler in
    server.py) can pass their own session. When None, opens one via the
    project's standard pattern using a dynamic import to honour test
    monkeypatches.
    """
    from ion.core.config import get_config
    from ion.services import cyab_data_health_service as dh
    from ion.services import cyab_doc_checklist_service as ck
    from ion.storage.database import get_engine, get_session_factory

    own_session = False
    if session is None:
        Session = get_session_factory(get_engine(get_config().db_path))
        session = Session()
        own_session = True
    try:
        return _coverage_matrix_impl(
            session=session, pillar=pillar, owner=owner, any_red=any_red,
            dh=dh, ck=ck,
        )
    finally:
        if own_session:
            session.close()


def _coverage_matrix_impl(*, session, pillar, owner, any_red, dh, ck) -> dict:
    """Inner builder kept separate so the helper above stays small."""
    q = select(CyabSystem)
    if pillar:
        q = q.where(CyabSystem.business_unit == pillar)
    if owner:
        q = q.where(CyabSystem.soc_analyst_owner == owner)
    systems = session.execute(q).scalars().all()

    rows = []
    for sys in systems:
        sid = sys.id

        ing = dh.ingestion_freshness(session, sid)
        ing_status = _worst_sla([r["sla_status"] for r in ing]) if ing else "unknown"

        fm = dh.field_mapping_completeness(session, sid)
        # Average completeness across sources that report a numeric value;
        # sources with no expected-field profile carry None and are excluded.
        scored = [r["completeness"] for r in fm if r.get("completeness") is not None]
        fm_pct = (sum(scored) / len(scored)) if scored else None
        fm_status = _pct_to_status(fm_pct, green_at=0.9, amber_at=0.6)

        cov = _coverage_pcts(dh.coverage_rollup(session, sid))
        intake_status = _pct_to_status(cov["intake_pct"], green_at=0.9, amber_at=0.5)
        det_status = _pct_to_status(cov["detection_pct"], green_at=0.8, amber_at=0.4)
        aud_status = _pct_to_status(cov["audit_pct"], green_at=0.8, amber_at=0.4)

        checklist = ck.coverage_summary(session, sid)
        ck_pct = (checklist["done"] / checklist["total"]) if checklist["total"] else 0
        ck_status = _pct_to_status(ck_pct, green_at=1.0, amber_at=0.5)

        signed_status = "green" if (sys.sign_dept_name and sys.sign_soc_name) else "red"

        cells = {
            "ingestion_fresh":    {"status": ing_status,    "tab": "data-health"},
            "fields_mapped":      {"status": fm_status,     "tab": "sources"},
            "intake_done":        {"status": intake_status, "tab": "intake"},
            "detections_shipped": {"status": det_status,    "tab": "detection"},
            "audit_shipped":      {"status": aud_status,    "tab": "audit-use-cases"},
            "checklist_done":     {"status": ck_status,     "tab": "overview"},
            "signed_off":         {"status": signed_status, "tab": "signoff"},
        }

        if any_red and not any(c["status"] == "red" for c in cells.values()):
            continue

        rows.append({
            "system_id":  sid,
            "name":       sys.name,
            "pillar":     sys.business_unit,
            "owner":      sys.soc_analyst_owner,
            "department": sys.department,
            "cells":      cells,
        })

    # Aggregates: computed against the unfiltered fleet so the strip stays
    # stable as the user filters rows. When no filter is active, reuse the
    # rows we already built; otherwise re-fetch the full set.
    all_systems_for_agg = systems if not (pillar or owner or any_red) else (
        session.execute(select(CyabSystem)).scalars().all()
    )
    total = len(all_systems_for_agg) or 1

    healthy = 0
    for sys in all_systems_for_agg:
        sid = sys.id
        ing = dh.ingestion_freshness(session, sid)
        ing_status = _worst_sla([r["sla_status"] for r in ing]) if ing else "unknown"
        fm = dh.field_mapping_completeness(session, sid)
        scored = [r["completeness"] for r in fm if r.get("completeness") is not None]
        fm_pct = (sum(scored) / len(scored)) if scored else None
        fm_status = _pct_to_status(fm_pct, green_at=0.9, amber_at=0.6)
        cov = _coverage_pcts(dh.coverage_rollup(session, sid))
        intake_status = _pct_to_status(cov["intake_pct"], green_at=0.9, amber_at=0.5)
        det_status = _pct_to_status(cov["detection_pct"], green_at=0.8, amber_at=0.4)
        aud_status = _pct_to_status(cov["audit_pct"], green_at=0.8, amber_at=0.4)
        checklist = ck.coverage_summary(session, sid)
        ck_pct = (checklist["done"] / checklist["total"]) if checklist["total"] else 0
        ck_status = _pct_to_status(ck_pct, green_at=1.0, amber_at=0.5)
        signed_status = "green" if (sys.sign_dept_name and sys.sign_soc_name) else "red"
        all_green = all(s == "green" for s in (
            ing_status, fm_status, intake_status, det_status,
            aud_status, ck_status, signed_status,
        ))
        if all_green:
            healthy += 1

    crit = sum(
        1 for sys in all_systems_for_agg
        if ck.coverage_summary(session, sys.id).get("critical_missing")
    )
    stale = sum(
        1 for sys in all_systems_for_agg
        if any(
            r["sla_status"] == "red"
            for r in dh.ingestion_freshness(session, sys.id)
        )
    )

    return {
        "dimensions": [
            "ingestion_fresh", "fields_mapped", "intake_done",
            "detections_shipped", "audit_shipped", "checklist_done",
            "signed_off",
        ],
        "rows": rows,
        "aggregates": {
            "pct_systems_healthy":  int(round(100 * healthy / total)),
            "pct_critical_missing": int(round(100 * crit / total)),
            "pct_stale_ingestion":  int(round(100 * stale / total)),
        },
    }


# ---------------------------------------------------------------------------
# Audit feed (Sub-plan C / Task 10)
# ---------------------------------------------------------------------------

@router.get(
    "/audit/feed",
    dependencies=[Depends(require_permission("alert:read"))],
)
async def audit_feed_endpoint(
    system_id: Optional[int] = None,
    user: Optional[str] = None,
    action_type: Optional[str] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
    limit: int = 200,
):
    """Chronological feed of CyAB compliance events.

    Thin router shim — opens a session via the standard dynamic-import
    pattern (so test monkeypatches of ``ion.storage.database.get_engine``
    are honoured) and delegates to :func:`audit_feed`. Same pattern as
    :func:`coverage_matrix` / :func:`_build_coverage_matrix`.
    """
    return await audit_feed(
        system_id=system_id, user=user, action_type=action_type,
        since=since, until=until, limit=limit, session=None,
    )


async def audit_feed(
    system_id: Optional[int] = None,
    user: Optional[str] = None,
    action_type: Optional[str] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
    limit: int = 200,
    session: Optional[Session] = None,
) -> dict:
    """Build the chronological feed payload.

    Unions four sources:
      - ``CyabSystem.created_at`` / ``archived_at`` (system lifecycle)
      - ``CyabSnapshot`` rows (sign-offs surfaced when ``notes`` mentions
        a sign-off, otherwise ``snapshot``)
      - ``CyabDocChecklistItem.updated_at`` deltas (status changes)
      - ``change_log_service`` entries with field=``containment_authority``
        — best-effort; the service does not yet expose ``list_events`` so
        a missing API is silently skipped rather than raising.

    Args:
      - ``system_id`` filter to one system
      - ``user`` filter by the ``who`` field
      - ``action_type`` filter by category
      - ``since`` / ``until`` ISO-8601 date or datetime cutoffs (inclusive)
      - ``limit`` cap on returned events (default 200)
      - ``session`` optional caller-supplied session (e.g. from the page
        handler in ``server.py``); when ``None`` we open one ourselves.

    The session is opened via dynamic imports rather than
    ``Depends(get_db_session)`` so the test harness's monkeypatch of
    ``ion.storage.database.get_engine`` is observed regardless of import
    order across the suite — same pattern as ``_build_coverage_matrix``.
    """
    own_session = False
    if session is None:
        from ion.core.config import get_config
        from ion.storage.database import get_engine, get_session_factory
        Session_ = get_session_factory(get_engine(get_config().db_path))
        session = Session_()
        own_session = True

    try:
        return _build_audit_feed(
            session=session,
            system_id=system_id, user=user, action_type=action_type,
            since=since, until=until, limit=limit,
        )
    finally:
        if own_session:
            session.close()


def _build_audit_feed(
    *,
    session: Session,
    system_id: Optional[int],
    user: Optional[str],
    action_type: Optional[str],
    since: Optional[str],
    until: Optional[str],
    limit: int,
) -> dict:
    """Inner builder kept separate so the endpoint stays small. Pure helper
    that takes a live session and returns the feed payload — no I/O setup.
    """
    from ion.models.cyab import CyabSystem, CyabSnapshot
    from ion.models.cyab_doc_checklist import CyabDocChecklistItem

    events: list = []

    # 1. System creates + archives. CyabSystem in this codebase has
    # created_at + created_by (user FK); archived_at is optional and
    # not yet on the model — getattr keeps this forward-compatible.
    sys_q = select(CyabSystem)
    if system_id:
        sys_q = sys_q.where(CyabSystem.id == system_id)
    for sys_row in session.execute(sys_q).scalars().all():
        if sys_row.created_at:
            who = "system"
            creator = getattr(sys_row, "creator", None)
            if creator is not None:
                who = creator.display_name or creator.username or "system"
            events.append({
                "when":        sys_row.created_at.isoformat(),
                "who":         who,
                "what":        f"System '{sys_row.name}' created",
                "system_id":   sys_row.id,
                "system_name": sys_row.name,
                "action_type": "create",
                "link":        f"/cyab/systems/{sys_row.id}",
            })
        archived_at = getattr(sys_row, "archived_at", None)
        if archived_at:
            events.append({
                "when":        archived_at.isoformat(),
                "who":         getattr(sys_row, "archived_by", None) or "system",
                "what":        f"System '{sys_row.name}' archived",
                "system_id":   sys_row.id,
                "system_name": sys_row.name,
                "action_type": "archive",
                "link":        f"/cyab/systems/{sys_row.id}",
            })

    # 2. Snapshots — treat as sign-offs when the notes contain that
    # phrasing, otherwise emit as ``snapshot``. CyabSnapshot has no
    # ``kind`` or ``signed_by`` column in this codebase; getattr keeps
    # the code forward-compatible if either gets added later.
    snap_q = select(CyabSnapshot)
    if system_id:
        snap_q = snap_q.where(CyabSnapshot.system_id == system_id)
    for snap in session.execute(snap_q).scalars().all():
        kind = getattr(snap, "kind", None)
        notes_lower = (snap.notes or "").lower()
        if kind in ("signoff", "checklist_update", "snapshot"):
            atype = kind
        elif "sign" in notes_lower and "off" in notes_lower:
            atype = "signoff"
        else:
            atype = "snapshot"
        when_dt = snap.created_at or datetime.combine(snap.snapshot_date, datetime.min.time())
        events.append({
            "when":          when_dt.isoformat(),
            "who":           getattr(snap, "signed_by", None) or "system",
            "what":          snap.notes or f"Snapshot recorded ({atype})",
            "system_id":     snap.system_id,
            "system_name":   snap.system.name if snap.system else None,
            "action_type":   atype,
            "snapshot_id":   snap.id,
            "snapshot_date": snap.snapshot_date.isoformat(),
            "link":          f"/cyab/systems/{snap.system_id}#snapshot={snap.id}",
            "pdf_link":      f"/api/cyab/systems/{snap.system_id}/onboarding-pack?as_of={snap.snapshot_date.isoformat()}",
        })

    # 3. Checklist updates. The model exposes the user FK as
    # ``updated_by_id`` and the relationship as ``updated_by``.
    ck_q = select(CyabDocChecklistItem)
    if system_id:
        ck_q = ck_q.where(CyabDocChecklistItem.system_id == system_id)
    for item in session.execute(ck_q).scalars().all():
        ts = getattr(item, "updated_at", None) or getattr(item, "created_at", None)
        if not ts:
            continue
        who = "system"
        ub = getattr(item, "updated_by", None)
        if ub is not None:
            who = ub.display_name or ub.username or "system"
        events.append({
            "when":        ts.isoformat(),
            "who":         who,
            "what":        f"Checklist item '{item.label}' → {item.status}",
            "system_id":   item.system_id,
            "system_name": None,
            "action_type": "checklist_update",
            "link":        f"/cyab/systems/{item.system_id}#tab=overview",
        })

    # 4. Containment-authority changes via change_log_service. The
    # service does not currently expose a ``list_events`` query API;
    # the try/except keeps this forward-compatible without failing.
    try:
        from ion.services import change_log_service as cls
        if hasattr(cls, "list_events"):
            cls_events = cls.list_events(
                session,
                entity_type="cyab.system",
                field="containment_authority",
                system_id=system_id,
                limit=200,
            )
            for ev in cls_events:
                when_v = ev["when"]
                events.append({
                    "when":        when_v.isoformat() if hasattr(when_v, "isoformat") else str(when_v),
                    "who":         ev.get("who") or "unknown",
                    "what":        f"Containment authority: {ev.get('old_value')} → {ev.get('new_value')}",
                    "system_id":   ev.get("entity_id"),
                    "system_name": None,
                    "action_type": "containment_change",
                    "link":        f"/cyab/systems/{ev.get('entity_id')}#tab=signoff",
                })
    except Exception:
        # Best-effort union — never let an aux source break the feed.
        pass

    # Filter by user / action_type
    if user:
        events = [e for e in events if e["who"] == user]
    if action_type:
        events = [e for e in events if e["action_type"] == action_type]

    # Date filters — accept either YYYY-MM-DD or full ISO datetime.
    def _parse(s: str):
        try:
            return datetime.fromisoformat(s)
        except Exception:
            return None

    if since:
        cutoff = _parse(since)
        if cutoff:
            events = [e for e in events if datetime.fromisoformat(e["when"]) >= cutoff]
    if until:
        cutoff = _parse(until)
        if cutoff:
            events = [e for e in events if datetime.fromisoformat(e["when"]) <= cutoff]

    events.sort(key=lambda e: e["when"], reverse=True)
    return {"events": events[:limit], "total": len(events)}


# ═══════════════════════════════════════════════════════════════════════════
#  Migrated from cyab_studio_api (dropped in v0.20.0).
#
#  All routes formerly under /api/cyab/studio/* now live here under
#  /api/cyab/*.  Templates and tests were updated to match; the old
#  /api/cyab/studio router mount and cyab_studio_api.py have been removed.
# ═══════════════════════════════════════════════════════════════════════════

import html as _html_mod
import logging as _logging
import re as _re
from typing import Any, Dict

from ion.models.cyab_subprofile import CyabPillar, CyabSubProfile
from ion.services.cyab_subprofile_service import (
    get_subprofile_full,
    get_use_case,
    list_pillars,
    list_subprofiles_for_pillar,
    patch_subprofile,
    system_coverage,
)
from ion.services import cyab_doc_checklist_service as _doc_svc

_studio_logger = _logging.getLogger(__name__)

_STUDIO_NOTES_MARKER = "STUDIO_AUTOSAVE"
_VALID_UC_STATUSES = {"shipped", "partial", "gap", "n/a"}


# ---------------------------------------------------------------------------
# Pydantic models (studio-origin)
# ---------------------------------------------------------------------------

class SubprofilePatch(BaseModel):
    label: Optional[str] = None
    icon: Optional[str] = None
    description: Optional[str] = None
    ecs_anchors: Optional[List[str]] = None
    expected_feeds: Optional[List[str]] = None
    catalogue: Optional[Dict[str, Any]] = None


class TideStubRequest(BaseModel):
    subprofile_id: str


class SignOffRequest(BaseModel):
    sign_dept_name: Optional[str] = None
    sign_soc_name: Optional[str] = None
    containment_authority: Optional[str] = None


class AnswersPatch(BaseModel):
    answers: Dict[str, Any]
    subprofile_id: Optional[str] = None


class UseCaseStatusPatch(BaseModel):
    statuses: Dict[str, Optional[str]]


class SubprofileCreate(BaseModel):
    id: str
    pillar_id: str
    label: str
    icon: Optional[str] = "cpu"
    description: Optional[str] = None
    ecs_anchors: Optional[List[str]] = None
    expected_feeds: Optional[List[str]] = None


class DocChecklistUpdate(BaseModel):
    status: Optional[str] = None
    url: Optional[str] = None
    notes: Optional[str] = None
    label: Optional[str] = None
    is_critical: Optional[bool] = None


class DocChecklistAdd(BaseModel):
    kind: str
    label: str
    category: str = "design"
    is_critical: bool = False
    status: str = "unknown"
    url: Optional[str] = None
    notes: Optional[str] = None


# ---------------------------------------------------------------------------
# Catalogue read — pillars + sub-profiles
# ---------------------------------------------------------------------------

@router.get("/pillars")
def get_pillars(session: Session = Depends(get_db_session)):
    return {"pillars": list_pillars(session)}


@router.get("/pillars/{pillar_id}/subprofiles")
def get_subprofiles_in_pillar(
    pillar_id: str,
    session: Session = Depends(get_db_session),
):
    pillar = session.get(CyabPillar, pillar_id)
    if pillar is None:
        raise HTTPException(status_code=404, detail="Unknown pillar")
    return {
        "pillar": {
            "id": pillar.id,
            "label": pillar.label,
            "icon": pillar.icon,
            "priority": pillar.priority,
            "description": pillar.description,
        },
        "subprofiles": list_subprofiles_for_pillar(session, pillar_id),
    }


@router.get("/subprofiles/{sub_id}")
def get_subprofile(sub_id: str, session: Session = Depends(get_db_session)):
    full = get_subprofile_full(session, sub_id)
    if full is None:
        raise HTTPException(status_code=404, detail="Unknown sub-profile")
    return full


def _row_to_full_dict(row: CyabSubProfile) -> Dict[str, Any]:
    return {
        "id": row.id,
        "pillar_id": row.pillar_id,
        "label": row.label,
        "icon": row.icon,
        "description": row.description,
        "ecs_anchors": json.loads(row.ecs_anchors or "[]"),
        "expected_feeds": json.loads(row.expected_feeds or "[]"),
        "catalogue": json.loads(row.catalogue_json or "{}"),
        "catalogue_version": row.catalogue_version,
        "is_custom": row.is_custom,
    }


@router.post(
    "/subprofiles",
    dependencies=[Depends(require_permission("case:update"))],
)
def create_subprofile_route(
    body: SubprofileCreate,
    session: Session = Depends(get_db_session),
):
    import re as _re2
    if not _re2.fullmatch(r"[a-z0-9_]{2,64}", body.id):
        raise HTTPException(status_code=400, detail="id must be 2–64 chars of [a-z0-9_]")
    pillar = session.get(CyabPillar, body.pillar_id)
    if pillar is None:
        raise HTTPException(status_code=404, detail="Unknown pillar")
    existing = session.get(CyabSubProfile, body.id)
    if existing is not None:
        raise HTTPException(status_code=409, detail="Sub-profile id already exists")
    row = CyabSubProfile(
        id=body.id,
        pillar_id=body.pillar_id,
        label=body.label,
        icon=body.icon or "cpu",
        ecs_anchors=json.dumps(body.ecs_anchors or []),
        expected_feeds=json.dumps(body.expected_feeds or []),
        catalogue_json=json.dumps({
            "intake_questions": [], "recommended_tasks": [],
            "detection_use_cases": [], "audit_use_cases": [], "references": [],
        }, sort_keys=True),
        catalogue_version=1,
        is_custom=True,
        description=body.description,
    )
    session.add(row)
    session.commit()
    return _row_to_full_dict(row)


@router.patch(
    "/subprofiles/{sub_id}",
    dependencies=[Depends(require_permission("case:update"))],
)
def patch_subprofile_route(
    sub_id: str,
    patch: SubprofilePatch,
    session: Session = Depends(get_db_session),
):
    payload = patch.model_dump(exclude_unset=True)
    if not payload:
        raise HTTPException(status_code=400, detail="Empty patch")
    updated = patch_subprofile(session, sub_id, payload)
    if updated is None:
        raise HTTPException(status_code=404, detail="Unknown sub-profile")
    return updated


@router.get("/subprofiles/{sub_id}/use-cases/{uc_id}")
def get_use_case_route(
    sub_id: str,
    uc_id: str,
    session: Session = Depends(get_db_session),
):
    uc = get_use_case(session, sub_id, uc_id)
    if uc is None:
        raise HTTPException(status_code=404, detail="Unknown use case")
    return uc


# ---------------------------------------------------------------------------
# TIDE stub generation
# ---------------------------------------------------------------------------

@router.post(
    "/use-cases/{uc_id}/tide-stub",
    dependencies=[Depends(require_permission("case:update"))],
)
def generate_tide_stub(
    uc_id: str,
    body: TideStubRequest,
    session: Session = Depends(get_db_session),
    current_user: Optional[User] = Depends(get_current_user),
):
    uc = get_use_case(session, body.subprofile_id, uc_id)
    if uc is None:
        raise HTTPException(status_code=404, detail="Unknown use case")
    try:
        tide = get_tide_service()
        if tide is None or not getattr(tide, "is_configured", lambda: False)():
            raise HTTPException(status_code=503, detail="TIDE not configured")
    except ImportError:
        raise HTTPException(status_code=503, detail="TIDE service unavailable")
    severity_map = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}
    rule_payload = {
        "name": uc.get("title", uc_id),
        "description": uc.get("description") or uc.get("summary") or "",
        "severity": severity_map.get(uc.get("risk", "medium"), "Medium"),
        "mitre_techniques": list(uc.get("mitre_ids") or []),
        "language": uc.get("logic_lang", "esql"),
        "rule_body": uc.get("logic_snippet", ""),
        "tags": ["cyab-onboarding", f"subprofile:{body.subprofile_id}"],
        "source": "ion.cyab.onboarding",
    }
    try:
        create_fn = getattr(tide, "create_rule_stub", None) or getattr(tide, "create_rule", None)
        if create_fn is None:
            raise HTTPException(status_code=501, detail="TIDE client lacks create_rule support")
        new_rule_id = create_fn(rule_payload)
    except HTTPException:
        raise
    except Exception as e:
        _studio_logger.warning("TIDE stub generation failed: %s", e)
        raise HTTPException(status_code=502, detail=f"TIDE create failed: {e}")
    full = get_subprofile_full(session, body.subprofile_id)
    if full is None:
        raise HTTPException(status_code=404, detail="Unknown sub-profile")
    cat = full.get("catalogue") or {}
    for kind in ("detection_use_cases", "audit_use_cases"):
        for entry in cat.get(kind) or []:
            if entry.get("id") == uc_id:
                ids = list(entry.get("tide_rule_ids") or [])
                ids.append(new_rule_id)
                entry["tide_rule_ids"] = ids
                break
    patch_subprofile(session, body.subprofile_id, {"catalogue": cat})
    return {"tide_rule_id": new_rule_id, "use_case_id": uc_id}


# ---------------------------------------------------------------------------
# System intake answers (autosave)
# ---------------------------------------------------------------------------

def _get_or_create_studio_assessment(
    session: Session, sys_id: int, user_id: Optional[int],
) -> CyabSystemAssessment:
    from ion.services.cyab_assessment_questions import SCHEMA_VERSION
    row = session.scalars(
        select(CyabSystemAssessment)
        .where(CyabSystemAssessment.system_id == sys_id)
        .where(CyabSystemAssessment.notes == _STUDIO_NOTES_MARKER)
        .order_by(CyabSystemAssessment.submitted_at.desc())
        .limit(1)
    ).first()
    if row is not None:
        return row
    row = CyabSystemAssessment(
        system_id=sys_id,
        schema_version=SCHEMA_VERSION,
        submitted_by=user_id,
        responses_json="{}",
        notes=_STUDIO_NOTES_MARKER,
    )
    session.add(row)
    session.flush()
    return row


@router.get("/systems/{sys_id}/answers")
def get_system_answers(sys_id: int, session: Session = Depends(get_db_session)):
    sys = session.get(CyabSystem, sys_id)
    if sys is None:
        raise HTTPException(status_code=404, detail="Unknown system")
    legacy = session.scalars(
        select(CyabSystemAssessment)
        .where(CyabSystemAssessment.system_id == sys_id)
        .where(CyabSystemAssessment.notes != _STUDIO_NOTES_MARKER)
        .order_by(CyabSystemAssessment.submitted_at.desc())
        .limit(1)
    ).first()
    studio = session.scalars(
        select(CyabSystemAssessment)
        .where(CyabSystemAssessment.system_id == sys_id)
        .where(CyabSystemAssessment.notes == _STUDIO_NOTES_MARKER)
        .limit(1)
    ).first()
    merged: Dict[str, Any] = {}
    for src in (legacy, studio):
        if src and src.responses_json:
            try:
                merged.update(json.loads(src.responses_json) or {})
            except json.JSONDecodeError:
                pass
    return {
        "system_id": sys_id,
        "answers": merged,
        "studio_assessment_id": studio.id if studio else None,
    }


@router.post(
    "/systems/{sys_id}/answers",
    dependencies=[Depends(require_permission("case:update"))],
)
def patch_system_answers(
    sys_id: int,
    body: AnswersPatch,
    session: Session = Depends(get_db_session),
    current_user: Optional[User] = Depends(get_current_user),
):
    sys = session.get(CyabSystem, sys_id)
    if sys is None:
        raise HTTPException(status_code=404, detail="Unknown system")
    row = _get_or_create_studio_assessment(
        session, sys_id, current_user.id if current_user else None,
    )
    try:
        existing = json.loads(row.responses_json or "{}")
    except json.JSONDecodeError:
        existing = {}
    for k, v in (body.answers or {}).items():
        if v is None:
            existing.pop(k, None)
        else:
            existing[k] = v
    row.responses_json = json.dumps(existing, default=str, sort_keys=True)
    row.submitted_at = datetime.utcnow()
    if current_user is not None:
        row.submitted_by = current_user.id
    session.commit()
    return {
        "system_id": sys_id,
        "studio_assessment_id": row.id,
        "answer_count": len(existing),
    }


# ---------------------------------------------------------------------------
# Data-source use-case status
# ---------------------------------------------------------------------------

@router.get("/systems/{sys_id}/data-sources")
def list_data_sources_for_system(
    sys_id: int,
    subprofile_id: Optional[str] = None,
    session: Session = Depends(get_db_session),
):
    sys = session.get(CyabSystem, sys_id)
    if sys is None:
        raise HTTPException(status_code=404, detail="Unknown system")
    q = select(CyabDataSource).where(CyabDataSource.system_id == sys_id)
    if subprofile_id:
        q = q.where(CyabDataSource.subprofile_id == subprofile_id)
    q = q.order_by(CyabDataSource.name.asc())
    rows = session.scalars(q).all()
    return {
        "system_id": sys_id,
        "subprofile_id": subprofile_id,
        "data_sources": [
            {
                "id": r.id,
                "name": r.name,
                "data_source_type": r.data_source_type,
                "subprofile_id": r.subprofile_id,
                "data_namespace": r.data_namespace,
            }
            for r in rows
        ],
    }


@router.get("/data-sources/{ds_id}/use-case-status")
def get_data_source_uc_status(ds_id: int, session: Session = Depends(get_db_session)):
    ds = session.get(CyabDataSource, ds_id)
    if ds is None:
        raise HTTPException(status_code=404, detail="Unknown data source")
    raw = ds.use_case_status
    parsed: Dict[str, str] = {}
    legacy: Optional[str] = None
    if raw:
        try:
            obj = json.loads(raw)
            if isinstance(obj, dict):
                parsed = {k: v for k, v in obj.items() if v in _VALID_UC_STATUSES}
            else:
                legacy = raw
        except json.JSONDecodeError:
            legacy = raw
    return {
        "data_source_id": ds_id,
        "subprofile_id": ds.subprofile_id,
        "statuses": parsed,
        "legacy_text": legacy,
    }


@router.post(
    "/data-sources/{ds_id}/use-case-status",
    dependencies=[Depends(require_permission("case:update"))],
)
def patch_data_source_uc_status(
    ds_id: int,
    body: UseCaseStatusPatch,
    session: Session = Depends(get_db_session),
):
    ds = session.get(CyabDataSource, ds_id)
    if ds is None:
        raise HTTPException(status_code=404, detail="Unknown data source")
    raw = ds.use_case_status
    existing: Dict[str, str] = {}
    if raw:
        try:
            obj = json.loads(raw)
            if isinstance(obj, dict):
                existing = {k: v for k, v in obj.items() if v in _VALID_UC_STATUSES}
        except json.JSONDecodeError:
            pass
    for k, v in (body.statuses or {}).items():
        if v is None:
            existing.pop(k, None)
            continue
        if v not in _VALID_UC_STATUSES:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid status '{v}' for {k}; must be one of {sorted(_VALID_UC_STATUSES)}",
            )
        existing[k] = v
    ds.use_case_status = json.dumps(existing, sort_keys=True)
    session.commit()
    return {"data_source_id": ds_id, "statuses": existing, "count": len(existing)}


# ---------------------------------------------------------------------------
# Per-system sub-profile coverage
# ---------------------------------------------------------------------------

@router.get("/systems/{sys_id}/coverage")
def get_system_coverage(sys_id: int, session: Session = Depends(get_db_session)):
    sys = session.get(CyabSystem, sys_id)
    if sys is None:
        raise HTTPException(status_code=404, detail="Unknown system")
    return system_coverage(session, sys_id)


# ---------------------------------------------------------------------------
# Onboarding Pack PDF
# ---------------------------------------------------------------------------

def _h(v: Any) -> str:
    return _html_mod.escape("" if v is None else str(v), quote=True)


def _render_onboarding_pack_html(session: Session, sys: CyabSystem) -> str:
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    org_asmt = session.scalars(
        select(CyabAssessment).order_by(CyabAssessment.submitted_at.desc()).limit(1)
    ).first()
    sys_asmt = session.scalars(
        select(CyabSystemAssessment)
        .where(CyabSystemAssessment.system_id == sys.id)
        .order_by(CyabSystemAssessment.submitted_at.desc()).limit(1)
    ).first()
    sources = session.scalars(
        select(CyabDataSource).where(CyabDataSource.system_id == sys.id)
    ).all()
    coverage = system_coverage(session, sys.id)
    cover = (
        f"<h1 style='border:none;margin:0;padding:0;'>CyAB Onboarding Pack</h1>"
        f"<p class='pdf-subtitle'>{_h(sys.name)} &bull; {_h(sys.department)} &bull; {now} &bull; ION</p>"
        f"<table class='pdf-meta'>"
        f"<tr><td>System</td><td><strong>{_h(sys.name)}</strong></td></tr>"
        f"<tr><td>Department</td><td>{_h(sys.department)}</td></tr>"
        f"<tr><td>Status</td><td>{_h(sys.status)}</td></tr>"
        f"<tr><td>Readiness score</td><td>{_h(sys.readiness_score)}%</td></tr>"
        f"</table>"
    )
    context = "<h2>Strategic context</h2>"
    if org_asmt and org_asmt.computed_profile_json:
        try:
            profile = json.loads(org_asmt.computed_profile_json)
        except json.JSONDecodeError:
            profile = {}
        rows_html = "".join(
            f"<tr><td>{_h(k)}</td><td>{_h(v)}</td></tr>" for k, v in profile.items()
        )
        context += f"<table class='pdf-meta'>{rows_html}</table>"
    else:
        context += "<p><em>No org-wide assessment captured yet.</em></p>"
    scope = (
        "<h2>System scope &mdash; data sources</h2><table>"
        "<thead><tr><th>Name</th><th>Type</th><th>Sub-profile</th>"
        "<th>SAL</th><th>Retention</th><th>P1 SLA</th><th>Namespace</th></tr></thead><tbody>"
    )
    for ds in sources:
        scope += (
            f"<tr><td>{_h(ds.name)}</td><td>{_h(ds.data_source_type)}</td>"
            f"<td>{_h(ds.subprofile_id) or '<em>not set</em>'}</td>"
            f"<td>{_h(ds.sal_tier)}</td><td>{_h(ds.retention)}</td>"
            f"<td>{_h(ds.p1_sla)}</td><td>{_h(ds.data_namespace)}</td></tr>"
        )
    scope += "</tbody></table>"
    readiness_html = "<h2>Per-sub-profile readiness</h2>"
    answers: Dict[str, Any] = {}
    if sys_asmt and sys_asmt.responses_json:
        try:
            answers = json.loads(sys_asmt.responses_json)
        except json.JSONDecodeError:
            answers = {}
    if not coverage["subprofiles"]:
        readiness_html += "<p><em>No sub-profiles assigned to data sources yet.</em></p>"
    else:
        for sp in coverage["subprofiles"]:
            sub_full = get_subprofile_full(session, sp["subprofile_id"]) or {}
            cat = sub_full.get("catalogue") or {}
            readiness_html += (
                f"<h3>{_h(sp['label'])}</h3>"
                f"<p class='pdf-meta'>Intake: {_h(sp['intake']['answered'])}/{_h(sp['intake']['total'])} "
                f"({_h(sp['intake']['pct'])}%) &bull; "
                f"Detection: {_h(sp['detection']['shipped'])}/{_h(sp['detection']['total'])} "
                f"({_h(sp['detection']['pct'])}%) &bull; "
                f"Audit: {_h(sp['audit']['shipped'])}/{_h(sp['audit']['total'])} "
                f"({_h(sp['audit']['pct'])}%)</p>"
            )
            qs = cat.get("intake_questions") or []
            if qs:
                readiness_html += (
                    "<table><thead><tr><th>Question</th><th>Answer</th></tr></thead><tbody>"
                )
                for q in qs:
                    ans = answers.get(q["key"], "<em>not answered</em>")
                    readiness_html += f"<tr><td>{_h(q['text'])}</td><td>{_h(ans)}</td></tr>"
                readiness_html += "</tbody></table>"
            dets = cat.get("detection_use_cases") or []
            if dets:
                readiness_html += (
                    "<h4>Detection coverage</h4>"
                    "<table><thead><tr><th>Use case</th><th>MITRE</th><th>Risk</th></tr></thead><tbody>"
                )
                for d in dets:
                    readiness_html += (
                        f"<tr><td>{_h(d.get('title'))}</td>"
                        f"<td>{_h(', '.join(d.get('mitre_ids') or []))}</td>"
                        f"<td>{_h(d.get('risk'))}</td></tr>"
                    )
                readiness_html += "</tbody></table>"
            auds = cat.get("audit_use_cases") or []
            if auds:
                readiness_html += (
                    "<h4>Audit / compliance coverage</h4>"
                    "<table><thead><tr><th>Use case</th><th>Compliance</th><th>Risk</th></tr></thead><tbody>"
                )
                for a in auds:
                    readiness_html += (
                        f"<tr><td>{_h(a.get('title'))}</td>"
                        f"<td>{_h(', '.join(a.get('compliance_frames') or []))}</td>"
                        f"<td>{_h(a.get('risk'))}</td></tr>"
                    )
                readiness_html += "</tbody></table>"
    containment = (
        f"<h2>Containment authority</h2><p>{_h(sys.containment_authority)}</p>"
        if sys.containment_authority else
        "<h2>Containment authority</h2><p><em>Not yet captured.</em></p>"
    )
    try:
        doc_items = _doc_svc.list_for_system(session, sys.id)
        doc_cov = _doc_svc.coverage_summary(session, sys.id)
    except Exception:
        doc_items, doc_cov = [], None
    if doc_items:
        by_cat: Dict[str, list] = {}
        for it in doc_items:
            by_cat.setdefault(it.get("category", "design"), []).append(it)
        cat_labels = {
            "design": "Architecture & Design", "operational": "Operational",
            "security": "Security & Risk", "compliance": "Compliance",
        }
        STATUS_LABEL = {
            "done": "Done", "in_progress": "In progress",
            "missing": "Missing", "na": "N/A", "unknown": "Unknown",
        }
        doc_rows = []
        for cat in ["design", "operational", "security", "compliance"]:
            if cat not in by_cat:
                continue
            doc_rows.append(f"<h3>{_h(cat_labels.get(cat, cat.title()))}</h3>")
            doc_rows.append(
                "<table><tr><th>Item</th><th>Status</th><th>Link</th><th>Notes</th></tr>"
            )
            for it in by_cat[cat]:
                star = " ★" if it.get("is_critical") else ""
                status_lbl = STATUS_LABEL.get(it.get("status", "unknown"), it.get("status", ""))
                url = it.get("url") or ""
                url_cell = f'<a href="{_h(url)}">{_h(url)[:60]}</a>' if url else ""
                doc_rows.append(
                    f"<tr><td>{_h(it.get('label', ''))}{star}</td>"
                    f"<td>{_h(status_lbl)}</td><td>{url_cell}</td>"
                    f"<td>{_h((it.get('notes') or '')[:160])}</td></tr>"
                )
            doc_rows.append("</table>")
        critical_block = ""
        if doc_cov and doc_cov.get("critical_missing"):
            missing = ", ".join(doc_cov["critical_missing"])
            critical_block = (
                f'<p style="color:#a40000;"><strong>Critical documents missing:</strong> '
                f'{_h(missing)}</p>'
            )
        doc_section = (
            "<h2>Documentation checklist</h2>"
            f'<p>★ marks critical items. Coverage: '
            f'<strong>{(doc_cov or {}).get("done", 0)}/{(doc_cov or {}).get("total", 0)}</strong> '
            f'done · {(doc_cov or {}).get("completion_pct", 0)}%.</p>'
            f"{critical_block}" + "".join(doc_rows)
        )
    else:
        doc_section = ""
    signoff = (
        "<h2>Sign-off</h2><table class='pdf-meta'>"
        f"<tr><td>Department lead</td><td>{_h(sys.sign_dept_name) or '<em>pending</em>'}</td>"
        f"<td>{_h(sys.sign_dept_date) or ''}</td></tr>"
        f"<tr><td>SOC lead</td><td>{_h(sys.sign_soc_name) or '<em>pending</em>'}</td>"
        f"<td>{_h(sys.sign_soc_date) or ''}</td></tr></table>"
    )
    style = (
        "<style>"
        "@page { size: A4; margin: 18mm; }"
        "body { font-family: -apple-system, 'Segoe UI', Roboto, sans-serif; color: #1a1a1a; font-size: 11pt; }"
        "h1 { font-size: 24pt; color: #0b3d91; }"
        "h2 { color: #0b3d91; border-bottom: 2px solid #0b3d91; padding-bottom: 4px; margin-top: 28px; }"
        "h3 { color: #1a4ea3; margin-top: 18px; }"
        "h4 { color: #444; margin-top: 12px; }"
        "table { width: 100%; border-collapse: collapse; margin: 8px 0; font-size: 10pt; }"
        "th, td { border: 1px solid #d0d7de; padding: 6px 8px; text-align: left; vertical-align: top; }"
        "th { background: #f6f8fa; }"
        "table.pdf-meta { width: auto; }"
        "table.pdf-meta td { border: none; padding: 3px 12px 3px 0; }"
        ".pdf-subtitle { color: #555; font-size: 10pt; margin-top: 0; }"
        "</style>"
    )
    return (
        f"<!DOCTYPE html><html><head>{style}</head>"
        f"<body>{cover}{context}{scope}{readiness_html}{containment}{doc_section}{signoff}</body></html>"
    )


from fastapi.responses import Response as _Response


@router.get(
    "/systems/{sys_id}/onboarding-pack",
    dependencies=[Depends(require_permission("case:read"))],
)
def render_onboarding_pack(sys_id: int, session: Session = Depends(get_db_session)):
    sys = session.get(CyabSystem, sys_id)
    if sys is None:
        raise HTTPException(status_code=404, detail="Unknown system")
    full_html = _render_onboarding_pack_html(session, sys)
    try:
        from weasyprint import HTML as WpHTML
        pdf_bytes = WpHTML(string=full_html).write_pdf()
        slug = _re.sub(r"[^A-Za-z0-9._-]+", "_", sys.name or "system").strip("_")[:60] or "system"
        filename = f"onboarding_pack_{slug}_{date.today().isoformat()}.pdf"
        return _Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "X-Content-Type-Options": "nosniff",
            },
        )
    except (ImportError, OSError):
        return _Response(
            content=full_html,
            media_type="text/html",
            headers={
                "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src data:",
                "X-Content-Type-Options": "nosniff",
            },
        )


@router.post(
    "/systems/{sys_id}/onboarding-pack/sign",
    dependencies=[Depends(require_permission("case:update"))],
)
def sign_onboarding_pack(
    sys_id: int,
    body: SignOffRequest,
    session: Session = Depends(get_db_session),
    current_user: Optional[User] = Depends(get_current_user),
):
    sys = session.get(CyabSystem, sys_id)
    if sys is None:
        raise HTTPException(status_code=404, detail="Unknown system")
    today = date.today()
    if body.sign_dept_name is not None:
        sys.sign_dept_name = body.sign_dept_name
        sys.sign_dept_date = today
    if body.sign_soc_name is not None:
        sys.sign_soc_name = body.sign_soc_name
        sys.sign_soc_date = today
    if body.containment_authority is not None:
        sys.containment_authority = body.containment_authority
    if sys.sign_dept_name and sys.sign_soc_name:
        sys.status = "ACTIVE"
    session.commit()
    session.refresh(sys)
    try:
        coverage = _doc_svc.coverage_summary(session, sys.id)
    except Exception:
        coverage = None
    return {
        "system_id": sys.id,
        "status": sys.status,
        "sign_dept_name": sys.sign_dept_name,
        "sign_dept_date": sys.sign_dept_date.isoformat() if sys.sign_dept_date else None,
        "sign_soc_name": sys.sign_soc_name,
        "sign_soc_date": sys.sign_soc_date.isoformat() if sys.sign_soc_date else None,
        "containment_authority": sys.containment_authority,
        "doc_checklist_coverage": coverage,
    }


# ---------------------------------------------------------------------------
# Documentation checklist
# ---------------------------------------------------------------------------

@router.get("/systems/{sys_id}/checklist")
def get_doc_checklist(
    sys_id: int,
    session: Session = Depends(get_db_session),
    _user: User = Depends(get_current_user),
):
    sys_row = session.get(CyabSystem, sys_id)
    if not sys_row:
        raise HTTPException(status_code=404, detail=f"System {sys_id} not found")
    return {
        "system_id": sys_id,
        "items": _doc_svc.list_for_system(session, sys_id),
        "coverage": _doc_svc.coverage_summary(session, sys_id),
    }


@router.put(
    "/checklist/{item_id}",
    dependencies=[Depends(require_permission("case:update"))],
)
def update_doc_checklist_item(
    item_id: int,
    body: DocChecklistUpdate,
    session: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
):
    try:
        out = _doc_svc.update_item(
            session, item_id,
            status=body.status, url=body.url, notes=body.notes,
            label=body.label, is_critical=body.is_critical,
            user_id=current_user.id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if out is None:
        raise HTTPException(status_code=404, detail=f"Checklist item {item_id} not found")
    return out


@router.post(
    "/systems/{sys_id}/checklist",
    dependencies=[Depends(require_permission("case:update"))],
)
def add_custom_doc_checklist_item(
    sys_id: int,
    body: DocChecklistAdd,
    session: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
):
    sys_row = session.get(CyabSystem, sys_id)
    if not sys_row:
        raise HTTPException(status_code=404, detail=f"System {sys_id} not found")
    try:
        out = _doc_svc.add_custom_item(
            session, sys_id,
            kind=body.kind, label=body.label, category=body.category,
            is_critical=body.is_critical, status=body.status,
            url=body.url, notes=body.notes,
            user_id=current_user.id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return out


@router.delete(
    "/checklist/{item_id}",
    dependencies=[Depends(require_permission("case:update"))],
)
def delete_custom_doc_checklist_item(
    item_id: int,
    session: Session = Depends(get_db_session),
    _user: User = Depends(get_current_user),
):
    ok = _doc_svc.delete_custom_item(session, item_id)
    if not ok:
        raise HTTPException(
            status_code=400,
            detail="Item not found, or it is a default-catalogue row (cannot be deleted).",
        )
    return {"ok": True, "deleted": item_id}


# ---------------------------------------------------------------------------
# System hard-delete (migrated from studio; used by both per-row UI and bulk)
# ---------------------------------------------------------------------------

def _delete_system_row(session: Session, sys_id: int) -> bool:
    """Hard-delete a CyabSystem and its non-cascading children."""
    from ion.models.cyab import CyabDataSource, CyabSnapshot
    sys_row = session.get(CyabSystem, sys_id)
    if sys_row is None:
        return False
    session.query(CyabSnapshot).filter(CyabSnapshot.system_id == sys_id).delete(
        synchronize_session=False
    )
    session.query(CyabDataSource).filter(CyabDataSource.system_id == sys_id).delete(
        synchronize_session=False
    )
    session.delete(sys_row)
    session.commit()
    return True


# ---------------------------------------------------------------------------
# Scoping pack PDF (inlined — no longer proxied from studio)
# ---------------------------------------------------------------------------

def _render_scoping_pack_pdf_html(scores: dict, answers: dict) -> str:
    from datetime import datetime as _dt
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    template_dir = Path(__file__).parent / "templates"
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(["html"]),
    )
    tmpl = env.get_template("cyab/_scoping_pack_pdf.html")
    return tmpl.render(
        scores=scores,
        answers=answers,
        generated_at=_dt.now().strftime("%Y-%m-%d %H:%M"),
    )
