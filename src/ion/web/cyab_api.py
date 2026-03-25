"""CyAB (Cyber Assurance Baseline) API — systems, data sources, snapshots."""

import json
from datetime import date, datetime, timedelta
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.orm import Session

from ion.auth.dependencies import get_current_user, require_permission
from ion.models.cyab import CyabSystem, CyabDataSource, CyabSnapshot, SYSTEM_ICONS
from ion.models.user import User, Role, user_roles
from ion.web.api import get_db_session
from ion.web.notification_api import create_notification

router = APIRouter()


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
    )
    session.add(ds)
    session.flush()

    # Recalculate system aggregates
    session.refresh(sys)
    _recalc_system_aggregates(sys)
    _create_snapshot(session, sys, notes=f"Data source added: {req.name}", ds_id=ds.id)
    session.commit()
    session.refresh(ds)
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
    for f in ["name", "data_source_type", "icon", "sal_tier", "uptime_target",
              "max_latency", "retention", "p1_sla", "field_mapping_score",
              "mandatory_score", "readiness_score", "risk_rating", "sal_compliance",
              "field_notes", "use_case_status", "use_case_gaps", "use_case_remediation"]:
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
# Review reminders
# ---------------------------------------------------------------------------

@router.post("/check-reminders")
async def check_review_reminders(session: Session = Depends(get_db_session)):
    today = date.today()
    due_systems = session.execute(
        select(CyabSystem).where(CyabSystem.next_review_date <= today + timedelta(days=7))
    ).scalars().all()
    if not due_systems:
        return {"notifications_sent": 0}

    lead_users = session.execute(
        select(User)
        .join(user_roles, user_roles.c.user_id == User.id)
        .join(Role, Role.id == user_roles.c.role_id)
        .where(Role.name.in_(["lead", "admin", "principal_analyst"]))
        .where(User.is_active == True)
    ).scalars().all()

    sent = 0
    for sys in due_systems:
        is_overdue = sys.next_review_date < today
        label = "OVERDUE" if is_overdue else "Due soon"
        for u in lead_users:
            create_notification(
                session=session, user_id=u.id, source="cyab_review",
                source_id=str(sys.id),
                title=f"CyAB Review {label}: {sys.name}",
                body=f"{sys.department} — review {'was due ' + sys.next_review_date.isoformat() if is_overdue else 'due ' + sys.next_review_date.isoformat()}",
                url=f"/cyab#{sys.id}",
            )
            sent += 1
    session.commit()
    return {"notifications_sent": sent, "systems_due": len(due_systems)}
