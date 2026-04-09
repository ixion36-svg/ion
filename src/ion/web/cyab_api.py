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
from ion.services.tide_service import get_tide_service, reset_tide_service
from ion.core.safe_errors import safe_error

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
        tide_system_id=req.tide_system_id,
        data_namespace=req.data_namespace,
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
# Detection Engineering endpoints (TIDE-powered)
# ---------------------------------------------------------------------------

@router.get("/tide/de/systems", dependencies=[Depends(require_permission("alert:read"))])
def tide_de_systems():
    """List all TIDE systems (for dropdown selectors)."""
    svc = get_tide_service()
    return svc.get_systems()


@router.get("/tide/de/posture", dependencies=[Depends(require_permission("alert:read"))])
def tide_de_posture():
    """Detection posture overview — totals, severity, quality, coverage."""
    svc = get_tide_service()
    result = svc.get_posture_stats()
    if result is None:
        return {"enabled": False}
    result["enabled"] = True
    return result


@router.get("/tide/de/disabled-critical", dependencies=[Depends(require_permission("alert:read"))])
def tide_de_disabled_critical():
    """Disabled critical/high severity rules."""
    svc = get_tide_service()
    return svc.get_disabled_critical_high()


@router.get("/tide/de/use-cases", dependencies=[Depends(require_permission("alert:read"))])
def tide_de_use_cases():
    """TIDE playbooks (use cases) with steps + per-technique detection coverage.

    A "use case" in CyAB / TIDE terminology is a baseline playbook describing
    a tactical sequence of TTPs we want to detect (e.g. "Insider Threat: Data
    Exfiltration"). The endpoint returns each use case with its ordered steps,
    each step's MITRE techniques, and how many TIDE rules cover them.
    """
    svc = get_tide_service()
    return svc.get_playbooks_with_kill_chains()


# Deprecated alias — kept for backwards compatibility with older clients.
@router.get("/tide/de/kill-chains", dependencies=[Depends(require_permission("alert:read"))])
def tide_de_kill_chains_alias():
    """Deprecated: use /tide/de/use-cases. Same response shape."""
    svc = get_tide_service()
    return svc.get_playbooks_with_kill_chains()


@router.get("/tide/de/navigator-layer", dependencies=[Depends(require_permission("alert:read"))])
def tide_de_navigator_layer():
    """Export the live TIDE coverage as a MITRE ATT&CK Navigator layer file.

    Returns a downloadable JSON layer compatible with
    https://mitre-attack.github.io/attack-navigator/. Each technique is
    annotated with the number of enabled / total TIDE rules and a heat-map
    colour. Auditors and red teams can drop the file straight into Navigator.
    """
    from fastapi.responses import Response
    import json
    from datetime import datetime

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
def tide_de_gaps():
    """Gap analysis — blind spots by tactic, unmapped rules, quick wins."""
    svc = get_tide_service()
    result = svc.get_gaps_analysis()
    if result is None:
        return {"enabled": False}
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
    from fastapi.responses import Response
    import html as html_mod

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
        from weasyprint import HTML as WpHTML
        import re as _re
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
