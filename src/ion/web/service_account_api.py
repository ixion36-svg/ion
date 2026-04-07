"""Service Account Tracker API."""

import logging
from fastapi import APIRouter, Depends, Query, HTTPException
from pydantic import BaseModel
from typing import Optional
from sqlalchemy.orm import Session
from ion.auth.dependencies import require_permission
from ion.web.api import get_db_session

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/service-accounts", tags=["service-accounts"])


class ServiceAccountCreate(BaseModel):
    account_name: str
    display_name: Optional[str] = None
    description: Optional[str] = None
    owner_id: Optional[int] = None
    department: Optional[str] = None
    account_type: str = "service"
    risk_level: str = "medium"
    rotation_days: Optional[int] = None
    systems: Optional[list] = None
    permissions: Optional[list] = None
    spn: Optional[str] = None
    notes: Optional[str] = None


@router.get("", dependencies=[Depends(require_permission("alert:read"))])
def list_service_accounts(
    status: str = Query(None),
    risk_level: str = Query(None),
    session: Session = Depends(get_db_session),
):
    from ion.services.service_account_service import get_service_accounts
    return {"accounts": get_service_accounts(session, status=status, risk_level=risk_level)}


@router.get("/risk-summary", dependencies=[Depends(require_permission("alert:read"))])
def get_risk_summary(session: Session = Depends(get_db_session)):
    from ion.services.service_account_service import get_account_risk_summary
    return get_account_risk_summary(session)


@router.get("/stale", dependencies=[Depends(require_permission("alert:read"))])
def get_stale(stale_days: int = Query(90, ge=1), session: Session = Depends(get_db_session)):
    from ion.services.service_account_service import get_stale_accounts
    return {"accounts": get_stale_accounts(session, stale_days=stale_days)}


@router.get("/{account_id}", dependencies=[Depends(require_permission("alert:read"))])
def get_account(account_id: int, session: Session = Depends(get_db_session)):
    from ion.services.service_account_service import get_service_account
    result = get_service_account(session, account_id)
    if not result:
        raise HTTPException(status_code=404, detail="Account not found")
    return result


@router.post("", dependencies=[Depends(require_permission("system:settings"))])
def create_account(data: ServiceAccountCreate, session: Session = Depends(get_db_session)):
    from ion.services.service_account_service import create_service_account
    import json
    return create_service_account(
        session,
        account_name=data.account_name, display_name=data.display_name,
        description=data.description, owner_id=data.owner_id,
        department=data.department, account_type=data.account_type,
        risk_level=data.risk_level, rotation_days=data.rotation_days,
        systems=json.dumps(data.systems) if data.systems else None,
        permissions=json.dumps(data.permissions) if data.permissions else None,
        spn=data.spn, notes=data.notes,
    )
