"""Ticker API — active list, per-user dismiss, admin CRUD."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ion.auth.dependencies import (
    get_current_user,
    require_any_permission,
    require_page_auth,
)
from ion.models.ticker import (
    Ticker,
    TickerDismissal,
    TickerKind,
    TickerSeverity,
    TickerSourceType,
)
from ion.models.user import User
from ion.web.api import get_db_session

logger = logging.getLogger(__name__)

router = APIRouter(tags=["ticker"])

_TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
_templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))
try:
    import ion as _ion_pkg
    _templates.env.globals["ion_version"] = _ion_pkg.__version__
except Exception:  # pragma: no cover
    _templates.env.globals.setdefault("ion_version", "")


_READ = ["ticker:read"]
_CREATE = ["ticker:create", "ticker:manage"]
_MANAGE = ["ticker:manage"]


class TickerCreate(BaseModel):
    kind: str = Field(default="manual_event")
    severity: str = Field(default="info")
    title: str = Field(..., min_length=1, max_length=500)
    body: Optional[str] = None
    link_url: Optional[str] = None
    expires_at: Optional[datetime] = None


class TickerUpdate(BaseModel):
    kind: Optional[str] = None
    severity: Optional[str] = None
    title: Optional[str] = None
    body: Optional[str] = None
    link_url: Optional[str] = None
    expires_at: Optional[datetime] = None


def _validate_enum(value: str, enum_cls) -> str:
    try:
        return enum_cls(value).value
    except (ValueError, TypeError):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid value '{value}' for {enum_cls.__name__}",
        )


@router.get(
    "/api/ticker/active",
    dependencies=[Depends(require_any_permission(_READ))],
)
def list_active_tickers(
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Tickers visible to the current user — not resolved, not expired,
    not dismissed by this user. Ordered: critical first, newest first."""
    now = datetime.now(timezone.utc)

    dismissed_ids_q = select(TickerDismissal.ticker_id).where(
        TickerDismissal.user_id == current_user.id
    )
    dismissed_ids = {row[0] for row in session.execute(dismissed_ids_q).all()}

    stmt = (
        select(Ticker)
        .where(Ticker.resolved_at.is_(None))
        .where((Ticker.expires_at.is_(None)) | (Ticker.expires_at > now))
    )
    rows = session.execute(stmt).scalars().all()

    severity_order = {"critical": 0, "warning": 1, "info": 2}
    visible = [
        r.to_dict()
        for r in rows
        if r.id not in dismissed_ids
    ]
    visible.sort(
        key=lambda t: (
            severity_order.get(t["severity"], 9),
            -(int(t["id"]) if t["id"] is not None else 0),
        )
    )
    return {"tickers": visible, "count": len(visible)}


@router.post(
    "/api/ticker/{ticker_id}/dismiss",
    dependencies=[Depends(require_any_permission(_READ))],
)
def dismiss_ticker(
    ticker_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """v0.19.13: per-user dismiss for any ticker, including critical.

    Was previously 403 for critical-severity rows on the theory that
    critical events shouldn't be ignorable. In practice it left
    analysts with no way to clear the strip when they'd already
    triaged a known FP cluster — they had to case every alert. Since
    dismiss is per-user and critical tickers also still auto-resolve
    when the underlying alert is cased, peer-analyst visibility is
    preserved.
    """
    ticker = session.get(Ticker, ticker_id)
    if not ticker:
        raise HTTPException(status_code=404, detail="Ticker not found")
    existing = (
        session.query(TickerDismissal)
        .filter(
            TickerDismissal.ticker_id == ticker_id,
            TickerDismissal.user_id == current_user.id,
        )
        .one_or_none()
    )
    if existing is not None:
        return {"dismissed": True, "already_dismissed": True}
    session.add(
        TickerDismissal(
            ticker_id=ticker_id,
            user_id=current_user.id,
            dismissed_at=datetime.now(timezone.utc),
        )
    )
    session.commit()
    return {"dismissed": True}


@router.post(
    "/api/ticker",
    dependencies=[Depends(require_any_permission(_CREATE))],
)
def create_ticker(
    data: TickerCreate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    kind = _validate_enum(data.kind, TickerKind)
    severity = _validate_enum(data.severity, TickerSeverity)
    # Manual producers cannot create auto-producer kind (critical_alert) —
    # reserve that for the background service.
    if kind == TickerKind.CRITICAL_ALERT.value:
        raise HTTPException(
            status_code=400,
            detail="critical_alert tickers are auto-generated only",
        )
    t = Ticker(
        kind=kind,
        severity=severity,
        title=data.title.strip(),
        body=data.body,
        link_url=data.link_url,
        source_type=TickerSourceType.MANUAL,
        source_user_id=current_user.id,
        expires_at=data.expires_at,
    )
    session.add(t)
    session.commit()
    return t.to_dict()


@router.put(
    "/api/ticker/{ticker_id}",
    dependencies=[Depends(require_any_permission(_MANAGE))],
)
def update_ticker(
    ticker_id: int,
    data: TickerUpdate,
    session: Session = Depends(get_db_session),
):
    t = session.get(Ticker, ticker_id)
    if not t:
        raise HTTPException(status_code=404, detail="Ticker not found")
    if t.source_type == TickerSourceType.AUTO.value:
        raise HTTPException(
            status_code=403,
            detail="Auto-generated tickers cannot be edited — resolve via the underlying alert",
        )
    for field, value in data.model_dump(exclude_unset=True).items():
        if value is None:
            continue
        if field in ("kind", "severity"):
            enum_cls = TickerKind if field == "kind" else TickerSeverity
            value = _validate_enum(value, enum_cls)
        setattr(t, field, value)
    session.commit()
    return t.to_dict()


@router.post(
    "/api/ticker/{ticker_id}/resolve",
    dependencies=[Depends(require_any_permission(_MANAGE))],
)
def resolve_ticker(
    ticker_id: int,
    session: Session = Depends(get_db_session),
):
    t = session.get(Ticker, ticker_id)
    if not t:
        raise HTTPException(status_code=404, detail="Ticker not found")
    t.resolved_at = datetime.now(timezone.utc)
    session.commit()
    return t.to_dict()


@router.delete(
    "/api/ticker/{ticker_id}",
    dependencies=[Depends(require_any_permission(_MANAGE))],
)
def delete_ticker(
    ticker_id: int,
    session: Session = Depends(get_db_session),
):
    t = session.get(Ticker, ticker_id)
    if not t:
        raise HTTPException(status_code=404, detail="Ticker not found")
    session.delete(t)
    session.commit()
    return {"deleted": True, "id": ticker_id}


@router.get(
    "/api/ticker",
    dependencies=[Depends(require_any_permission(_MANAGE))],
)
def list_all_tickers(
    include_resolved: bool = False,
    session: Session = Depends(get_db_session),
):
    stmt = select(Ticker).order_by(Ticker.created_at.desc())
    if not include_resolved:
        stmt = stmt.where(Ticker.resolved_at.is_(None))
    rows = session.execute(stmt).scalars().all()
    return {"tickers": [r.to_dict() for r in rows], "count": len(rows)}


# ---------------------------------------------------------------------------
# HTML page — admin manage view
# ---------------------------------------------------------------------------


@router.get("/tickers", response_class=HTMLResponse)
def tickers_page(
    request: Request,
    _user: User = Depends(require_page_auth),
):
    return _templates.TemplateResponse(
        request=request,
        name="tickers.html",
    )
