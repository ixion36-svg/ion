"""Notification API endpoints for ION."""

import logging
from typing import Optional
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, update, func
from sqlalchemy.orm import Session

from ion.auth.dependencies import get_current_user
from ion.models.notification import Notification
from ion.models.user import User
from ion.web.api import get_db_session as _get_db_session

logger = logging.getLogger(__name__)

router = APIRouter()


# ---- API endpoints ----

@router.get("/notifications")
async def get_notifications(
    unread_only: bool = False,
    limit: int = 50,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(_get_db_session),
):
    """Get notifications for the current user."""
    stmt = select(Notification).where(
        Notification.user_id == current_user.id
    )
    if unread_only:
        stmt = stmt.where(Notification.is_read == False)
    stmt = stmt.order_by(Notification.created_at.desc()).limit(limit)
    notifs = session.execute(stmt).scalars().all()

    return {
        "notifications": [
            {
                "id": n.id,
                "source": n.source,
                "source_id": n.source_id,
                "title": n.title,
                "body": n.body,
                "url": n.url,
                "is_read": n.is_read,
                "is_toast_shown": n.is_toast_shown,
                "created_at": n.created_at.isoformat() if n.created_at else None,
            }
            for n in notifs
        ],
        "unread_count": session.execute(
            select(func.count(Notification.id)).where(
                Notification.user_id == current_user.id,
                Notification.is_read == False,
            )
        ).scalar() or 0,
    }


@router.get("/notifications/unread-count")
async def get_unread_count(
    current_user: User = Depends(get_current_user),
    session: Session = Depends(_get_db_session),
):
    """Fast endpoint for polling — returns just the unread count and any new toasts."""
    count = session.execute(
        select(func.count(Notification.id)).where(
            Notification.user_id == current_user.id,
            Notification.is_read == False,
        )
    ).scalar() or 0

    # Get un-toasted notifications for toast display
    new_toasts = session.execute(
        select(Notification).where(
            Notification.user_id == current_user.id,
            Notification.is_toast_shown == False,
        ).order_by(Notification.created_at.asc()).limit(5)
    ).scalars().all()

    toast_list = []
    for n in new_toasts:
        toast_list.append({
            "id": n.id,
            "source": n.source,
            "title": n.title,
            "body": n.body,
            "url": n.url,
        })
        n.is_toast_shown = True

    session.commit()

    return {"unread_count": count, "toasts": toast_list}


@router.post("/notifications/{notification_id}/read")
async def mark_read(
    notification_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(_get_db_session),
):
    """Mark a notification as read."""
    notif = session.execute(
        select(Notification).where(
            Notification.id == notification_id,
            Notification.user_id == current_user.id,
        )
    ).scalar_one_or_none()
    if not notif:
        raise HTTPException(status_code=404, detail="Notification not found")
    notif.is_read = True
    session.commit()
    return {"ok": True}


@router.post("/notifications/read-all")
async def mark_all_read(
    current_user: User = Depends(get_current_user),
    session: Session = Depends(_get_db_session),
):
    """Mark all notifications as read for the current user."""
    session.execute(
        update(Notification).where(
            Notification.user_id == current_user.id,
            Notification.is_read == False,
        ).values(is_read=True)
    )
    session.commit()
    return {"ok": True}


# ---- Helper to create notifications from other modules ----

def create_notification(
    session: Session,
    user_id: int,
    source: str,
    title: str,
    body: str = None,
    url: str = None,
    source_id: str = None,
):
    """Create a notification. Call from within an existing session/transaction."""
    notif = Notification(
        user_id=user_id,
        source=source,
        source_id=source_id,
        title=title,
        body=body,
        url=url,
    )
    session.add(notif)
    return notif
