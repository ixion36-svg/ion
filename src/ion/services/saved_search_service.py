"""Saved searches and personal workspace bookmarks."""

import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select, func, and_, desc
from sqlalchemy.orm import Session

from ion.models.oncall import UserBookmark as SavedSearch

logger = logging.getLogger(__name__)


def get_saved_searches(session: Session, user_id: int, search_type: str = None) -> list[dict]:
    stmt = select(SavedSearch).where(SavedSearch.user_id == user_id)
    if search_type:
        stmt = stmt.where(SavedSearch.search_type == search_type)
    stmt = stmt.order_by(SavedSearch.is_pinned.desc(), SavedSearch.use_count.desc())
    results = session.execute(stmt).scalars().all()
    return [_to_dict(s) for s in results]


def create_saved_search(
    session: Session, user_id: int, name: str, search_type: str, query: str, is_pinned: bool = False
) -> dict:
    s = SavedSearch(
        user_id=user_id, name=name, search_type=search_type,
        query=query, is_pinned=is_pinned,
    )
    session.add(s)
    session.commit()
    session.refresh(s)
    return _to_dict(s)


def delete_saved_search(session: Session, search_id: int, user_id: int) -> bool:
    s = session.execute(
        select(SavedSearch).where(and_(SavedSearch.id == search_id, SavedSearch.user_id == user_id))
    ).scalar_one_or_none()
    if not s:
        return False
    session.delete(s)
    session.commit()
    return True


def toggle_pin(session: Session, search_id: int, user_id: int) -> Optional[dict]:
    s = session.execute(
        select(SavedSearch).where(and_(SavedSearch.id == search_id, SavedSearch.user_id == user_id))
    ).scalar_one_or_none()
    if not s:
        return None
    s.is_pinned = not s.is_pinned
    session.commit()
    return _to_dict(s)


def record_use(session: Session, search_id: int, user_id: int):
    s = session.execute(
        select(SavedSearch).where(and_(SavedSearch.id == search_id, SavedSearch.user_id == user_id))
    ).scalar_one_or_none()
    if s:
        s.use_count = (s.use_count or 0) + 1
        s.last_used_at = datetime.now(timezone.utc)
        session.commit()


def _to_dict(s: SavedSearch) -> dict:
    return {
        "id": s.id,
        "user_id": s.user_id,
        "name": s.name,
        "search_type": s.search_type,
        "query": s.query,
        "is_pinned": s.is_pinned,
        "use_count": s.use_count,
        "last_used_at": s.last_used_at.isoformat() if s.last_used_at else None,
        "created_at": s.created_at.isoformat() if s.created_at else None,
    }
