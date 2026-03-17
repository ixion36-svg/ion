"""Social Hub API -- notice board for team shoutouts, certs, and announcements."""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.orm import Session, selectinload

from ion.auth.dependencies import get_current_user
from ion.models.social import SocialPost, SocialComment, SocialReaction, CATEGORIES
from ion.models.user import User
from ion.web.api import get_db_session as _get_db_session

logger = logging.getLogger(__name__)

router = APIRouter(tags=["social"])

REACTION_EMOJIS = ["thumbsup", "clap", "fire", "heart", "rocket", "trophy"]


class PostCreate(BaseModel):
    title: str
    body: str
    category: str = "general"


class PostUpdate(BaseModel):
    title: Optional[str] = None
    body: Optional[str] = None
    category: Optional[str] = None


class CommentCreate(BaseModel):
    content: str


class ReactionToggle(BaseModel):
    emoji: str


def _serialize_post(post: SocialPost, current_user_id: int) -> dict:
    reaction_map = {}
    for r in post.reactions:
        if r.emoji not in reaction_map:
            reaction_map[r.emoji] = {"count": 0, "reacted": False}
        reaction_map[r.emoji]["count"] += 1
        if r.user_id == current_user_id:
            reaction_map[r.emoji]["reacted"] = True

    return {
        "id": post.id,
        "user_id": post.user_id,
        "author": post.user.username if post.user else "Unknown",
        "author_display": (post.user.display_name or post.user.username) if post.user else "Unknown",
        "category": post.category,
        "title": post.title,
        "body": post.body,
        "is_pinned": post.is_pinned,
        "created_at": post.created_at.isoformat() if post.created_at else None,
        "updated_at": post.updated_at.isoformat() if post.updated_at else None,
        "comment_count": len(post.comments),
        "reactions": reaction_map,
    }


@router.get("/")
async def list_posts(
    category: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(_get_db_session),
):
    """List social posts, pinned first, then newest."""
    stmt = (
        select(SocialPost)
        .options(selectinload(SocialPost.user), selectinload(SocialPost.reactions), selectinload(SocialPost.comments))
        .order_by(SocialPost.is_pinned.desc(), SocialPost.created_at.desc())
    )
    if category and category in CATEGORIES:
        stmt = stmt.where(SocialPost.category == category)
    stmt = stmt.offset(offset).limit(limit)
    posts = session.execute(stmt).scalars().all()

    return {"posts": [_serialize_post(p, current_user.id) for p in posts]}


@router.post("/")
async def create_post(
    data: PostCreate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(_get_db_session),
):
    """Create a new social post."""
    if data.category not in CATEGORIES:
        raise HTTPException(status_code=400, detail="Invalid category. Must be one of: " + ", ".join(CATEGORIES))
    if not data.title.strip() or not data.body.strip():
        raise HTTPException(status_code=400, detail="Title and body are required")

    post = SocialPost(
        user_id=current_user.id,
        category=data.category,
        title=data.title.strip(),
        body=data.body.strip(),
    )
    session.add(post)
    session.commit()
    session.refresh(post)
    return {"id": post.id, "created_at": post.created_at.isoformat()}


@router.get("/{post_id}")
async def get_post(
    post_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(_get_db_session),
):
    """Get a single post with full comments."""
    post = session.execute(
        select(SocialPost)
        .options(
            selectinload(SocialPost.user),
            selectinload(SocialPost.reactions).selectinload(SocialReaction.user),
            selectinload(SocialPost.comments).selectinload(SocialComment.user),
        )
        .where(SocialPost.id == post_id)
    ).scalar_one_or_none()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")

    result = _serialize_post(post, current_user.id)
    result["comments"] = [
        {
            "id": c.id,
            "user_id": c.user_id,
            "author": c.user.username if c.user else "Unknown",
            "author_display": (c.user.display_name or c.user.username) if c.user else "Unknown",
            "content": c.content,
            "created_at": c.created_at.isoformat() if c.created_at else None,
        }
        for c in post.comments
    ]
    return result


@router.put("/{post_id}")
async def update_post(
    post_id: int,
    data: PostUpdate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(_get_db_session),
):
    """Update a post (author or admin only)."""
    post = session.execute(select(SocialPost).where(SocialPost.id == post_id)).scalar_one_or_none()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")

    is_admin = any(r.name == "admin" for r in current_user.roles)
    if post.user_id != current_user.id and not is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    if data.title is not None:
        post.title = data.title.strip()
    if data.body is not None:
        post.body = data.body.strip()
    if data.category is not None:
        if data.category not in CATEGORIES:
            raise HTTPException(status_code=400, detail="Invalid category")
        post.category = data.category

    session.commit()
    return {"ok": True}


@router.delete("/{post_id}")
async def delete_post(
    post_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(_get_db_session),
):
    """Delete a post (author or admin only)."""
    post = session.execute(select(SocialPost).where(SocialPost.id == post_id)).scalar_one_or_none()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")

    is_admin = any(r.name == "admin" for r in current_user.roles)
    if post.user_id != current_user.id and not is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    session.delete(post)
    session.commit()
    return {"ok": True}


@router.post("/{post_id}/pin")
async def toggle_pin(
    post_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(_get_db_session),
):
    """Toggle pin (admin or lead only)."""
    role_names = {r.name for r in current_user.roles}
    if not role_names & {"admin", "lead"}:
        raise HTTPException(status_code=403, detail="Only admin or lead can pin posts")

    post = session.execute(select(SocialPost).where(SocialPost.id == post_id)).scalar_one_or_none()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")

    post.is_pinned = not post.is_pinned
    session.commit()
    return {"is_pinned": post.is_pinned}


@router.post("/{post_id}/comments")
async def add_comment(
    post_id: int,
    data: CommentCreate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(_get_db_session),
):
    """Add a comment to a post."""
    post = session.execute(select(SocialPost).where(SocialPost.id == post_id)).scalar_one_or_none()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    if not data.content.strip():
        raise HTTPException(status_code=400, detail="Comment cannot be empty")

    comment = SocialComment(
        post_id=post_id,
        user_id=current_user.id,
        content=data.content.strip(),
    )
    session.add(comment)
    session.commit()
    session.refresh(comment)
    return {"id": comment.id, "created_at": comment.created_at.isoformat()}


@router.delete("/{post_id}/comments/{comment_id}")
async def delete_comment(
    post_id: int,
    comment_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(_get_db_session),
):
    """Delete a comment (author or admin only)."""
    comment = session.execute(
        select(SocialComment).where(
            SocialComment.id == comment_id,
            SocialComment.post_id == post_id,
        )
    ).scalar_one_or_none()
    if not comment:
        raise HTTPException(status_code=404, detail="Comment not found")

    is_admin = any(r.name == "admin" for r in current_user.roles)
    if comment.user_id != current_user.id and not is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    session.delete(comment)
    session.commit()
    return {"ok": True}


@router.post("/{post_id}/reactions")
async def toggle_reaction(
    post_id: int,
    data: ReactionToggle,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(_get_db_session),
):
    """Toggle a reaction on a post (add if not exists, remove if exists)."""
    if data.emoji not in REACTION_EMOJIS:
        raise HTTPException(status_code=400, detail="Invalid emoji. Must be one of: " + ", ".join(REACTION_EMOJIS))

    post = session.execute(select(SocialPost).where(SocialPost.id == post_id)).scalar_one_or_none()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")

    existing = session.execute(
        select(SocialReaction).where(
            SocialReaction.post_id == post_id,
            SocialReaction.user_id == current_user.id,
            SocialReaction.emoji == data.emoji,
        )
    ).scalar_one_or_none()

    if existing:
        session.delete(existing)
        session.commit()
        return {"action": "removed", "emoji": data.emoji}
    else:
        reaction = SocialReaction(
            post_id=post_id,
            user_id=current_user.id,
            emoji=data.emoji,
        )
        session.add(reaction)
        session.commit()
        return {"action": "added", "emoji": data.emoji}
