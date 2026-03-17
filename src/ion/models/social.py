"""Social Hub models — notice board for team shoutouts, certs, and announcements."""

from datetime import datetime
from typing import Optional, List

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ion.models.base import Base


CATEGORIES = ["announcement", "good_work", "certification", "general"]


class SocialPost(Base):
    """A post on the Social Hub notice board."""

    __tablename__ = "social_posts"
    __table_args__ = (
        Index("ix_social_posts_pinned_created", "is_pinned", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    category: Mapped[str] = mapped_column(String(32), nullable=False, default="general")
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    is_pinned: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=func.now(), onupdate=func.now(), nullable=False)

    # Relationships
    user: Mapped["User"] = relationship("User", foreign_keys=[user_id])
    comments: Mapped[List["SocialComment"]] = relationship(
        "SocialComment", back_populates="post", cascade="all, delete-orphan",
        order_by="SocialComment.created_at",
    )
    reactions: Mapped[List["SocialReaction"]] = relationship(
        "SocialReaction", back_populates="post", cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<SocialPost(id={self.id}, category='{self.category}', title='{self.title[:30]}')>"


class SocialComment(Base):
    """A comment on a Social Hub post."""

    __tablename__ = "social_comments"
    __table_args__ = (
        Index("ix_social_comments_post", "post_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    post_id: Mapped[int] = mapped_column(Integer, ForeignKey("social_posts.id"), nullable=False)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now(), nullable=False)

    # Relationships
    post: Mapped["SocialPost"] = relationship("SocialPost", back_populates="comments")
    user: Mapped["User"] = relationship("User", foreign_keys=[user_id])

    def __repr__(self) -> str:
        return f"<SocialComment(id={self.id}, post_id={self.post_id})>"


class SocialReaction(Base):
    """An emoji reaction on a Social Hub post."""

    __tablename__ = "social_reactions"
    __table_args__ = (
        Index("ix_social_reaction_unique", "post_id", "user_id", "emoji", unique=True),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    post_id: Mapped[int] = mapped_column(Integer, ForeignKey("social_posts.id"), nullable=False)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    emoji: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now(), nullable=False)

    # Relationships
    post: Mapped["SocialPost"] = relationship("SocialPost", back_populates="reactions")
    user: Mapped["User"] = relationship("User", foreign_keys=[user_id])

    def __repr__(self) -> str:
        return f"<SocialReaction(post_id={self.post_id}, emoji='{self.emoji}')>"
