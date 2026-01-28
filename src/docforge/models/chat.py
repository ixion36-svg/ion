"""Chat models for analyst communication - DMs, groups, and case-linked chats."""

from datetime import datetime
from typing import Optional, List

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from docforge.models.base import Base, TimestampMixin


class ChatRoom(Base, TimestampMixin):
    """Chat room for direct messages or group conversations."""

    __tablename__ = "chat_rooms"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)  # Null for DMs
    room_type: Mapped[str] = mapped_column(String(20), nullable=False)  # 'direct' or 'group'
    case_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("alert_cases.id"), nullable=True
    )
    created_by_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=False
    )

    # Relationships
    members: Mapped[List["ChatRoomMember"]] = relationship(
        "ChatRoomMember", back_populates="room", cascade="all, delete-orphan"
    )
    messages: Mapped[List["ChatMessage"]] = relationship(
        "ChatMessage", back_populates="room", cascade="all, delete-orphan"
    )
    case: Mapped[Optional["AlertCase"]] = relationship(
        "AlertCase", foreign_keys=[case_id]
    )
    created_by: Mapped["User"] = relationship("User", foreign_keys=[created_by_id])

    def __repr__(self) -> str:
        return f"<ChatRoom(id={self.id}, type='{self.room_type}', name='{self.name}')>"


class ChatRoomMember(Base):
    """Membership record for a chat room."""

    __tablename__ = "chat_room_members"
    __table_args__ = (
        Index("ix_chat_room_members_room_user", "room_id", "user_id", unique=True),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    room_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("chat_rooms.id"), nullable=False
    )
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=False
    )
    joined_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), nullable=False
    )
    last_read_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    is_typing: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    typing_updated_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Relationships
    room: Mapped["ChatRoom"] = relationship("ChatRoom", back_populates="members")
    user: Mapped["User"] = relationship("User", foreign_keys=[user_id])

    def __repr__(self) -> str:
        return f"<ChatRoomMember(room_id={self.room_id}, user_id={self.user_id})>"


class ChatMessage(Base):
    """A message in a chat room."""

    __tablename__ = "chat_messages"
    __table_args__ = (
        Index("ix_chat_messages_room_created", "room_id", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    room_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("chat_rooms.id"), nullable=False
    )
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=False
    )
    content: Mapped[str] = mapped_column(Text, nullable=False)
    mentions: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)  # [user_id, ...]
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), nullable=False
    )
    edited_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Relationships
    room: Mapped["ChatRoom"] = relationship("ChatRoom", back_populates="messages")
    user: Mapped["User"] = relationship("User", foreign_keys=[user_id])
    reactions: Mapped[List["MessageReaction"]] = relationship(
        "MessageReaction", back_populates="message", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<ChatMessage(id={self.id}, room_id={self.room_id})>"


class MessageReaction(Base):
    """Emoji reaction on a message."""

    __tablename__ = "message_reactions"
    __table_args__ = (
        Index("ix_reaction_unique", "message_id", "user_id", "emoji", unique=True),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    message_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("chat_messages.id"), nullable=False
    )
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=False
    )
    emoji: Mapped[str] = mapped_column(String(10), nullable=False)  # e.g., "👍", "❤️"
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), nullable=False
    )

    # Relationships
    message: Mapped["ChatMessage"] = relationship("ChatMessage", back_populates="reactions")
    user: Mapped["User"] = relationship("User", foreign_keys=[user_id])

    def __repr__(self) -> str:
        return f"<MessageReaction(message_id={self.message_id}, emoji='{self.emoji}')>"
