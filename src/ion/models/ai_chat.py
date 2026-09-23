"""AI Chat history models."""

import enum
from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy import Enum as SQLEnum
from sqlalchemy.orm import relationship

from ion.models.base import Base


class AIContextType(str, enum.Enum):
    """AI chat context types."""
    ANALYST = "analyst"
    ENGINEERING = "engineering"
    DEFAULT = "default"


class AIChatSession(Base):
    """AI chat session/conversation."""
    __tablename__ = "ai_chat_sessions"
    __table_args__ = (
        Index("ix_ai_chat_sessions_user_updated", "user_id", "updated_at"),
    )

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    title = Column(String(200), nullable=True)  # Auto-generated from first message
    context_type = Column(SQLEnum(AIContextType, native_enum=False), default=AIContextType.DEFAULT)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    user = relationship("User", back_populates="ai_chat_sessions")
    messages = relationship("AIChatMessage", back_populates="session", cascade="all, delete-orphan",
                          order_by="AIChatMessage.created_at")


class AIChatMessage(Base):
    """Individual message in an AI chat session."""
    __tablename__ = "ai_chat_messages"
    __table_args__ = (
        Index("ix_ai_chat_messages_session_id", "session_id"),
    )

    id = Column(Integer, primary_key=True)
    session_id = Column(Integer, ForeignKey("ai_chat_sessions.id", ondelete="CASCADE"), nullable=False)
    role = Column(String(20), nullable=False)  # "user", "assistant", "system"
    content = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    session = relationship("AIChatSession", back_populates="messages")


class AIChatUpload(Base):
    """A file an analyst attached to the AI chat.

    Held in the database rather than process memory: ION runs several uvicorn
    workers, and a dict on the module would only ever be visible to the worker
    that served the upload -- the next request round-robins elsewhere and the
    file appears to vanish. Nothing is written to a filesystem; ``content`` is
    the decoded text that reaches the model.
    """

    __tablename__ = "ai_chat_uploads"
    __table_args__ = (
        Index("ix_ai_chat_uploads_user_uploaded", "user_id", "uploaded_at"),
    )

    id = Column(Integer, primary_key=True)
    # The short public handle the UI and the model prompt refer to.
    file_id = Column(String(32), nullable=False, unique=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)

    name = Column(String(255), nullable=False)
    size_bytes = Column(Integer, nullable=False, default=0)
    line_count = Column(Integer, nullable=False, default=0)
    content = Column(Text, nullable=False)

    # Provenance from ion.services.upload_scan, carried so the audit trail and
    # the hostile-data label survive a restart.
    sha256 = Column(String(64), nullable=True)
    indicators = Column(Text, nullable=True)  # JSON list; never compared in SQL

    uploaded_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("User")

