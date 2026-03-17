"""AI Chat history models."""

from datetime import datetime
from typing import Optional, List
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Enum as SQLEnum
from sqlalchemy.orm import relationship
import enum

from ion.models.base import Base


class AIContextType(str, enum.Enum):
    """AI chat context types."""
    ANALYST = "analyst"
    ENGINEERING = "engineering"
    DEFAULT = "default"


class AIChatSession(Base):
    """AI chat session/conversation."""
    __tablename__ = "ai_chat_sessions"

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

    @property
    def message_count(self) -> int:
        return len(self.messages) if self.messages else 0

    @property
    def preview(self) -> str:
        """Get preview of conversation (first user message)."""
        if self.messages:
            for msg in self.messages:
                if msg.role == "user":
                    return msg.content[:100] + "..." if len(msg.content) > 100 else msg.content
        return "Empty conversation"


class AIChatMessage(Base):
    """Individual message in an AI chat session."""
    __tablename__ = "ai_chat_messages"

    id = Column(Integer, primary_key=True)
    session_id = Column(Integer, ForeignKey("ai_chat_sessions.id", ondelete="CASCADE"), nullable=False)
    role = Column(String(20), nullable=False)  # "user", "assistant", "system"
    content = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    session = relationship("AIChatSession", back_populates="messages")
