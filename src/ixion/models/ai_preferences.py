"""AI user preferences and response feedback models."""

from datetime import datetime
from typing import Optional
from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship

from ixion.models.base import Base


class AIUserPreference(Base):
    """Per-user AI assistant preferences (RAG opt-in, custom instructions)."""
    __tablename__ = "ai_user_preferences"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, unique=True)

    # RAG opt-in flags (all default False — user must explicitly enable)
    rag_knowledge_base = Column(Boolean, default=False, nullable=False)
    rag_user_notes = Column(Boolean, default=False, nullable=False)
    rag_playbooks = Column(Boolean, default=False, nullable=False)

    # Response settings
    show_citations = Column(Boolean, default=True, nullable=False)
    custom_instructions = Column(Text, nullable=True)
    max_context_snippets = Column(Integer, default=3, nullable=False)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    user = relationship("User", backref="ai_preferences")


class AIResponseFeedback(Base):
    """Thumbs up/down feedback on AI responses."""
    __tablename__ = "ai_response_feedback"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    session_id = Column(Integer, ForeignKey("ai_chat_sessions.id", ondelete="SET NULL"), nullable=True)
    message_id = Column(Integer, ForeignKey("ai_chat_messages.id", ondelete="SET NULL"), nullable=True)
    rating = Column(String(10), nullable=False)  # "up" or "down"
    comment = Column(Text, nullable=True)
    context_type = Column(String(20), nullable=True)  # analyst/engineering/default
    rag_sources_used = Column(Text, nullable=True)  # JSON string of sources injected
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    user = relationship("User", backref="ai_feedback")
