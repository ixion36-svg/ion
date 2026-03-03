"""AI Chat history service with storage management."""

import logging
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from ion.models.ai_chat import AIChatSession, AIChatMessage, AIContextType

logger = logging.getLogger(__name__)

# Storage limits
MAX_SESSIONS_PER_USER = 50  # Maximum conversations per user
MAX_MESSAGES_PER_SESSION = 100  # Maximum messages per conversation
SESSION_RETENTION_DAYS = 90  # Auto-delete sessions older than this


class AIChatService:
    """Service for managing AI chat history."""

    def __init__(self, db_session: Session):
        self.db = db_session

    # =========================================================================
    # Session Management
    # =========================================================================

    def create_session(
        self,
        user_id: int,
        context_type: str = "default",
        title: Optional[str] = None
    ) -> AIChatSession:
        """Create a new chat session."""
        # Clean up old sessions first
        self._cleanup_old_sessions(user_id)

        session = AIChatSession(
            user_id=user_id,
            context_type=AIContextType(context_type),
            title=title
        )
        self.db.add(session)
        self.db.commit()
        self.db.refresh(session)

        logger.info(f"Created AI chat session {session.id} for user {user_id}")
        return session

    def get_session(self, session_id: int, user_id: int) -> Optional[AIChatSession]:
        """Get a session by ID (ensuring user owns it)."""
        return self.db.query(AIChatSession).filter(
            AIChatSession.id == session_id,
            AIChatSession.user_id == user_id
        ).first()

    def get_user_sessions(
        self,
        user_id: int,
        limit: int = 20,
        offset: int = 0
    ) -> List[AIChatSession]:
        """Get user's chat sessions, newest first."""
        return self.db.query(AIChatSession).filter(
            AIChatSession.user_id == user_id
        ).order_by(desc(AIChatSession.updated_at)).offset(offset).limit(limit).all()

    def get_session_count(self, user_id: int) -> int:
        """Get total session count for user."""
        return self.db.query(func.count(AIChatSession.id)).filter(
            AIChatSession.user_id == user_id
        ).scalar() or 0

    def update_session_title(
        self,
        session_id: int,
        user_id: int,
        title: str
    ) -> Optional[AIChatSession]:
        """Update session title."""
        session = self.get_session(session_id, user_id)
        if session:
            session.title = title[:200]  # Limit title length
            self.db.commit()
        return session

    def delete_session(self, session_id: int, user_id: int) -> bool:
        """Delete a session."""
        session = self.get_session(session_id, user_id)
        if session:
            self.db.delete(session)
            self.db.commit()
            logger.info(f"Deleted AI chat session {session_id}")
            return True
        return False

    # =========================================================================
    # Message Management
    # =========================================================================

    def add_message(
        self,
        session_id: int,
        user_id: int,
        role: str,
        content: str
    ) -> Optional[AIChatMessage]:
        """Add a message to a session."""
        session = self.get_session(session_id, user_id)
        if not session:
            return None

        # Check message limit
        msg_count = self.db.query(func.count(AIChatMessage.id)).filter(
            AIChatMessage.session_id == session_id
        ).scalar() or 0

        if msg_count >= MAX_MESSAGES_PER_SESSION:
            # Remove oldest messages to make room
            oldest = self.db.query(AIChatMessage).filter(
                AIChatMessage.session_id == session_id
            ).order_by(AIChatMessage.created_at).limit(10).all()
            for msg in oldest:
                self.db.delete(msg)

        message = AIChatMessage(
            session_id=session_id,
            role=role,
            content=content
        )
        self.db.add(message)

        # Update session timestamp and auto-generate title
        session.updated_at = datetime.utcnow()
        if not session.title and role == "user":
            # Use first user message as title
            session.title = content[:100] + "..." if len(content) > 100 else content

        self.db.commit()
        self.db.refresh(message)
        return message

    def get_session_messages(
        self,
        session_id: int,
        user_id: int,
        limit: int = 50
    ) -> List[AIChatMessage]:
        """Get messages for a session."""
        session = self.get_session(session_id, user_id)
        if not session:
            return []

        return self.db.query(AIChatMessage).filter(
            AIChatMessage.session_id == session_id
        ).order_by(AIChatMessage.created_at).limit(limit).all()

    # =========================================================================
    # Cleanup
    # =========================================================================

    def _cleanup_old_sessions(self, user_id: int):
        """Clean up old sessions to enforce limits."""
        # Delete sessions older than retention period
        cutoff = datetime.utcnow() - timedelta(days=SESSION_RETENTION_DAYS)
        old_sessions = self.db.query(AIChatSession).filter(
            AIChatSession.user_id == user_id,
            AIChatSession.updated_at < cutoff
        ).all()

        for session in old_sessions:
            self.db.delete(session)

        # Enforce max sessions limit
        session_count = self.get_session_count(user_id)
        if session_count >= MAX_SESSIONS_PER_USER:
            # Delete oldest sessions
            excess = session_count - MAX_SESSIONS_PER_USER + 1
            oldest = self.db.query(AIChatSession).filter(
                AIChatSession.user_id == user_id
            ).order_by(AIChatSession.updated_at).limit(excess).all()

            for session in oldest:
                self.db.delete(session)

        if old_sessions or (session_count >= MAX_SESSIONS_PER_USER):
            self.db.commit()

    def cleanup_all_old_sessions(self):
        """Global cleanup of old sessions (for scheduled task)."""
        cutoff = datetime.utcnow() - timedelta(days=SESSION_RETENTION_DAYS)
        deleted = self.db.query(AIChatSession).filter(
            AIChatSession.updated_at < cutoff
        ).delete()
        self.db.commit()

        if deleted:
            logger.info(f"Cleaned up {deleted} old AI chat sessions")
        return deleted

    # =========================================================================
    # Stats
    # =========================================================================

    def get_user_stats(self, user_id: int) -> Dict[str, Any]:
        """Get chat stats for a user."""
        session_count = self.get_session_count(user_id)

        message_count = self.db.query(func.count(AIChatMessage.id)).join(
            AIChatSession
        ).filter(
            AIChatSession.user_id == user_id
        ).scalar() or 0

        return {
            "session_count": session_count,
            "message_count": message_count,
            "max_sessions": MAX_SESSIONS_PER_USER,
            "max_messages_per_session": MAX_MESSAGES_PER_SESSION,
            "retention_days": SESSION_RETENTION_DAYS
        }
