"""Repository for authentication and audit operations."""

import hashlib
import json
from datetime import datetime
from typing import List, Optional

from sqlalchemy import delete, select
from sqlalchemy.orm import Session, joinedload

from ion.models.user import AuditLog, Role, User, UserSession


def _hash_session_token(token: str) -> str:
    """Compute the SHA-256 hex digest of a session token.

    G5 closure (v0.31.17): session tokens are stored as hashes at rest.
    The plaintext token only exists in the client cookie; the DB carries
    just the digest. SHA-256 without salt is appropriate here because
    tokens are 32 bytes of CSPRNG output (256-bit entropy) — preimage
    attacks are computationally infeasible, and a slow hash like bcrypt
    buys nothing for high-entropy random inputs.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class SessionRepository:
    """Repository for UserSession operations."""

    def __init__(self, session: Session):
        self.session = session

    def create(
        self,
        user_id: int,
        session_token: str,
        expires_at: datetime,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> UserSession:
        """Create a new user session. Stores the SHA-256 hash of the token."""
        user_session = UserSession(
            user_id=user_id,
            session_token_hash=_hash_session_token(session_token),
            expires_at=expires_at,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        self.session.add(user_session)
        self.session.flush()
        return user_session

    def get_by_token(self, session_token: str) -> Optional[UserSession]:
        """Get a session by token (hashes the input before lookup).

        v0.9.82 — matched to get_valid_session(): joinedload for the
        *-to-one relations, selectinload for the many-to-many collections.
        The previous chained joinedload produced the same cartesian
        (80+ rows per admin lookup) that was fixed on the hot path in
        v0.9.65 — this one was a landmine because logout is rare.
        """
        token_hash = _hash_session_token(session_token)
        stmt = (
            select(UserSession)
            .options(
                joinedload(UserSession.user)
                    .selectinload(User.roles)
                    .selectinload(Role.permissions),
                joinedload(UserSession.active_role)
                    .selectinload(Role.permissions),
            )
            .where(UserSession.session_token_hash == token_hash)
        )
        return self.session.execute(stmt).scalar_one_or_none()

    def get_valid_session(self, session_token: str) -> Optional[UserSession]:
        """Get a valid (non-expired) session by token (hashes input first).

        HOT PATH — runs on every authenticated request. The previous version
        chained joinedload across two many-to-many collections (User.roles +
        Role.permissions) which produced a cartesian product (~80 rows per
        admin lookup) and showed up as 100-330ms in pg_stat_statements under
        load. selectinload issues 3 fast IN-list queries instead — total
        query time drops to single-digit ms.
        """
        token_hash = _hash_session_token(session_token)
        stmt = (
            select(UserSession)
            .options(
                # User chain: joinedload the *-to-one (user), then selectinload
                # the *-to-many collections to avoid cartesian explosion.
                joinedload(UserSession.user)
                    .selectinload(User.roles)
                    .selectinload(Role.permissions),
                # active_role chain: same pattern.
                joinedload(UserSession.active_role)
                    .selectinload(Role.permissions),
            )
            .where(
                UserSession.session_token_hash == token_hash,
                UserSession.expires_at > datetime.utcnow(),
            )
        )
        return self.session.execute(stmt).unique().scalar_one_or_none()

    def list_by_user(self, user_id: int) -> List[UserSession]:
        """List all sessions for a user."""
        stmt = (
            select(UserSession)
            .where(UserSession.user_id == user_id)
            .order_by(UserSession.created_at.desc())
        )
        return list(self.session.execute(stmt).scalars().all())

    def delete(self, user_session: UserSession) -> None:
        """Delete a session."""
        self.session.delete(user_session)
        self.session.flush()

    def delete_by_token(self, session_token: str) -> bool:
        """Delete a session by token (hashes the input before lookup)."""
        token_hash = _hash_session_token(session_token)
        stmt = delete(UserSession).where(UserSession.session_token_hash == token_hash)
        result = self.session.execute(stmt)
        self.session.flush()
        return result.rowcount > 0

    def delete_all_for_user(self, user_id: int) -> int:
        """Delete all sessions for a user."""
        stmt = delete(UserSession).where(UserSession.user_id == user_id)
        result = self.session.execute(stmt)
        self.session.flush()
        return result.rowcount

    def delete_expired_for_user(self, user_id: int) -> int:
        """Delete only expired sessions for a user (keep valid ones)."""
        stmt = delete(UserSession).where(
            UserSession.user_id == user_id,
            UserSession.expires_at <= datetime.utcnow(),
        )
        result = self.session.execute(stmt)
        self.session.flush()
        return result.rowcount

    def delete_expired(self) -> int:
        """Delete all expired sessions."""
        stmt = delete(UserSession).where(UserSession.expires_at <= datetime.utcnow())
        result = self.session.execute(stmt)
        self.session.flush()
        return result.rowcount


class AuditLogRepository:
    """Repository for AuditLog operations."""

    def __init__(self, session: Session):
        self.session = session

    def create(
        self,
        action: str,
        user_id: int | None = None,
        resource_type: str | None = None,
        resource_id: int | None = None,
        details: dict | str | None = None,
        ip_address: str | None = None,
    ) -> AuditLog:
        """Create a new audit log entry."""
        if isinstance(details, dict):
            details = json.dumps(details)

        audit_log = AuditLog(
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
            ip_address=ip_address,
        )
        self.session.add(audit_log)
        self.session.flush()
        return audit_log

    def get_by_id(self, audit_log_id: int) -> Optional[AuditLog]:
        """Get an audit log by ID."""
        stmt = (
            select(AuditLog)
            .options(joinedload(AuditLog.user))
            .where(AuditLog.id == audit_log_id)
        )
        return self.session.execute(stmt).unique().scalar_one_or_none()

    def list_all(
        self,
        limit: int = 100,
        offset: int = 0,
        user_id: int | None = None,
        action: str | None = None,
        resource_type: str | None = None,
        from_date: datetime | None = None,
        to_date: datetime | None = None,
    ) -> List[AuditLog]:
        """List audit logs with optional filters."""
        stmt = (
            select(AuditLog)
            .options(joinedload(AuditLog.user))
        )

        if user_id is not None:
            stmt = stmt.where(AuditLog.user_id == user_id)
        if action is not None:
            stmt = stmt.where(AuditLog.action == action)
        if resource_type is not None:
            stmt = stmt.where(AuditLog.resource_type == resource_type)
        if from_date is not None:
            stmt = stmt.where(AuditLog.timestamp >= from_date)
        if to_date is not None:
            stmt = stmt.where(AuditLog.timestamp <= to_date)

        stmt = stmt.order_by(AuditLog.timestamp.desc()).offset(offset).limit(limit)
        return list(self.session.execute(stmt).unique().scalars().all())

    def count(
        self,
        user_id: int | None = None,
        action: str | None = None,
        resource_type: str | None = None,
    ) -> int:
        """Count audit logs with optional filters."""
        from sqlalchemy import func
        stmt = select(func.count(AuditLog.id))

        if user_id is not None:
            stmt = stmt.where(AuditLog.user_id == user_id)
        if action is not None:
            stmt = stmt.where(AuditLog.action == action)
        if resource_type is not None:
            stmt = stmt.where(AuditLog.resource_type == resource_type)

        return self.session.execute(stmt).scalar() or 0

    def list_by_user(self, user_id: int, limit: int = 50) -> List[AuditLog]:
        """List audit logs for a specific user."""
        stmt = (
            select(AuditLog)
            .where(AuditLog.user_id == user_id)
            .order_by(AuditLog.timestamp.desc())
            .limit(limit)
        )
        return list(self.session.execute(stmt).scalars().all())

    def list_by_resource(
        self,
        resource_type: str,
        resource_id: int,
        limit: int = 50,
    ) -> List[AuditLog]:
        """List audit logs for a specific resource."""
        stmt = (
            select(AuditLog)
            .options(joinedload(AuditLog.user))
            .where(
                AuditLog.resource_type == resource_type,
                AuditLog.resource_id == resource_id,
            )
            .order_by(AuditLog.timestamp.desc())
            .limit(limit)
        )
        return list(self.session.execute(stmt).unique().scalars().all())

    def delete_old_logs(self, before_date: datetime) -> int:
        """Delete audit logs older than the specified date."""
        stmt = delete(AuditLog).where(AuditLog.timestamp < before_date)
        result = self.session.execute(stmt)
        self.session.flush()
        return result.rowcount
