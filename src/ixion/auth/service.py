"""Authentication service for login, logout, and session management."""

import secrets
from datetime import datetime, timedelta
from typing import Optional, Tuple

from sqlalchemy.orm import Session

from ixion.models.user import User, UserSession, Role, Permission
from ixion.storage.user_repository import UserRepository, RoleRepository, PermissionRepository
from ixion.storage.auth_repository import SessionRepository, AuditLogRepository
from ixion.auth.password import password_hasher


class AuthService:
    """Service for authentication operations."""

    # Default session lifetime: 24 hours
    DEFAULT_SESSION_LIFETIME_HOURS = 24

    # Dummy hash for timing attack prevention - bcrypt hash of random string
    # Used to ensure constant-time comparison even when user doesn't exist
    _DUMMY_HASH = "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.NTtYB.1NQq1vRi"

    def __init__(
        self,
        session: Session,
        session_lifetime_hours: int = DEFAULT_SESSION_LIFETIME_HOURS,
    ):
        """Initialize auth service.

        Args:
            session: SQLAlchemy database session
            session_lifetime_hours: Session lifetime in hours
        """
        self.db_session = session
        self.session_lifetime_hours = session_lifetime_hours
        self.user_repo = UserRepository(session)
        self.role_repo = RoleRepository(session)
        self.permission_repo = PermissionRepository(session)
        self.session_repo = SessionRepository(session)
        self.audit_repo = AuditLogRepository(session)

    def login(
        self,
        username: str,
        password: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> Tuple[Optional[User], Optional[str], Optional[str]]:
        """Authenticate user and create session.

        Args:
            username: Username or email
            password: Plain text password
            ip_address: Client IP address
            user_agent: Client user agent string

        Returns:
            Tuple of (user, session_token, error_message)
            If login fails, user and session_token will be None
        """
        # Try to find user by username or email
        user = self.user_repo.get_by_username(username)
        if user is None:
            user = self.user_repo.get_by_email(username)

        # Timing attack prevention: always verify a password hash
        # even when user doesn't exist, to ensure constant-time response
        if user is None:
            # Verify against dummy hash to consume same time as real verification
            password_hasher.verify(password, self._DUMMY_HASH)
            self._log_failed_login(username, ip_address, "User not found")
            return None, None, "Invalid username or password"

        if not user.is_active:
            # Still verify password to prevent timing leak for disabled accounts
            password_hasher.verify(password, user.password_hash)
            self._log_failed_login(username, ip_address, "Account disabled")
            return None, None, "Account is disabled"

        if not password_hasher.verify(password, user.password_hash):
            self._log_failed_login(username, ip_address, "Invalid password")
            return None, None, "Invalid username or password"

        # Create session
        session_token = self._generate_session_token()
        expires_at = datetime.utcnow() + timedelta(hours=self.session_lifetime_hours)

        self.session_repo.create(
            user_id=user.id,
            session_token=session_token,
            expires_at=expires_at,
            ip_address=ip_address,
            user_agent=user_agent,
        )

        # Update last login
        self.user_repo.update_last_login(user)

        # Log successful login
        self.audit_repo.create(
            user_id=user.id,
            action="login",
            resource_type="user",
            resource_id=user.id,
            details={"ip_address": ip_address},
            ip_address=ip_address,
        )

        return user, session_token, None

    def logout(
        self,
        session_token: str,
        ip_address: str | None = None,
    ) -> bool:
        """Logout user by invalidating session.

        Args:
            session_token: Session token to invalidate
            ip_address: Client IP address for audit

        Returns:
            True if session was found and deleted
        """
        user_session = self.session_repo.get_by_token(session_token)
        if user_session:
            user_id = user_session.user_id
            self.session_repo.delete(user_session)

            self.audit_repo.create(
                user_id=user_id,
                action="logout",
                resource_type="user",
                resource_id=user_id,
                ip_address=ip_address,
            )
            return True
        return False

    def logout_all_sessions(
        self,
        user_id: int,
        ip_address: str | None = None,
    ) -> int:
        """Logout all sessions for a user.

        Args:
            user_id: User ID
            ip_address: Client IP address for audit

        Returns:
            Number of sessions deleted
        """
        count = self.session_repo.delete_all_for_user(user_id)

        self.audit_repo.create(
            user_id=user_id,
            action="logout_all",
            resource_type="user",
            resource_id=user_id,
            details={"sessions_deleted": count},
            ip_address=ip_address,
        )

        return count

    def validate_session(self, session_token: str) -> Optional[User]:
        """Validate a session token and return the user.

        Args:
            session_token: Session token to validate

        Returns:
            User if session is valid, None otherwise
        """
        user_session = self.session_repo.get_valid_session(session_token)
        if user_session is None:
            return None

        if not user_session.user.is_active:
            return None

        return user_session.user

    def change_password(
        self,
        user: User,
        current_password: str,
        new_password: str,
        ip_address: str | None = None,
    ) -> Tuple[bool, Optional[str]]:
        """Change user's password.

        Args:
            user: User to change password for
            current_password: Current password for verification
            new_password: New password
            ip_address: Client IP address for audit

        Returns:
            Tuple of (success, error_message)
        """
        if not password_hasher.verify(current_password, user.password_hash):
            self.audit_repo.create(
                user_id=user.id,
                action="password_change_failed",
                resource_type="user",
                resource_id=user.id,
                details={"reason": "Invalid current password"},
                ip_address=ip_address,
            )
            return False, "Current password is incorrect"

        new_hash = password_hasher.hash(new_password)
        self.user_repo.update_password(user, new_hash)

        self.audit_repo.create(
            user_id=user.id,
            action="password_changed",
            resource_type="user",
            resource_id=user.id,
            ip_address=ip_address,
        )

        return True, None

    def reset_password(
        self,
        user: User,
        new_password: str,
        must_change: bool = True,
        admin_user_id: int | None = None,
        ip_address: str | None = None,
    ) -> None:
        """Reset user's password (admin action).

        Args:
            user: User to reset password for
            new_password: New password
            must_change: Require password change on next login
            admin_user_id: Admin user performing the reset
            ip_address: Client IP address for audit
        """
        new_hash = password_hasher.hash(new_password)
        user.password_hash = new_hash
        user.must_change_password = must_change
        self.db_session.flush()

        self.audit_repo.create(
            user_id=admin_user_id,
            action="password_reset",
            resource_type="user",
            resource_id=user.id,
            details={"target_user": user.username, "must_change": must_change},
            ip_address=ip_address,
        )

    def cleanup_expired_sessions(self) -> int:
        """Remove all expired sessions.

        Returns:
            Number of sessions deleted
        """
        return self.session_repo.delete_expired()

    def _generate_session_token(self) -> str:
        """Generate a secure session token."""
        return secrets.token_urlsafe(32)

    def _log_failed_login(
        self,
        username: str,
        ip_address: str | None,
        reason: str,
    ) -> None:
        """Log a failed login attempt."""
        self.audit_repo.create(
            user_id=None,
            action="login_failed",
            resource_type="user",
            details={"username": username, "reason": reason},
            ip_address=ip_address,
        )

    # User management methods
    def create_user(
        self,
        username: str,
        email: str,
        password: str,
        display_name: str | None = None,
        role_names: list[str] | None = None,
        must_change_password: bool = False,
        admin_user_id: int | None = None,
        ip_address: str | None = None,
    ) -> Tuple[Optional[User], Optional[str]]:
        """Create a new user.

        Args:
            username: Username
            email: Email address
            password: Plain text password
            display_name: Display name
            role_names: List of role names to assign
            must_change_password: Require password change on first login
            admin_user_id: Admin user creating the user
            ip_address: Client IP address for audit

        Returns:
            Tuple of (user, error_message)
        """
        # Check for existing username
        if self.user_repo.get_by_username(username):
            return None, "Username already exists"

        # Check for existing email
        if self.user_repo.get_by_email(email):
            return None, "Email already exists"

        # Create user
        password_hash = password_hasher.hash(password)
        user = self.user_repo.create(
            username=username,
            email=email,
            password_hash=password_hash,
            display_name=display_name,
            must_change_password=must_change_password,
        )

        # Assign roles
        if role_names:
            roles = []
            for role_name in role_names:
                role = self.role_repo.get_by_name(role_name)
                if role:
                    roles.append(role)
            if roles:
                self.user_repo.set_roles(user, roles)

        # Audit log
        self.audit_repo.create(
            user_id=admin_user_id,
            action="user_created",
            resource_type="user",
            resource_id=user.id,
            details={"username": username, "roles": role_names},
            ip_address=ip_address,
        )

        return user, None

    def update_user_roles(
        self,
        user: User,
        role_names: list[str],
        admin_user_id: int | None = None,
        ip_address: str | None = None,
    ) -> None:
        """Update a user's roles.

        Args:
            user: User to update
            role_names: List of role names to assign
            admin_user_id: Admin user performing the update
            ip_address: Client IP address for audit
        """
        old_roles = [r.name for r in user.roles]

        roles = []
        for role_name in role_names:
            role = self.role_repo.get_by_name(role_name)
            if role:
                roles.append(role)

        self.user_repo.set_roles(user, roles)

        self.audit_repo.create(
            user_id=admin_user_id,
            action="user_roles_updated",
            resource_type="user",
            resource_id=user.id,
            details={
                "username": user.username,
                "old_roles": old_roles,
                "new_roles": role_names,
            },
            ip_address=ip_address,
        )

    # Seed methods for initial setup
    def seed_permissions(self) -> list[Permission]:
        """Create default permissions."""
        permissions_data = [
            # Template permissions
            ("template:read", "template", "read", "View templates"),
            ("template:create", "template", "create", "Create templates"),
            ("template:update", "template", "update", "Update templates"),
            ("template:delete", "template", "delete", "Delete templates"),
            # Document permissions
            ("document:read", "document", "read", "View documents"),
            ("document:create", "document", "create", "Create documents"),
            ("document:update", "document", "update", "Update documents"),
            ("document:delete", "document", "delete", "Delete documents"),
            # User permissions
            ("user:read", "user", "read", "View users"),
            ("user:create", "user", "create", "Create users"),
            ("user:update", "user", "update", "Update users"),
            ("user:delete", "user", "delete", "Delete users"),
            # System permissions
            ("system:audit_view", "system", "audit_view", "View audit logs"),
            ("system:settings", "system", "settings", "Manage system settings"),
            # Integration permissions
            ("integration:read", "integration", "read", "View integrations"),
            ("integration:manage", "integration", "manage", "Manage integrations and webhooks"),
        ]

        permissions = []
        for name, resource, action, description in permissions_data:
            existing = self.permission_repo.get_by_name(name)
            if existing:
                permissions.append(existing)
            else:
                permission = self.permission_repo.create(
                    name=name,
                    resource=resource,
                    action=action,
                    description=description,
                )
                permissions.append(permission)

        return permissions

    def seed_roles(self) -> list[Role]:
        """Create default roles with permissions."""
        all_permissions = {p.name: p for p in self.permission_repo.list_all()}

        roles_data = [
            (
                "admin",
                "Administrator with full access",
                True,
                list(all_permissions.keys()),  # All permissions
            ),
            (
                "editor",
                "Can create and edit templates and documents",
                True,
                [
                    "template:read", "template:create", "template:update", "template:delete",
                    "document:read", "document:create", "document:update", "document:delete",
                ],
            ),
            (
                "viewer",
                "Read-only access to templates and documents",
                True,
                ["template:read", "document:read"],
            ),
            (
                "engineering",
                "Engineering role with document access and server administration",
                True,
                [
                    "template:read", "template:create", "template:update", "template:delete",
                    "document:read", "document:create", "document:update", "document:delete",
                    "system:audit_view", "system:settings",
                    "integration:read", "integration:manage",
                ],
            ),
        ]

        roles = []
        for name, description, is_system, permission_names in roles_data:
            existing = self.role_repo.get_by_name(name)
            if existing:
                roles.append(existing)
            else:
                role = self.role_repo.create(
                    name=name,
                    description=description,
                    is_system=is_system,
                )
                role_permissions = [
                    all_permissions[pn] for pn in permission_names if pn in all_permissions
                ]
                self.role_repo.set_permissions(role, role_permissions)
                roles.append(role)

        return roles

    def seed_admin_user(
        self,
        username: str = "admin",
        password: str = "changeme",
        email: str = "admin@localhost",
    ) -> Optional[User]:
        """Create default admin user."""
        existing = self.user_repo.get_by_username(username)
        if existing:
            return existing

        admin_role = self.role_repo.get_by_name("admin")
        password_hash = password_hasher.hash(password)

        user = self.user_repo.create(
            username=username,
            email=email,
            password_hash=password_hash,
            display_name="Administrator",
            must_change_password=True,
        )

        if admin_role:
            self.user_repo.add_role(user, admin_role)

        return user
