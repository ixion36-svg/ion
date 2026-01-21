"""FastAPI dependencies for authentication and authorization."""

import logging
from typing import Optional, Callable, List, Generator

from fastapi import Depends, HTTPException, status, Request, Cookie
from sqlalchemy.orm import Session

from docforge.models.user import User
from docforge.core.config import get_config, get_oidc_config
from docforge.storage.database import get_engine, get_session_factory
from docforge.auth.service import AuthService

logger = logging.getLogger(__name__)

# Cookie name for session token
SESSION_COOKIE_NAME = "docforge_session"


def get_db_session() -> Generator[Session, None, None]:
    """FastAPI dependency for database session with proper cleanup."""
    config = get_config()
    engine = get_engine(config.db_path)
    factory = get_session_factory(engine)
    session = factory()
    try:
        yield session
    finally:
        session.close()


def get_auth_service(session: Session = Depends(get_db_session)) -> AuthService:
    """Get authentication service instance."""
    return AuthService(session)


def get_session_token(
    request: Request,
    docforge_session: Optional[str] = Cookie(default=None),
) -> Optional[str]:
    """Extract session token from cookie or Authorization header.

    Supports:
    - Cookie: docforge_session=<token>
    - Header: Authorization: Bearer <token>
    """
    # Try cookie first
    if docforge_session:
        return docforge_session

    # Try Authorization header
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        return auth_header[7:]

    return None


def get_current_user(
    session_token: Optional[str] = Depends(get_session_token),
    auth_service: AuthService = Depends(get_auth_service),
) -> User:
    """Get current authenticated user.

    Raises HTTPException 401 if not authenticated.
    """
    if not session_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = auth_service.validate_session(session_token)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


def get_current_user_optional(
    session_token: Optional[str] = Depends(get_session_token),
    auth_service: AuthService = Depends(get_auth_service),
) -> Optional[User]:
    """Get current user if authenticated, None otherwise.

    Does not raise an exception if not authenticated.
    """
    if not session_token:
        return None

    return auth_service.validate_session(session_token)


def get_current_user_hybrid(
    request: Request,
    session: Session = Depends(get_db_session),
) -> User:
    """Hybrid authentication: try session-based auth first, then OIDC.

    This dependency supports both traditional session-based authentication
    and Keycloak OIDC JWT tokens. It tries session validation first for
    backward compatibility, then falls back to OIDC if enabled.

    Raises HTTPException 401 if neither authentication method succeeds.
    """
    # Extract token from request
    token = get_session_token(request)

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 1. Try session-based auth first (existing behavior)
    auth_service = AuthService(session)
    user = auth_service.validate_session(token)
    if user:
        return user

    # 2. Try OIDC if enabled
    oidc_config = get_oidc_config()
    if oidc_config.enabled and oidc_config.is_valid():
        try:
            from docforge.auth.oidc import OIDCValidator, OIDCUserSync, OIDCValidationError
            from docforge.storage.auth_repository import AuditLogRepository

            validator = OIDCValidator(oidc_config)
            token_data = validator.validate_token(token)

            # Sync user to database
            sync = OIDCUserSync(session, oidc_config)
            user = sync.sync_user(token_data)
            session.commit()

            # Log OIDC auth to audit
            audit_repo = AuditLogRepository(session)
            audit_repo.create(
                user_id=user.id,
                action="oidc_login",
                details={"provider": "keycloak", "sub": token_data.sub},
                ip_address=get_client_ip(request),
            )
            session.commit()

            logger.debug(f"OIDC authentication successful for user: {user.username}")
            return user

        except OIDCValidationError as e:
            logger.debug(f"OIDC validation failed: {e}")
            # Fall through to 401
        except Exception as e:
            logger.error(f"OIDC authentication error: {e}")
            # Fall through to 401

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )


def require_permission(permission_name: str) -> Callable:
    """Dependency factory that requires a specific permission.

    Usage:
        @router.get("/admin", dependencies=[Depends(require_permission("admin:access"))])
        def admin_endpoint():
            ...
    """
    def dependency(user: User = Depends(get_current_user)) -> User:
        if not user.has_permission(permission_name):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: {permission_name} required",
            )
        return user
    return dependency


def require_any_permission(permission_names: List[str]) -> Callable:
    """Dependency factory that requires any of the specified permissions.

    Usage:
        @router.get("/edit", dependencies=[Depends(require_any_permission(["doc:edit", "doc:admin"]))])
        def edit_endpoint():
            ...
    """
    def dependency(user: User = Depends(get_current_user)) -> User:
        if not user.has_any_permission(permission_names):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: one of {permission_names} required",
            )
        return user
    return dependency


def require_admin(user: User = Depends(get_current_user)) -> User:
    """Require user to have admin role.

    Usage:
        @router.get("/admin-only", dependencies=[Depends(require_admin)])
        def admin_only_endpoint():
            ...
    """
    if not user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return user


class PermissionChecker:
    """Class-based permission checker for more complex scenarios.

    Usage:
        checker = PermissionChecker(["template:read", "template:write"])

        @router.get("/templates", dependencies=[Depends(checker)])
        def get_templates():
            ...
    """

    def __init__(
        self,
        required_permissions: List[str],
        require_all: bool = False,
    ):
        """Initialize permission checker.

        Args:
            required_permissions: List of permission names to check
            require_all: If True, user must have ALL permissions.
                        If False (default), user needs ANY permission.
        """
        self.required_permissions = required_permissions
        self.require_all = require_all

    def __call__(self, user: User = Depends(get_current_user)) -> User:
        if self.require_all:
            missing = [
                p for p in self.required_permissions
                if not user.has_permission(p)
            ]
            if missing:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Permission denied: missing {missing}",
                )
        else:
            if not user.has_any_permission(self.required_permissions):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Permission denied: one of {self.required_permissions} required",
                )
        return user


def get_client_ip(request: Request) -> Optional[str]:
    """Extract client IP address from request."""
    # Check X-Forwarded-For header (common with proxies)
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # Take the first IP in the chain
        return forwarded_for.split(",")[0].strip()

    # Fall back to direct client
    if request.client:
        return request.client.host

    return None
