"""FastAPI dependencies for authentication and authorization."""

import logging
from typing import Callable, List, Optional

from fastapi import Cookie, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from ion.auth.service import AuthService
from ion.core.client_ip import get_client_ip  # noqa: F401  (re-exported; many call sites import it from here)
from ion.core.config import get_config, get_oidc_config
from ion.models.user import User
from ion.storage.database import get_db_session  # noqa: F401  (re-exported; routers import it from here)

logger = logging.getLogger(__name__)

# Cookie name for session token
SESSION_COOKIE_NAME = "ion_session"

# F4: endpoints a must_change_password user may still reach so they can change
# their password (plus the static assets needed to render the change form).
# Everything else is blocked when ION_ENFORCE_PASSWORD_CHANGE is on. Prefix match.
_PWD_CHANGE_ALLOWED_PREFIXES = (
    "/api/auth/change-password",
    "/api/auth/me",
    "/api/auth/logout",
    "/static/",
)


def get_auth_service(session: Session = Depends(get_db_session)) -> AuthService:
    """Get authentication service instance."""
    return AuthService(session)


def get_session_token(
    request: Request,
    ion_session: Optional[str] = Cookie(default=None),
) -> Optional[str]:
    """Extract session token from cookie or Authorization header.

    Supports:
    - Cookie: ion_session=<token>
    - Header: Authorization: Bearer <token>
    """
    # Try cookie first
    if ion_session:
        return ion_session

    # Try Authorization header
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        return auth_header[7:]

    return None


def get_current_user(
    request: Request,
    session_token: Optional[str] = Depends(get_session_token),
    auth_service: AuthService = Depends(get_auth_service),
) -> User:
    """Get current authenticated user.

    Raises HTTPException 401 if not authenticated. When
    ION_ENFORCE_PASSWORD_CHANGE is on, also raises 403 for a user flagged
    must_change_password on any endpoint outside the password-change allowlist.
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

    # F4 (opt-in ION_ENFORCE_PASSWORD_CHANGE): a must_change_password user may
    # only reach the password-change endpoints. Without this the flag is
    # advisory (frontend-only) and a default-credential session could call any
    # API. In ION's deployment the only local account is admin (others are
    # OIDC), so this primarily protects the admin account.
    if getattr(user, "must_change_password", False) and get_config().enforce_password_change:
        path = request.url.path
        if not any(path.startswith(p) for p in _PWD_CHANGE_ALLOWED_PREFIXES):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Password change required before continuing",
            )

    # APM: tag the transaction with the analyst (no-op when APM is off).
    from ion.core import apm
    apm.set_user(
        username=getattr(user, "username", None),
        user_id=getattr(user, "id", None),
        email=getattr(user, "email", None),
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
            from ion.auth.oidc import OIDCUserSync, OIDCValidationError, OIDCValidator
            from ion.storage.auth_repository import AuditLogRepository

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


def require_page_auth(
    request: Request,
    session_token: Optional[str] = Depends(get_session_token),
    auth_service: AuthService = Depends(get_auth_service),
) -> User:
    """For page routes: redirect to /login if not authenticated."""
    if not session_token:
        raise HTTPException(
            status_code=status.HTTP_307_TEMPORARY_REDIRECT,
            headers={"Location": "/login?redirect=" + str(request.url.path)},
        )

    user = auth_service.validate_session(session_token)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_307_TEMPORARY_REDIRECT,
            headers={"Location": "/login?redirect=" + str(request.url.path)},
        )

    return user


def require_page_permission(permission_name: str) -> Callable:
    """For page routes: redirect to /login if not auth'd, 403 if no permission."""
    def dependency(
        request: Request,
        session_token: Optional[str] = Depends(get_session_token),
        auth_service: AuthService = Depends(get_auth_service),
    ) -> User:
        if not session_token:
            raise HTTPException(
                status_code=status.HTTP_307_TEMPORARY_REDIRECT,
                headers={"Location": "/login?redirect=" + str(request.url.path)},
            )

        user = auth_service.validate_session(session_token)
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_307_TEMPORARY_REDIRECT,
                headers={"Location": "/login?redirect=" + str(request.url.path)},
            )

        if not user.has_permission(permission_name):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: {permission_name} required",
            )
        return user
    return dependency


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


# get_client_ip is centralised in ion.core.client_ip and imported at
# the top of this module, then re-exported for the call sites that historically
# imported it from ion.auth.dependencies. The previous local implementation
# blindly trusted the first X-Forwarded-For value (spoofable); the shared one
# honours forwarded headers only from peers in ION_TRUSTED_PROXIES.
