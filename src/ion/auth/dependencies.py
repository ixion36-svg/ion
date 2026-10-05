"""FastAPI dependencies for authentication and authorization."""

import logging
from typing import Callable, List, Optional

from fastapi import Cookie, Depends, HTTPException, Request, status
from fastapi.concurrency import run_in_threadpool
from sqlalchemy.orm import Session

from ion.auth.service import AuthService
from ion.core.client_ip import get_client_ip  # noqa: F401  (re-exported; many call sites import it from here)
from ion.core.config import get_config, get_oidc_config
from ion.models.user import User
from ion.storage.database import get_db_session  # noqa: F401  (re-exported; routers import it from here)

logger = logging.getLogger(__name__)

# Which estate the analyst is looking at. Caller-controlled and validated on
# every request by resolve_tenant_for_user, so tampering gains nothing: a
# tenant-bound user is refused and keeps their own, and a platform user could
# have selected that tenant anyway. Not HttpOnly — the header toggle reads it.
TENANT_COOKIE = "ion_tenant"

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

# The page the login redirect sends a flagged user to. Gating page routes
# without this allowlisted locks the account out of its own remediation: the
# change-password form lives on /profile and nowhere else. Matched exactly, not
# by prefix — a prefix would silently exempt any future /profile* route.
_PWD_CHANGE_ALLOWED_PAGES = frozenset({"/profile"})


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


async def get_current_user(
    request: Request,
    session_token: Optional[str] = Depends(get_session_token),
    auth_service: AuthService = Depends(get_auth_service),
) -> User:
    """Get current authenticated user.

    Raises HTTPException 401 if not authenticated. When
    ION_ENFORCE_PASSWORD_CHANGE is on, also raises 403 for a user flagged
    must_change_password on any endpoint outside the password-change allowlist.

    Async on purpose: the blocking work runs in the threadpool, but the tenant
    ContextVars must be set HERE, in the request's own context. A sync
    dependency runs in a copied context, so a ContextVar set inside it is
    discarded before the route runs.
    """
    user, binding = await run_in_threadpool(
        _authenticate, request, session_token, auth_service
    )
    install_tenant_binding(binding)
    return user


def _authenticate(
    request: Request,
    session_token: Optional[str],
    auth_service: AuthService,
) -> tuple:
    """Blocking half of get_current_user: session validation + tenant resolve."""
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

    return user, apply_post_session_policy(request, user, auth_service)


def password_change_blocks(request: Request, user: User, *, pages: bool = False) -> bool:
    """Whether this request must be refused until the user changes password.

    ION_ENFORCE_PASSWORD_CHANGE, default ON. Without it the flag is advisory
    (frontend-only) and a default-credential session could call any API. In
    ION's deployment the only local account is admin (others are OIDC), so this
    primarily protects the admin account. ``pages`` additionally permits the
    page hosting the change-password form.
    """
    if not getattr(user, "must_change_password", False):
        return False
    if not get_config().enforce_password_change:
        return False
    path = request.url.path
    if pages and path.rstrip("/") in _PWD_CHANGE_ALLOWED_PAGES:
        return False
    return not any(path.startswith(p) for p in _PWD_CHANGE_ALLOWED_PREFIXES)


def _password_change_required(pages: bool) -> HTTPException:
    """Pages redirect to the form; API callers get a status they can read."""
    if pages:
        return HTTPException(
            status_code=status.HTTP_307_TEMPORARY_REDIRECT,
            headers={"Location": "/profile?change_password=1"},
        )
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Password change required before continuing",
    )


def apply_post_session_policy(
    request: Request, user: User, auth_service: AuthService, *, pages: bool = False
) -> Optional[tuple]:
    """Every policy that applies after a session validates. Shared by all entry points.

    ``validate_session()`` proves a token is live; it does not gate a pending
    password change or resolve the caller's tenant. An entry point that calls
    it directly and skips this inherits neither — MCP did, so a flagged user
    could run tools, and a tenant-bound user's writes reached the default
    estate because an unresolved tenant means "default" to the ES/Kibana
    overlay.

    Returns the tenant binding for the caller to install with
    :func:`install_tenant_binding`, from the request's own context.
    """
    if password_change_blocks(request, user, pages=pages):
        raise _password_change_required(pages)

    # APM: tag the transaction with the analyst (no-op when APM is off).
    from ion.core import apm
    apm.set_user(
        username=getattr(user, "username", None),
        user_id=getattr(user, "id", None),
        email=getattr(user, "email", None),
    )

    return _resolve_tenant_binding(request, user, auth_service)


def install_tenant_binding(binding: Optional[tuple]) -> None:
    """Set the tenant ContextVars. Only correct from the request's own context:
    a ContextVar set in a copied context (a sync dependency, a threadpool call)
    is discarded before the route runs."""
    if binding is None:
        return
    from ion.core.tenant_context import set_tenant_connection, set_tenant_id

    set_tenant_id(binding[0])
    set_tenant_connection(binding[1])


def _resolve_tenant_binding(
    request: Request, user: User, auth_service: AuthService
) -> Optional[tuple]:
    """The (tenant_id, connection) this request acts for; None when tenancy is off.

    Fails closed. The ES/Kibana overlay treats "no tenant bound" as the
    process-wide (default) estate, so proceeding unbound after a failed resolve
    would show a tenant's user another estate's data: a bound user whose tenant
    cannot be resolved (deactivated, or the lookup errored) is refused instead.
    """
    from ion.services.tenant_service import (
        multi_tenant_enabled,
        resolve_tenant_for_user,
        tenant_connection,
    )

    if not multi_tenant_enabled():
        return None

    # Caller-controlled, and validated by the resolver: a tenant-bound user
    # asking for another estate is refused and keeps their own.
    requested = request.cookies.get(TENANT_COOKIE) or request.headers.get("X-ION-Tenant")
    try:
        tenant = resolve_tenant_for_user(auth_service.db_session, user, requested)
    except HTTPException:
        raise
    except Exception:  # noqa: BLE001
        logger.warning("tenant resolution failed; refusing the request", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Tenant resolution failed",
        )
    if tenant is None and getattr(user, "tenant_id", None) is not None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Your estate is not available",
        )
    return (tenant.id if tenant else None, tenant_connection(tenant))


def _bind_tenant(request: Request, user: User, auth_service: AuthService) -> None:
    """Resolve and install the tenant, in the caller's own context.

    Correct only where the caller's context IS the request's (tests, in-context
    helpers). get_current_user does not use this: it resolves in the threadpool
    and sets the variables in its async body, because a threadpool dependency
    runs in a copied context whose ContextVar writes are discarded.
    """
    install_tenant_binding(_resolve_tenant_binding(request, user, auth_service))


def get_current_user_optional(
    session_token: Optional[str] = Depends(get_session_token),
    auth_service: AuthService = Depends(get_auth_service),
) -> Optional[User]:
    """Get current user if authenticated, None otherwise.

    Does not raise an exception if not authenticated. No caller today: a route
    that adopts it skips apply_post_session_policy, so route it through that
    first or it reintroduces the MCP bypass.
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

    No caller today: like get_current_user_optional it applies no
    post-session policy, so a route adopting it must call
    apply_post_session_policy itself.
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


# A 403 body naming the permission hands the caller ION's permission taxonomy,
# which is a map for targeting. The caller learns only that access was refused;
# the specific permission goes to the log, matching the uniform login contract.
_PERMISSION_DENIED_DETAIL = "Permission denied"


def _permission_denied(user: object, required: object) -> HTTPException:
    logger.warning(
        "Permission denied for user %s: %s required",
        getattr(user, "username", "<unknown>"), required,
    )
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=_PERMISSION_DENIED_DETAIL,
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
            raise _permission_denied(user, permission_name)
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
            raise _permission_denied(user, permission_names)
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


def _login_redirect(request: Request) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_307_TEMPORARY_REDIRECT,
        headers={"Location": "/login?redirect=" + str(request.url.path)},
    )


def _authenticate_page(
    request: Request,
    session_token: Optional[str],
    auth_service: AuthService,
    permission_name: Optional[str] = None,
) -> tuple:
    """Blocking half of the page authenticators: session, policy, permission.

    Pages apply the same post-session policy as the API, but a flagged user is
    redirected to the change-password form rather than shown a 403 they cannot
    act on.
    """
    if not session_token:
        raise _login_redirect(request)

    user = auth_service.validate_session(session_token)
    if user is None:
        raise _login_redirect(request)

    # Policy first: a flagged user should meet the change-password redirect, not
    # a permission error on a page they would be allowed once remediated.
    binding = apply_post_session_policy(request, user, auth_service, pages=True)

    if permission_name is not None and not user.has_permission(permission_name):
        raise _permission_denied(user, permission_name)

    return user, binding


async def require_page_auth(
    request: Request,
    session_token: Optional[str] = Depends(get_session_token),
    auth_service: AuthService = Depends(get_auth_service),
) -> User:
    """For page routes: redirect to /login if not authenticated.

    Async for the same reason as get_current_user — the tenant ContextVars must
    be set here, in the request's own context.
    """
    user, binding = await run_in_threadpool(
        _authenticate_page, request, session_token, auth_service
    )
    install_tenant_binding(binding)
    return user


def require_page_permission(permission_name: str) -> Callable:
    """For page routes: redirect to /login if not auth'd, 403 if no permission."""
    async def dependency(
        request: Request,
        session_token: Optional[str] = Depends(get_session_token),
        auth_service: AuthService = Depends(get_auth_service),
    ) -> User:
        user, binding = await run_in_threadpool(
            _authenticate_page, request, session_token, auth_service, permission_name
        )
        install_tenant_binding(binding)
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
                raise _permission_denied(user, missing)
        else:
            if not user.has_any_permission(self.required_permissions):
                raise _permission_denied(user, self.required_permissions)
        return user


# get_client_ip is centralised in ion.core.client_ip and imported at
# the top of this module, then re-exported for the call sites that historically
# imported it from ion.auth.dependencies. The previous local implementation
# blindly trusted the first X-Forwarded-For value (spoofable); the shared one
# honours forwarded headers only from peers in ION_TRUSTED_PROXIES.
