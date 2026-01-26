"""API routes for DocForge web interface."""

import asyncio
import json
import secrets
from pathlib import Path
from typing import Optional, List, Generator
from dataclasses import dataclass
from urllib.parse import quote as url_quote
from fastapi import APIRouter, HTTPException, UploadFile, File, Form, Depends, Request, Response, Cookie
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
import httpx
from slowapi import Limiter
from slowapi.util import get_remote_address

from docforge.core.config import get_config, get_oidc_config, get_gitlab_config

# Rate limiter - uses IP address as key
limiter = Limiter(key_func=get_remote_address)

# OIDC state cookie name for CSRF protection
OIDC_STATE_COOKIE_NAME = "oidc_state"
from docforge.core.exceptions import (
    TemplateNotFoundError,
    VersionNotFoundError,
    ValidationError,
    RenderError,
)
from docforge.storage.database import get_session_factory, get_engine
from docforge.services.template_service import TemplateService
from docforge.services.version_service import VersionService
from docforge.services.render_service import RenderService
from docforge.extraction.template_generator import TemplateGenerator
from docforge.storage.document_repository import DocumentRepository
from docforge.models.user import User
from docforge.auth.service import AuthService
from docforge.auth.dependencies import (
    get_current_user,
    get_current_user_optional,
    require_permission,
    require_admin,
    get_client_ip,
    get_auth_service,
    SESSION_COOKIE_NAME,
)
from docforge.storage.auth_repository import AuditLogRepository
from docforge.storage.user_repository import UserRepository, RoleRepository

router = APIRouter()


# Pydantic models for request/response
class TemplateCreate(BaseModel):
    name: str
    content: str = ""
    format: str = "markdown"
    description: Optional[str] = None
    tags: Optional[List[str]] = None


class TemplateUpdate(BaseModel):
    name: Optional[str] = None
    content: Optional[str] = None
    format: Optional[str] = None
    description: Optional[str] = None
    message: Optional[str] = None
    author: Optional[str] = None


class RenderRequest(BaseModel):
    data: dict = {}
    output_format: Optional[str] = None


class CheckpointCreate(BaseModel):
    name: str
    message: Optional[str] = None


class TagUpdate(BaseModel):
    add: Optional[List[str]] = None
    remove: Optional[List[str]] = None


class DocumentAmendment(BaseModel):
    rendered_content: str
    input_data: Optional[dict] = None
    amendment_reason: Optional[str] = None
    amended_by: Optional[str] = None


# Collection request/response models
class CollectionCreate(BaseModel):
    name: str
    description: Optional[str] = None
    icon: Optional[str] = None
    parent_id: Optional[int] = None


class CollectionUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    icon: Optional[str] = None
    parent_id: Optional[int] = None


# Validation request model
class ValidateRequest(BaseModel):
    data: dict = {}


# Batch render request model
class BatchRenderRequest(BaseModel):
    data_list: List[dict]
    output_format: Optional[str] = None
    document_name_field: Optional[str] = None
    document_name_prefix: Optional[str] = None
    save_documents: bool = True
    validate_data: bool = True
    stop_on_error: bool = False


# Auth request/response models
class LoginRequest(BaseModel):
    username: str
    password: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    display_name: Optional[str] = None
    roles: Optional[List[str]] = None


class UserUpdate(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None
    display_name: Optional[str] = None
    is_active: Optional[bool] = None


class UserRolesUpdate(BaseModel):
    roles: List[str]


class PasswordReset(BaseModel):
    new_password: str
    must_change: bool = True


@dataclass
class Services:
    """Container for service instances."""
    template: TemplateService
    version: VersionService
    render: RenderService
    document_repo: DocumentRepository
    session: Session


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


def get_services(session: Session = Depends(get_db_session)) -> Services:
    """Get service instances with injected session."""
    return Services(
        template=TemplateService(session),
        version=VersionService(session),
        render=RenderService(session),
        document_repo=DocumentRepository(session),
        session=session,
    )


# =============================================================================
# Auth endpoints
# =============================================================================

@router.post("/auth/login")
@limiter.limit("5/minute")  # Rate limit: 5 login attempts per minute per IP
async def login(
    request: Request,
    login_request: LoginRequest,
    response: Response,
    session: Session = Depends(get_db_session),
):
    """Login and create session."""
    auth_service = AuthService(session)
    ip_address = get_client_ip(request)
    user_agent = request.headers.get("User-Agent")

    user, session_token, error = auth_service.login(
        username=login_request.username,
        password=login_request.password,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    if error:
        session.commit()  # Commit audit log for failed attempt
        raise HTTPException(status_code=401, detail=error)

    session.commit()

    # Set session cookie
    config = get_config()
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session_token,
        httponly=True,
        samesite="strict",
        secure=config.cookie_secure,
        max_age=24 * 60 * 60,  # 24 hours
    )

    return {
        "message": "Login successful",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "display_name": user.display_name,
            "roles": [r.name for r in user.roles],
            "must_change_password": user.must_change_password,
        },
    }


@router.post("/auth/logout")
async def logout(
    request: Request,
    response: Response,
    current_user: User = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service),
):
    """Logout and invalidate session."""
    from docforge.auth.dependencies import get_session_token
    session_token = get_session_token(request)

    if session_token:
        ip_address = get_client_ip(request)
        auth_service.logout(session_token, ip_address)
        auth_service.db_session.commit()

    # Clear session cookie
    response.delete_cookie(key=SESSION_COOKIE_NAME)

    return {"message": "Logout successful"}


@router.get("/auth/me")
async def get_current_user_info(
    current_user: User = Depends(get_current_user),
):
    """Get current user information."""
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "display_name": current_user.display_name,
        "is_active": current_user.is_active,
        "must_change_password": current_user.must_change_password,
        "last_login": current_user.last_login.isoformat() if current_user.last_login else None,
        "roles": [r.name for r in current_user.roles],
        "permissions": list(set(
            p.name for r in current_user.roles for p in r.permissions
        )),
    }


@router.post("/auth/change-password")
async def change_password(
    password_request: ChangePasswordRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service),
):
    """Change current user's password."""
    ip_address = get_client_ip(request)

    success, error = auth_service.change_password(
        user=current_user,
        current_password=password_request.current_password,
        new_password=password_request.new_password,
        ip_address=ip_address,
    )

    if not success:
        auth_service.db_session.commit()
        raise HTTPException(status_code=400, detail=error)

    auth_service.db_session.commit()
    return {"message": "Password changed successfully"}


# =============================================================================
# OIDC/Keycloak endpoints
# =============================================================================

@router.get("/auth/oidc/config")
async def get_oidc_public_config(request: Request, response: Response):
    """Return public OIDC configuration for frontend.

    This endpoint is public and returns only the information needed
    for the frontend to initiate an OIDC login flow. It also generates
    a cryptographically secure state parameter for CSRF protection.
    """
    oidc_config = get_oidc_config()

    if not oidc_config.enabled or not oidc_config.is_valid():
        return {"enabled": False}

    # Build the redirect URI based on the request
    scheme = request.headers.get("X-Forwarded-Proto", request.url.scheme)
    host = request.headers.get("X-Forwarded-Host", request.url.netloc)
    redirect_uri = f"{scheme}://{host}/api/auth/oidc/callback"

    # Generate cryptographically secure state for CSRF protection
    state = secrets.token_urlsafe(32)

    # Store state in httponly cookie for validation on callback
    config = get_config()
    response.set_cookie(
        key=OIDC_STATE_COOKIE_NAME,
        value=state,
        httponly=True,
        samesite="lax",  # Lax needed for OAuth redirects
        secure=config.cookie_secure,
        max_age=600,  # 10 minutes
    )

    return {
        "enabled": True,
        "authorization_url": oidc_config.authorization_url,
        "client_id": oidc_config.client_id,
        "redirect_uri": redirect_uri,
        "state": state,  # Frontend must include this in auth request
    }


@router.get("/auth/oidc/callback")
@limiter.limit("10/minute")  # Rate limit OIDC callbacks
async def oidc_callback(
    request: Request,
    response: Response,
    code: Optional[str] = None,
    state: Optional[str] = None,
    error: Optional[str] = None,
    error_description: Optional[str] = None,
    session: Session = Depends(get_db_session),
    stored_state: Optional[str] = Cookie(None, alias=OIDC_STATE_COOKIE_NAME),
):
    """Handle OIDC authorization code callback from Keycloak.

    This endpoint exchanges the authorization code for tokens,
    validates the access token, syncs the user to DocForge,
    creates a session, and redirects to the dashboard.

    Validates the state parameter to prevent CSRF attacks.
    """
    # Helper to create safe redirect with URL-encoded error
    def error_redirect(msg: str) -> RedirectResponse:
        resp = RedirectResponse(
            url=f"/login?error={url_quote(msg)}",
            status_code=302,
        )
        # Clear the state cookie
        resp.delete_cookie(OIDC_STATE_COOKIE_NAME)
        return resp

    # Handle error response from Keycloak
    if error:
        error_msg = error_description or error
        return error_redirect(error_msg)

    # Validate state parameter (CSRF protection)
    if not state or not stored_state:
        return error_redirect("Missing state parameter")

    if not secrets.compare_digest(state, stored_state):
        return error_redirect("Invalid state parameter - possible CSRF attack")

    if not code:
        return error_redirect("Missing authorization code")

    oidc_config = get_oidc_config()
    if not oidc_config.enabled or not oidc_config.is_valid():
        return error_redirect("OIDC is not configured")

    # Build the redirect URI (must match what was sent in auth request)
    scheme = request.headers.get("X-Forwarded-Proto", request.url.scheme)
    host = request.headers.get("X-Forwarded-Host", request.url.netloc)
    redirect_uri = f"{scheme}://{host}/api/auth/oidc/callback"

    try:
        # Exchange authorization code for tokens
        async with httpx.AsyncClient() as client:
            token_response = await client.post(
                oidc_config.token_url,
                data={
                    "grant_type": "authorization_code",
                    "client_id": oidc_config.client_id,
                    "client_secret": oidc_config.client_secret,
                    "code": code,
                    "redirect_uri": redirect_uri,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=30.0,
            )

            if token_response.status_code != 200:
                error_data = token_response.json() if token_response.content else {}
                error_msg = error_data.get("error_description", "Token exchange failed")
                return error_redirect(error_msg)

            tokens = token_response.json()

        # Validate the access token and extract user info
        from docforge.auth.oidc import OIDCValidator, OIDCUserSync, OIDCValidationError
        from docforge.storage.auth_repository import AuditLogRepository

        validator = OIDCValidator(oidc_config)
        token_data = await validator.validate_token_async(tokens["access_token"])

        # Sync user to DocForge database
        sync = OIDCUserSync(session, oidc_config)
        user = sync.sync_user(token_data)
        session.commit()

        # Create a DocForge session for the user
        auth_service = AuthService(session)
        ip_address = get_client_ip(request)
        user_agent = request.headers.get("User-Agent")

        # Create session token
        from docforge.storage.auth_repository import SessionRepository
        import secrets
        from datetime import datetime, timedelta

        session_repo = SessionRepository(session)
        session_token = secrets.token_urlsafe(32)
        expires_at = datetime.utcnow() + timedelta(hours=24)

        session_repo.create(
            user_id=user.id,
            session_token=session_token,
            expires_at=expires_at,
            ip_address=ip_address,
            user_agent=user_agent,
        )

        # Log OIDC login to audit
        audit_repo = AuditLogRepository(session)
        audit_repo.create(
            user_id=user.id,
            action="oidc_login",
            details={
                "provider": "keycloak",
                "sub": token_data.sub,
                "email": token_data.email,
            },
            ip_address=ip_address,
        )

        session.commit()

        # Create redirect response with session cookie
        config = get_config()
        redirect_response = RedirectResponse(url="/", status_code=302)
        redirect_response.set_cookie(
            key=SESSION_COOKIE_NAME,
            value=session_token,
            httponly=True,
            samesite="strict",
            secure=config.cookie_secure,
            max_age=24 * 60 * 60,  # 24 hours
        )
        # Clear the state cookie on successful login
        redirect_response.delete_cookie(OIDC_STATE_COOKIE_NAME)

        return redirect_response

    except OIDCValidationError as e:
        return error_redirect(f"Token validation failed: {e}")
    except httpx.HTTPError:
        return error_redirect("Authentication service unavailable")
    except ValueError as e:
        # User creation failed (auto-create disabled)
        return error_redirect(str(e))
    except Exception:
        return error_redirect("Authentication failed")


# =============================================================================
# User management endpoints (admin only)
# =============================================================================

@router.get("/users", dependencies=[Depends(require_permission("user:read"))])
async def list_users(
    include_inactive: bool = False,
    session: Session = Depends(get_db_session),
):
    """List all users (admin only)."""
    user_repo = UserRepository(session)
    users = user_repo.list_all(include_inactive=include_inactive)

    return [
        {
            "id": u.id,
            "username": u.username,
            "email": u.email,
            "display_name": u.display_name,
            "is_active": u.is_active,
            "last_login": u.last_login.isoformat() if u.last_login else None,
            "roles": [r.name for r in u.roles],
            "created_at": u.created_at.isoformat() if u.created_at else None,
        }
        for u in users
    ]


@router.post("/users", dependencies=[Depends(require_permission("user:create"))])
async def create_user(
    user_create: UserCreate,
    request: Request,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Create a new user (admin only)."""
    auth_service = AuthService(session)
    ip_address = get_client_ip(request)

    user, error = auth_service.create_user(
        username=user_create.username,
        email=user_create.email,
        password=user_create.password,
        display_name=user_create.display_name,
        role_names=user_create.roles,
        must_change_password=True,
        admin_user_id=current_user.id,
        ip_address=ip_address,
    )

    if error:
        raise HTTPException(status_code=400, detail=error)

    session.commit()

    return {
        "id": user.id,
        "username": user.username,
        "message": "User created successfully",
    }


@router.get("/users/{user_id}", dependencies=[Depends(require_permission("user:read"))])
async def get_user(
    user_id: int,
    session: Session = Depends(get_db_session),
):
    """Get a user by ID (admin only)."""
    user_repo = UserRepository(session)
    user = user_repo.get_by_id(user_id)

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "display_name": user.display_name,
        "is_active": user.is_active,
        "must_change_password": user.must_change_password,
        "last_login": user.last_login.isoformat() if user.last_login else None,
        "roles": [r.name for r in user.roles],
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "updated_at": user.updated_at.isoformat() if user.updated_at else None,
    }


@router.put("/users/{user_id}", dependencies=[Depends(require_permission("user:update"))])
async def update_user(
    user_id: int,
    user_update: UserUpdate,
    request: Request,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Update a user (admin only)."""
    user_repo = UserRepository(session)
    audit_repo = AuditLogRepository(session)
    user = user_repo.get_by_id(user_id)

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Check for username/email conflicts
    if user_update.username and user_update.username != user.username:
        existing = user_repo.get_by_username(user_update.username)
        if existing:
            raise HTTPException(status_code=400, detail="Username already exists")

    if user_update.email and user_update.email != user.email:
        existing = user_repo.get_by_email(user_update.email)
        if existing:
            raise HTTPException(status_code=400, detail="Email already exists")

    user_repo.update(
        user=user,
        username=user_update.username,
        email=user_update.email,
        display_name=user_update.display_name,
        is_active=user_update.is_active,
    )

    audit_repo.create(
        user_id=current_user.id,
        action="user_updated",
        resource_type="user",
        resource_id=user.id,
        details={"changes": user_update.model_dump(exclude_none=True)},
        ip_address=get_client_ip(request),
    )

    session.commit()

    return {"id": user.id, "message": "User updated successfully"}


@router.delete("/users/{user_id}", dependencies=[Depends(require_permission("user:delete"))])
async def delete_user(
    user_id: int,
    request: Request,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Delete a user (admin only)."""
    if user_id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")

    user_repo = UserRepository(session)
    audit_repo = AuditLogRepository(session)
    user = user_repo.get_by_id(user_id)

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    username = user.username

    audit_repo.create(
        user_id=current_user.id,
        action="user_deleted",
        resource_type="user",
        resource_id=user_id,
        details={"username": username},
        ip_address=get_client_ip(request),
    )

    user_repo.delete(user)
    session.commit()

    return {"message": "User deleted successfully"}


@router.put("/users/{user_id}/roles", dependencies=[Depends(require_permission("user:update"))])
async def update_user_roles(
    user_id: int,
    roles_update: UserRolesUpdate,
    request: Request,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Update a user's roles (admin only)."""
    user_repo = UserRepository(session)
    user = user_repo.get_by_id(user_id)

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    auth_service = AuthService(session)
    auth_service.update_user_roles(
        user=user,
        role_names=roles_update.roles,
        admin_user_id=current_user.id,
        ip_address=get_client_ip(request),
    )

    session.commit()

    return {
        "id": user.id,
        "roles": [r.name for r in user.roles],
        "message": "User roles updated successfully",
    }


@router.post("/users/{user_id}/reset-password", dependencies=[Depends(require_permission("user:update"))])
async def reset_user_password(
    user_id: int,
    password_reset: PasswordReset,
    request: Request,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Reset a user's password (admin only)."""
    user_repo = UserRepository(session)
    user = user_repo.get_by_id(user_id)

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    auth_service = AuthService(session)
    auth_service.reset_password(
        user=user,
        new_password=password_reset.new_password,
        must_change=password_reset.must_change,
        admin_user_id=current_user.id,
        ip_address=get_client_ip(request),
    )

    session.commit()

    return {"message": "Password reset successfully"}


# =============================================================================
# Roles endpoint
# =============================================================================

@router.get("/roles")
async def list_roles(
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """List all roles."""
    role_repo = RoleRepository(session)
    roles = role_repo.list_all()

    return [
        {
            "id": r.id,
            "name": r.name,
            "description": r.description,
            "is_system": r.is_system,
            "permissions": [p.name for p in r.permissions],
        }
        for r in roles
    ]


# =============================================================================
# Audit log endpoint
# =============================================================================

@router.get("/audit-logs", dependencies=[Depends(require_permission("system:audit_view"))])
async def list_audit_logs(
    limit: int = 100,
    offset: int = 0,
    user_id: Optional[int] = None,
    action: Optional[str] = None,
    resource_type: Optional[str] = None,
    session: Session = Depends(get_db_session),
):
    """List audit logs (admin only)."""
    audit_repo = AuditLogRepository(session)
    logs = audit_repo.list_all(
        limit=limit,
        offset=offset,
        user_id=user_id,
        action=action,
        resource_type=resource_type,
    )

    return [
        {
            "id": log.id,
            "user_id": log.user_id,
            "username": log.user.username if log.user else None,
            "action": log.action,
            "resource_type": log.resource_type,
            "resource_id": log.resource_id,
            "details": json.loads(log.details) if log.details else None,
            "ip_address": log.ip_address,
            "timestamp": log.timestamp.isoformat() if log.timestamp else None,
        }
        for log in logs
    ]


# =============================================================================
# Collection endpoints (protected)
# =============================================================================

@router.get("/collections", dependencies=[Depends(require_permission("template:read"))])
async def list_collections(
    parent_id: Optional[int] = None,
    flat: bool = False,
    services: Services = Depends(get_services),
):
    """List all collections.

    Args:
        parent_id: Filter by parent folder (None for root folders)
        flat: If True, return flat list; if False, return hierarchical structure
    """
    collections = services.template.list_collections()

    def collection_to_dict(c):
        return {
            "id": c.id,
            "name": c.name,
            "description": c.description,
            "icon": c.icon,
            "parent_id": c.parent_id,
            "full_path": c.full_path,
            "template_count": len(c.templates),
            "document_count": len(c.documents) if hasattr(c, 'documents') else 0,
            "children": [collection_to_dict(child) for child in c.children] if not flat else None,
            "created_at": c.created_at.isoformat() if c.created_at else None,
            "updated_at": c.updated_at.isoformat() if c.updated_at else None,
        }

    if flat:
        return [collection_to_dict(c) for c in collections]
    else:
        # Return only root collections (parent_id is None), with nested children
        root_collections = [c for c in collections if c.parent_id is None]
        return [collection_to_dict(c) for c in root_collections]


@router.post("/collections", dependencies=[Depends(require_permission("template:create"))])
async def create_collection(
    collection: CollectionCreate,
    services: Services = Depends(get_services),
):
    """Create a new collection/folder."""
    try:
        c = services.template.create_collection(
            name=collection.name,
            description=collection.description,
            icon=collection.icon,
            parent_id=collection.parent_id,
        )
        services.session.commit()
        return {"id": c.id, "name": c.name, "parent_id": c.parent_id, "message": "Folder created successfully"}
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/collections/{collection_id}", dependencies=[Depends(require_permission("template:read"))])
async def get_collection(collection_id: int, services: Services = Depends(get_services)):
    """Get a collection by ID with its templates and documents."""
    from docforge.services.template_service import CollectionNotFoundError
    try:
        c = services.template.get_collection(collection_id)
        return {
            "id": c.id,
            "name": c.name,
            "description": c.description,
            "icon": c.icon,
            "parent_id": c.parent_id,
            "full_path": c.full_path,
            "templates": [
                {
                    "id": t.id,
                    "name": t.name,
                    "format": t.format,
                    "description": t.description,
                }
                for t in c.templates
            ],
            "documents": [
                {
                    "id": d.id,
                    "name": d.name,
                    "output_format": d.output_format,
                    "status": d.status,
                }
                for d in c.documents
            ] if hasattr(c, 'documents') else [],
            "children": [
                {"id": child.id, "name": child.name}
                for child in c.children
            ],
            "created_at": c.created_at.isoformat() if c.created_at else None,
            "updated_at": c.updated_at.isoformat() if c.updated_at else None,
        }
    except CollectionNotFoundError:
        raise HTTPException(status_code=404, detail="Collection not found")


@router.put("/collections/{collection_id}", dependencies=[Depends(require_permission("template:update"))])
async def update_collection(
    collection_id: int,
    collection: CollectionUpdate,
    services: Services = Depends(get_services),
):
    """Update a collection."""
    from docforge.services.template_service import CollectionNotFoundError
    try:
        c = services.template.update_collection(
            collection_id=collection_id,
            name=collection.name,
            description=collection.description,
            icon=collection.icon,
            parent_id=collection.parent_id,
        )
        services.session.commit()
        return {"id": c.id, "name": c.name, "message": "Collection updated successfully"}
    except CollectionNotFoundError:
        raise HTTPException(status_code=404, detail="Collection not found")
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/collections/{collection_id}", dependencies=[Depends(require_permission("template:delete"))])
async def delete_collection(collection_id: int, services: Services = Depends(get_services)):
    """Delete a collection (templates are unlinked, not deleted)."""
    from docforge.services.template_service import CollectionNotFoundError
    try:
        services.template.delete_collection(collection_id)
        services.session.commit()
        return {"message": "Collection deleted successfully"}
    except CollectionNotFoundError:
        raise HTTPException(status_code=404, detail="Collection not found")


@router.post("/collections/{collection_id}/templates/{template_id}", dependencies=[Depends(require_permission("template:update"))])
async def add_template_to_collection(
    collection_id: int,
    template_id: int,
    services: Services = Depends(get_services),
):
    """Add a template to a collection."""
    from docforge.services.template_service import CollectionNotFoundError
    try:
        services.template.add_template_to_collection(template_id, collection_id)
        services.session.commit()
        return {"message": "Template added to collection"}
    except CollectionNotFoundError:
        raise HTTPException(status_code=404, detail="Collection not found")
    except TemplateNotFoundError:
        raise HTTPException(status_code=404, detail="Template not found")


@router.delete("/templates/{template_id}/collection", dependencies=[Depends(require_permission("template:update"))])
async def remove_template_from_collection(
    template_id: int,
    services: Services = Depends(get_services),
):
    """Remove a template from its collection."""
    try:
        services.template.remove_template_from_collection(template_id)
        services.session.commit()
        return {"message": "Template removed from collection"}
    except TemplateNotFoundError:
        raise HTTPException(status_code=404, detail="Template not found")


@router.post("/collections/{collection_id}/documents/{document_id}", dependencies=[Depends(require_permission("document:update"))])
async def add_document_to_collection(
    collection_id: int,
    document_id: int,
    services: Services = Depends(get_services),
):
    """Add a document to a collection."""
    from docforge.services.template_service import CollectionNotFoundError
    try:
        collection = services.template.get_collection(collection_id)
        document = services.document_repo.get_by_id(document_id)
        if not document:
            raise HTTPException(status_code=404, detail="Document not found")

        services.template.collection_repo.add_document(collection, document)
        services.session.commit()
        return {"message": "Document added to collection"}
    except CollectionNotFoundError:
        raise HTTPException(status_code=404, detail="Collection not found")


@router.delete("/documents/{document_id}/collection", dependencies=[Depends(require_permission("document:update"))])
async def remove_document_from_collection(
    document_id: int,
    services: Services = Depends(get_services),
):
    """Remove a document from its collection."""
    document = services.document_repo.get_by_id(document_id)
    if not document:
        raise HTTPException(status_code=404, detail="Document not found")

    services.template.collection_repo.remove_document(document)
    services.session.commit()
    return {"message": "Document removed from collection"}


# =============================================================================
# Template endpoints (protected)
# =============================================================================
@router.get("/templates", dependencies=[Depends(require_permission("template:read"))])
async def list_templates(
    format: Optional[str] = None,
    tag: Optional[str] = None,
    search: Optional[str] = None,
    collection_id: Optional[int] = None,
    services: Services = Depends(get_services),
):
    """List all templates."""
    if search:
        templates = services.template.search_templates(search)
    else:
        tags = [tag] if tag else None
        templates = services.template.list_templates(
            format=format, tags=tags, collection_id=collection_id
        )

    return [
        {
            "id": t.id,
            "name": t.name,
            "format": t.format,
            "description": t.description,
            "current_version": t.current_version,
            "tags": [tag.name for tag in t.tags],
            "collection_id": t.collection_id,
            "collection_name": t.collection.name if t.collection else None,
            "created_at": t.created_at.isoformat() if t.created_at else None,
            "updated_at": t.updated_at.isoformat() if t.updated_at else None,
        }
        for t in templates
    ]


@router.post("/templates", dependencies=[Depends(require_permission("template:create"))])
async def create_template(template: TemplateCreate, services: Services = Depends(get_services)):
    """Create a new template."""
    try:
        t = services.template.create_template(
            name=template.name,
            content=template.content,
            format=template.format,
            description=template.description,
            tags=template.tags,
        )
        services.session.commit()
        return {"id": t.id, "name": t.name, "message": "Template created successfully"}
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/templates/{template_id}", dependencies=[Depends(require_permission("template:read"))])
async def get_template(template_id: int, services: Services = Depends(get_services)):
    """Get a template by ID."""
    try:
        t = services.template.get_template(template_id)
        return {
            "id": t.id,
            "name": t.name,
            "content": t.content,
            "format": t.format,
            "description": t.description,
            "current_version": t.current_version,
            "tags": [tag.name for tag in t.tags],
            "variables": [
                {
                    "name": v.name,
                    "var_type": v.var_type,
                    "required": v.required,
                    "default_value": v.default_value,
                    "description": v.description,
                }
                for v in t.variables
            ],
            "created_at": t.created_at.isoformat() if t.created_at else None,
            "updated_at": t.updated_at.isoformat() if t.updated_at else None,
        }
    except TemplateNotFoundError:
        raise HTTPException(status_code=404, detail="Template not found")


@router.put("/templates/{template_id}", dependencies=[Depends(require_permission("template:update"))])
async def update_template(template_id: int, template: TemplateUpdate, services: Services = Depends(get_services)):
    """Update a template."""
    try:
        t = services.template.update_template(
            template_id=template_id,
            name=template.name,
            content=template.content,
            format=template.format,
            description=template.description,
            version_message=template.message,
            version_author=template.author,
        )
        services.session.commit()
        return {"id": t.id, "name": t.name, "current_version": t.current_version}
    except TemplateNotFoundError:
        raise HTTPException(status_code=404, detail="Template not found")
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/templates/{template_id}", dependencies=[Depends(require_permission("template:delete"))])
async def delete_template(template_id: int, services: Services = Depends(get_services)):
    """Delete a template."""
    try:
        services.template.delete_template(template_id)
        services.session.commit()
        return {"message": "Template deleted successfully"}
    except TemplateNotFoundError:
        raise HTTPException(status_code=404, detail="Template not found")


@router.put("/templates/{template_id}/tags", dependencies=[Depends(require_permission("template:update"))])
async def update_tags(template_id: int, tags: TagUpdate, services: Services = Depends(get_services)):
    """Update template tags."""
    try:
        if tags.add:
            for tag_name in tags.add:
                services.template.add_tag(template_id, tag_name)
        if tags.remove:
            for tag_name in tags.remove:
                services.template.remove_tag(template_id, tag_name)
        services.session.commit()

        t = services.template.get_template(template_id)
        return {"tags": [tag.name for tag in t.tags]}
    except TemplateNotFoundError:
        raise HTTPException(status_code=404, detail="Template not found")


# Version endpoints
@router.get("/templates/{template_id}/versions", dependencies=[Depends(require_permission("template:read"))])
async def list_versions(template_id: int, checkpoints_only: bool = False, services: Services = Depends(get_services)):
    """List versions for a template."""
    try:
        versions = services.version.list_versions(template_id, checkpoints_only=checkpoints_only)
        return [
            {
                "id": v.id,
                "version_number": v.version_number,
                "is_checkpoint": v.is_checkpoint,
                "checkpoint_name": v.checkpoint_name,
                "message": v.message,
                "author": v.author,
                "created_at": v.created_at.isoformat() if v.created_at else None,
            }
            for v in versions
        ]
    except TemplateNotFoundError:
        raise HTTPException(status_code=404, detail="Template not found")


@router.get("/templates/{template_id}/versions/{version_number}", dependencies=[Depends(require_permission("template:read"))])
async def get_version(template_id: int, version_number: int, services: Services = Depends(get_services)):
    """Get a specific version."""
    try:
        v = services.version.get_version(template_id, version_number)
        return {
            "id": v.id,
            "version_number": v.version_number,
            "content": v.content,
            "diff": v.diff,
            "is_checkpoint": v.is_checkpoint,
            "checkpoint_name": v.checkpoint_name,
            "message": v.message,
            "author": v.author,
            "created_at": v.created_at.isoformat() if v.created_at else None,
        }
    except VersionNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/templates/{template_id}/checkpoint", dependencies=[Depends(require_permission("template:update"))])
async def create_checkpoint(template_id: int, checkpoint: CheckpointCreate, services: Services = Depends(get_services)):
    """Create a checkpoint."""
    try:
        v = services.version.create_checkpoint(template_id, checkpoint.name, checkpoint.message)
        services.session.commit()
        return {
            "version_number": v.version_number,
            "checkpoint_name": v.checkpoint_name,
            "message": "Checkpoint created successfully",
        }
    except TemplateNotFoundError:
        raise HTTPException(status_code=404, detail="Template not found")
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/templates/{template_id}/diff/{from_version}/{to_version}", dependencies=[Depends(require_permission("template:read"))])
async def diff_versions(template_id: int, from_version: int, to_version: int, services: Services = Depends(get_services)):
    """Get diff between two versions."""
    try:
        diff = services.version.diff_versions(template_id, from_version, to_version)
        return {"diff": diff}
    except (TemplateNotFoundError, VersionNotFoundError) as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/templates/{template_id}/rollback/{to_version}", dependencies=[Depends(require_permission("template:update"))])
async def rollback_version(template_id: int, to_version: int, message: Optional[str] = None, services: Services = Depends(get_services)):
    """Rollback to a previous version."""
    try:
        t = services.version.rollback(template_id, to_version, message)
        services.session.commit()
        return {"current_version": t.current_version, "message": "Rollback successful"}
    except (TemplateNotFoundError, VersionNotFoundError) as e:
        raise HTTPException(status_code=404, detail=str(e))


# Render endpoints
@router.post("/templates/{template_id}/preview", dependencies=[Depends(require_permission("template:read"))])
async def preview_template(template_id: int, render_request: RenderRequest, services: Services = Depends(get_services)):
    """Preview rendered template."""
    try:
        result = services.render.preview(template_id, data=render_request.data)
        return {"rendered": result}
    except TemplateNotFoundError:
        raise HTTPException(status_code=404, detail="Template not found")
    except RenderError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/templates/{template_id}/render", dependencies=[Depends(require_permission("document:create"))])
async def render_template(
    template_id: int,
    render_request: RenderRequest,
    document_name: Optional[str] = None,
    services: Services = Depends(get_services),
):
    """Render template and save document."""
    try:
        content, document = services.render.render(
            template_id,
            data=render_request.data,
            output_format=render_request.output_format,
            document_name=document_name,
        )
        services.session.commit()

        return {
            "rendered": content,
            "document_id": document.id if document else None,
        }
    except TemplateNotFoundError:
        raise HTTPException(status_code=404, detail="Template not found")
    except RenderError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/templates/{template_id}/validate", dependencies=[Depends(require_permission("template:read"))])
async def validate_template_data(
    template_id: int,
    validate_request: ValidateRequest,
    services: Services = Depends(get_services),
):
    """Validate input data against a template's variable schema.

    Returns validation result with any errors and warnings.
    """
    try:
        result = services.render.validate_data(template_id, validate_request.data)
        return {
            "is_valid": result.is_valid,
            "errors": [
                {
                    "field": e.field,
                    "message": e.message,
                    "error_type": e.error_type,
                }
                for e in result.errors
            ],
            "warnings": result.warnings,
        }
    except TemplateNotFoundError:
        raise HTTPException(status_code=404, detail="Template not found")


@router.post("/templates/{template_id}/batch-render", dependencies=[Depends(require_permission("document:create"))])
async def batch_render_template(
    template_id: int,
    batch_request: BatchRenderRequest,
    services: Services = Depends(get_services),
):
    """Render multiple documents from a list of data dictionaries.

    Each item in data_list will be rendered as a separate document.
    Returns a summary with success/failure counts and individual results.
    """
    try:
        summary = services.render.batch_render(
            template_id=template_id,
            data_list=batch_request.data_list,
            output_format=batch_request.output_format,
            document_name_field=batch_request.document_name_field,
            document_name_prefix=batch_request.document_name_prefix,
            save_documents=batch_request.save_documents,
            validate=batch_request.validate_data,
            stop_on_error=batch_request.stop_on_error,
        )
        services.session.commit()

        return {
            "total": summary.total,
            "successful": summary.successful,
            "failed": summary.failed,
            "results": [
                {
                    "index": r.index,
                    "success": r.success,
                    "document_id": r.document_id,
                    "document_name": r.document_name,
                    "error": r.error,
                    "validation_errors": [
                        {"field": e.field, "message": e.message}
                        for e in r.validation_errors
                    ] if r.validation_errors else None,
                }
                for r in summary.results
            ],
        }
    except TemplateNotFoundError:
        raise HTTPException(status_code=404, detail="Template not found")
    except RenderError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/templates/{template_id}/variables", dependencies=[Depends(require_permission("template:read"))])
async def get_template_variables(template_id: int, services: Services = Depends(get_services)):
    """Get variables used in a template."""
    try:
        t = services.template.get_template(template_id)

        from docforge.engine.renderer import TemplateRenderer
        renderer = TemplateRenderer()
        extracted = renderer.extract_variables(t.content)

        return {
            "extracted": list(extracted),
            "defined": [
                {
                    "name": v.name,
                    "var_type": v.var_type,
                    "required": v.required,
                    "default_value": v.default_value,
                }
                for v in t.variables
            ],
        }
    except TemplateNotFoundError:
        raise HTTPException(status_code=404, detail="Template not found")


# Document endpoints
@router.get("/documents", dependencies=[Depends(require_permission("document:read"))])
async def list_documents(
    template_id: Optional[int] = None,
    search: Optional[str] = None,
    services: Services = Depends(get_services),
):
    """List all documents with optional search."""
    documents = services.render.list_documents(template_id=template_id)

    # Filter by search query if provided
    if search:
        search_lower = search.lower()
        documents = [
            d for d in documents
            if search_lower in d.name.lower() or
               (d.rendered_content and search_lower in d.rendered_content.lower())
        ]

    return [
        {
            "id": d.id,
            "name": d.name,
            "output_format": d.output_format,
            "source_template_id": d.source_template_id,
            "source_template_version": d.source_template_version,
            "current_version": d.current_version,
            "status": d.status,
            "collection_id": d.collection_id,
            "collection_name": d.collection.name if d.collection else None,
            "created_at": d.created_at.isoformat() if d.created_at else None,
        }
        for d in documents
    ]


@router.get("/documents/search", dependencies=[Depends(require_permission("document:read"))])
async def search_documents(
    query: str,
    services: Services = Depends(get_services),
):
    """Search documents by name or content."""
    documents = services.render.list_documents()
    query_lower = query.lower()

    results = []
    for d in documents:
        score = 0
        matches = []

        # Check name match
        if query_lower in d.name.lower():
            score += 10
            matches.append("name")

        # Check content match
        if d.rendered_content and query_lower in d.rendered_content.lower():
            score += 5
            matches.append("content")

        if score > 0:
            results.append({
                "id": d.id,
                "name": d.name,
                "output_format": d.output_format,
                "source_template_id": d.source_template_id,
                "source_template_version": d.source_template_version,
                "created_at": d.created_at.isoformat() if d.created_at else None,
                "score": score,
                "matches": matches,
            })

    # Sort by score descending
    results.sort(key=lambda x: x["score"], reverse=True)
    return results


@router.get("/documents/{document_id}", dependencies=[Depends(require_permission("document:read"))])
async def get_document(document_id: int, services: Services = Depends(get_services)):
    """Get a document by ID."""
    document = services.render.get_document(document_id)
    if not document:
        raise HTTPException(status_code=404, detail="Document not found")

    return {
        "id": document.id,
        "name": document.name,
        "rendered_content": document.rendered_content,
        "output_format": document.output_format,
        "source_template_id": document.source_template_id,
        "source_template_version": document.source_template_version,
        "input_data": json.loads(document.input_data) if document.input_data else None,
        "current_version": document.current_version,
        "status": document.status,
        "created_at": document.created_at.isoformat() if document.created_at else None,
        "updated_at": document.updated_at.isoformat() if document.updated_at else None,
    }


@router.delete("/documents/{document_id}", dependencies=[Depends(require_permission("document:delete"))])
async def delete_document(document_id: int, services: Services = Depends(get_services)):
    """Delete a document."""
    document = services.render.get_document(document_id)
    if not document:
        raise HTTPException(status_code=404, detail="Document not found")

    services.render.delete_document(document_id)
    services.session.commit()
    return {"message": "Document deleted successfully"}


@router.put("/documents/{document_id}/amend", dependencies=[Depends(require_permission("document:update"))])
async def amend_document(
    document_id: int,
    amendment: DocumentAmendment,
    services: Services = Depends(get_services),
):
    """Create an amendment (new version) of a document."""
    document = services.document_repo.get_by_id(document_id)
    if not document:
        raise HTTPException(status_code=404, detail="Document not found")

    input_data_str = json.dumps(amendment.input_data) if amendment.input_data else None

    updated = services.document_repo.amend(
        document=document,
        rendered_content=amendment.rendered_content,
        input_data=input_data_str,
        amendment_reason=amendment.amendment_reason,
        amended_by=amendment.amended_by,
    )
    services.session.commit()

    return {
        "id": updated.id,
        "name": updated.name,
        "current_version": updated.current_version,
        "message": f"Document amended to version {updated.current_version}",
    }


@router.get("/documents/{document_id}/versions", dependencies=[Depends(require_permission("document:read"))])
async def list_document_versions(
    document_id: int,
    services: Services = Depends(get_services),
):
    """List all versions of a document."""
    document = services.document_repo.get_by_id(document_id)
    if not document:
        raise HTTPException(status_code=404, detail="Document not found")

    versions = services.document_repo.list_versions(document_id)

    return [
        {
            "id": v.id,
            "version_number": v.version_number,
            "amendment_reason": v.amendment_reason,
            "amended_by": v.amended_by,
            "created_at": v.created_at.isoformat() if v.created_at else None,
        }
        for v in versions
    ]


@router.get("/documents/{document_id}/versions/{version_number}", dependencies=[Depends(require_permission("document:read"))])
async def get_document_version(
    document_id: int,
    version_number: int,
    services: Services = Depends(get_services),
):
    """Get a specific version of a document."""
    version = services.document_repo.get_version(document_id, version_number)
    if not version:
        raise HTTPException(status_code=404, detail="Version not found")

    return {
        "id": version.id,
        "document_id": version.document_id,
        "version_number": version.version_number,
        "rendered_content": version.rendered_content,
        "input_data": json.loads(version.input_data) if version.input_data else None,
        "amendment_reason": version.amendment_reason,
        "amended_by": version.amended_by,
        "created_at": version.created_at.isoformat() if version.created_at else None,
    }


@router.post("/documents/{document_id}/archive", dependencies=[Depends(require_permission("document:update"))])
async def archive_document(
    document_id: int,
    services: Services = Depends(get_services),
):
    """Archive a document."""
    document = services.document_repo.get_by_id(document_id)
    if not document:
        raise HTTPException(status_code=404, detail="Document not found")

    services.document_repo.archive(document)
    services.session.commit()

    return {"message": "Document archived successfully"}


@router.post("/documents/{document_id}/restore", dependencies=[Depends(require_permission("document:update"))])
async def restore_document(
    document_id: int,
    services: Services = Depends(get_services),
):
    """Restore an archived document."""
    document = services.document_repo.get_by_id(document_id)
    if not document:
        raise HTTPException(status_code=404, detail="Document not found")

    services.document_repo.restore(document)
    services.session.commit()

    return {"message": "Document restored successfully"}


@router.post("/documents/{document_id}/revert/{version_number}", dependencies=[Depends(require_permission("document:update"))])
async def revert_document_to_version(
    document_id: int,
    version_number: int,
    amended_by: Optional[str] = None,
    services: Services = Depends(get_services),
):
    """Revert document to a previous version (creates new version with old content)."""
    document = services.document_repo.get_by_id(document_id)
    if not document:
        raise HTTPException(status_code=404, detail="Document not found")

    try:
        updated = services.document_repo.revert_to_version(
            document=document,
            version_number=version_number,
            amended_by=amended_by,
        )
        services.session.commit()

        return {
            "id": updated.id,
            "name": updated.name,
            "current_version": updated.current_version,
            "message": f"Document reverted to version {version_number}, now at version {updated.current_version}",
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


# Extract endpoints
@router.get("/extract/nlp-status")
async def get_nlp_status():
    """Check if NLP is available for enhanced extraction."""
    from docforge.extraction.nlp_service import get_nlp_service

    nlp_service = get_nlp_service()
    model_info = nlp_service.get_model_info()

    return {
        "nlp_available": model_info.get("available", False),
        "model_name": model_info.get("model_name"),
        "pipeline": model_info.get("pipeline", []),
        "entity_labels": model_info.get("entity_labels", []),
        "soc_patterns": model_info.get("soc_patterns", []),
        "soc_pattern_count": model_info.get("soc_pattern_count", 0),
        "spellcheck_available": model_info.get("spellcheck_available", False),
        "error": model_info.get("error"),
    }


class SpellCheckRequest(BaseModel):
    text: str
    ignore_patterns: Optional[List[str]] = None


class RewriteRequest(BaseModel):
    text: str
    style: str = "professional"


class ApplyRewriteRequest(BaseModel):
    text: str
    style: str = "professional"
    apply_all: bool = True
    selected_indices: Optional[List[int]] = None


@router.post("/extract/spell-check", dependencies=[Depends(require_permission("template:create"))])
async def spell_check_text(request: SpellCheckRequest):
    """Perform spell checking on text."""
    from docforge.extraction.nlp_service import get_nlp_service

    nlp = get_nlp_service()
    result = nlp.spell_check(request.text, request.ignore_patterns)

    return {
        "original": result.original,
        "corrected": result.corrected,
        "misspelled": result.misspelled,
        "suggestion_count": result.suggestion_count,
        "spellcheck_available": nlp.spellcheck_available,
    }


@router.post("/extract/rewrite-suggestions", dependencies=[Depends(require_permission("template:create"))])
async def get_rewrite_suggestions(request: RewriteRequest):
    """Get rewrite suggestions for text."""
    from docforge.extraction.nlp_service import get_nlp_service

    nlp = get_nlp_service()
    suggestions = nlp.suggest_rewrites(request.text, request.style)

    return {
        "suggestions": suggestions,
        "suggestion_count": len(suggestions),
        "style": request.style,
        "available_styles": ["professional", "concise", "formal", "technical"],
    }


@router.post("/extract/apply-rewrites", dependencies=[Depends(require_permission("template:create"))])
async def apply_rewrites(request: ApplyRewriteRequest):
    """Apply rewrite suggestions to text and return the rewritten version."""
    from docforge.extraction.nlp_service import get_nlp_service

    nlp = get_nlp_service()
    result = nlp.apply_rewrites(
        request.text,
        request.style,
        request.apply_all,
        request.selected_indices,
    )

    return result


@router.post("/extract/analyze", dependencies=[Depends(require_permission("template:create"))])
async def analyze_file(
    file: UploadFile = File(...),
    confidence: float = 0.5,
    use_nlp: bool = True,
):
    """Analyze a file for patterns using regex and optionally NLP.

    Args:
        file: The file to analyze.
        confidence: Minimum confidence threshold (0-1).
        use_nlp: Whether to use NLP-based entity recognition (requires spaCy).
    """
    content = await file.read()
    text = content.decode("utf-8", errors="ignore")

    generator = TemplateGenerator(use_nlp=use_nlp)
    matches, variables, stats = generator.analyze(text, confidence)

    return {
        "filename": file.filename,
        "patterns": [
            {
                "pattern_type": m.pattern_type,
                "value": m.value,
                "confidence": m.confidence,
                "suggested_name": m.suggested_name,
            }
            for m in matches
        ],
        "variables": [
            {
                "name": v.name,
                "var_type": v.var_type,
                "occurrences": v.occurrences,
                "confidence": v.confidence,
                "sample_values": v.sample_values,
            }
            for v in variables
        ],
        "stats": stats,
    }


@router.post("/extract/generate", dependencies=[Depends(require_permission("template:create"))])
async def generate_template_from_file(
    file: UploadFile = File(...),
    confidence: float = 0.7,
    use_nlp: bool = True,
    name: Optional[str] = None,
    save: bool = False,
    services: Services = Depends(get_services),
):
    """Generate a template from a file using regex and optionally NLP.

    Args:
        file: The file to generate a template from.
        confidence: Minimum confidence threshold (0-1).
        use_nlp: Whether to use NLP-based entity recognition.
        name: Optional name for saving the template.
        save: Whether to save the template to the database.
    """
    content = await file.read()
    text = content.decode("utf-8", errors="ignore")

    generator = TemplateGenerator(use_nlp=use_nlp)
    result = generator.generate(text, confidence)

    response = {
        "template_content": result.content,
        "variables": [
            {
                "name": v.name,
                "var_type": v.var_type,
                "occurrences": v.occurrences,
                "confidence": v.confidence,
            }
            for v in result.variables
        ],
        "replacements_made": result.replacements_made,
        "nlp_used": result.nlp_used,
        "detection_stats": result.detection_stats,
    }

    if save:
        template_name = name or (file.filename.rsplit(".", 1)[0] + "_template" if file.filename else "generated_template")

        try:
            t = services.template.create_template(
                name=template_name,
                content=result.content,
                format="markdown",
            )
            services.session.commit()
            response["saved_template_id"] = t.id
            response["saved_template_name"] = t.name
        except ValidationError as e:
            response["save_error"] = str(e)

    return response


# Stats endpoint
@router.get("/stats")
async def get_stats(
    current_user: User = Depends(get_current_user),
    services: Services = Depends(get_services),
):
    """Get system statistics."""
    templates = services.template.list_templates()
    documents = services.render.list_documents()
    tags = services.template.list_tags()

    return {
        "templates_count": len(templates),
        "documents_count": len(documents),
        "tags_count": len(tags),
        "tags": [t.name for t in tags],
    }


@router.get("/dashboard")
async def get_dashboard(
    current_user: User = Depends(get_current_user),
    services: Services = Depends(get_services),
):
    """Get comprehensive dashboard data including GitLab tasks."""
    # Basic stats
    templates = services.template.list_templates()
    documents = services.render.list_documents()
    tags = services.template.list_tags()

    # Recent documents (last 5)
    recent_docs = sorted(documents, key=lambda d: d.updated_at, reverse=True)[:5]

    # Recent templates (last 5)
    recent_templates = sorted(templates, key=lambda t: t.updated_at, reverse=True)[:5]

    # Fetch GitLab and Elasticsearch data in parallel with short timeouts
    async def fetch_gitlab_data():
        data = {
            "enabled": False,
            "connected": False,
            "open_issues": [],
            "assigned_to_me": [],
            "total_open": 0,
        }
        gitlab_config = get_gitlab_config()
        if gitlab_config.get("enabled") and gitlab_config.get("url") and gitlab_config.get("token"):
            data["enabled"] = True
            try:
                from docforge.services.gitlab_service import GitLabService
                gitlab = GitLabService()
                connection = await gitlab.test_connection()
                if connection.get("connected"):
                    data["connected"] = True
                    data["project_name"] = connection.get("project_name")
                    data["project_url"] = connection.get("web_url")
                    issues = await gitlab.list_issues(state="opened", per_page=10)
                    data["open_issues"] = [i.to_dict() for i in issues]
                    data["total_open"] = len(issues)
            except Exception as e:
                data["error"] = str(e)
        return data

    async def fetch_elasticsearch_data():
        data = {
            "enabled": False,
            "connected": False,
            "alerts": [],
            "total_alerts": 0,
            "critical_count": 0,
            "high_count": 0,
        }
        es_config = get_elasticsearch_config()
        if es_config.get("enabled") and es_config.get("url"):
            data["enabled"] = True
            try:
                from docforge.services.elasticsearch_service import ElasticsearchService
                es_service = ElasticsearchService()
                if es_service.is_configured:
                    connection = await es_service.test_connection()
                    if connection.get("connected"):
                        data["connected"] = True
                        data["cluster_name"] = connection.get("cluster_name")
                        alerts = await es_service.get_alerts(hours=24, limit=10)
                        data["alerts"] = [a.to_dict() for a in alerts]
                        data["total_alerts"] = len(alerts)
                        data["critical_count"] = sum(1 for a in alerts if a.severity == "critical")
                        data["high_count"] = sum(1 for a in alerts if a.severity == "high")
                    else:
                        data["error"] = connection.get("error", "Connection failed")
            except Exception as e:
                data["error"] = str(e)
        return data

    # Run both with 8 second timeouts so dashboard loads quickly
    async def safe_fetch(coro):
        try:
            return await asyncio.wait_for(coro, timeout=8.0)
        except asyncio.TimeoutError:
            return None

    gitlab_result, es_result = await asyncio.gather(
        safe_fetch(fetch_gitlab_data()),
        safe_fetch(fetch_elasticsearch_data()),
    )

    gitlab_data = gitlab_result or {
        "enabled": True, "connected": False, "open_issues": [],
        "assigned_to_me": [], "total_open": 0, "error": "Connection timed out",
    }
    elasticsearch_data = es_result or {
        "enabled": True, "connected": False, "alerts": [],
        "total_alerts": 0, "critical_count": 0, "high_count": 0,
        "error": "Connection timed out",
    }

    return {
        "user": {
            "id": current_user.id,
            "username": current_user.username,
            "display_name": current_user.display_name,
            "email": current_user.email,
            "roles": [r.name for r in current_user.roles],
        },
        "stats": {
            "templates_count": len(templates),
            "documents_count": len(documents),
            "tags_count": len(tags),
        },
        "recent_templates": [
            {
                "id": t.id,
                "name": t.name,
                "format": t.format.value if hasattr(t.format, 'value') else t.format,
                "updated_at": t.updated_at.isoformat() if t.updated_at else None,
                "tags": [tag.name for tag in t.tags],
            }
            for t in recent_templates
        ],
        "recent_documents": [
            {
                "id": d.id,
                "name": d.name,
                "template_name": d.source_template.name if d.source_template else "Unknown",
                "updated_at": d.updated_at.isoformat() if d.updated_at else None,
                "status": d.status,
            }
            for d in recent_docs
        ],
        "gitlab": gitlab_data,
        "elasticsearch": elasticsearch_data,
    }


# Sample templates endpoint
@router.post("/samples/create", dependencies=[Depends(require_permission("template:create"))])
async def create_sample_templates(services: Services = Depends(get_services)):
    """Create sample templates including cyber SOI."""
    created = []

    # Cyber SOI Template
    soi_template = {
        "name": "Cyber Security SOI",
        "format": "markdown",
        "description": "Standard Operating Instructions template for cyber security operations",
        "tags": ["cyber", "security", "soi", "operations"],
        "content": """# STANDARD OPERATING INSTRUCTIONS (SOI)
## {{ operation_name }}

**Classification:** {{ classification }}
**Effective Date:** {{ effective_date }}
**Version:** {{ version }}
**Prepared By:** {{ prepared_by }}
**Approved By:** {{ approved_by }}

---

## 1. PURPOSE

{{ purpose_description }}

---

## 2. SCOPE

{{ scope_description }}

---

## 3. REFERENCES

{{ references }}

---

## 4. DEFINITIONS

{{ definitions }}

---

## 5. RESPONSIBILITIES

### 5.1 Primary Personnel
{{ primary_responsibilities }}

### 5.2 Supporting Personnel
{{ supporting_responsibilities }}

---

## 6. PROCEDURES

### 6.1 Pre-Operation Checklist
{{ pre_operation_checklist }}

### 6.2 Operational Procedures
{{ operational_procedures }}

### 6.3 Post-Operation Procedures
{{ post_operation_procedures }}

---

## 7. TOOLS AND RESOURCES

{{ tools_and_resources }}

---

## 8. REPORTING REQUIREMENTS

{{ reporting_requirements }}

---

## 9. ESCALATION PROCEDURES

### 9.1 Incident Classification
{{ incident_classification }}

### 9.2 Escalation Matrix
{{ escalation_matrix }}

---

## 10. SECURITY CONSIDERATIONS

{{ security_considerations }}

---

## 11. APPENDICES

{{ appendices }}

---

**Document Control:**
- Last Updated: {{ last_updated }}
- Review Cycle: {{ review_cycle }}
- Distribution: {{ distribution_list }}
""",
    }

    # Check if SOI template already exists
    existing = services.template.search_templates("Cyber Security SOI")
    if not existing:
        try:
            t = services.template.create_template(**soi_template)
            services.session.commit()
            created.append({"id": t.id, "name": t.name})
        except Exception as e:
            pass

    # Incident Report Template
    incident_template = {
        "name": "Cyber Incident Report",
        "format": "markdown",
        "description": "Template for documenting cyber security incidents",
        "tags": ["cyber", "incident", "report", "security"],
        "content": """# CYBER INCIDENT REPORT

**Incident ID:** {{ incident_id }}
**Date/Time Detected:** {{ detection_datetime }}
**Reported By:** {{ reported_by }}
**Severity:** {{ severity }}

---

## INCIDENT SUMMARY

{{ incident_summary }}

---

## AFFECTED SYSTEMS

{{ affected_systems }}

---

## TIMELINE OF EVENTS

{{ timeline }}

---

## INDICATORS OF COMPROMISE (IOCs)

{{ iocs }}

---

## INITIAL RESPONSE ACTIONS

{{ initial_response }}

---

## ROOT CAUSE ANALYSIS

{{ root_cause }}

---

## IMPACT ASSESSMENT

### Business Impact
{{ business_impact }}

### Data Impact
{{ data_impact }}

---

## REMEDIATION STEPS

{{ remediation_steps }}

---

## LESSONS LEARNED

{{ lessons_learned }}

---

## RECOMMENDATIONS

{{ recommendations }}

---

**Report Completed By:** {{ completed_by }}
**Date:** {{ completion_date }}
**Status:** {{ status }}
""",
    }

    existing = services.template.search_templates("Cyber Incident Report")
    if not existing:
        try:
            t = services.template.create_template(**incident_template)
            services.session.commit()
            created.append({"id": t.id, "name": t.name})
        except Exception:
            pass

    # Vulnerability Assessment Template
    vuln_template = {
        "name": "Vulnerability Assessment Report",
        "format": "markdown",
        "description": "Template for vulnerability assessment findings",
        "tags": ["cyber", "vulnerability", "assessment", "security"],
        "content": """# VULNERABILITY ASSESSMENT REPORT

**Assessment ID:** {{ assessment_id }}
**Target System:** {{ target_system }}
**Assessment Date:** {{ assessment_date }}
**Assessor:** {{ assessor }}

---

## EXECUTIVE SUMMARY

{{ executive_summary }}

---

## SCOPE OF ASSESSMENT

{{ assessment_scope }}

---

## METHODOLOGY

{{ methodology }}

---

## FINDINGS SUMMARY

| Severity | Count |
|----------|-------|
| Critical | {{ critical_count }} |
| High     | {{ high_count }} |
| Medium   | {{ medium_count }} |
| Low      | {{ low_count }} |

---

## DETAILED FINDINGS

{{ detailed_findings }}

---

## RISK ANALYSIS

{{ risk_analysis }}

---

## REMEDIATION RECOMMENDATIONS

{{ remediation_recommendations }}

---

## APPENDIX: TECHNICAL DETAILS

{{ technical_details }}

---

**Assessment Completed:** {{ completion_date }}
**Next Scheduled Assessment:** {{ next_assessment }}
""",
    }

    existing = services.template.search_templates("Vulnerability Assessment Report")
    if not existing:
        try:
            t = services.template.create_template(**vuln_template)
            services.session.commit()
            created.append({"id": t.id, "name": t.name})
        except Exception:
            pass

    return {"created": created, "message": f"Created {len(created)} sample templates"}


# =============================================================================
# GitLab Integration Endpoints
# =============================================================================

from docforge.services.gitlab_service import (
    GitLabService,
    GitLabError,
    get_gitlab_service,
    reset_gitlab_service,
)


# Pydantic models for GitLab requests
class GitLabConfigUpdate(BaseModel):
    """Request to update GitLab configuration."""

    url: str
    token: str
    project_id: str


class GitLabIssueCreate(BaseModel):
    """Request to create a GitLab issue."""

    title: str
    description: Optional[str] = None
    labels: Optional[List[str]] = None
    assignee_ids: Optional[List[int]] = None
    milestone_id: Optional[int] = None
    due_date: Optional[str] = None


class GitLabIssueUpdate(BaseModel):
    """Request to update a GitLab issue."""

    title: Optional[str] = None
    description: Optional[str] = None
    labels: Optional[List[str]] = None
    state_event: Optional[str] = None  # "close" or "reopen"
    assignee_ids: Optional[List[int]] = None
    milestone_id: Optional[int] = None
    due_date: Optional[str] = None


class GitLabCommentCreate(BaseModel):
    """Request to add a comment to an issue."""

    body: str


class GitLabLabelCreate(BaseModel):
    """Request to create a label."""

    name: str
    color: str
    description: Optional[str] = None


@router.get("/gitlab/config")
async def get_gitlab_config_endpoint(
    current_user: User = Depends(require_permission("template:read")),
):
    """Get current GitLab configuration status."""
    config = get_gitlab_config()
    return {
        "enabled": config["enabled"],
        "url": config["url"],
        "project_id": config["project_id"],
        "has_token": bool(config["token"]),
    }


@router.post("/gitlab/config")
async def update_gitlab_config_endpoint(
    config_update: GitLabConfigUpdate,
    current_user: User = Depends(require_admin),
):
    """Update GitLab configuration (admin only).

    Note: This saves to the config file and resets the service.
    """
    from docforge.core.config import get_config, set_config
    import os

    # Get current config
    config = get_config()

    # Update GitLab settings
    config.gitlab_enabled = True
    config.gitlab_url = config_update.url
    config.gitlab_token = config_update.token
    config.gitlab_project_id = config_update.project_id

    # Save to config file
    data_dir = os.environ.get("DOCFORGE_DATA_DIR")
    if data_dir:
        config_path = Path(data_dir) / ".docforge" / "config.json"
    else:
        config_path = Path.cwd() / ".docforge" / "config.json"

    config.to_file(config_path)

    # Reset the service to pick up new config
    reset_gitlab_service()

    # Test connection
    service = get_gitlab_service()
    connection_result = await service.test_connection()
    await service.close()

    return {
        "success": True,
        "message": "GitLab configuration saved",
        "connection": connection_result,
    }


@router.delete("/gitlab/config")
async def disable_gitlab_config_endpoint(
    current_user: User = Depends(require_admin),
):
    """Disable GitLab integration (admin only)."""
    from docforge.core.config import get_config
    import os

    config = get_config()
    config.gitlab_enabled = False
    config.gitlab_url = ""
    config.gitlab_token = ""
    config.gitlab_project_id = ""

    data_dir = os.environ.get("DOCFORGE_DATA_DIR")
    if data_dir:
        config_path = Path(data_dir) / ".docforge" / "config.json"
    else:
        config_path = Path.cwd() / ".docforge" / "config.json"

    config.to_file(config_path)
    reset_gitlab_service()

    return {"success": True, "message": "GitLab integration disabled"}


@router.get("/gitlab/test")
async def test_gitlab_connection(
    current_user: User = Depends(require_permission("template:read")),
):
    """Test the GitLab connection."""
    service = get_gitlab_service()
    try:
        result = await service.test_connection()
        return result
    finally:
        await service.close()


@router.get("/gitlab/issues")
async def list_gitlab_issues(
    state: str = "all",
    labels: Optional[str] = None,
    search: Optional[str] = None,
    per_page: int = 20,
    page: int = 1,
    current_user: User = Depends(require_permission("template:read")),
):
    """List GitLab issues.

    Args:
        state: Filter by state ("opened", "closed", "all")
        labels: Comma-separated list of labels
        search: Search in title and description
        per_page: Number of issues per page
        page: Page number
    """
    service = get_gitlab_service()
    try:
        label_list = labels.split(",") if labels else None
        issues = await service.list_issues(
            state=state,
            labels=label_list,
            search=search,
            per_page=per_page,
            page=page,
        )
        return {"issues": [issue.to_dict() for issue in issues]}
    except GitLabError as e:
        raise HTTPException(status_code=e.status_code or 500, detail=str(e))
    finally:
        await service.close()


@router.get("/gitlab/issues/{issue_iid}")
async def get_gitlab_issue(
    issue_iid: int,
    current_user: User = Depends(require_permission("template:read")),
):
    """Get a specific GitLab issue."""
    service = get_gitlab_service()
    try:
        issue = await service.get_issue(issue_iid)
        return issue.to_dict()
    except GitLabError as e:
        raise HTTPException(status_code=e.status_code or 500, detail=str(e))
    finally:
        await service.close()


@router.post("/gitlab/issues")
async def create_gitlab_issue(
    issue_data: GitLabIssueCreate,
    current_user: User = Depends(require_permission("template:create")),
):
    """Create a new GitLab issue."""
    service = get_gitlab_service()
    try:
        issue = await service.create_issue(
            title=issue_data.title,
            description=issue_data.description,
            labels=issue_data.labels,
            assignee_ids=issue_data.assignee_ids,
            milestone_id=issue_data.milestone_id,
            due_date=issue_data.due_date,
        )
        return issue.to_dict()
    except GitLabError as e:
        raise HTTPException(status_code=e.status_code or 500, detail=str(e))
    finally:
        await service.close()


@router.put("/gitlab/issues/{issue_iid}")
async def update_gitlab_issue(
    issue_iid: int,
    issue_data: GitLabIssueUpdate,
    current_user: User = Depends(require_permission("template:update")),
):
    """Update a GitLab issue."""
    service = get_gitlab_service()
    try:
        issue = await service.update_issue(
            issue_iid=issue_iid,
            title=issue_data.title,
            description=issue_data.description,
            labels=issue_data.labels,
            state_event=issue_data.state_event,
            assignee_ids=issue_data.assignee_ids,
            milestone_id=issue_data.milestone_id,
            due_date=issue_data.due_date,
        )
        return issue.to_dict()
    except GitLabError as e:
        raise HTTPException(status_code=e.status_code or 500, detail=str(e))
    finally:
        await service.close()


@router.post("/gitlab/issues/{issue_iid}/close")
async def close_gitlab_issue(
    issue_iid: int,
    current_user: User = Depends(require_permission("template:update")),
):
    """Close a GitLab issue."""
    service = get_gitlab_service()
    try:
        issue = await service.close_issue(issue_iid)
        return issue.to_dict()
    except GitLabError as e:
        raise HTTPException(status_code=e.status_code or 500, detail=str(e))
    finally:
        await service.close()


@router.post("/gitlab/issues/{issue_iid}/reopen")
async def reopen_gitlab_issue(
    issue_iid: int,
    current_user: User = Depends(require_permission("template:update")),
):
    """Reopen a closed GitLab issue."""
    service = get_gitlab_service()
    try:
        issue = await service.reopen_issue(issue_iid)
        return issue.to_dict()
    except GitLabError as e:
        raise HTTPException(status_code=e.status_code or 500, detail=str(e))
    finally:
        await service.close()


@router.delete("/gitlab/issues/{issue_iid}")
async def delete_gitlab_issue(
    issue_iid: int,
    current_user: User = Depends(require_admin),
):
    """Delete a GitLab issue (admin only)."""
    service = get_gitlab_service()
    try:
        await service.delete_issue(issue_iid)
        return {"success": True, "message": f"Issue #{issue_iid} deleted"}
    except GitLabError as e:
        raise HTTPException(status_code=e.status_code or 500, detail=str(e))
    finally:
        await service.close()


@router.get("/gitlab/issues/{issue_iid}/comments")
async def list_gitlab_issue_comments(
    issue_iid: int,
    per_page: int = 20,
    page: int = 1,
    current_user: User = Depends(require_permission("template:read")),
):
    """List comments on a GitLab issue."""
    service = get_gitlab_service()
    try:
        comments = await service.list_issue_comments(
            issue_iid=issue_iid,
            per_page=per_page,
            page=page,
        )
        return {"comments": [comment.to_dict() for comment in comments]}
    except GitLabError as e:
        raise HTTPException(status_code=e.status_code or 500, detail=str(e))
    finally:
        await service.close()


@router.post("/gitlab/issues/{issue_iid}/comments")
async def add_gitlab_issue_comment(
    issue_iid: int,
    comment_data: GitLabCommentCreate,
    current_user: User = Depends(require_permission("template:create")),
):
    """Add a comment to a GitLab issue."""
    service = get_gitlab_service()
    try:
        comment = await service.add_issue_comment(
            issue_iid=issue_iid,
            body=comment_data.body,
        )
        return comment.to_dict()
    except GitLabError as e:
        raise HTTPException(status_code=e.status_code or 500, detail=str(e))
    finally:
        await service.close()


@router.get("/gitlab/labels")
async def list_gitlab_labels(
    current_user: User = Depends(require_permission("template:read")),
):
    """List all labels in the GitLab project."""
    service = get_gitlab_service()
    try:
        labels = await service.list_labels()
        return {"labels": labels}
    except GitLabError as e:
        raise HTTPException(status_code=e.status_code or 500, detail=str(e))
    finally:
        await service.close()


@router.post("/gitlab/labels")
async def create_gitlab_label(
    label_data: GitLabLabelCreate,
    current_user: User = Depends(require_permission("template:create")),
):
    """Create a new label in the GitLab project."""
    service = get_gitlab_service()
    try:
        label = await service.create_label(
            name=label_data.name,
            color=label_data.color,
            description=label_data.description,
        )
        return label
    except GitLabError as e:
        raise HTTPException(status_code=e.status_code or 500, detail=str(e))
    finally:
        await service.close()


@router.get("/gitlab/milestones")
async def list_gitlab_milestones(
    state: str = "active",
    current_user: User = Depends(require_permission("template:read")),
):
    """List milestones in the GitLab project."""
    service = get_gitlab_service()
    try:
        milestones = await service.list_milestones(state=state)
        return {"milestones": milestones}
    except GitLabError as e:
        raise HTTPException(status_code=e.status_code or 500, detail=str(e))
    finally:
        await service.close()


@router.get("/gitlab/members")
async def list_gitlab_members(
    current_user: User = Depends(require_permission("template:read")),
):
    """List project members for assignment."""
    service = get_gitlab_service()
    try:
        members = await service.list_members()
        return {"members": members}
    except GitLabError as e:
        raise HTTPException(status_code=e.status_code or 500, detail=str(e))
    finally:
        await service.close()


# ============================================================================
# Elasticsearch Alerts Endpoints
# ============================================================================

from docforge.services.elasticsearch_service import ElasticsearchService, ElasticsearchError
from docforge.core.config import get_elasticsearch_config


def get_elasticsearch_service() -> ElasticsearchService:
    """Get configured Elasticsearch service instance."""
    return ElasticsearchService()


@router.get("/elasticsearch/config")
async def get_es_config_status(
    current_user: User = Depends(get_current_user),
):
    """Get Elasticsearch configuration status (not sensitive data)."""
    config = get_elasticsearch_config()
    return {
        "enabled": config.get("enabled", False),
        "url": config.get("url", "")[:50] + "..." if len(config.get("url", "")) > 50 else config.get("url", ""),
        "has_credentials": bool(config.get("api_key") or (config.get("username") and config.get("password"))),
        "alert_index": config.get("alert_index", ""),
    }


@router.post("/elasticsearch/config", dependencies=[Depends(require_admin)])
async def update_es_config(
    request: Request,
    current_user: User = Depends(get_current_user),
):
    """Update Elasticsearch configuration (admin only)."""
    data = await request.json()

    config = get_config()
    config_path = Path.cwd() / ".docforge" / "config.json"

    # Update config fields
    if "enabled" in data:
        config.elasticsearch_enabled = data["enabled"]
    if "url" in data:
        config.elasticsearch_url = data["url"]
    if "api_key" in data:
        config.elasticsearch_api_key = data["api_key"]
    if "username" in data:
        config.elasticsearch_username = data["username"]
    if "password" in data:
        config.elasticsearch_password = data["password"]
    if "alert_index" in data:
        config.elasticsearch_alert_index = data["alert_index"]
    if "verify_ssl" in data:
        config.elasticsearch_verify_ssl = data["verify_ssl"]

    config.to_file(config_path)

    return {"message": "Elasticsearch configuration updated"}


@router.get("/elasticsearch/test")
async def test_es_connection(
    current_user: User = Depends(get_current_user),
):
    """Test Elasticsearch connection."""
    service = get_elasticsearch_service()
    result = await service.test_connection()
    return result


@router.get("/elasticsearch/alerts")
async def get_es_alerts(
    hours: int = 24,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 50,
    current_user: User = Depends(get_current_user),
):
    """Fetch alerts from Elasticsearch.

    Args:
        hours: Number of hours to look back (default 24)
        severity: Filter by severity (critical, high, medium, low, info)
        status: Filter by status (open, acknowledged, resolved)
        limit: Maximum number of alerts (default 50)
    """
    config = get_elasticsearch_config()
    if not config.get("enabled"):
        return {"alerts": [], "enabled": False, "message": "Elasticsearch integration is not enabled"}

    service = get_elasticsearch_service()
    if not service.is_configured:
        return {"alerts": [], "enabled": True, "configured": False, "message": "Elasticsearch is not configured"}

    try:
        alerts = await service.get_alerts(
            hours=hours,
            severity=severity,
            status=status,
            limit=limit,
        )
        return {
            "alerts": [a.to_dict() for a in alerts],
            "total": len(alerts),
            "hours": hours,
            "enabled": True,
            "configured": True,
        }
    except ElasticsearchError as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Alert Triage, Comments & Case Management Endpoints
# ============================================================================

from docforge.models.alert_triage import (
    AlertTriage,
    AlertTriageStatus,
    AlertComment,
    AlertCase,
    AlertCaseStatus,
)


class TriageUpdate(BaseModel):
    status: Optional[str] = None
    assigned_to_id: Optional[int] = None
    priority: Optional[str] = None
    case_id: Optional[int] = None


class CommentCreate(BaseModel):
    content: str


class CaseCreate(BaseModel):
    title: str
    description: Optional[str] = None
    severity: Optional[str] = None
    assigned_to_id: Optional[int] = None
    alert_ids: Optional[List[str]] = None


class CaseUpdate(BaseModel):
    title: Optional[str] = None
    status: Optional[str] = None
    assigned_to_id: Optional[int] = None
    description: Optional[str] = None
    severity: Optional[str] = None


@router.get("/elasticsearch/alerts/cases")
async def list_cases(
    status: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """List all investigation cases."""
    query = session.query(AlertCase)
    if status:
        query = query.filter(AlertCase.status == status)
    cases = query.order_by(AlertCase.created_at.desc()).all()
    return {
        "cases": [
            {
                "id": c.id,
                "case_number": c.case_number,
                "title": c.title,
                "description": c.description,
                "status": c.status.value if hasattr(c.status, "value") else c.status,
                "severity": c.severity,
                "created_by": c.created_by.username if c.created_by else None,
                "assigned_to": c.assigned_to.username if c.assigned_to else None,
                "assigned_to_id": c.assigned_to_id,
                "alert_count": len(c.triage_entries),
                "created_at": c.created_at.isoformat() if c.created_at else None,
                "updated_at": c.updated_at.isoformat() if c.updated_at else None,
            }
            for c in cases
        ]
    }


@router.post("/elasticsearch/alerts/cases")
async def create_case(
    data: CaseCreate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Create a new investigation case, optionally linking alert IDs."""
    # Generate next case number
    last_case = (
        session.query(AlertCase)
        .order_by(AlertCase.id.desc())
        .first()
    )
    next_num = 1 if not last_case else last_case.id + 1
    case_number = f"CASE-{next_num:04d}"

    new_case = AlertCase(
        case_number=case_number,
        title=data.title,
        description=data.description,
        status=AlertCaseStatus.OPEN,
        severity=data.severity,
        created_by_id=current_user.id,
        assigned_to_id=data.assigned_to_id,
    )
    session.add(new_case)
    session.flush()

    # Link alert IDs if provided
    linked = 0
    if data.alert_ids:
        for alert_id in data.alert_ids:
            triage = session.query(AlertTriage).filter_by(es_alert_id=alert_id).first()
            if not triage:
                triage = AlertTriage(
                    es_alert_id=alert_id,
                    status=AlertTriageStatus.INVESTIGATING,
                )
                session.add(triage)
                session.flush()
            triage.case_id = new_case.id
            linked += 1

    session.commit()
    return {
        "id": new_case.id,
        "case_number": new_case.case_number,
        "title": new_case.title,
        "status": new_case.status.value if hasattr(new_case.status, "value") else new_case.status,
        "linked_alerts": linked,
    }


@router.get("/elasticsearch/alerts/cases/{case_id}")
async def get_case_detail(
    case_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Get case detail with linked alerts."""
    case = session.query(AlertCase).filter_by(id=case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    return {
        "id": case.id,
        "case_number": case.case_number,
        "title": case.title,
        "description": case.description,
        "status": case.status.value if hasattr(case.status, "value") else case.status,
        "severity": case.severity,
        "created_by": case.created_by.username if case.created_by else None,
        "assigned_to": case.assigned_to.username if case.assigned_to else None,
        "assigned_to_id": case.assigned_to_id,
        "created_at": case.created_at.isoformat() if case.created_at else None,
        "updated_at": case.updated_at.isoformat() if case.updated_at else None,
        "alerts": [
            {
                "es_alert_id": t.es_alert_id,
                "status": t.status.value if hasattr(t.status, "value") else t.status,
                "priority": t.priority,
            }
            for t in case.triage_entries
        ],
    }


@router.patch("/elasticsearch/alerts/cases/{case_id}")
async def update_case(
    case_id: int,
    data: CaseUpdate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Update case status, assignee, title, etc."""
    case = session.query(AlertCase).filter_by(id=case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    if data.title is not None:
        case.title = data.title
    if data.description is not None:
        case.description = data.description
    if data.severity is not None:
        case.severity = data.severity
    if data.status is not None:
        case.status = data.status
    if data.assigned_to_id is not None:
        case.assigned_to_id = data.assigned_to_id

    session.commit()
    return {
        "id": case.id,
        "case_number": case.case_number,
        "title": case.title,
        "status": case.status.value if hasattr(case.status, "value") else case.status,
        "message": "Case updated",
    }


@router.get("/elasticsearch/alerts/{alert_id}/triage")
async def get_alert_triage(
    alert_id: str,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Get triage state and comments for an alert."""
    triage = session.query(AlertTriage).filter_by(es_alert_id=alert_id).first()
    comments = (
        session.query(AlertComment)
        .filter_by(es_alert_id=alert_id)
        .order_by(AlertComment.created_at.asc())
        .all()
    )

    triage_data = None
    if triage:
        triage_data = {
            "id": triage.id,
            "es_alert_id": triage.es_alert_id,
            "status": triage.status.value if hasattr(triage.status, "value") else triage.status,
            "assigned_to_id": triage.assigned_to_id,
            "assigned_to": triage.assigned_to.username if triage.assigned_to else None,
            "case_id": triage.case_id,
            "case_number": triage.case.case_number if triage.case else None,
            "priority": triage.priority,
        }

    return {
        "triage": triage_data,
        "comments": [
            {
                "id": c.id,
                "user": c.user.username if c.user else "Unknown",
                "content": c.content,
                "created_at": c.created_at.isoformat() if c.created_at else None,
            }
            for c in comments
        ],
    }


@router.put("/elasticsearch/alerts/{alert_id}/triage")
async def update_alert_triage(
    alert_id: str,
    data: TriageUpdate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Update triage status, assignee, priority for an alert."""
    triage = session.query(AlertTriage).filter_by(es_alert_id=alert_id).first()
    if not triage:
        triage = AlertTriage(es_alert_id=alert_id)
        session.add(triage)
        session.flush()

    if data.status is not None:
        triage.status = data.status
    if data.assigned_to_id is not None:
        triage.assigned_to_id = data.assigned_to_id
    if data.priority is not None:
        triage.priority = data.priority
    if data.case_id is not None:
        triage.case_id = data.case_id

    session.commit()
    return {
        "id": triage.id,
        "es_alert_id": triage.es_alert_id,
        "status": triage.status.value if hasattr(triage.status, "value") else triage.status,
        "priority": triage.priority,
        "assigned_to_id": triage.assigned_to_id,
        "case_id": triage.case_id,
        "message": "Triage updated",
    }


@router.post("/elasticsearch/alerts/{alert_id}/comments")
async def add_alert_comment(
    alert_id: str,
    data: CommentCreate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Add a comment to an alert."""
    comment = AlertComment(
        es_alert_id=alert_id,
        user_id=current_user.id,
        content=data.content,
    )
    session.add(comment)
    session.commit()
    return {
        "id": comment.id,
        "es_alert_id": comment.es_alert_id,
        "user": current_user.username,
        "content": comment.content,
        "created_at": comment.created_at.isoformat() if comment.created_at else None,
    }


@router.get("/elasticsearch/alerts/{alert_id}/related")
async def get_es_related_alerts(
    alert_id: str,
    host: Optional[str] = None,
    user: Optional[str] = None,
    rule_name: Optional[str] = None,
    hours: int = 72,
    current_user: User = Depends(get_current_user),
):
    """Get alerts related to a specific alert by host, user, or rule."""
    config = get_elasticsearch_config()
    if not config.get("enabled"):
        raise HTTPException(status_code=400, detail="Elasticsearch not enabled")

    service = get_elasticsearch_service()
    if not service.is_configured:
        raise HTTPException(status_code=400, detail="Elasticsearch not configured")

    try:
        related = await service.get_related_alerts(
            alert_id=alert_id,
            host=host,
            user=user,
            rule_name=rule_name,
            hours=hours,
        )
        return {
            "alert_id": alert_id,
            "related": {
                key: [a.to_dict() for a in alerts]
                for key, alerts in related.items()
            },
        }
    except ElasticsearchError as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/elasticsearch/alerts/stats")
async def get_es_alert_stats(
    hours: int = 24,
    current_user: User = Depends(get_current_user),
):
    """Get alert statistics from Elasticsearch."""
    config = get_elasticsearch_config()
    if not config.get("enabled"):
        return {"enabled": False}

    service = get_elasticsearch_service()
    if not service.is_configured:
        return {"enabled": True, "configured": False}

    try:
        stats = await service.get_alert_stats(hours=hours)
        return {
            "enabled": True,
            "configured": True,
            **stats,
        }
    except ElasticsearchError as e:
        raise HTTPException(status_code=500, detail=str(e))
