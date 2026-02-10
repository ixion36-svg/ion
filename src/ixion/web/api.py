"""API routes for IXION web interface."""

import asyncio
import json
import logging
import re
import secrets
from datetime import datetime, timezone, timedelta
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

from ixion.core.config import get_config, get_oidc_config, get_gitlab_config, get_kibana_config
from ixion.services.kibana_cases_service import get_kibana_cases_service

# Rate limiter - uses IP address as key
limiter = Limiter(key_func=get_remote_address)

# OIDC state cookie name for CSRF protection
OIDC_STATE_COOKIE_NAME = "oidc_state"
from ixion.core.exceptions import (
    TemplateNotFoundError,
    VersionNotFoundError,
    ValidationError,
    RenderError,
)
from ixion.storage.database import get_session_factory, get_engine
from ixion.services.template_service import TemplateService
from ixion.services.version_service import VersionService
from ixion.services.render_service import RenderService
from ixion.extraction.template_generator import TemplateGenerator
from ixion.storage.document_repository import DocumentRepository
from ixion.models.user import User
from ixion.auth.service import AuthService
from ixion.auth.dependencies import (
    get_current_user,
    get_current_user_optional,
    require_permission,
    require_admin,
    get_client_ip,
    get_auth_service,
    SESSION_COOKIE_NAME,
)
from ixion.storage.auth_repository import AuditLogRepository
from ixion.storage.user_repository import UserRepository, RoleRepository

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
    # Auto-detect HTTPS from request or use configured value
    config = get_config()
    is_https = (
        request.url.scheme == "https" or
        request.headers.get("X-Forwarded-Proto") == "https"
    )
    cookie_secure = config.cookie_secure or is_https

    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session_token,
        httponly=True,
        samesite="strict",
        secure=cookie_secure,
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
    from ixion.auth.dependencies import get_session_token
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
    validates the access token, syncs the user to IXION,
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
        from ixion.auth.oidc import OIDCValidator, OIDCUserSync, OIDCValidationError
        from ixion.storage.auth_repository import AuditLogRepository

        validator = OIDCValidator(oidc_config)
        token_data = await validator.validate_token_async(tokens["access_token"])

        # Sync user to IXION database
        sync = OIDCUserSync(session, oidc_config)
        user = sync.sync_user(token_data)
        session.commit()

        # Create a IXION session for the user
        ip_address = get_client_ip(request)
        user_agent = request.headers.get("User-Agent")

        # Create session token with session rotation
        from ixion.storage.auth_repository import SessionRepository
        import secrets
        from datetime import datetime, timedelta

        session_repo = SessionRepository(session)
        audit_repo = AuditLogRepository(session)

        # Session rotation: invalidate all existing sessions for this user
        old_session_count = session_repo.delete_all_for_user(user.id)
        if old_session_count > 0:
            audit_repo.create(
                user_id=user.id,
                action="session_rotation",
                resource_type="user",
                resource_id=user.id,
                details={"old_sessions_invalidated": old_session_count, "source": "oidc"},
                ip_address=ip_address,
            )

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
        # Auto-detect HTTPS from request or use configured value
        config = get_config()
        is_https = (
            request.url.scheme == "https" or
            request.headers.get("X-Forwarded-Proto") == "https"
        )
        cookie_secure = config.cookie_secure or is_https

        redirect_response = RedirectResponse(url="/", status_code=302)
        redirect_response.set_cookie(
            key=SESSION_COOKIE_NAME,
            value=session_token,
            httponly=True,
            samesite="strict",
            secure=cookie_secure,
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
    from ixion.services.template_service import CollectionNotFoundError
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
    from ixion.services.template_service import CollectionNotFoundError
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
    from ixion.services.template_service import CollectionNotFoundError
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
    from ixion.services.template_service import CollectionNotFoundError
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
    from ixion.services.template_service import CollectionNotFoundError
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

        from ixion.engine.renderer import TemplateRenderer
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
    """Check if AI document analysis is available."""
    from ixion.services.ai_document_service import get_ai_document_service

    service = get_ai_document_service()
    info = service.get_service_info()
    ai_available = await service.is_ai_available()

    return {
        "nlp_available": ai_available,  # Kept for backward compatibility
        "ai_available": ai_available,
        "model_name": info.get("backend", "ollama"),
        "features": info.get("features", []),
        "soc_patterns": info.get("soc_patterns", []),
        "soc_pattern_count": info.get("soc_pattern_count", 0),
        "spellcheck_available": ai_available,
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
    """Perform spell checking on text using AI."""
    from ixion.services.ai_document_service import get_ai_document_service

    service = get_ai_document_service()
    result = await service.spell_check(request.text)

    return {
        "original": result.original,
        "corrected": result.corrected,
        "misspelled": result.misspelled,
        "suggestion_count": result.suggestion_count,
        "spellcheck_available": await service.is_ai_available(),
    }


@router.post("/extract/rewrite-suggestions", dependencies=[Depends(require_permission("template:create"))])
async def get_rewrite_suggestions(request: RewriteRequest):
    """Get rewrite suggestions for text using AI."""
    from ixion.services.ai_document_service import get_ai_document_service

    service = get_ai_document_service()
    suggestions = await service.suggest_rewrites(request.text, request.style)

    return {
        "suggestions": suggestions,
        "suggestion_count": len(suggestions),
        "style": request.style,
        "available_styles": ["professional", "concise", "formal", "technical"],
    }


@router.post("/extract/apply-rewrites", dependencies=[Depends(require_permission("template:create"))])
async def apply_rewrites(request: ApplyRewriteRequest):
    """Apply rewrite suggestions to text using AI."""
    from ixion.services.ai_document_service import get_ai_document_service

    service = get_ai_document_service()
    result = await service.apply_rewrites(request.text, request.style)

    return {
        "original": result.original,
        "rewritten": result.rewritten,
        "changes_applied": result.changes_applied,
        "changes": result.changes,
        "style": result.style,
    }


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
                from ixion.services.gitlab_service import GitLabService
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
                from ixion.services.elasticsearch_service import ElasticsearchService
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

from ixion.services.gitlab_service import (
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
    from ixion.core.config import get_config, set_config
    import os

    # Get current config
    config = get_config()

    # Update GitLab settings
    config.gitlab_enabled = True
    config.gitlab_url = config_update.url
    config.gitlab_token = config_update.token
    config.gitlab_project_id = config_update.project_id

    # Save to config file
    data_dir = os.environ.get("IXION_DATA_DIR")
    if data_dir:
        config_path = Path(data_dir) / ".ixion" / "config.json"
    else:
        config_path = Path.cwd() / ".ixion" / "config.json"

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
    from ixion.core.config import get_config
    import os

    config = get_config()
    config.gitlab_enabled = False
    config.gitlab_url = ""
    config.gitlab_token = ""
    config.gitlab_project_id = ""

    data_dir = os.environ.get("IXION_DATA_DIR")
    if data_dir:
        config_path = Path(data_dir) / ".ixion" / "config.json"
    else:
        config_path = Path.cwd() / ".ixion" / "config.json"

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
    current_user: User = Depends(require_permission("template:delete")),
):
    """Delete a GitLab issue."""
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

from ixion.services.elasticsearch_service import ElasticsearchService, ElasticsearchError
from ixion.core.config import get_elasticsearch_config


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
    config_path = Path.cwd() / ".ixion" / "config.json"

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


@router.get("/elasticsearch/alerts/mitre-stats")
async def get_mitre_stats(
    hours: int = 24,
    current_user: User = Depends(get_current_user),
):
    """Get MITRE ATT&CK technique/tactic statistics from alerts.

    Args:
        hours: Number of hours to look back (default 24)

    Returns:
        Dict with technique counts, tactic counts, and total alerts with MITRE data.
    """
    config = get_elasticsearch_config()
    if not config.get("enabled"):
        return {"techniques": {}, "tactics": {}, "total_alerts_with_mitre": 0, "time_range_hours": hours}

    service = get_elasticsearch_service()
    if not service.is_configured:
        return {"techniques": {}, "tactics": {}, "total_alerts_with_mitre": 0, "time_range_hours": hours}

    try:
        # Fetch alerts and aggregate MITRE data
        alerts = await service.get_alerts(hours=hours, limit=1000)

        techniques = {}
        tactics = {}
        total_with_mitre = 0

        for alert in alerts:
            if alert.mitre_technique_id:
                total_with_mitre += 1
                tech_id = alert.mitre_technique_id
                if tech_id not in techniques:
                    techniques[tech_id] = {
                        "name": alert.mitre_technique_name or "",
                        "tactic": alert.mitre_tactic_name or "",
                        "count": 0,
                    }
                techniques[tech_id]["count"] += 1

                if alert.mitre_tactic_name:
                    tactic = alert.mitre_tactic_name
                    tactics[tactic] = tactics.get(tactic, 0) + 1

        return {
            "techniques": techniques,
            "tactics": tactics,
            "total_alerts_with_mitre": total_with_mitre,
            "time_range_hours": hours,
        }
    except ElasticsearchError as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Alert Triage, Comments & Case Management Endpoints
# ============================================================================

from ixion.models.alert_triage import (
    AlertTriage,
    AlertTriageStatus,
    AlertCase,
    AlertCaseStatus,
    Note,
    NoteEntityType,
)


OBSERVABLE_TYPES = {"hostname", "source_ip", "destination_ip", "url", "domain", "user_account"}


class TriageUpdate(BaseModel):
    status: Optional[str] = None
    assigned_to_id: Optional[int] = None
    priority: Optional[str] = None
    case_id: Optional[int] = None
    analyst_notes: Optional[str] = None
    observables: Optional[List[dict]] = None
    mitre_techniques: Optional[List[dict]] = None


class BulkTriageUpdate(BaseModel):
    """Bulk update multiple alerts at once."""
    alert_ids: List[str]
    status: Optional[str] = None
    assigned_to_id: Optional[int] = None
    priority: Optional[str] = None
    case_id: Optional[int] = None
    add_to_new_case: Optional[bool] = False
    new_case_title: Optional[str] = None
    new_case_severity: Optional[str] = None


class AutoPopulateRequest(BaseModel):
    host: Optional[str] = None
    user: Optional[str] = None
    raw_data: Optional[dict] = None


class AlertContext(BaseModel):
    alert_id: str
    host: Optional[str] = None
    user: Optional[str] = None
    raw_data: Optional[dict] = None


class CommentCreate(BaseModel):
    content: str


class CaseNoteCreate(BaseModel):
    content: str


class CaseCreate(BaseModel):
    title: str
    description: Optional[str] = None
    severity: Optional[str] = None
    assigned_to_id: Optional[int] = None
    alert_ids: Optional[List[str]] = None
    affected_hosts: Optional[List[str]] = None
    affected_users: Optional[List[str]] = None
    triggered_rules: Optional[List[str]] = None
    evidence_summary: Optional[str] = None
    alert_contexts: Optional[List["AlertContext"]] = None


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

    # Get Kibana service for URL generation
    kibana_service = get_kibana_cases_service()
    kibana_enabled = kibana_service.enabled

    def get_kibana_url(case):
        if kibana_enabled and case.kibana_case_id:
            return kibana_service.get_case_url(case.kibana_case_id)
        return None

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
                "affected_hosts": c.affected_hosts,
                "affected_users": c.affected_users,
                "triggered_rules": c.triggered_rules,
                "evidence_summary": c.evidence_summary,
                "source_alert_ids": c.source_alert_ids,
                "observables_count": len(c.observables) if c.observables else 0,
                "kibana_case_id": c.kibana_case_id,
                "kibana_url": get_kibana_url(c),
                "created_at": c.created_at.isoformat() if c.created_at else None,
                "updated_at": c.updated_at.isoformat() if c.updated_at else None,
            }
            for c in cases
        ]
    }


_case_es_logger = logging.getLogger(__name__)


def _build_case_es_doc(case, session) -> dict:
    """Build the full Elasticsearch document from an AlertCase ORM object."""
    now = datetime.now(timezone.utc).isoformat()
    return {
        "id": case.id,
        "@timestamp": now,
        "case_number": case.case_number,
        "title": case.title,
        "description": case.description,
        "status": case.status.value if hasattr(case.status, "value") else case.status,
        "severity": case.severity,
        "created_by": case.created_by.username if case.created_by else None,
        "assigned_to": case.assigned_to.username if case.assigned_to else None,
        "affected_hosts": case.affected_hosts or [],
        "affected_users": case.affected_users or [],
        "triggered_rules": case.triggered_rules or [],
        "evidence_summary": case.evidence_summary,
        "source_alert_ids": case.source_alert_ids or [],
        "alert_count": len(case.source_alert_ids) if case.source_alert_ids else 0,
        "notes": [
            {
                "user": n.user.username if n.user else "Unknown",
                "content": n.content,
                "created_at": n.created_at.isoformat() if n.created_at else None,
            }
            for n in case.notes
        ],
        "created_at": case.created_at.isoformat() if case.created_at else None,
        "updated_at": case.updated_at.isoformat() if case.updated_at else None,
    }


async def _sync_case_to_es(case, session):
    """Sync a case to Elasticsearch. Logs warnings on failure, never raises."""
    try:
        es_config = get_elasticsearch_config()
        if not es_config.get("enabled"):
            return
        es_service = get_elasticsearch_service()
        if not es_service.is_configured:
            return
        doc = _build_case_es_doc(case, session)
        await es_service.index_case(doc)
    except Exception as e:
        _case_es_logger.warning("Failed to sync case %s to ES: %s", getattr(case, "id", "?"), e)


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
        affected_hosts=data.affected_hosts,
        affected_users=data.affected_users,
        triggered_rules=data.triggered_rules,
        evidence_summary=data.evidence_summary,
        source_alert_ids=data.alert_ids,
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

    # Auto-populate observables for linked alerts if context provided
    # and aggregate all observables for the case
    case_observables = []
    seen_observables = set()

    if data.alert_contexts:
        context_map = {ctx.alert_id: ctx for ctx in data.alert_contexts}
        for alert_id in (data.alert_ids or []):
            ctx = context_map.get(alert_id)
            if not ctx:
                continue
            triage = session.query(AlertTriage).filter_by(es_alert_id=alert_id).first()
            if triage:
                _populate_triage_observables(triage, ctx.host, ctx.user, ctx.raw_data)

            # Extract observables from raw_data for case-level aggregation
            if ctx.raw_data:
                for obs in _extract_observables_from_raw(ctx.raw_data):
                    key = (obs["type"], obs["value"])
                    if key not in seen_observables:
                        seen_observables.add(key)
                        case_observables.append(obs)

    # Store aggregated observables on the case
    if case_observables:
        new_case.observables = case_observables

    session.commit()
    session.refresh(new_case)
    await _sync_case_to_es(new_case, session)

    # Sync to Kibana Cases if enabled
    kibana_url = None
    try:
        kibana_service = get_kibana_cases_service()
        if kibana_service.enabled:
            # Build description with case context
            kibana_desc = data.description or ""
            if data.affected_hosts:
                kibana_desc += f"\n\n**Affected Hosts:** {', '.join(data.affected_hosts)}"
            if data.affected_users:
                kibana_desc += f"\n\n**Affected Users:** {', '.join(data.affected_users)}"
            if data.evidence_summary:
                kibana_desc += f"\n\n**Evidence Summary:**\n{data.evidence_summary}"

            # Add observables to description
            if case_observables:
                kibana_desc += "\n\n**Observables:**\n"
                # Group observables by type for cleaner display
                obs_by_type = {}
                for obs in case_observables:
                    obs_type = obs["type"]
                    if obs_type not in obs_by_type:
                        obs_by_type[obs_type] = []
                    obs_by_type[obs_type].append(obs["value"])
                for obs_type, values in sorted(obs_by_type.items()):
                    kibana_desc += f"- **{obs_type}:** {', '.join(values[:5])}"
                    if len(values) > 5:
                        kibana_desc += f" (+{len(values) - 5} more)"
                    kibana_desc += "\n"

            # Add linked alert IDs to description for reference
            if data.alert_ids:
                kibana_desc += f"\n**Linked Alert IDs ({len(data.alert_ids)}):**\n"
                kibana_desc += "\n".join(f"- `{aid}`" for aid in data.alert_ids[:10])
                if len(data.alert_ids) > 10:
                    kibana_desc += f"\n- ... and {len(data.alert_ids) - 10} more"

            kibana_case = kibana_service.create_case(
                title=f"[{case_number}] {data.title}",
                description=kibana_desc.strip(),
                severity=data.severity or "low",
                tags=[case_number, "ixion"],
            )
            if kibana_case:
                new_case.kibana_case_id = kibana_case.get("id")
                new_case.kibana_case_version = kibana_case.get("version")
                session.commit()
                kibana_url = kibana_service.get_case_url(new_case.kibana_case_id)

                # Attach alerts to Kibana case if using securitySolution owner
                if data.alert_ids and kibana_service.config.get("case_owner") == "securitySolution":
                    try:
                        kibana_service.attach_alerts_to_case(
                            case_id=new_case.kibana_case_id,
                            alert_ids=data.alert_ids,
                            alert_index=".alerts-security.alerts-default",
                        )
                    except Exception as attach_err:
                        _case_es_logger.warning("Failed to attach alerts to Kibana case: %s", attach_err)
    except Exception as e:
        _case_es_logger.warning("Failed to sync case to Kibana: %s", e)

    return {
        "id": new_case.id,
        "case_number": new_case.case_number,
        "title": new_case.title,
        "status": new_case.status.value if hasattr(new_case.status, "value") else new_case.status,
        "linked_alerts": linked,
        "observables": new_case.observables or [],
        "kibana_case_id": new_case.kibana_case_id,
        "kibana_url": kibana_url,
    }


@router.post("/elasticsearch/alerts/cases/{case_id}/notes")
async def add_case_note(
    case_id: int,
    data: CaseNoteCreate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Add an investigation note to a case."""
    case = session.query(AlertCase).filter_by(id=case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    note = Note(
        entity_type=NoteEntityType.CASE,
        entity_id=str(case_id),
        user_id=current_user.id,
        content=data.content,
    )
    session.add(note)
    session.commit()
    session.refresh(case)
    await _sync_case_to_es(case, session)

    # Sync note to Kibana as comment
    if case.kibana_case_id:
        try:
            kibana_service = get_kibana_cases_service()
            if kibana_service.enabled:
                comment_text = f"**{current_user.username}:** {data.content}"
                kibana_service.add_comment(case.kibana_case_id, comment_text)
        except Exception as e:
            _case_es_logger.warning("Failed to sync note to Kibana: %s", e)

    return {
        "id": note.id,
        "case_id": note.case_id,
        "user": current_user.username,
        "content": note.content,
        "created_at": note.created_at.isoformat() if note.created_at else None,
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

    # Get Kibana URL if available
    kibana_url = None
    if case.kibana_case_id:
        try:
            kibana_service = get_kibana_cases_service()
            if kibana_service.enabled:
                kibana_url = kibana_service.get_case_url(case.kibana_case_id)
        except Exception:
            pass

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
        "affected_hosts": case.affected_hosts,
        "affected_users": case.affected_users,
        "triggered_rules": case.triggered_rules,
        "evidence_summary": case.evidence_summary,
        "source_alert_ids": case.source_alert_ids,
        "observables": case.observables or [],
        "kibana_case_id": case.kibana_case_id,
        "kibana_url": kibana_url,
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
        "notes": [
            {
                "id": n.id,
                "user": n.user.username if n.user else "Unknown",
                "content": n.content,
                "created_at": n.created_at.isoformat() if n.created_at else None,
            }
            for n in case.notes
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
    session.refresh(case)
    await _sync_case_to_es(case, session)

    # Sync updates to Kibana
    kibana_url = None
    if case.kibana_case_id:
        try:
            kibana_service = get_kibana_cases_service()
            if kibana_service.enabled:
                # Map IXION status to Kibana status
                kibana_status = None
                if data.status:
                    status_map = {
                        "open": "open",
                        "in_progress": "in-progress",
                        "resolved": "closed",
                        "closed": "closed",
                    }
                    kibana_status = status_map.get(data.status)

                # Get current version from Kibana
                kibana_case = kibana_service.get_case(case.kibana_case_id)
                if kibana_case:
                    version = kibana_case.get("version")
                    updated = kibana_service.update_case(
                        case_id=case.kibana_case_id,
                        version=version,
                        title=f"[{case.case_number}] {case.title}" if data.title else None,
                        description=data.description,
                        status=kibana_status,
                        severity=data.severity,
                    )
                    if updated:
                        case.kibana_case_version = updated.get("version")
                        session.commit()
                kibana_url = kibana_service.get_case_url(case.kibana_case_id)
        except Exception as e:
            _case_es_logger.warning("Failed to sync case update to Kibana: %s", e)

    return {
        "id": case.id,
        "case_number": case.case_number,
        "title": case.title,
        "status": case.status.value if hasattr(case.status, "value") else case.status,
        "kibana_url": kibana_url,
        "message": "Case updated",
    }


class BatchTriageRequest(BaseModel):
    alert_ids: List[str]


@router.post("/elasticsearch/alerts-triage/batch")
async def get_batch_triage(
    data: BatchTriageRequest,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Get triage data (including case info) for multiple alerts at once."""
    if not data.alert_ids:
        return {"triage": {}}

    triages = (
        session.query(AlertTriage)
        .filter(AlertTriage.es_alert_id.in_(data.alert_ids))
        .all()
    )

    result = {}
    for t in triages:
        result[t.es_alert_id] = {
            "status": t.status.value if hasattr(t.status, "value") else t.status,
            "priority": t.priority,
            "case_id": t.case_id,
            "case_number": t.case.case_number if t.case else None,
            "case_title": t.case.title if t.case else None,
        }

    return {"triage": result}


@router.post("/elasticsearch/alerts-triage/bulk-update")
async def bulk_update_triage(
    data: BulkTriageUpdate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Bulk update triage status, assignee, priority for multiple alerts."""
    if not data.alert_ids:
        raise HTTPException(status_code=400, detail="No alert IDs provided")

    updated = 0
    new_case = None

    # If creating a new case for these alerts
    if data.add_to_new_case and data.new_case_title:
        # Generate case number
        last_case = session.query(AlertCase).order_by(AlertCase.id.desc()).first()
        next_num = 1 if not last_case else last_case.id + 1
        case_number = f"CASE-{next_num:04d}"

        new_case = AlertCase(
            case_number=case_number,
            title=data.new_case_title,
            status=AlertCaseStatus.OPEN,
            severity=data.new_case_severity or "medium",
            created_by_id=current_user.id,
            source_alert_ids=data.alert_ids,
        )
        session.add(new_case)
        session.flush()

    for alert_id in data.alert_ids:
        triage = session.query(AlertTriage).filter_by(es_alert_id=alert_id).first()
        if not triage:
            triage = AlertTriage(es_alert_id=alert_id)
            session.add(triage)
            session.flush()

        if data.status is not None:
            triage.status = data.status
        if data.assigned_to_id is not None:
            triage.assigned_to_id = data.assigned_to_id if data.assigned_to_id > 0 else None
        if data.priority is not None:
            triage.priority = data.priority
        if data.case_id is not None:
            triage.case_id = data.case_id if data.case_id > 0 else None
        if new_case:
            triage.case_id = new_case.id

        updated += 1

    session.commit()

    result = {
        "updated": updated,
        "alert_ids": data.alert_ids,
    }

    if new_case:
        result["new_case"] = {
            "id": new_case.id,
            "case_number": new_case.case_number,
            "title": new_case.title,
        }

    return result


@router.get("/elasticsearch/alerts/{alert_id}/triage")
async def get_alert_triage(
    alert_id: str,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Get triage state and comments for an alert."""
    triage = session.query(AlertTriage).filter_by(es_alert_id=alert_id).first()
    comments = (
        session.query(Note)
        .filter(Note.entity_type == NoteEntityType.ALERT, Note.entity_id == alert_id)
        .order_by(Note.created_at.asc())
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
            "analyst_notes": triage.analyst_notes,
            "observables": triage.observables,
            "mitre_techniques": triage.mitre_techniques,
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
    if data.analyst_notes is not None:
        triage.analyst_notes = data.analyst_notes
    if data.observables is not None:
        # Validate observable types and values
        validated = []
        for obs in data.observables:
            obs_type = obs.get("type", "")
            obs_value = obs.get("value", "")
            if obs_type not in OBSERVABLE_TYPES:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid observable type: {obs_type}. Must be one of: {', '.join(sorted(OBSERVABLE_TYPES))}",
                )
            if not obs_value or not str(obs_value).strip():
                continue
            validated.append({"type": obs_type, "value": str(obs_value).strip()})
        triage.observables = validated

    if data.mitre_techniques is not None:
        import re
        validated_techniques = []
        technique_pattern = re.compile(r"^T\d{4}(\.\d{3})?$")
        for tech in data.mitre_techniques:
            tech_id = tech.get("technique_id", "")
            if not tech_id:
                continue
            if not technique_pattern.match(tech_id):
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid MITRE technique ID: {tech_id}. Must match pattern T#### or T####.###",
                )
            validated_techniques.append({
                "technique_id": tech_id,
                "technique_name": tech.get("technique_name", ""),
                "tactic_name": tech.get("tactic_name", ""),
                "source": tech.get("source", "manual"),
            })
        triage.mitre_techniques = validated_techniques

    session.commit()
    return {
        "id": triage.id,
        "es_alert_id": triage.es_alert_id,
        "status": triage.status.value if hasattr(triage.status, "value") else triage.status,
        "priority": triage.priority,
        "assigned_to_id": triage.assigned_to_id,
        "case_id": triage.case_id,
        "analyst_notes": triage.analyst_notes,
        "observables": triage.observables,
        "mitre_techniques": triage.mitre_techniques,
        "message": "Triage updated",
    }


def _extract_observables_from_raw(raw_data: dict) -> list:
    """Extract observables from ECS-style and Kibana Security alert data."""
    observables = []
    seen = set()

    def _add(obs_type: str, value: str):
        value = str(value).strip()
        if value and (obs_type, value) not in seen:
            seen.add((obs_type, value))
            observables.append({"type": obs_type, "value": value})

    def _get_nested(data: dict, dotted_key: str):
        """Retrieve a nested value using dot notation.

        Handles both formats:
        - Flattened dot notation keys: data["source.ip"]
        - Nested objects: data["source"]["ip"]
        """
        # First try flattened dot notation (Kibana Security alerts)
        if dotted_key in data:
            return data[dotted_key]

        # Then try nested object traversal (ECS standard)
        keys = dotted_key.split(".")
        current = data
        for k in keys:
            if isinstance(current, dict):
                current = current.get(k)
            else:
                return None
        return current

    def _extract_field(fields: list, obs_type: str):
        """Extract value from multiple possible field paths."""
        for field in fields:
            val = _get_nested(raw_data, field)
            if val:
                if isinstance(val, list):
                    for v in val:
                        if v:
                            _add(obs_type, str(v))
                else:
                    _add(obs_type, str(val))

    ip_pattern = re.compile(
        r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
    )

    # === IP Addresses ===
    # source.ip → source_ip
    _extract_field(["source.ip", "client.ip"], "source_ip")

    # destination.ip → destination_ip
    _extract_field(["destination.ip", "server.ip"], "destination_ip")

    # host.ip → host_ip
    _extract_field(["host.ip"], "host_ip")

    # === Hostnames ===
    _extract_field(["host.name", "host.hostname", "agent.hostname"], "hostname")

    # === User Accounts ===
    _extract_field(["user.name", "user.id", "winlog.event_data.TargetUserName"], "user_account")

    # === URLs and Domains ===
    _extract_field(["url.full", "url.original"], "url")
    _extract_field(["url.domain", "dns.question.name", "destination.domain"], "domain")

    # === File Information ===
    _extract_field(["file.path", "process.executable", "file.name"], "file_path")
    _extract_field(["file.hash.sha256", "process.hash.sha256"], "sha256")
    _extract_field(["file.hash.md5", "process.hash.md5"], "md5")
    _extract_field(["file.hash.sha1", "process.hash.sha1"], "sha1")

    # === Process Information ===
    _extract_field(["process.name", "process.executable"], "process_name")
    _extract_field(["process.command_line", "process.args"], "command_line")
    _extract_field(["process.pid"], "process_id")
    _extract_field(["process.parent.name"], "parent_process")

    # === Network ===
    _extract_field(["destination.port", "server.port"], "port")
    _extract_field(["network.protocol", "network.transport"], "protocol")

    # === Email ===
    _extract_field(["email.from.address", "email.sender.address"], "email")
    _extract_field(["email.subject"], "email_subject")

    # === Registry (Windows) ===
    _extract_field(["registry.path", "registry.key"], "registry_key")
    _extract_field(["registry.value"], "registry_value")

    # === MITRE ATT&CK ===
    _extract_field(["threat.technique.id", "kibana.alert.rule.threat.technique.id"], "mitre_technique")
    _extract_field(["threat.technique.name", "kibana.alert.rule.threat.technique.name"], "mitre_technique_name")
    _extract_field(["threat.tactic.name", "kibana.alert.rule.threat.tactic.name"], "mitre_tactic")

    # === Event Context ===
    _extract_field(["event.action", "kibana.alert.original_event.action"], "event_action")
    _extract_field(["event.category", "kibana.alert.original_event.category"], "event_category")
    _extract_field(["event.outcome", "kibana.alert.original_event.outcome"], "event_outcome")
    _extract_field(["message"], "message")

    # === Kibana Security Alert specific fields ===
    _extract_field(["kibana.alert.rule.name", "rule.name"], "rule_name")
    _extract_field(["kibana.alert.rule.description", "rule.description"], "rule_description")
    _extract_field(["kibana.alert.reason"], "alert_reason")
    _extract_field(["kibana.alert.severity", "severity"], "severity")
    _extract_field(["kibana.alert.risk_score"], "risk_score")

    # source.address / destination.address → source_ip / destination_ip (if IP-shaped)
    for field, obs_type in (("source.address", "source_ip"), ("destination.address", "destination_ip")):
        val = _get_nested(raw_data, field)
        if val:
            vals = val if isinstance(val, list) else [val]
            for v in vals:
                v_str = str(v).strip()
                if ip_pattern.match(v_str):
                    _add(obs_type, v_str)

    return observables


def _populate_triage_observables(triage, host=None, user=None, raw_data=None) -> bool:
    """Populate observables on a triage record from alert context.

    Extracts host→hostname, user→user_account, raw_data→ECS fields.
    Returns True if populated, False if skipped (already has observables).
    """
    if triage.observables:
        return False

    observables = []
    seen = set()

    def _add(obs_type: str, value: str):
        value = str(value).strip()
        if value and (obs_type, value) not in seen:
            seen.add((obs_type, value))
            observables.append({"type": obs_type, "value": value})

    if host:
        _add("hostname", host)
    if user:
        _add("user_account", user)
    if raw_data:
        for obs in _extract_observables_from_raw(raw_data):
            _add(obs["type"], obs["value"])

    triage.observables = observables if observables else None
    return True


@router.post("/elasticsearch/alerts/{alert_id}/triage/auto-populate-observables")
async def auto_populate_observables(
    alert_id: str,
    data: AutoPopulateRequest,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Auto-populate observables from alert context. Idempotent - won't overwrite existing."""
    triage = session.query(AlertTriage).filter_by(es_alert_id=alert_id).first()
    if not triage:
        triage = AlertTriage(es_alert_id=alert_id)
        session.add(triage)
        session.flush()

    populated = _populate_triage_observables(triage, data.host, data.user, data.raw_data)
    session.commit()

    return {"observables": triage.observables, "auto_populated": populated}


@router.post("/elasticsearch/alerts/{alert_id}/comments")
async def add_alert_comment(
    alert_id: str,
    data: CommentCreate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Add a comment to an alert."""
    comment = Note(
        entity_type=NoteEntityType.ALERT,
        entity_id=alert_id,
        user_id=current_user.id,
        content=data.content,
    )
    session.add(comment)
    session.commit()
    return {
        "id": comment.id,
        "es_alert_id": comment.entity_id,
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


# ============================================================================
# Elasticsearch Discover Search Endpoints
# ============================================================================


class DiscoverSearchRequest(BaseModel):
    """Request model for discover search."""
    index_pattern: str = "logs-*"
    query: str = "*"
    time_field: str = "@timestamp"
    time_from: Optional[str] = "now-24h"
    time_to: Optional[str] = "now"
    size: int = 100
    sort_field: Optional[str] = None
    sort_order: str = "desc"
    fields: Optional[List[str]] = None


class DiscoverHistogramRequest(BaseModel):
    """Request model for discover histogram."""
    index_pattern: str = "logs-*"
    query: str = "*"
    time_field: str = "@timestamp"
    time_from: str = "now-24h"
    time_to: str = "now"
    interval: str = "1h"


@router.post("/elasticsearch/discover/search")
async def discover_search(
    request: DiscoverSearchRequest,
    current_user: User = Depends(get_current_user),
):
    """Execute a discover-style search across Elasticsearch indices.

    Supports Lucene/KQL query syntax for flexible searching.
    """
    config = get_elasticsearch_config()
    if not config.get("enabled"):
        raise HTTPException(status_code=400, detail="Elasticsearch is not enabled")

    service = get_elasticsearch_service()
    if not service.is_configured:
        raise HTTPException(status_code=400, detail="Elasticsearch is not configured")

    try:
        result = await service.discover_search(
            index_pattern=request.index_pattern,
            query=request.query,
            time_field=request.time_field,
            time_from=request.time_from,
            time_to=request.time_to,
            size=request.size,
            sort_field=request.sort_field,
            sort_order=request.sort_order,
            fields=request.fields,
        )

        if "error" in result and result["error"]:
            raise HTTPException(status_code=500, detail=result["error"])

        return result

    except ElasticsearchError as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/elasticsearch/discover/histogram")
async def discover_histogram(
    request: DiscoverHistogramRequest,
    current_user: User = Depends(get_current_user),
):
    """Get a time histogram for discover visualization."""
    config = get_elasticsearch_config()
    if not config.get("enabled"):
        raise HTTPException(status_code=400, detail="Elasticsearch is not enabled")

    service = get_elasticsearch_service()
    if not service.is_configured:
        raise HTTPException(status_code=400, detail="Elasticsearch is not configured")

    try:
        result = await service.discover_histogram(
            index_pattern=request.index_pattern,
            query=request.query,
            time_field=request.time_field,
            time_from=request.time_from,
            time_to=request.time_to,
            interval=request.interval,
        )

        if "error" in result and result["error"]:
            raise HTTPException(status_code=500, detail=result["error"])

        return result

    except ElasticsearchError as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Elasticsearch Index Browser Endpoints
# ============================================================================


@router.get("/elasticsearch/indices")
async def list_indices(
    pattern: str = "*",
    include_system: bool = False,
    include_stats: bool = True,
    current_user: User = Depends(get_current_user),
):
    """List available Elasticsearch indices.

    Args:
        pattern: Index pattern to filter (e.g., "logs-*")
        include_system: Include system indices (starting with .)
        include_stats: Include document count and size stats
    """
    config = get_elasticsearch_config()
    if not config.get("enabled"):
        raise HTTPException(status_code=400, detail="Elasticsearch is not enabled")

    service = get_elasticsearch_service()
    if not service.is_configured:
        raise HTTPException(status_code=400, detail="Elasticsearch is not configured")

    try:
        result = await service.list_indices(
            pattern=pattern,
            include_system=include_system,
            include_stats=include_stats,
        )

        if "error" in result and result["error"]:
            raise HTTPException(status_code=500, detail=result["error"])

        return result

    except ElasticsearchError as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/elasticsearch/indices/{index_pattern}/mappings")
async def get_index_mappings(
    index_pattern: str,
    current_user: User = Depends(get_current_user),
):
    """Get field mappings for an index pattern.

    Returns field names, types, and whether they are searchable/aggregatable.
    """
    config = get_elasticsearch_config()
    if not config.get("enabled"):
        raise HTTPException(status_code=400, detail="Elasticsearch is not enabled")

    service = get_elasticsearch_service()
    if not service.is_configured:
        raise HTTPException(status_code=400, detail="Elasticsearch is not configured")

    try:
        result = await service.get_index_mappings(index_pattern=index_pattern)

        if "error" in result and result["error"]:
            raise HTTPException(status_code=500, detail=result["error"])

        return result

    except ElasticsearchError as e:
        raise HTTPException(status_code=500, detail=str(e))


class FieldStatsRequest(BaseModel):
    """Request model for field statistics."""
    index_pattern: str
    field: str
    size: int = 10
    time_field: Optional[str] = "@timestamp"
    time_from: Optional[str] = "now-24h"
    time_to: Optional[str] = "now"


@router.post("/elasticsearch/indices/field-stats")
async def get_field_stats(
    request: FieldStatsRequest,
    current_user: User = Depends(get_current_user),
):
    """Get statistics and top values for a specific field.

    Returns cardinality, top values, and counts.
    """
    config = get_elasticsearch_config()
    if not config.get("enabled"):
        raise HTTPException(status_code=400, detail="Elasticsearch is not enabled")

    service = get_elasticsearch_service()
    if not service.is_configured:
        raise HTTPException(status_code=400, detail="Elasticsearch is not configured")

    try:
        result = await service.get_field_stats(
            index_pattern=request.index_pattern,
            field=request.field,
            size=request.size,
            time_field=request.time_field,
            time_from=request.time_from,
            time_to=request.time_to,
        )

        if "error" in result and result["error"]:
            raise HTTPException(status_code=500, detail=result["error"])

        return result

    except ElasticsearchError as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# IOC Hunt Endpoints
# ============================================================================


class IOCHuntRequest(BaseModel):
    """Request model for IOC hunt."""
    ioc_value: str
    ioc_type: Optional[str] = None  # ip, hash, domain, url, email (auto-detected if not provided)
    index_pattern: str = "*,-.*"
    time_field: str = "@timestamp"
    time_from: Optional[str] = "now-30d"
    time_to: Optional[str] = "now"
    size: int = 100


class IOCHuntBulkRequest(BaseModel):
    """Request model for bulk IOC hunt."""
    ioc_values: List[str]
    index_pattern: str = "*,-.*"
    time_from: Optional[str] = "now-30d"
    time_to: Optional[str] = "now"


@router.post("/elasticsearch/ioc-hunt")
async def ioc_hunt(
    request: IOCHuntRequest,
    current_user: User = Depends(get_current_user),
):
    """Hunt for an IOC (Indicator of Compromise) across all Elasticsearch indices.

    Automatically detects IOC type (IP, hash, domain, URL, email) and searches
    relevant fields. Returns matching documents and index statistics.
    """
    config = get_elasticsearch_config()
    if not config.get("enabled"):
        raise HTTPException(status_code=400, detail="Elasticsearch is not enabled")

    service = get_elasticsearch_service()
    if not service.is_configured:
        raise HTTPException(status_code=400, detail="Elasticsearch is not configured")

    try:
        result = await service.ioc_hunt(
            ioc_value=request.ioc_value,
            ioc_type=request.ioc_type,
            index_pattern=request.index_pattern,
            time_field=request.time_field,
            time_from=request.time_from,
            time_to=request.time_to,
            size=request.size,
        )

        if "error" in result and result["error"]:
            raise HTTPException(status_code=500, detail=result["error"])

        return result

    except ElasticsearchError as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/elasticsearch/ioc-hunt/bulk")
async def ioc_hunt_bulk(
    request: IOCHuntBulkRequest,
    current_user: User = Depends(get_current_user),
):
    """Hunt for multiple IOCs at once.

    Searches for up to 100 IOCs and returns a summary of which were found
    and in which indices.
    """
    config = get_elasticsearch_config()
    if not config.get("enabled"):
        raise HTTPException(status_code=400, detail="Elasticsearch is not enabled")

    service = get_elasticsearch_service()
    if not service.is_configured:
        raise HTTPException(status_code=400, detail="Elasticsearch is not configured")

    try:
        result = await service.ioc_hunt_bulk(
            ioc_values=request.ioc_values,
            index_pattern=request.index_pattern,
            time_from=request.time_from,
            time_to=request.time_to,
        )

        if "error" in result and result["error"]:
            raise HTTPException(status_code=500, detail=result["error"])

        return result

    except ElasticsearchError as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# OpenCTI Integration Endpoints
# ============================================================================

from ixion.services.opencti_service import (
    OpenCTIService,
    OpenCTIError,
    get_opencti_service,
    reset_opencti_service,
)
from ixion.core.config import get_opencti_config


class OpenCTIConfigUpdate(BaseModel):
    url: str
    token: str
    verify_ssl: bool = True


class OpenCTIEnrichRequest(BaseModel):
    type: str  # e.g., "ipv4-addr", "domain-name", "file-sha256", "url"
    value: str


class OpenCTIEnrichBatchRequest(BaseModel):
    observables: List[dict]  # [{"type": "...", "value": "..."}, ...]


@router.get("/opencti/config")
async def get_opencti_config_endpoint(
    current_user: User = Depends(get_current_user),
):
    """Get OpenCTI configuration status (no sensitive data)."""
    config = get_opencti_config()
    return {
        "enabled": config.get("enabled", False),
        "url": config.get("url", ""),
        "has_token": bool(config.get("token")),
        "verify_ssl": config.get("verify_ssl", True),
    }


@router.post("/opencti/config", dependencies=[Depends(require_admin)])
async def update_opencti_config_endpoint(
    config_update: OpenCTIConfigUpdate,
    current_user: User = Depends(get_current_user),
):
    """Update OpenCTI configuration (admin only)."""
    import os

    config = get_config()
    config.opencti_enabled = True
    config.opencti_url = config_update.url
    config.opencti_token = config_update.token
    config.opencti_verify_ssl = config_update.verify_ssl

    data_dir = os.environ.get("IXION_DATA_DIR")
    if data_dir:
        config_path = Path(data_dir) / ".ixion" / "config.json"
    else:
        config_path = Path.cwd() / ".ixion" / "config.json"

    config.to_file(config_path)
    reset_opencti_service()

    # Test connection with new config
    service = get_opencti_service()
    connection_result = await service.test_connection()

    return {
        "success": True,
        "message": "OpenCTI configuration saved",
        "connection": connection_result,
    }


@router.delete("/opencti/config", dependencies=[Depends(require_admin)])
async def disable_opencti_config_endpoint(
    current_user: User = Depends(get_current_user),
):
    """Disable OpenCTI integration (admin only)."""
    import os

    config = get_config()
    config.opencti_enabled = False
    config.opencti_url = ""
    config.opencti_token = ""

    data_dir = os.environ.get("IXION_DATA_DIR")
    if data_dir:
        config_path = Path(data_dir) / ".ixion" / "config.json"
    else:
        config_path = Path.cwd() / ".ixion" / "config.json"

    config.to_file(config_path)
    reset_opencti_service()

    return {"success": True, "message": "OpenCTI integration disabled"}


@router.get("/opencti/test")
async def test_opencti_connection(
    current_user: User = Depends(get_current_user),
):
    """Test the OpenCTI connection."""
    service = get_opencti_service()
    result = await service.test_connection()
    return result


@router.post("/opencti/enrich/batch")
async def enrich_batch(
    request_data: OpenCTIEnrichBatchRequest,
    current_user: User = Depends(get_current_user),
):
    """Enrich multiple observables via OpenCTI.

    Request body: {"observables": [{"type": "ipv4-addr", "value": "1.2.3.4"}, ...]}
    """
    config = get_opencti_config()
    if not config.get("enabled"):
        return {
            "results": [],
            "error": "OpenCTI integration is not enabled",
        }

    service = get_opencti_service()
    if not service.is_configured:
        return {
            "results": [],
            "error": "OpenCTI is not configured",
        }

    results = await service.enrich_batch(request_data.observables)
    return {
        "results": results,
        "total": len(results),
        "found": sum(1 for r in results if r.get("found")),
    }


@router.post("/opencti/enrich")
async def enrich_observable(
    request_data: OpenCTIEnrichRequest,
    current_user: User = Depends(get_current_user),
):
    """Enrich a single observable via OpenCTI.

    Request body: {"type": "ipv4-addr", "value": "1.2.3.4"}
    """
    config = get_opencti_config()
    if not config.get("enabled"):
        return {
            "found": False,
            "type": request_data.type,
            "value": request_data.value,
            "error": "OpenCTI integration is not enabled",
        }

    service = get_opencti_service()
    if not service.is_configured:
        return {
            "found": False,
            "type": request_data.type,
            "value": request_data.value,
            "error": "OpenCTI is not configured",
        }

    result = await service.enrich_observable(request_data.type, request_data.value)
    return result


# =============================================================================
# Chat endpoints
# =============================================================================

from ixion.models.chat import ChatRoom, ChatRoomMember, ChatMessage, MessageReaction
from sqlalchemy import select, and_, or_, func as sqlfunc


class ChatRoomCreate(BaseModel):
    room_type: str  # 'direct' or 'group'
    name: Optional[str] = None
    case_id: Optional[int] = None
    member_ids: List[int]


class ChatRoomUpdate(BaseModel):
    name: Optional[str] = None
    add_member_ids: Optional[List[int]] = None
    remove_member_ids: Optional[List[int]] = None


class ChatMessageCreate(BaseModel):
    content: str
    mentions: Optional[List[str]] = None  # usernames


class ChatMessageUpdate(BaseModel):
    content: str


class ChatReactionCreate(BaseModel):
    emoji: str


class ChatTypingUpdate(BaseModel):
    is_typing: bool


@router.get("/chat/rooms")
async def list_chat_rooms(
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """List chat rooms for the current user with unread counts."""
    # Get rooms where user is a member
    stmt = (
        select(ChatRoom)
        .join(ChatRoomMember, ChatRoomMember.room_id == ChatRoom.id)
        .where(ChatRoomMember.user_id == current_user.id)
        .order_by(ChatRoom.updated_at.desc())
    )
    rooms = list(session.execute(stmt).unique().scalars().all())

    result = []
    for room in rooms:
        # Get member info for this room
        member_stmt = select(ChatRoomMember).where(ChatRoomMember.room_id == room.id)
        members = list(session.execute(member_stmt).scalars().all())

        # Find current user's membership
        user_member = next((m for m in members if m.user_id == current_user.id), None)

        # Calculate unread count
        unread_count = 0
        if user_member:
            msg_stmt = select(sqlfunc.count(ChatMessage.id)).where(
                ChatMessage.room_id == room.id
            )
            if user_member.last_read_at:
                msg_stmt = msg_stmt.where(ChatMessage.created_at > user_member.last_read_at)
            msg_stmt = msg_stmt.where(ChatMessage.user_id != current_user.id)
            unread_count = session.execute(msg_stmt).scalar() or 0

        # Get last message
        last_msg_stmt = (
            select(ChatMessage)
            .where(ChatMessage.room_id == room.id)
            .order_by(ChatMessage.created_at.desc())
            .limit(1)
        )
        last_msg = session.execute(last_msg_stmt).scalar_one_or_none()

        # Build display name
        display_name = room.name
        if room.room_type == 'direct' and not display_name:
            # For DMs, show the other user's name
            other_member = next((m for m in members if m.user_id != current_user.id), None)
            if other_member and other_member.user:
                display_name = other_member.user.display_name or other_member.user.username

        # Get linked case info if any
        case_number = None
        if room.case_id:
            from ixion.models.alert_triage import AlertCase
            case = session.execute(select(AlertCase).where(AlertCase.id == room.case_id)).scalar_one_or_none()
            if case:
                case_number = case.case_number

        result.append({
            "id": room.id,
            "name": room.name,
            "display_name": display_name,
            "room_type": room.room_type,
            "case_id": room.case_id,
            "case_number": case_number,
            "unread_count": unread_count,
            "last_message": last_msg.content[:50] + "..." if last_msg and len(last_msg.content) > 50 else (last_msg.content if last_msg else None),
            "last_message_at": last_msg.created_at.isoformat() if last_msg else None,
            "member_count": len(members),
        })

    return {"rooms": result}


@router.post("/chat/rooms")
async def create_chat_room(
    data: ChatRoomCreate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Create a new chat room (DM or group)."""
    # Validate room type
    if data.room_type not in ['direct', 'group']:
        raise HTTPException(status_code=400, detail="Invalid room type")

    # For direct messages, check if a DM already exists between these users
    if data.room_type == 'direct':
        if len(data.member_ids) != 1:
            raise HTTPException(status_code=400, detail="Direct messages require exactly one other user")

        other_user_id = data.member_ids[0]

        # Check for existing DM
        existing_stmt = (
            select(ChatRoom)
            .join(ChatRoomMember, ChatRoomMember.room_id == ChatRoom.id)
            .where(
                ChatRoom.room_type == 'direct',
                ChatRoomMember.user_id.in_([current_user.id, other_user_id])
            )
            .group_by(ChatRoom.id)
            .having(sqlfunc.count(ChatRoomMember.id) == 2)
        )
        existing = session.execute(existing_stmt).scalar_one_or_none()

        if existing:
            return {"room_id": existing.id, "message": "Existing conversation found"}

    # Create the room
    room = ChatRoom(
        name=data.name if data.room_type == 'group' else None,
        room_type=data.room_type,
        case_id=data.case_id,
        created_by_id=current_user.id,
    )
    session.add(room)
    session.flush()

    # Add current user as member
    session.add(ChatRoomMember(room_id=room.id, user_id=current_user.id))

    # Add other members
    for member_id in data.member_ids:
        if member_id != current_user.id:
            session.add(ChatRoomMember(room_id=room.id, user_id=member_id))

    session.commit()

    return {"room_id": room.id, "message": "Room created"}


@router.get("/chat/rooms/{room_id}")
async def get_chat_room(
    room_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Get chat room details."""
    # Verify user is a member
    member_stmt = select(ChatRoomMember).where(
        ChatRoomMember.room_id == room_id,
        ChatRoomMember.user_id == current_user.id
    )
    membership = session.execute(member_stmt).scalar_one_or_none()
    if not membership:
        raise HTTPException(status_code=404, detail="Room not found")

    room_stmt = select(ChatRoom).where(ChatRoom.id == room_id)
    room = session.execute(room_stmt).scalar_one_or_none()
    if not room:
        raise HTTPException(status_code=404, detail="Room not found")

    # Get all members
    members_stmt = (
        select(ChatRoomMember)
        .where(ChatRoomMember.room_id == room_id)
    )
    members = list(session.execute(members_stmt).scalars().all())

    # Build display name
    display_name = room.name
    if room.room_type == 'direct' and not display_name:
        other_member = next((m for m in members if m.user_id != current_user.id), None)
        if other_member and other_member.user:
            display_name = other_member.user.display_name or other_member.user.username

    # Get linked case info if any
    case_info = None
    if room.case_id:
        from ixion.models.alert_triage import AlertCase
        case = session.execute(select(AlertCase).where(AlertCase.id == room.case_id)).scalar_one_or_none()
        if case:
            case_info = {
                "id": case.id,
                "case_number": case.case_number,
                "title": case.title,
                "description": case.description,
                "status": case.status.value if hasattr(case.status, 'value') else str(case.status),
                "severity": case.severity,
                "affected_hosts": case.affected_hosts or [],
                "affected_users": case.affected_users or [],
                "triggered_rules": case.triggered_rules or [],
                "evidence_summary": case.evidence_summary,
                "created_at": case.created_at.isoformat() if case.created_at else None,
                "assigned_to": case.assigned_to.display_name or case.assigned_to.username if case.assigned_to else None,
            }

    return {
        "id": room.id,
        "name": room.name,
        "display_name": display_name,
        "room_type": room.room_type,
        "case_id": room.case_id,
        "case_info": case_info,
        "created_by_id": room.created_by_id,
        "created_at": room.created_at.isoformat(),
        "members": [
            {
                "id": m.user_id,
                "username": m.user.username,
                "display_name": m.user.display_name,
                "joined_at": m.joined_at.isoformat(),
            }
            for m in members if m.user
        ],
    }


@router.put("/chat/rooms/{room_id}")
async def update_chat_room(
    room_id: int,
    data: ChatRoomUpdate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Update chat room (name, members)."""
    # Verify user is a member
    member_stmt = select(ChatRoomMember).where(
        ChatRoomMember.room_id == room_id,
        ChatRoomMember.user_id == current_user.id
    )
    if not session.execute(member_stmt).scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Room not found")

    room_stmt = select(ChatRoom).where(ChatRoom.id == room_id)
    room = session.execute(room_stmt).scalar_one_or_none()
    if not room:
        raise HTTPException(status_code=404, detail="Room not found")

    # Only group chats can be renamed
    if data.name is not None and room.room_type == 'group':
        room.name = data.name

    # Add members (groups only)
    if data.add_member_ids and room.room_type == 'group':
        for member_id in data.add_member_ids:
            existing = session.execute(
                select(ChatRoomMember).where(
                    ChatRoomMember.room_id == room_id,
                    ChatRoomMember.user_id == member_id
                )
            ).scalar_one_or_none()
            if not existing:
                session.add(ChatRoomMember(room_id=room_id, user_id=member_id))

    # Remove members (groups only, can't remove self this way)
    if data.remove_member_ids and room.room_type == 'group':
        for member_id in data.remove_member_ids:
            if member_id != current_user.id:
                member = session.execute(
                    select(ChatRoomMember).where(
                        ChatRoomMember.room_id == room_id,
                        ChatRoomMember.user_id == member_id
                    )
                ).scalar_one_or_none()
                if member:
                    session.delete(member)

    session.commit()
    return {"message": "Room updated"}


@router.delete("/chat/rooms/{room_id}")
async def leave_chat_room(
    room_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Leave a chat room."""
    member_stmt = select(ChatRoomMember).where(
        ChatRoomMember.room_id == room_id,
        ChatRoomMember.user_id == current_user.id
    )
    membership = session.execute(member_stmt).scalar_one_or_none()
    if not membership:
        raise HTTPException(status_code=404, detail="Room not found")

    session.delete(membership)

    # Check if room is now empty
    remaining_stmt = select(sqlfunc.count(ChatRoomMember.id)).where(
        ChatRoomMember.room_id == room_id
    )
    remaining = session.execute(remaining_stmt).scalar() or 0

    if remaining == 0:
        # Delete the room if no members left
        room = session.execute(select(ChatRoom).where(ChatRoom.id == room_id)).scalar_one_or_none()
        if room:
            session.delete(room)

    session.commit()
    return {"message": "Left room"}


@router.get("/chat/rooms/{room_id}/messages")
async def get_chat_messages(
    room_id: int,
    since: Optional[str] = None,
    limit: int = 50,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Get messages from a chat room, optionally since a timestamp."""
    # Verify user is a member
    member_stmt = select(ChatRoomMember).where(
        ChatRoomMember.room_id == room_id,
        ChatRoomMember.user_id == current_user.id
    )
    if not session.execute(member_stmt).scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Room not found")

    # Build query
    stmt = (
        select(ChatMessage)
        .where(ChatMessage.room_id == room_id)
        .order_by(ChatMessage.created_at.asc())
        .limit(min(limit, 100))
    )

    if since:
        try:
            since_dt = datetime.fromisoformat(since.replace('Z', '+00:00'))
            stmt = stmt.where(ChatMessage.created_at > since_dt)
        except ValueError:
            pass  # Invalid timestamp, ignore filter

    messages = list(session.execute(stmt).scalars().all())

    result = []
    for msg in messages:
        # Get reactions
        reactions_stmt = select(MessageReaction).where(MessageReaction.message_id == msg.id)
        reactions = list(session.execute(reactions_stmt).scalars().all())

        result.append({
            "id": msg.id,
            "user_id": msg.user_id,
            "username": msg.user.username if msg.user else None,
            "display_name": msg.user.display_name if msg.user else None,
            "content": msg.content,
            "mentions": msg.mentions,
            "created_at": msg.created_at.isoformat(),
            "edited_at": msg.edited_at.isoformat() if msg.edited_at else None,
            "reactions": [
                {
                    "emoji": r.emoji,
                    "user_id": r.user_id,
                    "username": r.user.username if r.user else None,
                }
                for r in reactions
            ],
        })

    return {"messages": result}


@router.post("/chat/rooms/{room_id}/messages")
async def send_chat_message(
    room_id: int,
    data: ChatMessageCreate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Send a message to a chat room."""
    # Verify user is a member
    member_stmt = select(ChatRoomMember).where(
        ChatRoomMember.room_id == room_id,
        ChatRoomMember.user_id == current_user.id
    )
    if not session.execute(member_stmt).scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Room not found")

    if not data.content.strip():
        raise HTTPException(status_code=400, detail="Message cannot be empty")

    # Resolve mention usernames to user IDs
    mention_ids = None
    if data.mentions:
        user_repo = UserRepository(session)
        mention_ids = []
        for username in data.mentions:
            user = user_repo.get_by_username(username)
            if user:
                mention_ids.append(user.id)

    # Create message
    message = ChatMessage(
        room_id=room_id,
        user_id=current_user.id,
        content=data.content.strip(),
        mentions=mention_ids,
    )
    session.add(message)

    # Update room's updated_at
    room = session.execute(select(ChatRoom).where(ChatRoom.id == room_id)).scalar_one_or_none()
    if room:
        room.updated_at = datetime.utcnow()

    # Clear typing indicator
    member = session.execute(member_stmt).scalar_one_or_none()
    if member:
        member.is_typing = False
        member.typing_updated_at = None

    session.commit()

    return {
        "message_id": message.id,
        "created_at": message.created_at.isoformat(),
    }


@router.put("/chat/rooms/{room_id}/messages/{message_id}")
async def edit_chat_message(
    room_id: int,
    message_id: int,
    data: ChatMessageUpdate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Edit a message (only own messages)."""
    msg_stmt = select(ChatMessage).where(
        ChatMessage.id == message_id,
        ChatMessage.room_id == room_id,
        ChatMessage.user_id == current_user.id
    )
    message = session.execute(msg_stmt).scalar_one_or_none()

    if not message:
        raise HTTPException(status_code=404, detail="Message not found")

    if not data.content.strip():
        raise HTTPException(status_code=400, detail="Message cannot be empty")

    message.content = data.content.strip()
    message.edited_at = datetime.utcnow()

    session.commit()
    return {"message": "Message updated"}


@router.delete("/chat/rooms/{room_id}/messages/{message_id}")
async def delete_chat_message(
    room_id: int,
    message_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Delete a message (only own messages)."""
    msg_stmt = select(ChatMessage).where(
        ChatMessage.id == message_id,
        ChatMessage.room_id == room_id,
        ChatMessage.user_id == current_user.id
    )
    message = session.execute(msg_stmt).scalar_one_or_none()

    if not message:
        raise HTTPException(status_code=404, detail="Message not found")

    session.delete(message)
    session.commit()

    return {"message": "Message deleted"}


@router.post("/chat/messages/{message_id}/reactions")
async def add_reaction(
    message_id: int,
    data: ChatReactionCreate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Add a reaction to a message."""
    # Verify message exists and user has access
    msg_stmt = select(ChatMessage).where(ChatMessage.id == message_id)
    message = session.execute(msg_stmt).scalar_one_or_none()

    if not message:
        raise HTTPException(status_code=404, detail="Message not found")

    # Verify user is a member of the room
    member_stmt = select(ChatRoomMember).where(
        ChatRoomMember.room_id == message.room_id,
        ChatRoomMember.user_id == current_user.id
    )
    if not session.execute(member_stmt).scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Message not found")

    # Check if reaction already exists
    existing_stmt = select(MessageReaction).where(
        MessageReaction.message_id == message_id,
        MessageReaction.user_id == current_user.id,
        MessageReaction.emoji == data.emoji
    )
    if session.execute(existing_stmt).scalar_one_or_none():
        return {"message": "Reaction already exists"}

    # Add reaction
    reaction = MessageReaction(
        message_id=message_id,
        user_id=current_user.id,
        emoji=data.emoji,
    )
    session.add(reaction)
    session.commit()

    return {"message": "Reaction added"}


@router.delete("/chat/messages/{message_id}/reactions/{emoji}")
async def remove_reaction(
    message_id: int,
    emoji: str,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Remove a reaction from a message."""
    reaction_stmt = select(MessageReaction).where(
        MessageReaction.message_id == message_id,
        MessageReaction.user_id == current_user.id,
        MessageReaction.emoji == emoji
    )
    reaction = session.execute(reaction_stmt).scalar_one_or_none()

    if not reaction:
        raise HTTPException(status_code=404, detail="Reaction not found")

    session.delete(reaction)
    session.commit()

    return {"message": "Reaction removed"}


@router.post("/chat/rooms/{room_id}/typing")
async def update_typing_status(
    room_id: int,
    data: ChatTypingUpdate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Update typing status for current user in a room."""
    member_stmt = select(ChatRoomMember).where(
        ChatRoomMember.room_id == room_id,
        ChatRoomMember.user_id == current_user.id
    )
    member = session.execute(member_stmt).scalar_one_or_none()

    if not member:
        raise HTTPException(status_code=404, detail="Room not found")

    member.is_typing = data.is_typing
    member.typing_updated_at = datetime.utcnow() if data.is_typing else None

    session.commit()
    return {"message": "Typing status updated"}


@router.get("/chat/rooms/{room_id}/typing")
async def get_typing_users(
    room_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Get users currently typing in a room."""
    # Verify user is a member
    member_stmt = select(ChatRoomMember).where(
        ChatRoomMember.room_id == room_id,
        ChatRoomMember.user_id == current_user.id
    )
    if not session.execute(member_stmt).scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Room not found")

    # Get typing users (typing within last 5 seconds)
    cutoff = datetime.utcnow() - timedelta(seconds=5)
    typing_stmt = (
        select(ChatRoomMember)
        .where(
            ChatRoomMember.room_id == room_id,
            ChatRoomMember.is_typing == True,
            ChatRoomMember.typing_updated_at > cutoff
        )
    )
    typing_members = list(session.execute(typing_stmt).scalars().all())

    return {
        "typing_users": [
            {
                "id": m.user_id,
                "username": m.user.username if m.user else None,
                "display_name": m.user.display_name if m.user else None,
            }
            for m in typing_members
        ]
    }


@router.post("/chat/rooms/{room_id}/read")
async def mark_messages_read(
    room_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Mark all messages in a room as read."""
    member_stmt = select(ChatRoomMember).where(
        ChatRoomMember.room_id == room_id,
        ChatRoomMember.user_id == current_user.id
    )
    member = session.execute(member_stmt).scalar_one_or_none()

    if not member:
        raise HTTPException(status_code=404, detail="Room not found")

    member.last_read_at = datetime.utcnow()
    session.commit()

    return {"message": "Messages marked as read"}


@router.get("/chat/users")
async def search_chat_users(
    q: str = "",
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Search users for @mention autocomplete and new chat creation."""
    user_repo = UserRepository(session)

    if q:
        # Search by username or display name
        stmt = (
            select(User)
            .where(
                User.is_active == True,
                or_(
                    User.username.ilike(f"%{q}%"),
                    User.display_name.ilike(f"%{q}%")
                )
            )
            .limit(10)
        )
        users = list(session.execute(stmt).scalars().all())
    else:
        # Return all active users (limited)
        stmt = select(User).where(User.is_active == True).limit(20)
        users = list(session.execute(stmt).scalars().all())

    return {
        "users": [
            {
                "id": u.id,
                "username": u.username,
                "display_name": u.display_name,
            }
            for u in users
        ]
    }


# ============================================================================
# Kibana Cases Integration Endpoints
# ============================================================================


class KibanaCaseCreate(BaseModel):
    title: str
    description: Optional[str] = ""
    severity: Optional[str] = "low"
    tags: Optional[List[str]] = None
    alert_ids: Optional[List[str]] = None
    alert_index: Optional[str] = "alerts-ixion"


class KibanaCaseUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    severity: Optional[str] = None
    tags: Optional[List[str]] = None


class KibanaCaseComment(BaseModel):
    comment: str


@router.get("/kibana/config")
async def get_kibana_config_endpoint(
    current_user: User = Depends(get_current_user),
):
    """Get Kibana Cases configuration status."""
    config = get_kibana_config()
    return {
        "enabled": config.get("enabled", False),
        "url": config.get("url", ""),
        "has_credentials": bool(config.get("username") and config.get("password")),
        "space_id": config.get("space_id", "default"),
        "case_owner": config.get("case_owner", "securitySolution"),
    }


@router.get("/kibana/status")
async def get_kibana_status(
    current_user: User = Depends(get_current_user),
):
    """Test Kibana connectivity and return status."""
    service = get_kibana_cases_service()
    if not service.enabled:
        return {
            "connected": False,
            "error": "Kibana Cases integration not enabled",
        }

    result = service.test_connection()
    return {
        "connected": result.get("success", False),
        "version": result.get("version"),
        "status": result.get("status"),
        "error": result.get("error"),
    }


@router.get("/kibana/cases")
async def list_kibana_cases(
    status: Optional[str] = None,
    page: int = 1,
    per_page: int = 20,
    current_user: User = Depends(get_current_user),
):
    """List cases from Kibana."""
    service = get_kibana_cases_service()
    if not service.enabled:
        raise HTTPException(status_code=503, detail="Kibana Cases integration not enabled")

    result = service.list_cases(status=status, page=page, per_page=per_page)
    if "error" in result and result.get("error"):
        raise HTTPException(status_code=502, detail=result["error"])

    # Transform to consistent format
    cases = []
    for c in result.get("cases", []):
        cases.append({
            "id": c.get("id"),
            "title": c.get("title"),
            "description": c.get("description"),
            "status": c.get("status"),
            "severity": c.get("severity"),
            "tags": c.get("tags", []),
            "created_by": c.get("created_by", {}).get("username"),
            "created_at": c.get("created_at"),
            "updated_at": c.get("updated_at"),
            "kibana_url": service.get_case_url(c.get("id")),
            "comments_count": c.get("totalComment", 0),
            "alerts_count": c.get("totalAlerts", 0),
        })

    return {
        "cases": cases,
        "total": result.get("total", 0),
        "page": result.get("page", page),
        "per_page": result.get("per_page", per_page),
    }


@router.post("/kibana/cases")
async def create_kibana_case(
    data: KibanaCaseCreate,
    current_user: User = Depends(get_current_user),
):
    """Create a new case in Kibana."""
    service = get_kibana_cases_service()
    if not service.enabled:
        raise HTTPException(status_code=503, detail="Kibana Cases integration not enabled")

    # Map severity
    severity_map = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
    }
    severity = severity_map.get(data.severity, "low")

    result = service.create_case(
        title=data.title,
        description=data.description or "",
        severity=severity,
        tags=data.tags,
    )

    if not result:
        raise HTTPException(status_code=502, detail="Failed to create case in Kibana")

    case_id = result.get("id")

    # Attach alerts if provided
    if data.alert_ids and case_id:
        service.attach_alerts_to_case(
            case_id=case_id,
            alert_ids=data.alert_ids,
            alert_index=data.alert_index or "alerts-ixion",
        )

    return {
        "id": case_id,
        "title": result.get("title"),
        "status": result.get("status"),
        "severity": result.get("severity"),
        "kibana_url": service.get_case_url(case_id),
        "message": "Case created in Kibana",
    }


@router.get("/kibana/cases/{case_id}")
async def get_kibana_case(
    case_id: str,
    current_user: User = Depends(get_current_user),
):
    """Get a case from Kibana by ID."""
    service = get_kibana_cases_service()
    if not service.enabled:
        raise HTTPException(status_code=503, detail="Kibana Cases integration not enabled")

    result = service.get_case(case_id)
    if not result:
        raise HTTPException(status_code=404, detail="Case not found in Kibana")

    comments = service.get_case_comments(case_id)

    return {
        "id": result.get("id"),
        "title": result.get("title"),
        "description": result.get("description"),
        "status": result.get("status"),
        "severity": result.get("severity"),
        "tags": result.get("tags", []),
        "created_by": result.get("created_by", {}).get("username"),
        "created_at": result.get("created_at"),
        "updated_at": result.get("updated_at"),
        "version": result.get("version"),
        "kibana_url": service.get_case_url(case_id),
        "comments": [
            {
                "id": c.get("id"),
                "comment": c.get("comment"),
                "created_by": c.get("created_by", {}).get("username"),
                "created_at": c.get("created_at"),
            }
            for c in comments
            if c.get("type") == "user"
        ],
    }


@router.patch("/kibana/cases/{case_id}")
async def update_kibana_case(
    case_id: str,
    data: KibanaCaseUpdate,
    current_user: User = Depends(get_current_user),
):
    """Update a case in Kibana."""
    service = get_kibana_cases_service()
    if not service.enabled:
        raise HTTPException(status_code=503, detail="Kibana Cases integration not enabled")

    # Get current case to get version
    current = service.get_case(case_id)
    if not current:
        raise HTTPException(status_code=404, detail="Case not found in Kibana")

    version = current.get("version")

    # Map status
    status_map = {
        "open": "open",
        "in_progress": "in-progress",
        "in-progress": "in-progress",
        "resolved": "closed",
        "closed": "closed",
    }

    result = service.update_case(
        case_id=case_id,
        version=version,
        title=data.title,
        description=data.description,
        status=status_map.get(data.status) if data.status else None,
        severity=data.severity,
        tags=data.tags,
    )

    if not result:
        raise HTTPException(status_code=502, detail="Failed to update case in Kibana")

    return {
        "id": result.get("id"),
        "title": result.get("title"),
        "status": result.get("status"),
        "kibana_url": service.get_case_url(case_id),
        "message": "Case updated in Kibana",
    }


@router.post("/kibana/cases/{case_id}/comments")
async def add_kibana_case_comment(
    case_id: str,
    data: KibanaCaseComment,
    current_user: User = Depends(get_current_user),
):
    """Add a comment to a Kibana case."""
    service = get_kibana_cases_service()
    if not service.enabled:
        raise HTTPException(status_code=503, detail="Kibana Cases integration not enabled")

    result = service.add_comment(
        case_id=case_id,
        comment=data.comment,
    )

    if not result:
        raise HTTPException(status_code=502, detail="Failed to add comment to Kibana case")

    return {
        "case_id": case_id,
        "comment": data.comment,
        "message": "Comment added to Kibana case",
    }


@router.delete("/kibana/cases/{case_id}")
async def delete_kibana_case(
    case_id: str,
    current_user: User = Depends(get_current_user),
):
    """Delete a case from Kibana."""
    service = get_kibana_cases_service()
    if not service.enabled:
        raise HTTPException(status_code=503, detail="Kibana Cases integration not enabled")

    success = service.delete_case(case_id)
    if not success:
        raise HTTPException(status_code=502, detail="Failed to delete case from Kibana")

    return {
        "message": "Case deleted from Kibana",
    }


# ============================================================================
# Kibana Bidirectional Sync Endpoints
# ============================================================================

from ixion.services.kibana_sync_service import get_kibana_sync_service


@router.post("/kibana/sync")
async def sync_from_kibana(
    current_user: User = Depends(get_current_user),
):
    """Manually trigger sync of comments from Kibana to IXION."""
    sync_service = get_kibana_sync_service()

    result = await sync_service.sync_all_cases()

    return {
        "message": "Sync completed",
        "comments_synced": result.get("synced", 0),
        "cases_processed": result.get("cases", 0),
        "error": result.get("error"),
    }


@router.post("/kibana/sync/case/{case_id}")
async def sync_case_from_kibana(
    case_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Sync comments from Kibana for a specific case."""
    case = session.query(AlertCase).filter_by(id=case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    if not case.kibana_case_id:
        raise HTTPException(status_code=400, detail="Case not linked to Kibana")

    sync_service = get_kibana_sync_service()
    synced = await sync_service.sync_case_comments(session, case)

    # Also sync status
    status_updated = await sync_service.sync_case_status_from_kibana(session, case)

    return {
        "message": "Case sync completed",
        "comments_synced": synced,
        "status_updated": status_updated,
        "case_number": case.case_number,
    }


# ============================================================================
# Saved Searches Endpoints
# ============================================================================

from ixion.models.saved_search import SavedSearch, SearchType
from ixion.storage.saved_search_repository import SavedSearchRepository


class SavedSearchCreate(BaseModel):
    name: str
    description: Optional[str] = None
    search_type: str = "discover"
    search_params: dict
    is_shared: bool = False


class SavedSearchUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    search_params: Optional[dict] = None
    is_shared: Optional[bool] = None


@router.get("/saved-searches")
async def list_saved_searches(
    search_type: Optional[str] = None,
    favorites_only: bool = False,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """List saved searches for the current user (owned + shared)."""
    repo = SavedSearchRepository(session)
    searches = repo.list_for_user(
        user_id=current_user.id,
        search_type=search_type,
        favorites_only=favorites_only,
    )

    return {
        "saved_searches": [s.to_dict() for s in searches],
        "total": len(searches),
    }


@router.post("/saved-searches")
async def create_saved_search(
    data: SavedSearchCreate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Create a new saved search."""
    if not data.name or not data.name.strip():
        raise HTTPException(status_code=400, detail="Name is required")

    if not data.search_params:
        raise HTTPException(status_code=400, detail="Search params are required")

    repo = SavedSearchRepository(session)
    saved_search = repo.create(
        name=data.name.strip(),
        description=data.description,
        search_type=data.search_type,
        search_params=data.search_params,
        created_by_id=current_user.id,
        is_shared=data.is_shared,
    )
    session.commit()

    return {
        "saved_search": saved_search.to_dict(),
        "message": "Saved search created",
    }


@router.get("/saved-searches/{search_id}")
async def get_saved_search(
    search_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Get a saved search by ID."""
    repo = SavedSearchRepository(session)
    saved_search = repo.get_by_id(search_id)

    if not saved_search:
        raise HTTPException(status_code=404, detail="Saved search not found")

    # Check access: must be owner or search must be shared
    if saved_search.created_by_id != current_user.id and not saved_search.is_shared:
        raise HTTPException(status_code=404, detail="Saved search not found")

    return {"saved_search": saved_search.to_dict()}


@router.put("/saved-searches/{search_id}")
async def update_saved_search(
    search_id: int,
    data: SavedSearchUpdate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Update a saved search (owner only)."""
    repo = SavedSearchRepository(session)
    saved_search = repo.get_by_id(search_id)

    if not saved_search:
        raise HTTPException(status_code=404, detail="Saved search not found")

    # Only owner can update
    if saved_search.created_by_id != current_user.id:
        raise HTTPException(status_code=403, detail="Only the owner can update this search")

    saved_search = repo.update(
        saved_search,
        name=data.name,
        description=data.description,
        search_params=data.search_params,
        is_shared=data.is_shared,
    )
    session.commit()

    return {
        "saved_search": saved_search.to_dict(),
        "message": "Saved search updated",
    }


@router.delete("/saved-searches/{search_id}")
async def delete_saved_search(
    search_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Delete a saved search (owner only)."""
    repo = SavedSearchRepository(session)
    saved_search = repo.get_by_id(search_id)

    if not saved_search:
        raise HTTPException(status_code=404, detail="Saved search not found")

    # Only owner can delete
    if saved_search.created_by_id != current_user.id:
        raise HTTPException(status_code=403, detail="Only the owner can delete this search")

    repo.delete(saved_search)
    session.commit()

    return {"message": "Saved search deleted"}


@router.post("/saved-searches/{search_id}/execute")
async def execute_saved_search(
    search_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Execute a saved search and return results."""
    repo = SavedSearchRepository(session)
    saved_search = repo.get_by_id(search_id)

    if not saved_search:
        raise HTTPException(status_code=404, detail="Saved search not found")

    # Check access
    if saved_search.created_by_id != current_user.id and not saved_search.is_shared:
        raise HTTPException(status_code=404, detail="Saved search not found")

    # Record execution
    repo.record_execution(saved_search)
    session.commit()

    # Execute the search based on type
    params = saved_search.search_params

    if saved_search.search_type == SearchType.DISCOVER.value:
        # Execute discover search
        from ixion.services.elasticsearch_service import ElasticsearchService, get_elasticsearch_service

        config = get_elasticsearch_config()
        if not config.get("enabled"):
            raise HTTPException(status_code=400, detail="Elasticsearch is not enabled")

        service = get_elasticsearch_service()
        if not service.is_configured:
            raise HTTPException(status_code=400, detail="Elasticsearch is not configured")

        result = await service.discover_search(
            index_pattern=params.get("index_pattern", "*"),
            query=params.get("query", "*"),
            time_field=params.get("time_field", "@timestamp"),
            time_from=params.get("time_from", "now-24h"),
            time_to=params.get("time_to", "now"),
            size=params.get("size", 100),
            sort_field=params.get("sort_field"),
            sort_order=params.get("sort_order", "desc"),
        )

        return {
            "saved_search": saved_search.to_dict(),
            "results": result,
        }

    elif saved_search.search_type == SearchType.IOC_HUNT.value:
        # Execute IOC hunt
        from ixion.services.elasticsearch_service import get_elasticsearch_service

        config = get_elasticsearch_config()
        if not config.get("enabled"):
            raise HTTPException(status_code=400, detail="Elasticsearch is not enabled")

        service = get_elasticsearch_service()
        if not service.is_configured:
            raise HTTPException(status_code=400, detail="Elasticsearch is not configured")

        result = await service.ioc_hunt(
            ioc_value=params.get("ioc_value", ""),
            ioc_type=params.get("ioc_type"),
            index_pattern=params.get("index_pattern", "*"),
            time_field=params.get("time_field", "@timestamp"),
            time_from=params.get("time_from", "now-24h"),
            time_to=params.get("time_to", "now"),
            size=params.get("size", 100),
        )

        return {
            "saved_search": saved_search.to_dict(),
            "results": result,
        }

    else:
        raise HTTPException(status_code=400, detail=f"Unknown search type: {saved_search.search_type}")


@router.post("/saved-searches/{search_id}/favorite")
async def toggle_saved_search_favorite(
    search_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Toggle favorite status of a saved search (owner only)."""
    repo = SavedSearchRepository(session)
    saved_search = repo.get_by_id(search_id)

    if not saved_search:
        raise HTTPException(status_code=404, detail="Saved search not found")

    # Only owner can favorite
    if saved_search.created_by_id != current_user.id:
        raise HTTPException(status_code=403, detail="Only the owner can favorite this search")

    saved_search = repo.toggle_favorite(saved_search)
    session.commit()

    return {
        "saved_search": saved_search.to_dict(),
        "is_favorite": saved_search.is_favorite,
    }


# ============================================================================
# Playbooks Endpoints
# ============================================================================

from ixion.models.playbook import Playbook, PlaybookStep, PlaybookExecution, StepType, ExecutionStatus
from ixion.storage.playbook_repository import PlaybookRepository


class PlaybookStepCreate(BaseModel):
    step_type: str
    title: str
    description: Optional[str] = None
    step_params: Optional[dict] = None
    is_required: bool = False


class PlaybookCreate(BaseModel):
    name: str
    description: Optional[str] = None
    is_active: bool = True
    trigger_conditions: dict
    priority: int = 0
    steps: Optional[List[PlaybookStepCreate]] = None


class PlaybookUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    is_active: Optional[bool] = None
    trigger_conditions: Optional[dict] = None
    priority: Optional[int] = None
    steps: Optional[List[PlaybookStepCreate]] = None


class StepStatusUpdate(BaseModel):
    status: str  # 'completed', 'skipped', 'pending'
    notes: Optional[str] = None


@router.get("/playbooks")
async def list_playbooks(
    active_only: bool = False,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """List all playbooks."""
    repo = PlaybookRepository(session)
    playbooks = repo.list_playbooks(active_only=active_only)

    return {
        "playbooks": [p.to_dict(include_steps=True) for p in playbooks],
        "total": len(playbooks),
    }


@router.post("/playbooks")
async def create_playbook(
    data: PlaybookCreate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Create a new playbook with steps."""
    if not data.name or not data.name.strip():
        raise HTTPException(status_code=400, detail="Name is required")

    if not data.trigger_conditions:
        raise HTTPException(status_code=400, detail="Trigger conditions are required")

    repo = PlaybookRepository(session)

    # Check for duplicate name
    existing = repo.get_playbook_by_name(data.name.strip())
    if existing:
        raise HTTPException(status_code=400, detail="A playbook with this name already exists")

    playbook = repo.create_playbook(
        name=data.name.strip(),
        description=data.description,
        is_active=data.is_active,
        trigger_conditions=data.trigger_conditions,
        priority=data.priority,
        created_by_id=current_user.id,
    )

    # Add steps if provided
    if data.steps:
        for order, step_data in enumerate(data.steps, start=1):
            repo.add_step(
                playbook=playbook,
                step_order=order,
                step_type=step_data.step_type,
                title=step_data.title,
                description=step_data.description,
                step_params=step_data.step_params,
                is_required=step_data.is_required,
            )

    session.commit()

    # Refresh to get steps
    playbook = repo.get_playbook_by_id(playbook.id)

    return {
        "playbook": playbook.to_dict(include_steps=True),
        "message": "Playbook created",
    }


@router.get("/playbooks/{playbook_id}")
async def get_playbook(
    playbook_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Get a playbook by ID."""
    repo = PlaybookRepository(session)
    playbook = repo.get_playbook_by_id(playbook_id)

    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")

    return {"playbook": playbook.to_dict(include_steps=True)}


@router.put("/playbooks/{playbook_id}")
async def update_playbook(
    playbook_id: int,
    data: PlaybookUpdate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Update a playbook."""
    repo = PlaybookRepository(session)
    playbook = repo.get_playbook_by_id(playbook_id)

    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")

    # Check name uniqueness if changing
    if data.name and data.name.strip() != playbook.name:
        existing = repo.get_playbook_by_name(data.name.strip())
        if existing:
            raise HTTPException(status_code=400, detail="A playbook with this name already exists")

    playbook = repo.update_playbook(
        playbook,
        name=data.name.strip() if data.name else None,
        description=data.description,
        is_active=data.is_active,
        trigger_conditions=data.trigger_conditions,
        priority=data.priority,
    )

    # Replace steps if provided
    if data.steps is not None:
        steps_data = [
            {
                "step_type": s.step_type,
                "title": s.title,
                "description": s.description,
                "step_params": s.step_params,
                "is_required": s.is_required,
            }
            for s in data.steps
        ]
        repo.replace_steps(playbook, steps_data)

    session.commit()

    # Refresh
    playbook = repo.get_playbook_by_id(playbook_id)

    return {
        "playbook": playbook.to_dict(include_steps=True),
        "message": "Playbook updated",
    }


@router.delete("/playbooks/{playbook_id}")
async def delete_playbook(
    playbook_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Delete a playbook."""
    repo = PlaybookRepository(session)
    playbook = repo.get_playbook_by_id(playbook_id)

    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")

    repo.delete_playbook(playbook)
    session.commit()

    return {"message": "Playbook deleted"}


@router.get("/elasticsearch/alerts/{alert_id}/recommended-playbooks")
async def get_recommended_playbooks(
    alert_id: str,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Get playbooks that match the given alert's characteristics."""
    # First get the alert to extract its characteristics
    from ixion.services.elasticsearch_service import get_elasticsearch_service

    config = get_elasticsearch_config()
    if not config.get("enabled"):
        raise HTTPException(status_code=400, detail="Elasticsearch is not enabled")

    service = get_elasticsearch_service()
    if not service.is_configured:
        raise HTTPException(status_code=400, detail="Elasticsearch is not configured")

    # Try to get alert details
    alert = await service.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    # Extract characteristics for matching
    rule_name = alert.rule_name
    severity = alert.severity
    mitre_techniques = alert.mitre_techniques or []
    mitre_tactics = alert.mitre_tactics or []

    # Find matching playbooks
    repo = PlaybookRepository(session)
    matching_playbooks = repo.find_matching_playbooks(
        rule_name=rule_name,
        severity=severity,
        mitre_techniques=mitre_techniques,
        mitre_tactics=mitre_tactics,
    )

    # Check for active executions
    active_executions = repo.get_executions_for_alert(alert_id)
    active_playbook_ids = {
        e.playbook_id for e in active_executions
        if e.status == ExecutionStatus.IN_PROGRESS.value
    }

    result = []
    for playbook in matching_playbooks:
        pb_dict = playbook.to_dict(include_steps=True)
        pb_dict["has_active_execution"] = playbook.id in active_playbook_ids
        result.append(pb_dict)

    return {
        "playbooks": result,
        "total": len(result),
        "alert": {
            "id": alert_id,
            "rule_name": rule_name,
            "severity": severity,
            "mitre_techniques": mitre_techniques,
            "mitre_tactics": mitre_tactics,
        },
    }


@router.post("/elasticsearch/alerts/{alert_id}/playbook/{playbook_id}/start")
async def start_playbook_execution(
    alert_id: str,
    playbook_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Start a playbook execution for an alert."""
    repo = PlaybookRepository(session)
    playbook = repo.get_playbook_by_id(playbook_id)

    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")

    if not playbook.is_active:
        raise HTTPException(status_code=400, detail="Playbook is not active")

    # Check for existing active execution
    existing = repo.get_active_execution_for_alert(alert_id, playbook_id)
    if existing:
        return {
            "execution": existing.to_dict(include_playbook=True),
            "message": "Execution already in progress",
            "already_started": True,
        }

    # Start new execution
    execution = repo.start_execution(
        playbook=playbook,
        es_alert_id=alert_id,
        executed_by_id=current_user.id,
    )
    session.commit()

    # Refresh to get relationships
    execution = repo.get_execution(execution.id)

    return {
        "execution": execution.to_dict(include_playbook=True),
        "message": "Playbook execution started",
    }


@router.get("/playbook-executions/{execution_id}")
async def get_playbook_execution(
    execution_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Get a playbook execution by ID."""
    repo = PlaybookRepository(session)
    execution = repo.get_execution(execution_id)

    if not execution:
        raise HTTPException(status_code=404, detail="Execution not found")

    return {"execution": execution.to_dict(include_playbook=True)}


@router.get("/elasticsearch/alerts/{alert_id}/playbook-executions")
async def get_alert_playbook_executions(
    alert_id: str,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Get all playbook executions for an alert."""
    repo = PlaybookRepository(session)
    executions = repo.get_executions_for_alert(alert_id)

    return {
        "executions": [e.to_dict(include_playbook=True) for e in executions],
        "total": len(executions),
    }


@router.put("/playbook-executions/{execution_id}/steps/{step_id}")
async def update_step_status(
    execution_id: int,
    step_id: int,
    data: StepStatusUpdate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Update the status of a step in a playbook execution."""
    repo = PlaybookRepository(session)
    execution = repo.get_execution(execution_id)

    if not execution:
        raise HTTPException(status_code=404, detail="Execution not found")

    if execution.status != ExecutionStatus.IN_PROGRESS.value:
        raise HTTPException(status_code=400, detail="Execution is not in progress")

    # Verify step belongs to this playbook
    step = repo.get_step_by_id(step_id)
    if not step or step.playbook_id != execution.playbook_id:
        raise HTTPException(status_code=404, detail="Step not found in this playbook")

    # Update step status
    valid_statuses = ["completed", "skipped", "pending"]
    if data.status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {valid_statuses}")

    execution = repo.update_step_status(
        execution=execution,
        step_id=step_id,
        status=data.status,
        completed_by_id=current_user.id,
        completed_by_username=current_user.username,
        notes=data.notes,
    )
    session.commit()

    return {
        "execution": execution.to_dict(include_playbook=True),
        "step_id": step_id,
        "status": data.status,
    }


@router.post("/playbook-executions/{execution_id}/complete")
async def complete_playbook_execution(
    execution_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Manually mark a playbook execution as completed."""
    repo = PlaybookRepository(session)
    execution = repo.get_execution(execution_id)

    if not execution:
        raise HTTPException(status_code=404, detail="Execution not found")

    if execution.status != ExecutionStatus.IN_PROGRESS.value:
        raise HTTPException(status_code=400, detail="Execution is not in progress")

    execution = repo.complete_execution(execution)
    session.commit()

    return {
        "execution": execution.to_dict(include_playbook=True),
        "message": "Execution completed",
    }


@router.post("/playbook-executions/{execution_id}/fail")
async def fail_playbook_execution(
    execution_id: int,
    reason: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Mark a playbook execution as failed."""
    repo = PlaybookRepository(session)
    execution = repo.get_execution(execution_id)

    if not execution:
        raise HTTPException(status_code=404, detail="Execution not found")

    if execution.status != ExecutionStatus.IN_PROGRESS.value:
        raise HTTPException(status_code=400, detail="Execution is not in progress")

    execution = repo.fail_execution(execution, reason=reason)
    session.commit()

    return {
        "execution": execution.to_dict(include_playbook=True),
        "message": "Execution marked as failed",
    }
