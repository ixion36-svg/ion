"""API routes for DocForge web interface."""

import json
from pathlib import Path
from typing import Optional, List, Generator
from dataclasses import dataclass
from fastapi import APIRouter, HTTPException, UploadFile, File, Form, Depends, Request, Response
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
import httpx

from docforge.core.config import get_config, get_oidc_config
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
async def login(
    login_request: LoginRequest,
    request: Request,
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
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session_token,
        httponly=True,
        samesite="strict",
        secure=False,  # Set to True in production with HTTPS
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
async def get_oidc_public_config(request: Request):
    """Return public OIDC configuration for frontend.

    This endpoint is public and returns only the information needed
    for the frontend to initiate an OIDC login flow.
    """
    oidc_config = get_oidc_config()

    if not oidc_config.enabled or not oidc_config.is_valid():
        return {"enabled": False}

    # Build the redirect URI based on the request
    scheme = request.headers.get("X-Forwarded-Proto", request.url.scheme)
    host = request.headers.get("X-Forwarded-Host", request.url.netloc)
    redirect_uri = f"{scheme}://{host}/api/auth/oidc/callback"

    return {
        "enabled": True,
        "authorization_url": oidc_config.authorization_url,
        "client_id": oidc_config.client_id,
        "redirect_uri": redirect_uri,
    }


@router.get("/auth/oidc/callback")
async def oidc_callback(
    request: Request,
    response: Response,
    code: Optional[str] = None,
    state: Optional[str] = None,
    error: Optional[str] = None,
    error_description: Optional[str] = None,
    session: Session = Depends(get_db_session),
):
    """Handle OIDC authorization code callback from Keycloak.

    This endpoint exchanges the authorization code for tokens,
    validates the access token, syncs the user to DocForge,
    creates a session, and redirects to the dashboard.
    """
    # Handle error response from Keycloak
    if error:
        error_msg = error_description or error
        return RedirectResponse(
            url=f"/login?error={error_msg}",
            status_code=302,
        )

    if not code:
        return RedirectResponse(
            url="/login?error=Missing authorization code",
            status_code=302,
        )

    oidc_config = get_oidc_config()
    if not oidc_config.enabled or not oidc_config.is_valid():
        return RedirectResponse(
            url="/login?error=OIDC is not configured",
            status_code=302,
        )

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
                return RedirectResponse(
                    url=f"/login?error={error_msg}",
                    status_code=302,
                )

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
        redirect_response = RedirectResponse(url="/", status_code=302)
        redirect_response.set_cookie(
            key=SESSION_COOKIE_NAME,
            value=session_token,
            httponly=True,
            samesite="strict",
            secure=False,  # Set to True in production with HTTPS
            max_age=24 * 60 * 60,  # 24 hours
        )

        return redirect_response

    except OIDCValidationError as e:
        return RedirectResponse(
            url=f"/login?error=Token validation failed: {e}",
            status_code=302,
        )
    except httpx.HTTPError as e:
        return RedirectResponse(
            url=f"/login?error=Authentication service unavailable",
            status_code=302,
        )
    except ValueError as e:
        # User creation failed (auto-create disabled)
        return RedirectResponse(
            url=f"/login?error={e}",
            status_code=302,
        )
    except Exception as e:
        return RedirectResponse(
            url=f"/login?error=Authentication failed",
            status_code=302,
        )


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
# Template endpoints (protected)
# =============================================================================
@router.get("/templates", dependencies=[Depends(require_permission("template:read"))])
async def list_templates(
    format: Optional[str] = None,
    tag: Optional[str] = None,
    search: Optional[str] = None,
    services: Services = Depends(get_services),
):
    """List all templates."""
    if search:
        templates = services.template.search_templates(search)
    else:
        tags = [tag] if tag else None
        templates = services.template.list_templates(format=format, tags=tags)

    return [
        {
            "id": t.id,
            "name": t.name,
            "format": t.format,
            "description": t.description,
            "current_version": t.current_version,
            "tags": [tag.name for tag in t.tags],
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
@router.post("/extract/analyze", dependencies=[Depends(require_permission("template:create"))])
async def analyze_file(file: UploadFile = File(...), confidence: float = 0.5):
    """Analyze a file for patterns."""
    content = await file.read()
    text = content.decode("utf-8", errors="ignore")

    generator = TemplateGenerator()
    matches, variables = generator.analyze(text, confidence)

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
    }


@router.post("/extract/generate", dependencies=[Depends(require_permission("template:create"))])
async def generate_template_from_file(
    file: UploadFile = File(...),
    confidence: float = 0.7,
    name: Optional[str] = None,
    save: bool = False,
    services: Services = Depends(get_services),
):
    """Generate a template from a file."""
    content = await file.read()
    text = content.decode("utf-8", errors="ignore")

    generator = TemplateGenerator()
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
