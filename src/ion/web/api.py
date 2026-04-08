"""API routes for ION web interface."""

import asyncio
import json
import logging
import re

logger = logging.getLogger(__name__)
import secrets
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional, List, Dict, Generator
from dataclasses import dataclass
from urllib.parse import quote as url_quote
from fastapi import APIRouter, HTTPException, UploadFile, File, Form, Depends, Request, Response, Cookie
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
import httpx
from slowapi import Limiter
from slowapi.util import get_remote_address

from ion.core.config import get_config, get_oidc_config, get_gitlab_config, get_dfir_iris_config, get_ssl_verify
from ion.services.dfir_iris_service import get_dfir_iris_service
from ion.services.case_description import build_case_description
from ion.services.kibana_sync_helpers import (
    sync_new_case_to_kibana,
    sync_note_to_kibana,
    sync_case_update_to_kibana,
    get_kibana_case_url,
)
from ion.services.observable_extractor import extract_observables_from_raw

# Rate limiter - uses IP address as key
# Global default: 120 requests/minute per IP. Individual endpoints can override.
limiter = Limiter(key_func=get_remote_address, default_limits=["120/minute"])

# OIDC state cookie name for CSRF protection
OIDC_STATE_COOKIE_NAME = "oidc_state"
from ion.core.exceptions import (
    TemplateNotFoundError,
    VersionNotFoundError,
    ValidationError,
    RenderError,
)
from ion.storage.database import get_session_factory, get_engine
from ion.services.template_service import TemplateService
from ion.services.version_service import VersionService
from ion.services.render_service import RenderService
from ion.storage.document_repository import DocumentRepository
from ion.models.user import User
from ion.auth.service import AuthService
from ion.auth.dependencies import (
    get_current_user,
    get_current_user_optional,
    get_session_token,
    require_permission,
    require_admin,
    get_client_ip,
    get_auth_service,
    SESSION_COOKIE_NAME,
)
from ion.storage.auth_repository import AuditLogRepository
from ion.storage.user_repository import UserRepository, RoleRepository

router = APIRouter()


# Pydantic models for request/response
class TemplateCreate(BaseModel):
    name: str
    content: str = ""
    format: str = "markdown"
    description: Optional[str] = None
    tags: Optional[List[str]] = None
    document_type: Optional[str] = None
    sections: Optional[List[dict]] = None


class TemplateUpdate(BaseModel):
    name: Optional[str] = None
    content: Optional[str] = None
    format: Optional[str] = None
    description: Optional[str] = None
    message: Optional[str] = None
    author: Optional[str] = None
    document_type: Optional[str] = None
    sections: Optional[List[dict]] = None


class RenderRequest(BaseModel):
    data: dict = {}
    output_format: Optional[str] = None
    content_override: Optional[str] = None


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


class DocumentTagsUpdate(BaseModel):
    tags: List[str]


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
    employment_type: Optional[str] = "cs"  # cs, contractor, military, other


class UserUpdate(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None
    display_name: Optional[str] = None
    is_active: Optional[bool] = None
    employment_type: Optional[str] = None
    gitlab_username: Optional[str] = None
    elastic_uid: Optional[str] = None
    elastic_username: Optional[str] = None
    keycloak_sub: Optional[str] = None


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
    from ion.auth.dependencies import get_session_token
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
    focus_role = getattr(current_user, '_focus_role', None)
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "display_name": current_user.display_name,
        "is_active": current_user.is_active,
        "must_change_password": current_user.must_change_password,
        "last_login": current_user.last_login.isoformat() if current_user.last_login else None,
        "roles": [r.name for r in current_user.roles],
        "focus_role": focus_role.name if focus_role else None,
        "employment_type": getattr(current_user, "employment_type", None) or "cs",
        "permissions": list(set(
            p.name for r in current_user.effective_roles for p in r.permissions
        )),
        "gitlab_username": getattr(current_user, "gitlab_username", None),
        "elastic_username": getattr(current_user, "elastic_username", None),
        "elastic_uid": getattr(current_user, "elastic_uid", None),
        "keycloak_sub": getattr(current_user, "keycloak_sub", None),
    }


class FocusModeRequest(BaseModel):
    role: Optional[str] = None  # role name or null to clear


@router.post("/auth/focus-mode")
async def set_focus_mode(
    body: FocusModeRequest,
    session_token: Optional[str] = Depends(get_session_token),
    session: Session = Depends(get_db_session),
):
    """Switch focus mode to a specific role. Pass null to show all roles."""
    from ion.models.user import UserSession
    from ion.storage.auth_repository import SessionRepository

    if not session_token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    repo = SessionRepository(session)
    user_session = repo.get_valid_session(session_token)
    if not user_session:
        raise HTTPException(status_code=401, detail="Invalid session")

    user = user_session.user
    if body.role is None:
        # Clear focus — use all roles
        user_session.active_role_id = None
        session.commit()
        return {
            "focus_role": None,
            "permissions": list(set(
                p.name for r in user.roles for p in r.permissions
            )),
        }

    # Find the requested role among the user's assigned roles
    target_role = next((r for r in user.roles if r.name == body.role), None)
    if not target_role:
        raise HTTPException(status_code=400, detail=f"Role '{body.role}' is not assigned to you")

    user_session.active_role_id = target_role.id
    session.commit()

    return {
        "focus_role": target_role.name,
        "permissions": list(set(p.name for p in target_role.permissions)),
    }


class ProfileUpdate(BaseModel):
    """Self-service identity mapping update."""
    display_name: Optional[str] = None
    elastic_username: Optional[str] = None
    gitlab_username: Optional[str] = None


@router.put("/auth/profile")
async def update_own_profile(
    data: ProfileUpdate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Update the current user's own profile and identity mappings."""
    # Re-fetch from injected session to ensure change tracking works
    user = session.query(User).filter_by(id=current_user.id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    changes = {}
    if data.display_name is not None:
        user.display_name = data.display_name
        changes["display_name"] = data.display_name
    if data.elastic_username is not None:
        user.elastic_username = data.elastic_username or None
        user.elastic_uid = None
        changes["elastic_username"] = data.elastic_username
    if data.gitlab_username is not None:
        user.gitlab_username = data.gitlab_username or None
        changes["gitlab_username"] = data.gitlab_username

    if changes:
        session.commit()
        from ion.storage.auth_repository import AuditLogRepository
        try:
            AuditLogRepository(session).create(
                user_id=user.id,
                action="profile_updated",
                resource_type="user",
                resource_id=user.id,
                details=changes,
            )
            session.commit()
        except Exception:
            pass

    return {
        "message": "Profile updated",
        "elastic_username": user.elastic_username,
        "elastic_uid": user.elastic_uid,
        "gitlab_username": user.gitlab_username,
    }


@router.post("/auth/profile/resolve-elastic")
async def resolve_elastic_uid(
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Resolve the current user's Elastic/Kibana user profile UID.

    Tries: elastic_username → ION username → email prefix.
    Queries Kibana's user profile suggest API.
    """
    from ion.services.kibana_cases_service import get_kibana_cases_service

    kb_svc = get_kibana_cases_service()
    if not kb_svc.enabled:
        raise HTTPException(status_code=400, detail="Kibana integration is not configured")

    # Try each candidate username in order
    candidates = []
    if getattr(current_user, "elastic_username", None):
        candidates.append(current_user.elastic_username)
    candidates.append(current_user.username)
    if current_user.email:
        candidates.append(current_user.email.split("@")[0])
    if current_user.display_name:
        candidates.append(current_user.display_name)

    resolved_uid = None
    matched_username = None
    all_profiles = []

    for candidate in candidates:
        profiles = kb_svc.suggest_user_profiles(candidate)
        for profile in profiles:
            profile_user = profile.get("user", {})
            p_username = profile_user.get("username", "") if isinstance(profile_user, dict) else ""
            p_email = profile_user.get("email", "") if isinstance(profile_user, dict) else ""
            p_full = profile_user.get("full_name", "") if isinstance(profile_user, dict) else ""
            all_profiles.append({
                "uid": profile.get("uid"),
                "username": p_username,
                "email": p_email,
                "full_name": p_full,
            })

            # Exact match on username
            if p_username == candidate:
                resolved_uid = profile.get("uid")
                matched_username = p_username
                break
            # Match on email
            if p_email and p_email == current_user.email:
                resolved_uid = profile.get("uid")
                matched_username = p_username
                break

        if resolved_uid:
            break

    if resolved_uid:
        user = session.query(User).filter_by(id=current_user.id).first()
        if user:
            user.elastic_uid = resolved_uid
            if matched_username and not getattr(user, "elastic_username", None):
                user.elastic_username = matched_username
            session.commit()

    return {
        "resolved": resolved_uid is not None,
        "elastic_uid": resolved_uid,
        "matched_username": matched_username,
        "candidates_tried": candidates,
        "profiles_found": all_profiles,
    }


@router.post("/admin/users/resolve-elastic", dependencies=[Depends(require_permission("user:update"))])
async def bulk_resolve_elastic_uids(
    session: Session = Depends(get_db_session),
):
    """Admin: Resolve Elastic UIDs for all users that don't have one yet."""
    from ion.services.kibana_cases_service import get_kibana_cases_service

    kb_svc = get_kibana_cases_service()
    if not kb_svc.enabled:
        raise HTTPException(status_code=400, detail="Kibana integration is not configured")

    users = session.query(User).filter(
        User.is_active == True,  # noqa: E712
        User.elastic_uid == None,  # noqa: E711
    ).all()

    resolved = []
    failed = []

    for user in users:
        candidates = []
        if getattr(user, "elastic_username", None):
            candidates.append(user.elastic_username)
        candidates.append(user.username)
        if user.email:
            candidates.append(user.email.split("@")[0])

        uid = None
        for candidate in candidates:
            uid = kb_svc.resolve_user_uid(candidate)
            if uid:
                user.elastic_uid = uid
                if not getattr(user, "elastic_username", None):
                    user.elastic_username = candidate
                resolved.append({"user": user.username, "uid": uid, "matched_via": candidate})
                break

        if not uid:
            failed.append({"user": user.username, "candidates_tried": candidates})

    session.commit()

    return {
        "resolved_count": len(resolved),
        "failed_count": len(failed),
        "resolved": resolved,
        "failed": failed,
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

    # Build the redirect URI — use explicit base_url if configured,
    # otherwise auto-detect from request headers (fragile behind proxies)
    config = get_config()
    scheme = request.headers.get("X-Forwarded-Proto", request.url.scheme)
    if config.base_url:
        redirect_uri = f"{config.base_url}/api/auth/oidc/callback"
    else:
        host = request.headers.get("X-Forwarded-Host", request.url.netloc)
        redirect_uri = f"{scheme}://{host}/api/auth/oidc/callback"

    # Generate cryptographically secure state for CSRF protection
    state = secrets.token_urlsafe(32)

    # Store state in httponly cookie for validation on callback
    is_https = scheme == "https"
    cookie_secure = config.cookie_secure or is_https
    response.set_cookie(
        key=OIDC_STATE_COOKIE_NAME,
        value=state,
        httponly=True,
        samesite="lax",  # Lax needed for OAuth redirects
        secure=cookie_secure,
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
    validates the access token, syncs the user to ION,
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
    config = get_config()
    if config.base_url:
        redirect_uri = f"{config.base_url}/api/auth/oidc/callback"
    else:
        scheme = request.headers.get("X-Forwarded-Proto", request.url.scheme)
        host = request.headers.get("X-Forwarded-Host", request.url.netloc)
        redirect_uri = f"{scheme}://{host}/api/auth/oidc/callback"

    try:
        # Exchange authorization code for tokens
        logger.info(f"OIDC callback: exchanging code at {oidc_config.token_url} (redirect_uri={redirect_uri})")
        async with httpx.AsyncClient(verify=get_ssl_verify(oidc_config.verify_ssl)) as client:
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
                logger.warning(f"OIDC token exchange failed ({token_response.status_code}): {error_msg}")
                return error_redirect(error_msg)

            tokens = token_response.json()
            logger.info("OIDC callback: token exchange successful")

        # Validate the access token and extract user info
        from ion.auth.oidc import OIDCValidator, OIDCUserSync, OIDCValidationError
        from ion.storage.auth_repository import AuditLogRepository

        validator = OIDCValidator(oidc_config)
        token_data = await validator.validate_token_async(tokens["access_token"])
        logger.info(f"OIDC callback: token validated for {token_data.preferred_username} ({token_data.email})")

        # Sync user to ION database
        sync = OIDCUserSync(session, oidc_config)
        user = sync.sync_user(token_data)
        session.commit()
        logger.info(f"OIDC callback: user synced — {user.username} (id={user.id})")

        # Auto-resolve Elastic UID on login if not cached
        if not getattr(user, 'elastic_uid', None):
            try:
                from ion.services.kibana_cases_service import get_kibana_cases_service
                kb_svc = get_kibana_cases_service()
                if kb_svc.enabled:
                    lookup = getattr(user, 'elastic_username', None) or user.username
                    uid = kb_svc.resolve_user_uid(lookup)
                    if not uid and lookup != user.username:
                        uid = kb_svc.resolve_user_uid(user.username)
                    if uid:
                        user.elastic_uid = uid
                        if not getattr(user, 'elastic_username', None):
                            user.elastic_username = lookup
                        session.commit()
                        logger.info(f"OIDC callback: resolved elastic_uid for {user.username}: {uid}")
            except Exception as e:
                logger.debug(f"OIDC callback: elastic_uid resolve skipped: {e}")

        # Create a ION session for the user
        ip_address = get_client_ip(request)
        user_agent = request.headers.get("User-Agent")

        # Create session token with session rotation
        from ion.storage.auth_repository import SessionRepository

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
        logger.warning(f"OIDC token validation failed: {e}")
        return error_redirect(f"Token validation failed: {e}")
    except httpx.HTTPError as e:
        logger.error(f"OIDC token exchange HTTP error: {e}", exc_info=True)
        return error_redirect("Authentication service unavailable")
    except ValueError as e:
        # User creation failed (auto-create disabled)
        logger.warning(f"OIDC user sync failed: {e}")
        return error_redirect(str(e))
    except Exception as e:
        logger.error(f"Unexpected OIDC callback error: {e}", exc_info=True)
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
            "employment_type": getattr(u, "employment_type", None) or "cs",
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

    # Set employment type
    if user_create.employment_type and user_create.employment_type in ("cs", "contractor", "military", "other"):
        user.employment_type = user_create.employment_type

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
        "employment_type": getattr(user, "employment_type", None) or "cs",
        "gitlab_username": getattr(user, "gitlab_username", None) or "",
        "elastic_username": getattr(user, "elastic_username", None) or "",
        "elastic_uid": getattr(user, "elastic_uid", None) or "",
        "keycloak_sub": getattr(user, "keycloak_sub", None) or "",
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

    # Update employment type if provided
    if user_update.employment_type and user_update.employment_type in ("cs", "contractor", "military", "other"):
        user.employment_type = user_update.employment_type
    # Update external service identifiers
    if user_update.gitlab_username is not None:
        user.gitlab_username = user_update.gitlab_username or None
    if user_update.elastic_username is not None:
        user.elastic_username = user_update.elastic_username or None
        # Clear cached UID when username changes
        user.elastic_uid = None
    if user_update.elastic_uid is not None:
        user.elastic_uid = user_update.elastic_uid or None
    if user_update.keycloak_sub is not None:
        user.keycloak_sub = user_update.keycloak_sub or None

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
    from ion.services.template_service import CollectionNotFoundError
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
    from ion.services.template_service import CollectionNotFoundError
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
    from ion.services.template_service import CollectionNotFoundError
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
    from ion.services.template_service import CollectionNotFoundError
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
    from ion.services.template_service import CollectionNotFoundError
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
    document_type: Optional[str] = None,
    services: Services = Depends(get_services),
):
    """List all templates."""
    if search:
        templates = services.template.search_templates(search)
    else:
        tags = [tag] if tag else None
        templates = services.template.list_templates(
            format=format, tags=tags, collection_id=collection_id,
            document_type=document_type,
        )

    return [
        {
            "id": t.id,
            "name": t.name,
            "format": t.format,
            "description": t.description,
            "document_type": t.document_type,
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
            document_type=template.document_type,
            sections=template.sections,
        )
        services.session.commit()
        return {"id": t.id, "name": t.name, "message": "Template created successfully"}
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/templates/section-types", dependencies=[Depends(require_permission("template:read"))])
async def get_section_types():
    """Return all available section type definitions for the visual editor."""
    from ion.services.section_types import SECTION_TYPES
    return SECTION_TYPES


@router.get("/templates/{template_id}", dependencies=[Depends(require_permission("template:read"))])
async def get_template(template_id: int, services: Services = Depends(get_services)):
    """Get a template by ID."""
    try:
        t = services.template.get_template(template_id)
        sections_json = None
        has_sections = False
        if t.sections_json:
            try:
                sections_json = json.loads(t.sections_json)
                has_sections = True
            except (json.JSONDecodeError, TypeError):
                pass
        return {
            "id": t.id,
            "name": t.name,
            "content": t.content,
            "format": t.format,
            "description": t.description,
            "document_type": t.document_type,
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
            "sections": sections_json,
            "has_sections": has_sections,
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
            document_type=template.document_type,
            sections=template.sections,
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


@router.get("/document-types", dependencies=[Depends(require_permission("template:read"))])
async def list_document_types():
    """List available document types for templates."""
    from ion.services.soc_template_service import DOCUMENT_TYPES
    return {"types": DOCUMENT_TYPES}


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
        # If the user edited sections in the UI, override the rendered content
        if render_request.content_override and document:
            document.content = render_request.content_override
            content = render_request.content_override
        services.session.commit()

        return {
            "rendered": content,
            "document_id": document.id if document else None,
        }
    except TemplateNotFoundError:
        raise HTTPException(status_code=404, detail="Template not found")
    except RenderError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/templates/{template_id}/render-pdf", dependencies=[Depends(require_permission("template:read"))])
async def render_template_pdf(
    template_id: int,
    render_request: RenderRequest,
    services: Services = Depends(get_services),
):
    """Render a template and return the result as a PDF."""
    try:
        result = services.render.preview(template_id, data=render_request.data)
    except TemplateNotFoundError:
        raise HTTPException(status_code=404, detail="Template not found")
    except RenderError as e:
        raise HTTPException(status_code=400, detail=str(e))

    template = services.template.get_template(template_id)
    fmt = render_request.output_format or (template.format if template else "markdown")
    title = template.name if template else "Document"

    try:
        from ion.services.pdf_export_service import generate_pdf, _content_to_html
        body_html = _content_to_html(result, fmt)
        metadata = {
            "Template": title,
            "Format": fmt.title(),
        }
        pdf_bytes = generate_pdf(body_html, title=title, metadata=metadata)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    safe_name = re.sub(r'[^\w\s\-.]', '', title).strip() or "document"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{safe_name}.pdf"'},
    )


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

        from ion.engine.renderer import TemplateRenderer
        renderer = TemplateRenderer()
        extracted = renderer.extract_variables(t.content)

        import json as _json
        defined = []
        for v in t.variables:
            d = {
                "name": v.name,
                "var_type": v.var_type,
                "required": v.required,
                "default_value": v.default_value,
            }
            if v.options:
                try:
                    d["options"] = _json.loads(v.options)
                except (ValueError, TypeError):
                    pass
            defined.append(d)

        return {
            "extracted": list(extracted),
            "defined": defined,
        }
    except TemplateNotFoundError:
        raise HTTPException(status_code=404, detail="Template not found")


# Document endpoints
@router.post("/documents/upload", dependencies=[Depends(require_permission("document:create"))])
async def upload_document(
    file: UploadFile = File(...),
    name: Optional[str] = Form(None),
    output_format: Optional[str] = Form(None),
    tags: Optional[str] = Form(None),
    collection_id: Optional[int] = Form(None),
    services: Services = Depends(get_services),
):
    """Upload a file as a new document.

    Args:
        file: The file to upload.
        name: Optional document name (defaults to filename).
        output_format: Format (markdown, html, text). Auto-detected from extension if not provided.
        tags: Comma-separated tag names.
        collection_id: Optional collection/folder ID.
    """
    content = await file.read()
    if len(content) > 50 * 1024 * 1024:  # 50 MB
        raise HTTPException(status_code=400, detail="File too large (max 50 MB)")
    text = content.decode("utf-8", errors="ignore")

    # Determine document name
    doc_name = name or (file.filename or "Untitled Document")

    # Auto-detect format from file extension
    if not output_format and file.filename:
        ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
        format_map = {"md": "markdown", "html": "html", "htm": "html", "csv": "csv", "txt": "text"}
        output_format = format_map.get(ext, "text")
    output_format = output_format or "text"

    document = services.document_repo.create(
        name=doc_name,
        rendered_content=text,
        output_format=output_format,
    )

    if collection_id:
        document.collection_id = collection_id
        services.session.flush()

    # Handle tags
    tag_names = []
    if tags:
        tag_names = [t.strip() for t in tags.split(",") if t.strip()]
    if tag_names:
        services.document_repo.set_tags(document, tag_names)

    services.session.commit()

    return {
        "id": document.id,
        "name": document.name,
        "output_format": document.output_format,
        "collection_id": document.collection_id,
        "tags": [t.name for t in document.tags],
        "current_version": document.current_version,
        "created_at": document.created_at.isoformat() if document.created_at else None,
    }


class DocumentCreateRequest(BaseModel):
    name: str
    content: str
    output_format: str = "markdown"
    tags: Optional[List[str]] = None
    collection_id: Optional[int] = None


@router.post("/documents/create", dependencies=[Depends(require_permission("document:create"))])
async def create_document(req: DocumentCreateRequest, services: Services = Depends(get_services)):
    """Create a document from content (no file upload needed)."""
    document = services.document_repo.create(
        name=req.name,
        rendered_content=req.content,
        output_format=req.output_format,
    )
    if req.collection_id:
        document.collection_id = req.collection_id
        services.session.flush()
    if req.tags:
        services.document_repo.set_tags(document, req.tags)
    services.session.commit()
    return {
        "id": document.id,
        "name": document.name,
        "output_format": document.output_format,
        "created_at": document.created_at.isoformat() if document.created_at else None,
    }


@router.put("/documents/{document_id}/tags", dependencies=[Depends(require_permission("document:update"))])
async def update_document_tags(
    document_id: int,
    body: DocumentTagsUpdate,
    services: Services = Depends(get_services),
):
    """Set tags on a document (replaces existing tags)."""
    document = services.document_repo.get_by_id(document_id)
    if not document:
        raise HTTPException(status_code=404, detail="Document not found")

    tags = services.document_repo.set_tags(document, body.tags)
    services.session.commit()

    return {
        "id": document.id,
        "tags": [t.name for t in tags],
    }


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
            "source_template_document_type": d.source_template.document_type if d.source_template else None,
            "current_version": d.current_version,
            "status": d.status,
            "collection_id": d.collection_id,
            "collection_name": d.collection.name if d.collection else None,
            "tags": [t.name for t in d.tags] if d.tags else [],
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
        "tags": [t.name for t in document.tags] if document.tags else [],
        "created_at": document.created_at.isoformat() if document.created_at else None,
        "updated_at": document.updated_at.isoformat() if document.updated_at else None,
    }


@router.get("/documents/{document_id}/pdf", dependencies=[Depends(require_permission("document:read"))])
async def export_document_pdf(document_id: int, services: Services = Depends(get_services)):
    """Export a document as a professionally styled PDF."""
    document = services.render.get_document(document_id)
    if not document:
        raise HTTPException(status_code=404, detail="Document not found")
    try:
        from ion.services.pdf_export_service import document_to_pdf
        pdf_bytes = document_to_pdf(document)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    safe_name = re.sub(r'[^\w\s\-.]', '', document.name).strip() or "document"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{safe_name}.pdf"'},
    )


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


# Health check endpoint (no auth required)
@router.get("/health")
async def health_check():
    """Simple health check for Docker/load balancers."""
    from ion.storage.database import get_engine
    from ion import __version__
    engine = get_engine()
    db_type = engine.dialect.name  # "postgresql" or "sqlite"
    return {"status": "ok", "database": db_type, "version": __version__}


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
                from ion.services.gitlab_service import GitLabService
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
                from ion.services.elasticsearch_service import ElasticsearchService
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

    focus_role = getattr(current_user, '_focus_role', None)
    return {
        "user": {
            "id": current_user.id,
            "username": current_user.username,
            "display_name": current_user.display_name,
            "email": current_user.email,
            "roles": [r.name for r in current_user.roles],
            "focus_role": focus_role.name if focus_role else None,
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


@router.get("/dashboard/team-metrics", dependencies=[Depends(require_permission("alert:read"))])
async def get_team_metrics(
    current_user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
):
    """Team performance metrics for Lead dashboard."""
    from sqlalchemy import func as sqlfunc
    from ion.models.alert_triage import AlertCase, AlertCaseStatus, AlertTriage, AlertTriageStatus

    now = datetime.utcnow()

    # Open cases count
    open_cases = session.query(sqlfunc.count(AlertCase.id)).filter(
        AlertCase.status != AlertCaseStatus.CLOSED
    ).scalar() or 0

    # Unassigned open alerts count
    unassigned_alerts = session.query(sqlfunc.count(AlertTriage.id)).filter(
        AlertTriage.case_id.is_(None),
        AlertTriage.status == AlertTriageStatus.OPEN,
    ).scalar() or 0

    # MTTR - mean time to resolution (last 30 days)
    thirty_days_ago = now - timedelta(days=30)
    closed_cases_30d = session.query(AlertCase).filter(
        AlertCase.closed_at >= thirty_days_ago,
        AlertCase.closed_at.isnot(None),
    ).all()

    mttr = None
    if closed_cases_30d:
        durations = [(c.closed_at - c.created_at).total_seconds() / 3600 for c in closed_cases_30d]
        mttr = round(sum(durations) / len(durations), 1)

    # Closure rate (7 days)
    seven_days_ago = now - timedelta(days=7)
    created_7d = session.query(sqlfunc.count(AlertCase.id)).filter(
        AlertCase.created_at >= seven_days_ago
    ).scalar() or 0
    closed_7d = session.query(sqlfunc.count(AlertCase.id)).filter(
        AlertCase.closed_at >= seven_days_ago
    ).scalar() or 0

    # Cases by severity (open only)
    severity_rows = session.query(
        AlertCase.severity, sqlfunc.count(AlertCase.id)
    ).filter(
        AlertCase.status != AlertCaseStatus.CLOSED
    ).group_by(AlertCase.severity).all()
    severity_counts = dict(severity_rows)

    # Cases by assignee
    assignee_rows = session.query(
        AlertCase.assigned_to_id,
        sqlfunc.count(AlertCase.id),
    ).filter(
        AlertCase.status != AlertCaseStatus.CLOSED
    ).group_by(AlertCase.assigned_to_id).all()

    # Closed in 7d per assignee
    closed_by_assignee_rows = session.query(
        AlertCase.assigned_to_id,
        sqlfunc.count(AlertCase.id),
    ).filter(
        AlertCase.closed_at >= seven_days_ago,
    ).group_by(AlertCase.assigned_to_id).all()
    closed_by_assignee = dict(closed_by_assignee_rows)

    cases_by_assignee = []
    for user_id, open_count in assignee_rows:
        if user_id is None:
            cases_by_assignee.append({
                "username": "Unassigned",
                "display_name": "Unassigned",
                "open_count": open_count,
                "closed_7d": closed_by_assignee.get(None, 0),
            })
        else:
            user = session.query(User).filter_by(id=user_id).first()
            cases_by_assignee.append({
                "username": user.username if user else "Unknown",
                "display_name": user.display_name if user else "Unknown",
                "open_count": open_count,
                "closed_7d": closed_by_assignee.get(user_id, 0),
            })

    # Recent closures (last 10)
    recent_closures_q = session.query(AlertCase).filter(
        AlertCase.closed_at.isnot(None)
    ).order_by(AlertCase.closed_at.desc()).limit(10).all()

    recent_closures = []
    for c in recent_closures_q:
        closed_by_user = session.query(User).filter_by(id=c.closed_by_id).first() if c.closed_by_id else None
        recent_closures.append({
            "id": c.id,
            "case_number": c.case_number,
            "title": c.title,
            "severity": c.severity,
            "closure_reason": c.closure_reason,
            "closed_by": closed_by_user.display_name if closed_by_user else "Unknown",
            "closed_at": c.closed_at.isoformat() if c.closed_at else None,
        })

    return {
        "open_cases": open_cases,
        "unassigned_alerts": unassigned_alerts,
        "mttr_hours": mttr,
        "closure_rate_7d": round(closed_7d / created_7d * 100, 1) if created_7d > 0 else None,
        "created_7d": created_7d,
        "closed_7d": closed_7d,
        "cases_by_severity": {
            "critical": severity_counts.get("critical", 0),
            "high": severity_counts.get("high", 0),
            "medium": severity_counts.get("medium", 0),
            "low": severity_counts.get("low", 0),
        },
        "cases_by_assignee": cases_by_assignee,
        "recent_closures": recent_closures,
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

from ion.services.gitlab_service import (
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
    from ion.core.config import get_config, set_config
    import os

    # Get current config
    config = get_config()

    # Update GitLab settings
    config.gitlab_enabled = True
    config.gitlab_url = config_update.url
    config.gitlab_token = config_update.token
    config.gitlab_project_id = config_update.project_id

    # Save to config file
    data_dir = os.environ.get("ION_DATA_DIR")
    if data_dir:
        config_path = Path(data_dir) / ".ion" / "config.json"
    else:
        config_path = Path.cwd() / ".ion" / "config.json"

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
    from ion.core.config import get_config
    import os

    config = get_config()
    config.gitlab_enabled = False
    config.gitlab_url = ""
    config.gitlab_token = ""
    config.gitlab_project_id = ""

    data_dir = os.environ.get("ION_DATA_DIR")
    if data_dir:
        config_path = Path(data_dir) / ".ion" / "config.json"
    else:
        config_path = Path.cwd() / ".ion" / "config.json"

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
    scope: Optional[str] = None,
    author_username: Optional[str] = None,
    assignee_username: Optional[str] = None,
    my_issues: bool = False,
    current_user: User = Depends(require_permission("template:read")),
):
    """List GitLab issues.

    Args:
        state: Filter by state ("opened", "closed", "all")
        labels: Comma-separated list of labels
        search: Search in title and description
        per_page: Number of issues per page
        page: Page number
        scope: GitLab scope filter ("created_by_me", "assigned_to_me", "all")
        author_username: Filter by author GitLab username
        assignee_username: Filter by assignee GitLab username
        my_issues: If true, auto-filter to current user's GitLab username
    """
    service = get_gitlab_service()
    try:
        label_list = labels.split(",") if labels else None

        # Auto-filter to current user's GitLab username if requested
        # Fetches both assigned-to and created-by, then merges (deduped)
        if my_issues and not author_username and not assignee_username:
            gl_user = getattr(current_user, 'gitlab_username', None) or current_user.username
            assigned, authored = await asyncio.gather(
                service.list_issues(
                    state=state, labels=label_list, search=search,
                    per_page=per_page, page=page,
                    assignee_username=gl_user, scope=scope,
                ),
                service.list_issues(
                    state=state, labels=label_list, search=search,
                    per_page=per_page, page=page,
                    author_username=gl_user, scope=scope,
                ),
            )
            seen = set()
            issues = []
            for issue in assigned + authored:
                if issue.id not in seen:
                    seen.add(issue.id)
                    issues.append(issue)
            issues.sort(key=lambda i: i.updated_at, reverse=True)
            return {"issues": [issue.to_dict() for issue in issues]}

        issues = await service.list_issues(
            state=state,
            labels=label_list,
            search=search,
            per_page=per_page,
            page=page,
            author_username=author_username,
            assignee_username=assignee_username,
            scope=scope,
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
        description = issue_data.description or ""
        sudo_user = None
        if service.sudo_enabled:
            # Impersonate: GitLab natively shows the real user
            sudo_user = current_user.username
        else:
            # Text attribution fallback
            display = current_user.display_name or current_user.username
            description += f"\n\n---\n*Created by {display} via ION*"
        issue = await service.create_issue(
            title=issue_data.title,
            description=description,
            labels=issue_data.labels,
            assignee_ids=issue_data.assignee_ids,
            milestone_id=issue_data.milestone_id,
            due_date=issue_data.due_date,
            sudo_user=sudo_user,
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
        sudo_user = None
        if service.sudo_enabled:
            # Impersonate: GitLab natively shows the real user
            sudo_user = current_user.username
            body = comment_data.body
        else:
            # Text attribution fallback
            display = current_user.display_name or current_user.username
            body = f"**{display}** (via ION):\n\n{comment_data.body}"
        comment = await service.add_issue_comment(
            issue_iid=issue_iid,
            body=body,
            sudo_user=sudo_user,
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

from ion.services.elasticsearch_service import ElasticsearchService, ElasticsearchError
from ion.core.config import get_elasticsearch_config


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
    config_path = Path.cwd() / ".ion" / "config.json"

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
    limit: int = 500,
    include_closed: bool = False,
    time_from: Optional[str] = None,
    time_to: Optional[str] = None,
    current_user: User = Depends(require_permission("alert:read")),
):
    """Fetch alerts from Elasticsearch.

    Args:
        hours: Number of hours to look back (default 24, ignored if time_from set)
        severity: Filter by severity (critical, high, medium, low, info)
        status: Filter by status (open, acknowledged, closed)
        limit: Maximum number of alerts (default 500)
        include_closed: Include closed/resolved alerts (default False)
        time_from: Absolute start time (ISO 8601). Overrides hours.
        time_to: Absolute end time (ISO 8601). Defaults to now.
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
            include_closed=include_closed,
            time_from=time_from,
            time_to=time_to,
        )
        return {
            "alerts": [a.to_dict() for a in alerts],
            "total": len(alerts),
            "hours": hours,
            "enabled": True,
            "configured": True,
        }
    except ElasticsearchError as e:
        logger.warning("Elasticsearch connection error fetching alerts: %s", e)
        return {
            "alerts": [],
            "total": 0,
            "hours": hours,
            "enabled": True,
            "configured": True,
            "connection_error": True,
            "message": str(e),
        }


@router.get("/elasticsearch/alerts/mitre-stats")
async def get_mitre_stats(
    hours: int = 24,
    current_user: User = Depends(require_permission("alert:read")),
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
        logger.warning("Elasticsearch connection error fetching MITRE stats: %s", e)
        return {
            "techniques": {},
            "tactics": {},
            "total_alerts_with_mitre": 0,
            "time_range_hours": hours,
            "connection_error": True,
            "message": str(e),
        }


# ============================================================================
# Alert Triage, Comments & Case Management Endpoints
# ============================================================================

from ion.models.alert_triage import (
    AlertTriage,
    AlertTriageStatus,
    AlertCase,
    AlertCaseStatus,
    CaseClosureReason,
    KnownFalsePositive,
    Note,
    NoteEntityType,
)


OBSERVABLE_TYPES = {"hostname", "source_ip", "destination_ip", "url", "domain", "user_account"}


class TriageUpdate(BaseModel):
    status: Optional[str] = None
    assigned_to_id: Optional[int] = None
    assigned_to_name: Optional[str] = None  # ES user name (used when ES user mapping is configured)
    priority: Optional[str] = None
    case_id: Optional[int] = None
    analyst_notes: Optional[str] = None
    observables: Optional[List[dict]] = None
    mitre_techniques: Optional[List[dict]] = None


class AlertClosureRequest(BaseModel):
    """Request body for closing an alert with a specific closure type."""
    closure_type: str  # "benign", "escalated", "false_positive"
    notes: Optional[str] = None
    create_kfp: Optional[bool] = False
    kfp_title: Optional[str] = None
    kfp_description: Optional[str] = None
    match_rules: Optional[List[str]] = None
    match_hosts: Optional[List[str]] = None
    match_users: Optional[List[str]] = None
    match_ips: Optional[List[str]] = None


class BulkTriageUpdate(BaseModel):
    """Bulk update multiple alerts at once."""
    alert_ids: List[str]
    status: Optional[str] = None
    assigned_to_id: Optional[int] = None
    assigned_to_name: Optional[str] = None  # ES user name (used when ES user mapping is configured)
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
    closure_reason: Optional[str] = None
    closure_notes: Optional[str] = None


@router.get("/elasticsearch/alerts/cases")
async def list_cases(
    status: Optional[str] = None,
    current_user: User = Depends(require_permission("case:read")),
    session: Session = Depends(get_db_session),
):
    """List all investigation cases."""
    query = session.query(AlertCase)
    if status:
        query = query.filter(AlertCase.status == status)
    cases = query.order_by(AlertCase.created_at.desc()).all()

    # Get DFIR-IRIS service for URL generation
    iris_service = get_dfir_iris_service()

    def get_iris_url(case):
        if case.dfir_iris_case_id:
            return iris_service.get_case_url(case.dfir_iris_case_id)
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
                "kibana_url": get_kibana_case_url(c.kibana_case_id),
                "dfir_iris_case_id": c.dfir_iris_case_id,
                "dfir_iris_url": get_iris_url(c),
                "closure_reason": c.closure_reason,
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


def _build_kfp_es_doc(kfp) -> dict:
    """Build the Elasticsearch document from a KnownFalsePositive ORM object."""
    now = datetime.now(timezone.utc).isoformat()
    return {
        "id": kfp.id,
        "@timestamp": now,
        "title": kfp.title,
        "description": kfp.description,
        "match_hosts": kfp.match_hosts or [],
        "match_users": kfp.match_users or [],
        "match_ips": kfp.match_ips or [],
        "match_rules": kfp.match_rules or [],
        "is_active": kfp.is_active,
        "source_case_id": kfp.source_case_id,
        "created_by": kfp.created_by.username if kfp.created_by else None,
        "created_at": kfp.created_at.isoformat() if kfp.created_at else None,
        "updated_at": kfp.updated_at.isoformat() if kfp.updated_at else None,
    }


async def _sync_kfp_to_es(kfp):
    """Sync a KFP entry to Elasticsearch. Logs warnings on failure, never raises."""
    try:
        es_config = get_elasticsearch_config()
        if not es_config.get("enabled"):
            return
        es_service = get_elasticsearch_service()
        if not es_service.is_configured:
            return
        doc = _build_kfp_es_doc(kfp)
        await es_service.index_kfp(doc)
    except Exception as e:
        _case_es_logger.warning("Failed to sync KFP %s to ES: %s", getattr(kfp, "id", "?"), e)


_RULE_CATEGORY_KEYWORDS = {
    "Credential Access": ["brute force", "credential", "kerberoast", "kerberos", "lsass", "mimikatz", "password", "ntlm"],
    "Execution": ["powershell", "script", "command", "wmi", "macro", "malware", "trojan"],
    "Lateral Movement": ["lateral", "psexec", "rdp", "remote", "smb", "wmi"],
    "Exfiltration": ["exfiltration", "upload", "data loss", "transfer"],
    "Persistence": ["persistence", "scheduled task", "registry", "service", "startup"],
    "Privilege Escalation": ["privilege", "escalation", "uac", "bypass", "admin"],
    "Command and Control": ["c2", "beacon", "dns tunnel", "dga", "cobalt", "ssl"],
    "Defense Evasion": ["evasion", "log clear", "firewall", "disable", "tamper"],
    "Network Security": ["port scan", "scan", "firewall rule"],
    "Initial Access": ["phishing", "email", "login", "geo"],
    "Impact": ["ransomware", "encrypt", "wiper", "destroy"],
}


def _classify_rule_category(rules: list[str] | None) -> str:
    """Classify rules into a security domain category based on keywords."""
    if not rules:
        return "General"
    combined = " ".join(rules).lower()
    for category, keywords in _RULE_CATEGORY_KEYWORDS.items():
        if any(kw in combined for kw in keywords):
            return category
    return "General"


def _build_kfp_registry_content(category: str, kfps: list) -> str:
    """Build the full markdown content for a KFP registry document."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    active = [k for k in kfps if k.is_active]
    inactive = [k for k in kfps if not k.is_active]

    lines = [
        f"# Known False Positives Registry — {category}",
        "",
        f"> **Last updated:** {now} | **Active entries:** {len(active)} | **Total:** {len(kfps)}",
        "",
        "## Active Entries",
        "",
    ]

    if active:
        lines.append("| ID | Title | Rules | Hosts | Users | IPs | Source Case | Created |")
        lines.append("|---:|-------|-------|-------|-------|-----|------------|---------|")
        for k in active:
            rules = ", ".join(k.match_rules) if k.match_rules else "—"
            hosts = ", ".join(k.match_hosts) if k.match_hosts else "—"
            users = ", ".join(k.match_users) if k.match_users else "—"
            ips = ", ".join(k.match_ips) if k.match_ips else "—"
            case = f"Case #{k.source_case_id}" if k.source_case_id else "—"
            created = k.created_at.strftime("%Y-%m-%d") if k.created_at else "—"
            lines.append(f"| {k.id} | {k.title} | {rules} | {hosts} | {users} | {ips} | {case} | {created} |")
    else:
        lines.append("*No active entries.*")

    lines.append("")

    # Details for each active entry
    for k in active:
        lines.append(f"### KFP-{k.id:04d}: {k.title}")
        lines.append("")
        lines.append(k.description or "*No description.*")
        lines.append("")
        by = k.created_by.username if k.created_by else "Unknown"
        lines.append(f"*Created by {by} on {k.created_at.strftime('%Y-%m-%d %H:%M UTC') if k.created_at else 'N/A'}*")
        lines.append("")
        lines.append("---")
        lines.append("")

    if inactive:
        lines.append("## Inactive / Retired Entries")
        lines.append("")
        lines.append("| ID | Title | Deactivated |")
        lines.append("|---:|-------|-------------|")
        for k in inactive:
            updated = k.updated_at.strftime("%Y-%m-%d") if k.updated_at else "—"
            lines.append(f"| {k.id} | {k.title} | {updated} |")
        lines.append("")

    lines.append("---")
    lines.append("*Auto-generated by ION Known False Positive Registry*")

    return "\n".join(lines)


def _create_kfp_document(session: Session, kfp, username: str) -> int | None:
    """Create or update the consolidated KFP registry document for this KFP's rule category.

    Each rule category gets its own collection and a single registry document
    listing all KFP entries in that category.

    Returns the document ID, or None on failure.
    """
    try:
        from ion.models.template import Collection
        from ion.models.document import Document

        category = _classify_rule_category(kfp.match_rules)
        collection_name = f"Known False Positives — {category}"
        doc_name = f"KFP Registry — {category}"

        # Get or create collection for this category
        collection = session.query(Collection).filter_by(name=collection_name).first()
        if not collection:
            collection = Collection(
                name=collection_name,
                description=f"Known False Positive registry for {category} detection rules",
            )
            session.add(collection)
            session.flush()

        # Get all KFPs in this category to rebuild the full document
        all_kfps = session.query(KnownFalsePositive).all()
        category_kfps = [
            k for k in all_kfps
            if _classify_rule_category(k.match_rules) == category
        ]

        content = _build_kfp_registry_content(category, category_kfps)
        input_data = json.dumps({
            "category": category,
            "kfp_ids": [k.id for k in category_kfps],
        })

        doc_repo = DocumentRepository(session)

        # Find existing registry document for this category (by name — unique per category)
        existing = session.query(Document).filter(
            Document.name == doc_name,
            Document.status == "active",
        ).first()

        if existing:
            # Amend the existing document with updated content
            existing.collection_id = collection.id
            doc_repo.amend(
                document=existing,
                rendered_content=content,
                input_data=input_data,
                amendment_reason=f"Added KFP-{kfp.id:04d}: {kfp.title}",
                amended_by=username,
            )
            session.flush()
            return existing.id
        else:
            # Create new registry document
            document = doc_repo.create(
                name=doc_name,
                rendered_content=content,
                output_format="markdown",
                input_data=input_data,
            )
            document.collection_id = collection.id
            session.flush()
            return document.id
    except Exception as e:
        _case_es_logger.warning("Failed to create KFP document for KFP %s: %s", getattr(kfp, "id", "?"), e)
        return None


@router.post("/elasticsearch/alerts/cases")
async def create_case(
    data: CaseCreate,
    current_user: User = Depends(require_permission("case:create")),
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
        assigned_to_id=data.assigned_to_id if data.assigned_to_id else current_user.id,
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
                    status=AlertTriageStatus.ACKNOWLEDGED,
                )
                session.add(triage)
                session.flush()
            triage.case_id = new_case.id
            linked += 1

    # Auto-populate legacy triage observables and collect raw data for enrichment
    raw_data_list = []

    if data.alert_contexts:
        context_map = {ctx.alert_id: ctx for ctx in data.alert_contexts}
        for alert_id in (data.alert_ids or []):
            ctx = context_map.get(alert_id)
            if not ctx:
                continue
            triage = session.query(AlertTriage).filter_by(es_alert_id=alert_id).first()
            if triage:
                _populate_triage_observables(triage, ctx.host, ctx.user, ctx.raw_data)
            if ctx.raw_data:
                raw_data_list.append(ctx.raw_data)
            else:
                logger.info("create_case: alert %s has no raw_data in context", alert_id)
    else:
        logger.info("create_case: no alert_contexts provided")

    logger.info("create_case: collected %d raw_data items for enrichment", len(raw_data_list))

    # Notify assignee
    if data.assigned_to_id and data.assigned_to_id != current_user.id:
        try:
            from ion.web.notification_api import create_notification
            create_notification(
                session, data.assigned_to_id,
                source="case_assigned",
                title=f"Case assigned: {case_number}",
                body=data.title[:120],
                url="/cases",
                source_id=str(case_number),
            )
        except Exception as _ne:
            logger.debug("Failed to create case notification: %s", _ne)

    session.commit()
    session.refresh(new_case)

    # Extract, normalize, enrich, and link observables to case
    from ion.services.observable_service import get_observable_service
    obs_service = get_observable_service(session)
    enriched_observables = await obs_service.extract_enrich_for_case(
        case_id=new_case.id,
        raw_data_list=raw_data_list,
    )

    # Store enriched observables on the case (for display and Kibana sync)
    case_observables = enriched_observables or []
    logger.info("create_case: %d observables enriched for case %s", len(case_observables), case_number)
    if case_observables:
        new_case.observables = case_observables
        session.commit()

    await _sync_case_to_es(new_case, session)

    # Resolve Kibana assignee UID for case creation
    create_assignee_uid = None
    if data.assigned_to_id:
        assignee_user = session.query(User).filter_by(id=data.assigned_to_id).first()
        if assignee_user:
            if assignee_user.elastic_uid:
                create_assignee_uid = assignee_user.elastic_uid
            else:
                try:
                    from ion.services.kibana_cases_service import get_kibana_cases_service
                    kb_svc = get_kibana_cases_service()
                    if kb_svc.enabled:
                        # Try elastic_username first, then ION username
                        lookup_name = getattr(assignee_user, 'elastic_username', None) or assignee_user.username
                        uid = kb_svc.resolve_user_uid(lookup_name)
                        if not uid and lookup_name != assignee_user.username:
                            uid = kb_svc.resolve_user_uid(assignee_user.username)
                        if uid:
                            create_assignee_uid = uid
                            assignee_user.elastic_uid = uid
                            session.commit()
                except Exception:
                    pass

    # Sync to Kibana Cases if enabled
    kibana_url = None
    kibana_result = sync_new_case_to_kibana(
        case_number=case_number,
        title=data.title,
        description=data.description,
        severity=data.severity,
        affected_hosts=data.affected_hosts,
        affected_users=data.affected_users,
        evidence_summary=data.evidence_summary,
        observables=case_observables,
        alert_ids=data.alert_ids,
        triggered_rules=data.triggered_rules,
        assignee_elastic_uid=create_assignee_uid,
    )
    if kibana_result:
        new_case.kibana_case_id = kibana_result["kibana_case_id"]
        new_case.kibana_case_version = kibana_result["kibana_case_version"]
        kibana_url = kibana_result["kibana_url"]
        session.commit()

    # Auto-check KFP registry for matches
    fp_suggestions = _match_known_false_positives(
        session,
        hosts=data.affected_hosts,
        users=data.affected_users,
        ips=[o["value"] for o in (case_observables or []) if o.get("type") in ("source_ip", "destination_ip")],
        rules=data.triggered_rules,
    )

    # Auto-close case if strong KFP match (rules + at least one other field)
    auto_closed = False
    auto_closed_kfp = None
    for fp in fp_suggestions:
        matched = fp.get("matched_fields", [])
        if "rules" in matched and len(matched) >= 2:
            # Strong match — auto-close the case
            new_case.status = AlertCaseStatus.CLOSED
            new_case.closure_reason = "false_positive"
            new_case.closed_by_id = current_user.id
            new_case.closed_at = datetime.utcnow()

            # Set all linked triage entries to CLOSED
            for triage_entry in new_case.triage_entries:
                triage_entry.status = AlertTriageStatus.CLOSED

            # Add auto-closure note
            auto_note = Note(
                entity_type=NoteEntityType.CASE,
                entity_id=str(new_case.id),
                user_id=current_user.id,
                content=f"**Auto-closed as Known False Positive**\n\nMatched KFP: {fp['title']} (ID: {fp['id']})\nMatched fields: {', '.join(matched)}",
            )
            session.add(auto_note)
            session.commit()

            if new_case.kibana_case_id:
                sync_note_to_kibana(new_case.kibana_case_id, current_user.username, auto_note.content)

            auto_closed = True
            auto_closed_kfp = fp
            break

    return {
        "id": new_case.id,
        "case_number": new_case.case_number,
        "title": new_case.title,
        "status": new_case.status.value if hasattr(new_case.status, "value") else new_case.status,
        "linked_alerts": linked,
        "observables": new_case.observables or [],
        "kibana_case_id": new_case.kibana_case_id,
        "kibana_url": kibana_url,
        "dfir_iris_case_id": new_case.dfir_iris_case_id,
        "dfir_iris_url": None,
        "fp_suggestions": fp_suggestions,
        "auto_closed": auto_closed,
        "auto_closed_kfp": auto_closed_kfp,
    }


@router.post("/elasticsearch/alerts/cases/{case_id}/notes")
async def add_case_note(
    case_id: int,
    data: CaseNoteCreate,
    current_user: User = Depends(require_permission("case:update")),
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
    sync_note_to_kibana(case.kibana_case_id, current_user.username, data.content)

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
    current_user: User = Depends(require_permission("case:read")),
    session: Session = Depends(get_db_session),
):
    """Get case detail with linked alerts."""
    case = session.query(AlertCase).filter_by(id=case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    # Get Kibana URL if available
    kibana_url = get_kibana_case_url(case.kibana_case_id)

    # Get DFIR-IRIS URL if available
    dfir_iris_url = None
    if case.dfir_iris_case_id:
        try:
            iris_svc = get_dfir_iris_service()
            dfir_iris_url = iris_svc.get_case_url(case.dfir_iris_case_id)
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
        "dfir_iris_case_id": case.dfir_iris_case_id,
        "dfir_iris_url": dfir_iris_url,
        "closure_reason": case.closure_reason,
        "closure_notes": case.closure_notes,
        "closed_by": case.closed_by.username if case.closed_by else None,
        "closed_at": case.closed_at.isoformat() if case.closed_at else None,
        "created_at": case.created_at.isoformat() if case.created_at else None,
        "updated_at": case.updated_at.isoformat() if case.updated_at else None,
        "alerts": [
            {
                "es_alert_id": t.es_alert_id,
                "status": t.status.value if hasattr(t.status, "value") else t.status,
                "priority": t.priority,
                "observables": t.observables or [],
                "mitre_techniques": t.mitre_techniques or [],
                "analyst_notes": t.analyst_notes,
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
    current_user: User = Depends(require_permission("case:update")),
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
    if data.assigned_to_id is not None:
        old_assignee = case.assigned_to_id
        case.assigned_to_id = data.assigned_to_id
        # Notify new assignee
        if data.assigned_to_id and data.assigned_to_id != current_user.id and data.assigned_to_id != old_assignee:
            try:
                from ion.web.notification_api import create_notification
                create_notification(
                    session, data.assigned_to_id,
                    source="case_assigned",
                    title=f"Case reassigned: {case.case_number}",
                    body=case.title[:120] if case.title else "",
                    url="/cases",
                    source_id=str(case.case_number),
                )
            except Exception as _ne:
                logger.debug("Failed to create reassign notification: %s", _ne)
        # Commit the assignment immediately so it persists even if Kibana sync fails
        session.commit()
    _synced_alert_ids = []
    _mapped_triage = None
    if data.status is not None:
        old_status = case.status.value if hasattr(case.status, "value") else case.status
        new_status = data.status
        # Closing: require closure_reason
        if new_status == "closed" and old_status != "closed":
            if not data.closure_reason:
                raise HTTPException(
                    status_code=400,
                    detail="closure_reason is required when closing a case",
                )
            valid_reasons = {r.value for r in CaseClosureReason}
            if data.closure_reason not in valid_reasons:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid closure_reason. Must be one of: {', '.join(sorted(valid_reasons))}",
                )
            case.closure_reason = data.closure_reason
            case.closure_notes = data.closure_notes
            case.closed_by_id = current_user.id
            case.closed_at = datetime.utcnow()

            # Add closure note to the case journal and sync to Kibana
            reason_label = data.closure_reason.replace("_", " ").title()
            closure_note = Note(
                entity_type=NoteEntityType.CASE,
                entity_id=str(case_id),
                user_id=current_user.id,
                content=f"**Case closed as {reason_label}**\n\nNotes: {data.closure_notes or 'N/A'}",
            )
            session.add(closure_note)
            if case.kibana_case_id:
                sync_note_to_kibana(case.kibana_case_id, current_user.username, closure_note.content)
        # Reopening: clear closure fields
        elif new_status != "closed" and old_status == "closed":
            case.closure_reason = None
            case.closure_notes = None
            case.closed_by_id = None
            case.closed_at = None
        case.status = new_status

        # Sync linked alert triage statuses to match case status
        _case_to_triage = {
            "open": "open",
            "acknowledged": "acknowledged",
            "closed": "closed",
        }
        _mapped_triage = _case_to_triage.get(new_status)
        _synced_alert_ids = []
        if _mapped_triage:
            linked_triages = session.query(AlertTriage).filter_by(case_id=case.id).all()
            for t in linked_triages:
                t.status = _mapped_triage
                _synced_alert_ids.append(t.es_alert_id)

    session.commit()
    session.refresh(case)
    await _sync_case_to_es(case, session)

    # Sync alert workflow_status to Elasticsearch
    if data.status is not None and _synced_alert_ids:
        try:
            from ion.services.elasticsearch_service import ElasticsearchService
            es = ElasticsearchService()
            if es.is_configured:
                await es.update_alert_workflow_status(_synced_alert_ids, _mapped_triage)
        except Exception as e:
            logger.warning(f"Failed to sync alert workflow_status on case update: {e}")

    # Resolve Kibana assignee UID if assignee changed
    assignee_elastic_uid = None
    if data.assigned_to_id is not None and case.kibana_case_id:
        assignee = session.query(User).filter_by(id=data.assigned_to_id).first()
        if assignee:
            # Use cached elastic_uid, or look it up from Kibana and cache it
            if assignee.elastic_uid:
                assignee_elastic_uid = assignee.elastic_uid
            else:
                try:
                    from ion.services.kibana_cases_service import get_kibana_cases_service
                    kb_service = get_kibana_cases_service()
                    if kb_service.enabled:
                        lookup_name = getattr(assignee, 'elastic_username', None) or assignee.username
                        uid = kb_service.resolve_user_uid(lookup_name)
                        if not uid and lookup_name != assignee.username:
                            uid = kb_service.resolve_user_uid(assignee.username)
                        if uid:
                            assignee_elastic_uid = uid
                            assignee.elastic_uid = uid
                            session.commit()
                            logger.info("Cached elastic_uid for user %s: %s", assignee.username, uid)
                except Exception as e:
                    logger.debug("Failed to resolve Kibana UID for %s: %s", assignee.username, e)

    # Sync updates to Kibana
    new_version, kibana_url = sync_case_update_to_kibana(
        kibana_case_id=case.kibana_case_id,
        case_number=case.case_number,
        title=data.title,
        description=data.description,
        status=data.status,
        severity=data.severity,
        assignee_elastic_uid=assignee_elastic_uid,
    )
    if new_version:
        case.kibana_case_version = new_version
        session.commit()

    # Get DFIR-IRIS URL if available
    dfir_iris_url = None
    if case.dfir_iris_case_id:
        try:
            iris_svc = get_dfir_iris_service()
            dfir_iris_url = iris_svc.get_case_url(case.dfir_iris_case_id)
        except Exception:
            pass

    return {
        "id": case.id,
        "case_number": case.case_number,
        "title": case.title,
        "status": case.status.value if hasattr(case.status, "value") else case.status,
        "closure_reason": case.closure_reason,
        "closure_notes": case.closure_notes,
        "closed_by": case.closed_by.username if case.closed_by else None,
        "closed_at": case.closed_at.isoformat() if case.closed_at else None,
        "kibana_url": kibana_url,
        "dfir_iris_case_id": case.dfir_iris_case_id,
        "dfir_iris_url": dfir_iris_url,
        "message": "Case updated",
    }


@router.post("/elasticsearch/alerts/cases/{case_id}/escalate/dfir-iris")
async def escalate_case_to_dfir_iris(
    case_id: int,
    current_user: User = Depends(require_permission("case:update")),
    session: Session = Depends(get_db_session),
):
    """Escalate an ION case to DFIR-IRIS for incident response."""
    from datetime import datetime, timezone
    from ion.models.integration import IntegrationType, IntegrationEventType, LogLevel, IntegrationEvent

    case = session.query(AlertCase).filter_by(id=case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    # Check if already escalated
    if case.dfir_iris_case_id:
        iris_svc = get_dfir_iris_service()
        return {
            "status": "already_escalated",
            "iris_case_id": case.dfir_iris_case_id,
            "iris_url": iris_svc.get_case_url(case.dfir_iris_case_id),
            "message": "Case was already escalated to DFIR-IRIS",
        }

    # Check service availability
    iris_service = get_dfir_iris_service()
    if not iris_service.enabled:
        raise HTTPException(
            status_code=400,
            detail="DFIR-IRIS integration is not enabled or not configured",
        )

    # Build rich description
    desc_parts = [case.description or "No description provided."]
    if case.affected_hosts:
        desc_parts.append(f"\n**Affected Hosts:** {', '.join(case.affected_hosts)}")
    if case.affected_users:
        desc_parts.append(f"\n**Affected Users:** {', '.join(case.affected_users)}")
    if case.triggered_rules:
        desc_parts.append(f"\n**Triggered Rules:** {', '.join(case.triggered_rules)}")
    if case.evidence_summary:
        desc_parts.append(f"\n**Evidence Summary:**\n{case.evidence_summary}")
    if case.source_alert_ids:
        desc_parts.append(f"\n**Linked ION Alerts ({len(case.source_alert_ids)}):**")
        for aid in case.source_alert_ids[:20]:
            desc_parts.append(f"- `{aid}`")
        if len(case.source_alert_ids) > 20:
            desc_parts.append(f"- ... and {len(case.source_alert_ids) - 20} more")
    if case.observables:
        desc_parts.append(f"\n**Observables ({len(case.observables)}):**")
        for obs in case.observables[:20]:
            desc_parts.append(f"- [{obs.get('type', '?')}] {obs.get('value', '?')}")
        if len(case.observables) > 20:
            desc_parts.append(f"- ... and {len(case.observables) - 20} more")

    description = "\n".join(desc_parts)

    try:
        # 1. Create IRIS case
        iris_case = await iris_service.create_case(
            title=f"[{case.case_number}] {case.title}",
            description=description,
            severity=case.severity or "medium",
            soc_id=case.case_number,
        )
        iris_case_id = iris_case.get("case_id")
        if not iris_case_id:
            raise HTTPException(status_code=502, detail="DFIR-IRIS did not return a case ID")

        # 2. Push observables as IOCs
        iocs_pushed = 0
        if case.observables:
            for obs in case.observables:
                obs_type = obs.get("type", "")
                obs_value = obs.get("value", "")
                if not obs_value:
                    continue
                try:
                    iris_ioc_type_id = iris_service.map_ioc_type(obs_type)
                    await iris_service.add_ioc(
                        case_id=iris_case_id,
                        value=obs_value,
                        ioc_type_id=iris_ioc_type_id,
                        description=f"Auto-imported from ION {case.case_number} ({obs_type})",
                        tags=["ion", obs_type],
                    )
                    iocs_pushed += 1
                except Exception as ioc_err:
                    _case_es_logger.warning("Failed to push IOC %s to IRIS: %s", obs_value, ioc_err)

        # 3. Push case notes
        notes_pushed = 0
        for note in case.notes:
            try:
                await iris_service.add_note(
                    case_id=iris_case_id,
                    title=f"Note by {note.user.username if note.user else 'Unknown'} ({note.created_at.strftime('%Y-%m-%d %H:%M') if note.created_at else 'N/A'})",
                    content=note.content,
                )
                notes_pushed += 1
            except Exception as note_err:
                _case_es_logger.warning("Failed to push note to IRIS: %s", note_err)

        # 4. Add timeline events for each alert in the case
        now_iso = datetime.now(timezone.utc).isoformat()
        events_pushed = 0
        if case.source_alert_ids:
            try:
                es_service = get_elasticsearch_service()
                es_alerts = await es_service.get_alerts_by_ids(case.source_alert_ids)

                for alert in es_alerts:
                    try:
                        event_content_parts = []
                        if alert.message:
                            event_content_parts.append(alert.message)
                        if alert.host:
                            event_content_parts.append(f"**Host:** {alert.host}")
                        if alert.user:
                            event_content_parts.append(f"**User:** {alert.user}")
                        if alert.severity:
                            event_content_parts.append(f"**Severity:** {alert.severity}")
                        if alert.mitre_technique_id:
                            technique = alert.mitre_technique_id
                            if alert.mitre_technique_name:
                                technique += f" ({alert.mitre_technique_name})"
                            event_content_parts.append(f"**MITRE:** {technique}")
                        if alert.mitre_tactic_name:
                            event_content_parts.append(f"**Tactic:** {alert.mitre_tactic_name}")

                        event_tags = ["ion", "alert"]
                        if alert.severity:
                            event_tags.append(alert.severity)
                        if alert.mitre_technique_id:
                            event_tags.append(alert.mitre_technique_id)

                        category_id = iris_service.map_tactic_to_category(
                            alert.mitre_tactic_name or ""
                        )
                        await iris_service.add_event(
                            case_id=iris_case_id,
                            title=f"[{alert.severity.upper()}] {alert.rule_name or alert.title}",
                            date=alert.timestamp.isoformat() if alert.timestamp else now_iso,
                            content="\n".join(event_content_parts),
                            source=f"ION ({alert.source})",
                            tags=event_tags,
                            category_id=category_id,
                        )
                        events_pushed += 1
                    except Exception as evt_err:
                        _case_es_logger.warning(
                            "Failed to push alert %s as timeline event: %s", alert.id, evt_err
                        )
            except Exception as es_err:
                _case_es_logger.warning("Failed to fetch alerts from ES for timeline: %s", es_err)

        # Add escalation summary event
        try:
            await iris_service.add_event(
                case_id=iris_case_id,
                title=f"Case escalated from ION ({case.case_number})",
                date=now_iso,
                content=f"Escalated by {current_user.username}. {iocs_pushed} IOCs, {notes_pushed} notes, and {events_pushed} alert timeline events transferred.",
                source="ION",
                tags=["escalation", "ion"],
                category_id=1,
            )
        except Exception as evt_err:
            _case_es_logger.warning("Failed to add escalation event to IRIS: %s", evt_err)

        # 5. Store link back on the ION case
        case.dfir_iris_case_id = iris_case_id
        session.commit()

        # 6. Log integration event
        try:
            event = IntegrationEvent(
                event_type=IntegrationEventType.ACTIVITY,
                integration_type=IntegrationType.DFIR_IRIS,
                action="escalate_case",
                level=LogLevel.INFO,
                message=f"Case {case.case_number} escalated to DFIR-IRIS (IRIS case #{iris_case_id})",
                details={
                    "ion_case_id": case.id,
                    "iris_case_id": iris_case_id,
                    "iocs_pushed": iocs_pushed,
                    "notes_pushed": notes_pushed,
                    "events_pushed": events_pushed,
                },
                user_id=current_user.id,
            )
            session.add(event)
            session.commit()
        except Exception:
            pass

        return {
            "status": "escalated",
            "iris_case_id": iris_case_id,
            "iris_url": iris_service.get_case_url(iris_case_id),
            "iocs_pushed": iocs_pushed,
            "notes_pushed": notes_pushed,
            "events_pushed": events_pushed,
        }

    except HTTPException:
        raise
    except httpx.HTTPStatusError as e:
        # Surface the clearer auth-failure messages from the service
        msg = str(e)
        if "authentication failed" in msg.lower() or "login page" in msg.lower():
            detail = msg
        else:
            detail = f"DFIR-IRIS API error: HTTP {e.response.status_code} - {e.response.text[:200]}"
        raise HTTPException(status_code=502, detail=detail)
    except httpx.ConnectError as e:
        raise HTTPException(
            status_code=502,
            detail=f"Cannot connect to DFIR-IRIS: {e}",
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Escalation failed: {str(e)}",
        )


# ============================================================================
# Known False Positives Registry
# ============================================================================


def _match_known_false_positives(
    session: Session,
    hosts: Optional[List[str]] = None,
    users: Optional[List[str]] = None,
    ips: Optional[List[str]] = None,
    rules: Optional[List[str]] = None,
) -> list:
    """Check active KFP entries for matches against the given observables."""
    kfps = session.query(KnownFalsePositive).filter_by(is_active=True).all()
    results = []
    hosts_lower = {h.lower() for h in (hosts or []) if h}
    users_lower = {u.lower() for u in (users or []) if u}
    ips_lower = {i.lower() for i in (ips or []) if i}
    rules_lower = {r.lower() for r in (rules or []) if r}

    for kfp in kfps:
        matched_fields = []
        if kfp.match_hosts and hosts_lower:
            kfp_hosts = {h.lower() for h in kfp.match_hosts}
            if kfp_hosts & hosts_lower:
                matched_fields.append("hosts")
        if kfp.match_users and users_lower:
            kfp_users = {u.lower() for u in kfp.match_users}
            if kfp_users & users_lower:
                matched_fields.append("users")
        if kfp.match_ips and ips_lower:
            kfp_ips = {i.lower() for i in kfp.match_ips}
            if kfp_ips & ips_lower:
                matched_fields.append("ips")
        if kfp.match_rules and rules_lower:
            kfp_rules = {r.lower() for r in kfp.match_rules}
            if kfp_rules & rules_lower:
                matched_fields.append("rules")
        if matched_fields:
            results.append({
                "id": kfp.id,
                "title": kfp.title,
                "description": kfp.description,
                "matched_fields": matched_fields,
                "source_case_id": kfp.source_case_id,
            })
    return results


class KFPCreate(BaseModel):
    title: str
    description: str
    match_hosts: Optional[List[str]] = None
    match_users: Optional[List[str]] = None
    match_ips: Optional[List[str]] = None
    match_rules: Optional[List[str]] = None
    source_case_id: Optional[int] = None


class KFPUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    match_hosts: Optional[List[str]] = None
    match_users: Optional[List[str]] = None
    match_ips: Optional[List[str]] = None
    match_rules: Optional[List[str]] = None
    is_active: Optional[bool] = None


class KFPMatchRequest(BaseModel):
    hosts: Optional[List[str]] = None
    users: Optional[List[str]] = None
    ips: Optional[List[str]] = None
    rules: Optional[List[str]] = None


class CloseAsFPRequest(BaseModel):
    known_fp_id: int


@router.get("/known-false-positives")
async def list_known_false_positives(
    active_only: bool = True,
    current_user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
):
    """List all known false positive entries."""
    query = session.query(KnownFalsePositive)
    if active_only:
        query = query.filter_by(is_active=True)
    kfps = query.order_by(KnownFalsePositive.created_at.desc()).all()
    return {
        "known_false_positives": [
            {
                "id": kfp.id,
                "title": kfp.title,
                "description": kfp.description,
                "match_hosts": kfp.match_hosts,
                "match_users": kfp.match_users,
                "match_ips": kfp.match_ips,
                "match_rules": kfp.match_rules,
                "is_active": kfp.is_active,
                "source_case_id": kfp.source_case_id,
                "created_by": kfp.created_by.username if kfp.created_by else None,
                "created_at": kfp.created_at.isoformat() if kfp.created_at else None,
                "updated_at": kfp.updated_at.isoformat() if kfp.updated_at else None,
            }
            for kfp in kfps
        ]
    }


@router.post("/known-false-positives")
async def create_known_false_positive(
    data: KFPCreate,
    current_user: User = Depends(require_permission("alert:triage")),
    session: Session = Depends(get_db_session),
):
    """Create a new known false positive entry."""
    kfp = KnownFalsePositive(
        title=data.title,
        description=data.description,
        match_hosts=data.match_hosts,
        match_users=data.match_users,
        match_ips=data.match_ips,
        match_rules=data.match_rules,
        source_case_id=data.source_case_id,
        created_by_id=current_user.id,
    )
    session.add(kfp)
    session.commit()
    session.refresh(kfp)
    await _sync_kfp_to_es(kfp)
    doc_id = _create_kfp_document(session, kfp, current_user.username)
    session.commit()
    return {
        "id": kfp.id,
        "title": kfp.title,
        "description": kfp.description,
        "match_hosts": kfp.match_hosts,
        "match_users": kfp.match_users,
        "match_ips": kfp.match_ips,
        "match_rules": kfp.match_rules,
        "is_active": kfp.is_active,
        "source_case_id": kfp.source_case_id,
        "created_by": kfp.created_by.username if kfp.created_by else None,
        "created_at": kfp.created_at.isoformat() if kfp.created_at else None,
        "document_id": doc_id,
    }


@router.get("/known-false-positives/{kfp_id}")
async def get_known_false_positive(
    kfp_id: int,
    current_user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
):
    """Get a single known false positive entry."""
    kfp = session.query(KnownFalsePositive).filter_by(id=kfp_id).first()
    if not kfp:
        raise HTTPException(status_code=404, detail="Known false positive not found")
    return {
        "id": kfp.id,
        "title": kfp.title,
        "description": kfp.description,
        "match_hosts": kfp.match_hosts,
        "match_users": kfp.match_users,
        "match_ips": kfp.match_ips,
        "match_rules": kfp.match_rules,
        "is_active": kfp.is_active,
        "source_case_id": kfp.source_case_id,
        "created_by": kfp.created_by.username if kfp.created_by else None,
        "created_at": kfp.created_at.isoformat() if kfp.created_at else None,
        "updated_at": kfp.updated_at.isoformat() if kfp.updated_at else None,
    }


@router.put("/known-false-positives/{kfp_id}")
async def update_known_false_positive(
    kfp_id: int,
    data: KFPUpdate,
    current_user: User = Depends(require_permission("alert:triage")),
    session: Session = Depends(get_db_session),
):
    """Update a known false positive entry."""
    kfp = session.query(KnownFalsePositive).filter_by(id=kfp_id).first()
    if not kfp:
        raise HTTPException(status_code=404, detail="Known false positive not found")
    if data.title is not None:
        kfp.title = data.title
    if data.description is not None:
        kfp.description = data.description
    if data.match_hosts is not None:
        kfp.match_hosts = data.match_hosts
    if data.match_users is not None:
        kfp.match_users = data.match_users
    if data.match_ips is not None:
        kfp.match_ips = data.match_ips
    if data.match_rules is not None:
        kfp.match_rules = data.match_rules
    if data.is_active is not None:
        kfp.is_active = data.is_active
    session.commit()
    session.refresh(kfp)
    await _sync_kfp_to_es(kfp)
    return {
        "id": kfp.id,
        "title": kfp.title,
        "description": kfp.description,
        "match_hosts": kfp.match_hosts,
        "match_users": kfp.match_users,
        "match_ips": kfp.match_ips,
        "match_rules": kfp.match_rules,
        "is_active": kfp.is_active,
        "message": "Updated",
    }


@router.delete("/known-false-positives/{kfp_id}")
async def delete_known_false_positive(
    kfp_id: int,
    current_user: User = Depends(require_permission("alert:triage")),
    session: Session = Depends(get_db_session),
):
    """Soft-delete a known false positive entry (set is_active=false)."""
    kfp = session.query(KnownFalsePositive).filter_by(id=kfp_id).first()
    if not kfp:
        raise HTTPException(status_code=404, detail="Known false positive not found")
    kfp.is_active = False
    session.commit()
    session.refresh(kfp)
    await _sync_kfp_to_es(kfp)
    return {"message": "Known false positive deactivated"}


@router.post("/known-false-positives/match")
async def match_known_false_positives(
    data: KFPMatchRequest,
    current_user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
):
    """Check if given observables match any known false positive entries."""
    matches = _match_known_false_positives(
        session,
        hosts=data.hosts,
        users=data.users,
        ips=data.ips,
        rules=data.rules,
    )
    return {"matches": matches}


@router.post("/elasticsearch/alerts/cases/{case_id}/close-as-fp")
async def close_case_as_known_fp(
    case_id: int,
    data: CloseAsFPRequest,
    current_user: User = Depends(require_permission("alert:triage")),
    session: Session = Depends(get_db_session),
):
    """Close a case as a known false positive, setting all linked alerts to false_positive."""
    case = session.query(AlertCase).filter_by(id=case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    kfp = session.query(KnownFalsePositive).filter_by(id=data.known_fp_id).first()
    if not kfp:
        raise HTTPException(status_code=404, detail="Known false positive entry not found")

    # Close the case
    case.status = AlertCaseStatus.CLOSED
    case.closure_reason = CaseClosureReason.FALSE_POSITIVE.value
    case.closure_notes = f"Matched known FP: {kfp.title}\n\n{kfp.description}"
    case.closed_by_id = current_user.id
    case.closed_at = datetime.utcnow()

    # Set all linked AlertTriage entries to closed
    updated_alerts = 0
    for triage in case.triage_entries:
        triage.status = AlertTriageStatus.CLOSED
        updated_alerts += 1

    session.commit()
    session.refresh(case)
    await _sync_case_to_es(case, session)

    return {
        "id": case.id,
        "case_number": case.case_number,
        "status": "closed",
        "closure_reason": "false_positive",
        "known_fp_title": kfp.title,
        "updated_alerts": updated_alerts,
        "message": "Case closed as known false positive",
    }


class BatchTriageRequest(BaseModel):
    alert_ids: List[str]


class BatchTriageRequestWithStatus(BaseModel):
    """Batch triage request that can include ES-side statuses for sync."""
    alert_ids: List[str]
    es_statuses: Optional[Dict[str, str]] = None  # { alert_id: "open"|"acknowledged"|"closed" }


@router.post("/elasticsearch/alerts-triage/batch")
async def get_batch_triage(
    data: BatchTriageRequestWithStatus,
    current_user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
):
    """Get triage data (including case info) for multiple alerts at once.

    If es_statuses is provided, syncs Kibana/ES status changes into ION triage
    records (Kibana → ION direction). This handles the case where someone changes
    alert status directly in Kibana.
    """
    if not data.alert_ids:
        return {"triage": {}}

    triages = (
        session.query(AlertTriage)
        .filter(AlertTriage.es_alert_id.in_(data.alert_ids))
        .all()
    )
    triage_map = {t.es_alert_id: t for t in triages}

    # Sync ES status → ION triage (Kibana → ION direction)
    if data.es_statuses:
        valid_statuses = {"open", "acknowledged", "closed"}
        for alert_id, es_status in data.es_statuses.items():
            es_status_lower = es_status.lower() if es_status else "open"
            if es_status_lower not in valid_statuses:
                continue

            triage = triage_map.get(alert_id)
            if triage:
                # Update if ES status differs from ION status
                ion_status = triage.status.value if hasattr(triage.status, "value") else str(triage.status)
                if ion_status.lower() != es_status_lower:
                    triage.status = AlertTriageStatus(es_status_lower)
                    logger.debug("Synced ES status '%s' → ION triage for alert %s", es_status_lower, alert_id)
            else:
                # Create triage record from ES status (so ION tracks it)
                if es_status_lower != "open":
                    # Only create records for non-open statuses (open is the default)
                    new_triage = AlertTriage(
                        es_alert_id=alert_id,
                        status=AlertTriageStatus(es_status_lower),
                    )
                    session.add(new_triage)
                    triage_map[alert_id] = new_triage

        try:
            session.commit()
        except Exception:
            session.rollback()
            logger.warning("Failed to sync ES statuses to ION triage")

    result = {}
    for t in triage_map.values():
        result[t.es_alert_id] = {
            "status": t.status.value if hasattr(t.status, "value") else t.status,
            "priority": t.priority,
            "case_id": t.case_id,
            "case_number": t.case.case_number if t.case else None,
            "case_title": t.case.title if t.case else None,
        }

    return {"triage": result}


@router.get("/elasticsearch/assignment_users")
async def get_assignment_users(
    q: str = "",
    refresh: bool = False,
    current_user: User = Depends(require_permission("alert:read")),
):
    """Get users available for alert assignment from the configured ES index.

    Results are cached for 5 minutes. Pass ?refresh=true to force a fresh fetch.
    """
    from ion.services.elasticsearch_service import ElasticsearchService
    es = ElasticsearchService()
    if not es.is_configured or not es.user_mapping_configured:
        return {"users": [], "source": "none", "configured": False}

    users = await es.get_assignment_users(search=q, force_refresh=refresh)
    return {"users": users, "source": "elasticsearch", "configured": True}


@router.post("/elasticsearch/alerts-triage/bulk-update")
async def bulk_update_triage(
    data: BulkTriageUpdate,
    current_user: User = Depends(require_permission("alert:triage")),
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

    # Sync workflow_status to Elasticsearch when bulk-updating status
    if data.status:
        try:
            from ion.services.elasticsearch_service import ElasticsearchService
            es = ElasticsearchService()
            if es.is_configured:
                await es.update_alert_workflow_status(data.alert_ids, data.status)
        except Exception as e:
            logger.warning(f"Failed to sync bulk workflow_status to ES: {e}")

    # Sync assignment to Elasticsearch when bulk-updating assignee
    if data.assigned_to_name is not None or data.assigned_to_id is not None:
        try:
            from ion.services.elasticsearch_service import ElasticsearchService
            es = ElasticsearchService()
            if es.is_configured and es.assignment_field:
                if data.assigned_to_name:
                    user_name = data.assigned_to_name
                elif data.assigned_to_id and data.assigned_to_id > 0:
                    assignee = session.query(User).get(data.assigned_to_id)
                    user_name = assignee.display_name or assignee.username if assignee else None
                else:
                    user_name = None
                await es.update_alert_assignment(data.alert_ids, user_name)
        except Exception as e:
            logger.warning(f"Failed to sync bulk assignment to ES: {e}")

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
    current_user: User = Depends(require_permission("alert:read")),
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
    current_user: User = Depends(require_permission("alert:triage")),
    session: Session = Depends(get_db_session),
):
    """Update triage status, assignee, priority for an alert."""
    triage = session.query(AlertTriage).filter_by(es_alert_id=alert_id).first()
    if not triage:
        triage = AlertTriage(es_alert_id=alert_id)
        session.add(triage)
        session.flush()

    status_changed = False
    if data.status is not None:
        triage.status = data.status
        status_changed = True
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

    # Sync workflow_status to Elasticsearch when triage status changes
    if status_changed and data.status:
        try:
            from ion.services.elasticsearch_service import ElasticsearchService
            es = ElasticsearchService()
            if es.is_configured:
                await es.update_alert_workflow_status([alert_id], data.status)
        except Exception as e:
            logger.warning(f"Failed to sync workflow_status to ES for {alert_id}: {e}")

    # Sync assignment to Elasticsearch when assignee changes
    if data.assigned_to_name is not None or data.assigned_to_id is not None:
        try:
            from ion.services.elasticsearch_service import ElasticsearchService
            es = ElasticsearchService()
            if es.is_configured and es.assignment_field:
                if data.assigned_to_name:
                    # ES user name provided directly
                    user_name = data.assigned_to_name
                elif data.assigned_to_id and data.assigned_to_id > 0:
                    # Resolve ION user ID to display name
                    assignee = session.query(User).get(data.assigned_to_id)
                    user_name = assignee.display_name or assignee.username if assignee else None
                else:
                    user_name = None  # Unassign
                await es.update_alert_assignment([alert_id], user_name)
        except Exception as e:
            logger.warning(f"Failed to sync assignment to ES for {alert_id}: {e}")

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


@router.post("/elasticsearch/alerts/{alert_id}/close")
async def close_alert(
    alert_id: str,
    data: AlertClosureRequest,
    current_user: User = Depends(require_permission("alert:triage")),
    session: Session = Depends(get_db_session),
):
    """Close an alert as benign, escalated, or false positive.

    Propagates a note to the parent case (ION + Kibana) and optionally
    creates a KFP registry entry for false positives.
    """
    # Map closure_type to AlertTriageStatus
    closure_map = {
        "benign": AlertTriageStatus.CLOSED,
        "escalated": AlertTriageStatus.ACKNOWLEDGED,
        "false_positive": AlertTriageStatus.CLOSED,
    }
    if data.closure_type not in closure_map:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid closure_type. Must be one of: {', '.join(closure_map.keys())}",
        )
    new_status = closure_map[data.closure_type]
    label = data.closure_type.replace("_", " ").title()

    # Get or create triage record
    triage = session.query(AlertTriage).filter_by(es_alert_id=alert_id).first()
    if not triage:
        triage = AlertTriage(es_alert_id=alert_id)
        session.add(triage)
        session.flush()

    triage.status = new_status

    note_added_to_case = False
    kfp_created = None

    # If triage has a parent case, add a closure note and close the case
    case_closed = False
    if triage.case_id:
        case = session.query(AlertCase).filter_by(id=triage.case_id).first()
        if case:
            note_content = f"**Alert closed as {label}**\nAlert: `{alert_id}`\nReason: {data.notes or 'N/A'}"
            note = Note(
                entity_type=NoteEntityType.CASE,
                entity_id=str(case.id),
                user_id=current_user.id,
                content=note_content,
            )
            session.add(note)
            note_added_to_case = True

            # Close the parent case with mapped closure reason
            closure_reason_map = {
                "benign": "benign_true_positive",
                "escalated": "true_positive",
                "false_positive": "false_positive",
            }
            if case.status != AlertCaseStatus.CLOSED:
                case.status = AlertCaseStatus.CLOSED
                case.closure_reason = closure_reason_map.get(data.closure_type, "not_applicable")
                case.closure_notes = data.notes or f"Closed via alert closure ({label})"
                case.closed_by_id = current_user.id
                case.closed_at = datetime.utcnow()
                case_closed = True

                # Close all other linked alerts in the same case
                other_triages = session.query(AlertTriage).filter(
                    AlertTriage.case_id == case.id,
                    AlertTriage.es_alert_id != alert_id,
                    AlertTriage.status != AlertTriageStatus.CLOSED,
                ).all()
                for ot in other_triages:
                    ot.status = new_status

            # Sync note to Kibana
            if case.kibana_case_id:
                sync_note_to_kibana(case.kibana_case_id, current_user.username, note_content)

    # For false positives, optionally create KFP entry
    if data.closure_type == "false_positive" and data.create_kfp:
        # Fall back to extracting from triage observables if not provided
        match_hosts = data.match_hosts or []
        match_users = data.match_users or []
        match_ips = data.match_ips or []
        match_rules = data.match_rules or []

        if triage.observables and (not match_hosts or not match_users or not match_ips):
            for obs in triage.observables:
                obs_type = obs.get("type", "")
                obs_value = obs.get("value", "")
                if not obs_value:
                    continue
                if obs_type == "hostname" and not match_hosts:
                    match_hosts.append(obs_value)
                elif obs_type == "user_account" and not match_users:
                    match_users.append(obs_value)
                elif obs_type in ("source_ip", "destination_ip") and not match_ips:
                    match_ips.append(obs_value)

        kfp = KnownFalsePositive(
            title=data.kfp_title or f"FP: Alert {alert_id}",
            description=data.kfp_description or data.notes or "",
            match_hosts=match_hosts if match_hosts else None,
            match_users=match_users if match_users else None,
            match_ips=match_ips if match_ips else None,
            match_rules=match_rules if match_rules else None,
            source_case_id=triage.case_id,
            created_by_id=current_user.id,
        )
        session.add(kfp)
        session.flush()
        kfp_created = {
            "id": kfp.id,
            "title": kfp.title,
        }

    session.commit()

    # Sync workflow_status to Elasticsearch for closed alerts
    try:
        from ion.services.elasticsearch_service import ElasticsearchService
        es = ElasticsearchService()
        if es.is_configured:
            # Collect all alert IDs that were closed (primary + sibling alerts in the case)
            closed_alert_ids = [alert_id]
            if case_closed and triage.case_id:
                sibling_triages = session.query(AlertTriage).filter(
                    AlertTriage.case_id == triage.case_id,
                    AlertTriage.es_alert_id != alert_id,
                ).all()
                closed_alert_ids.extend(st.es_alert_id for st in sibling_triages)
            status_str = new_status.value if hasattr(new_status, "value") else new_status
            await es.update_alert_workflow_status(closed_alert_ids, status_str)
    except Exception as e:
        logger.warning(f"Failed to sync workflow_status to ES on alert close: {e}")

    # Sync KFP to ES and create document if one was created
    if kfp_created:
        session.refresh(kfp)
        await _sync_kfp_to_es(kfp)
        _create_kfp_document(session, kfp, current_user.username)
        session.commit()

    return {
        "status": new_status.value if hasattr(new_status, "value") else new_status,
        "closure_type": data.closure_type,
        "alert_id": alert_id,
        "note_added_to_case": note_added_to_case,
        "case_closed": case_closed,
        "kfp_created": kfp_created,
        "message": f"Alert closed as {label}",
    }


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
        for obs in extract_observables_from_raw(raw_data):
            _add(obs["type"], obs["value"])

    triage.observables = observables if observables else None
    return True


@router.post("/elasticsearch/alerts/{alert_id}/triage/auto-populate-observables")
async def auto_populate_observables(
    alert_id: str,
    data: AutoPopulateRequest,
    current_user: User = Depends(require_permission("alert:triage")),
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
    current_user: User = Depends(require_permission("alert:triage")),
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
    current_user: User = Depends(require_permission("alert:read")),
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
    current_user: User = Depends(require_permission("alert:read")),
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


_DISCOVER_BLOCKED_PREFIXES = (".kibana", ".security", ".internal", ".tasks", ".apm", ".fleet")


def _validate_index_pattern(pattern: str) -> str:
    """Block access to system/internal ES indices via discover."""
    lower = pattern.lower().strip()
    for prefix in _DISCOVER_BLOCKED_PREFIXES:
        if lower.startswith(prefix):
            raise ValueError(f"Access to system index '{pattern}' is not permitted")
    return pattern


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
    try:
        _validate_index_pattern(request.index_pattern)
    except ValueError as e:
        raise HTTPException(status_code=403, detail=str(e))

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
    try:
        _validate_index_pattern(request.index_pattern)
    except ValueError as e:
        raise HTTPException(status_code=403, detail=str(e))

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

from ion.services.opencti_service import (
    OpenCTIService,
    OpenCTIError,
    get_opencti_service,
    reset_opencti_service,
)
from ion.core.config import get_opencti_config


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

    data_dir = os.environ.get("ION_DATA_DIR")
    if data_dir:
        config_path = Path(data_dir) / ".ion" / "config.json"
    else:
        config_path = Path.cwd() / ".ion" / "config.json"

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

    data_dir = os.environ.get("ION_DATA_DIR")
    if data_dir:
        config_path = Path(data_dir) / ".ion" / "config.json"
    else:
        config_path = Path.cwd() / ".ion" / "config.json"

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

from ion.models.chat import ChatRoom, ChatRoomMember, ChatMessage, MessageReaction
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
    reply_to_id: Optional[int] = None


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
            from ion.models.alert_triage import AlertCase
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
        from ion.models.alert_triage import AlertCase
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

        # Build reply preview if this message is a reply
        reply_preview = None
        reply_to_id = getattr(msg, "reply_to_id", None)
        if reply_to_id:
            reply_msg = session.execute(
                select(ChatMessage).where(ChatMessage.id == reply_to_id)
            ).scalar_one_or_none()
            if reply_msg:
                reply_preview = {
                    "id": reply_msg.id,
                    "username": reply_msg.user.username if reply_msg.user else None,
                    "display_name": reply_msg.user.display_name if reply_msg.user else None,
                    "content": reply_msg.content[:120] + ("..." if len(reply_msg.content) > 120 else ""),
                }

        result.append({
            "id": msg.id,
            "user_id": msg.user_id,
            "username": msg.user.username if msg.user else None,
            "display_name": msg.user.display_name if msg.user else None,
            "content": msg.content,
            "mentions": msg.mentions,
            "reply_to_id": reply_to_id,
            "reply_preview": reply_preview,
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
        reply_to_id=data.reply_to_id,
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

    # Create notifications for mentions and DMs
    try:
        from ion.web.notification_api import create_notification
        sender_name = current_user.display_name or current_user.username
        snippet = data.content.strip()[:80]

        # Notifications for @mentions
        if mention_ids:
            for uid in mention_ids:
                if uid != current_user.id:
                    create_notification(
                        session, uid,
                        source="chat_mention",
                        title=f"{sender_name} mentioned you",
                        body=snippet,
                        url=f"#chat-room-{room_id}",
                        source_id=str(room_id),
                    )

        # Notification for DM (direct messages to the other user)
        # or group chat messages (notify all other members)
        other_members = session.execute(
            select(ChatRoomMember.user_id).where(
                ChatRoomMember.room_id == room_id,
                ChatRoomMember.user_id != current_user.id,
            )
        ).scalars().all()

        notified_ids = set(mention_ids or [])
        room_name = room.name or "Chat" if room else "Chat"

        for uid in other_members:
            if uid in notified_ids:
                continue  # Already notified via @mention
            if room and room.room_type == "direct":
                create_notification(
                    session, uid,
                    source="chat_dm",
                    title=f"DM from {sender_name}",
                    body=snippet,
                    url=f"#chat-room-{room_id}",
                    source_id=str(room_id),
                )
            elif room and room.room_type == "group":
                create_notification(
                    session, uid,
                    source="chat_group",
                    title=f"{sender_name} in {room_name}",
                    body=snippet,
                    url=f"#chat-room-{room_id}",
                    source_id=str(room_id),
                )
    except Exception as _notif_err:
        logger.debug("Failed to create chat notification: %s", _notif_err)

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
# Chat Memes Endpoints
# ============================================================================

from ion.models.chat import ChatMeme


@router.get("/chat/memes")
async def list_memes(
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """List all available memes for use in chat."""
    memes = list(session.execute(select(ChatMeme).order_by(ChatMeme.name)).scalars().all())
    return {
        "memes": [
            {
                "id": m.id,
                "name": m.name,
                "filename": m.filename,
                "url": f"/static/memes/{m.filename}",
                "uploaded_by": m.uploaded_by.username if m.uploaded_by else None,
            }
            for m in memes
        ]
    }


@router.post("/chat/memes")
async def upload_meme(
    name: str = Form(...),
    file: UploadFile = File(...),
    current_user: User = Depends(require_permission("system:settings")),
    session: Session = Depends(get_db_session),
):
    """Upload a new custom meme image (admin/engineering only)."""
    import re
    from pathlib import Path

    # Validate name (alphanumeric + underscores, 1-64 chars)
    if not re.match(r'^[a-z0-9_]{1,64}$', name):
        raise HTTPException(400, "Meme name must be 1-64 lowercase alphanumeric characters or underscores")

    # Check duplicate name
    existing = session.execute(select(ChatMeme).where(ChatMeme.name == name)).scalar_one_or_none()
    if existing:
        raise HTTPException(409, f"Meme '{name}' already exists")

    # Validate file type
    allowed_ext = {'.png', '.gif', '.jpg', '.jpeg', '.webp'}
    fname = file.filename or "meme.png"
    ext = '.' + fname.rsplit('.', 1)[-1].lower() if '.' in fname else ''
    if ext not in allowed_ext:
        raise HTTPException(400, f"Allowed image types: {', '.join(allowed_ext)}")

    # Read and save
    content = await file.read()
    if len(content) > 2 * 1024 * 1024:  # 2 MB limit
        raise HTTPException(400, "Meme image must be under 2 MB")
    if len(content) == 0:
        raise HTTPException(400, "Empty file")

    safe_filename = f"{name}{ext}"
    meme_dir = Path(__file__).parent / "static" / "memes"
    meme_dir.mkdir(parents=True, exist_ok=True)
    (meme_dir / safe_filename).write_bytes(content)

    meme = ChatMeme(name=name, filename=safe_filename, uploaded_by_id=current_user.id)
    session.add(meme)
    session.commit()

    return {
        "id": meme.id,
        "name": meme.name,
        "filename": meme.filename,
        "url": f"/static/memes/{meme.filename}",
    }


@router.delete("/chat/memes/{meme_id}")
async def delete_meme(
    meme_id: int,
    current_user: User = Depends(require_permission("system:settings")),
    session: Session = Depends(get_db_session),
):
    """Delete a custom meme (admin/engineering only)."""
    from pathlib import Path

    meme = session.execute(select(ChatMeme).where(ChatMeme.id == meme_id)).scalar_one_or_none()
    if not meme:
        raise HTTPException(404, "Meme not found")

    # Delete file
    meme_path = Path(__file__).parent / "static" / "memes" / meme.filename
    if meme_path.exists():
        meme_path.unlink()

    session.delete(meme)
    session.commit()
    return {"message": f"Meme '{meme.name}' deleted"}


# ============================================================================
# Saved Searches Endpoints
# ============================================================================

from ion.models.saved_search import SavedSearch, SearchType
from ion.storage.saved_search_repository import SavedSearchRepository


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
        from ion.services.elasticsearch_service import get_elasticsearch_service

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

from ion.models.playbook import Playbook, PlaybookStep, PlaybookExecution, StepType, ExecutionStatus
from ion.storage.playbook_repository import PlaybookRepository


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
    action_data: Optional[dict] = None  # {action_taken, findings, evidence_collected, risk_assessment}


class ExecutionCompleteRequest(BaseModel):
    outcome: Optional[str] = None
    outcome_notes: Optional[str] = None


@router.get("/playbooks")
async def list_playbooks(
    active_only: bool = False,
    current_user: User = Depends(require_permission("playbook:read")),
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
    current_user: User = Depends(require_permission("playbook:create")),
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
    current_user: User = Depends(require_permission("playbook:read")),
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
    current_user: User = Depends(require_permission("playbook:update")),
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
    current_user: User = Depends(require_permission("playbook:delete")),
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
    current_user: User = Depends(require_permission("playbook:read")),
    session: Session = Depends(get_db_session),
):
    """Get playbooks that match the given alert's characteristics."""
    # First get the alert to extract its characteristics
    config = get_elasticsearch_config()
    if not config.get("enabled"):
        raise HTTPException(status_code=400, detail="Elasticsearch is not enabled")

    service = get_elasticsearch_service()
    if not service.is_configured:
        raise HTTPException(status_code=400, detail="Elasticsearch is not configured")

    # Try to get alert details
    alerts = await service.get_alerts_by_ids([alert_id])
    if not alerts:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert = alerts[0]

    # Extract characteristics for matching
    rule_name = alert.rule_name
    severity = alert.severity
    mitre_techniques = [alert.mitre_technique_id] if alert.mitre_technique_id else []
    mitre_tactics = [alert.mitre_tactic_name] if alert.mitre_tactic_name else []

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
    seen_ids = set()
    for playbook in matching_playbooks:
        pb_dict = playbook.to_dict(include_steps=True)
        pb_dict["has_active_execution"] = playbook.id in active_playbook_ids
        pb_dict["match_source"] = "alert"
        result.append(pb_dict)
        seen_ids.add(playbook.id)

    # Also include pattern-based recommendations for this alert's host/user
    from ion.services.pattern_detection_service import PatternDetectionService

    try:
        host = alert.host if hasattr(alert, "host") else None
        user = alert.user if hasattr(alert, "user") else None
        if host or user:
            context_alerts = await service.get_alerts(hours=24, limit=200)
            if context_alerts:
                detector = PatternDetectionService()
                patterns = detector.detect_patterns(context_alerts)
                for p in patterns:
                    if (p.group_by == "host" and p.group_key == host) or \
                       (p.group_by == "user" and p.group_key == user):
                        pb = repo.find_playbook_for_pattern(p.pattern_id)
                        if pb and pb.id not in seen_ids:
                            pb_dict = pb.to_dict(include_steps=True)
                            pb_dict["has_active_execution"] = pb.id in active_playbook_ids
                            pb_dict["match_source"] = "pattern"
                            pb_dict["pattern_id"] = p.pattern_id
                            pb_dict["pattern_name"] = p.pattern_name
                            result.append(pb_dict)
                            seen_ids.add(pb.id)
    except Exception:
        pass  # pattern enrichment is best-effort

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


@router.get("/elasticsearch/alerts/{alert_id}/suggested-playbooks")
async def get_suggested_playbooks(
    alert_id: str,
    current_user: User = Depends(require_permission("playbook:read")),
    session: Session = Depends(get_db_session),
):
    """Get all playbooks (active + inactive) that match the given alert's characteristics."""
    config = get_elasticsearch_config()
    if not config.get("enabled"):
        raise HTTPException(status_code=400, detail="Elasticsearch is not enabled")

    service = get_elasticsearch_service()
    if not service.is_configured:
        raise HTTPException(status_code=400, detail="Elasticsearch is not configured")

    alerts = await service.get_alerts_by_ids([alert_id])
    if not alerts:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert = alerts[0]

    rule_name = alert.rule_name
    severity = alert.severity
    mitre_techniques = [alert.mitre_technique_id] if alert.mitre_technique_id else []
    mitre_tactics = [alert.mitre_tactic_name] if alert.mitre_tactic_name else []

    repo = PlaybookRepository(session)
    suggested = repo.find_suggested_playbooks(
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
    for playbook in suggested:
        pb_dict = playbook.to_dict(include_steps=True)
        pb_dict["suggestion_type"] = "recommended" if playbook.is_active else "library"
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
    current_user: User = Depends(require_permission("playbook:execute")),
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

    # Auto-detect case link via alert triage
    from ion.models.alert_triage import AlertTriage
    case_id = None
    triage = session.query(AlertTriage).filter_by(es_alert_id=alert_id).first()
    if triage and triage.case_id:
        case_id = triage.case_id

    # Start new execution
    execution = repo.start_execution(
        playbook=playbook,
        es_alert_id=alert_id,
        executed_by_id=current_user.id,
        case_id=case_id,
    )
    session.commit()

    # Refresh to get relationships
    execution = repo.get_execution(execution.id)

    return {
        "execution": execution.to_dict(include_playbook=True),
        "message": "Playbook execution started",
    }


@router.get("/playbook-executions/summary")
async def playbook_executions_summary(
    current_user: User = Depends(require_permission("playbook:execute")),
    session: Session = Depends(get_db_session),
):
    """Get summary counts of playbook executions by status."""
    repo = PlaybookRepository(session)
    counts = repo.get_execution_counts_by_status()

    return {
        "in_progress": counts.get("in_progress", 0),
        "pending": counts.get("pending", 0),
        "completed": counts.get("completed", 0),
        "failed": counts.get("failed", 0),
        "total": sum(counts.values()),
    }


@router.get("/playbook-executions/{execution_id}")
async def get_playbook_execution(
    execution_id: int,
    current_user: User = Depends(require_permission("playbook:execute")),
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
    current_user: User = Depends(require_permission("playbook:execute")),
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
    current_user: User = Depends(require_permission("playbook:execute")),
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
        action_data=data.action_data,
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
    data: ExecutionCompleteRequest = ExecutionCompleteRequest(),
    current_user: User = Depends(require_permission("playbook:execute")),
    session: Session = Depends(get_db_session),
):
    """Manually mark a playbook execution as completed with optional outcome."""
    from ion.models.playbook import ExecutionOutcome
    from ion.services.execution_report_service import ExecutionReportService

    repo = PlaybookRepository(session)
    execution = repo.get_execution(execution_id)

    if not execution:
        raise HTTPException(status_code=404, detail="Execution not found")

    if execution.status != ExecutionStatus.IN_PROGRESS.value:
        raise HTTPException(status_code=400, detail="Execution is not in progress")

    outcome = data.outcome
    outcome_notes = data.outcome_notes

    # Validate outcome value
    if outcome:
        valid_outcomes = [e.value for e in ExecutionOutcome]
        if outcome not in valid_outcomes:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid outcome. Must be one of: {valid_outcomes}",
            )

    execution = repo.complete_execution(
        execution, outcome=outcome, outcome_notes=outcome_notes
    )

    # Auto-generate investigation report
    report_document_id = None
    try:
        report_service = ExecutionReportService(session)
        document = report_service.generate_report(
            execution, analyst_username=current_user.username
        )
        report_document_id = document.id
    except Exception:
        logging.getLogger(__name__).exception(
            "Failed to generate report for execution %d", execution_id
        )

    session.commit()

    return {
        "execution": execution.to_dict(include_playbook=True),
        "report_document_id": report_document_id,
        "message": "Execution completed",
    }


@router.post("/playbook-executions/{execution_id}/regenerate-report")
async def regenerate_playbook_report(
    execution_id: int,
    current_user: User = Depends(require_permission("playbook:execute")),
    session: Session = Depends(get_db_session),
):
    """Regenerate the investigation report for a completed execution."""
    from ion.services.execution_report_service import ExecutionReportService

    repo = PlaybookRepository(session)
    execution = repo.get_execution(execution_id)

    if not execution:
        raise HTTPException(status_code=404, detail="Execution not found")

    if execution.status != ExecutionStatus.COMPLETED.value:
        raise HTTPException(status_code=400, detail="Execution is not completed")

    report_service = ExecutionReportService(session)
    document = report_service.regenerate_report(
        execution, analyst_username=current_user.username
    )
    session.commit()

    return {
        "execution": execution.to_dict(include_playbook=True),
        "report_document_id": document.id,
        "report_version": document.current_version,
        "message": "Report regenerated",
    }


@router.post("/playbook-executions/{execution_id}/fail")
async def fail_playbook_execution(
    execution_id: int,
    reason: Optional[str] = None,
    current_user: User = Depends(require_permission("playbook:execute")),
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


# ============================================================================
# Playbook Execution Dashboard & Case Integration
# ============================================================================


@router.get("/playbook-executions")
async def list_playbook_executions(
    status: Optional[str] = None,
    limit: int = 50,
    current_user: User = Depends(require_permission("playbook:execute")),
    session: Session = Depends(get_db_session),
):
    """Dashboard listing of playbook executions with progress info."""
    repo = PlaybookRepository(session)
    executions = repo.get_executions_dashboard(status=status, limit=limit)

    results = []
    for e in executions:
        data = e.to_dict(include_playbook=True)
        # Calculate progress
        steps = e.playbook.steps if e.playbook else []
        step_statuses = e.step_statuses or {}
        total_steps = len(steps)
        completed_steps = sum(
            1 for s in step_statuses.values()
            if isinstance(s, dict) and s.get("status") in ("completed", "skipped")
        )
        data["total_steps"] = total_steps
        data["completed_steps"] = completed_steps
        data["progress_pct"] = round((completed_steps / total_steps) * 100) if total_steps > 0 else 0
        results.append(data)

    return {"executions": results, "total": len(results)}


@router.get("/elasticsearch/alerts/cases/{case_id}/playbook-executions")
async def get_case_playbook_executions(
    case_id: int,
    current_user: User = Depends(require_permission("playbook:execute")),
    session: Session = Depends(get_db_session),
):
    """Get playbook executions linked to a case, auto-backfilling from alert triage."""
    from ion.models.alert_triage import AlertTriage, AlertCase

    # Verify case exists
    case = session.query(AlertCase).filter_by(id=case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    repo = PlaybookRepository(session)

    # Get directly linked executions
    linked = repo.get_executions_for_case(case_id)
    linked_ids = {e.id for e in linked}

    # Discover unlinked executions via alert triage entries
    triage_entries = session.query(AlertTriage).filter_by(case_id=case_id).all()
    alert_ids = [t.es_alert_id for t in triage_entries]

    discovered = []
    for alert_id in alert_ids:
        execs = repo.get_executions_for_alert(alert_id)
        for e in execs:
            if e.id not in linked_ids:
                # Auto-backfill case_id
                e.case_id = case_id
                linked_ids.add(e.id)
                discovered.append(e)

    if discovered:
        session.commit()

    all_executions = linked + discovered

    results = []
    for e in all_executions:
        data = e.to_dict(include_playbook=True)
        steps = e.playbook.steps if e.playbook else []
        step_statuses = e.step_statuses or {}
        total_steps = len(steps)
        completed_steps = sum(
            1 for s in step_statuses.values()
            if isinstance(s, dict) and s.get("status") in ("completed", "skipped")
        )
        data["total_steps"] = total_steps
        data["completed_steps"] = completed_steps
        data["progress_pct"] = round((completed_steps / total_steps) * 100) if total_steps > 0 else 0
        results.append(data)

    return {"executions": results, "total": len(results)}


@router.post("/elasticsearch/alerts/cases/{case_id}/playbook/{playbook_id}/start")
async def start_playbook_from_case(
    case_id: int,
    playbook_id: int,
    current_user: User = Depends(require_permission("playbook:execute")),
    session: Session = Depends(get_db_session),
):
    """Start a playbook execution from a case context."""
    from ion.models.alert_triage import AlertTriage, AlertCase

    # Verify case exists
    case = session.query(AlertCase).filter_by(id=case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    repo = PlaybookRepository(session)
    playbook = repo.get_playbook_by_id(playbook_id)
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    if not playbook.is_active:
        raise HTTPException(status_code=400, detail="Playbook is not active")

    # Find first alert in the case to use as target
    triage_entry = session.query(AlertTriage).filter_by(case_id=case_id).first()
    if not triage_entry:
        raise HTTPException(status_code=400, detail="Case has no linked alerts")

    alert_id = triage_entry.es_alert_id

    # Check for existing active execution
    existing = repo.get_active_execution_for_alert(alert_id, playbook_id)
    if existing:
        # Link to case if not already
        if not existing.case_id:
            existing.case_id = case_id
            session.commit()
        return {
            "execution": existing.to_dict(include_playbook=True),
            "message": "Execution already in progress",
            "already_started": True,
        }

    execution = repo.start_execution(
        playbook=playbook,
        es_alert_id=alert_id,
        executed_by_id=current_user.id,
        case_id=case_id,
    )
    session.commit()

    execution = repo.get_execution(execution.id)
    return {
        "execution": execution.to_dict(include_playbook=True),
        "message": "Playbook execution started from case",
    }


# ============================================================================
# Multi-Alert Pattern Detection
# ============================================================================

@router.get("/alerts/host-patterns")
async def get_host_patterns(
    hours: int = 24,
    current_user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
):
    """Detect multi-alert attack patterns grouped by host/user.

    Fetches alerts from Elasticsearch, runs pattern detection, matches to
    playbooks, and auto-starts executions for auto_execute patterns.
    """
    from ion.services.pattern_detection_service import PatternDetectionService

    config = get_elasticsearch_config()
    if not config.get("enabled"):
        return {"patterns": [], "total": 0, "message": "Elasticsearch is not enabled"}

    service = get_elasticsearch_service()
    if not service.is_configured:
        return {"patterns": [], "total": 0, "message": "Elasticsearch is not configured"}

    try:
        alerts = await service.get_alerts(hours=hours, limit=500)
    except ElasticsearchError as e:
        return {"patterns": [], "total": 0, "error": str(e)}

    if not alerts:
        return {"patterns": [], "total": 0}

    detector = PatternDetectionService()
    detected = detector.detect_patterns(alerts)

    repo = PlaybookRepository(session)
    results = []

    for pattern in detected:
        playbook = repo.find_playbook_for_pattern(pattern.pattern_id)

        pattern_data = pattern.to_dict()
        pattern_data["playbook"] = playbook.to_dict(include_steps=True) if playbook else None
        pattern_data["execution"] = None
        pattern_data["auto_started"] = False

        if playbook and pattern.auto_execute:
            # Auto-start: pick the first matched alert as the representative
            representative_alert_id = pattern.matched_alerts[0].id if pattern.matched_alerts else None
            if representative_alert_id:
                existing = repo.get_active_execution_for_alert(
                    representative_alert_id, playbook.id
                )
                if existing:
                    pattern_data["execution"] = existing.to_dict(include_playbook=True)
                else:
                    execution = repo.start_execution(
                        playbook=playbook,
                        es_alert_id=representative_alert_id,
                        executed_by_id=current_user.id,
                    )
                    pattern_data["execution"] = execution.to_dict(include_playbook=True)
                    pattern_data["auto_started"] = True

        results.append(pattern_data)

    if any(r.get("auto_started") for r in results):
        session.commit()

    return {
        "patterns": results,
        "total": len(results),
    }


# ============================================================
# ANALYST WORKSPACE — Knowledge Base Integration
# ============================================================

@router.get("/analyst/knowledge-base")
async def get_analyst_knowledge_base(
    current_user: User = Depends(require_permission("document:read")),
    session: Session = Depends(get_db_session),
):
    """Get SOC analyst knowledge base articles organized by collection.

    Returns articles from the 'Analyst Knowledge Base' collection,
    organized by topic for easy reference during alert triage and
    case investigation.
    """
    from ion.models.document import Document
    from ion.models.template import Collection

    # Find Knowledge Base parent collection
    analyst_kb = session.query(Collection).filter_by(
        name="Knowledge Base"
    ).first()

    if not analyst_kb:
        return {
            "status": "not_found",
            "message": "Knowledge Base not configured",
            "collections": []
        }

    # Get all child collections
    child_collections = session.query(Collection).filter_by(
        parent_id=analyst_kb.id
    ).order_by(Collection.name).all()

    result = {
        "status": "success",
        "parent": {
            "id": analyst_kb.id,
            "name": analyst_kb.name,
            "description": analyst_kb.description,
        },
        "collections": []
    }

    # For each collection, get its documents
    for collection in child_collections:
        docs = session.query(Document).filter_by(
            collection_id=collection.id
        ).order_by(Document.name).all()

        collection_data = {
            "id": collection.id,
            "name": collection.name,
            "description": collection.description,
            "article_count": len(docs),
            "articles": [
                {
                    "id": doc.id,
                    "name": doc.name,
                    "format": doc.output_format,
                    "tags": [t.name for t in doc.tags] if doc.tags else [],
                    "created_at": doc.created_at.isoformat() if doc.created_at else None,
                }
                for doc in docs
            ]
        }
        result["collections"].append(collection_data)

    return result


@router.get("/analyst/knowledge-base/search")
async def search_analyst_knowledge_base(
    q: str,
    current_user: User = Depends(require_permission("document:read")),
    session: Session = Depends(get_db_session),
):
    """Search analyst knowledge base by article title or content.

    Parameters:
        q: Search query string

    Returns: Matching articles with collection context
    """
    from ion.models.document import Document
    from ion.models.template import Collection

    # Find Knowledge Base parent
    analyst_kb = session.query(Collection).filter_by(
        name="Knowledge Base"
    ).first()

    if not analyst_kb:
        return {"results": [], "total": 0}

    # Get child collection IDs
    child_ids = [
        c.id for c in session.query(Collection).filter_by(
            parent_id=analyst_kb.id
        ).all()
    ]

    # Search documents in those collections
    search_term = f"%{q.lower()}%"
    docs = session.query(Document).filter(
        Document.collection_id.in_(child_ids),
        Document.name.ilike(search_term)
    ).order_by(Document.name).all()

    results = [
        {
            "id": doc.id,
            "name": doc.name,
            "collection_id": doc.collection_id,
            "collection_name": doc.collection.name if doc.collection else "Unknown",
            "format": doc.output_format,
            "tags": [t.name for t in doc.tags] if doc.tags else [],
            "created_at": doc.created_at.isoformat() if doc.created_at else None,
        }
        for doc in docs
    ]

    return {"results": results, "total": len(results)}


# =============================================================================
# DFIR-IRIS Integration Endpoints
# =============================================================================

@router.get("/iris/config")
async def get_iris_config_endpoint(
    current_user: User = Depends(get_current_user),
):
    """Get DFIR-IRIS configuration status (no sensitive data)."""
    config = get_dfir_iris_config()
    return {
        "enabled": config.get("enabled", False),
        "url": config.get("url", ""),
        "has_token": bool(config.get("api_key")),
        "verify_ssl": config.get("verify_ssl", True),
        "default_customer": config.get("default_customer", 1),
    }


@router.get("/iris/test")
async def test_iris_connection(
    current_user: User = Depends(get_current_user),
):
    """Test the DFIR-IRIS connection."""
    from ion.services.dfir_iris_service import get_dfir_iris_service
    from ion.core.config import get_config as _get_config, get_ssl_verify
    import httpx as _httpx
    service = get_dfir_iris_service()
    if not service.is_configured:
        return {"connected": False, "error": "DFIR-IRIS is not configured"}
    try:
        cfg = _get_config()
        async with _httpx.AsyncClient(
            headers={"Authorization": f"Bearer {cfg.dfir_iris_api_key}"},
            verify=get_ssl_verify(cfg.dfir_iris_verify_ssl),
            timeout=_httpx.Timeout(10.0, connect=5.0),
        ) as client:
            resp = await client.get(f"{cfg.dfir_iris_url}/api/versions")
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                return {
                    "connected": True,
                    "status": "ok",
                    "version": data.get("iris_current", "unknown"),
                    "api_version": data.get("api_current", "unknown"),
                }
            # Fallback to test_connection
            result = await service.test_connection()
            if result.get("success"):
                return {"connected": True, "status": "ok", "version": "unknown"}
            return {"connected": False, "error": result.get("error", "Connection failed")}
    except Exception as e:
        return {"connected": False, "error": str(e)}
