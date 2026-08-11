"""API routes for ION web interface."""

import asyncio
import json
import logging
import re

logger = logging.getLogger(__name__)
# Rate limiter - uses IP address as key
# Global default: 120 requests/minute per IP. Individual endpoints can override.
# Disable with ION_RATE_LIMIT_ENABLED=false in .env
import os as _os
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import quote as url_quote

import httpx
from fastapi import (
    APIRouter,
    Cookie,
    Depends,
    File,
    Form,
    HTTPException,
    Request,
    Response,
    UploadFile,
)
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.orm import Session, joinedload

from ion.core.client_ip import get_client_ip as _trusted_client_ip
from ion.core.config import (
    get_config,
    get_dfir_iris_config,
    get_gitlab_config,
    get_oidc_config,
    get_ssl_verify,
)
from ion.core.safe_errors import safe_error
from ion.services.dfir_iris_service import get_dfir_iris_service
from ion.services.kibana_cases_service import get_kibana_cases_service
from ion.services.kibana_sync_helpers import (
    sync_note_to_kibana,
)
from ion.services.observable_extractor import extract_observables_from_raw

_rate_limit_enabled = _os.environ.get("ION_RATE_LIMIT_ENABLED", "true").lower() not in ("false", "0", "no")

# kill switch for the multi-alert pattern detector's auto-start
# branch in /alerts/host-patterns. Defaults to OFF — analysts asked for
# explicit "Start Playbook" clicks instead of surprise executions
# appearing on the case timeline. Flip ION_AUTO_PLAYBOOK_ENABLED=true
# in .env to restore the v0.19.x behaviour.
_auto_playbook_enabled = _os.environ.get(
    "ION_AUTO_PLAYBOOK_ENABLED", "false"
).lower() in ("true", "1", "yes")
def _rate_limit_key(request) -> str:
    """Rate-limit bucket key: the trusted-proxy-aware client IP (v0.39.3).

    slowapi's default get_remote_address keys on the TCP peer, which behind a
    shared ingress is the proxy IP — collapsing every user into one bucket.
    Keying on the canonical client IP fixes that; set ION_TRUSTED_PROXIES so it
    resolves the real client rather than the ingress. Falls back to the peer.
    """
    return _trusted_client_ip(request) or get_remote_address(request)


limiter = Limiter(
    key_func=_rate_limit_key,
    default_limits=["120/minute"],
    enabled=_rate_limit_enabled,
)

# OIDC state cookie name for CSRF protection
OIDC_STATE_COOKIE_NAME = "oidc_state"
from ion.auth.dependencies import (
    SESSION_COOKIE_NAME,
    get_auth_service,
    get_client_ip,
    get_current_user,
    get_session_token,
    require_admin,
    require_permission,
)
from ion.auth.service import AuthService
from ion.core.exceptions import (
    RenderError,
    TemplateNotFoundError,
    ValidationError,
    VersionNotFoundError,
)
from ion.models.user import User
from ion.services.render_service import RenderService
from ion.services.template_service import TemplateService
from ion.services.version_service import VersionService
from ion.storage.auth_repository import AuditLogRepository
from ion.storage.database import get_db_session
from ion.storage.document_repository import DocumentRepository
from ion.storage.user_repository import RoleRepository, UserRepository

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


# get_db_session is the canonical request-scoped session dependency defined in
# ion.storage.database; it is imported above and re-exported here so the ~45
# routers that do `from ion.web.api import get_db_session` keep working from a
# single source of truth.


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
@limiter.limit("10/minute")
async def login(
    request: Request,
    login_request: LoginRequest,
    response: Response,
    session: Session = Depends(get_db_session),
):
    """Login and create session. Rate-limited to 10/min per IP."""
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


@router.post("/auth/change-password")
@limiter.limit("5/minute")
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
    # Helper to create safe redirect with URL-encoded error.
    # The path is hard-coded to /login; only the error message is data-driven
    # and is URL-encoded with `safe=''` so EVERY character (including /, ?, #)
    # is percent-encoded. This makes the redirect provably target /login.
    def error_redirect(msg: str) -> RedirectResponse:
        encoded = url_quote(str(msg or "Login failed"), safe="")
        resp = RedirectResponse(
            url="/login?error=" + encoded,
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
        from ion.auth.oidc import OIDCUserSync, OIDCValidationError, OIDCValidator
        from ion.storage.auth_repository import AuditLogRepository

        validator = OIDCValidator(oidc_config)
        token_data = await validator.validate_token_async(tokens["access_token"])
        # scrubbed email out of the INFO message — every login
        # was emitting the user's email to the log index, which under ECS
        # log shipping ends up in long-term storage. Username alone is
        # enough for trace correlation; email is logged at DEBUG only.
        logger.info(f"OIDC callback: token validated for {token_data.preferred_username}")
        logger.debug(f"OIDC callback: token email = {token_data.email}")

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
        return error_redirect("Token validation failed")
    except httpx.HTTPError as e:
        logger.error(f"OIDC token exchange HTTP error: {e}", exc_info=True)
        return error_redirect("Authentication service unavailable")
    except ValueError as e:
        # User creation failed (auto-create disabled). Log the full message
        # server-side, but show a generic reason to the user.
        logger.warning(f"OIDC user sync failed: {e}")
        return error_redirect("Account provisioning failed")
    except Exception as e:
        logger.error(f"Unexpected OIDC callback error: {e}", exc_info=True)
        return error_redirect("Authentication failed")


# =============================================================================
# User management endpoints (admin only)
# =============================================================================

@router.get("/users/assignable", dependencies=[Depends(require_permission("alert:read"))])
async def list_assignable_users(
    session: Session = Depends(get_db_session),
):
    """Lightweight user list for assignment pickers.

    Returns only the fields a picker needs: id, username, display_name, and
    elastic_uid (so callers can show which users have a Kibana profile mapped).
    Gated by `alert:read` so every analyst can populate their assignment
    dropdown — `/api/users` requires `user:read` which analysts don't have.
    """
    def _query_assignable():
        user_repo = UserRepository(session)
        users = user_repo.list_all(include_inactive=False)
        return {
            "users": [
                {
                    "id": u.id,
                    "username": u.username,
                    "display_name": u.display_name or u.username,
                    "has_elastic_profile": bool(getattr(u, "elastic_uid", None)),
                }
                for u in users
            ]
        }

    return await asyncio.to_thread(_query_assignable)


@router.get("/users", dependencies=[Depends(require_permission("user:read"))])
async def list_users(
    include_inactive: bool = False,
    session: Session = Depends(get_db_session),
):
    """List all users (admin only)."""
    def _query_users():
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
                "elastic_username": getattr(u, "elastic_username", None),
                "elastic_uid": getattr(u, "elastic_uid", None),
                "keycloak_sub": getattr(u, "keycloak_sub", None),
                "gitlab_username": getattr(u, "gitlab_username", None),
                "created_at": u.created_at.isoformat() if u.created_at else None,
            }
            for u in users
        ]

    return await asyncio.to_thread(_query_users)


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
    try:
        auth_service.reset_password(
            user=user,
            new_password=password_reset.new_password,
            must_change=password_reset.must_change,
            admin_user_id=current_user.id,
            ip_address=get_client_ip(request),
        )
    except ValueError as exc:
        # Password-policy violation (opt-in F6) — surface as a 400 rather than 500.
        raise HTTPException(status_code=400, detail=str(exc))

    session.commit()

    return {"message": "Password reset successfully"}


# =============================================================================
# Roles endpoint
# =============================================================================

@router.get("/roles", dependencies=[Depends(require_permission("user:read"))])
async def list_roles(
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """List all roles.

    v0.19.17: gated on user:read (matches /users). The endpoint
    returns the full role-to-permission map, useful for an
    authenticated attacker planning privilege escalation. Most
    analysts have no legitimate reason to enumerate roles; admins
    and team leads who do will already have user:read.
    """
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

def _parse_audit_details(raw: Optional[str]):
    """Audit ``details`` is usually a JSON object, but some historical
    producers stored a bare string (e.g. ``"203.0.113.0/24"``,
    ``"deleted entry 2"``). ``json.loads`` on those raises and, in a list
    comprehension, 500s the WHOLE audit-log page. Fall back to the raw string
    so one legacy row can't blank the entire view (the frontend
    ``formatDetails`` already renders a plain string). (v0.49.5)
    """
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        return raw


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
            "details": _parse_audit_details(log.details),
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
        raise HTTPException(status_code=400, detail=safe_error(e))


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
        raise HTTPException(status_code=400, detail=safe_error(e))


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
        raise HTTPException(status_code=400, detail=safe_error(e))


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
        raise HTTPException(status_code=400, detail=safe_error(e))


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
        raise HTTPException(status_code=404, detail=safe_error(e))


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
        raise HTTPException(status_code=400, detail=safe_error(e))


@router.get("/templates/{template_id}/diff/{from_version}/{to_version}", dependencies=[Depends(require_permission("template:read"))])
async def diff_versions(template_id: int, from_version: int, to_version: int, services: Services = Depends(get_services)):
    """Get diff between two versions."""
    try:
        diff = services.version.diff_versions(template_id, from_version, to_version)
        return {"diff": diff}
    except (TemplateNotFoundError, VersionNotFoundError) as e:
        raise HTTPException(status_code=404, detail=safe_error(e))


@router.post("/templates/{template_id}/rollback/{to_version}", dependencies=[Depends(require_permission("template:update"))])
async def rollback_version(template_id: int, to_version: int, message: Optional[str] = None, services: Services = Depends(get_services)):
    """Rollback to a previous version."""
    try:
        t = services.version.rollback(template_id, to_version, message)
        services.session.commit()
        return {"current_version": t.current_version, "message": "Rollback successful"}
    except (TemplateNotFoundError, VersionNotFoundError) as e:
        raise HTTPException(status_code=404, detail=safe_error(e))


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
        raise HTTPException(status_code=400, detail=safe_error(e))


@router.post("/templates/{template_id}/render")
async def render_template(
    template_id: int,
    render_request: RenderRequest,
    document_name: Optional[str] = None,
    current_user: User = Depends(require_permission("document:create")),
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
        # rendering a template is a create path too — stamp the author
        # so the person who produced the document can remove it again.
        if document:
            document.created_by_id = current_user.id
        services.session.commit()

        return {
            "rendered": content,
            "document_id": document.id if document else None,
        }
    except TemplateNotFoundError:
        raise HTTPException(status_code=404, detail="Template not found")
    except RenderError as e:
        raise HTTPException(status_code=400, detail=safe_error(e))


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
        raise HTTPException(status_code=400, detail=safe_error(e))

    template = services.template.get_template(template_id)
    fmt = render_request.output_format or (template.format if template else "markdown")
    title = template.name if template else "Document"

    try:
        from ion.services.pdf_export_service import _content_to_html, generate_pdf
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


@router.post("/templates/{template_id}/batch-render")
async def batch_render_template(
    template_id: int,
    batch_request: BatchRenderRequest,
    current_user: User = Depends(require_permission("document:create")),
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
        # a batch is still authored work — stamp every document it
        # saved, or the person who ran it could not delete any of them.
        from ion.models.document import Document

        saved_ids = [r.document_id for r in summary.results if r.document_id]
        if saved_ids:
            services.session.query(Document).filter(
                Document.id.in_(saved_ids)
            ).update({"created_by_id": current_user.id}, synchronize_session=False)
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
        raise HTTPException(status_code=400, detail=safe_error(e))


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
@router.post("/documents/upload")
async def upload_document(
    file: UploadFile = File(...),
    name: Optional[str] = Form(None),
    output_format: Optional[str] = Form(None),
    tags: Optional[str] = Form(None),
    collection_id: Optional[int] = Form(None),
    current_user: User = Depends(require_permission("document:create")),
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
    text_content = content.decode("utf-8", errors="ignore")

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
        rendered_content=text_content,
        output_format=output_format,
    )
    # stamp the author. This is what later lets them delete it again
    # without holding document:delete.
    document.created_by_id = current_user.id

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

    try:
        AuditLogRepository(services.session).create(
            action="document_create",
            user_id=current_user.id,
            resource_type="document",
            resource_id=document.id,
            details=f"name={document.name}; via=upload",
        )
        services.session.commit()
    except Exception:
        logger.exception("document_create audit log write failed (non-fatal)")

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
        # the list endpoint returns these two, the detail endpoint did
        # not — so anything opening a document directly (the KB deep-link, the
        # rebuilt panel) could not say which folder it was in or who wrote it.
        "collection_id": document.collection_id,
        "created_by_id": document.created_by_id,
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


@router.delete("/documents/{document_id}")
async def delete_document(
    document_id: int,
    current_user: User = Depends(require_permission("document:read")),
    services: Services = Depends(get_services),
):
    """Delete a document — your own, or anyone's with ``document:delete``.

    v0.79.0. The endpoint gate is ``document:read`` (which everyone holds)
    because the real rule is about OWNERSHIP, not about a role: an analyst who
    added a document can remove it again, and nobody else's work. That check
    runs HERE, before the delete, against the row we just loaded — an
    ownership rule enforced in the caller or the UI is not enforced at all
    (the v0.20.1 workbench TOCTOU lesson).

    Documents created before ``created_by_id`` existed have no owner, so they
    fall through to the ``document:delete`` branch — unowned work is not
    everyone's to delete.
    """
    document = services.render.get_document(document_id)
    if not document:
        raise HTTPException(status_code=404, detail="Document not found")

    owner_id = getattr(document, "created_by_id", None)
    is_owner = owner_id is not None and owner_id == current_user.id
    may_delete_any = current_user.has_permission("document:delete")
    if not (is_owner or may_delete_any):
        raise HTTPException(
            status_code=403,
            detail="You can only delete documents you created.",
        )

    doc_name = document.name
    services.render.delete_document(document_id)
    services.session.commit()

    # Audit AFTER the commit that removed it: the entry records a delete that
    # actually happened. resource_id is kept even though the row is gone — it
    # is what ties the entry to the document referenced elsewhere.
    try:
        AuditLogRepository(services.session).create(
            action="document_delete",
            user_id=current_user.id,
            resource_type="document",
            resource_id=document_id,
            details=f"name={doc_name}; as={'owner' if is_owner else 'document:delete'}",
        )
        services.session.commit()
    except Exception:
        logger.exception("document_delete audit log write failed (non-fatal)")

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
        raise HTTPException(status_code=404, detail=safe_error(e))


# Health check endpoint (no auth required)
def _health_core() -> dict:
    """Shared version + database-type block used by /health and /health/deep.

    Both endpoints used to re-import __version__ and re-build the dialect
    lookup independently (audit Amend C). Centralising here so a future
    field change lands once.
    """
    from ion import __version__
    from ion.storage.database import get_engine
    engine = get_engine()
    return {"database": engine.dialect.name, "version": __version__}


@router.get("/health")
async def health_check():
    """Health check for Docker/load balancers. Returns basic status."""
    return {"status": "ok", **_health_core()}


@router.get("/health/deep")
async def deep_health_check(
    current_user: User = Depends(get_current_user),
):
    """Deep health check — probes all integrations. Not for load balancers
    (too slow), but useful for dashboards and monitoring.

    v0.19.17: now requires authentication. The endpoint enumerates
    every configured integration (ES, Kibana, OpenCTI, TIDE, etc.)
    plus their connectivity error strings — useful pre-auth recon
    for an attacker mapping the deployment topology. /health (the
    shallow check used by load balancers) stays public.
    """
    from ion.core.config import get_config

    config = get_config()
    checks = dict(_health_core())

    # Elasticsearch
    try:
        es_svc = get_elasticsearch_service()
        if es_svc.is_configured:
            es_result = await es_svc.test_connection()
            checks["elasticsearch"] = {
                "status": "ok" if es_result.get("connected") else "error",
                "cluster": es_result.get("cluster_name"),
            }
        else:
            checks["elasticsearch"] = {"status": "not_configured"}
    except Exception as e:
        checks["elasticsearch"] = {"status": "error", "error": safe_error(e, "health.elasticsearch")}

    # TIDE
    try:
        from ion.services.tide_service import get_tide_service
        tide = get_tide_service()
        if tide.enabled:
            result = tide.test_connection()
            checks["tide"] = {
                "status": "ok" if result.get("ok") else "error",
                "rules": result.get("rule_count", 0),
                "space": result.get("space"),
            }
        else:
            checks["tide"] = {"status": "not_configured"}
    except Exception as e:
        checks["tide"] = {"status": "error", "error": safe_error(e, "health.tide")}

    # Ollama
    try:
        from ion.services.ollama_service import get_ollama_service
        ollama = get_ollama_service()
        avail = await ollama.is_available()
        checks["ollama"] = {"status": "ok" if avail else "unavailable"}
    except Exception as e:
        checks["ollama"] = {"status": "error", "error": safe_error(e, "health.ollama")}

    # OpenCTI
    try:
        from ion.services.opencti_service import get_opencti_service
        opencti = get_opencti_service()
        if opencti.is_configured:
            result = await opencti.test_connection()
            checks["opencti"] = {
                "status": "ok" if result.get("connected") else "error",
            }
        else:
            checks["opencti"] = {"status": "not_configured"}
    except Exception as e:
        checks["opencti"] = {"status": "error", "error": safe_error(e, "health.opencti")}

    # Arkime
    try:
        from ion.services.arkime_service import get_arkime_service
        arkime = get_arkime_service()
        if arkime.is_configured:
            result = await arkime.test_connection()
            checks["arkime"] = {
                "status": "ok" if result.get("connected") else "error",
                "auth_mode": result.get("auth_mode"),
            }
        else:
            checks["arkime"] = {"status": "not_configured"}
    except Exception as e:
        checks["arkime"] = {"status": "error", "error": safe_error(e, "health.arkime")}

    overall = "ok" if all(
        c.get("status") in ("ok", "not_configured")
        for c in checks.values() if isinstance(c, dict)
    ) else "degraded"

    return {"status": overall, "checks": checks}


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
    # Lightweight counts + recent items — avoids loading all templates/docs
    # just to count them (was 600ms+, now ~5ms).
    # Wrapped in to_thread so sync DB calls don't block the event loop.
    def _fetch_db_stats():
        tc = services.template.template_repo.count()
        dc = services.document_repo.count()
        tgc = services.template.template_repo.count_tags()
        rt = services.template.template_repo.list_recent(5)
        rd = services.document_repo.list_recent(5)
        # Serialize while session is still open (accesses lazy relationships)
        rt_dicts = [
            {
                "id": t.id,
                "name": t.name,
                "format": t.format.value if hasattr(t.format, 'value') else t.format,
                "updated_at": t.updated_at.isoformat() if t.updated_at else None,
                "tags": [tag.name for tag in t.tags],
            }
            for t in rt
        ]
        rd_dicts = [
            {
                "id": d.id,
                "name": d.name,
                "template_name": d.source_template.name if d.source_template else "Unknown",
                "updated_at": d.updated_at.isoformat() if d.updated_at else None,
                "status": d.status,
            }
            for d in rd
        ]
        return tc, dc, tgc, rt_dicts, rd_dicts

    template_count, document_count, tag_count, recent_templates, recent_docs = (
        await asyncio.to_thread(_fetch_db_stats)
    )

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
                data["error"] = safe_error(e)
        return data

    async def fetch_elasticsearch_data():
        data = {
            "enabled": False,
            "connected": False,
            "alerts": [],
            "total_alerts": 0,
            "critical_count": 0,
            "high_count": 0,
            "alerts_histogram": [],
        }
        es_config = get_elasticsearch_config()
        if es_config.get("enabled") and es_config.get("url"):
            data["enabled"] = True
            try:
                from ion.services.elasticsearch_service import ElasticsearchService
                es_service = ElasticsearchService()
                if es_service.is_configured:
                    # Skip test_connection() — the alerts query itself will
                    # fail fast if ES is down, saving a redundant round-trip.
                    try:
                        alerts, histogram = await asyncio.gather(
                            es_service.get_alerts(hours=24, limit=10),
                            es_service.get_alerts_histogram(hours=24, interval="1h"),
                        )
                        data["connected"] = True
                        data["alerts"] = [a.to_dict(include_raw=False) for a in alerts]
                        data["total_alerts"] = len(alerts)
                        data["critical_count"] = sum(1 for a in alerts if a.severity == "critical")
                        data["high_count"] = sum(1 for a in alerts if a.severity == "high")
                        data["alerts_histogram"] = histogram or []
                    except Exception:
                        data["error"] = "Elasticsearch connection failed"
            except Exception as e:
                data["error"] = safe_error(e)
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
            "templates_count": template_count,
            "documents_count": document_count,
            "tags_count": tag_count,
        },
        "recent_templates": recent_templates,
        "recent_documents": recent_docs,
        "gitlab": gitlab_data,
        "elasticsearch": elasticsearch_data,
    }


@router.get("/dashboard/team-metrics", dependencies=[Depends(require_permission("alert:read"))])
async def get_team_metrics(
    current_user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
):
    """Team performance metrics for Lead dashboard."""
    # Wrapped in to_thread — this endpoint runs 8+ DB queries (counts,
    # aggregations, per-assignee lookups) that would block the loop.
    def _compute_team_metrics():
        from sqlalchemy import func as sqlfunc

        from ion.models.alert_triage import (
            AlertCase,
            AlertCaseStatus,
            AlertTriage,
            AlertTriageStatus,
        )

        now = datetime.utcnow()

        open_cases = session.query(sqlfunc.count(AlertCase.id)).filter(
            AlertCase.status != AlertCaseStatus.CLOSED
        ).scalar() or 0

        unassigned_alerts = session.query(sqlfunc.count(AlertTriage.id)).filter(
            AlertTriage.case_id.is_(None),
            AlertTriage.status == AlertTriageStatus.OPEN,
        ).scalar() or 0

        thirty_days_ago = now - timedelta(days=30)
        closed_cases_30d = session.query(AlertCase).filter(
            AlertCase.closed_at >= thirty_days_ago,
            AlertCase.closed_at.isnot(None),
        ).all()

        mttr = None
        if closed_cases_30d:
            durations = [(c.closed_at - c.created_at).total_seconds() / 3600 for c in closed_cases_30d]
            mttr = round(sum(durations) / len(durations), 1)

        seven_days_ago = now - timedelta(days=7)
        created_7d = session.query(sqlfunc.count(AlertCase.id)).filter(
            AlertCase.created_at >= seven_days_ago
        ).scalar() or 0
        closed_7d = session.query(sqlfunc.count(AlertCase.id)).filter(
            AlertCase.closed_at >= seven_days_ago
        ).scalar() or 0

        severity_rows = session.query(
            AlertCase.severity, sqlfunc.count(AlertCase.id)
        ).filter(
            AlertCase.status != AlertCaseStatus.CLOSED
        ).group_by(AlertCase.severity).all()
        severity_counts = dict(severity_rows)

        assignee_rows = session.query(
            AlertCase.assigned_to_id,
            sqlfunc.count(AlertCase.id),
        ).filter(
            AlertCase.status != AlertCaseStatus.CLOSED
        ).group_by(AlertCase.assigned_to_id).all()

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

    return await asyncio.to_thread(_compute_team_metrics)


# Sample templates endpoint
# =============================================================================
# GitLab Integration Endpoints
# =============================================================================





# ============================================================================
# Elasticsearch Alerts Endpoints
# ============================================================================

from ion.core.config import get_elasticsearch_config
from ion.services.elasticsearch_service import ElasticsearchError, ElasticsearchService


def get_elasticsearch_service() -> ElasticsearchService:
    """Get configured Elasticsearch service instance."""
    return ElasticsearchService()






















# ============================================================================
# Alert Triage, Comments & Case Management Endpoints
# ============================================================================

from ion.models.alert_triage import (
    AlertCase,
    AlertCaseStatus,
    AlertTriage,
    AlertTriageStatus,
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


class CommentCreate(BaseModel):
    content: str




_case_es_logger = logging.getLogger(__name__)






# ──────────────────────────────────────────────────────────────────────────
# Case-update background sync helpers
#
# Every helper opens its OWN DB session — request-scoped sessions are
# closed by the time FastAPI schedules these, so they cannot borrow the
# caller's session. Each one is a best-effort fire-and-forget: exceptions
# are logged, never re-raised, so a dead downstream never causes the
# user-visible PATCH to 500.
# ──────────────────────────────────────────────────────────────────────────











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
        from ion.models.document import Document
        from ion.models.template import Collection

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




class BatchTriageRequest(BaseModel):
    alert_ids: List[str]


class BatchTriageRequestWithStatus(BaseModel):
    """Batch triage request that can include ES-side statuses for sync."""
    alert_ids: List[str]
    es_statuses: Optional[Dict[str, str]] = None  # { alert_id: "open"|"acknowledged"|"closed" }


# ThreatLevel ordering from models/observable.py. "unknown" is the floor, not a
# clean bill of health — an observable nobody has enriched yet is not benign.
_THREAT_ORDER = ["critical", "high", "medium", "low", "benign", "unknown"]


def _worst_observable_threat(observables: list, levels: Optional[Dict[str, str]] = None) -> str:
    """Highest threat level among an alert's observables.

    AlertTriage.observables is a free-form JSON snapshot written by several
    producers (triage extraction, the AI extractor, manual entry). In practice it
    stores only ``{"type", "value"}`` — enrichment lives on the Observable
    registry, not here — so the level is looked up by normalised value via
    ``levels``. Reading only the snapshot returns "unknown" for every alert,
    which renders as a column that never changes.

    A row may still be a bare string or carry its own threat_level. Malformed
    input must not decide the answer, and must not raise on a list endpoint.
    """
    worst = len(_THREAT_ORDER) - 1
    for o in observables:
        if not isinstance(o, dict):
            continue
        level = o.get("threat_level")
        if not level and levels:
            level = levels.get(str(o.get("value", "")).strip().lower())
        level = str(level or "unknown").lower()
        if level in _THREAT_ORDER:
            worst = min(worst, _THREAT_ORDER.index(level))
    return _THREAT_ORDER[worst]


def _observable_threat_levels(session: Session, triages: list) -> Dict[str, str]:
    """Map normalised observable value -> threat level, in ONE query per batch.

    Looked up by value alone rather than (type, value): the snapshot's type
    strings come from a different vocabulary than ObservableType in places
    ("ip" vs "ipv4"), and a value collision across types would at worst
    over-report severity, which is the safe direction for a triage queue.
    """
    from ion.models.observable import Observable

    wanted = set()
    for t in triages:
        obs = t.observables if isinstance(t.observables, list) else []
        for o in obs:
            if isinstance(o, dict) and o.get("value"):
                wanted.add(str(o["value"]).strip().lower())
    if not wanted:
        return {}
    rows = (
        session.query(Observable.normalized_value, Observable.threat_level)
        .filter(Observable.normalized_value.in_(wanted))
        .all()
    )
    out: Dict[str, str] = {}
    for value, level in rows:
        lvl = level.value if hasattr(level, "value") else str(level or "")
        out[str(value).strip().lower()] = lvl.split(".")[-1].lower()
    return out


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

    # Wrapped in to_thread — multiple DB queries + potential writes per alert
    # in the batch would block the event loop for the entire batch duration.
    def _batch_triage():
        # case and assigned_to are both read for every row below. Lazy-loading
        # them issues one SELECT per alert, and this endpoint is called with up
        # to 500 ids — the same shape as the alert_triage seq scan that was half
        # of production response time at v0.79.4.
        triages = (
            session.query(AlertTriage)
            .options(
                joinedload(AlertTriage.case),
                joinedload(AlertTriage.assigned_to),
            )
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
                    ion_status = triage.status.value if hasattr(triage.status, "value") else str(triage.status)
                    if ion_status.lower() != es_status_lower:
                        triage.status = AlertTriageStatus(es_status_lower)
                        logger.debug("Synced ES status '%s' → ION triage for alert %s", es_status_lower, alert_id)
                else:
                    if es_status_lower != "open":
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

        # one lookup for the whole batch, not one per alert
        threat_levels = _observable_threat_levels(session, list(triage_map.values()))

        result = {}
        for t in triage_map.values():
            # Observables can be long; the queue only needs the count and the
            # worst threat level, so the list is summarised rather than shipped
            # 500 times over. The detail panel already fetches the full set.
            obs = t.observables if isinstance(t.observables, list) else []
            result[t.es_alert_id] = {
                "status": t.status.value if hasattr(t.status, "value") else t.status,
                "priority": t.priority,
                "case_id": t.case_id,
                "case_number": t.case.case_number if t.case else None,
                "case_title": t.case.title if t.case else None,
                "assigned_to": t.assigned_to.username if t.assigned_to else None,
                # advisory only — the queue renders it as model output, never as
                # a verdict ION asserts
                "suggested_verdict": t.suggested_verdict,
                "suggested_verdict_confidence": t.suggested_verdict_confidence_int,
                "observable_count": len(obs),
                "observable_threat": _worst_observable_threat(obs, threat_levels),
            }

        return {"triage": result}

    return await asyncio.to_thread(_batch_triage)


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
        from ion.services.case_numbering import assign_case_number

        new_case = AlertCase(
            title=data.new_case_title,
            status=AlertCaseStatus.OPEN,
            severity=data.new_case_severity or "medium",
            created_by_id=current_user.id,
            source_alert_ids=data.alert_ids,
        )
        # Collision-free number from the DB-assigned id (was max(id)+1 — raced).
        assign_case_number(session, new_case)

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
    """Get triage state and comments for an alert.

    Also queries investigation memory for prior investigations, IOC context,
    and false-positive likelihood so the analyst sees relevant history inline.
    """
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
            "source_system": triage.source_system,
            # Bob confidence scoring + circuit breaker
            "suggested_verdict": getattr(triage, "suggested_verdict", None),
            "suggested_verdict_confidence": getattr(triage, "suggested_verdict_confidence", None),
            "suggested_verdict_confidence_int": getattr(triage, "suggested_verdict_confidence_int", None),
            "bob_escalation_badge": getattr(triage, "bob_escalation_badge", None),
        }

        # emit an alert_view audit event keyed on the triage PK so
        # the adaptive lab grader can back-correlate via lab_session_fixtures
        # (which stores materialised_row_id = AlertTriage.id). Cheap insert;
        # the existing (user_id, action) index covers the grader's lookup.
        try:
            AuditLogRepository(session).create(
                action="alert_view",
                user_id=current_user.id,
                resource_type="alert_triage",
                resource_id=triage.id,
                details=f"es_alert_id={alert_id}",
            )
            session.commit()
        except Exception:
            logger.exception("alert_view audit log write failed (non-fatal)")
            session.rollback()

    # ------------------------------------------------------------------
    # Investigation memory enrichment
    # ------------------------------------------------------------------
    prior_investigations: list = []
    ioc_context: dict = {}
    fp_likelihood: dict = {"is_fp": False, "reason": None}

    try:
        from ion.services.investigation_memory_service import get_investigation_memory_service
        mem_svc = get_investigation_memory_service()

        # Build a lightweight alert dict for memory lookups. Use triage
        # fields + try fetching the live ES alert for richer data.
        alert_dict: dict = {"_id": alert_id}
        _rule_name = None
        _source_ip = None
        _dest_ip = None

        try:
            from ion.services.elasticsearch_service import ElasticsearchService
            _es = ElasticsearchService()
            if _es.is_configured:
                _hits = await _es.get_alerts_by_ids([alert_id])
                if _hits:
                    _hit = _hits[0]
                    _rule_name = _hit.rule_name
                    _source_ip = _hit.source_ip
                    _dest_ip = _hit.destination_ip
                    alert_dict.update({
                        "rule_name": _rule_name,
                        "rule.name": _rule_name,
                        "host.name": _hit.host,
                        "user.name": _hit.user,
                        "source.ip": _source_ip,
                        "destination.ip": _dest_ip,
                    })
                    if _hit.raw_data:
                        alert_dict["_source"] = _hit.raw_data
                    # Auto-extract observables if triage exists but has none
                    if triage and not triage.observables and _hit.raw_data:
                        try:
                            populated = _populate_triage_observables(
                                triage, _hit.host, _hit.user, _hit.raw_data
                            )
                            if populated:
                                session.commit()
                                # Refresh triage_data with the new observables
                                if triage_data:
                                    triage_data["observables"] = triage.observables
                                # Background-enrich the extracted observables
                                _obs_to_enrich = list(triage.observables or [])
                                _triage_id = triage.id
                                if _obs_to_enrich:
                                    import asyncio
                                    asyncio.ensure_future(
                                        _background_enrich_triage_observables(_triage_id, _obs_to_enrich)
                                    )
                        except Exception:
                            session.rollback()

        except Exception as _es_err:
            logger.debug("Triage memory: ES lookup failed for %s: %s", alert_id, _es_err)

        # 1. Prior investigations for the same rule/signature
        if _rule_name:
            past = mem_svc.past_for_signature(_rule_name, limit=5)
            for inv in past:
                prior_investigations.append({
                    "id": inv.id,
                    "verdict": inv.verdict,
                    "severity": inv.severity_assessment,
                    "summary": (inv.summary_text or "")[:200],
                    "created_at": inv.created_at.isoformat() if inv.created_at else None,
                })

        # 2. IOC sightings for source/dest IPs
        for _ioc_label, _ioc_val in [("source_ip", _source_ip), ("destination_ip", _dest_ip)]:
            if _ioc_val:
                sighting = mem_svc.lookup_ioc("ip", _ioc_val)
                if sighting:
                    ioc_context[_ioc_label] = {
                        "value": sighting.ioc_value,
                        "seen_count": sighting.seen_count,
                        "is_known_bad": sighting.is_known_bad,
                        "is_known_good": sighting.is_known_good,
                        "last_seen": sighting.last_seen_at.isoformat() if sighting.last_seen_at else None,
                    }

        # 3. FP likelihood
        is_fp, fp_sig = mem_svc.is_likely_fp(alert_dict)
        if is_fp and fp_sig:
            fp_likelihood = {
                "is_fp": True,
                "reason": fp_sig.reason,
                "confidence": fp_sig.confidence,
                "rule_name": fp_sig.rule_name,
            }
    except Exception as _mem_err:
        logger.debug("Triage memory enrichment failed for %s: %s", alert_id, _mem_err)

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
        "prior_investigations": prior_investigations,
        "ioc_context": ioc_context,
        "fp_likelihood": fp_likelihood,
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
    is_new = triage is None
    if is_new:
        triage = AlertTriage(es_alert_id=alert_id)
        session.add(triage)
        session.flush()

    # Snapshot source_system + auto-extract observables on first triage touch
    if is_new or not triage.source_system or not triage.observables:
        try:
            from ion.services.elasticsearch_service import ElasticsearchService
            _es = ElasticsearchService()
            if _es.is_configured:
                _hits = await _es.get_alerts_by_ids([alert_id])
                if _hits:
                    _hit = _hits[0]
                    if not triage.source_system and _hit.source_system:
                        triage.source_system = _hit.source_system
                    # Auto-extract observables from raw alert data
                    if not triage.observables and _hit.raw_data:
                        _populate_triage_observables(
                            triage, _hit.host, _hit.user, _hit.raw_data
                        )
                        # Background-enrich after extraction
                        if triage.observables:
                            _obs = list(triage.observables)
                            _tid = triage.id
                            import asyncio
                            asyncio.ensure_future(
                                _background_enrich_triage_observables(_tid, _obs)
                            )
        except Exception as e:
            logger.debug(f"Failed to snapshot/extract for {alert_id}: {e}")

    status_changed = False
    if data.status is not None:
        triage.status = data.status
        status_changed = True
    if data.assigned_to_id is not None:
        triage.assigned_to_id = data.assigned_to_id
    if data.priority is not None:
        triage.priority = data.priority
    if data.case_id is not None:
        # track whether the case link actually changed so the audit
        # row only fires on a real transition (not a no-op re-PATCH).
        _case_id_changed = triage.case_id != data.case_id
        triage.case_id = data.case_id
        if _case_id_changed:
            try:
                AuditLogRepository(session).create(
                    action="alert_linked",
                    user_id=current_user.id,
                    resource_type="alert_triage",
                    resource_id=triage.id,
                    details={
                        "case_id": data.case_id,
                        "es_alert_id": alert_id,
                    },
                )
            except Exception:
                logger.exception(
                    "alert_linked audit write failed (PUT triage path, non-fatal)"
                )
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


async def _background_enrich_triage_observables(triage_id: int, observables: list) -> None:
    """Background task: enrich extracted observables via OpenCTI and persist results."""
    try:
        from ion.services.opencti_service import get_opencti_service
        opencti = get_opencti_service()
        if not opencti.is_configured:
            return

        # Map observable types to OpenCTI lookup types
        type_map = {
            "source_ip": "ipv4-addr", "destination_ip": "ipv4-addr", "host_ip": "ipv4-addr",
            "hostname": "domain-name", "source_hostname": "domain-name", "destination_hostname": "domain-name",
            "domain": "domain-name", "url": "url",
            "sha256": "file-sha256", "sha1": "file-sha1", "md5": "file-md5",
        }

        enriched = []
        for obs in observables:
            obs_copy = dict(obs)
            lookup_type = type_map.get(obs["type"])
            if lookup_type:
                try:
                    result = await opencti.enrich_observable(lookup_type, obs["value"])
                    if result.get("found"):
                        obs_copy["enriched"] = True
                        obs_copy["threat_labels"] = [l.get("value", "") for l in result.get("labels", [])]
                        obs_copy["threat_actors"] = [
                            a.get("name", "") for a in result.get("threat_actors", [])
                        ]
                        obs_copy["indicator_count"] = len(result.get("indicators", []))
                        obs_copy["score"] = (result.get("observable") or {}).get("score")
                except Exception:
                    pass
            enriched.append(obs_copy)

        # Persist enriched observables back to triage
        from ion.core.config import get_config
        from ion.models.alert_triage import AlertTriage
        from ion.storage.database import get_engine, get_session_factory
        engine = get_engine(get_config().db_path)
        session = get_session_factory(engine)()
        try:
            triage = session.query(AlertTriage).filter_by(id=triage_id).first()
            if triage:
                triage.observables = enriched
                session.commit()
        finally:
            session.close()
    except Exception as e:
        logger.debug("Background observable enrichment failed for triage %s: %s", triage_id, e)


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






# ============================================================================
# Elasticsearch Discover Search Endpoints
# ============================================================================








# ============================================================================
# Elasticsearch Index Browser Endpoints
# ============================================================================






# ============================================================================
# IOC Hunt Endpoints
# ============================================================================






# ============================================================================
# OpenCTI Integration Endpoints
# ============================================================================

from ion.core.config import get_opencti_config
from ion.services.opencti_service import (
    get_opencti_service,
    reset_opencti_service,
)


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
        # 503 (not 200) so clients can distinguish availability failure from a
        # successful empty result; body shape preserved for existing frontends.
        return JSONResponse(
            status_code=503,
            content={"results": [], "error": "OpenCTI integration is not enabled"},
        )

    service = get_opencti_service()
    if not service.is_configured:
        return JSONResponse(
            status_code=503,
            content={"results": [], "error": "OpenCTI is not configured"},
        )

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
        # 503 (not 200); body keeps the `error` key the frontends read.
        return JSONResponse(
            status_code=503,
            content={
                "found": False,
                "type": request_data.type,
                "value": request_data.value,
                "error": "OpenCTI integration is not enabled",
            },
        )

    service = get_opencti_service()
    if not service.is_configured:
        return JSONResponse(
            status_code=503,
            content={
                "found": False,
                "type": request_data.type,
                "value": request_data.value,
                "error": "OpenCTI is not configured",
            },
        )

    result = await service.enrich_observable(request_data.type, request_data.value)
    return result



# ============================================================================
# Saved Searches Endpoints
# ============================================================================

from ion.models.saved_search import SearchType
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

from ion.models.playbook import ExecutionStatus
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
        return {"patterns": [], "total": 0, "error": safe_error(e)}

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

        if playbook and pattern.auto_execute and _auto_playbook_enabled:
            # Auto-start: pick the first matched alert as the representative.
            # gated on ION_AUTO_PLAYBOOK_ENABLED (default false).
            # When the flag is off the matched playbook is still surfaced in
            # `pattern_data["playbook"]` so the analyst can click Start
            # Playbook themselves — no surprise executions on the timeline.
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
    include_articles: bool = True,
    recent: int = 0,
    current_user: User = Depends(require_permission("document:read")),
    session: Session = Depends(get_db_session),
):
    """Get SOC analyst knowledge base articles organized by collection.

    Returns articles from the 'Analyst Knowledge Base' collection,
    organized by topic for easy reference during alert triage and
    case investigation.

    v0.79.0 — this endpoint existed but nothing called it, while the SOC
    workspace's KB panel sat empty until you typed a search. Two parameters
    make it usable as a browse surface:

        include_articles=false  collection names + counts only. The full form
                                returns every article in the library (~600),
                                which is a lot of payload to render a topic
                                list.
        recent=N                the N most recently updated articles across
                                the whole KB, so someone who does not know
                                what to search for still has a way in.
    """
    from sqlalchemy import func

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
    child_ids_for_recent = [c.id for c in child_collections]

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
        if include_articles:
            docs = session.query(Document).filter_by(
                collection_id=collection.id
            ).order_by(Document.name).all()
            article_count = len(docs)
        else:
            # Count in SQL rather than loading ~600 rows to call len() on them.
            docs = []
            article_count = session.query(func.count(Document.id)).filter(
                Document.collection_id == collection.id
            ).scalar() or 0

        collection_data = {
            "id": collection.id,
            "name": collection.name,
            "description": collection.description,
            "article_count": article_count,
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

    if recent > 0 and child_ids_for_recent:
        recent_docs = (
            session.query(Document)
            .filter(Document.collection_id.in_(child_ids_for_recent))
            .order_by(Document.updated_at.desc())
            .limit(min(recent, 50))
            .all()
        )
        result["recent"] = [
            {
                "id": doc.id,
                "name": doc.name,
                "collection_id": doc.collection_id,
                "collection_name": doc.collection.name if doc.collection else "Unknown",
                "updated_at": doc.updated_at.isoformat() if doc.updated_at else None,
            }
            for doc in recent_docs
        ]

    return result


@router.get("/analyst/knowledge-base/search")
async def search_analyst_knowledge_base(
    q: str = "",
    collection_id: Optional[int] = None,
    limit: int = 25,
    current_user: User = Depends(require_permission("document:read")),
    session: Session = Depends(get_db_session),
):
    """Search analyst knowledge base by article title or content.

    Parameters:
        q: Search query string. Optional when ``collection_id`` is given.
        collection_id: restrict to one KB collection. Browsing a topic is
            NOT the same as searching for its name — "Windows & Active
            Directory" is a shelf label, and text-searching for it returns
            nothing because no article says it. Passing the id lists what is
            actually on that shelf.
        limit: maximum results (capped at 100)

    Returns: Matching articles with collection context, each carrying
    ``matched_in`` ("title" or "content") and a ``snippet`` of the
    surrounding body text when the match was in the content.
    """
    from sqlalchemy import or_

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

    # Search documents in those collections.
    #
    # this filtered on Document.name ONLY, despite the docstring
    # promising title-or-content — so an analyst searching for a command, a
    # registry key or an event ID found nothing unless it happened to be in a
    # title. Body text is searched too now.
    q = (q or "").strip()
    if not q and collection_id is None:
        return {"results": [], "total": 0}

    # A collection_id outside the KB tree must not become a way to read
    # documents from anywhere else in the library.
    scope_ids = [collection_id] if collection_id in child_ids else child_ids

    filters = [Document.collection_id.in_(scope_ids)]
    if q:
        search_term = f"%{q.lower()}%"
        filters.append(
            or_(
                Document.name.ilike(search_term),
                Document.rendered_content.ilike(search_term),
            )
        )

    docs = session.query(Document).filter(
        *filters
    ).order_by(Document.name).limit(max(1, min(limit, 100))).all()

    def _snippet(doc) -> Optional[str]:
        """A window of body text around the first match.

        Without this a content hit is indistinguishable from a title hit —
        the analyst gets a title that does not obviously contain what they
        typed and has to open it to find out why it matched.
        """
        if not q:
            return None
        body = doc.rendered_content or ""
        at = body.lower().find(q.lower())
        if at < 0:
            return None
        start = max(0, at - 60)
        end = min(len(body), at + len(q) + 90)
        text = " ".join(body[start:end].split())
        return ("…" if start else "") + text + ("…" if end < len(body) else "")

    results = [
        {
            "id": doc.id,
            "name": doc.name,
            "collection_id": doc.collection_id,
            "collection_name": doc.collection.name if doc.collection else "Unknown",
            "format": doc.output_format,
            "tags": [t.name for t in doc.tags] if doc.tags else [],
            "created_at": doc.created_at.isoformat() if doc.created_at else None,
            "matched_in": (
                "collection" if not q
                else "title" if q.lower() in (doc.name or "").lower()
                else "content"
            ),
            "snippet": _snippet(doc),
        }
        for doc in docs
    ]

    # Title matches first — a document NAMED "LSASS credential dumping" is a
    # better answer for "lsass" than one that mentions it in passing.
    results.sort(key=lambda r: (r["matched_in"] != "title", r["name"].lower()))

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
    import httpx as _httpx

    from ion.core.config import get_config as _get_config
    from ion.core.config import get_ssl_verify
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
        return {"connected": False, "error": safe_error(e)}
