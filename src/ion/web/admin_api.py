"""Admin API endpoints for system configuration and management."""

from pathlib import Path
from typing import Optional
from datetime import datetime
import os
import platform
import sys

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from ion.web.api import limiter
from ion.auth.dependencies import require_admin, require_permission
from ion.models.user import User
from ion.core.config import get_config, set_config, Config
from ion.core.url_validator import validate_integration_url

router = APIRouter()


# =============================================================================
# Configuration Models
# =============================================================================

class GeneralSettingsUpdate(BaseModel):
    """General application settings."""
    default_format: Optional[str] = None
    auto_save: Optional[bool] = None
    max_versions_to_keep: Optional[int] = None
    cookie_secure: Optional[bool] = None


class GitLabSettingsUpdate(BaseModel):
    """GitLab integration settings."""
    gitlab_enabled: Optional[bool] = None
    gitlab_url: Optional[str] = None
    gitlab_token: Optional[str] = None  # Only update if provided and not masked
    gitlab_project_id: Optional[str] = None
    gitlab_verify_ssl: Optional[bool] = None


class OpenCTISettingsUpdate(BaseModel):
    """OpenCTI integration settings."""
    opencti_enabled: Optional[bool] = None
    opencti_url: Optional[str] = None
    opencti_token: Optional[str] = None  # Only update if provided and not masked
    opencti_verify_ssl: Optional[bool] = None


class ElasticsearchSettingsUpdate(BaseModel):
    """Elasticsearch integration settings."""
    elasticsearch_enabled: Optional[bool] = None
    elasticsearch_url: Optional[str] = None
    elasticsearch_api_key: Optional[str] = None  # Only update if provided and not masked
    elasticsearch_username: Optional[str] = None
    elasticsearch_password: Optional[str] = None  # Only update if provided and not masked
    elasticsearch_alert_index: Optional[str] = None
    elasticsearch_case_index: Optional[str] = None
    elasticsearch_verify_ssl: Optional[bool] = None


class OIDCSettingsUpdate(BaseModel):
    """OIDC/Keycloak settings."""
    base_url: Optional[str] = None
    oidc_enabled: Optional[bool] = None
    oidc_keycloak_url: Optional[str] = None
    oidc_realm: Optional[str] = None
    oidc_client_id: Optional[str] = None
    oidc_client_secret: Optional[str] = None  # Only update if provided and not masked
    oidc_auto_create_users: Optional[bool] = None
    oidc_role_claim: Optional[str] = None
    oidc_verify_ssl: Optional[bool] = None


class KibanaSettingsUpdate(BaseModel):
    """Kibana Cases integration settings."""
    kibana_cases_enabled: Optional[bool] = None
    kibana_url: Optional[str] = None
    kibana_username: Optional[str] = None
    kibana_password: Optional[str] = None  # Only update if provided and not masked
    kibana_space_id: Optional[str] = None
    kibana_case_owner: Optional[str] = None
    kibana_verify_ssl: Optional[bool] = None


class DFIRIrisSettingsUpdate(BaseModel):
    """DFIR-IRIS integration settings."""
    dfir_iris_enabled: Optional[bool] = None
    dfir_iris_url: Optional[str] = None
    dfir_iris_api_key: Optional[str] = None  # Only update if provided and not masked
    dfir_iris_verify_ssl: Optional[bool] = None
    dfir_iris_default_customer: Optional[int] = None


# =============================================================================
# Helper Functions
# =============================================================================

def mask_secret(value: str, visible_chars: int = 4) -> str:
    """Mask a secret value, showing only the last few characters."""
    if not value:
        return ""
    if len(value) <= visible_chars:
        return "*" * len(value)
    return "*" * (len(value) - visible_chars) + value[-visible_chars:]


def get_config_path() -> Path:
    """Get the path to the config file."""
    data_dir = os.environ.get("ION_DATA_DIR")
    if data_dir:
        return Path(data_dir) / ".ion" / "config.json"
    return Path.cwd() / ".ion" / "config.json"


def reload_config() -> Config:
    """Reload configuration from file."""
    set_config(None)  # Clear cached config
    return get_config()


# =============================================================================
# Configuration Endpoints
# =============================================================================

@router.get("/config")
async def get_configuration(current_user: User = Depends(require_permission("system:settings"))):
    """Get all configuration settings (secrets are masked)."""
    config = get_config()

    return {
        "general": {
            "db_path": str(config.db_path),
            "default_format": config.default_format,
            "auto_save": config.auto_save,
            "max_versions_to_keep": config.max_versions_to_keep,
            "cookie_secure": config.cookie_secure,
        },
        "gitlab": {
            "gitlab_enabled": config.gitlab_enabled,
            "gitlab_url": config.gitlab_url,
            "gitlab_token": mask_secret(config.gitlab_token),
            "gitlab_token_set": bool(config.gitlab_token),
            "gitlab_project_id": config.gitlab_project_id,
            "gitlab_verify_ssl": config.gitlab_verify_ssl,
        },
        "opencti": {
            "opencti_enabled": config.opencti_enabled,
            "opencti_url": config.opencti_url,
            "opencti_token": mask_secret(config.opencti_token),
            "opencti_token_set": bool(config.opencti_token),
            "opencti_verify_ssl": config.opencti_verify_ssl,
        },
        "elasticsearch": {
            "elasticsearch_enabled": config.elasticsearch_enabled,
            "elasticsearch_url": config.elasticsearch_url,
            "elasticsearch_api_key": mask_secret(config.elasticsearch_api_key),
            "elasticsearch_api_key_set": bool(config.elasticsearch_api_key),
            "elasticsearch_username": config.elasticsearch_username,
            "elasticsearch_password": mask_secret(config.elasticsearch_password),
            "elasticsearch_password_set": bool(config.elasticsearch_password),
            "elasticsearch_alert_index": config.elasticsearch_alert_index,
            "elasticsearch_case_index": config.elasticsearch_case_index,
            "elasticsearch_verify_ssl": config.elasticsearch_verify_ssl,
        },
        "oidc": {
            "base_url": config.base_url,
            "oidc_enabled": config.oidc_enabled,
            "oidc_keycloak_url": config.oidc_keycloak_url,
            "oidc_realm": config.oidc_realm,
            "oidc_client_id": config.oidc_client_id,
            "oidc_client_secret": mask_secret(config.oidc_client_secret),
            "oidc_client_secret_set": bool(config.oidc_client_secret),
            "oidc_auto_create_users": config.oidc_auto_create_users,
            "oidc_role_claim": config.oidc_role_claim,
            "oidc_verify_ssl": config.oidc_verify_ssl,
        },
        "kibana": {
            "kibana_cases_enabled": config.kibana_cases_enabled,
            "kibana_url": config.kibana_url,
            "kibana_username": config.kibana_username,
            "kibana_password": mask_secret(config.kibana_password),
            "kibana_password_set": bool(config.kibana_password),
            "kibana_space_id": config.kibana_space_id,
            "kibana_case_owner": config.kibana_case_owner,
            "kibana_verify_ssl": config.kibana_verify_ssl,
        },
        "dfir_iris": {
            "dfir_iris_enabled": config.dfir_iris_enabled,
            "dfir_iris_url": config.dfir_iris_url,
            "dfir_iris_api_key": mask_secret(config.dfir_iris_api_key),
            "dfir_iris_api_key_set": bool(config.dfir_iris_api_key),
            "dfir_iris_verify_ssl": config.dfir_iris_verify_ssl,
            "dfir_iris_default_customer": config.dfir_iris_default_customer,
        },
        "config_path": str(get_config_path()),
    }


@router.put("/config/general")
async def update_general_settings(
    settings: GeneralSettingsUpdate,
    current_user: User = Depends(require_permission("system:settings")),
):
    """Update general application settings."""
    config = get_config()

    if settings.default_format is not None:
        if settings.default_format not in ["markdown", "html", "text"]:
            raise HTTPException(400, "Invalid format. Must be: markdown, html, or text")
        config.default_format = settings.default_format

    if settings.auto_save is not None:
        config.auto_save = settings.auto_save

    if settings.max_versions_to_keep is not None:
        if settings.max_versions_to_keep < 1:
            raise HTTPException(400, "max_versions_to_keep must be at least 1")
        config.max_versions_to_keep = settings.max_versions_to_keep

    if settings.cookie_secure is not None:
        config.cookie_secure = settings.cookie_secure

    config.to_file(get_config_path())
    return {"status": "updated", "section": "general"}


@router.put("/config/gitlab")
async def update_gitlab_settings(
    settings: GitLabSettingsUpdate,
    current_user: User = Depends(require_permission("system:settings")),
):
    """Update GitLab integration settings."""
    config = get_config()

    if settings.gitlab_enabled is not None:
        config.gitlab_enabled = settings.gitlab_enabled

    if settings.gitlab_url is not None:
        config.gitlab_url = settings.gitlab_url.rstrip("/")

    if settings.gitlab_token is not None and not settings.gitlab_token.startswith("*"):
        config.gitlab_token = settings.gitlab_token

    if settings.gitlab_project_id is not None:
        config.gitlab_project_id = settings.gitlab_project_id

    if settings.gitlab_verify_ssl is not None:
        config.gitlab_verify_ssl = settings.gitlab_verify_ssl

    config.to_file(get_config_path())
    reload_config()
    return {"status": "updated", "section": "gitlab"}


@router.put("/config/opencti")
async def update_opencti_settings(
    settings: OpenCTISettingsUpdate,
    current_user: User = Depends(require_permission("system:settings")),
):
    """Update OpenCTI integration settings."""
    config = get_config()

    if settings.opencti_enabled is not None:
        config.opencti_enabled = settings.opencti_enabled

    if settings.opencti_url is not None:
        config.opencti_url = settings.opencti_url.rstrip("/")

    if settings.opencti_token is not None and not settings.opencti_token.startswith("*"):
        config.opencti_token = settings.opencti_token

    if settings.opencti_verify_ssl is not None:
        config.opencti_verify_ssl = settings.opencti_verify_ssl

    config.to_file(get_config_path())
    reload_config()
    return {"status": "updated", "section": "opencti"}


@router.put("/config/elasticsearch")
async def update_elasticsearch_settings(
    settings: ElasticsearchSettingsUpdate,
    current_user: User = Depends(require_permission("system:settings")),
):
    """Update Elasticsearch integration settings."""
    config = get_config()

    if settings.elasticsearch_enabled is not None:
        config.elasticsearch_enabled = settings.elasticsearch_enabled

    if settings.elasticsearch_url is not None:
        config.elasticsearch_url = settings.elasticsearch_url.rstrip("/")

    if settings.elasticsearch_api_key is not None and not settings.elasticsearch_api_key.startswith("*"):
        config.elasticsearch_api_key = settings.elasticsearch_api_key

    if settings.elasticsearch_username is not None:
        config.elasticsearch_username = settings.elasticsearch_username

    if settings.elasticsearch_password is not None and not settings.elasticsearch_password.startswith("*"):
        config.elasticsearch_password = settings.elasticsearch_password

    if settings.elasticsearch_alert_index is not None:
        config.elasticsearch_alert_index = settings.elasticsearch_alert_index

    if settings.elasticsearch_case_index is not None:
        config.elasticsearch_case_index = settings.elasticsearch_case_index

    if settings.elasticsearch_verify_ssl is not None:
        config.elasticsearch_verify_ssl = settings.elasticsearch_verify_ssl

    config.to_file(get_config_path())
    reload_config()
    return {"status": "updated", "section": "elasticsearch"}


@router.put("/config/oidc")
async def update_oidc_settings(
    settings: OIDCSettingsUpdate,
    current_user: User = Depends(require_permission("system:settings")),
):
    """Update OIDC/Keycloak settings."""
    config = get_config()

    if settings.base_url is not None:
        config.base_url = settings.base_url.rstrip("/")

    if settings.oidc_enabled is not None:
        config.oidc_enabled = settings.oidc_enabled

    if settings.oidc_keycloak_url is not None:
        config.oidc_keycloak_url = settings.oidc_keycloak_url.rstrip("/")

    if settings.oidc_realm is not None:
        config.oidc_realm = settings.oidc_realm

    if settings.oidc_client_id is not None:
        config.oidc_client_id = settings.oidc_client_id

    if settings.oidc_client_secret is not None and not settings.oidc_client_secret.startswith("*"):
        config.oidc_client_secret = settings.oidc_client_secret

    if settings.oidc_auto_create_users is not None:
        config.oidc_auto_create_users = settings.oidc_auto_create_users

    if settings.oidc_role_claim is not None:
        config.oidc_role_claim = settings.oidc_role_claim

    if settings.oidc_verify_ssl is not None:
        config.oidc_verify_ssl = settings.oidc_verify_ssl

    config.to_file(get_config_path())
    reload_config()
    return {"status": "updated", "section": "oidc"}


@router.put("/config/kibana")
async def update_kibana_settings(
    settings: KibanaSettingsUpdate,
    current_user: User = Depends(require_permission("system:settings")),
):
    """Update Kibana Cases integration settings."""
    config = get_config()

    if settings.kibana_cases_enabled is not None:
        config.kibana_cases_enabled = settings.kibana_cases_enabled

    if settings.kibana_url is not None:
        config.kibana_url = settings.kibana_url.rstrip("/")

    if settings.kibana_username is not None:
        config.kibana_username = settings.kibana_username

    if settings.kibana_password is not None and not settings.kibana_password.startswith("*"):
        config.kibana_password = settings.kibana_password

    if settings.kibana_space_id is not None:
        config.kibana_space_id = settings.kibana_space_id

    if settings.kibana_case_owner is not None:
        config.kibana_case_owner = settings.kibana_case_owner

    if settings.kibana_verify_ssl is not None:
        config.kibana_verify_ssl = settings.kibana_verify_ssl

    config.to_file(get_config_path())
    reload_config()

    from ion.services.kibana_cases_service import reset_kibana_cases_service
    reset_kibana_cases_service()

    return {"status": "updated", "section": "kibana"}


@router.put("/config/dfir_iris")
async def update_dfir_iris_settings(
    settings: DFIRIrisSettingsUpdate,
    current_user: User = Depends(require_permission("system:settings")),
):
    """Update DFIR-IRIS integration settings."""
    config = get_config()

    if settings.dfir_iris_enabled is not None:
        config.dfir_iris_enabled = settings.dfir_iris_enabled

    if settings.dfir_iris_url is not None:
        config.dfir_iris_url = settings.dfir_iris_url.rstrip("/")

    if settings.dfir_iris_api_key is not None and not settings.dfir_iris_api_key.startswith("*"):
        config.dfir_iris_api_key = settings.dfir_iris_api_key

    if settings.dfir_iris_verify_ssl is not None:
        config.dfir_iris_verify_ssl = settings.dfir_iris_verify_ssl

    if settings.dfir_iris_default_customer is not None:
        config.dfir_iris_default_customer = settings.dfir_iris_default_customer

    config.to_file(get_config_path())
    reload_config()
    return {"status": "updated", "section": "dfir_iris"}


@router.post("/config/test/{integration}")
async def test_integration_connection(
    integration: str,
    current_user: User = Depends(require_permission("system:settings")),
):
    """Test connection to an integration."""
    if integration == "gitlab":
        from ion.services.gitlab_service import get_gitlab_service
        service = get_gitlab_service()
        if not service.is_configured:
            return {"success": False, "error": "GitLab is not configured"}
        try:
            result = service.test_connection()
            return {"success": True, "details": result}
        except Exception as e:
            return {"success": False, "error": str(e)}

    elif integration == "opencti":
        from ion.services.opencti_service import get_opencti_service
        service = get_opencti_service()
        if not service.is_configured:
            return {"success": False, "error": "OpenCTI is not configured"}
        try:
            result = service.test_connection()
            return {"success": True, "details": result}
        except Exception as e:
            return {"success": False, "error": str(e)}

    elif integration == "elasticsearch":
        from ion.services.elasticsearch_service import ElasticsearchService
        service = ElasticsearchService()
        if not service.is_configured:
            return {"success": False, "error": "Elasticsearch is not configured"}
        try:
            result = await service.test_connection()
            return {"success": result.get("connected", False), "details": result, "error": result.get("error")}
        except Exception as e:
            return {"success": False, "error": str(e)}

    elif integration == "kibana":
        from ion.services.kibana_cases_service import get_kibana_cases_service
        service = get_kibana_cases_service()
        if not service.enabled:
            return {"success": False, "error": "Kibana Cases is not enabled"}
        try:
            result = service.test_connection()
            return {"success": result.get("success", False), "details": result, "error": result.get("error")}
        except Exception as e:
            return {"success": False, "error": str(e)}

    elif integration == "dfir_iris":
        config = get_config()
        if not config.dfir_iris_enabled:
            return {"success": False, "error": "DFIR-IRIS is not enabled"}
        if not config.dfir_iris_url or not config.dfir_iris_api_key:
            return {"success": False, "error": "DFIR-IRIS URL and API key are required"}
        try:
            import httpx
            from ion.core.config import get_ssl_verify
            async with httpx.AsyncClient(
                headers={"Authorization": f"Bearer {config.dfir_iris_api_key}"},
                verify=get_ssl_verify(config.dfir_iris_verify_ssl),
                timeout=httpx.Timeout(10.0, connect=5.0),
            ) as client:
                response = await client.get(f"{config.dfir_iris_url}/api/versions")
                response.raise_for_status()
                data = response.json()
                return {"success": True, "details": data}
        except Exception as e:
            return {"success": False, "error": str(e)}

    else:
        raise HTTPException(400, f"Unknown integration: {integration}")


# =============================================================================
# System Information Endpoints
# =============================================================================

@router.get("/system/info")
async def get_system_info(current_user: User = Depends(require_admin)):
    """Get system information."""
    import ion

    # Get installed packages
    try:
        import pkg_resources
        packages = {
            pkg.key: pkg.version
            for pkg in pkg_resources.working_set
            if pkg.key in [
                "fastapi", "uvicorn", "sqlalchemy", "pydantic",
                "jinja2", "python-jose", "passlib", "httpx",
                "psutil", "aiofiles"
            ]
        }
    except Exception:
        packages = {}

    # Get disk usage for data directory
    config = get_config()
    data_dir = config.db_path.parent
    try:
        import psutil
        disk = psutil.disk_usage(str(data_dir))
        disk_info = {
            "total_gb": round(disk.total / (1024**3), 2),
            "used_gb": round(disk.used / (1024**3), 2),
            "free_gb": round(disk.free / (1024**3), 2),
            "percent": disk.percent,
        }
    except Exception:
        disk_info = None

    # Database file size
    db_size_mb = 0
    if config.db_path.exists():
        db_size_mb = round(config.db_path.stat().st_size / (1024**2), 2)

    return {
        "ion_version": getattr(ion, "__version__", "0.1.0"),
        "python_version": sys.version,
        "platform": platform.platform(),
        "architecture": platform.machine(),
        "packages": packages,
        "data_directory": str(data_dir),
        "database_path": str(config.db_path),
        "database_size_mb": db_size_mb,
        "config_path": str(get_config_path()),
        "disk": disk_info,
    }


@router.get("/system/env")
async def get_environment_variables(current_user: User = Depends(require_admin)):
    """Get ION-related environment variables (values masked)."""
    env_vars = {}
    for key, value in os.environ.items():
        if key.startswith("ION_"):
            # Mask sensitive values
            if any(s in key.lower() for s in ["password", "secret", "token", "key"]):
                env_vars[key] = mask_secret(value) if value else "(not set)"
            else:
                env_vars[key] = value if value else "(not set)"

    return {"variables": env_vars}


# =============================================================================
# Session Management Endpoints
# =============================================================================

@router.get("/sessions")
async def get_active_sessions(current_user: User = Depends(require_admin)):
    """Get all active user sessions."""
    from ion.storage.database import get_engine, get_session
    from ion.models.user import User as UserModel
    from sqlalchemy import text
    from datetime import datetime, timedelta

    config = get_config()
    engine = get_engine(config.db_path)

    sessions = []
    try:
        with next(get_session(engine)) as db:
            # Get users with their last activity
            # Note: We don't have a sessions table, so we'll show users
            # with their last login time as a proxy for active sessions
            users = db.query(UserModel).filter(UserModel.is_active == True).all()

            for user in users:
                sessions.append({
                    "user_id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "last_login": user.last_login.isoformat() if user.last_login else None,
                    "is_active": user.is_active,
                    "roles": [role.name for role in user.roles] if user.roles else [],
                })
    except Exception as e:
        return {"error": str(e), "sessions": []}

    return {"sessions": sessions, "total": len(sessions)}


@router.post("/sessions/{user_id}/revoke")
async def revoke_user_session(
    user_id: int,
    current_user: User = Depends(require_admin),
):
    """Revoke a user's session by deactivating their account temporarily."""
    if user_id == current_user.id:
        raise HTTPException(400, "Cannot revoke your own session")

    from ion.storage.database import get_engine, get_session
    from ion.models.user import User as UserModel

    config = get_config()
    engine = get_engine(config.db_path)

    try:
        with next(get_session(engine)) as db:
            user = db.query(UserModel).filter(UserModel.id == user_id).first()
            if not user:
                raise HTTPException(404, "User not found")

            # Log the session revocation
            from ion.services.integration_log_service import IntegrationLogService
            log_service = IntegrationLogService(db)
            log_service.log_event(
                integration_type="system",
                action="session_revoke",
                message=f"Session revoked for user {user.username} by {current_user.username}",
                level="warning",
                user_id=current_user.id,
            )

            db.commit()

            return {
                "status": "revoked",
                "user_id": user_id,
                "username": user.username,
                "message": "User session has been marked for revocation. User will need to re-authenticate.",
            }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Failed to revoke session: {str(e)}")


# =============================================================================
# Database Management Endpoints
# =============================================================================

@router.get("/database/stats")
async def get_database_stats(current_user: User = Depends(require_admin)):
    """Get database statistics."""
    from ion.storage.database import get_engine, get_session
    from sqlalchemy import text, inspect

    config = get_config()
    engine = get_engine(config.db_path)

    stats = {
        "database_path": str(config.db_path),
        "database_size_mb": 0,
        "tables": [],
    }

    # Get file size
    if config.db_path.exists():
        stats["database_size_mb"] = round(config.db_path.stat().st_size / (1024**2), 2)

    try:
        inspector = inspect(engine)
        table_names = inspector.get_table_names()

        with next(get_session(engine)) as db:
            for table_name in table_names:
                # Get row count
                result = db.execute(text(f"SELECT COUNT(*) FROM {table_name}"))
                row_count = result.scalar()

                stats["tables"].append({
                    "name": table_name,
                    "row_count": row_count,
                })

        # Sort by row count descending
        stats["tables"].sort(key=lambda x: x["row_count"], reverse=True)
        stats["total_tables"] = len(stats["tables"])
        stats["total_rows"] = sum(t["row_count"] for t in stats["tables"])

    except Exception as e:
        stats["error"] = str(e)

    return stats


@router.post("/database/backup")
@limiter.limit("5/minute")
async def create_database_backup(request: Request, current_user: User = Depends(require_admin)):
    """Create a backup of the database."""
    import shutil
    from datetime import datetime

    config = get_config()

    if not config.db_path.exists():
        raise HTTPException(404, "Database file not found")

    # Create backup directory
    backup_dir = config.db_path.parent / "backups"
    backup_dir.mkdir(exist_ok=True)

    # Generate backup filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_filename = f"ion_backup_{timestamp}.db"
    backup_path = backup_dir / backup_filename

    try:
        shutil.copy2(config.db_path, backup_path)

        # Log the backup
        from ion.storage.database import get_engine, get_session
        engine = get_engine(config.db_path)
        with next(get_session(engine)) as db:
            from ion.services.integration_log_service import IntegrationLogService
            log_service = IntegrationLogService(db)
            log_service.log_event(
                integration_type="system",
                action="database_backup",
                message=f"Database backup created: {backup_filename}",
                level="info",
                user_id=current_user.id,
            )
            db.commit()

        return {
            "status": "success",
            "backup_path": str(backup_path),
            "backup_size_mb": round(backup_path.stat().st_size / (1024**2), 2),
            "timestamp": timestamp,
        }
    except Exception as e:
        raise HTTPException(500, f"Backup failed: {str(e)}")


@router.get("/database/backups")
async def list_database_backups(current_user: User = Depends(require_admin)):
    """List available database backups."""
    config = get_config()
    backup_dir = config.db_path.parent / "backups"

    if not backup_dir.exists():
        return {"backups": [], "total": 0}

    backups = []
    for backup_file in backup_dir.glob("ion_backup_*.db"):
        backups.append({
            "filename": backup_file.name,
            "path": str(backup_file),
            "size_mb": round(backup_file.stat().st_size / (1024**2), 2),
            "created_at": datetime.fromtimestamp(backup_file.stat().st_mtime).isoformat(),
        })

    # Sort by creation time descending
    backups.sort(key=lambda x: x["created_at"], reverse=True)

    return {"backups": backups, "total": len(backups)}


@router.delete("/database/backups/{filename}")
async def delete_database_backup(
    filename: str,
    current_user: User = Depends(require_admin),
):
    """Delete a database backup."""
    import re

    # Validate filename format to prevent path traversal
    if not re.match(r'^ion_backup_\d{8}_\d{6}\.db$', filename):
        raise HTTPException(400, "Invalid backup filename format")

    config = get_config()
    backup_path = config.db_path.parent / "backups" / filename

    if not backup_path.exists():
        raise HTTPException(404, "Backup not found")

    try:
        backup_path.unlink()
        return {"status": "deleted", "filename": filename}
    except Exception as e:
        raise HTTPException(500, f"Failed to delete backup: {str(e)}")


@router.post("/database/restore/{filename}")
@limiter.limit("3/minute")
async def restore_database_backup(
    request: Request,
    filename: str,
    current_user: User = Depends(require_admin),
):
    """Restore database from a backup. Creates a backup of current DB first."""
    import re
    import shutil

    # Validate filename format
    if not re.match(r'^ion_backup_\d{8}_\d{6}\.db$', filename):
        raise HTTPException(400, "Invalid backup filename format")

    config = get_config()
    backup_path = config.db_path.parent / "backups" / filename

    if not backup_path.exists():
        raise HTTPException(404, "Backup not found")

    # Create a backup of current database first
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pre_restore_backup = config.db_path.parent / "backups" / f"ion_pre_restore_{timestamp}.db"

    try:
        # Backup current database
        if config.db_path.exists():
            config.db_path.parent.joinpath("backups").mkdir(exist_ok=True)
            shutil.copy2(config.db_path, pre_restore_backup)

        # Restore from backup
        shutil.copy2(backup_path, config.db_path)

        return {
            "status": "restored",
            "restored_from": filename,
            "pre_restore_backup": str(pre_restore_backup),
            "message": "Database restored successfully. Please restart the server for changes to take effect.",
        }
    except Exception as e:
        raise HTTPException(500, f"Restore failed: {str(e)}")


@router.post("/database/cleanup")
@limiter.limit("3/minute")
async def cleanup_old_data(
    request: Request,
    days_to_keep: int = 30,
    current_user: User = Depends(require_admin),
):
    """Clean up old logs and temporary data."""
    from ion.storage.database import get_engine, get_session
    from sqlalchemy import text
    from datetime import datetime, timedelta

    if days_to_keep < 1:
        raise HTTPException(400, "days_to_keep must be at least 1")

    config = get_config()
    engine = get_engine(config.db_path)

    cutoff_date = datetime.utcnow() - timedelta(days=days_to_keep)
    deleted_counts = {}

    try:
        with next(get_session(engine)) as db:
            # Clean up old integration logs
            try:
                result = db.execute(
                    text("DELETE FROM integration_logs WHERE timestamp < :cutoff"),
                    {"cutoff": cutoff_date}
                )
                deleted_counts["integration_logs"] = result.rowcount
            except Exception:
                deleted_counts["integration_logs"] = 0

            # Clean up old webhook logs
            try:
                result = db.execute(
                    text("DELETE FROM webhook_logs WHERE created_at < :cutoff"),
                    {"cutoff": cutoff_date}
                )
                deleted_counts["webhook_logs"] = result.rowcount
            except Exception:
                deleted_counts["webhook_logs"] = 0

            # Clean up old health checks
            try:
                result = db.execute(
                    text("DELETE FROM integration_health_checks WHERE checked_at < :cutoff"),
                    {"cutoff": cutoff_date}
                )
                deleted_counts["health_checks"] = result.rowcount
            except Exception:
                deleted_counts["health_checks"] = 0

            # Clean up old audit logs (keep more history)
            audit_cutoff = datetime.utcnow() - timedelta(days=days_to_keep * 3)
            try:
                result = db.execute(
                    text("DELETE FROM audit_logs WHERE timestamp < :cutoff"),
                    {"cutoff": audit_cutoff}
                )
                deleted_counts["audit_logs"] = result.rowcount
            except Exception:
                deleted_counts["audit_logs"] = 0

            db.commit()

            # Log the cleanup
            from ion.services.integration_log_service import IntegrationLogService
            log_service = IntegrationLogService(db)
            total_deleted = sum(deleted_counts.values())
            log_service.log_event(
                integration_type="system",
                action="database_cleanup",
                message=f"Cleaned up {total_deleted} old records (keeping {days_to_keep} days)",
                level="info",
                user_id=current_user.id,
                details=deleted_counts,
            )
            db.commit()

        return {
            "status": "success",
            "deleted_counts": deleted_counts,
            "total_deleted": sum(deleted_counts.values()),
            "cutoff_date": cutoff_date.isoformat(),
        }
    except Exception as e:
        raise HTTPException(500, f"Cleanup failed: {str(e)}")


# =============================================================================
# Integration Wizard Endpoints
# =============================================================================

class WizardIntegrationConfig(BaseModel):
    """Configuration for a single integration in wizard mode."""
    enabled: Optional[bool] = None
    url: Optional[str] = None
    api_key: Optional[str] = None
    token: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    verify_ssl: Optional[bool] = None
    # Elasticsearch specific
    alert_index: Optional[str] = None
    case_index: Optional[str] = None
    # Kibana specific
    space_id: Optional[str] = None
    case_owner: Optional[str] = None
    # GitLab specific
    project_id: Optional[str] = None
    # Ollama specific
    model: Optional[str] = None
    timeout: Optional[int] = None
    # DFIR-IRIS specific
    default_customer: Optional[int] = None


class WizardDiagnoseRequest(BaseModel):
    """Request for AI-powered error diagnosis."""
    integration: str
    error_message: str
    config: dict  # Sanitized config (no secrets)


class WizardSaveAllRequest(BaseModel):
    """Request to save all wizard configurations."""
    integrations: dict  # Dict of integration_name -> WizardIntegrationConfig


# AI Diagnosis system prompt
DIAGNOSIS_SYSTEM_PROMPT = """You are an expert systems administrator helping diagnose integration configuration errors.

When analyzing errors:
1. Identify the root cause from the error message
2. Consider common causes for this integration type
3. Provide step-by-step solutions
4. Include security considerations when relevant

Format your response EXACTLY as follows (include all sections):

DIAGNOSIS: [Brief description of what went wrong]

CAUSE: [Most likely root cause]

SOLUTIONS:
1. [First solution - most likely to work]
2. [Second solution - alternative approach]
3. [Third solution if applicable]

SECURITY NOTE: [Any security implications or recommendations]

ACTIONABLE: [List any fixes that can be auto-applied, comma-separated. Valid options: disable_ssl_verification, increase_timeout, use_http. Leave empty if none apply]"""


@router.get("/wizard/integrations")
async def get_wizard_integrations(current_user: User = Depends(require_permission("integration:manage"))):
    """Get all integrations with their current status for the wizard."""
    config = get_config()

    integrations = {
        "elasticsearch": {
            "name": "Elasticsearch",
            "description": "Search and analytics engine for alerts and case data",
            "enabled": config.elasticsearch_enabled,
            "configured": bool(config.elasticsearch_url) and (
                bool(config.elasticsearch_api_key) or
                (bool(config.elasticsearch_username) and bool(config.elasticsearch_password))
            ),
            "url": config.elasticsearch_url,
            "fields": {
                "url": {"type": "url", "label": "Elasticsearch URL", "placeholder": "https://localhost:9200", "required": True},
                "username": {"type": "text", "label": "Username", "placeholder": "elastic"},
                "password": {"type": "password", "label": "Password", "placeholder": "Leave blank to keep current"},
                "api_key": {"type": "password", "label": "API Key (alternative)", "placeholder": "Leave blank to keep current"},
                "alert_index": {"type": "text", "label": "Alert Index Pattern", "default": ".alerts-*,.watcher-history-*,alerts-*"},
                "case_index": {"type": "text", "label": "Case Index", "default": "ion-cases"},
                "verify_ssl": {"type": "checkbox", "label": "Verify SSL Certificate", "default": True},
            },
            "auth_modes": ["basic", "api_key"],
        },
        "kibana": {
            "name": "Kibana",
            "description": "Elastic Kibana for case synchronization",
            "enabled": config.kibana_cases_enabled,
            "configured": bool(config.kibana_url),
            "url": config.kibana_url,
            "fields": {
                "url": {"type": "url", "label": "Kibana URL", "placeholder": "http://localhost:5601", "required": True},
                "username": {"type": "text", "label": "Username", "placeholder": "Uses ES credentials if empty"},
                "password": {"type": "password", "label": "Password", "placeholder": "Leave blank to keep current"},
                "space_id": {"type": "text", "label": "Space ID", "default": "default"},
                "case_owner": {"type": "select", "label": "Case Owner", "options": ["securitySolution", "observability", "cases"], "default": "securitySolution"},
                "verify_ssl": {"type": "checkbox", "label": "Verify SSL Certificate", "default": True},
            },
        },
        "gitlab": {
            "name": "GitLab",
            "description": "Version control and template synchronization",
            "enabled": config.gitlab_enabled,
            "configured": bool(config.gitlab_url) and bool(config.gitlab_token),
            "url": config.gitlab_url,
            "fields": {
                "url": {"type": "url", "label": "GitLab URL", "placeholder": "https://gitlab.example.com", "required": True},
                "token": {"type": "password", "label": "Personal Access Token", "placeholder": "Token with 'api' scope", "required": True},
                "project_id": {"type": "text", "label": "Project ID or Path", "placeholder": "group/project or 123", "required": True},
                "verify_ssl": {"type": "checkbox", "label": "Verify SSL Certificate", "default": True},
            },
        },
        "opencti": {
            "name": "OpenCTI",
            "description": "Cyber threat intelligence platform",
            "enabled": config.opencti_enabled,
            "configured": bool(config.opencti_url) and bool(config.opencti_token),
            "url": config.opencti_url,
            "fields": {
                "url": {"type": "url", "label": "OpenCTI URL", "placeholder": "http://localhost:8888", "required": True},
                "token": {"type": "password", "label": "API Token", "placeholder": "Bearer token (UUID)", "required": True},
                "verify_ssl": {"type": "checkbox", "label": "Verify SSL Certificate", "default": True},
            },
        },
        "ollama": {
            "name": "Ollama",
            "description": "AI model for chat and analysis (local or remote Ollama)",
            "enabled": config.ollama_enabled,
            "configured": bool(config.ollama_url),
            "url": config.ollama_url,
            "fields": {
                "url": {"type": "url", "label": "Ollama URL", "placeholder": "http://localhost:11434", "default": "http://localhost:11434"},
                "model": {"type": "select", "label": "Default Model", "options": [], "default": "qwen2.5:0.5b", "dynamic": True},
                "timeout": {"type": "number", "label": "Request Timeout (seconds)", "default": 120, "min": 30, "max": 600},
                "verify_ssl": {"type": "checkbox", "label": "Verify SSL Certificate", "default": True},
            },
        },
        "virustotal": {
            "name": "VirusTotal",
            "description": "Malware and URL scanning service",
            "enabled": config.virustotal_enabled,
            "configured": bool(config.virustotal_api_key),
            "fields": {
                "api_key": {"type": "password", "label": "API Key", "placeholder": "Your VirusTotal API key", "required": True},
            },
        },
        "abuseipdb": {
            "name": "AbuseIPDB",
            "description": "IP address reputation database",
            "enabled": config.abuseipdb_enabled,
            "configured": bool(config.abuseipdb_api_key),
            "fields": {
                "api_key": {"type": "password", "label": "API Key", "placeholder": "Your AbuseIPDB API key", "required": True},
            },
        },
        "dfir_iris": {
            "name": "DFIR-IRIS",
            "description": "Incident response platform for case escalation",
            "enabled": config.dfir_iris_enabled,
            "configured": bool(config.dfir_iris_url) and bool(config.dfir_iris_api_key),
            "url": config.dfir_iris_url,
            "fields": {
                "url": {"type": "url", "label": "DFIR-IRIS URL", "placeholder": "https://iris.example.com", "required": True},
                "api_key": {"type": "password", "label": "API Key", "placeholder": "Bearer API key from IRIS user profile", "required": True},
                "verify_ssl": {"type": "checkbox", "label": "Verify SSL Certificate", "default": True},
                "default_customer": {"type": "number", "label": "Default Customer ID", "default": 1, "min": 1},
            },
        },
    }

    return {"integrations": integrations}


@router.post("/wizard/test/{integration}")
async def test_wizard_integration(
    integration: str,
    config_data: WizardIntegrationConfig,
    current_user: User = Depends(require_permission("integration:manage")),
):
    """Test connection for an integration without saving configuration."""
    import httpx

    if integration == "elasticsearch":
        try:
            url = (config_data.url or "").rstrip("/")
            if not url:
                return {"success": False, "error": "URL is required"}

            # Validate URL for SSRF protection
            is_valid, error = validate_integration_url(url, "elasticsearch")
            if not is_valid:
                return {"success": False, "error": f"Invalid URL: {error}"}

            headers = {"Content-Type": "application/json"}
            auth = None

            if config_data.api_key and not config_data.api_key.startswith("*"):
                headers["Authorization"] = f"ApiKey {config_data.api_key}"
            elif config_data.username and config_data.password:
                if not config_data.password.startswith("*"):
                    auth = (config_data.username, config_data.password)
                else:
                    # Use existing password from config
                    existing = get_config()
                    auth = (config_data.username, existing.elasticsearch_password)

            async with httpx.AsyncClient(
                headers=headers,
                auth=auth,
                verify=config_data.verify_ssl if config_data.verify_ssl is not None else True,
                timeout=httpx.Timeout(10.0, connect=5.0),
            ) as client:
                response = await client.get(f"{url}/")
                response.raise_for_status()
                data = response.json()
                return {
                    "success": True,
                    "details": {
                        "cluster_name": data.get("cluster_name"),
                        "version": data.get("version", {}).get("number"),
                    }
                }
        except httpx.ConnectError as e:
            return {"success": False, "error": f"Connection failed: {str(e)}"}
        except httpx.HTTPStatusError as e:
            return {"success": False, "error": f"HTTP {e.response.status_code}: {e.response.text[:200]}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    elif integration == "kibana":
        try:
            url = (config_data.url or "").rstrip("/")
            if not url:
                return {"success": False, "error": "URL is required"}

            # Validate URL for SSRF protection
            is_valid, error = validate_integration_url(url, "kibana")
            if not is_valid:
                return {"success": False, "error": f"Invalid URL: {error}"}

            # Get credentials - fall back to ES if not provided
            existing = get_config()
            username = config_data.username or existing.kibana_username or existing.elasticsearch_username
            password = config_data.password if config_data.password and not config_data.password.startswith("*") else existing.kibana_password or existing.elasticsearch_password

            auth = (username, password) if username and password else None
            space_id = config_data.space_id or "default"

            from ion.core.config import get_ssl_verify
            verify = get_ssl_verify(config_data.verify_ssl if config_data.verify_ssl is not None else True)
            async with httpx.AsyncClient(
                auth=auth,
                timeout=httpx.Timeout(10.0, connect=5.0),
                verify=verify,
            ) as client:
                response = await client.get(f"{url}/api/status")
                response.raise_for_status()
                data = response.json()
                return {
                    "success": True,
                    "details": {
                        "version": data.get("version", {}).get("number"),
                        "status": data.get("status", {}).get("overall", {}).get("level"),
                    }
                }
        except httpx.ConnectError as e:
            return {"success": False, "error": f"Connection failed: {str(e)}"}
        except httpx.HTTPStatusError as e:
            return {"success": False, "error": f"HTTP {e.response.status_code}: {e.response.text[:200]}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    elif integration == "gitlab":
        try:
            url = (config_data.url or "").rstrip("/")
            if not url:
                return {"success": False, "error": "URL is required"}

            # Validate URL for SSRF protection
            is_valid, error = validate_integration_url(url, "gitlab")
            if not is_valid:
                return {"success": False, "error": f"Invalid URL: {error}"}

            existing = get_config()
            token = config_data.token if config_data.token and not config_data.token.startswith("*") else existing.gitlab_token
            if not token:
                return {"success": False, "error": "Token is required"}

            project_id = config_data.project_id or existing.gitlab_project_id
            if not project_id:
                return {"success": False, "error": "Project ID is required"}

            from ion.core.config import get_ssl_verify
            verify = get_ssl_verify(config_data.verify_ssl if config_data.verify_ssl is not None else True)
            async with httpx.AsyncClient(
                headers={"PRIVATE-TOKEN": token},
                timeout=httpx.Timeout(10.0, connect=5.0),
                verify=verify,
            ) as client:
                # URL-encode the project path if it contains /
                import urllib.parse
                encoded_project = urllib.parse.quote(project_id, safe="")
                response = await client.get(f"{url}/api/v4/projects/{encoded_project}")
                response.raise_for_status()
                data = response.json()
                return {
                    "success": True,
                    "details": {
                        "project_name": data.get("name"),
                        "web_url": data.get("web_url"),
                    }
                }
        except httpx.ConnectError as e:
            return {"success": False, "error": f"Connection failed: {str(e)}"}
        except httpx.HTTPStatusError as e:
            error_msg = f"HTTP {e.response.status_code}"
            if e.response.status_code == 401:
                error_msg = "Invalid token or insufficient permissions"
            elif e.response.status_code == 404:
                error_msg = "Project not found - check project ID"
            return {"success": False, "error": error_msg}
        except Exception as e:
            return {"success": False, "error": str(e)}

    elif integration == "opencti":
        try:
            url = (config_data.url or "").rstrip("/")
            if not url:
                return {"success": False, "error": "URL is required"}

            # Validate URL for SSRF protection
            is_valid, error = validate_integration_url(url, "opencti")
            if not is_valid:
                return {"success": False, "error": f"Invalid URL: {error}"}

            existing = get_config()
            token = config_data.token if config_data.token and not config_data.token.startswith("*") else existing.opencti_token
            if not token:
                return {"success": False, "error": "Token is required"}

            query = '{ about { version } }'
            async with httpx.AsyncClient(
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                },
                verify=config_data.verify_ssl if config_data.verify_ssl is not None else True,
                timeout=httpx.Timeout(10.0, connect=5.0),
            ) as client:
                response = await client.post(
                    f"{url}/graphql",
                    json={"query": query}
                )
                response.raise_for_status()
                data = response.json()
                version = data.get("data", {}).get("about", {}).get("version", "unknown")
                return {
                    "success": True,
                    "details": {"version": version}
                }
        except httpx.ConnectError as e:
            return {"success": False, "error": f"Connection failed: {str(e)}"}
        except httpx.HTTPStatusError as e:
            return {"success": False, "error": f"HTTP {e.response.status_code}: {e.response.text[:200]}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    elif integration == "ollama":
        try:
            url = (config_data.url or "http://localhost:11434").rstrip("/")

            # Validate URL for SSRF protection (ollama allows Docker service names)
            is_valid, error = validate_integration_url(url, "ollama")
            if not is_valid:
                return {"success": False, "error": f"Invalid URL: {error}"}

            from ion.core.config import get_ssl_verify
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(10.0, connect=5.0),
                verify=get_ssl_verify(config.ollama_verify_ssl),
            ) as client:
                response = await client.get(f"{url}/api/tags")
                response.raise_for_status()
                data = response.json()
                models = [m.get("name") for m in data.get("models", [])]
                return {
                    "success": True,
                    "details": {
                        "models": models,
                        "model_count": len(models),
                    }
                }
        except httpx.ConnectError as e:
            return {"success": False, "error": f"Connection failed: Is Ollama running at {url}?"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    elif integration == "virustotal":
        try:
            existing = get_config()
            api_key = config_data.api_key if config_data.api_key and not config_data.api_key.startswith("*") else existing.virustotal_api_key
            if not api_key:
                return {"success": False, "error": "API key is required"}

            async with httpx.AsyncClient(
                headers={"x-apikey": api_key},
                timeout=httpx.Timeout(10.0, connect=5.0),
            ) as client:
                # Test with a simple API call
                response = await client.get("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8")
                if response.status_code == 401:
                    return {"success": False, "error": "Invalid API key"}
                response.raise_for_status()
                return {"success": True, "details": {"status": "API key validated"}}
        except httpx.ConnectError as e:
            return {"success": False, "error": f"Connection failed: {str(e)}"}
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                return {"success": False, "error": "Invalid API key"}
            return {"success": False, "error": f"HTTP {e.response.status_code}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    elif integration == "abuseipdb":
        try:
            existing = get_config()
            api_key = config_data.api_key if config_data.api_key and not config_data.api_key.startswith("*") else existing.abuseipdb_api_key
            if not api_key:
                return {"success": False, "error": "API key is required"}

            async with httpx.AsyncClient(
                headers={
                    "Key": api_key,
                    "Accept": "application/json",
                },
                timeout=httpx.Timeout(10.0, connect=5.0),
            ) as client:
                response = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": "8.8.8.8"}
                )
                if response.status_code == 401:
                    return {"success": False, "error": "Invalid API key"}
                response.raise_for_status()
                return {"success": True, "details": {"status": "API key validated"}}
        except httpx.ConnectError as e:
            return {"success": False, "error": f"Connection failed: {str(e)}"}
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401 or e.response.status_code == 403:
                return {"success": False, "error": "Invalid API key"}
            return {"success": False, "error": f"HTTP {e.response.status_code}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    elif integration == "dfir_iris":
        try:
            url = (config_data.url or "").rstrip("/")
            if not url:
                return {"success": False, "error": "URL is required"}

            is_valid, error = validate_integration_url(url, "dfir_iris")
            if not is_valid:
                return {"success": False, "error": f"Invalid URL: {error}"}

            existing = get_config()
            api_key = config_data.api_key if config_data.api_key and not config_data.api_key.startswith("*") else existing.dfir_iris_api_key
            if not api_key:
                return {"success": False, "error": "API key is required"}

            async with httpx.AsyncClient(
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                verify=config_data.verify_ssl if config_data.verify_ssl is not None else True,
                timeout=httpx.Timeout(10.0, connect=5.0),
            ) as client:
                response = await client.get(f"{url}/manage/cases/list")
                if response.status_code == 401:
                    return {"success": False, "error": "Invalid API key or insufficient permissions"}
                response.raise_for_status()
                data = response.json()
                return {
                    "success": True,
                    "details": {
                        "status": data.get("status", "ok"),
                        "message": "Connected to DFIR-IRIS",
                    }
                }
        except httpx.ConnectError as e:
            return {"success": False, "error": f"Connection failed: {str(e)}"}
        except httpx.HTTPStatusError as e:
            return {"success": False, "error": f"HTTP {e.response.status_code}: {e.response.text[:200]}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    else:
        raise HTTPException(400, f"Unknown integration: {integration}")


@router.post("/wizard/diagnose")
async def diagnose_integration_error(
    request: WizardDiagnoseRequest,
    current_user: User = Depends(require_permission("integration:manage")),
):
    """Use AI to diagnose integration configuration errors."""
    config = get_config()

    # Check if Ollama is available
    if not config.ollama_enabled:
        return {
            "available": False,
            "message": "AI diagnosis requires Ollama to be enabled",
        }

    from ion.services.ollama_service import get_ollama_service, OllamaError

    try:
        ollama = get_ollama_service()
        if not await ollama.is_available():
            return {
                "available": False,
                "message": "Ollama service is not running",
            }

        # Build the diagnosis prompt
        prompt = f"""Integration: {request.integration}
Error Message: {request.error_message}

Configuration (secrets masked):
{_format_config_for_diagnosis(request.config)}

Please analyze this error and provide a diagnosis."""

        # Get AI diagnosis
        result = await ollama.chat(
            messages=[{"role": "user", "content": prompt}],
            system_prompt=DIAGNOSIS_SYSTEM_PROMPT,
            temperature=0.3,  # Lower temperature for more consistent output
        )

        diagnosis_text = result.get("content", "")

        # Parse the structured response
        diagnosis = _parse_diagnosis_response(diagnosis_text)

        return {
            "available": True,
            "diagnosis": diagnosis,
            "raw_response": diagnosis_text,
        }

    except OllamaError as e:
        return {
            "available": False,
            "message": f"AI diagnosis failed: {str(e)}",
        }
    except Exception as e:
        return {
            "available": False,
            "message": f"Unexpected error: {str(e)}",
        }


def _format_config_for_diagnosis(config: dict) -> str:
    """Format config dict for AI diagnosis, masking any potential secrets."""
    lines = []
    for key, value in config.items():
        if any(s in key.lower() for s in ["password", "secret", "token", "key", "api_key"]):
            value = "***MASKED***" if value else "(not set)"
        elif value is None:
            value = "(not set)"
        lines.append(f"  {key}: {value}")
    return "\n".join(lines)


def _parse_diagnosis_response(text: str) -> dict:
    """Parse structured diagnosis response from AI."""
    result = {
        "summary": "",
        "cause": "",
        "solutions": [],
        "security_note": "",
        "actionable": [],
    }

    # Parse DIAGNOSIS section
    if "DIAGNOSIS:" in text:
        start = text.find("DIAGNOSIS:") + len("DIAGNOSIS:")
        end = text.find("CAUSE:") if "CAUSE:" in text else len(text)
        result["summary"] = text[start:end].strip()

    # Parse CAUSE section
    if "CAUSE:" in text:
        start = text.find("CAUSE:") + len("CAUSE:")
        end = text.find("SOLUTIONS:") if "SOLUTIONS:" in text else len(text)
        result["cause"] = text[start:end].strip()

    # Parse SOLUTIONS section
    if "SOLUTIONS:" in text:
        start = text.find("SOLUTIONS:") + len("SOLUTIONS:")
        end = text.find("SECURITY NOTE:") if "SECURITY NOTE:" in text else (
            text.find("ACTIONABLE:") if "ACTIONABLE:" in text else len(text)
        )
        solutions_text = text[start:end].strip()
        # Parse numbered solutions
        import re
        solutions = re.findall(r'\d+\.\s*(.+?)(?=\d+\.|$)', solutions_text, re.DOTALL)
        result["solutions"] = [s.strip() for s in solutions if s.strip()]

    # Parse SECURITY NOTE section
    if "SECURITY NOTE:" in text:
        start = text.find("SECURITY NOTE:") + len("SECURITY NOTE:")
        end = text.find("ACTIONABLE:") if "ACTIONABLE:" in text else len(text)
        result["security_note"] = text[start:end].strip()

    # Parse ACTIONABLE section
    if "ACTIONABLE:" in text:
        start = text.find("ACTIONABLE:") + len("ACTIONABLE:")
        actionable_text = text[start:].strip().split("\n")[0]
        if actionable_text and actionable_text.lower() not in ["none", "n/a", ""]:
            actions = [a.strip() for a in actionable_text.split(",")]
            # Validate actionable items
            valid_actions = ["disable_ssl_verification", "increase_timeout", "use_http"]
            result["actionable"] = [a for a in actions if a in valid_actions]

    return result


@router.put("/wizard/save/{integration}")
async def save_wizard_integration(
    integration: str,
    config_data: WizardIntegrationConfig,
    current_user: User = Depends(require_permission("integration:manage")),
):
    """Save configuration for a single integration."""
    config = get_config()

    if integration == "elasticsearch":
        if config_data.enabled is not None:
            config.elasticsearch_enabled = config_data.enabled
        if config_data.url is not None:
            config.elasticsearch_url = config_data.url.rstrip("/")
        if config_data.api_key is not None and not config_data.api_key.startswith("*"):
            config.elasticsearch_api_key = config_data.api_key
        if config_data.username is not None:
            config.elasticsearch_username = config_data.username
        if config_data.password is not None and not config_data.password.startswith("*"):
            config.elasticsearch_password = config_data.password
        if config_data.alert_index is not None:
            config.elasticsearch_alert_index = config_data.alert_index
        if config_data.case_index is not None:
            config.elasticsearch_case_index = config_data.case_index
        if config_data.verify_ssl is not None:
            config.elasticsearch_verify_ssl = config_data.verify_ssl

    elif integration == "kibana":
        if config_data.enabled is not None:
            config.kibana_cases_enabled = config_data.enabled
        if config_data.url is not None:
            config.kibana_url = config_data.url.rstrip("/")
        if config_data.username is not None:
            config.kibana_username = config_data.username
        if config_data.password is not None and not config_data.password.startswith("*"):
            config.kibana_password = config_data.password
        if config_data.space_id is not None:
            config.kibana_space_id = config_data.space_id
        if config_data.case_owner is not None:
            config.kibana_case_owner = config_data.case_owner
        if config_data.verify_ssl is not None:
            config.kibana_verify_ssl = config_data.verify_ssl

    elif integration == "gitlab":
        if config_data.enabled is not None:
            config.gitlab_enabled = config_data.enabled
        if config_data.url is not None:
            config.gitlab_url = config_data.url.rstrip("/")
        if config_data.token is not None and not config_data.token.startswith("*"):
            config.gitlab_token = config_data.token
        if config_data.project_id is not None:
            config.gitlab_project_id = config_data.project_id
        if config_data.verify_ssl is not None:
            config.gitlab_verify_ssl = config_data.verify_ssl

    elif integration == "opencti":
        if config_data.enabled is not None:
            config.opencti_enabled = config_data.enabled
        if config_data.url is not None:
            config.opencti_url = config_data.url.rstrip("/")
        if config_data.token is not None and not config_data.token.startswith("*"):
            config.opencti_token = config_data.token
        if config_data.verify_ssl is not None:
            config.opencti_verify_ssl = config_data.verify_ssl

    elif integration == "ollama":
        if config_data.enabled is not None:
            config.ollama_enabled = config_data.enabled
        if config_data.url is not None:
            config.ollama_url = config_data.url.rstrip("/")
        if config_data.model is not None:
            config.ollama_model = config_data.model
        if config_data.timeout is not None:
            config.ollama_timeout = config_data.timeout
        if config_data.verify_ssl is not None:
            config.ollama_verify_ssl = config_data.verify_ssl

    elif integration == "virustotal":
        if config_data.enabled is not None:
            config.virustotal_enabled = config_data.enabled
        if config_data.api_key is not None and not config_data.api_key.startswith("*"):
            config.virustotal_api_key = config_data.api_key

    elif integration == "abuseipdb":
        if config_data.enabled is not None:
            config.abuseipdb_enabled = config_data.enabled
        if config_data.api_key is not None and not config_data.api_key.startswith("*"):
            config.abuseipdb_api_key = config_data.api_key

    elif integration == "dfir_iris":
        if config_data.enabled is not None:
            config.dfir_iris_enabled = config_data.enabled
        if config_data.url is not None:
            config.dfir_iris_url = config_data.url.rstrip("/")
        if config_data.api_key is not None and not config_data.api_key.startswith("*"):
            config.dfir_iris_api_key = config_data.api_key
        if config_data.verify_ssl is not None:
            config.dfir_iris_verify_ssl = config_data.verify_ssl
        if config_data.default_customer is not None:
            config.dfir_iris_default_customer = config_data.default_customer

    else:
        raise HTTPException(400, f"Unknown integration: {integration}")

    config.to_file(get_config_path())
    reload_config()

    # Reset singleton services so they pick up new settings
    if integration == "ollama":
        from ion.services.ollama_service import reset_ollama_service
        reset_ollama_service()
    elif integration == "kibana":
        from ion.services.kibana_cases_service import reset_kibana_cases_service
        reset_kibana_cases_service()
    elif integration == "gitlab":
        from ion.services.gitlab_service import reset_gitlab_service
        reset_gitlab_service()

    return {"status": "saved", "integration": integration}


@router.post("/wizard/save-all")
async def save_all_wizard_integrations(
    request: WizardSaveAllRequest,
    current_user: User = Depends(require_permission("integration:manage")),
):
    """Save all integration configurations at once."""
    config = get_config()
    saved = []
    errors = []

    for integration_name, config_data_dict in request.integrations.items():
        try:
            # Convert dict to WizardIntegrationConfig
            config_data = WizardIntegrationConfig(**config_data_dict)

            if integration_name == "elasticsearch":
                if config_data.enabled is not None:
                    config.elasticsearch_enabled = config_data.enabled
                if config_data.url is not None:
                    config.elasticsearch_url = config_data.url.rstrip("/")
                if config_data.api_key is not None and not config_data.api_key.startswith("*"):
                    config.elasticsearch_api_key = config_data.api_key
                if config_data.username is not None:
                    config.elasticsearch_username = config_data.username
                if config_data.password is not None and not config_data.password.startswith("*"):
                    config.elasticsearch_password = config_data.password
                if config_data.alert_index is not None:
                    config.elasticsearch_alert_index = config_data.alert_index
                if config_data.case_index is not None:
                    config.elasticsearch_case_index = config_data.case_index
                if config_data.verify_ssl is not None:
                    config.elasticsearch_verify_ssl = config_data.verify_ssl
                saved.append("elasticsearch")

            elif integration_name == "kibana":
                if config_data.enabled is not None:
                    config.kibana_cases_enabled = config_data.enabled
                if config_data.url is not None:
                    config.kibana_url = config_data.url.rstrip("/")
                if config_data.username is not None:
                    config.kibana_username = config_data.username
                if config_data.password is not None and not config_data.password.startswith("*"):
                    config.kibana_password = config_data.password
                if config_data.space_id is not None:
                    config.kibana_space_id = config_data.space_id
                if config_data.case_owner is not None:
                    config.kibana_case_owner = config_data.case_owner
                if config_data.verify_ssl is not None:
                    config.kibana_verify_ssl = config_data.verify_ssl
                saved.append("kibana")

            elif integration_name == "gitlab":
                if config_data.enabled is not None:
                    config.gitlab_enabled = config_data.enabled
                if config_data.url is not None:
                    config.gitlab_url = config_data.url.rstrip("/")
                if config_data.token is not None and not config_data.token.startswith("*"):
                    config.gitlab_token = config_data.token
                if config_data.project_id is not None:
                    config.gitlab_project_id = config_data.project_id
                if config_data.verify_ssl is not None:
                    config.gitlab_verify_ssl = config_data.verify_ssl
                saved.append("gitlab")

            elif integration_name == "opencti":
                if config_data.enabled is not None:
                    config.opencti_enabled = config_data.enabled
                if config_data.url is not None:
                    config.opencti_url = config_data.url.rstrip("/")
                if config_data.token is not None and not config_data.token.startswith("*"):
                    config.opencti_token = config_data.token
                if config_data.verify_ssl is not None:
                    config.opencti_verify_ssl = config_data.verify_ssl
                saved.append("opencti")

            elif integration_name == "ollama":
                if config_data.enabled is not None:
                    config.ollama_enabled = config_data.enabled
                if config_data.url is not None:
                    config.ollama_url = config_data.url.rstrip("/")
                if config_data.model is not None:
                    config.ollama_model = config_data.model
                if config_data.timeout is not None:
                    config.ollama_timeout = config_data.timeout
                if config_data.verify_ssl is not None:
                    config.ollama_verify_ssl = config_data.verify_ssl
                saved.append("ollama")

            elif integration_name == "virustotal":
                if config_data.enabled is not None:
                    config.virustotal_enabled = config_data.enabled
                if config_data.api_key is not None and not config_data.api_key.startswith("*"):
                    config.virustotal_api_key = config_data.api_key
                saved.append("virustotal")

            elif integration_name == "abuseipdb":
                if config_data.enabled is not None:
                    config.abuseipdb_enabled = config_data.enabled
                if config_data.api_key is not None and not config_data.api_key.startswith("*"):
                    config.abuseipdb_api_key = config_data.api_key
                saved.append("abuseipdb")

            elif integration_name == "dfir_iris":
                if config_data.enabled is not None:
                    config.dfir_iris_enabled = config_data.enabled
                if config_data.url is not None:
                    config.dfir_iris_url = config_data.url.rstrip("/")
                if config_data.api_key is not None and not config_data.api_key.startswith("*"):
                    config.dfir_iris_api_key = config_data.api_key
                if config_data.verify_ssl is not None:
                    config.dfir_iris_verify_ssl = config_data.verify_ssl
                if config_data.default_customer is not None:
                    config.dfir_iris_default_customer = config_data.default_customer
                saved.append("dfir_iris")

            else:
                errors.append({"integration": integration_name, "error": "Unknown integration"})

        except Exception as e:
            errors.append({"integration": integration_name, "error": str(e)})

    # Save all changes
    config.to_file(get_config_path())
    reload_config()

    # Reset singleton services so they pick up new settings
    if "ollama" in saved:
        from ion.services.ollama_service import reset_ollama_service
        reset_ollama_service()
    if "kibana" in saved:
        from ion.services.kibana_cases_service import reset_kibana_cases_service
        reset_kibana_cases_service()
    if "gitlab" in saved:
        from ion.services.gitlab_service import reset_gitlab_service
        reset_gitlab_service()

    return {
        "status": "completed",
        "saved": saved,
        "errors": errors,
    }


@router.get("/wizard/ollama/models")
async def get_ollama_models(current_user: User = Depends(require_permission("integration:manage"))):
    """Get available Ollama models for selection."""
    config = get_config()

    if not config.ollama_url:
        return {"available": False, "models": [], "error": "Ollama URL not configured"}

    import httpx
    from ion.core.config import get_ssl_verify

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(5.0, connect=3.0), verify=get_ssl_verify(config.ollama_verify_ssl)) as client:
            response = await client.get(f"{config.ollama_url.rstrip('/')}/api/tags")
            response.raise_for_status()
            data = response.json()

            models = []
            for model in data.get("models", []):
                models.append({
                    "name": model.get("name"),
                    "size": model.get("size"),
                    "modified_at": model.get("modified_at"),
                    "parameter_size": model.get("details", {}).get("parameter_size", ""),
                })

            return {
                "available": True,
                "models": models,
                "current": config.ollama_model,
            }

    except httpx.ConnectError:
        return {"available": False, "models": [], "error": "Cannot connect to Ollama"}
    except Exception as e:
        return {"available": False, "models": [], "error": str(e)}
