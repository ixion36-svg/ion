"""Admin API endpoints for system configuration and management."""

from pathlib import Path
from typing import Optional
from datetime import datetime
import os
import platform
import sys

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from ixion.auth.dependencies import require_admin
from ixion.models.user import User
from ixion.core.config import get_config, set_config, Config

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
    oidc_enabled: Optional[bool] = None
    oidc_keycloak_url: Optional[str] = None
    oidc_realm: Optional[str] = None
    oidc_client_id: Optional[str] = None
    oidc_client_secret: Optional[str] = None  # Only update if provided and not masked
    oidc_auto_create_users: Optional[bool] = None
    oidc_role_claim: Optional[str] = None


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
    data_dir = os.environ.get("IXION_DATA_DIR")
    if data_dir:
        return Path(data_dir) / ".ixion" / "config.json"
    return Path.cwd() / ".ixion" / "config.json"


def reload_config() -> Config:
    """Reload configuration from file."""
    set_config(None)  # Clear cached config
    return get_config()


# =============================================================================
# Configuration Endpoints
# =============================================================================

@router.get("/config")
async def get_configuration(current_user: User = Depends(require_admin)):
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
            "oidc_enabled": config.oidc_enabled,
            "oidc_keycloak_url": config.oidc_keycloak_url,
            "oidc_realm": config.oidc_realm,
            "oidc_client_id": config.oidc_client_id,
            "oidc_client_secret": mask_secret(config.oidc_client_secret),
            "oidc_client_secret_set": bool(config.oidc_client_secret),
            "oidc_auto_create_users": config.oidc_auto_create_users,
            "oidc_role_claim": config.oidc_role_claim,
        },
        "config_path": str(get_config_path()),
    }


@router.put("/config/general")
async def update_general_settings(
    settings: GeneralSettingsUpdate,
    current_user: User = Depends(require_admin),
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
    current_user: User = Depends(require_admin),
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

    config.to_file(get_config_path())
    reload_config()
    return {"status": "updated", "section": "gitlab"}


@router.put("/config/opencti")
async def update_opencti_settings(
    settings: OpenCTISettingsUpdate,
    current_user: User = Depends(require_admin),
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
    current_user: User = Depends(require_admin),
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
    current_user: User = Depends(require_admin),
):
    """Update OIDC/Keycloak settings."""
    config = get_config()

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

    config.to_file(get_config_path())
    reload_config()
    return {"status": "updated", "section": "oidc"}


@router.post("/config/test/{integration}")
async def test_integration_connection(
    integration: str,
    current_user: User = Depends(require_admin),
):
    """Test connection to an integration."""
    if integration == "gitlab":
        from ixion.services.gitlab_service import get_gitlab_service
        service = get_gitlab_service()
        if not service.is_configured:
            return {"success": False, "error": "GitLab is not configured"}
        try:
            result = service.test_connection()
            return {"success": True, "details": result}
        except Exception as e:
            return {"success": False, "error": str(e)}

    elif integration == "opencti":
        from ixion.services.opencti_service import get_opencti_service
        service = get_opencti_service()
        if not service.is_configured:
            return {"success": False, "error": "OpenCTI is not configured"}
        try:
            result = service.test_connection()
            return {"success": True, "details": result}
        except Exception as e:
            return {"success": False, "error": str(e)}

    elif integration == "elasticsearch":
        from ixion.services.elasticsearch_service import ElasticsearchService
        service = ElasticsearchService()
        if not service.is_configured:
            return {"success": False, "error": "Elasticsearch is not configured"}
        try:
            result = service.test_connection()
            return {"success": True, "details": result}
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
    import ixion

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
        "ixion_version": getattr(ixion, "__version__", "0.1.0"),
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
    """Get IXION-related environment variables (values masked)."""
    env_vars = {}
    for key, value in os.environ.items():
        if key.startswith("IXION_"):
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
    from ixion.storage.database import get_engine, get_session
    from ixion.models.user import User as UserModel
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

    from ixion.storage.database import get_engine, get_session
    from ixion.models.user import User as UserModel

    config = get_config()
    engine = get_engine(config.db_path)

    try:
        with next(get_session(engine)) as db:
            user = db.query(UserModel).filter(UserModel.id == user_id).first()
            if not user:
                raise HTTPException(404, "User not found")

            # Log the session revocation
            from ixion.services.integration_log_service import IntegrationLogService
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
    from ixion.storage.database import get_engine, get_session
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
async def create_database_backup(current_user: User = Depends(require_admin)):
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
    backup_filename = f"ixion_backup_{timestamp}.db"
    backup_path = backup_dir / backup_filename

    try:
        shutil.copy2(config.db_path, backup_path)

        # Log the backup
        from ixion.storage.database import get_engine, get_session
        engine = get_engine(config.db_path)
        with next(get_session(engine)) as db:
            from ixion.services.integration_log_service import IntegrationLogService
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
    for backup_file in backup_dir.glob("ixion_backup_*.db"):
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
    if not re.match(r'^ixion_backup_\d{8}_\d{6}\.db$', filename):
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
async def restore_database_backup(
    filename: str,
    current_user: User = Depends(require_admin),
):
    """Restore database from a backup. Creates a backup of current DB first."""
    import re
    import shutil

    # Validate filename format
    if not re.match(r'^ixion_backup_\d{8}_\d{6}\.db$', filename):
        raise HTTPException(400, "Invalid backup filename format")

    config = get_config()
    backup_path = config.db_path.parent / "backups" / filename

    if not backup_path.exists():
        raise HTTPException(404, "Backup not found")

    # Create a backup of current database first
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pre_restore_backup = config.db_path.parent / "backups" / f"ixion_pre_restore_{timestamp}.db"

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
async def cleanup_old_data(
    days_to_keep: int = 30,
    current_user: User = Depends(require_admin),
):
    """Clean up old logs and temporary data."""
    from ixion.storage.database import get_engine, get_session
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
            from ixion.services.integration_log_service import IntegrationLogService
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
