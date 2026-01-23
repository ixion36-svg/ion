"""Configuration management for DocForge."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Dict
import json
import os


@dataclass
class Config:
    """DocForge configuration."""

    db_path: Path = field(default_factory=lambda: Path.cwd() / ".docforge" / "docforge.db")
    default_format: str = "markdown"
    auto_save: bool = True
    max_versions_to_keep: int = 100

    # OIDC/Keycloak configuration
    oidc_enabled: bool = False
    oidc_keycloak_url: str = ""
    oidc_realm: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_auto_create_users: bool = True
    oidc_role_claim: str = "realm_access.roles"
    oidc_role_mapping: Dict[str, str] = field(default_factory=dict)

    # Security settings
    cookie_secure: bool = False  # Set to True when using HTTPS in production

    # GitLab integration
    gitlab_enabled: bool = False
    gitlab_url: str = ""  # e.g., https://gitlab.example.com or http://localhost:8929
    gitlab_token: str = ""  # Personal access token with api scope
    gitlab_project_id: str = ""  # Project ID or path (e.g., "group/project" or "123")

    @classmethod
    def from_file(cls, path: Path) -> "Config":
        """Load configuration from a JSON file."""
        if not path.exists():
            return cls()
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Get default db_path if not in file
        default_db_path = path.parent / "docforge.db"
        db_path_str = data.get("db_path")
        db_path = Path(db_path_str) if db_path_str else default_db_path

        return cls(
            db_path=db_path,
            default_format=data.get("default_format", "markdown"),
            auto_save=data.get("auto_save", True),
            max_versions_to_keep=data.get("max_versions_to_keep", 100),
            # OIDC configuration
            oidc_enabled=data.get("oidc_enabled", False),
            oidc_keycloak_url=data.get("oidc_keycloak_url", ""),
            oidc_realm=data.get("oidc_realm", ""),
            oidc_client_id=data.get("oidc_client_id", ""),
            oidc_client_secret=data.get("oidc_client_secret", ""),
            oidc_auto_create_users=data.get("oidc_auto_create_users", True),
            oidc_role_claim=data.get("oidc_role_claim", "realm_access.roles"),
            oidc_role_mapping=data.get("oidc_role_mapping", {}),
            # Security settings
            cookie_secure=data.get("cookie_secure", False),
            # GitLab integration
            gitlab_enabled=data.get("gitlab_enabled", False),
            gitlab_url=data.get("gitlab_url", ""),
            gitlab_token=data.get("gitlab_token", ""),
            gitlab_project_id=data.get("gitlab_project_id", ""),
        )

    def to_file(self, path: Path) -> None:
        """Save configuration to a JSON file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "db_path": str(self.db_path),
                    "default_format": self.default_format,
                    "auto_save": self.auto_save,
                    "max_versions_to_keep": self.max_versions_to_keep,
                    # OIDC configuration
                    "oidc_enabled": self.oidc_enabled,
                    "oidc_keycloak_url": self.oidc_keycloak_url,
                    "oidc_realm": self.oidc_realm,
                    "oidc_client_id": self.oidc_client_id,
                    "oidc_client_secret": self.oidc_client_secret,
                    "oidc_auto_create_users": self.oidc_auto_create_users,
                    "oidc_role_claim": self.oidc_role_claim,
                    "oidc_role_mapping": self.oidc_role_mapping,
                    # Security settings
                    "cookie_secure": self.cookie_secure,
                    # GitLab integration
                    "gitlab_enabled": self.gitlab_enabled,
                    "gitlab_url": self.gitlab_url,
                    "gitlab_token": self.gitlab_token,
                    "gitlab_project_id": self.gitlab_project_id,
                },
                f,
                indent=2,
            )


_config: Optional[Config] = None


def _get_env_bool(key: str, default: bool = False) -> bool:
    """Get boolean from environment variable."""
    val = os.environ.get(key, "").lower()
    if val in ("true", "1", "yes"):
        return True
    elif val in ("false", "0", "no"):
        return False
    return default


def get_config() -> Config:
    """Get the global configuration instance.

    Configuration is loaded in order of precedence:
    1. Environment variables (highest priority)
    2. Config file (.docforge/config.json)
    3. Default values (lowest priority)
    """
    global _config
    if _config is None:
        # Check for data directory override (for Docker)
        data_dir = os.environ.get("DOCFORGE_DATA_DIR")
        if data_dir:
            config_path = Path(data_dir) / ".docforge" / "config.json"
        else:
            config_path = Path.cwd() / ".docforge" / "config.json"

        # Load from file if exists
        if config_path.exists():
            _config = Config.from_file(config_path)
        else:
            _config = Config()

        # Override with environment variables
        if os.environ.get("DOCFORGE_COOKIE_SECURE"):
            _config.cookie_secure = _get_env_bool("DOCFORGE_COOKIE_SECURE")
        if os.environ.get("DOCFORGE_OIDC_ENABLED"):
            _config.oidc_enabled = _get_env_bool("DOCFORGE_OIDC_ENABLED")
        if os.environ.get("DOCFORGE_OIDC_KEYCLOAK_URL"):
            _config.oidc_keycloak_url = os.environ.get("DOCFORGE_OIDC_KEYCLOAK_URL", "")
        if os.environ.get("DOCFORGE_OIDC_REALM"):
            _config.oidc_realm = os.environ.get("DOCFORGE_OIDC_REALM", "")
        if os.environ.get("DOCFORGE_OIDC_CLIENT_ID"):
            _config.oidc_client_id = os.environ.get("DOCFORGE_OIDC_CLIENT_ID", "")
        if os.environ.get("DOCFORGE_OIDC_CLIENT_SECRET"):
            _config.oidc_client_secret = os.environ.get("DOCFORGE_OIDC_CLIENT_SECRET", "")

        # GitLab environment variable overrides
        if os.environ.get("DOCFORGE_GITLAB_ENABLED"):
            _config.gitlab_enabled = _get_env_bool("DOCFORGE_GITLAB_ENABLED")
        if os.environ.get("DOCFORGE_GITLAB_URL"):
            _config.gitlab_url = os.environ.get("DOCFORGE_GITLAB_URL", "")
        if os.environ.get("DOCFORGE_GITLAB_TOKEN"):
            _config.gitlab_token = os.environ.get("DOCFORGE_GITLAB_TOKEN", "")
        if os.environ.get("DOCFORGE_GITLAB_PROJECT_ID"):
            _config.gitlab_project_id = os.environ.get("DOCFORGE_GITLAB_PROJECT_ID", "")

    return _config


def set_config(config: Config) -> None:
    """Set the global configuration instance."""
    global _config
    _config = config


def get_oidc_config():
    """Get OIDC configuration from the global config.

    Returns an OIDCConfig instance populated from the global Config.
    """
    from docforge.auth.oidc_config import OIDCConfig

    config = get_config()
    return OIDCConfig(
        enabled=config.oidc_enabled,
        keycloak_url=config.oidc_keycloak_url,
        realm=config.oidc_realm,
        client_id=config.oidc_client_id,
        client_secret=config.oidc_client_secret,
        auto_create_users=config.oidc_auto_create_users,
        role_claim=config.oidc_role_claim,
        role_mapping=config.oidc_role_mapping,
    )


def get_gitlab_config() -> dict:
    """Get GitLab configuration from the global config.

    Returns a dictionary with GitLab configuration.
    """
    config = get_config()
    return {
        "enabled": config.gitlab_enabled,
        "url": config.gitlab_url,
        "token": config.gitlab_token,
        "project_id": config.gitlab_project_id,
    }
