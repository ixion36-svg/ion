"""Configuration management for ION."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Dict
import json
import os


@dataclass
class Config:
    """ION configuration."""

    db_path: Path = field(default_factory=lambda: Path.cwd() / ".ion" / "ion.db")
    default_format: str = "markdown"
    auto_save: bool = True
    max_versions_to_keep: int = 100

    # OIDC/Keycloak configuration
    oidc_enabled: bool = True
    oidc_keycloak_url: str = ""
    oidc_realm: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_auto_create_users: bool = True
    oidc_role_claim: str = "realm_access.roles"
    oidc_role_mapping: Dict[str, str] = field(default_factory=dict)
    oidc_verify_ssl: bool = True

    # Custom CA bundle for self-signed certificates (set via ION_CA_BUNDLE env var)
    ca_bundle: str = ""  # Path to CA cert file, e.g. /etc/ssl/certs/my-ca.pem

    # Security settings
    cookie_secure: bool = False  # Set to True when using HTTPS in production
    debug_mode: bool = False  # Enable API docs and detailed errors (disable in production)
    account_lockout_enabled: bool = False  # Lock accounts after repeated failed logins

    # GitLab integration
    gitlab_enabled: bool = True
    gitlab_url: str = ""  # e.g., https://gitlab.example.com or http://localhost:8929
    gitlab_token: str = ""  # Personal access token with api scope
    gitlab_project_id: str = ""  # Project ID or path (e.g., "group/project" or "123")

    # OpenCTI integration
    opencti_enabled: bool = True
    opencti_url: str = ""  # e.g., http://localhost:8888
    opencti_token: str = ""  # API bearer token (UUID)
    opencti_verify_ssl: bool = True

    # Elasticsearch integration
    elasticsearch_enabled: bool = True
    elasticsearch_url: str = ""  # e.g., https://localhost:9200
    elasticsearch_api_key: str = ""  # API key (preferred over username/password)
    elasticsearch_username: str = ""  # Basic auth username
    elasticsearch_password: str = ""  # Basic auth password
    elasticsearch_alert_index: str = ".alerts-*,.watcher-history-*,alerts-*"  # Alert index pattern
    elasticsearch_case_index: str = "ion-cases"  # Index for synced case documents
    elasticsearch_verify_ssl: bool = True

    # Ollama AI integration
    ollama_enabled: bool = True
    ollama_url: str = "http://localhost:11434"  # Ollama API URL
    ollama_model: str = "qwen2.5:7b"  # Default model
    ollama_timeout: int = 120  # Request timeout in seconds

    # Kibana Cases integration
    kibana_cases_enabled: bool = True
    kibana_url: str = ""  # e.g., http://localhost:5601
    kibana_username: str = ""  # Kibana username (uses ES credentials if not set)
    kibana_password: str = ""  # Kibana password
    kibana_space_id: str = "default"  # Kibana space ID
    kibana_case_owner: str = "securitySolution"  # Case owner app (securitySolution, observability, cases)

    # DFIR-IRIS integration
    dfir_iris_enabled: bool = False
    dfir_iris_url: str = ""  # e.g., https://iris.example.com
    dfir_iris_api_key: str = ""  # Bearer API key from IRIS user profile
    dfir_iris_verify_ssl: bool = True
    dfir_iris_default_customer: int = 1  # Default customer ID in IRIS

    # VirusTotal integration
    virustotal_enabled: bool = False
    virustotal_api_key: str = ""  # VirusTotal API key

    # AbuseIPDB integration
    abuseipdb_enabled: bool = False
    abuseipdb_api_key: str = ""  # AbuseIPDB API key

    @classmethod
    def from_file(cls, path: Path) -> "Config":
        """Load configuration from a JSON file."""
        if not path.exists():
            return cls()
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Get default db_path if not in file
        default_db_path = path.parent / "ion.db"
        db_path_str = data.get("db_path")
        db_path = Path(db_path_str) if db_path_str else default_db_path

        return cls(
            db_path=db_path,
            default_format=data.get("default_format", "markdown"),
            auto_save=data.get("auto_save", True),
            max_versions_to_keep=data.get("max_versions_to_keep", 100),
            # OIDC configuration
            oidc_enabled=data.get("oidc_enabled", True),
            oidc_keycloak_url=data.get("oidc_keycloak_url", ""),
            oidc_realm=data.get("oidc_realm", ""),
            oidc_client_id=data.get("oidc_client_id", ""),
            oidc_client_secret=data.get("oidc_client_secret", ""),
            oidc_auto_create_users=data.get("oidc_auto_create_users", True),
            oidc_role_claim=data.get("oidc_role_claim", "realm_access.roles"),
            oidc_role_mapping=data.get("oidc_role_mapping", {}),
            oidc_verify_ssl=data.get("oidc_verify_ssl", True),
            # Security settings
            cookie_secure=data.get("cookie_secure", False),
            debug_mode=data.get("debug_mode", False),
            account_lockout_enabled=data.get("account_lockout_enabled", False),
            # GitLab integration
            gitlab_enabled=data.get("gitlab_enabled", True),
            gitlab_url=data.get("gitlab_url", ""),
            gitlab_token=data.get("gitlab_token", ""),
            gitlab_project_id=data.get("gitlab_project_id", ""),
            # OpenCTI integration
            opencti_enabled=data.get("opencti_enabled", True),
            opencti_url=data.get("opencti_url", ""),
            opencti_token=data.get("opencti_token", ""),
            opencti_verify_ssl=data.get("opencti_verify_ssl", True),
            # Elasticsearch integration
            elasticsearch_enabled=data.get("elasticsearch_enabled", True),
            elasticsearch_url=data.get("elasticsearch_url", ""),
            elasticsearch_api_key=data.get("elasticsearch_api_key", ""),
            elasticsearch_username=data.get("elasticsearch_username", ""),
            elasticsearch_password=data.get("elasticsearch_password", ""),
            elasticsearch_alert_index=data.get("elasticsearch_alert_index", ".alerts-*,.watcher-history-*,alerts-*"),
            elasticsearch_case_index=data.get("elasticsearch_case_index", "ion-cases"),
            elasticsearch_verify_ssl=data.get("elasticsearch_verify_ssl", True),
            # Ollama AI integration
            ollama_enabled=data.get("ollama_enabled", True),
            ollama_url=data.get("ollama_url", "http://localhost:11434"),
            ollama_model=data.get("ollama_model", "qwen2.5:7b"),
            ollama_timeout=data.get("ollama_timeout", 120),
            # Kibana Cases integration
            kibana_cases_enabled=data.get("kibana_cases_enabled", True),
            kibana_url=data.get("kibana_url", ""),
            kibana_username=data.get("kibana_username", ""),
            kibana_password=data.get("kibana_password", ""),
            kibana_space_id=data.get("kibana_space_id", "default"),
            kibana_case_owner=data.get("kibana_case_owner", "securitySolution"),
            # DFIR-IRIS integration
            dfir_iris_enabled=data.get("dfir_iris_enabled", False),
            dfir_iris_url=data.get("dfir_iris_url", ""),
            dfir_iris_api_key=data.get("dfir_iris_api_key", ""),
            dfir_iris_verify_ssl=data.get("dfir_iris_verify_ssl", True),
            dfir_iris_default_customer=data.get("dfir_iris_default_customer", 1),
            # VirusTotal integration
            virustotal_enabled=data.get("virustotal_enabled", False),
            virustotal_api_key=data.get("virustotal_api_key", ""),
            # AbuseIPDB integration
            abuseipdb_enabled=data.get("abuseipdb_enabled", False),
            abuseipdb_api_key=data.get("abuseipdb_api_key", ""),
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
                    "oidc_verify_ssl": self.oidc_verify_ssl,
                    # Security settings
                    "cookie_secure": self.cookie_secure,
                    "debug_mode": self.debug_mode,
                    "account_lockout_enabled": self.account_lockout_enabled,
                    # GitLab integration
                    "gitlab_enabled": self.gitlab_enabled,
                    "gitlab_url": self.gitlab_url,
                    "gitlab_token": self.gitlab_token,
                    "gitlab_project_id": self.gitlab_project_id,
                    # OpenCTI integration
                    "opencti_enabled": self.opencti_enabled,
                    "opencti_url": self.opencti_url,
                    "opencti_token": self.opencti_token,
                    "opencti_verify_ssl": self.opencti_verify_ssl,
                    # Elasticsearch integration
                    "elasticsearch_enabled": self.elasticsearch_enabled,
                    "elasticsearch_url": self.elasticsearch_url,
                    "elasticsearch_api_key": self.elasticsearch_api_key,
                    "elasticsearch_username": self.elasticsearch_username,
                    "elasticsearch_password": self.elasticsearch_password,
                    "elasticsearch_alert_index": self.elasticsearch_alert_index,
                    "elasticsearch_case_index": self.elasticsearch_case_index,
                    "elasticsearch_verify_ssl": self.elasticsearch_verify_ssl,
                    # Ollama AI integration
                    "ollama_enabled": self.ollama_enabled,
                    "ollama_url": self.ollama_url,
                    "ollama_model": self.ollama_model,
                    "ollama_timeout": self.ollama_timeout,
                    # Kibana Cases integration
                    "kibana_cases_enabled": self.kibana_cases_enabled,
                    "kibana_url": self.kibana_url,
                    "kibana_username": self.kibana_username,
                    "kibana_password": self.kibana_password,
                    "kibana_space_id": self.kibana_space_id,
                    "kibana_case_owner": self.kibana_case_owner,
                    # DFIR-IRIS integration
                    "dfir_iris_enabled": self.dfir_iris_enabled,
                    "dfir_iris_url": self.dfir_iris_url,
                    "dfir_iris_api_key": self.dfir_iris_api_key,
                    "dfir_iris_verify_ssl": self.dfir_iris_verify_ssl,
                    "dfir_iris_default_customer": self.dfir_iris_default_customer,
                    # VirusTotal integration
                    "virustotal_enabled": self.virustotal_enabled,
                    "virustotal_api_key": self.virustotal_api_key,
                    # AbuseIPDB integration
                    "abuseipdb_enabled": self.abuseipdb_enabled,
                    "abuseipdb_api_key": self.abuseipdb_api_key,
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
    2. Config file (.ion/config.json)
    3. Default values (lowest priority)
    """
    global _config
    if _config is None:
        # Check for data directory override (for Docker)
        data_dir = os.environ.get("ION_DATA_DIR")
        if data_dir:
            config_path = Path(data_dir) / ".ion" / "config.json"
        else:
            config_path = Path.cwd() / ".ion" / "config.json"

        # Load from file if exists
        if config_path.exists():
            _config = Config.from_file(config_path)
        else:
            _config = Config()

        # Override with environment variables
        if os.environ.get("ION_CA_BUNDLE"):
            _config.ca_bundle = os.environ.get("ION_CA_BUNDLE", "")
        if os.environ.get("ION_COOKIE_SECURE"):
            _config.cookie_secure = _get_env_bool("ION_COOKIE_SECURE")
        if os.environ.get("ION_DEBUG_MODE"):
            _config.debug_mode = _get_env_bool("ION_DEBUG_MODE")
        if os.environ.get("ION_ACCOUNT_LOCKOUT_ENABLED"):
            _config.account_lockout_enabled = _get_env_bool("ION_ACCOUNT_LOCKOUT_ENABLED")
        if os.environ.get("ION_OIDC_ENABLED"):
            _config.oidc_enabled = _get_env_bool("ION_OIDC_ENABLED", True)
        if os.environ.get("ION_OIDC_KEYCLOAK_URL"):
            _config.oidc_keycloak_url = os.environ.get("ION_OIDC_KEYCLOAK_URL", "")
        if os.environ.get("ION_OIDC_REALM"):
            _config.oidc_realm = os.environ.get("ION_OIDC_REALM", "")
        if os.environ.get("ION_OIDC_CLIENT_ID"):
            _config.oidc_client_id = os.environ.get("ION_OIDC_CLIENT_ID", "")
        if os.environ.get("ION_OIDC_CLIENT_SECRET"):
            _config.oidc_client_secret = os.environ.get("ION_OIDC_CLIENT_SECRET", "")
        if os.environ.get("ION_OIDC_VERIFY_SSL"):
            _config.oidc_verify_ssl = _get_env_bool("ION_OIDC_VERIFY_SSL", True)

        # GitLab environment variable overrides
        if os.environ.get("ION_GITLAB_ENABLED"):
            _config.gitlab_enabled = _get_env_bool("ION_GITLAB_ENABLED", True)
        if os.environ.get("ION_GITLAB_URL"):
            _config.gitlab_url = os.environ.get("ION_GITLAB_URL", "")
        if os.environ.get("ION_GITLAB_TOKEN"):
            _config.gitlab_token = os.environ.get("ION_GITLAB_TOKEN", "")
        if os.environ.get("ION_GITLAB_PROJECT_ID"):
            _config.gitlab_project_id = os.environ.get("ION_GITLAB_PROJECT_ID", "")

        # OpenCTI environment variable overrides
        if os.environ.get("ION_OPENCTI_ENABLED"):
            _config.opencti_enabled = _get_env_bool("ION_OPENCTI_ENABLED", True)
        if os.environ.get("ION_OPENCTI_URL"):
            _config.opencti_url = os.environ.get("ION_OPENCTI_URL", "")
        if os.environ.get("ION_OPENCTI_TOKEN"):
            _config.opencti_token = os.environ.get("ION_OPENCTI_TOKEN", "")
        if os.environ.get("ION_OPENCTI_VERIFY_SSL"):
            _config.opencti_verify_ssl = _get_env_bool("ION_OPENCTI_VERIFY_SSL", True)

        # Elasticsearch environment variable overrides
        if os.environ.get("ION_ELASTICSEARCH_ENABLED"):
            _config.elasticsearch_enabled = _get_env_bool("ION_ELASTICSEARCH_ENABLED", True)
        if os.environ.get("ION_ELASTICSEARCH_URL"):
            _config.elasticsearch_url = os.environ.get("ION_ELASTICSEARCH_URL", "")
        if os.environ.get("ION_ELASTICSEARCH_API_KEY"):
            _config.elasticsearch_api_key = os.environ.get("ION_ELASTICSEARCH_API_KEY", "")
        if os.environ.get("ION_ELASTICSEARCH_USERNAME"):
            _config.elasticsearch_username = os.environ.get("ION_ELASTICSEARCH_USERNAME", "")
        if os.environ.get("ION_ELASTICSEARCH_PASSWORD"):
            _config.elasticsearch_password = os.environ.get("ION_ELASTICSEARCH_PASSWORD", "")
        if os.environ.get("ION_ELASTICSEARCH_ALERT_INDEX"):
            _config.elasticsearch_alert_index = os.environ.get("ION_ELASTICSEARCH_ALERT_INDEX", "")
        if os.environ.get("ION_ELASTICSEARCH_CASE_INDEX"):
            _config.elasticsearch_case_index = os.environ.get("ION_ELASTICSEARCH_CASE_INDEX", "ion-cases")
        if os.environ.get("ION_ELASTICSEARCH_VERIFY_SSL"):
            _config.elasticsearch_verify_ssl = _get_env_bool("ION_ELASTICSEARCH_VERIFY_SSL", True)

        # Ollama environment overrides
        if os.environ.get("ION_OLLAMA_ENABLED"):
            _config.ollama_enabled = _get_env_bool("ION_OLLAMA_ENABLED", True)
        if os.environ.get("ION_OLLAMA_URL") or os.environ.get("OLLAMA_URL"):
            _config.ollama_url = os.environ.get("ION_OLLAMA_URL") or os.environ.get("OLLAMA_URL", "http://localhost:11434")
        if os.environ.get("ION_OLLAMA_MODEL"):
            _config.ollama_model = os.environ.get("ION_OLLAMA_MODEL", "qwen2.5:7b")
        if os.environ.get("ION_OLLAMA_TIMEOUT"):
            _config.ollama_timeout = int(os.environ.get("ION_OLLAMA_TIMEOUT", "120"))

        # Kibana Cases environment overrides
        if os.environ.get("ION_KIBANA_CASES_ENABLED"):
            _config.kibana_cases_enabled = _get_env_bool("ION_KIBANA_CASES_ENABLED", True)
        if os.environ.get("ION_KIBANA_URL"):
            _config.kibana_url = os.environ.get("ION_KIBANA_URL", "")
        if os.environ.get("ION_KIBANA_USERNAME"):
            _config.kibana_username = os.environ.get("ION_KIBANA_USERNAME", "")
        if os.environ.get("ION_KIBANA_PASSWORD"):
            _config.kibana_password = os.environ.get("ION_KIBANA_PASSWORD", "")
        if os.environ.get("ION_KIBANA_SPACE_ID"):
            _config.kibana_space_id = os.environ.get("ION_KIBANA_SPACE_ID", "default")
        if os.environ.get("ION_KIBANA_CASE_OWNER"):
            _config.kibana_case_owner = os.environ.get("ION_KIBANA_CASE_OWNER", "securitySolution")

        # DFIR-IRIS environment overrides
        if os.environ.get("ION_DFIR_IRIS_ENABLED"):
            _config.dfir_iris_enabled = _get_env_bool("ION_DFIR_IRIS_ENABLED")
        if os.environ.get("ION_DFIR_IRIS_URL"):
            _config.dfir_iris_url = os.environ.get("ION_DFIR_IRIS_URL", "")
        if os.environ.get("ION_DFIR_IRIS_API_KEY"):
            _config.dfir_iris_api_key = os.environ.get("ION_DFIR_IRIS_API_KEY", "")
        if os.environ.get("ION_DFIR_IRIS_VERIFY_SSL"):
            _config.dfir_iris_verify_ssl = _get_env_bool("ION_DFIR_IRIS_VERIFY_SSL", True)
        if os.environ.get("ION_DFIR_IRIS_DEFAULT_CUSTOMER"):
            _config.dfir_iris_default_customer = int(os.environ.get("ION_DFIR_IRIS_DEFAULT_CUSTOMER", "1"))

        # VirusTotal environment overrides
        if os.environ.get("ION_VIRUSTOTAL_ENABLED"):
            _config.virustotal_enabled = _get_env_bool("ION_VIRUSTOTAL_ENABLED")
        if os.environ.get("ION_VIRUSTOTAL_API_KEY"):
            _config.virustotal_api_key = os.environ.get("ION_VIRUSTOTAL_API_KEY", "")

        # AbuseIPDB environment overrides
        if os.environ.get("ION_ABUSEIPDB_ENABLED"):
            _config.abuseipdb_enabled = _get_env_bool("ION_ABUSEIPDB_ENABLED")
        if os.environ.get("ION_ABUSEIPDB_API_KEY"):
            _config.abuseipdb_api_key = os.environ.get("ION_ABUSEIPDB_API_KEY", "")

    return _config


def set_config(config: Optional[Config]) -> None:
    """Set the global configuration instance. Pass None to clear cache."""
    global _config
    _config = config


from typing import Union


def get_ssl_verify(verify_ssl: bool = True) -> Union[bool, str]:
    """Resolve the httpx ``verify`` parameter.

    Returns:
        - CA bundle path (str) when ``ION_CA_BUNDLE`` is set and ``verify_ssl`` is True
        - True when ``verify_ssl`` is True and no custom CA bundle is configured
        - False when ``verify_ssl`` is False
    """
    if not verify_ssl:
        return False
    config = get_config()
    if config.ca_bundle:
        return config.ca_bundle
    return True


def get_oidc_config():
    """Get OIDC configuration from the global config.

    Returns an OIDCConfig instance populated from the global Config.
    """
    from ion.auth.oidc_config import OIDCConfig

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
        verify_ssl=config.oidc_verify_ssl,
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


def get_opencti_config() -> dict:
    """Get OpenCTI configuration from the global config.

    Returns a dictionary with OpenCTI configuration.
    """
    config = get_config()
    return {
        "enabled": config.opencti_enabled,
        "url": config.opencti_url,
        "token": config.opencti_token,
        "verify_ssl": config.opencti_verify_ssl,
    }


def get_elasticsearch_config() -> dict:
    """Get Elasticsearch configuration from the global config.

    Returns a dictionary with Elasticsearch configuration.
    """
    config = get_config()
    return {
        "enabled": config.elasticsearch_enabled,
        "url": config.elasticsearch_url,
        "api_key": config.elasticsearch_api_key,
        "username": config.elasticsearch_username,
        "password": config.elasticsearch_password,
        "alert_index": config.elasticsearch_alert_index,
        "case_index": config.elasticsearch_case_index,
        "verify_ssl": config.elasticsearch_verify_ssl,
    }


def get_kibana_config() -> dict:
    """Get Kibana Cases configuration from the global config.

    Returns a dictionary with Kibana configuration.
    """
    config = get_config()
    # Fall back to Elasticsearch credentials if Kibana-specific ones not set
    username = config.kibana_username or config.elasticsearch_username
    password = config.kibana_password or config.elasticsearch_password
    return {
        "enabled": config.kibana_cases_enabled,
        "url": config.kibana_url,
        "username": username,
        "password": password,
        "space_id": config.kibana_space_id,
        "case_owner": config.kibana_case_owner,
    }


def get_dfir_iris_config() -> dict:
    """Get DFIR-IRIS configuration from the global config.

    Returns a dictionary with DFIR-IRIS configuration.
    """
    config = get_config()
    return {
        "enabled": config.dfir_iris_enabled,
        "url": config.dfir_iris_url,
        "api_key": config.dfir_iris_api_key,
        "verify_ssl": config.dfir_iris_verify_ssl,
        "default_customer": config.dfir_iris_default_customer,
    }
