"""Configuration management for ION."""

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional


@dataclass
class Config:
    """ION configuration."""

    db_path: Path = field(default_factory=lambda: Path.cwd() / ".ion" / "ion.db")
    default_format: str = "markdown"
    auto_save: bool = True
    max_versions_to_keep: int = 100

    # Base URL for OIDC redirect URIs (e.g., https://ion.example.org)
    base_url: str = "https://ion.guardedglass.internal"

    # OIDC/Keycloak configuration
    oidc_enabled: bool = True
    oidc_keycloak_url: str = ""
    oidc_realm: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_auto_create_users: bool = True
    oidc_role_claim: str = "realm_access.roles"
    oidc_role_mapping: Dict[str, str] = field(default_factory=dict)
    oidc_verify_ssl: bool = False

    # Custom CA bundle for self-signed certificates (set via ION_CA_BUNDLE env var)
    ca_bundle: str = ""  # Path to CA cert file, e.g. /etc/ssl/certs/my-ca.pem

    # TLS for ION web server (serve HTTPS directly without reverse proxy)
    ssl_cert: str = ""  # Path to PEM certificate file
    ssl_key: str = ""   # Path to PEM private key file

    # Security settings
    cookie_secure: bool = False  # Set to True when using HTTPS in production
    debug_mode: bool = False  # Enable API docs and detailed errors (disable in production)
    account_lockout_enabled: bool = False  # Lock accounts after repeated failed logins

    # GitLab integration
    gitlab_enabled: bool = True
    gitlab_url: str = ""  # e.g., https://gitlab.example.com or http://localhost:8929
    gitlab_token: str = ""  # Personal access token with api scope
    gitlab_project_id: str = ""  # Project ID or path (e.g., "group/project" or "123")
    gitlab_verify_ssl: bool = False
    gitlab_sudo_enabled: bool = False  # Requires admin-level API token

    # OpenCTI integration
    opencti_enabled: bool = True
    opencti_url: str = ""  # e.g., http://localhost:8888
    opencti_token: str = ""  # API bearer token (UUID)
    opencti_verify_ssl: bool = False

    # Arkime integration (v5.x viewer API — fetch raw PCAPs by session id)
    arkime_enabled: bool = False
    arkime_url: str = ""  # e.g., https://viewer.guardedglass.internal
    # Preferred auth: Keycloak OAuth2 client_credentials grant
    arkime_keycloak_issuer: str = ""  # e.g., https://keycloak.guardedglass.internal/realms/soc
    arkime_keycloak_client_id: str = ""
    arkime_keycloak_client_secret: str = ""
    arkime_keycloak_scope: str = "openid"  # space-separated scopes
    # Fallback auth for dev / non-SSO setups
    arkime_username: str = ""  # HTTP basic auth
    arkime_password: str = ""
    arkime_api_key: str = ""  # Digest-style token
    arkime_verify_ssl: bool = False

    # Elasticsearch integration
    elasticsearch_enabled: bool = True
    elasticsearch_url: str = ""  # e.g., https://localhost:9200
    elasticsearch_api_key: str = ""  # API key (preferred over username/password)
    elasticsearch_username: str = ""  # Basic auth username
    elasticsearch_password: str = ""  # Basic auth password
    elasticsearch_alert_index: str = ".alerts-security.alerts-production"  # Alert index pattern
    elasticsearch_case_index: str = "ion-cases"  # Index for synced case documents
    elasticsearch_verify_ssl: bool = False
    # User mapping for alert assignment
    elasticsearch_user_index: str = "ion-users"  # ES index containing user profiles
    elasticsearch_user_field: str = "ion.user"  # Field in user index with display names
    elasticsearch_assignment_field: str = "kibana.alert.workflow_user"  # Field on alerts to write assignment

    # Ollama AI integration
    ollama_enabled: bool = True
    ollama_url: str = "http://localhost:11434"  # Ollama API URL
    ollama_model: str = "llama3.1:8b"  # Default model
    ollama_timeout: int = 300  # Request timeout in seconds (v0.17.3: bumped 120 → 300 for long investigation prompts)
    ollama_verify_ssl: bool = False

    # Kibana Cases integration
    kibana_cases_enabled: bool = True
    kibana_url: str = ""  # e.g., http://localhost:5601
    kibana_username: str = ""  # Kibana username (uses ES credentials if not set)
    kibana_password: str = ""  # Kibana password
    kibana_space_id: str = "production"  # Kibana space ID
    kibana_case_owner: str = "securitySolution"  # Case owner app (securitySolution, observability, cases)
    kibana_verify_ssl: bool = False

    # DFIR-IRIS integration
    dfir_iris_enabled: bool = False
    dfir_iris_url: str = ""  # e.g., https://iris.example.com
    dfir_iris_api_key: str = ""  # Bearer API key from IRIS user profile
    dfir_iris_verify_ssl: bool = False
    dfir_iris_default_customer: int = 1  # Default customer ID in IRIS

    # VirusTotal integration
    virustotal_enabled: bool = False
    virustotal_api_key: str = ""  # VirusTotal API key
    virustotal_url: str = "https://www.virustotal.com"
    virustotal_verify_ssl: bool = True
    virustotal_timeout: int = 30
    virustotal_rate_limit: int = 4  # requests/minute (free tier)

    # Shodan integration
    shodan_enabled: bool = False
    shodan_api_key: str = ""
    shodan_url: str = "https://api.shodan.io"
    shodan_verify_ssl: bool = True
    shodan_timeout: int = 30

    # AbuseIPDB integration
    abuseipdb_enabled: bool = False
    abuseipdb_api_key: str = ""  # AbuseIPDB API key

    # TIDE (Threat Informed Detection Engineering) integration
    tide_enabled: bool = False
    tide_url: str = ""  # e.g., https://tide.example.com
    tide_api_key: str = ""  # X-TIDE-API-KEY for external query API
    tide_verify_ssl: bool = False
    tide_space: str = "default"  # Kibana space where TIDE rules live (e.g., default, production)
    tide_client_id: str = ""  # TIDE 4.x tenant (client) id. Leave blank for single-tenant API keys.

    # Generic job scheduler
    scheduler_enabled: bool = True
    scheduler_interval_s: int = 30

    # Case grouper (auto-group alerts into [Auto] cases)
    case_grouper_enabled: bool = True
    case_grouper_interval_s: int = 60
    case_grouper_window_minutes: int = 15
    case_grouper_push_to_kibana: bool = True
    case_grouper_auto_investigate: bool = True
    # Delay in seconds between successive investigation enqueues so Ollama's
    # parallel slots don't all fill at once (preventing 120s HTTP timeouts).
    # With per-case investigation (default) this is rarely triggered.
    case_grouper_stagger_s: float = 3.0
    # Minimum number of similar alerts in the window before they are grouped
    # into a single [Auto] case. Set >1 to let small bursts accumulate.
    case_grouper_min_cluster_size: int = 1
    # Maximum alerts attached to a single auto-case. Once reached, new matching
    # alerts create a fresh case. Prevents runaway mega-cases.
    case_grouper_max_alerts_per_case: int = 20
    # If True, grouper runs ONE investigation per case (cluster-level) instead
    # of one per alert. Reduces LLM load ~N× and gives AI full cluster context.
    case_grouper_investigate_per_case: bool = True

    # PII anonymising proxy (tokenises sensitive fields before LLM calls)
    pii_anon_enabled: bool = False
    pii_fields_file: str = ""  # optional override; empty = use packaged default

    # Investigation loop
    investigation_loop_enabled: bool = True
    investigation_sweep_interval_s: int = 900
    investigation_max_per_sweep: int = 50
    investigation_llm_timeout_s: int = 120

    # --- Active response executors ---
    exec_dry_run: bool = True          # Safety: default TRUE; no real calls made
    exec_default_timeout_s: int = 20

    # Firewall REST webhook (block_ip)
    exec_firewall_url: str = ""
    exec_firewall_api_key: str = ""
    exec_firewall_verify_ssl: bool = True

    # DNS sinkhole (block_domain)
    exec_dns_sinkhole_url: str = ""
    exec_dns_sinkhole_api_key: str = ""
    exec_dns_sinkhole_verify_ssl: bool = True

    # EDR webhook (quarantine_host)
    exec_edr_url: str = ""
    exec_edr_api_key: str = ""
    exec_edr_verify_ssl: bool = True

    # Email gateway (block_sender)
    exec_email_gateway_url: str = ""
    exec_email_gateway_api_key: str = ""
    exec_email_gateway_verify_ssl: bool = True

    # Active Directory LDAP (disable_account, reset_password)
    exec_ad_ldap_uri: str = ""
    exec_ad_bind_dn: str = ""
    exec_ad_bind_password: str = ""
    exec_ad_user_search_base: str = ""
    exec_ad_verify_ssl: bool = True

    # Generic webhook catch-all
    exec_generic_webhook_api_key: str = ""

    # SMTP / email notification integration
    smtp_enabled: bool = False
    smtp_host: str = ""  # e.g., smtp.gmail.com or mail.example.com
    smtp_port: int = 587  # 587 for STARTTLS, 465 for implicit TLS
    smtp_username: str = ""  # SMTP auth username (leave blank for unauthenticated relays)
    smtp_password: str = ""  # SMTP auth password
    smtp_from_address: str = ""  # Sender address, e.g., ion-noreply@example.com
    smtp_from_name: str = "ION"  # Display name for the From header
    smtp_use_tls: bool = False  # Implicit TLS (port 465). Mutually exclusive with STARTTLS.
    smtp_use_starttls: bool = True  # Upgrade plaintext connection to TLS (port 587)
    smtp_timeout: int = 30  # Socket timeout in seconds
    smtp_verify_ssl: bool = True  # Verify server certificate

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
            # Base URL
            base_url=data.get("base_url", "https://ion.guardedglass.internal"),
            # OIDC configuration
            oidc_enabled=data.get("oidc_enabled", True),
            oidc_keycloak_url=data.get("oidc_keycloak_url", ""),
            oidc_realm=data.get("oidc_realm", ""),
            oidc_client_id=data.get("oidc_client_id", ""),
            oidc_client_secret=data.get("oidc_client_secret", ""),
            oidc_auto_create_users=data.get("oidc_auto_create_users", True),
            oidc_role_claim=data.get("oidc_role_claim", "realm_access.roles"),
            oidc_role_mapping=data.get("oidc_role_mapping", {}),
            oidc_verify_ssl=data.get("oidc_verify_ssl", False),
            # TLS
            ssl_cert=data.get("ssl_cert", ""),
            ssl_key=data.get("ssl_key", ""),
            # Security settings
            cookie_secure=data.get("cookie_secure", False),
            debug_mode=data.get("debug_mode", False),
            account_lockout_enabled=data.get("account_lockout_enabled", False),
            # GitLab integration
            gitlab_enabled=data.get("gitlab_enabled", True),
            gitlab_url=data.get("gitlab_url", ""),
            gitlab_token=data.get("gitlab_token", ""),
            gitlab_project_id=data.get("gitlab_project_id", ""),
            gitlab_verify_ssl=data.get("gitlab_verify_ssl", False),
            gitlab_sudo_enabled=data.get("gitlab_sudo_enabled", False),
            # OpenCTI integration
            opencti_enabled=data.get("opencti_enabled", True),
            opencti_url=data.get("opencti_url", ""),
            opencti_token=data.get("opencti_token", ""),
            opencti_verify_ssl=data.get("opencti_verify_ssl", False),
            arkime_enabled=data.get("arkime_enabled", False),
            arkime_url=data.get("arkime_url", ""),
            arkime_keycloak_issuer=data.get("arkime_keycloak_issuer", ""),
            arkime_keycloak_client_id=data.get("arkime_keycloak_client_id", ""),
            arkime_keycloak_client_secret=data.get("arkime_keycloak_client_secret", ""),
            arkime_keycloak_scope=data.get("arkime_keycloak_scope", "openid"),
            arkime_username=data.get("arkime_username", ""),
            arkime_password=data.get("arkime_password", ""),
            arkime_api_key=data.get("arkime_api_key", ""),
            arkime_verify_ssl=data.get("arkime_verify_ssl", False),
            # Elasticsearch integration
            elasticsearch_enabled=data.get("elasticsearch_enabled", True),
            elasticsearch_url=data.get("elasticsearch_url", ""),
            elasticsearch_api_key=data.get("elasticsearch_api_key", ""),
            elasticsearch_username=data.get("elasticsearch_username", ""),
            elasticsearch_password=data.get("elasticsearch_password", ""),
            elasticsearch_alert_index=data.get("elasticsearch_alert_index", ".alerts-security.alerts-production"),
            elasticsearch_case_index=data.get("elasticsearch_case_index", "ion-cases"),
            elasticsearch_verify_ssl=data.get("elasticsearch_verify_ssl", False),
            elasticsearch_user_index=data.get("elasticsearch_user_index", "ion-users"),
            elasticsearch_user_field=data.get("elasticsearch_user_field", "ion.user"),
            elasticsearch_assignment_field=data.get("elasticsearch_assignment_field", "kibana.alert.workflow_user"),
            # Ollama AI integration
            ollama_enabled=data.get("ollama_enabled", True),
            ollama_url=data.get("ollama_url", "http://localhost:11434"),
            ollama_model=data.get("ollama_model", "llama3.1:8b"),
            # v0.17.3 upgrade migration: silently bump the historical 120s
            # default to 300s so existing deployments pick up the longer
            # investigation timeout without an operator edit. Anyone who
            # explicitly chose 120 (rare — that's just the old default)
            # can override via ION_OLLAMA_TIMEOUT in .env.
            ollama_timeout=(300 if data.get("ollama_timeout", 300) == 120 else data.get("ollama_timeout", 300)),
            ollama_verify_ssl=data.get("ollama_verify_ssl", False),
            # Kibana Cases integration
            kibana_cases_enabled=data.get("kibana_cases_enabled", True),
            kibana_url=data.get("kibana_url", ""),
            kibana_username=data.get("kibana_username", ""),
            kibana_password=data.get("kibana_password", ""),
            kibana_space_id=data.get("kibana_space_id", "production"),
            kibana_case_owner=data.get("kibana_case_owner", "securitySolution"),
            kibana_verify_ssl=data.get("kibana_verify_ssl", False),
            # DFIR-IRIS integration
            dfir_iris_enabled=data.get("dfir_iris_enabled", False),
            dfir_iris_url=data.get("dfir_iris_url", ""),
            dfir_iris_api_key=data.get("dfir_iris_api_key", ""),
            dfir_iris_verify_ssl=data.get("dfir_iris_verify_ssl", False),
            dfir_iris_default_customer=data.get("dfir_iris_default_customer", 1),
            # VirusTotal integration
            virustotal_enabled=data.get("virustotal_enabled", False),
            virustotal_api_key=data.get("virustotal_api_key", ""),
            virustotal_url=data.get("virustotal_url", "https://www.virustotal.com"),
            virustotal_verify_ssl=data.get("virustotal_verify_ssl", True),
            virustotal_timeout=data.get("virustotal_timeout", 30),
            virustotal_rate_limit=data.get("virustotal_rate_limit", 4),
            # Shodan integration
            shodan_enabled=data.get("shodan_enabled", False),
            shodan_api_key=data.get("shodan_api_key", ""),
            shodan_url=data.get("shodan_url", "https://api.shodan.io"),
            shodan_verify_ssl=data.get("shodan_verify_ssl", True),
            shodan_timeout=data.get("shodan_timeout", 30),
            # AbuseIPDB integration
            abuseipdb_enabled=data.get("abuseipdb_enabled", False),
            abuseipdb_api_key=data.get("abuseipdb_api_key", ""),
            # TIDE integration
            tide_enabled=data.get("tide_enabled", False),
            tide_url=data.get("tide_url", ""),
            tide_api_key=data.get("tide_api_key", ""),
            tide_verify_ssl=data.get("tide_verify_ssl", False),
            tide_space=data.get("tide_space", "default"),
            tide_client_id=data.get("tide_client_id", ""),
            # Generic scheduler
            scheduler_enabled=data.get("scheduler_enabled", True),
            scheduler_interval_s=data.get("scheduler_interval_s", 30),
            # Case grouper
            case_grouper_enabled=data.get("case_grouper_enabled", True),
            case_grouper_interval_s=data.get("case_grouper_interval_s", 60),
            case_grouper_window_minutes=data.get("case_grouper_window_minutes", 15),
            case_grouper_push_to_kibana=data.get("case_grouper_push_to_kibana", True),
            case_grouper_auto_investigate=data.get("case_grouper_auto_investigate", True),
            case_grouper_stagger_s=data.get("case_grouper_stagger_s", 3.0),
            case_grouper_min_cluster_size=data.get("case_grouper_min_cluster_size", 1),
            case_grouper_max_alerts_per_case=data.get("case_grouper_max_alerts_per_case", 20),
            case_grouper_investigate_per_case=data.get("case_grouper_investigate_per_case", True),
            # PII anonymising proxy
            pii_anon_enabled=data.get("pii_anon_enabled", False),
            pii_fields_file=data.get("pii_fields_file", ""),
            # Investigation loop
            investigation_loop_enabled=data.get("investigation_loop_enabled", True),
            investigation_sweep_interval_s=data.get("investigation_sweep_interval_s", 900),
            investigation_max_per_sweep=data.get("investigation_max_per_sweep", 50),
            investigation_llm_timeout_s=data.get("investigation_llm_timeout_s", 120),
            # Active response executors
            exec_dry_run=data.get("exec_dry_run", True),
            exec_default_timeout_s=data.get("exec_default_timeout_s", 20),
            exec_firewall_url=data.get("exec_firewall_url", ""),
            exec_firewall_api_key=data.get("exec_firewall_api_key", ""),
            exec_firewall_verify_ssl=data.get("exec_firewall_verify_ssl", True),
            exec_dns_sinkhole_url=data.get("exec_dns_sinkhole_url", ""),
            exec_dns_sinkhole_api_key=data.get("exec_dns_sinkhole_api_key", ""),
            exec_dns_sinkhole_verify_ssl=data.get("exec_dns_sinkhole_verify_ssl", True),
            exec_edr_url=data.get("exec_edr_url", ""),
            exec_edr_api_key=data.get("exec_edr_api_key", ""),
            exec_edr_verify_ssl=data.get("exec_edr_verify_ssl", True),
            exec_email_gateway_url=data.get("exec_email_gateway_url", ""),
            exec_email_gateway_api_key=data.get("exec_email_gateway_api_key", ""),
            exec_email_gateway_verify_ssl=data.get("exec_email_gateway_verify_ssl", True),
            exec_ad_ldap_uri=data.get("exec_ad_ldap_uri", ""),
            exec_ad_bind_dn=data.get("exec_ad_bind_dn", ""),
            exec_ad_bind_password=data.get("exec_ad_bind_password", ""),
            exec_ad_user_search_base=data.get("exec_ad_user_search_base", ""),
            exec_ad_verify_ssl=data.get("exec_ad_verify_ssl", True),
            exec_generic_webhook_api_key=data.get("exec_generic_webhook_api_key", ""),
            # SMTP integration
            smtp_enabled=data.get("smtp_enabled", False),
            smtp_host=data.get("smtp_host", ""),
            smtp_port=data.get("smtp_port", 587),
            smtp_username=data.get("smtp_username", ""),
            smtp_password=data.get("smtp_password", ""),
            smtp_from_address=data.get("smtp_from_address", ""),
            smtp_from_name=data.get("smtp_from_name", "ION"),
            smtp_use_tls=data.get("smtp_use_tls", False),
            smtp_use_starttls=data.get("smtp_use_starttls", True),
            smtp_timeout=data.get("smtp_timeout", 30),
            smtp_verify_ssl=data.get("smtp_verify_ssl", True),
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
                    # Base URL
                    "base_url": self.base_url,
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
                    # TLS
                    "ssl_cert": self.ssl_cert,
                    "ssl_key": self.ssl_key,
                    # Security settings
                    "cookie_secure": self.cookie_secure,
                    "debug_mode": self.debug_mode,
                    "account_lockout_enabled": self.account_lockout_enabled,
                    # GitLab integration
                    "gitlab_enabled": self.gitlab_enabled,
                    "gitlab_url": self.gitlab_url,
                    "gitlab_token": self.gitlab_token,
                    "gitlab_project_id": self.gitlab_project_id,
                    "gitlab_verify_ssl": self.gitlab_verify_ssl,
                    "gitlab_sudo_enabled": self.gitlab_sudo_enabled,
                    # OpenCTI integration
                    "opencti_enabled": self.opencti_enabled,
                    "opencti_url": self.opencti_url,
                    "opencti_token": self.opencti_token,
                    "opencti_verify_ssl": self.opencti_verify_ssl,
                    "arkime_enabled": self.arkime_enabled,
                    "arkime_url": self.arkime_url,
                    "arkime_keycloak_issuer": self.arkime_keycloak_issuer,
                    "arkime_keycloak_client_id": self.arkime_keycloak_client_id,
                    "arkime_keycloak_client_secret": self.arkime_keycloak_client_secret,
                    "arkime_keycloak_scope": self.arkime_keycloak_scope,
                    "arkime_username": self.arkime_username,
                    "arkime_password": self.arkime_password,
                    "arkime_api_key": self.arkime_api_key,
                    "arkime_verify_ssl": self.arkime_verify_ssl,
                    # Elasticsearch integration
                    "elasticsearch_enabled": self.elasticsearch_enabled,
                    "elasticsearch_url": self.elasticsearch_url,
                    "elasticsearch_api_key": self.elasticsearch_api_key,
                    "elasticsearch_username": self.elasticsearch_username,
                    "elasticsearch_password": self.elasticsearch_password,
                    "elasticsearch_alert_index": self.elasticsearch_alert_index,
                    "elasticsearch_case_index": self.elasticsearch_case_index,
                    "elasticsearch_verify_ssl": self.elasticsearch_verify_ssl,
                    "elasticsearch_user_index": self.elasticsearch_user_index,
                    "elasticsearch_user_field": self.elasticsearch_user_field,
                    "elasticsearch_assignment_field": self.elasticsearch_assignment_field,
                    # Ollama AI integration
                    "ollama_enabled": self.ollama_enabled,
                    "ollama_url": self.ollama_url,
                    "ollama_model": self.ollama_model,
                    "ollama_timeout": self.ollama_timeout,
                    "ollama_verify_ssl": self.ollama_verify_ssl,
                    # Kibana Cases integration
                    "kibana_cases_enabled": self.kibana_cases_enabled,
                    "kibana_url": self.kibana_url,
                    "kibana_username": self.kibana_username,
                    "kibana_password": self.kibana_password,
                    "kibana_space_id": self.kibana_space_id,
                    "kibana_case_owner": self.kibana_case_owner,
                    "kibana_verify_ssl": self.kibana_verify_ssl,
                    # DFIR-IRIS integration
                    "dfir_iris_enabled": self.dfir_iris_enabled,
                    "dfir_iris_url": self.dfir_iris_url,
                    "dfir_iris_api_key": self.dfir_iris_api_key,
                    "dfir_iris_verify_ssl": self.dfir_iris_verify_ssl,
                    "dfir_iris_default_customer": self.dfir_iris_default_customer,
                    # VirusTotal integration
                    "virustotal_enabled": self.virustotal_enabled,
                    "virustotal_api_key": self.virustotal_api_key,
                    "virustotal_url": self.virustotal_url,
                    "virustotal_verify_ssl": self.virustotal_verify_ssl,
                    "virustotal_timeout": self.virustotal_timeout,
                    "virustotal_rate_limit": self.virustotal_rate_limit,
                    # Shodan integration
                    "shodan_enabled": self.shodan_enabled,
                    "shodan_api_key": self.shodan_api_key,
                    "shodan_url": self.shodan_url,
                    "shodan_verify_ssl": self.shodan_verify_ssl,
                    "shodan_timeout": self.shodan_timeout,
                    # AbuseIPDB integration
                    "abuseipdb_enabled": self.abuseipdb_enabled,
                    "abuseipdb_api_key": self.abuseipdb_api_key,
                    # TIDE integration
                    "tide_enabled": self.tide_enabled,
                    "tide_url": self.tide_url,
                    "tide_api_key": self.tide_api_key,
                    "tide_verify_ssl": self.tide_verify_ssl,
                    "tide_space": self.tide_space,
                    "tide_client_id": self.tide_client_id,
                    # Generic scheduler
                    "scheduler_enabled": self.scheduler_enabled,
                    "scheduler_interval_s": self.scheduler_interval_s,
                    # Case grouper
                    "case_grouper_enabled": self.case_grouper_enabled,
                    "case_grouper_interval_s": self.case_grouper_interval_s,
                    "case_grouper_window_minutes": self.case_grouper_window_minutes,
                    "case_grouper_push_to_kibana": self.case_grouper_push_to_kibana,
                    "case_grouper_auto_investigate": self.case_grouper_auto_investigate,
                    "case_grouper_stagger_s": self.case_grouper_stagger_s,
                    "case_grouper_min_cluster_size": self.case_grouper_min_cluster_size,
                    "case_grouper_max_alerts_per_case": self.case_grouper_max_alerts_per_case,
                    "case_grouper_investigate_per_case": self.case_grouper_investigate_per_case,
                    # PII anonymising proxy
                    "pii_anon_enabled": self.pii_anon_enabled,
                    "pii_fields_file": self.pii_fields_file,
                    # Investigation loop
                    "investigation_loop_enabled": self.investigation_loop_enabled,
                    "investigation_sweep_interval_s": self.investigation_sweep_interval_s,
                    "investigation_max_per_sweep": self.investigation_max_per_sweep,
                    "investigation_llm_timeout_s": self.investigation_llm_timeout_s,
                    # Active response executors
                    "exec_dry_run": self.exec_dry_run,
                    "exec_default_timeout_s": self.exec_default_timeout_s,
                    "exec_firewall_url": self.exec_firewall_url,
                    "exec_firewall_api_key": self.exec_firewall_api_key,
                    "exec_firewall_verify_ssl": self.exec_firewall_verify_ssl,
                    "exec_dns_sinkhole_url": self.exec_dns_sinkhole_url,
                    "exec_dns_sinkhole_api_key": self.exec_dns_sinkhole_api_key,
                    "exec_dns_sinkhole_verify_ssl": self.exec_dns_sinkhole_verify_ssl,
                    "exec_edr_url": self.exec_edr_url,
                    "exec_edr_api_key": self.exec_edr_api_key,
                    "exec_edr_verify_ssl": self.exec_edr_verify_ssl,
                    "exec_email_gateway_url": self.exec_email_gateway_url,
                    "exec_email_gateway_api_key": self.exec_email_gateway_api_key,
                    "exec_email_gateway_verify_ssl": self.exec_email_gateway_verify_ssl,
                    "exec_ad_ldap_uri": self.exec_ad_ldap_uri,
                    "exec_ad_bind_dn": self.exec_ad_bind_dn,
                    "exec_ad_bind_password": self.exec_ad_bind_password,
                    "exec_ad_user_search_base": self.exec_ad_user_search_base,
                    "exec_ad_verify_ssl": self.exec_ad_verify_ssl,
                    "exec_generic_webhook_api_key": self.exec_generic_webhook_api_key,
                    # SMTP integration
                    "smtp_enabled": self.smtp_enabled,
                    "smtp_host": self.smtp_host,
                    "smtp_port": self.smtp_port,
                    "smtp_username": self.smtp_username,
                    "smtp_password": self.smtp_password,
                    "smtp_from_address": self.smtp_from_address,
                    "smtp_from_name": self.smtp_from_name,
                    "smtp_use_tls": self.smtp_use_tls,
                    "smtp_use_starttls": self.smtp_use_starttls,
                    "smtp_timeout": self.smtp_timeout,
                    "smtp_verify_ssl": self.smtp_verify_ssl,
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
            # Use data_dir for db_path when set (Docker), otherwise CWD
            if data_dir:
                _config = Config(db_path=Path(data_dir) / ".ion" / "ion.db")
            else:
                _config = Config()

        # Override with environment variables
        _env_base_url = os.environ.get("ION_BASE_URL", "").strip()
        if _env_base_url:
            _config.base_url = _env_base_url.rstrip("/")
        if os.environ.get("ION_CA_BUNDLE"):
            _config.ca_bundle = os.environ.get("ION_CA_BUNDLE", "")
        if os.environ.get("ION_SSL_CERT"):
            _config.ssl_cert = os.environ.get("ION_SSL_CERT", "")
        if os.environ.get("ION_SSL_KEY"):
            _config.ssl_key = os.environ.get("ION_SSL_KEY", "")
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
            _config.oidc_verify_ssl = _get_env_bool("ION_OIDC_VERIFY_SSL", False)

        # GitLab environment variable overrides
        if os.environ.get("ION_GITLAB_ENABLED"):
            _config.gitlab_enabled = _get_env_bool("ION_GITLAB_ENABLED", True)
        if os.environ.get("ION_GITLAB_URL"):
            _config.gitlab_url = os.environ.get("ION_GITLAB_URL", "")
        if os.environ.get("ION_GITLAB_TOKEN"):
            _config.gitlab_token = os.environ.get("ION_GITLAB_TOKEN", "")
        if os.environ.get("ION_GITLAB_PROJECT_ID"):
            _config.gitlab_project_id = os.environ.get("ION_GITLAB_PROJECT_ID", "")
        if os.environ.get("ION_GITLAB_VERIFY_SSL"):
            _config.gitlab_verify_ssl = _get_env_bool("ION_GITLAB_VERIFY_SSL", False)
        if os.environ.get("ION_GITLAB_SUDO"):
            _config.gitlab_sudo_enabled = _get_env_bool("ION_GITLAB_SUDO", False)

        # OpenCTI environment variable overrides
        if os.environ.get("ION_OPENCTI_ENABLED"):
            _config.opencti_enabled = _get_env_bool("ION_OPENCTI_ENABLED", True)
        if os.environ.get("ION_OPENCTI_URL"):
            _config.opencti_url = os.environ.get("ION_OPENCTI_URL", "")
        if os.environ.get("ION_OPENCTI_TOKEN"):
            _config.opencti_token = os.environ.get("ION_OPENCTI_TOKEN", "")
        if os.environ.get("ION_OPENCTI_VERIFY_SSL"):
            _config.opencti_verify_ssl = _get_env_bool("ION_OPENCTI_VERIFY_SSL", False)

        # Arkime environment variable overrides
        if os.environ.get("ION_ARKIME_ENABLED"):
            _config.arkime_enabled = _get_env_bool("ION_ARKIME_ENABLED", False)
        if os.environ.get("ION_ARKIME_URL"):
            _config.arkime_url = os.environ.get("ION_ARKIME_URL", "").rstrip("/")
        if os.environ.get("ION_ARKIME_KEYCLOAK_ISSUER"):
            _config.arkime_keycloak_issuer = os.environ.get(
                "ION_ARKIME_KEYCLOAK_ISSUER", ""
            ).rstrip("/")
        if os.environ.get("ION_ARKIME_KEYCLOAK_CLIENT_ID"):
            _config.arkime_keycloak_client_id = os.environ.get(
                "ION_ARKIME_KEYCLOAK_CLIENT_ID", ""
            )
        if os.environ.get("ION_ARKIME_KEYCLOAK_CLIENT_SECRET"):
            _config.arkime_keycloak_client_secret = os.environ.get(
                "ION_ARKIME_KEYCLOAK_CLIENT_SECRET", ""
            )
        if os.environ.get("ION_ARKIME_KEYCLOAK_SCOPE"):
            _config.arkime_keycloak_scope = os.environ.get(
                "ION_ARKIME_KEYCLOAK_SCOPE", "openid"
            )
        if os.environ.get("ION_ARKIME_USERNAME"):
            _config.arkime_username = os.environ.get("ION_ARKIME_USERNAME", "")
        if os.environ.get("ION_ARKIME_PASSWORD"):
            _config.arkime_password = os.environ.get("ION_ARKIME_PASSWORD", "")
        if os.environ.get("ION_ARKIME_API_KEY"):
            _config.arkime_api_key = os.environ.get("ION_ARKIME_API_KEY", "")
        if os.environ.get("ION_ARKIME_VERIFY_SSL"):
            _config.arkime_verify_ssl = _get_env_bool("ION_ARKIME_VERIFY_SSL", False)

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
            _config.elasticsearch_verify_ssl = _get_env_bool("ION_ELASTICSEARCH_VERIFY_SSL", False)

        # Ollama environment overrides
        if os.environ.get("ION_OLLAMA_ENABLED"):
            _config.ollama_enabled = _get_env_bool("ION_OLLAMA_ENABLED", True)
        if os.environ.get("ION_OLLAMA_URL") or os.environ.get("OLLAMA_URL"):
            _config.ollama_url = os.environ.get("ION_OLLAMA_URL") or os.environ.get("OLLAMA_URL", "http://localhost:11434")
        if os.environ.get("ION_OLLAMA_MODEL"):
            _config.ollama_model = os.environ.get("ION_OLLAMA_MODEL", "llama3.1:8b")
        if os.environ.get("ION_OLLAMA_TIMEOUT"):
            _config.ollama_timeout = int(os.environ.get("ION_OLLAMA_TIMEOUT", "300"))
        if os.environ.get("ION_OLLAMA_VERIFY_SSL"):
            _config.ollama_verify_ssl = _get_env_bool("ION_OLLAMA_VERIFY_SSL", False)

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
            _config.kibana_space_id = os.environ.get("ION_KIBANA_SPACE_ID", "production")
        if os.environ.get("ION_KIBANA_CASE_OWNER"):
            _config.kibana_case_owner = os.environ.get("ION_KIBANA_CASE_OWNER", "securitySolution")
        if os.environ.get("ION_KIBANA_VERIFY_SSL"):
            _config.kibana_verify_ssl = _get_env_bool("ION_KIBANA_VERIFY_SSL", False)

        # DFIR-IRIS environment overrides
        if os.environ.get("ION_DFIR_IRIS_ENABLED"):
            _config.dfir_iris_enabled = _get_env_bool("ION_DFIR_IRIS_ENABLED")
        if os.environ.get("ION_DFIR_IRIS_URL"):
            _config.dfir_iris_url = os.environ.get("ION_DFIR_IRIS_URL", "")
        if os.environ.get("ION_DFIR_IRIS_API_KEY"):
            _config.dfir_iris_api_key = os.environ.get("ION_DFIR_IRIS_API_KEY", "")
        if os.environ.get("ION_DFIR_IRIS_VERIFY_SSL"):
            _config.dfir_iris_verify_ssl = _get_env_bool("ION_DFIR_IRIS_VERIFY_SSL", False)
        if os.environ.get("ION_DFIR_IRIS_DEFAULT_CUSTOMER"):
            _config.dfir_iris_default_customer = int(os.environ.get("ION_DFIR_IRIS_DEFAULT_CUSTOMER", "1"))

        # VirusTotal environment overrides
        if os.environ.get("ION_VIRUSTOTAL_ENABLED"):
            _config.virustotal_enabled = _get_env_bool("ION_VIRUSTOTAL_ENABLED")
        if os.environ.get("ION_VIRUSTOTAL_API_KEY"):
            _config.virustotal_api_key = os.environ.get("ION_VIRUSTOTAL_API_KEY", "")
        if os.environ.get("ION_VIRUSTOTAL_URL"):
            _config.virustotal_url = os.environ.get("ION_VIRUSTOTAL_URL", "")
        if os.environ.get("ION_VIRUSTOTAL_VERIFY_SSL"):
            _config.virustotal_verify_ssl = _get_env_bool("ION_VIRUSTOTAL_VERIFY_SSL", True)
        if os.environ.get("ION_VIRUSTOTAL_TIMEOUT"):
            _config.virustotal_timeout = int(os.environ.get("ION_VIRUSTOTAL_TIMEOUT", "30"))
        if os.environ.get("ION_VIRUSTOTAL_RATE_LIMIT"):
            _config.virustotal_rate_limit = int(os.environ.get("ION_VIRUSTOTAL_RATE_LIMIT", "4"))

        # Shodan environment overrides
        if os.environ.get("ION_SHODAN_ENABLED"):
            _config.shodan_enabled = _get_env_bool("ION_SHODAN_ENABLED", False)
        if os.environ.get("ION_SHODAN_API_KEY"):
            _config.shodan_api_key = os.environ.get("ION_SHODAN_API_KEY", "")
        if os.environ.get("ION_SHODAN_URL"):
            _config.shodan_url = os.environ.get("ION_SHODAN_URL", "")
        if os.environ.get("ION_SHODAN_VERIFY_SSL"):
            _config.shodan_verify_ssl = _get_env_bool("ION_SHODAN_VERIFY_SSL", True)
        if os.environ.get("ION_SHODAN_TIMEOUT"):
            _config.shodan_timeout = int(os.environ.get("ION_SHODAN_TIMEOUT", "30"))

        # AbuseIPDB environment overrides
        if os.environ.get("ION_ABUSEIPDB_ENABLED"):
            _config.abuseipdb_enabled = _get_env_bool("ION_ABUSEIPDB_ENABLED")
        if os.environ.get("ION_ABUSEIPDB_API_KEY"):
            _config.abuseipdb_api_key = os.environ.get("ION_ABUSEIPDB_API_KEY", "")

        # TIDE environment overrides
        if os.environ.get("ION_TIDE_ENABLED"):
            _config.tide_enabled = _get_env_bool("ION_TIDE_ENABLED")
        if os.environ.get("ION_TIDE_URL"):
            _config.tide_url = os.environ.get("ION_TIDE_URL", "")
        if os.environ.get("ION_TIDE_API_KEY"):
            _config.tide_api_key = os.environ.get("ION_TIDE_API_KEY", "")
        if os.environ.get("ION_TIDE_VERIFY_SSL"):
            _config.tide_verify_ssl = _get_env_bool("ION_TIDE_VERIFY_SSL", False)
        if os.environ.get("ION_TIDE_SPACE"):
            _config.tide_space = os.environ.get("ION_TIDE_SPACE", "default")
        if os.environ.get("ION_TIDE_CLIENT_ID"):
            _config.tide_client_id = os.environ.get("ION_TIDE_CLIENT_ID", "")

        # Generic scheduler env overrides
        if os.environ.get("ION_SCHEDULER_ENABLED"):
            _config.scheduler_enabled = _get_env_bool("ION_SCHEDULER_ENABLED", True)
        if os.environ.get("ION_SCHEDULER_INTERVAL_S"):
            try:
                _config.scheduler_interval_s = int(os.environ.get("ION_SCHEDULER_INTERVAL_S", "30"))
            except ValueError:
                pass

        # Case grouper env overrides
        if os.environ.get("ION_CASE_GROUPER_ENABLED"):
            _config.case_grouper_enabled = _get_env_bool("ION_CASE_GROUPER_ENABLED", True)
        if os.environ.get("ION_CASE_GROUPER_INTERVAL_S"):
            try:
                _config.case_grouper_interval_s = int(os.environ.get("ION_CASE_GROUPER_INTERVAL_S", "60"))
            except ValueError:
                pass
        if os.environ.get("ION_CASE_GROUPER_WINDOW_MINUTES"):
            try:
                _config.case_grouper_window_minutes = int(os.environ.get("ION_CASE_GROUPER_WINDOW_MINUTES", "15"))
            except ValueError:
                pass
        if os.environ.get("ION_CASE_GROUPER_PUSH_TO_KIBANA"):
            _config.case_grouper_push_to_kibana = _get_env_bool("ION_CASE_GROUPER_PUSH_TO_KIBANA", True)
        if os.environ.get("ION_CASE_GROUPER_AUTO_INVESTIGATE"):
            _config.case_grouper_auto_investigate = _get_env_bool("ION_CASE_GROUPER_AUTO_INVESTIGATE", True)
        if os.environ.get("ION_CASE_GROUPER_STAGGER_S"):
            try:
                _config.case_grouper_stagger_s = float(os.environ.get("ION_CASE_GROUPER_STAGGER_S", "3.0"))
            except ValueError:
                pass
        if os.environ.get("ION_CASE_GROUPER_MIN_CLUSTER_SIZE"):
            try:
                _config.case_grouper_min_cluster_size = int(os.environ.get("ION_CASE_GROUPER_MIN_CLUSTER_SIZE", "1"))
            except ValueError:
                pass
        if os.environ.get("ION_CASE_GROUPER_MAX_ALERTS_PER_CASE"):
            try:
                _config.case_grouper_max_alerts_per_case = int(os.environ.get("ION_CASE_GROUPER_MAX_ALERTS_PER_CASE", "20"))
            except ValueError:
                pass
        if os.environ.get("ION_CASE_GROUPER_INVESTIGATE_PER_CASE"):
            _config.case_grouper_investigate_per_case = _get_env_bool("ION_CASE_GROUPER_INVESTIGATE_PER_CASE", True)

        # PII anonymising proxy env overrides
        if os.environ.get("ION_PII_ANON_ENABLED"):
            _config.pii_anon_enabled = _get_env_bool("ION_PII_ANON_ENABLED", False)
        if os.environ.get("ION_PII_FIELDS_FILE"):
            _config.pii_fields_file = os.environ.get("ION_PII_FIELDS_FILE", "")

        # Investigation loop env overrides
        if os.environ.get("ION_INVESTIGATION_LOOP_ENABLED"):
            _config.investigation_loop_enabled = _get_env_bool("ION_INVESTIGATION_LOOP_ENABLED", True)
        if os.environ.get("ION_INVESTIGATION_SWEEP_INTERVAL_S"):
            _config.investigation_sweep_interval_s = int(os.environ.get("ION_INVESTIGATION_SWEEP_INTERVAL_S", "900"))
        if os.environ.get("ION_INVESTIGATION_MAX_PER_SWEEP"):
            _config.investigation_max_per_sweep = int(os.environ.get("ION_INVESTIGATION_MAX_PER_SWEEP", "50"))
        if os.environ.get("ION_INVESTIGATION_LLM_TIMEOUT_S"):
            _config.investigation_llm_timeout_s = int(os.environ.get("ION_INVESTIGATION_LLM_TIMEOUT_S", "120"))

        # Active response executor overrides
        if os.environ.get("ION_EXEC_DRY_RUN"):
            _config.exec_dry_run = _get_env_bool("ION_EXEC_DRY_RUN", True)
        if os.environ.get("ION_EXEC_DEFAULT_TIMEOUT_S"):
            try:
                _config.exec_default_timeout_s = int(os.environ["ION_EXEC_DEFAULT_TIMEOUT_S"])
            except ValueError:
                pass
        if os.environ.get("ION_EXEC_FIREWALL_URL"):
            _config.exec_firewall_url = os.environ.get("ION_EXEC_FIREWALL_URL", "")
        if os.environ.get("ION_EXEC_FIREWALL_API_KEY"):
            _config.exec_firewall_api_key = os.environ.get("ION_EXEC_FIREWALL_API_KEY", "")
        if os.environ.get("ION_EXEC_FIREWALL_VERIFY_SSL"):
            _config.exec_firewall_verify_ssl = _get_env_bool("ION_EXEC_FIREWALL_VERIFY_SSL", True)
        if os.environ.get("ION_EXEC_DNS_SINKHOLE_URL"):
            _config.exec_dns_sinkhole_url = os.environ.get("ION_EXEC_DNS_SINKHOLE_URL", "")
        if os.environ.get("ION_EXEC_DNS_SINKHOLE_API_KEY"):
            _config.exec_dns_sinkhole_api_key = os.environ.get("ION_EXEC_DNS_SINKHOLE_API_KEY", "")
        if os.environ.get("ION_EXEC_DNS_SINKHOLE_VERIFY_SSL"):
            _config.exec_dns_sinkhole_verify_ssl = _get_env_bool("ION_EXEC_DNS_SINKHOLE_VERIFY_SSL", True)
        if os.environ.get("ION_EXEC_EDR_URL"):
            _config.exec_edr_url = os.environ.get("ION_EXEC_EDR_URL", "")
        if os.environ.get("ION_EXEC_EDR_API_KEY"):
            _config.exec_edr_api_key = os.environ.get("ION_EXEC_EDR_API_KEY", "")
        if os.environ.get("ION_EXEC_EDR_VERIFY_SSL"):
            _config.exec_edr_verify_ssl = _get_env_bool("ION_EXEC_EDR_VERIFY_SSL", True)
        if os.environ.get("ION_EXEC_EMAIL_GATEWAY_URL"):
            _config.exec_email_gateway_url = os.environ.get("ION_EXEC_EMAIL_GATEWAY_URL", "")
        if os.environ.get("ION_EXEC_EMAIL_GATEWAY_API_KEY"):
            _config.exec_email_gateway_api_key = os.environ.get("ION_EXEC_EMAIL_GATEWAY_API_KEY", "")
        if os.environ.get("ION_EXEC_EMAIL_GATEWAY_VERIFY_SSL"):
            _config.exec_email_gateway_verify_ssl = _get_env_bool("ION_EXEC_EMAIL_GATEWAY_VERIFY_SSL", True)
        if os.environ.get("ION_EXEC_AD_LDAP_URI"):
            _config.exec_ad_ldap_uri = os.environ.get("ION_EXEC_AD_LDAP_URI", "")
        if os.environ.get("ION_EXEC_AD_BIND_DN"):
            _config.exec_ad_bind_dn = os.environ.get("ION_EXEC_AD_BIND_DN", "")
        if os.environ.get("ION_EXEC_AD_BIND_PASSWORD"):
            _config.exec_ad_bind_password = os.environ.get("ION_EXEC_AD_BIND_PASSWORD", "")
        if os.environ.get("ION_EXEC_AD_USER_SEARCH_BASE"):
            _config.exec_ad_user_search_base = os.environ.get("ION_EXEC_AD_USER_SEARCH_BASE", "")
        if os.environ.get("ION_EXEC_AD_VERIFY_SSL"):
            _config.exec_ad_verify_ssl = _get_env_bool("ION_EXEC_AD_VERIFY_SSL", True)
        if os.environ.get("ION_EXEC_GENERIC_WEBHOOK_API_KEY"):
            _config.exec_generic_webhook_api_key = os.environ.get("ION_EXEC_GENERIC_WEBHOOK_API_KEY", "")

        # SMTP environment overrides
        if os.environ.get("ION_SMTP_ENABLED"):
            _config.smtp_enabled = _get_env_bool("ION_SMTP_ENABLED", False)
        if os.environ.get("ION_SMTP_HOST"):
            _config.smtp_host = os.environ.get("ION_SMTP_HOST", "")
        if os.environ.get("ION_SMTP_PORT"):
            _config.smtp_port = int(os.environ.get("ION_SMTP_PORT", "587"))
        if os.environ.get("ION_SMTP_USERNAME"):
            _config.smtp_username = os.environ.get("ION_SMTP_USERNAME", "")
        if os.environ.get("ION_SMTP_PASSWORD"):
            _config.smtp_password = os.environ.get("ION_SMTP_PASSWORD", "")
        if os.environ.get("ION_SMTP_FROM_ADDRESS"):
            _config.smtp_from_address = os.environ.get("ION_SMTP_FROM_ADDRESS", "")
        if os.environ.get("ION_SMTP_FROM_NAME"):
            _config.smtp_from_name = os.environ.get("ION_SMTP_FROM_NAME", "ION")
        if os.environ.get("ION_SMTP_USE_TLS"):
            _config.smtp_use_tls = _get_env_bool("ION_SMTP_USE_TLS", False)
        if os.environ.get("ION_SMTP_USE_STARTTLS"):
            _config.smtp_use_starttls = _get_env_bool("ION_SMTP_USE_STARTTLS", True)
        if os.environ.get("ION_SMTP_TIMEOUT"):
            _config.smtp_timeout = int(os.environ.get("ION_SMTP_TIMEOUT", "30"))
        if os.environ.get("ION_SMTP_VERIFY_SSL"):
            _config.smtp_verify_ssl = _get_env_bool("ION_SMTP_VERIFY_SSL", True)

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
        "verify_ssl": config.gitlab_verify_ssl,
        "sudo_enabled": config.gitlab_sudo_enabled,
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


def get_arkime_config() -> dict:
    """Get Arkime configuration from the global config.

    Returns a dictionary with Arkime viewer connection details. Includes
    both Keycloak OAuth2 client_credentials settings (preferred) and
    HTTP basic / API-key fallbacks for dev environments.
    """
    config = get_config()
    return {
        "enabled": config.arkime_enabled,
        "url": config.arkime_url,
        "keycloak_issuer": config.arkime_keycloak_issuer,
        "keycloak_client_id": config.arkime_keycloak_client_id,
        "keycloak_client_secret": config.arkime_keycloak_client_secret,
        "keycloak_scope": config.arkime_keycloak_scope,
        "username": config.arkime_username,
        "password": config.arkime_password,
        "api_key": config.arkime_api_key,
        "verify_ssl": config.arkime_verify_ssl,
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
        "user_index": config.elasticsearch_user_index,
        "user_field": config.elasticsearch_user_field,
        "assignment_field": config.elasticsearch_assignment_field,
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
        "verify_ssl": config.kibana_verify_ssl,
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


def get_tide_config() -> dict:
    """Get TIDE configuration from the global config."""
    config = get_config()
    return {
        "enabled": config.tide_enabled,
        "url": config.tide_url,
        "api_key": config.tide_api_key,
        "verify_ssl": config.tide_verify_ssl,
        "space": config.tide_space,
        "client_id": config.tide_client_id,
    }
