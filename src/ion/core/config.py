"""Configuration management for ION."""

import json
import logging
import os
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Dict, Optional

logger = logging.getLogger(__name__)

# Warn-once guard so the OIDC TLS-verification-disabled banner is logged a
# single time at first use rather than on every get_oidc_config() call.
_oidc_tls_warned = False


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
    # Development deployment. Relaxes cookie_secure so the app works over
    # plain HTTP, and downgrades the weak-admin-password startup error to a
    # warning. NEVER set in production.
    dev_mode: bool = False
    cookie_secure: bool = True  # Secure flag on session cookies. dev_mode drops it unless ION_COOKIE_SECURE says otherwise
    debug_mode: bool = False  # Enable API docs and detailed errors (disable in production)
    account_lockout_enabled: bool = False  # Lock accounts after repeated failed logins
    ip_blocking_enabled: bool = False  # Auto-block IPs on attack detection (opt-in; needs ION_TRUSTED_PROXIES behind a proxy)
    webhook_require_signature: bool = True  # Reject inbound webhooks with no HMAC secret configured
    enforce_password_change: bool = True  # Block must_change_password users from APIs until they change it
    password_min_length: int = 0  # Minimum password length on set/change; 0 = policy disabled (opt-in)
    security_scan_authenticated: bool = False  # Run payload-pattern WAF checks on authenticated traffic too (default off — analysts legitimately handle malicious content)
    authz_alert_enabled: bool = True  # Record 401/403 and alert on repeated unauthorized-access attempts
    authz_alert_threshold: int = 5  # 401/403 responses from one actor within the window that escalate to a HIGH event
    response_actions_enabled: bool = False  # Expose the response-action surface (request/approve/execute); opt-in, off by default
    # Seed the six default incident-notification templates at startup.
    # OFF by default: startup seeding is the only way rows reach
    # comm_templates, and nothing should write to a production database
    # unless an operator asks for it. Idempotent when on.
    comm_templates_seed: bool = False
    response_actions_live: bool = False  # Dispatch to real firewall/EDR/AD adapters. Off = every execution is forced dry-run
    alert_detail_v2: bool = True  # Serve the redesigned alert-detail panel (decision-first header + tabbed body + source badges). Set false to fall back to the previous render
    alert_field_pins: bool = True  # Let analysts pin alert fields to the Case-context panel (per-user, per-rule). Inert unless alert_detail_v2 is on
    bob_custom_templates: bool = True  # Let Bob generate custom per-rule investigation templates (human-reviewed) alongside the authored guide
    multi_tenant: bool = False  # Serve several client estates from one instance (per-tenant Elasticsearch/Kibana). Off = one estate from the process-wide config, as before
    chat_grounding_check: bool = True  # After a chat answer streams, check its specifics against the retrieved context; advisory only, one extra LLM call per grounded answer
    csrf_enabled: bool = True  # Enforce CSRF token + Origin checks on cookie-authenticated state-changing requests. ON by default; escape hatch for debugging only
    csrf_extra_origins: str = ""  # Comma-separated additional origins accepted by the CSRF Origin check (deploys fronted by another hostname). Own Host and base_url always accepted
    authz_alert_window_minutes: int = 5  # Rolling window for the authz-failure threshold

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

    # Arkime integration (v5.x viewer API — fetch raw PCAPs by session id).
    # Auth is HTTP Basic ONLY — ArkimeService dropped Keycloak/Digest/API-key.
    arkime_enabled: bool = False
    arkime_url: str = ""  # e.g., https://viewer.guardedglass.internal
    arkime_username: str = ""
    arkime_password: str = ""
    arkime_verify_ssl: bool = False

    # Elasticsearch integration
    elasticsearch_enabled: bool = True
    elasticsearch_url: str = ""  # e.g., https://localhost:9200
    elasticsearch_api_key: str = ""  # API key (preferred over username/password)
    elasticsearch_username: str = ""  # Basic auth username
    elasticsearch_password: str = ""  # Basic auth password
    elasticsearch_alert_index: str = ".alerts-security.alerts-production"  # Alert index pattern
    elasticsearch_esql_enabled: bool = False  # Use ES|QL (/_query) for supported aggregations; opt-in, falls back to the DSL path on any error
    # Optional raw process-events index (Elastic Defend endpoint events) for the
    # full process explorer — resolves named ancestry + child processes by
    # entity-id. Empty = off; the explorer then uses the alert-local tree only.
    elasticsearch_process_events_index: str = ""
    elasticsearch_case_index: str = "ion-cases"  # Index for synced case documents
    elasticsearch_verify_ssl: bool = False
    # User mapping for alert assignment
    elasticsearch_user_index: str = "ion-users"  # ES index containing user profiles
    elasticsearch_user_field: str = "ion.user"  # Field in user index with display names
    elasticsearch_assignment_field: str = "kibana.alert.workflow_user"  # Field on alerts to write assignment

    # Ollama AI integration
    ollama_enabled: bool = True
    ollama_url: str = "http://localhost:11434"  # Ollama API URL
    ollama_model: str = "hf.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF"  # Default model (Bob) — security-tuned, Llama-3.1-8B based
    # Ollama context window (num_ctx) passed on every chat call. Ollama defaults
    # this to ~4096 unless set — far below Bob's ~12K prompt+generation budget,
    # so the prompt was being silently front-truncated. 16384 fits the budget
    # with headroom at modest KV-cache cost; raise toward 65536 on RAM-rich hosts
    # to exploit Foundation-Sec's 64K window. Env: ION_OLLAMA_NUM_CTX.
    ollama_num_ctx: int = 16384
    ollama_timeout: int = 300  # Request timeout in seconds (v0.17.3: bumped 120 → 300 for long investigation prompts)
    ollama_verify_ssl: bool = False

    # Kibana Cases integration
    kibana_cases_enabled: bool = True
    kibana_url: str = ""  # e.g., http://localhost:5601
    kibana_username: str = ""  # Kibana username (uses ES credentials if not set)
    kibana_password: str = ""  # Kibana password
    kibana_space_id: str = "production"  # Kibana space ID
    kibana_case_owner: str = "securitySolution"  # Case owner app (securitySolution, observability, cases)
    kibana_custom_fields_enabled: bool = False  # Provision + populate native Kibana case custom fields (ION case #, severity, rules, hosts); opt-in
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

    # Detection Engineering optional module (licensed). Enforcement ships
    # dormant: while de_license_enforced is False the module behaves as it did
    # before licensing (mounted, RBAC-gated, no licence). See ion.licensing.
    de_license_enforced: bool = False  # master switch — gate DE behind a licence
    # ION_WORKFORCE_ENABLED — onboarding/offboarding lifecycle. On by
    # default: "who is cleared to be on this console today, and what did we
    # take off them when they left" is a question every SOC has to answer,
    # and the module was shipping complete, migrated and inert behind a
    # 404 that looks the same as broken. Turning it on grants nobody
    # anything — a journey still has to be assigned and its requirements
    # verified before sync_granted_roles confers a role.
    workforce_enabled: bool = True
    # How long a granted ION role outlives a lapsed mandatory item. The journey
    # suspends at once and the lead is told; 0 revokes the permissions with it.
    workforce_lapse_grace_days: int = 7
    de_module_enabled: bool = False    # operator intent to run DE (needs a licence when enforced)
    de_license: str = ""               # ION_DE_LICENSE — inline signed token or path to a licence file

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
    # was 120; the v0.17.3 fix-pack bumped the module default
    # in investigation_service to 300 (real prompts on an 8B model take
    # 130-180s warm — longer cold/CPU) but missed this config-dataclass copy.
    # Resolution order
    # in _single_llm_call is env -> config -> module-default, so
    # config=120 was overriding the 300 default that v0.17.3 actually
    # shipped. Brought into line.
    investigation_llm_timeout_s: int = 300

    # --- Attack Path (Bob Pathfinding) ---
    # Master feature flag (Phase 4 package). Gates the whole Attack Path
    # surface: the /cases/{id}/attack-path endpoint, Bob's case-analysis
    # path-injection, and the Phase-3 recurrence link. The existing
    # ION_ATTACK_PATH_RECURRENCE_ENABLED / _THRESHOLD sub-flags continue to
    # work UNDER this switch. Default ON; disabling degrades to the prior
    # (pre-Attack-Path) behaviour — air-gap-safe. Env: ION_ATTACK_PATH_ENABLED.
    attack_path_enabled: bool = True

    # --- Bob confidence-gated escalation tier (Attack Path Phase 4) ---
    # "Try harder" deep pass before abstaining to a human: on a low-confidence
    # verdict for a high/critical alert, re-run once with more self-consistency
    # seeds (and optionally a larger PROD model) to raise confidence. Advisory
    # only — the human still decides. Default ON. Env: ION_BOB_ESCALATION_TIER_ENABLED.
    bob_escalation_tier_enabled: bool = True
    # Self-consistency seeds for the deep pass (more seeds = steadier confidence
    # at higher cost). Clamped 1..5. Env: ION_BOB_ESCALATION_SAMPLES.
    bob_escalation_samples: int = 3
    # Optional larger model for the deep pass on PROD's background queue. Empty =
    # reuse the same Foundation-Sec-8B model (air-gap-safe default, no config
    # needed). Env: ION_BOB_ESCALATION_MODEL.
    bob_escalation_model: str = ""

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
            dev_mode=data.get("dev_mode", False),
            cookie_secure=data.get("cookie_secure", True),
            debug_mode=data.get("debug_mode", False),
            account_lockout_enabled=data.get("account_lockout_enabled", False),
            ip_blocking_enabled=data.get("ip_blocking_enabled", False),
            webhook_require_signature=data.get("webhook_require_signature", True),
            enforce_password_change=data.get("enforce_password_change", True),
            password_min_length=data.get("password_min_length", 0),
            security_scan_authenticated=data.get("security_scan_authenticated", False),
            authz_alert_enabled=data.get("authz_alert_enabled", True),
            authz_alert_threshold=data.get("authz_alert_threshold", 5),
            response_actions_enabled=data.get("response_actions_enabled", False),
            comm_templates_seed=data.get("comm_templates_seed", False),
            response_actions_live=data.get("response_actions_live", False),
            alert_detail_v2=data.get("alert_detail_v2", True),
            alert_field_pins=data.get("alert_field_pins", True),
            bob_custom_templates=data.get("bob_custom_templates", True),
            multi_tenant=data.get("multi_tenant", False),
            chat_grounding_check=data.get("chat_grounding_check", True),
            csrf_enabled=data.get("csrf_enabled", True),
            csrf_extra_origins=data.get("csrf_extra_origins", ""),
            authz_alert_window_minutes=data.get("authz_alert_window_minutes", 5),
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
            arkime_username=data.get("arkime_username", ""),
            arkime_password=data.get("arkime_password", ""),
            arkime_verify_ssl=data.get("arkime_verify_ssl", False),
            # Elasticsearch integration
            elasticsearch_enabled=data.get("elasticsearch_enabled", True),
            elasticsearch_url=data.get("elasticsearch_url", ""),
            elasticsearch_api_key=data.get("elasticsearch_api_key", ""),
            elasticsearch_username=data.get("elasticsearch_username", ""),
            elasticsearch_password=data.get("elasticsearch_password", ""),
            elasticsearch_alert_index=data.get("elasticsearch_alert_index", ".alerts-security.alerts-production"),
            elasticsearch_esql_enabled=data.get("elasticsearch_esql_enabled", False),
            elasticsearch_case_index=data.get("elasticsearch_case_index", "ion-cases"),
            elasticsearch_verify_ssl=data.get("elasticsearch_verify_ssl", False),
            elasticsearch_user_index=data.get("elasticsearch_user_index", "ion-users"),
            elasticsearch_user_field=data.get("elasticsearch_user_field", "ion.user"),
            elasticsearch_assignment_field=data.get("elasticsearch_assignment_field", "kibana.alert.workflow_user"),
            # Ollama AI integration
            ollama_enabled=data.get("ollama_enabled", True),
            ollama_url=data.get("ollama_url", "http://localhost:11434"),
            ollama_model=data.get("ollama_model", "hf.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF"),
            # upgrade migration: silently bump the historical 120s
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
            kibana_custom_fields_enabled=data.get("kibana_custom_fields_enabled", False),
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
            de_license_enforced=data.get("de_license_enforced", False),
            workforce_enabled=data.get("workforce_enabled", True),
            de_module_enabled=data.get("de_module_enabled", False),
            de_license=data.get("de_license", ""),
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
            investigation_llm_timeout_s=data.get("investigation_llm_timeout_s", 300),
            # Attack Path + Bob escalation tier
            attack_path_enabled=data.get("attack_path_enabled", True),
            bob_escalation_tier_enabled=data.get("bob_escalation_tier_enabled", True),
            bob_escalation_samples=data.get("bob_escalation_samples", 3),
            bob_escalation_model=data.get("bob_escalation_model", ""),
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
        """Save configuration to a JSON file.

        Serialised from the dataclass rather than a hand-written dict. The
        hand-written one had fallen twenty fields behind: ``Config`` carried
        162, ``from_file`` read 162 back, and this wrote 141, so
        ``response_actions_enabled``, ``response_actions_live``,
        ``csrf_enabled``, ``multi_tenant``, ``ca_bundle``,
        ``workforce_enabled`` and fourteen others could be set in memory,
        reported as saved, and lost on the next start. That is the "a save
        that reports success and changes nothing" failure this file's
        _drop_env_held docstring says v0.99.7 exists to close, still live
        for those twenty. Deriving it means a field added to Config is
        persisted without anyone having to remember.

        Written 0600. Since v0.99.7 this file -- not `.env` -- is where the
        Elasticsearch, Kibana, Arkime, GitLab, OpenCTI, TIDE, SMTP, OIDC and
        response-action credentials live, in plaintext. It is created with
        the mode rather than chmod'd afterwards so the secrets never exist
        world-readable, not even briefly; the mode argument only applies on
        creation, so an inherited 0644 file from an earlier version is also
        tightened below.
        """
        # The whole env-merged object is written, deliberately: that is
        # what makes scripts/migrate-env-to-settings.ps1 work, since it
        # exists to get effective values into config.json before .env is
        # pruned, and every field it cares about is environment-held by
        # definition at that moment. _drop_env_held stops a *submitted*
        # env-held value being stored; it does not stop the environment's
        # own value being persisted, and should not.
        payload = {}
        for f in fields(self):
            value = getattr(self, f.name)
            # Path and the role-mapping dict are the only non-scalars.
            # str() on a Path keeps the round trip, since from_file passes
            # db_path back through Path(). Everything else json handles.
            payload[f.name] = str(value) if isinstance(value, Path) else value

        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        try:
            os.chmod(path, 0o600)
        except OSError:
            # A filesystem that cannot carry the mode (a bind-mounted CIFS
            # share, some Windows paths) must not break saving settings.
            logger.warning("Could not set 0600 on %s; check its permissions", path)


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
        if os.environ.get("ION_DEV_MODE"):
            _config.dev_mode = _get_env_bool("ION_DEV_MODE")
        if os.environ.get("ION_COOKIE_SECURE"):
            _config.cookie_secure = _get_env_bool("ION_COOKIE_SECURE")
        elif _config.dev_mode:
            # Plain-HTTP development: a Secure cookie is never sent back, so
            # leaving the production default on would silently break login.
            _config.cookie_secure = False
        if os.environ.get("ION_DEBUG_MODE"):
            _config.debug_mode = _get_env_bool("ION_DEBUG_MODE")
        if os.environ.get("ION_ACCOUNT_LOCKOUT_ENABLED"):
            _config.account_lockout_enabled = _get_env_bool("ION_ACCOUNT_LOCKOUT_ENABLED")
        if os.environ.get("ION_IP_BLOCKING_ENABLED"):
            _config.ip_blocking_enabled = _get_env_bool("ION_IP_BLOCKING_ENABLED")
        if os.environ.get("ION_WEBHOOK_REQUIRE_SIGNATURE"):
            _config.webhook_require_signature = _get_env_bool("ION_WEBHOOK_REQUIRE_SIGNATURE")
        if os.environ.get("ION_ENFORCE_PASSWORD_CHANGE"):
            _config.enforce_password_change = _get_env_bool("ION_ENFORCE_PASSWORD_CHANGE")
        if os.environ.get("ION_PASSWORD_MIN_LENGTH"):
            try:
                _config.password_min_length = int(os.environ["ION_PASSWORD_MIN_LENGTH"])
            except ValueError:
                pass  # keep default (disabled) on a non-integer value
        if os.environ.get("ION_SECURITY_SCAN_AUTHENTICATED"):
            _config.security_scan_authenticated = _get_env_bool("ION_SECURITY_SCAN_AUTHENTICATED")
        if os.environ.get("ION_AUTHZ_ALERT_ENABLED"):
            _config.authz_alert_enabled = _get_env_bool("ION_AUTHZ_ALERT_ENABLED", True)
        if os.environ.get("ION_RESPONSE_ACTIONS_ENABLED"):
            _config.response_actions_enabled = _get_env_bool("ION_RESPONSE_ACTIONS_ENABLED")
        if os.environ.get("ION_COMM_TEMPLATES_SEED"):
            _config.comm_templates_seed = _get_env_bool("ION_COMM_TEMPLATES_SEED")
        if os.environ.get("ION_RESPONSE_ACTIONS_LIVE"):
            _config.response_actions_live = _get_env_bool("ION_RESPONSE_ACTIONS_LIVE")
        if os.environ.get("ION_ALERT_DETAIL_V2"):
            _config.alert_detail_v2 = _get_env_bool("ION_ALERT_DETAIL_V2", True)
        if os.environ.get("ION_ALERT_FIELD_PINS"):
            _config.alert_field_pins = _get_env_bool("ION_ALERT_FIELD_PINS", True)
        if os.environ.get("ION_BOB_CUSTOM_TEMPLATES"):
            _config.bob_custom_templates = _get_env_bool("ION_BOB_CUSTOM_TEMPLATES", True)
        if os.environ.get("ION_MULTI_TENANT"):
            _config.multi_tenant = _get_env_bool("ION_MULTI_TENANT")
        if os.environ.get("ION_CHAT_GROUNDING_CHECK"):
            _config.chat_grounding_check = _get_env_bool("ION_CHAT_GROUNDING_CHECK", True)
        if os.environ.get("ION_CSRF_ENABLED"):
            _config.csrf_enabled = _get_env_bool("ION_CSRF_ENABLED", True)
        _env_csrf_origins = os.environ.get("ION_CSRF_EXTRA_ORIGINS", "").strip()
        if _env_csrf_origins:
            _config.csrf_extra_origins = _env_csrf_origins
        if os.environ.get("ION_AUTHZ_ALERT_THRESHOLD"):
            try:
                _config.authz_alert_threshold = int(os.environ["ION_AUTHZ_ALERT_THRESHOLD"])
            except ValueError:
                pass
        if os.environ.get("ION_AUTHZ_ALERT_WINDOW_MINUTES"):
            try:
                _config.authz_alert_window_minutes = int(os.environ["ION_AUTHZ_ALERT_WINDOW_MINUTES"])
            except ValueError:
                pass
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
        if os.environ.get("ION_ARKIME_USERNAME"):
            _config.arkime_username = os.environ.get("ION_ARKIME_USERNAME", "")
        if os.environ.get("ION_ARKIME_PASSWORD"):
            _config.arkime_password = os.environ.get("ION_ARKIME_PASSWORD", "")
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
        if os.environ.get("ION_ELASTICSEARCH_ESQL_ENABLED"):
            _config.elasticsearch_esql_enabled = _get_env_bool("ION_ELASTICSEARCH_ESQL_ENABLED")
        if os.environ.get("ION_ELASTICSEARCH_PROCESS_EVENTS_INDEX"):
            _config.elasticsearch_process_events_index = os.environ.get(
                "ION_ELASTICSEARCH_PROCESS_EVENTS_INDEX", ""
            )
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
            _config.ollama_model = os.environ.get("ION_OLLAMA_MODEL", "hf.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF")
        if os.environ.get("ION_OLLAMA_TIMEOUT"):
            _config.ollama_timeout = int(os.environ.get("ION_OLLAMA_TIMEOUT", "300"))
        if os.environ.get("ION_OLLAMA_NUM_CTX"):
            try:
                _config.ollama_num_ctx = int(os.environ.get("ION_OLLAMA_NUM_CTX", "16384"))
            except ValueError:
                pass
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
        if os.environ.get("ION_KIBANA_CUSTOM_FIELDS_ENABLED"):
            _config.kibana_custom_fields_enabled = _get_env_bool("ION_KIBANA_CUSTOM_FIELDS_ENABLED")
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

        # Detection Engineering module licensing
        if os.environ.get("ION_DE_LICENSE_ENFORCED"):
            _config.de_license_enforced = _get_env_bool("ION_DE_LICENSE_ENFORCED", False)
        if os.environ.get("ION_WORKFORCE_ENABLED"):
            _config.workforce_enabled = _get_env_bool("ION_WORKFORCE_ENABLED", True)
        if os.environ.get("ION_WORKFORCE_LAPSE_GRACE_DAYS"):
            try:
                _config.workforce_lapse_grace_days = int(
                    os.environ["ION_WORKFORCE_LAPSE_GRACE_DAYS"])
            except ValueError:
                logger.warning("ION_WORKFORCE_LAPSE_GRACE_DAYS is not a number; keeping %s",
                               _config.workforce_lapse_grace_days)
        if os.environ.get("ION_DE_MODULE_ENABLED"):
            _config.de_module_enabled = _get_env_bool("ION_DE_MODULE_ENABLED", False)
        if os.environ.get("ION_DE_LICENSE"):
            _config.de_license = os.environ.get("ION_DE_LICENSE", "")

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
            _config.investigation_llm_timeout_s = int(os.environ.get("ION_INVESTIGATION_LLM_TIMEOUT_S", "300"))

        # Attack Path + Bob escalation-tier env overrides
        if os.environ.get("ION_ATTACK_PATH_ENABLED"):
            _config.attack_path_enabled = _get_env_bool("ION_ATTACK_PATH_ENABLED", True)
        if os.environ.get("ION_BOB_ESCALATION_TIER_ENABLED"):
            _config.bob_escalation_tier_enabled = _get_env_bool("ION_BOB_ESCALATION_TIER_ENABLED", True)
        if os.environ.get("ION_BOB_ESCALATION_SAMPLES"):
            try:
                _config.bob_escalation_samples = int(os.environ["ION_BOB_ESCALATION_SAMPLES"])
            except ValueError:
                pass  # keep default on a non-integer value
        if os.environ.get("ION_BOB_ESCALATION_MODEL"):
            _config.bob_escalation_model = os.environ.get("ION_BOB_ESCALATION_MODEL", "")

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


# ── Where did a setting come from? ──
#
# get_config() ranks environment variables above .ion/config.json. That is
# deliberate, but it used to be invisible: a value edited in the settings UI
# saved successfully and changed nothing, which is how the dashboard spent an
# hour reporting ELASTICSEARCH DEGRADED on 2026-10-04.
#
# This map is declarative rather than instrumented into the override block
# above, because that block is several hundred hand-written `if os.environ.get`
# lines and threading a recorder through every one of them would be a far
# larger change for the same answer.
#
# It is GENERATED from that block and covers every field it assigns from an
# environment variable, so the badge is a complete guard rather than a partial
# one. Two tests hold it there: test_every_mapped_field_exists_on_config
# catches typos and renames, and test_env_field_map_matches_override_block
# fails if someone adds an override without a map entry. Regenerate rather
# than hand-editing.
ENV_FIELD_MAP: dict[str, str] = {
    # Assigned via a local (_env_base_url) rather than a literal
    # os.environ.get on the right-hand side, so the generator cannot see
    # it. Kept by hand; test_indirect_overrides_are_mapped guards it.
    "base_url": "ION_BASE_URL",
    "abuseipdb_api_key": "ION_ABUSEIPDB_API_KEY",
    "abuseipdb_enabled": "ION_ABUSEIPDB_ENABLED",
    "account_lockout_enabled": "ION_ACCOUNT_LOCKOUT_ENABLED",
    "alert_detail_v2": "ION_ALERT_DETAIL_V2",
    "alert_field_pins": "ION_ALERT_FIELD_PINS",
    "arkime_enabled": "ION_ARKIME_ENABLED",
    "arkime_password": "ION_ARKIME_PASSWORD",
    "arkime_url": "ION_ARKIME_URL",
    "arkime_username": "ION_ARKIME_USERNAME",
    "arkime_verify_ssl": "ION_ARKIME_VERIFY_SSL",
    "attack_path_enabled": "ION_ATTACK_PATH_ENABLED",
    "authz_alert_enabled": "ION_AUTHZ_ALERT_ENABLED",
    "authz_alert_threshold": "ION_AUTHZ_ALERT_THRESHOLD",
    "authz_alert_window_minutes": "ION_AUTHZ_ALERT_WINDOW_MINUTES",
    "bob_custom_templates": "ION_BOB_CUSTOM_TEMPLATES",
    "bob_escalation_model": "ION_BOB_ESCALATION_MODEL",
    "bob_escalation_samples": "ION_BOB_ESCALATION_SAMPLES",
    "bob_escalation_tier_enabled": "ION_BOB_ESCALATION_TIER_ENABLED",
    "ca_bundle": "ION_CA_BUNDLE",
    "case_grouper_auto_investigate": "ION_CASE_GROUPER_AUTO_INVESTIGATE",
    "case_grouper_enabled": "ION_CASE_GROUPER_ENABLED",
    "case_grouper_interval_s": "ION_CASE_GROUPER_INTERVAL_S",
    "case_grouper_investigate_per_case": "ION_CASE_GROUPER_INVESTIGATE_PER_CASE",
    "case_grouper_max_alerts_per_case": "ION_CASE_GROUPER_MAX_ALERTS_PER_CASE",
    "case_grouper_min_cluster_size": "ION_CASE_GROUPER_MIN_CLUSTER_SIZE",
    "case_grouper_push_to_kibana": "ION_CASE_GROUPER_PUSH_TO_KIBANA",
    "case_grouper_stagger_s": "ION_CASE_GROUPER_STAGGER_S",
    "case_grouper_window_minutes": "ION_CASE_GROUPER_WINDOW_MINUTES",
    "chat_grounding_check": "ION_CHAT_GROUNDING_CHECK",
    "comm_templates_seed": "ION_COMM_TEMPLATES_SEED",
    "cookie_secure": "ION_COOKIE_SECURE",
    "csrf_enabled": "ION_CSRF_ENABLED",
    "de_license": "ION_DE_LICENSE",
    "de_license_enforced": "ION_DE_LICENSE_ENFORCED",
    "de_module_enabled": "ION_DE_MODULE_ENABLED",
    "debug_mode": "ION_DEBUG_MODE",
    "dev_mode": "ION_DEV_MODE",
    "dfir_iris_api_key": "ION_DFIR_IRIS_API_KEY",
    "dfir_iris_default_customer": "ION_DFIR_IRIS_DEFAULT_CUSTOMER",
    "dfir_iris_enabled": "ION_DFIR_IRIS_ENABLED",
    "dfir_iris_url": "ION_DFIR_IRIS_URL",
    "dfir_iris_verify_ssl": "ION_DFIR_IRIS_VERIFY_SSL",
    "elasticsearch_alert_index": "ION_ELASTICSEARCH_ALERT_INDEX",
    "elasticsearch_api_key": "ION_ELASTICSEARCH_API_KEY",
    "elasticsearch_case_index": "ION_ELASTICSEARCH_CASE_INDEX",
    "elasticsearch_enabled": "ION_ELASTICSEARCH_ENABLED",
    "elasticsearch_esql_enabled": "ION_ELASTICSEARCH_ESQL_ENABLED",
    "elasticsearch_password": "ION_ELASTICSEARCH_PASSWORD",
    "elasticsearch_process_events_index": "ION_ELASTICSEARCH_PROCESS_EVENTS_INDEX",
    "elasticsearch_url": "ION_ELASTICSEARCH_URL",
    "elasticsearch_username": "ION_ELASTICSEARCH_USERNAME",
    "elasticsearch_verify_ssl": "ION_ELASTICSEARCH_VERIFY_SSL",
    "enforce_password_change": "ION_ENFORCE_PASSWORD_CHANGE",
    "exec_ad_bind_dn": "ION_EXEC_AD_BIND_DN",
    "exec_ad_bind_password": "ION_EXEC_AD_BIND_PASSWORD",
    "exec_ad_ldap_uri": "ION_EXEC_AD_LDAP_URI",
    "exec_ad_user_search_base": "ION_EXEC_AD_USER_SEARCH_BASE",
    "exec_ad_verify_ssl": "ION_EXEC_AD_VERIFY_SSL",
    "exec_default_timeout_s": "ION_EXEC_DEFAULT_TIMEOUT_S",
    "exec_dns_sinkhole_api_key": "ION_EXEC_DNS_SINKHOLE_API_KEY",
    "exec_dns_sinkhole_url": "ION_EXEC_DNS_SINKHOLE_URL",
    "exec_dns_sinkhole_verify_ssl": "ION_EXEC_DNS_SINKHOLE_VERIFY_SSL",
    "exec_dry_run": "ION_EXEC_DRY_RUN",
    "exec_edr_api_key": "ION_EXEC_EDR_API_KEY",
    "exec_edr_url": "ION_EXEC_EDR_URL",
    "exec_edr_verify_ssl": "ION_EXEC_EDR_VERIFY_SSL",
    "exec_email_gateway_api_key": "ION_EXEC_EMAIL_GATEWAY_API_KEY",
    "exec_email_gateway_url": "ION_EXEC_EMAIL_GATEWAY_URL",
    "exec_email_gateway_verify_ssl": "ION_EXEC_EMAIL_GATEWAY_VERIFY_SSL",
    "exec_firewall_api_key": "ION_EXEC_FIREWALL_API_KEY",
    "exec_firewall_url": "ION_EXEC_FIREWALL_URL",
    "exec_firewall_verify_ssl": "ION_EXEC_FIREWALL_VERIFY_SSL",
    "exec_generic_webhook_api_key": "ION_EXEC_GENERIC_WEBHOOK_API_KEY",
    "gitlab_enabled": "ION_GITLAB_ENABLED",
    "gitlab_project_id": "ION_GITLAB_PROJECT_ID",
    "gitlab_sudo_enabled": "ION_GITLAB_SUDO",
    "gitlab_token": "ION_GITLAB_TOKEN",
    "gitlab_url": "ION_GITLAB_URL",
    "gitlab_verify_ssl": "ION_GITLAB_VERIFY_SSL",
    "investigation_llm_timeout_s": "ION_INVESTIGATION_LLM_TIMEOUT_S",
    "investigation_loop_enabled": "ION_INVESTIGATION_LOOP_ENABLED",
    "investigation_max_per_sweep": "ION_INVESTIGATION_MAX_PER_SWEEP",
    "investigation_sweep_interval_s": "ION_INVESTIGATION_SWEEP_INTERVAL_S",
    "ip_blocking_enabled": "ION_IP_BLOCKING_ENABLED",
    "kibana_case_owner": "ION_KIBANA_CASE_OWNER",
    "kibana_cases_enabled": "ION_KIBANA_CASES_ENABLED",
    "kibana_custom_fields_enabled": "ION_KIBANA_CUSTOM_FIELDS_ENABLED",
    "kibana_password": "ION_KIBANA_PASSWORD",
    "kibana_space_id": "ION_KIBANA_SPACE_ID",
    "kibana_url": "ION_KIBANA_URL",
    "kibana_username": "ION_KIBANA_USERNAME",
    "kibana_verify_ssl": "ION_KIBANA_VERIFY_SSL",
    "multi_tenant": "ION_MULTI_TENANT",
    "oidc_client_id": "ION_OIDC_CLIENT_ID",
    "oidc_client_secret": "ION_OIDC_CLIENT_SECRET",
    "oidc_enabled": "ION_OIDC_ENABLED",
    "oidc_keycloak_url": "ION_OIDC_KEYCLOAK_URL",
    "oidc_realm": "ION_OIDC_REALM",
    "oidc_verify_ssl": "ION_OIDC_VERIFY_SSL",
    "ollama_enabled": "ION_OLLAMA_ENABLED",
    "ollama_model": "ION_OLLAMA_MODEL",
    "ollama_num_ctx": "ION_OLLAMA_NUM_CTX",
    "ollama_timeout": "ION_OLLAMA_TIMEOUT",
    "ollama_url": "ION_OLLAMA_URL",
    "ollama_verify_ssl": "ION_OLLAMA_VERIFY_SSL",
    "opencti_enabled": "ION_OPENCTI_ENABLED",
    "opencti_token": "ION_OPENCTI_TOKEN",
    "opencti_url": "ION_OPENCTI_URL",
    "opencti_verify_ssl": "ION_OPENCTI_VERIFY_SSL",
    "password_min_length": "ION_PASSWORD_MIN_LENGTH",
    "pii_anon_enabled": "ION_PII_ANON_ENABLED",
    "pii_fields_file": "ION_PII_FIELDS_FILE",
    "response_actions_enabled": "ION_RESPONSE_ACTIONS_ENABLED",
    "response_actions_live": "ION_RESPONSE_ACTIONS_LIVE",
    "scheduler_enabled": "ION_SCHEDULER_ENABLED",
    "scheduler_interval_s": "ION_SCHEDULER_INTERVAL_S",
    "security_scan_authenticated": "ION_SECURITY_SCAN_AUTHENTICATED",
    "shodan_api_key": "ION_SHODAN_API_KEY",
    "shodan_enabled": "ION_SHODAN_ENABLED",
    "shodan_timeout": "ION_SHODAN_TIMEOUT",
    "shodan_url": "ION_SHODAN_URL",
    "shodan_verify_ssl": "ION_SHODAN_VERIFY_SSL",
    "smtp_enabled": "ION_SMTP_ENABLED",
    "smtp_from_address": "ION_SMTP_FROM_ADDRESS",
    "smtp_from_name": "ION_SMTP_FROM_NAME",
    "smtp_host": "ION_SMTP_HOST",
    "smtp_password": "ION_SMTP_PASSWORD",
    "smtp_port": "ION_SMTP_PORT",
    "smtp_timeout": "ION_SMTP_TIMEOUT",
    "smtp_use_starttls": "ION_SMTP_USE_STARTTLS",
    "smtp_use_tls": "ION_SMTP_USE_TLS",
    "smtp_username": "ION_SMTP_USERNAME",
    "smtp_verify_ssl": "ION_SMTP_VERIFY_SSL",
    "ssl_cert": "ION_SSL_CERT",
    "ssl_key": "ION_SSL_KEY",
    "tide_api_key": "ION_TIDE_API_KEY",
    "tide_client_id": "ION_TIDE_CLIENT_ID",
    "tide_enabled": "ION_TIDE_ENABLED",
    "tide_space": "ION_TIDE_SPACE",
    "tide_url": "ION_TIDE_URL",
    "tide_verify_ssl": "ION_TIDE_VERIFY_SSL",
    "virustotal_api_key": "ION_VIRUSTOTAL_API_KEY",
    "virustotal_enabled": "ION_VIRUSTOTAL_ENABLED",
    "virustotal_rate_limit": "ION_VIRUSTOTAL_RATE_LIMIT",
    "virustotal_timeout": "ION_VIRUSTOTAL_TIMEOUT",
    "virustotal_url": "ION_VIRUSTOTAL_URL",
    "virustotal_verify_ssl": "ION_VIRUSTOTAL_VERIFY_SSL",
    "webhook_require_signature": "ION_WEBHOOK_REQUIRE_SIGNATURE",
    "workforce_enabled": "ION_WORKFORCE_ENABLED",
    "workforce_lapse_grace_days": "ION_WORKFORCE_LAPSE_GRACE_DAYS",
}

# Read before the app can consult its own settings, so these cannot move into
# config.json. ION_DATA_DIR is the strongest case: it is how config.json is
# located. ION_VERSION is read by Compose to resolve the image tag, and
# ION_LOG_LEVEL when logging is configured, which happens before config loads.
BOOTSTRAP_ENV_KEYS: frozenset[str] = frozenset({
    "ION_VERSION",
    "ION_DATA_DIR",
    "ION_HOST",
    "ION_PORT",
    "ION_WORKERS",
    "ION_LOG_LEVEL",
})


def _config_file_path() -> Path:
    """The same path get_config() loads from."""
    data_dir = os.environ.get("ION_DATA_DIR")
    if data_dir:
        return Path(data_dir) / ".ion" / "config.json"
    return Path.cwd() / ".ion" / "config.json"


# get_config()'s override block tests the RAW value for truthiness
# (`if os.environ.get("ION_ELASTICSEARCH_URL")`), so a key blanked with spaces
# rather than emptied is applied as-is: the effective elasticsearch_url becomes
# "   ". Only base_url strips before testing, so only base_url treats a
# whitespace-only value as unset.
#
# These functions therefore mirror truthiness rather than doing the tidier
# thing, because the tidier answer is the dangerous one: reporting "default"
# for a field the environment is in fact holding renders it editable in the
# settings UI, the save reports success, and the environment keeps winning —
# the exact failure this mechanism exists to prevent.
_STRIPPED_ENV_FIELDS: frozenset[str] = frozenset({"base_url"})


def _env_override(field: str) -> Optional[str]:
    """The environment value get_config() would apply to `field`, else None."""
    env_name = ENV_FIELD_MAP.get(field)
    if not env_name:
        return None
    raw = os.environ.get(env_name, "")
    value = raw.strip() if field in _STRIPPED_ENV_FIELDS else raw
    return value or None


def env_held_fields() -> frozenset[str]:
    """Every field whose effective value the environment is currently holding.

    The right question for a write path, and cheaper than
    config_field_sources(): these are the fields a `PUT` must not persist,
    because config.json loses to the environment on the next load. No file read
    — provenance is not needed, only "is the environment deciding this".
    """
    return frozenset(f for f in ENV_FIELD_MAP if _env_override(f) is not None)


def _stored_config(path: Optional[Path] = None) -> dict:
    """The parsed config.json, or {} when it is absent or unreadable.

    ``path`` is explicit for ``to_file``, which may be writing somewhere
    other than the resolved location (the setup wizard, and tests).
    """
    if path is None:
        path = _config_file_path()
    if not path.exists():
        return {}
    try:
        with open(path, encoding="utf-8") as fh:
            stored = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}
    return stored if isinstance(stored, dict) else {}


def config_field_source(field: str) -> str:
    """Report where `field`'s effective value came from.

    Returns "environment", "file" or "default". An unmapped field, or one whose
    environment variable is empty, reports as if it were unset — which is how
    get_config() treats it. A whitespace-only value is NOT unset: see
    _STRIPPED_ENV_FIELDS.
    """
    if _env_override(field) is not None:
        return "environment"
    if field in _stored_config():
        return "file"
    return "default"


def config_field_sources() -> dict[str, str]:
    """config_field_source() for every field the settings UI can show.

    Reads config.json once rather than once per field: this runs on every
    GET /api/admin/config, and ENV_FIELD_MAP has 151 entries.
    """
    stored = _stored_config()
    sources = {}
    # `name`, not `field`: this module imports `field` from dataclasses, and a
    # loop variable of that name shadows it (ruff F402).
    for name in ENV_FIELD_MAP:
        if _env_override(name) is not None:
            sources[name] = "environment"
        elif name in stored:
            sources[name] = "file"
        else:
            sources[name] = "default"
    return sources


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

    # Security visibility: OIDC token trust ultimately rests on the JWKS we
    # fetch from Keycloak. With TLS verification off, an on-path attacker can
    # serve a forged JWKS and mint tokens accepted as any user. The default is
    # left off for air-gapped/self-signed deployments, but the insecure state
    # must never be silent — log a loud, once-only warning so operators can see
    # it in `docker logs ion` and opt back in via ION_OIDC_VERIFY_SSL=true /
    # ION_CA_BUNDLE. (Code-review finding #1.)
    global _oidc_tls_warned
    if config.oidc_enabled and not config.oidc_verify_ssl and not _oidc_tls_warned:
        _oidc_tls_warned = True
        logger.warning(
            "OIDC TLS verification is DISABLED (ION_OIDC_VERIFY_SSL=false). "
            "Keycloak JWKS/token-exchange traffic is not certificate-verified; "
            "an on-path attacker could forge the signing keys and impersonate "
            "any user. Set ION_OIDC_VERIFY_SSL=true (and ION_CA_BUNDLE for "
            "self-signed certs) in any environment where the link to Keycloak "
            "is not fully trusted."
        )

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

    Returns Arkime viewer connection details. HTTP Basic auth only.
    """
    config = get_config()
    return {
        "enabled": config.arkime_enabled,
        "url": config.arkime_url,
        "username": config.arkime_username,
        "password": config.arkime_password,
        "verify_ssl": config.arkime_verify_ssl,
    }


def _overlay_tenant(base: dict, section: str) -> dict:
    """Apply the active tenant's connection settings over the process-wide ones.

    This is the single place tenancy reaches Elasticsearch and Kibana: every
    caller builds its client from these two functions, so overlaying here makes
    ~30 construction sites tenant-aware without touching any of them.

    Only keys the tenant actually set are overlaid — a tenant row that leaves a
    field blank inherits rather than blanking a working connection. With no
    tenant bound the base is returned untouched, which is every single-estate
    deploy.
    """
    try:
        from ion.core.tenant_context import current_tenant_connection

        conn = current_tenant_connection()
    except Exception:  # pragma: no cover - context must never break config
        return base
    if not conn:
        return base
    overlay = conn.get(section) or {}
    if not overlay:
        return base
    merged = dict(base)
    merged.update({k: v for k, v in overlay.items() if v is not None})
    # A tenant that sets basic-auth credentials must not inherit the process
    # api_key: the ES client prefers api_key over basic auth, so the inherited
    # key would be sent to the tenant's cluster and its own account never used.
    if (
        "api_key" in merged
        and "api_key" not in overlay
        and ("username" in overlay or "password" in overlay)
    ):
        merged["api_key"] = ""
    return merged


def get_elasticsearch_config() -> dict:
    """Get Elasticsearch configuration for the active tenant, or the process-wide one."""
    config = get_config()
    return _overlay_tenant({
        "enabled": config.elasticsearch_enabled,
        "url": config.elasticsearch_url,
        "api_key": config.elasticsearch_api_key,
        "username": config.elasticsearch_username,
        "password": config.elasticsearch_password,
        "alert_index": config.elasticsearch_alert_index,
        "process_events_index": config.elasticsearch_process_events_index,
        "case_index": config.elasticsearch_case_index,
        "verify_ssl": config.elasticsearch_verify_ssl,
        "user_index": config.elasticsearch_user_index,
        "user_field": config.elasticsearch_user_field,
        "assignment_field": config.elasticsearch_assignment_field,
    }, "es")


def get_kibana_config() -> dict:
    """Get Kibana Cases configuration from the global config.

    Returns a dictionary with Kibana configuration.
    """
    config = get_config()
    # Fall back to Elasticsearch credentials if Kibana-specific ones not set.
    # With a tenant bound, both fallback steps stay inside that tenant: its own
    # Kibana creds, else its (overlaid) ES creds — never the process-wide
    # Kibana pair, which is another estate's login.
    es = get_elasticsearch_config()
    try:
        from ion.core.tenant_context import current_tenant_connection

        conn = current_tenant_connection()
    except Exception:  # pragma: no cover - context must never break config
        conn = None
    if conn:
        tenant_kibana = conn.get("kibana") or {}
        username = tenant_kibana.get("username") or es.get("username", "")
        password = tenant_kibana.get("password") or es.get("password", "")
    else:
        username = config.kibana_username or es.get("username", "")
        password = config.kibana_password or es.get("password", "")
    return _overlay_tenant({
        "enabled": config.kibana_cases_enabled,
        "url": config.kibana_url,
        "username": username,
        "password": password,
        "space_id": config.kibana_space_id,
        "case_owner": config.kibana_case_owner,
        "verify_ssl": config.kibana_verify_ssl,
    }, "kibana")


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
