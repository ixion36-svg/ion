"""OIDC/Keycloak configuration for DocForge."""

from dataclasses import dataclass, field
from typing import Dict


@dataclass
class OIDCConfig:
    """OIDC/Keycloak configuration settings.

    This dataclass holds all configuration needed for Keycloak SSO integration.
    When disabled, the system falls back to session-based authentication only.
    """

    enabled: bool = False
    keycloak_url: str = ""  # Base URL, e.g., https://keycloak.example.com
    realm: str = ""  # Keycloak realm name
    client_id: str = ""  # OIDC client ID
    client_secret: str = ""  # OIDC client secret (for confidential clients)
    auto_create_users: bool = True  # Auto-create DocForge users on first OIDC login
    role_claim: str = "realm_access.roles"  # JWT claim path for roles
    role_mapping: Dict[str, str] = field(default_factory=dict)  # Keycloak -> DocForge role mapping

    @property
    def issuer_url(self) -> str:
        """Get the OIDC issuer URL."""
        if not self.keycloak_url or not self.realm:
            return ""
        base = self.keycloak_url.rstrip("/")
        return f"{base}/realms/{self.realm}"

    @property
    def authorization_url(self) -> str:
        """Get the OIDC authorization endpoint URL."""
        if not self.issuer_url:
            return ""
        return f"{self.issuer_url}/protocol/openid-connect/auth"

    @property
    def token_url(self) -> str:
        """Get the OIDC token endpoint URL."""
        if not self.issuer_url:
            return ""
        return f"{self.issuer_url}/protocol/openid-connect/token"

    @property
    def jwks_url(self) -> str:
        """Get the OIDC JWKS (public keys) endpoint URL."""
        if not self.issuer_url:
            return ""
        return f"{self.issuer_url}/protocol/openid-connect/certs"

    @property
    def userinfo_url(self) -> str:
        """Get the OIDC userinfo endpoint URL."""
        if not self.issuer_url:
            return ""
        return f"{self.issuer_url}/protocol/openid-connect/userinfo"

    @property
    def end_session_url(self) -> str:
        """Get the OIDC end session (logout) endpoint URL."""
        if not self.issuer_url:
            return ""
        return f"{self.issuer_url}/protocol/openid-connect/logout"

    def is_valid(self) -> bool:
        """Check if the configuration has minimum required fields."""
        return bool(
            self.enabled
            and self.keycloak_url
            and self.realm
            and self.client_id
        )
