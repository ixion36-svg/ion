"""OIDC/Keycloak token validation and user synchronization."""

import time
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any

import httpx
from jose import jwt, JWTError, ExpiredSignatureError
from sqlalchemy.orm import Session

from ion.auth.oidc_config import OIDCConfig
from ion.models.user import User, Role
from ion.storage.user_repository import UserRepository, RoleRepository

logger = logging.getLogger(__name__)


@dataclass
class OIDCTokenData:
    """Data extracted from a validated OIDC token."""

    sub: str  # Keycloak user ID (subject)
    email: str
    preferred_username: str
    roles: List[str] = field(default_factory=list)
    raw_claims: Dict[str, Any] = field(default_factory=dict)
    given_name: Optional[str] = None
    family_name: Optional[str] = None
    name: Optional[str] = None

    @property
    def display_name(self) -> str:
        """Get a display name from available claims."""
        if self.name:
            return self.name
        if self.given_name and self.family_name:
            return f"{self.given_name} {self.family_name}"
        if self.given_name:
            return self.given_name
        return self.preferred_username


class OIDCValidationError(Exception):
    """Raised when OIDC token validation fails."""

    pass


class OIDCValidator:
    """Validates Keycloak JWT tokens."""

    def __init__(self, config: OIDCConfig):
        self.config = config
        self._jwks_cache: Optional[Dict] = None
        self._jwks_cache_time: Optional[float] = None
        self._cache_ttl = 3600  # 1 hour cache for JWKS

    async def get_jwks(self) -> Dict:
        """Fetch and cache Keycloak public keys (JWKS).

        Returns the JSON Web Key Set used to verify token signatures.
        Keys are cached for 1 hour to reduce latency.
        """
        now = time.time()

        # Return cached keys if still valid
        if (
            self._jwks_cache is not None
            and self._jwks_cache_time is not None
            and (now - self._jwks_cache_time) < self._cache_ttl
        ):
            return self._jwks_cache

        # Fetch fresh keys
        try:
            async with httpx.AsyncClient(verify=self.config.verify_ssl) as client:
                response = await client.get(
                    self.config.jwks_url,
                    timeout=10.0,
                )
                response.raise_for_status()
                self._jwks_cache = response.json()
                self._jwks_cache_time = now
                logger.debug("Fetched fresh JWKS from Keycloak")
                return self._jwks_cache
        except httpx.HTTPError as e:
            logger.error(f"Failed to fetch JWKS: {e}")
            # If we have cached keys, use them even if expired
            if self._jwks_cache is not None:
                logger.warning("Using expired JWKS cache due to fetch failure")
                return self._jwks_cache
            raise OIDCValidationError(f"Failed to fetch JWKS: {e}")

    def get_jwks_sync(self) -> Dict:
        """Synchronous version of get_jwks for non-async contexts."""
        now = time.time()

        if (
            self._jwks_cache is not None
            and self._jwks_cache_time is not None
            and (now - self._jwks_cache_time) < self._cache_ttl
        ):
            return self._jwks_cache

        try:
            with httpx.Client(verify=self.config.verify_ssl) as client:
                response = client.get(
                    self.config.jwks_url,
                    timeout=10.0,
                )
                response.raise_for_status()
                self._jwks_cache = response.json()
                self._jwks_cache_time = now
                return self._jwks_cache
        except httpx.HTTPError as e:
            if self._jwks_cache is not None:
                return self._jwks_cache
            raise OIDCValidationError(f"Failed to fetch JWKS: {e}")

    def _extract_roles(self, claims: Dict[str, Any]) -> List[str]:
        """Extract roles from JWT claims based on configured role_claim path.

        Supports nested paths like 'realm_access.roles' or 'groups'.
        """
        roles = []
        claim_path = self.config.role_claim.split(".")

        current = claims
        for part in claim_path:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                current = None
                break

        if isinstance(current, list):
            roles = [str(r) for r in current]
        elif isinstance(current, str):
            roles = [current]

        return roles

    def validate_token(self, token: str) -> OIDCTokenData:
        """Validate a JWT token and extract claims.

        Args:
            token: The JWT access token to validate

        Returns:
            OIDCTokenData with extracted claims

        Raises:
            OIDCValidationError: If token validation fails
        """
        if not self.config.is_valid():
            raise OIDCValidationError("OIDC configuration is invalid")

        try:
            # Get the signing keys
            jwks = self.get_jwks_sync()

            # Decode and verify the token
            # We need to get the key ID from the token header
            unverified_header = jwt.get_unverified_header(token)
            kid = unverified_header.get("kid")

            if not kid:
                raise OIDCValidationError("Token missing key ID (kid)")

            # Find the matching key
            rsa_key = None
            for key in jwks.get("keys", []):
                if key.get("kid") == kid:
                    rsa_key = key
                    break

            if not rsa_key:
                raise OIDCValidationError(f"Key {kid} not found in JWKS")

            # Verify and decode the token
            claims = jwt.decode(
                token,
                rsa_key,
                algorithms=["RS256"],
                audience=self.config.client_id,
                issuer=self.config.issuer_url,
                options={
                    "verify_aud": True,
                    "verify_iss": True,
                    "verify_exp": True,
                    "verify_iat": True,
                },
            )

            # Extract required claims
            sub = claims.get("sub")
            if not sub:
                raise OIDCValidationError("Token missing subject (sub) claim")

            email = claims.get("email", "")
            preferred_username = claims.get("preferred_username", sub)

            # Extract roles
            roles = self._extract_roles(claims)

            return OIDCTokenData(
                sub=sub,
                email=email,
                preferred_username=preferred_username,
                roles=roles,
                raw_claims=claims,
                given_name=claims.get("given_name"),
                family_name=claims.get("family_name"),
                name=claims.get("name"),
            )

        except ExpiredSignatureError:
            raise OIDCValidationError("Token has expired")
        except JWTError as e:
            raise OIDCValidationError(f"Token validation failed: {e}")

    async def validate_token_async(self, token: str) -> OIDCTokenData:
        """Async version of validate_token."""
        if not self.config.is_valid():
            raise OIDCValidationError("OIDC configuration is invalid")

        try:
            jwks = await self.get_jwks()

            unverified_header = jwt.get_unverified_header(token)
            kid = unverified_header.get("kid")

            if not kid:
                raise OIDCValidationError("Token missing key ID (kid)")

            rsa_key = None
            for key in jwks.get("keys", []):
                if key.get("kid") == kid:
                    rsa_key = key
                    break

            if not rsa_key:
                raise OIDCValidationError(f"Key {kid} not found in JWKS")

            claims = jwt.decode(
                token,
                rsa_key,
                algorithms=["RS256"],
                audience=self.config.client_id,
                issuer=self.config.issuer_url,
            )

            sub = claims.get("sub")
            if not sub:
                raise OIDCValidationError("Token missing subject (sub) claim")

            email = claims.get("email", "")
            preferred_username = claims.get("preferred_username", sub)
            roles = self._extract_roles(claims)

            return OIDCTokenData(
                sub=sub,
                email=email,
                preferred_username=preferred_username,
                roles=roles,
                raw_claims=claims,
                given_name=claims.get("given_name"),
                family_name=claims.get("family_name"),
                name=claims.get("name"),
            )

        except ExpiredSignatureError:
            raise OIDCValidationError("Token has expired")
        except JWTError as e:
            raise OIDCValidationError(f"Token validation failed: {e}")


class OIDCUserSync:
    """Synchronizes Keycloak users to ION database."""

    def __init__(self, session: Session, config: OIDCConfig):
        self.session = session
        self.config = config
        self.user_repo = UserRepository(session)
        self.role_repo = RoleRepository(session)

    def sync_user(self, token_data: OIDCTokenData) -> User:
        """Find or create a ION user from OIDC token data.

        Args:
            token_data: Validated token data from Keycloak

        Returns:
            The synchronized User object

        Raises:
            ValueError: If user creation fails and auto_create is disabled
        """
        # Try to find existing user by email (primary identifier)
        user = self.user_repo.get_by_email(token_data.email)

        if user is None and token_data.preferred_username:
            # Fall back to username lookup
            user = self.user_repo.get_by_username(token_data.preferred_username)

        if user is None:
            # User doesn't exist in ION
            if not self.config.auto_create_users:
                raise ValueError(
                    f"User {token_data.email} not found and auto-creation is disabled"
                )

            # Create new user
            user = self._create_user(token_data)
            logger.info(f"Created new user from OIDC: {user.username}")
        else:
            # Update existing user's last login
            self.user_repo.update_last_login(user)

        # Sync roles from Keycloak
        self._sync_roles(user, token_data.roles)

        return user

    def _create_user(self, token_data: OIDCTokenData) -> User:
        """Create a new ION user from OIDC token data."""
        # Generate a unique username if needed
        username = token_data.preferred_username
        if self.user_repo.get_by_username(username):
            # Username taken, use email prefix with suffix
            base = token_data.email.split("@")[0]
            counter = 1
            while self.user_repo.get_by_username(f"{base}_{counter}"):
                counter += 1
            username = f"{base}_{counter}"

        # Create user without password (OIDC users can't local login until admin sets password)
        user = self.user_repo.create(
            username=username,
            email=token_data.email,
            password_hash="",  # Empty hash - user can't local login
            display_name=token_data.display_name,
            is_active=True,
            must_change_password=False,
        )

        # Update last login immediately
        self.user_repo.update_last_login(user)

        return user

    def _sync_roles(self, user: User, keycloak_roles: List[str]) -> None:
        """Synchronize user roles from Keycloak to ION.

        Uses direct name matching first, then falls back to configured mapping.
        """
        ion_roles = self.map_roles(keycloak_roles)

        if ion_roles:
            self.user_repo.set_roles(user, ion_roles)
            logger.debug(
                f"Synced roles for {user.username}: {[r.name for r in ion_roles]}"
            )

    def map_roles(self, keycloak_roles: List[str]) -> List[Role]:
        """Map Keycloak roles to ION roles.

        First tries direct name match, then uses configured role_mapping.
        """
        ion_roles = []
        seen_role_ids = set()

        for kc_role in keycloak_roles:
            # Try direct match first
            df_role = self.role_repo.get_by_name(kc_role)
            if df_role and df_role.id not in seen_role_ids:
                ion_roles.append(df_role)
                seen_role_ids.add(df_role.id)
                continue

            # Try configured mapping
            if kc_role in self.config.role_mapping:
                mapped_name = self.config.role_mapping[kc_role]
                df_role = self.role_repo.get_by_name(mapped_name)
                if df_role and df_role.id not in seen_role_ids:
                    ion_roles.append(df_role)
                    seen_role_ids.add(df_role.id)

        return ion_roles
