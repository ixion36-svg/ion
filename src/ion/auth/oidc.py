"""OIDC/Keycloak token validation and user synchronization.

v0.31.8: migrated from python-jose to PyJWT. Same JWT semantics for our
RS256-only Keycloak path; PyJWT drops the transitive `ecdsa` dep that
carried CVE-2024-23342. See docs/SECURE_BY_DESIGN.md P17.
"""

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx
import jwt
from jwt import ExpiredSignatureError, InvalidTokenError, PyJWK
from sqlalchemy.orm import Session

from ion.auth.oidc_config import OIDCConfig
from ion.core.config import get_ssl_verify
from ion.models.user import Role, User
from ion.storage.user_repository import RoleRepository, UserRepository

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
            async with httpx.AsyncClient(verify=get_ssl_verify(self.config.verify_ssl)) as client:
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
            with httpx.Client(verify=get_ssl_verify(self.config.verify_ssl)) as client:
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

            # Wrap the JWK dict into PyJWK so jwt.decode gets the
            # signing key in the form it expects. PyJWT 2.x accepts a
            # PyJWK directly (its `.key` attribute is the cryptography
            # public-key object).
            try:
                signing_key = PyJWK.from_dict(rsa_key).key
            except Exception as e:  # pragma: no cover - shape errors only
                raise OIDCValidationError(f"Invalid JWKS key shape for kid {kid}: {e}")

            # Verify and decode the token
            claims = jwt.decode(
                token,
                signing_key,
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
        except InvalidTokenError as e:
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

            try:
                signing_key = PyJWK.from_dict(rsa_key).key
            except Exception as e:  # pragma: no cover - shape errors only
                raise OIDCValidationError(f"Invalid JWKS key shape for kid {kid}: {e}")

            claims = jwt.decode(
                token,
                signing_key,
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
        except InvalidTokenError as e:
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
        # Identity resolution order matters for security. Match on the
        # IMMUTABLE Keycloak subject first; only fall back to email/username
        # when no subject match exists, and never let an incoming token rebind
        # an account that already belongs to a different subject.
        #
        # 1) Immutable subject — the authoritative identity anchor.
        user = self.user_repo.get_by_keycloak_sub(token_data.sub)

        # 2) Email fallback. Email is NOT a trustworthy identity anchor on its
        #    own (it can be reassigned in the IdP), so refuse to rebind a local
        #    account that is already bound to a DIFFERENT Keycloak subject —
        #    that would be account takeover. Accounts with no subject yet
        #    (never federated) remain bindable, so realms that do not emit an
        #    email_verified claim keep working exactly as before.
        if user is None and token_data.email:
            candidate = self.user_repo.get_by_email(token_data.email)
            user = self._guard_rebind(candidate, token_data)

        # 3) Username — same rebind guard.
        if user is None and token_data.preferred_username:
            candidate = self.user_repo.get_by_username(token_data.preferred_username)
            user = self._guard_rebind(candidate, token_data)

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

        # Store Keycloak subject identifier (immutable)
        if token_data.sub and getattr(user, 'keycloak_sub', None) != token_data.sub:
            user.keycloak_sub = token_data.sub
            logger.debug(f"Stored keycloak_sub for {user.username}: {token_data.sub}")

        # Sync roles from Keycloak
        self._sync_roles(user, token_data.roles)

        return user

    def _guard_rebind(
        self, candidate: Optional[User], token_data: OIDCTokenData
    ) -> Optional[User]:
        """Return ``candidate`` unless it is already bound to a different subject.

        Email/username are not trustworthy identity anchors: an attacker who can
        set their own Keycloak email/username to a victim's value would otherwise
        be bound to the victim's existing ION account. If the matched local
        account already carries a ``keycloak_sub`` that differs from the incoming
        token's subject, refuse the match (the caller then falls through to user
        creation, giving the attacker their OWN account, not the victim's).

        A candidate with no ``keycloak_sub`` yet (never federated) is still
        bindable, preserving today's behaviour for realms without verified email.
        """
        if candidate is None:
            return None
        existing_sub = getattr(candidate, "keycloak_sub", None)
        if existing_sub and token_data.sub and existing_sub != token_data.sub:
            logger.warning(
                "OIDC sync refused to rebind local user '%s' (matched by "
                "email/username) — it is already bound to a different Keycloak "
                "subject. Incoming sub=%s, stored sub=%s.",
                candidate.username, token_data.sub, existing_sub,
            )
            return None
        return candidate

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
