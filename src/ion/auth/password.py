"""Password hashing utilities using bcrypt."""

from typing import Optional

from passlib.context import CryptContext

# A small denylist of obviously-weak passwords, always rejected when the policy
# is active. Defence-in-depth, not the primary control (length is).
_COMMON_WEAK = frozenset(
    {
        "password", "admin", "changeme", "123456", "12345678", "123456789",
        "password1", "password123", "qwerty", "qwerty123", "letmein", "welcome",
        "admin123", "iloveyou", "secret", "ion", "ion2025", "admin2025",
    }
)


def validate_password_policy(password: str, min_length: int = 0) -> Optional[str]:
    """Return an error string if the password violates policy, else None.

    OPT-IN (v0.39.4): when ``min_length <= 0`` the policy is disabled and every
    password is accepted (no behaviour change). When active it enforces a
    minimum length and rejects a small denylist of obviously-weak values. Set
    ``ION_PASSWORD_MIN_LENGTH`` (e.g. 12) to turn it on. In ION's deployment the
    only local account is ``admin`` (everyone else is Keycloak/OIDC), so this
    primarily governs the admin password set via the UI; the seed password in
    ``ION_ADMIN_PASSWORD`` is validated separately at startup.
    """
    if min_length <= 0:
        return None  # policy disabled — accept anything (default)
    if len(password) < min_length:
        return f"Password must be at least {min_length} characters long"
    if password.lower() in _COMMON_WEAK:
        return "Password is too common; choose a stronger one"
    return None


class PasswordHasher:
    """Handles password hashing and verification using bcrypt."""

    def __init__(self, rounds: int = 12):
        """Initialize password hasher with bcrypt.

        Args:
            rounds: bcrypt work factor (default 12)
        """
        self._context = CryptContext(
            schemes=["bcrypt"],
            deprecated="auto",
            bcrypt__rounds=rounds,
        )

    def hash(self, password: str) -> str:
        """Hash a password.

        Args:
            password: Plain text password

        Returns:
            Hashed password string
        """
        return self._context.hash(password)

    def verify(self, password: str, hashed: str) -> bool:
        """Verify a password against its hash.

        Args:
            password: Plain text password to verify
            hashed: Previously hashed password

        Returns:
            True if password matches, False otherwise
        """
        return self._context.verify(password, hashed)

    def needs_rehash(self, hashed: str) -> bool:
        """Check if a hash needs to be updated (e.g., work factor changed).

        Args:
            hashed: Password hash to check

        Returns:
            True if hash should be regenerated
        """
        return self._context.needs_update(hashed)


# Default hasher instance
password_hasher = PasswordHasher()
