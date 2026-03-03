"""Password hashing utilities using bcrypt."""

from passlib.context import CryptContext


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
