"""Authentication and authorization module for ION."""

from ion.auth.password import PasswordHasher
from ion.auth.service import AuthService
from ion.auth.dependencies import (
    get_current_user,
    get_current_user_optional,
    get_current_user_hybrid,
    require_permission,
    require_any_permission,
    require_admin,
)
from ion.auth.oidc_config import OIDCConfig
from ion.auth.oidc import (
    OIDCValidator,
    OIDCUserSync,
    OIDCTokenData,
    OIDCValidationError,
)

__all__ = [
    "PasswordHasher",
    "AuthService",
    "get_current_user",
    "get_current_user_optional",
    "get_current_user_hybrid",
    "require_permission",
    "require_any_permission",
    "require_admin",
    # OIDC components
    "OIDCConfig",
    "OIDCValidator",
    "OIDCUserSync",
    "OIDCTokenData",
    "OIDCValidationError",
]
