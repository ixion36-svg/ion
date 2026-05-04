"""Authentication and authorization module for ION."""

from ion.auth.dependencies import (
    get_current_user,
    get_current_user_hybrid,
    get_current_user_optional,
    require_admin,
    require_any_permission,
    require_permission,
)
from ion.auth.oidc import (
    OIDCTokenData,
    OIDCUserSync,
    OIDCValidationError,
    OIDCValidator,
)
from ion.auth.oidc_config import OIDCConfig
from ion.auth.password import PasswordHasher
from ion.auth.service import AuthService

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
