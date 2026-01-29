"""Authentication and authorization module for IXION."""

from ixion.auth.password import PasswordHasher
from ixion.auth.service import AuthService
from ixion.auth.dependencies import (
    get_current_user,
    get_current_user_optional,
    get_current_user_hybrid,
    require_permission,
    require_any_permission,
    require_admin,
)
from ixion.auth.oidc_config import OIDCConfig
from ixion.auth.oidc import (
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
