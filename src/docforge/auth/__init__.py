"""Authentication and authorization module for DocForge."""

from docforge.auth.password import PasswordHasher
from docforge.auth.service import AuthService
from docforge.auth.dependencies import (
    get_current_user,
    get_current_user_optional,
    get_current_user_hybrid,
    require_permission,
    require_any_permission,
    require_admin,
)
from docforge.auth.oidc_config import OIDCConfig
from docforge.auth.oidc import (
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
