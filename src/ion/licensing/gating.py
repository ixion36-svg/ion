"""Optional-module availability gating.

Availability is deliberately split from entitlement so the licensing machinery
can ship dormant:

* ``de_license_enforced`` (ION_DE_LICENSE_ENFORCED) is the master switch and
  defaults **off**. While off, the DE module behaves exactly as it did before
  licensing existed — mounted, RBAC-gated, no licence required.
* When enforcement is turned on, DE is available only if the operator flag
  ``de_module_enabled`` is set **and** a validly-signed licence names the
  module. Expiry is informational (a signed-but-expired licence still entitles),
  per the deployment's air-gap posture.
"""

from __future__ import annotations

import logging

from ion.core.config import get_config
from ion.licensing.licence_service import get_licence_service

logger = logging.getLogger(__name__)

MODULE_DE = "detection_engineering"


def de_module_available() -> bool:
    """Whether the Detection Engineering module should be mounted/shown."""
    cfg = get_config()
    if not cfg.de_license_enforced:
        return True  # dormant: pre-licensing behaviour
    if not cfg.de_module_enabled:
        return False
    return get_licence_service().status().entitles(MODULE_DE)


def de_module_status() -> dict:
    """Human-facing status for startup logging and the nav/UI."""
    cfg = get_config()
    st = get_licence_service().status()
    return {
        "available": de_module_available(),
        "enforced": cfg.de_license_enforced,
        "flag_enabled": cfg.de_module_enabled,
        "licensed": st.entitles(MODULE_DE),
        "customer_id": st.customer_id,
        "expired": st.expired,
    }


def require_de_module() -> None:
    """FastAPI dependency: 404 when the DE module is not available.

    404 (not 403) so a licence-gated deployment exposes nothing — the endpoint
    is indistinguishable from one that does not exist, matching the opt-in-SOAR
    pattern in response_api.
    """
    from fastapi import HTTPException

    if not de_module_available():
        raise HTTPException(status_code=404, detail="Not found")
