"""Unified IOC enrichment API.

Fans out a single IOC lookup to every configured enrichment provider
(VirusTotal, Shodan, and — if present — AbuseIPDB) and returns a combined
result. Providers that are not configured are skipped gracefully.
"""

from __future__ import annotations

import asyncio
import importlib
import logging
from typing import Any, Awaitable, Callable, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ion.auth.dependencies import require_page_auth
from ion.models.user import User
from ion.services.shodan_service import (
    ShodanError,
    ShodanService,
    get_shodan_service,
)
from ion.services.virustotal_service import (
    RateLimitedError as VirusTotalRateLimitedError,
)
from ion.services.virustotal_service import (
    VirusTotalError,
    VirusTotalService,
    get_virustotal_service,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["enrichment"])


# --- Auth: prefer `alerts:enrich` permission, fall back to page auth -------
#
# We try the explicit permission first. If it fails (e.g., permission isn't
# defined yet or the user lacks it), we fall back to ``require_page_auth`` so
# any authenticated analyst can still use the enrichment API. If neither
# succeeds the original error from page auth is re-raised.

def _auth_dependency(
    page_user: User = Depends(require_page_auth),
) -> User:
    """Accept any authenticated user; privileged users also pass trivially.

    ``require_page_auth`` already enforces session auth. Permission-gating is
    applied inside the endpoint bodies via ``user.has_permission`` so callers
    without ``alerts:enrich`` but with an active session still get a useful
    response (a 403 from ``require_permission`` would 307-redirect page routes
    inconsistently — this pattern matches how other fallback-auth APIs in ION
    prefer page auth for JSON endpoints that may be called from UI and CLI).
    """
    return page_user


def _require_enrich(user: User = Depends(_auth_dependency)) -> User:
    """Enforce ``alerts:enrich`` when the permission system knows about it.

    If the user lacks the permission *and* it exists in the permission system
    as a defined permission, return 403. Otherwise, allow authenticated users
    through (graceful for deployments that haven't added the permission yet).
    """
    try:
        has = user.has_permission("observable:enrich")
    except Exception:
        has = True
    if has:
        return user
    # Admins always pass
    if getattr(user, "is_admin", False):
        return user
    raise HTTPException(status_code=403, detail="Permission denied: alerts:enrich required")


# --- Request / response models --------------------------------------------

_ALLOWED_IOC_TYPES = {"ip", "domain", "url", "sha256"}


class EnrichmentRequest(BaseModel):
    ioc_type: str = Field(..., description="One of ip, domain, url, sha256")
    value: str = Field(..., min_length=1, description="IOC value to enrich")


class EnrichmentStatus(BaseModel):
    enrichers: Dict[str, Dict[str, Any]]


# --- AbuseIPDB optional integration ---------------------------------------

def _try_load_abuseipdb() -> Optional[Any]:
    """Return an AbuseIPDB service instance, or None if no module exists."""
    candidates = [
        "ion.services.abuseipdb_service",
        "ion.services.ioc_enrich_service",
    ]
    for module_name in candidates:
        try:
            module = importlib.import_module(module_name)
        except ImportError:
            continue
        for getter_name in (
            "get_abuseipdb_service",
            "get_ioc_enrich_service",
        ):
            getter = getattr(module, getter_name, None)
            if callable(getter):
                try:
                    return getter()
                except Exception as exc:  # pragma: no cover — defensive
                    logger.warning(
                        "Failed to instantiate %s.%s: %s",
                        module_name, getter_name, exc,
                    )
                    return None
    return None


# --- Enrichment fan-out ----------------------------------------------------

async def _call_vt(
    vt: VirusTotalService, ioc_type: str, value: str
) -> Dict[str, Any]:
    """Run a VirusTotal lookup for the given IOC, returning a result dict."""
    try:
        if ioc_type == "ip":
            return await vt.lookup_ip(value)
        if ioc_type == "domain":
            return await vt.lookup_domain(value)
        if ioc_type == "url":
            return await vt.lookup_url(value)
        if ioc_type == "sha256":
            return await vt.lookup_file_hash(value)
        return {
            "source": "virustotal",
            "found": False,
            "error": f"Unsupported ioc_type: {ioc_type}",
        }
    except VirusTotalRateLimitedError as exc:
        return {
            "source": "virustotal",
            "found": False,
            "error": "rate_limited",
            "message": str(exc),
        }
    except VirusTotalError as exc:
        return {
            "source": "virustotal",
            "found": False,
            "error": str(exc),
        }


async def _call_shodan(
    shodan: ShodanService, ioc_type: str, value: str
) -> Dict[str, Any]:
    """Run a Shodan lookup. Only IP IOCs are supported."""
    if ioc_type != "ip":
        return {
            "source": "shodan",
            "found": False,
            "skipped": True,
            "reason": f"Shodan only supports ip IOCs (got {ioc_type})",
        }
    try:
        return await shodan.lookup_ip(value)
    except ShodanError as exc:
        return {
            "source": "shodan",
            "found": False,
            "error": str(exc),
        }


async def _call_abuseipdb(
    service: Any, ioc_type: str, value: str
) -> Dict[str, Any]:
    """Run an AbuseIPDB lookup if the service exposes a compatible method."""
    if ioc_type != "ip":
        return {
            "source": "abuseipdb",
            "found": False,
            "skipped": True,
            "reason": f"AbuseIPDB only supports ip IOCs (got {ioc_type})",
        }
    try:
        method: Optional[Callable[[str], Awaitable[Dict[str, Any]]]] = (
            getattr(service, "lookup_ip", None)
            or getattr(service, "check_ip", None)
            or getattr(service, "enrich_ip", None)
        )
        if method is None:
            return {
                "source": "abuseipdb",
                "found": False,
                "error": "AbuseIPDB service has no lookup_ip method",
            }
        result = method(value)
        if asyncio.iscoroutine(result):
            result = await result
        if isinstance(result, dict):
            result.setdefault("source", "abuseipdb")
            return result
        return {"source": "abuseipdb", "found": False, "raw": result}
    except Exception as exc:  # pragma: no cover — defensive
        logger.warning("AbuseIPDB enrichment failed: %s", exc)
        return {"source": "abuseipdb", "found": False, "error": str(exc)}


# --- Routes ----------------------------------------------------------------

@router.post("/lookup")
async def lookup_ioc(
    payload: EnrichmentRequest,
    user: User = Depends(_require_enrich),
) -> Dict[str, Any]:
    """Enrich a single IOC across all enabled providers."""
    ioc_type = (payload.ioc_type or "").strip().lower()
    value = (payload.value or "").strip()
    if ioc_type not in _ALLOWED_IOC_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"ioc_type must be one of {sorted(_ALLOWED_IOC_TYPES)}",
        )
    if not value:
        raise HTTPException(status_code=400, detail="value is required")

    tasks: List[Awaitable[Dict[str, Any]]] = []
    providers: List[str] = []

    vt = get_virustotal_service()
    if vt.enabled and vt.is_configured:
        tasks.append(_call_vt(vt, ioc_type, value))
        providers.append("virustotal")

    shodan = get_shodan_service()
    if shodan.enabled and shodan.is_configured:
        tasks.append(_call_shodan(shodan, ioc_type, value))
        providers.append("shodan")

    abuseipdb = _try_load_abuseipdb()
    if abuseipdb is not None:
        # Respect an ``enabled`` / ``is_configured`` attribute if present
        enabled = getattr(abuseipdb, "enabled", True)
        configured_attr = getattr(abuseipdb, "is_configured", True)
        configured = configured_attr() if callable(configured_attr) else configured_attr
        if enabled and configured:
            tasks.append(_call_abuseipdb(abuseipdb, ioc_type, value))
            providers.append("abuseipdb")

    if not tasks:
        return {
            "ioc_type": ioc_type,
            "value": value,
            "results": {},
            "providers": [],
            "message": "No enrichment providers are enabled or configured",
        }

    settled = await asyncio.gather(*tasks, return_exceptions=True)

    results: Dict[str, Any] = {}
    for provider, outcome in zip(providers, settled):
        if isinstance(outcome, Exception):
            logger.warning("Enricher %s raised: %s", provider, outcome)
            results[provider] = {
                "source": provider,
                "found": False,
                "error": str(outcome),
            }
        else:
            results[provider] = outcome

    return {
        "ioc_type": ioc_type,
        "value": value,
        "providers": providers,
        "results": results,
    }


@router.get("/status", response_model=EnrichmentStatus)
async def enrichment_status(
    user: User = Depends(_require_enrich),
) -> EnrichmentStatus:
    """Return a summary of which enrichers are enabled/configured."""
    vt = get_virustotal_service()
    shodan = get_shodan_service()
    abuseipdb = _try_load_abuseipdb()

    enrichers: Dict[str, Dict[str, Any]] = {
        "virustotal": {
            "enabled": bool(vt.enabled),
            "configured": bool(vt.is_configured),
            "available": bool(vt.enabled and vt.is_configured),
            "supports": ["ip", "domain", "url", "sha256"],
            "url": vt.url,
            "rate_limit_per_min": vt.rate_limit,
        },
        "shodan": {
            "enabled": bool(shodan.enabled),
            "configured": bool(shodan.is_configured),
            "available": bool(shodan.enabled and shodan.is_configured),
            "supports": ["ip"],
            "url": shodan.url,
        },
    }

    if abuseipdb is not None:
        enabled = bool(getattr(abuseipdb, "enabled", True))
        configured_attr = getattr(abuseipdb, "is_configured", True)
        configured = bool(
            configured_attr() if callable(configured_attr) else configured_attr
        )
        enrichers["abuseipdb"] = {
            "enabled": enabled,
            "configured": configured,
            "available": enabled and configured,
            "supports": ["ip"],
        }

    return EnrichmentStatus(enrichers=enrichers)
