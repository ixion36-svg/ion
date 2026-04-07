"""PCAP file upload and analysis API."""

import logging
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.models.user import User

logger = logging.getLogger(__name__)

router = APIRouter(tags=["pcap"])

MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB
ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}


@router.post("/analyze")
async def analyze_pcap(
    file: UploadFile = File(...),
    user: User = Depends(require_permission("alert:read")),
):
    """Upload and analyze a PCAP file, then enrich external IPs/domains."""
    # Validate extension
    filename = file.filename or "upload.pcap"
    ext = ""
    for e in ALLOWED_EXTENSIONS:
        if filename.lower().endswith(e):
            ext = e
            break
    if not ext:
        raise HTTPException(400, f"Unsupported file type. Allowed: {', '.join(ALLOWED_EXTENSIONS)}")

    # Read file content
    content = await file.read()
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(400, f"File too large. Maximum size: {MAX_FILE_SIZE // (1024 * 1024)} MB")
    if len(content) == 0:
        raise HTTPException(400, "Empty file")

    # Parse
    try:
        from ion.services.pcap_service import parse_pcap, _is_private
        result = parse_pcap(content, filename)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(500, f"Analysis failed: {e}")

    response = result.to_dict()

    # Extract and enrich observables (non-blocking — failures don't break the response)
    try:
        enrichments = await _enrich_pcap_observables(result, _is_private)
        if enrichments:
            response["threat_intel"] = enrichments
    except Exception as e:
        logger.warning("PCAP observable enrichment failed: %s", e)
        response["threat_intel"] = {"error": str(e), "observables": []}

    return response


async def _enrich_pcap_observables(result, is_private_fn) -> dict:
    """Extract external IPs and domains from PCAP results, create observables, enrich via OpenCTI."""
    from ion.services.observable_service import ObservableService
    from ion.models.observable import ObservableType
    from ion.storage.database import get_engine, get_session_factory
    from ion.core.config import get_config

    config = get_config()
    engine = get_engine(config.db_path)
    factory = get_session_factory(engine)
    session = factory()

    try:
        obs_service = ObservableService(session)

        # Collect unique external IPs
        seen_ips = set()
        for entry in (result.top_src_ips or []) + (result.top_dst_ips or []):
            ip = entry.get("ip", "") if isinstance(entry, dict) else str(entry)
            if ip and not is_private_fn(ip) and ip not in seen_ips:
                seen_ips.add(ip)

        # Collect unique domains from DNS + TLS SNI
        seen_domains = set()
        for entry in result.dns_queries or []:
            q = entry.get("query", "") if isinstance(entry, dict) else str(entry)
            if q and q != "." and not q.endswith(".local"):
                seen_domains.add(q.rstrip(".").lower())
        for entry in result.tls_handshakes or []:
            sni = entry.get("sni", "") if isinstance(entry, dict) else str(entry)
            if sni and not sni.endswith(".local"):
                seen_domains.add(sni.lower())

        observables = []

        # Create IP observables
        for ip in list(seen_ips)[:50]:  # Cap at 50 to avoid flooding
            try:
                obs, created = obs_service.get_or_create(ObservableType.IPV4, ip)
                observables.append(obs)
            except Exception as e:
                logger.debug("Failed to create observable for IP %s: %s", ip, e)

        # Create domain observables
        for domain in list(seen_domains)[:50]:
            try:
                obs, created = obs_service.get_or_create(ObservableType.DOMAIN, domain)
                observables.append(obs)
            except Exception as e:
                logger.debug("Failed to create observable for domain %s: %s", domain, e)

        session.commit()

        # Enrich via OpenCTI
        enriched = []
        for obs in observables:
            entry = {
                "type": obs.type.value if hasattr(obs.type, "value") else str(obs.type),
                "value": obs.value,
                "observable_id": obs.id,
                "threat_level": obs.threat_level.value if hasattr(obs.threat_level, "value") else str(obs.threat_level),
                "sighting_count": obs.sighting_count,
                "enrichment": None,
            }
            try:
                enrichment = await obs_service.enrich(obs.id, source="opencti")
                if enrichment:
                    entry["threat_level"] = obs.threat_level.value if hasattr(obs.threat_level, "value") else str(obs.threat_level)
                    entry["enrichment"] = {
                        "source": enrichment.source,
                        "is_malicious": enrichment.is_malicious,
                        "score": enrichment.score,
                        "labels": enrichment.labels or [],
                        "threat_actors": enrichment.threat_actors or [],
                        "reports": enrichment.reports or [],
                    }
            except Exception as e:
                logger.debug("Enrichment failed for %s: %s", obs.value, e)

            enriched.append(entry)

        session.commit()

        # Sort: malicious first, then by score descending
        enriched.sort(key=lambda x: (
            -((x.get("enrichment") or {}).get("score") or 0),
            0 if (x.get("enrichment") or {}).get("is_malicious") else 1,
        ))

        malicious_count = sum(1 for e in enriched if e.get("enrichment", {}) and e["enrichment"].get("is_malicious"))
        return {
            "total": len(enriched),
            "malicious_count": malicious_count,
            "ips_checked": len(seen_ips),
            "domains_checked": len(seen_domains),
            "observables": enriched,
        }

    except Exception as e:
        session.rollback()
        raise
    finally:
        session.close()
