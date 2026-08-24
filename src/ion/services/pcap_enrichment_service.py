"""Threat-intel enrichment for PCAP analysis results.

Shared by the manual analyzer (``/api/pcap/analyze``) and the Arkime
auto-case pipeline (``pcap_analysis_service``): extract external IPs and
domains from a parsed ``PcapResult``, create Observable rows, enrich them
via OpenCTI, and answer "have we seen this before?" from ION's own
observable→case link history.
"""

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


async def enrich_pcap_observables(result, is_private_fn) -> dict:
    """Extract external IPs and domains from PCAP results, create observables, enrich via OpenCTI."""
    from ion.core.config import get_config
    from ion.models.observable import ObservableType
    from ion.services.observable_service import ObservableService
    from ion.storage.database import get_engine, get_session_factory

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

    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def ti_findings(enrichments: dict) -> list:
    """Build finding dicts for pcap observables that threat intel flags known-bad."""
    out = []
    for e in (enrichments.get("observables") or []):
        enr = e.get("enrichment") or {}
        score = enr.get("score") or 0
        if not (enr.get("is_malicious") or score >= 75):
            continue
        labels = ", ".join(enr.get("labels") or [])
        actors = ", ".join(enr.get("threat_actors") or [])
        out.append({
            "category": "Threat Intel Match",
            "severity": "critical" if enr.get("is_malicious") else "high",
            "title": f"Known-bad {e.get('type', 'observable')} in traffic: {e.get('value', '?')}",
            "detail": f"Observable {e.get('value', '?')} matched threat intel "
                      f"(source {enr.get('source', '?')}, score {score})"
                      + (f"; labels: {labels}" if labels else "")
                      + (f"; actors: {actors}" if actors else "") + ".",
            "mitre": [],
        })
    return out


def seen_before_for_case(
    entries: List[Dict[str, Any]],
    case_id: int,
    limit: int = 8,
) -> Optional[List[Dict[str, Any]]]:
    """Prior-case history for enriched PCAP observables.

    ``entries`` is the ``observables`` list from ``enrich_pcap_observables``.
    Returns per-observable rows for those already linked to at least one case
    OTHER than ``case_id`` (must run before the current case's links are
    written, or the answer includes ourselves), or ``[]`` when every
    observable is new to ION. ``None`` only on total failure, so callers can
    distinguish "checked, nothing prior" from "could not check". Capped to
    ``limit`` rows, most-linked first.
    """
    if not entries:
        return []
    try:
        from ion.core.config import get_config
        from ion.models.alert_triage import AlertCase
        from ion.models.observable import ObservableLink, ObservableLinkType
        from ion.storage.database import get_engine, get_session_factory
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("pcap_enrichment: cannot import deps for seen-before: %s", exc)
        return None

    config = get_config()
    engine = get_engine(config.db_path)
    factory = get_session_factory(engine)
    session = factory()
    try:
        out: List[Dict[str, Any]] = []
        for e in entries:
            oid = e.get("observable_id")
            if not oid:
                continue
            try:
                links = (
                    session.query(ObservableLink)
                    .filter(
                        ObservableLink.observable_id == oid,
                        ObservableLink.link_type == ObservableLinkType.CASE,
                        ObservableLink.entity_id != case_id,
                    )
                    .all()
                )
                prior_case_ids = {link.entity_id for link in links}
                if not prior_case_ids:
                    continue
                last_case = (
                    session.query(AlertCase)
                    .filter(AlertCase.id.in_(prior_case_ids))
                    .order_by(AlertCase.created_at.desc())
                    .first()
                )
                out.append({
                    "value": e.get("value"),
                    "type": e.get("type"),
                    "prior_case_count": len(prior_case_ids),
                    "last_case_number": last_case.case_number if last_case else None,
                    "malicious": bool((e.get("enrichment") or {}).get("is_malicious")),
                })
            except Exception as exc:
                logger.debug(
                    "pcap_enrichment: seen-before lookup failed for %s: %s",
                    e.get("value"), exc,
                )
        # Flagged observables first, then by how often ION has seen them.
        out.sort(key=lambda r: (not r["malicious"], -r["prior_case_count"]))
        return out[:limit]
    except Exception as exc:
        logger.warning("pcap_enrichment: seen-before pass failed: %s", exc)
        return None
    finally:
        session.close()
