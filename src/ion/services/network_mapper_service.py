"""Network Mapper — live asset inventory synced from Elasticsearch.

Periodically queries logs-* for unique hostnames via composite aggregation,
extracts OS / IP / MAC metadata from the latest event per host, and upserts
into the network_assets / network_asset_ips / network_asset_macs tables.

All sync operations are idempotent. Re-running with the same data is a no-op
(last_seen / event_count are updated, IP/MAC rows are upserted).
"""

import logging
import os
import threading
import time
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from ion.models.network_asset import NetworkAsset, NetworkAssetIP, NetworkAssetMAC

logger = logging.getLogger(__name__)

_SYNC_INTERVAL = int(os.environ.get("ION_NETMAP_INTERVAL_S", "120"))
_LOOKBACK_MINUTES = int(os.environ.get("ION_NETMAP_LOOKBACK_MIN", "10"))
_INDEX_PATTERN = os.environ.get("ION_NETMAP_INDEX", "logs-*")
_BUCKET_SIZE = 500


async def sync_once(lookback_minutes: int = _LOOKBACK_MINUTES) -> dict[str, int]:
    """Run one sync cycle: query ES, upsert into Postgres.

    Returns {"hosts_processed": N, "ips_upserted": N, "macs_upserted": N}.
    """
    from ion.services.elasticsearch_service import ElasticsearchService, ElasticsearchError

    es = ElasticsearchService()
    if not es.is_configured:
        return {"hosts_processed": 0, "error": "ES not configured"}

    stats = {"hosts_processed": 0, "ips_upserted": 0, "macs_upserted": 0}
    after_key = None

    while True:
        buckets, after_key = await _fetch_host_page(es, lookback_minutes, after_key)
        if not buckets:
            break
        _upsert_batch(buckets, stats)
        if after_key is None:
            break

    logger.info(
        "netmap sync: %d hosts, %d IPs, %d MACs",
        stats["hosts_processed"], stats["ips_upserted"], stats["macs_upserted"],
    )
    return stats


async def _fetch_host_page(
    es: Any,
    lookback_minutes: int,
    after_key: Optional[dict],
) -> tuple[list[dict], Optional[dict]]:
    """One page of the composite aggregation on host.hostname."""
    from ion.services.elasticsearch_service import ElasticsearchError

    agg: dict[str, Any] = {
        "composite": {
            "size": _BUCKET_SIZE,
            "sources": [{"hostname": {"terms": {"field": "host.hostname"}}}],
        },
        "aggs": {
            "latest": {
                "top_hits": {
                    "size": 1,
                    "sort": [{"@timestamp": "desc"}],
                    "_source": [
                        "host.hostname", "host.os.name", "host.os.version",
                        "host.os.family", "host.os.platform", "host.architecture",
                        "host.ip", "host.mac",
                        "source.ip", "destination.ip",
                        "system", "data_stream.namespace",
                        "@timestamp", "_index",
                    ],
                },
            },
            "doc_count_total": {"value_count": {"field": "@timestamp"}},
        },
    }
    if after_key:
        agg["composite"]["after"] = after_key

    body: dict[str, Any] = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"exists": {"field": "host.hostname"}},
                    {"range": {"@timestamp": {"gte": f"now-{lookback_minutes}m"}}},
                ],
            },
        },
        "aggs": {"hosts": agg},
    }

    try:
        encoded = _INDEX_PATTERN.replace(",", "%2C")
        result = await es._request("POST", f"/{encoded}/_search", json=body)
    except ElasticsearchError as e:
        logger.warning("netmap ES query failed: %s", e)
        return [], None
    except Exception as e:
        logger.warning("netmap ES unexpected: %s", e)
        return [], None

    hosts_agg = result.get("aggregations", {}).get("hosts", {})
    raw_buckets = hosts_agg.get("buckets", [])
    next_key = hosts_agg.get("after_key")

    parsed = []
    for b in raw_buckets:
        hostname = b.get("key", {}).get("hostname")
        if not hostname:
            continue
        hits = b.get("latest", {}).get("hits", {}).get("hits", [])
        src = hits[0].get("_source", {}) if hits else {}
        index_name = hits[0].get("_index", "") if hits else ""
        doc_count = b.get("doc_count_total", {}).get("value", b.get("doc_count", 1))

        # Flatten nested objects via dotted-path helper
        def _f(d: dict, path: str):
            parts = path.split(".")
            cur = d
            for p in parts:
                if isinstance(cur, dict):
                    cur = cur.get(p)
                else:
                    return None
            return cur

        host_obj = src.get("host") if isinstance(src.get("host"), dict) else {}
        os_obj = host_obj.get("os") if isinstance(host_obj.get("os"), dict) else {}

        # IP list — host.ip is typically an array
        ips_raw = host_obj.get("ip") or []
        if isinstance(ips_raw, str):
            ips_raw = [ips_raw]
        # Also pull source.ip / destination.ip for standalone IP tracking
        for ip_field in ("source.ip", "destination.ip"):
            v = _f(src, ip_field)
            if v and isinstance(v, str) and v not in ips_raw:
                ips_raw.append(v)
            elif isinstance(v, list):
                ips_raw.extend(x for x in v if x not in ips_raw)

        macs_raw = host_obj.get("mac") or []
        if isinstance(macs_raw, str):
            macs_raw = [macs_raw]

        # Source systems: system field + data_stream.namespace
        source_systems = set()
        sys_field = src.get("system")
        if isinstance(sys_field, str) and sys_field:
            source_systems.add(sys_field)
        ds_ns = _f(src, "data_stream.namespace")
        if isinstance(ds_ns, str) and ds_ns:
            source_systems.add(ds_ns)

        ts_raw = src.get("@timestamp")
        try:
            ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00")) if ts_raw else datetime.now(timezone.utc)
        except Exception:
            ts = datetime.now(timezone.utc)

        parsed.append({
            "hostname": hostname.strip().lower(),
            "display_hostname": (host_obj.get("hostname") or hostname).strip(),
            "os_name": os_obj.get("name"),
            "os_version": os_obj.get("version"),
            "os_family": os_obj.get("family"),
            "os_platform": os_obj.get("platform"),
            "architecture": host_obj.get("architecture"),
            "ips": [str(ip) for ip in ips_raw if ip],
            "macs": [str(m).lower() for m in macs_raw if m],
            "source_systems": sorted(source_systems),
            "timestamp": ts,
            "index": index_name,
            "doc_count": int(doc_count),
        })

    return parsed, next_key


def _upsert_batch(batch: list[dict], stats: dict) -> None:
    """Upsert a batch of host records into Postgres."""
    from ion.storage.database import get_session_factory

    session = get_session_factory()()
    try:
        for rec in batch:
            _upsert_one(session, rec, stats)
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def _upsert_one(session: Session, rec: dict, stats: dict) -> None:
    """Upsert a single host + its IPs and MACs."""
    now = rec["timestamp"]
    asset = session.query(NetworkAsset).filter_by(hostname=rec["hostname"]).first()

    if asset is None:
        asset = NetworkAsset(
            hostname=rec["hostname"],
            display_hostname=rec["display_hostname"],
            os_name=rec.get("os_name"),
            os_version=rec.get("os_version"),
            os_family=rec.get("os_family"),
            os_platform=rec.get("os_platform"),
            architecture=rec.get("architecture"),
            first_seen=now,
            last_seen=now,
            event_count=rec["doc_count"],
            last_index=rec.get("index"),
            source_systems=rec.get("source_systems", []),
        )
        session.add(asset)
        session.flush()
    else:
        # Update — latest-wins for OS metadata, additive for counts/systems
        if now > asset.last_seen:
            asset.last_seen = now
        asset.event_count = (asset.event_count or 0) + rec["doc_count"]
        asset.last_index = rec.get("index") or asset.last_index
        asset.display_hostname = rec["display_hostname"] or asset.display_hostname
        for field in ("os_name", "os_version", "os_family", "os_platform", "architecture"):
            new_val = rec.get(field)
            if new_val:
                setattr(asset, field, new_val)
        # Merge source systems
        existing = set(asset.source_systems or [])
        existing.update(rec.get("source_systems", []))
        asset.source_systems = sorted(existing)
        session.flush()

    stats["hosts_processed"] += 1

    # Upsert IPs
    for ip in rec.get("ips", []):
        existing_ip = (
            session.query(NetworkAssetIP)
            .filter_by(asset_id=asset.id, ip=ip)
            .first()
        )
        if existing_ip is None:
            session.add(NetworkAssetIP(
                asset_id=asset.id, ip=ip,
                first_seen=now, last_seen=now, event_count=1,
            ))
            stats["ips_upserted"] += 1
        else:
            if now > existing_ip.last_seen:
                existing_ip.last_seen = now
            existing_ip.event_count += 1
            stats["ips_upserted"] += 1

    # Upsert MACs
    for mac in rec.get("macs", []):
        existing_mac = (
            session.query(NetworkAssetMAC)
            .filter_by(asset_id=asset.id, mac=mac)
            .first()
        )
        if existing_mac is None:
            session.add(NetworkAssetMAC(
                asset_id=asset.id, mac=mac,
                first_seen=now, last_seen=now,
            ))
            stats["macs_upserted"] += 1
        else:
            if now > existing_mac.last_seen:
                existing_mac.last_seen = now
            stats["macs_upserted"] += 1


# ── Background loop ──────────────────────────────────────────────────────

_stop_event = threading.Event()


def start_background_loop(interval_s: int = _SYNC_INTERVAL) -> None:
    """Run sync_once in a loop on a background thread.

    Meant to be called from server.py startup inside a run_locked() guard
    so only one uvicorn worker runs it.
    """
    import asyncio

    def _loop():
        logger.info("Network Mapper background sync started (interval: %ds)", interval_s)
        while not _stop_event.is_set():
            try:
                asyncio.run(sync_once())
            except Exception as e:
                logger.warning("Network Mapper sync error: %s", e)
            _stop_event.wait(interval_s)
        logger.info("Network Mapper background sync stopped")

    t = threading.Thread(target=_loop, daemon=True, name="netmap-sync")
    t.start()


def stop_background_loop() -> None:
    _stop_event.set()
