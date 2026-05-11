"""CyAB Data Health service.

Aggregates three signals per system for the Data Health tab:
  1. Ingestion freshness  - last event seen per data source, SLA pill
  2. Field mapping        - % of expected fields present in declared mapping
  3. Coverage rollup      - wraps cyab_subprofile_service.system_coverage()

Phase 2 will add a 4th panel (Reconciliation drift vs CMDB).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from ion.models.cyab import CyabDataSource

# Per-source-type expected ECS fields. Drives "field mapping completeness".
# Conservative defaults; expand as new source types are added.
EXPECTED_FIELDS_BY_TYPE: Dict[str, List[str]] = {
    "windows-evtx":     ["@timestamp", "host.name", "event.code", "user.name"],
    "generic-syslog":   ["@timestamp", "host.name", "message"],
    "linux-auditd":     ["@timestamp", "host.name", "user.name", "process.name"],
    "aws-cloudtrail":   ["@timestamp", "user.name", "event.action", "source.ip"],
    "office365":        ["@timestamp", "user.name", "event.action", "source.ip"],
    "okta":             ["@timestamp", "user.name", "event.action", "source.ip"],
    "azure-ad":         ["@timestamp", "user.name", "event.action", "source.ip"],
    "edr-generic":      ["@timestamp", "host.name", "process.name", "user.name"],
}

# SLA: how stale a source can get before the freshness pill turns amber/red.
DEFAULT_SLA_AMBER_SECONDS = 60 * 60        # 1 hour
DEFAULT_SLA_RED_SECONDS   = 60 * 60 * 24   # 24 hours


def _sla_status(last_event_at: Optional[datetime]) -> str:
    """Map last-event timestamp to a status pill: 'fresh' | 'amber' | 'red' | 'unknown'."""
    if last_event_at is None:
        return "unknown"
    age = (datetime.now(timezone.utc) - last_event_at).total_seconds()
    if age < DEFAULT_SLA_AMBER_SECONDS:
        return "fresh"
    if age < DEFAULT_SLA_RED_SECONDS:
        return "amber"
    return "red"


def _parse_field_mapping(raw: Any) -> Dict[str, Any]:
    """field_mapping is stored as JSON-encoded text on CyabDataSource (Task 6).

    Accept any of: None, '' (empty string), JSON-encoded string, or a dict
    (the dict form is convenient for tests and forward-compat).
    """
    if raw is None or raw == "":
        return {}
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def ingestion_freshness(session: Session, system_id: int) -> List[Dict[str, Any]]:
    """Return per-source rows: {source_id, source_name, last_event_at, sla_status}.

    Phase-1 implementation reads ``last_event_at`` from CyabDataSource (populated
    by a future background sync; defaults to None for now -> 'unknown' pill).
    The attribute may not exist on the model yet; ``getattr`` returns None.
    Phase-2 may query Elasticsearch directly per source.
    """
    sources = session.execute(
        select(CyabDataSource).where(CyabDataSource.system_id == system_id)
    ).scalars().all()

    rows: List[Dict[str, Any]] = []
    for src in sources:
        last = getattr(src, "last_event_at", None)
        rows.append({
            "source_id":        src.id,
            "source_name":      src.name,
            "data_source_type": src.data_source_type,
            "last_event_at":    last,
            "sla_status":       _sla_status(last),
        })
    return rows


def field_mapping_completeness(session: Session, system_id: int) -> List[Dict[str, Any]]:
    """Per-source rows: {source_id, source_name, completeness (0..1), missing_fields, expected_fields}.

    Sources of an unknown ``data_source_type`` (no expected-field profile) report
    ``completeness: None`` and a ``note`` so the UI can show 'n/a' rather than 0%.
    """
    sources = session.execute(
        select(CyabDataSource).where(CyabDataSource.system_id == system_id)
    ).scalars().all()

    rows: List[Dict[str, Any]] = []
    for src in sources:
        expected = EXPECTED_FIELDS_BY_TYPE.get(src.data_source_type or "", [])
        mapping = _parse_field_mapping(src.field_mapping)
        if not expected:
            rows.append({
                "source_id":       src.id,
                "source_name":     src.name,
                "completeness":    None,
                "missing_fields":  [],
                "expected_fields": [],
                "note":            "No expected-field profile for source type.",
            })
            continue
        missing = [f for f in expected if f not in mapping]
        completeness = (len(expected) - len(missing)) / len(expected)
        rows.append({
            "source_id":       src.id,
            "source_name":     src.name,
            "completeness":    completeness,
            "missing_fields":  missing,
            "expected_fields": expected,
        })
    return rows


def coverage_rollup(session: Session, system_id: int) -> Dict[str, Any]:
    """Wraps ``cyab_subprofile_service.system_coverage`` for the Data Health panel."""
    from ion.services.cyab_subprofile_service import system_coverage
    return system_coverage(session, system_id)


def reconciliation_panel(session: Session, system_id: int) -> Dict[str, Any]:
    """Phase 2 stub. Returns a 'coming soon' marker for the UI to show greyed-out."""
    return {
        "available": False,
        "reason":    "Reconciliation requires CMDB integration (Phase 2).",
    }
