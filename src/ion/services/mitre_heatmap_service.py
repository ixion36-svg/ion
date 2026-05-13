"""MITRE ATT&CK coverage heatmap service (v0.22.0).

Read-only service. Compares three signals per technique:
  1. CyAB catalogue declared coverage (shipped use cases)
  2. Alert-side observations (alert_triage.mitre_techniques)
  3. Pin observations (case_evidence_pins + forensic_case_pins)

Air-gap constraint: technique metadata is loaded from the bundled snapshot
at src/ion/data/attack_techniques.json — never fetched at runtime.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from sqlalchemy import text
from sqlalchemy.orm import Session

from ion.models.cyab import CyabDataSource
from ion.models.cyab_subprofile import CyabSubProfile
from ion.services.cyab_subprofile_service import _aggregate_uc_status

_SNAPSHOT_PATH = Path(__file__).parent.parent / "data" / "attack_techniques.json"
_TECHNIQUE_NORM_RE = re.compile(r"^T?(\d{4}(?:\.\d{3})?)$", re.IGNORECASE)

# --------------------------------------------------------------------------
# Technique metadata loader (loaded once, module-level cache)
# --------------------------------------------------------------------------

def _load_snapshot() -> Tuple[Dict[str, dict], Dict[str, str]]:
    """Return (id_to_meta, name_to_id) from the bundled JSON snapshot."""
    raw = json.loads(_SNAPSHOT_PATH.read_text(encoding="utf-8"))
    by_id: Dict[str, dict] = {}
    by_name: Dict[str, str] = {}
    for entry in raw:
        tid = entry["id"].upper()
        by_id[tid] = {
            "name": entry["name"],
            "tactic_ids": entry.get("tactic_ids") or [],
            "is_subtechnique": entry.get("is_subtechnique", False),
            "parent_id": entry.get("parent_id"),
        }
        by_name[entry["name"].lower()] = tid
    return by_id, by_name


_snapshot_cache: Optional[Tuple[Dict[str, dict], Dict[str, str]]] = None


def _get_snapshot() -> Tuple[Dict[str, dict], Dict[str, str]]:
    global _snapshot_cache
    if _snapshot_cache is None:
        _snapshot_cache = _load_snapshot()
    return _snapshot_cache


# --------------------------------------------------------------------------
# Technique ID normalisation
# --------------------------------------------------------------------------

def normalize_technique_id(raw: str) -> Optional[str]:
    """Normalize a raw technique ID to uppercase T-prefixed form.

    Handles: 't1558.003', 'T1558.003', '1558.003', 'T1558' → 'T1558.003' etc.
    Returns None if the string doesn't match the expected pattern.
    """
    m = _TECHNIQUE_NORM_RE.match(raw.strip())
    if not m:
        return None
    return "T" + m.group(1).upper()


# --------------------------------------------------------------------------
# Catalogue signal
# --------------------------------------------------------------------------

def _catalogue_techniques(
    session: Session, system_id: Optional[int]
) -> Dict[str, str]:
    """Return {technique_id: best_status} for all techniques in the CyAB catalogue.

    best_status is the best (highest-rank) use_case_status across all data
    sources fleet-wide (or scoped to system_id if provided), using the same
    rank ladder as _aggregate_uc_status: shipped=3, partial=2, n/a=1, gap=0.
    """
    from sqlalchemy import select

    if system_id is not None:
        sources = list(
            session.scalars(
                select(CyabDataSource).where(CyabDataSource.system_id == system_id)
            ).all()
        )
    else:
        sources = list(session.scalars(select(CyabDataSource)).all())

    subprofiles = list(session.scalars(select(CyabSubProfile)).all())

    # Build {sub_id: [uc_id, ...]} and collect mitre_ids per uc_id.
    uc_to_mitre: Dict[str, List[str]] = {}
    sub_uc_ids: Dict[str, List[str]] = {}

    for sub in subprofiles:
        cat = json.loads(sub.catalogue_json or "{}")
        detections = cat.get("detection_use_cases") or []
        uc_ids = [d["id"] for d in detections if d.get("id")]
        sub_uc_ids[sub.id] = uc_ids
        for uc in detections:
            uc_id = uc.get("id")
            if not uc_id:
                continue
            mitre_ids = uc.get("mitre_ids") or []
            uc_to_mitre[uc_id] = [
                normalize_technique_id(tid)
                for tid in mitre_ids
                if normalize_technique_id(tid)
            ]

    # For each sub-profile, call _aggregate_uc_status to get best status per uc.
    rank = {"shipped": 3, "partial": 2, "n/a": 1, "gap": 0}
    tech_best: Dict[str, str] = {}

    for sub in subprofiles:
        uc_ids = sub_uc_ids.get(sub.id) or []
        if not uc_ids:
            continue
        uc_status = _aggregate_uc_status(sources, sub.id, uc_ids)
        for uc_id, status in uc_status.items():
            for tid in uc_to_mitre.get(uc_id) or []:
                current = tech_best.get(tid, "gap")
                if rank.get(status, 0) > rank.get(current, 0):
                    tech_best[tid] = status

    return tech_best


# --------------------------------------------------------------------------
# Observation queries (Postgres + SQLite compatibility)
# --------------------------------------------------------------------------

def _alert_observations_postgres(session: Session) -> Dict[str, int]:
    """Return {technique_id: distinct_alert_case_count} via LATERAL unnest."""
    sql = text(
        """
        SELECT
            upper(unnested.technique_id) AS tid,
            COUNT(DISTINCT at2.case_id) AS cnt
        FROM alert_triage AS at2
        CROSS JOIN LATERAL json_array_elements_text(at2.mitre_techniques)
            AS unnested(technique_id)
        WHERE at2.case_id IS NOT NULL
          AND at2.mitre_techniques IS NOT NULL
          -- v0.30.1: Postgres `json` type has no `!=` operator; cast to
          -- text so we can compare against the JSON null literal as a
          -- plain string. Without this the heatmap 500s with
          -- "operator does not exist: json <> json".
          AND at2.mitre_techniques::text != 'null'
        GROUP BY upper(unnested.technique_id)
        """
    )
    rows = session.execute(sql).fetchall()
    result: Dict[str, int] = {}
    for tid_raw, cnt in rows:
        tid = normalize_technique_id(tid_raw) if tid_raw else None
        if tid:
            result[tid] = result.get(tid, 0) + int(cnt)
    return result


def _alert_observations_sqlite(session: Session) -> Dict[str, int]:
    """SQLite fallback: fetch rows with mitre_techniques and unnest in Python."""
    sql = text(
        "SELECT mitre_techniques, case_id FROM alert_triage "
        "WHERE case_id IS NOT NULL AND mitre_techniques IS NOT NULL"
    )
    rows = session.execute(sql).fetchall()
    # {case_id: set(technique_ids)} to count distinct cases
    case_sets: Dict[str, set] = defaultdict(set)
    for mt_raw, case_id in rows:
        if mt_raw is None:
            continue
        if isinstance(mt_raw, str):
            try:
                mt = json.loads(mt_raw)
            except (json.JSONDecodeError, TypeError):
                continue
        else:
            mt = mt_raw
        if not isinstance(mt, list):
            continue
        for raw_tid in mt:
            tid = normalize_technique_id(str(raw_tid)) if raw_tid else None
            if tid:
                case_sets[tid].add(case_id)
    return {tid: len(cases) for tid, cases in case_sets.items()}


def _alert_observations(session: Session) -> Dict[str, int]:
    dialect = session.bind.dialect.name  # type: ignore[union-attr]
    if dialect == "sqlite":
        return _alert_observations_sqlite(session)
    return _alert_observations_postgres(session)


def _pin_observations_postgres(session: Session) -> Dict[str, int]:
    """Return {technique_id: total_pin_count} from both pin tables via LATERAL."""
    sql = text(
        """
        SELECT upper(u.technique_id) AS tid, COUNT(*) AS cnt
        FROM (
            -- v0.30.1: cast to text for the != 'null' check; see the
            -- alert_triage query above for the rationale.
            SELECT json_array_elements_text(cep.mitre_techniques) AS technique_id
            FROM case_evidence_pins AS cep
            WHERE cep.mitre_techniques IS NOT NULL
              AND cep.mitre_techniques::text != 'null'
              AND cep.finding_status != 'dismissed'

            UNION ALL

            SELECT json_array_elements_text(fcp.mitre_techniques) AS technique_id
            FROM forensic_case_pins AS fcp
            WHERE fcp.mitre_techniques IS NOT NULL
              AND fcp.mitre_techniques::text != 'null'
              AND fcp.finding_status != 'dismissed'
        ) AS u
        GROUP BY upper(u.technique_id)
        """
    )
    rows = session.execute(sql).fetchall()
    result: Dict[str, int] = {}
    for tid_raw, cnt in rows:
        tid = normalize_technique_id(tid_raw) if tid_raw else None
        if tid:
            result[tid] = result.get(tid, 0) + int(cnt)
    return result


def _pin_observations_sqlite(session: Session) -> Dict[str, int]:
    """SQLite fallback: fetch and unnest in Python."""
    counts: Dict[str, int] = defaultdict(int)
    for table in ("case_evidence_pins", "forensic_case_pins"):
        sql = text(
            f"SELECT mitre_techniques FROM {table} "  # noqa: S608
            "WHERE mitre_techniques IS NOT NULL AND finding_status != 'dismissed'"
        )
        for (mt_raw,) in session.execute(sql).fetchall():
            if mt_raw is None:
                continue
            if isinstance(mt_raw, str):
                try:
                    mt = json.loads(mt_raw)
                except (json.JSONDecodeError, TypeError):
                    continue
            else:
                mt = mt_raw
            if not isinstance(mt, list):
                continue
            for raw_tid in mt:
                tid = normalize_technique_id(str(raw_tid)) if raw_tid else None
                if tid:
                    counts[tid] += 1
    return dict(counts)


def _pin_observations(session: Session) -> Dict[str, int]:
    dialect = session.bind.dialect.name  # type: ignore[union-attr]
    if dialect == "sqlite":
        return _pin_observations_sqlite(session)
    return _pin_observations_postgres(session)


# --------------------------------------------------------------------------
# Cell state computation
# --------------------------------------------------------------------------

_STATUS_IS_COVERED = frozenset({"shipped", "partial"})


def _cell_state(catalogue_status: str, alert_count: int, pin_count: int) -> str:
    covered = catalogue_status in _STATUS_IS_COVERED
    observed = (alert_count + pin_count) > 0
    if covered and observed:
        return "covered_exercised"
    if covered and not observed:
        return "covered_not_exercised"
    if not covered and observed:
        return "not_covered_seen"
    return "not_covered_not_seen"


# --------------------------------------------------------------------------
# Public interface
# --------------------------------------------------------------------------

def get_heatmap(session: Session, system_id: Optional[int] = None) -> dict:
    """Build and return the MITRE ATT&CK coverage heatmap dict.

    Returns:
        {
            "generated_at": "ISO-8601",
            "technique_count": int,
            "cells": [
                {
                    "technique_id": "T1558.003",
                    "technique_label": "Kerberoasting",
                    "tactic_ids": ["TA0006"],
                    "catalogue_state": "shipped"|"partial"|"gap"|"n/a"|"absent",
                    "alert_case_count": int,
                    "pin_count": int,
                    "cell_state": "covered_exercised"|"covered_not_exercised"|
                                  "not_covered_seen"|"not_covered_not_seen",
                }
            ],
            "summary": {
                "covered_exercised": int,
                "covered_not_exercised": int,
                "not_covered_seen": int,
            }
        }
    """
    snapshot, _ = _get_snapshot()
    catalogue = _catalogue_techniques(session, system_id)
    alert_obs = _alert_observations(session)
    pin_obs = _pin_observations(session)

    # Union of all technique IDs across all three sources.
    all_tids = set(snapshot.keys()) | set(catalogue.keys()) | set(alert_obs.keys()) | set(pin_obs.keys())

    cells = []
    summary = {"covered_exercised": 0, "covered_not_exercised": 0, "not_covered_seen": 0}

    for tid in sorted(all_tids):
        meta = snapshot.get(tid)
        label = meta["name"] if meta else tid
        tactic_ids = meta["tactic_ids"] if meta else []

        cat_status = catalogue.get(tid, "absent")
        a_count = alert_obs.get(tid, 0)
        p_count = pin_obs.get(tid, 0)
        state = _cell_state(cat_status, a_count, p_count)

        if state in summary:
            summary[state] += 1

        cells.append(
            {
                "technique_id": tid,
                "technique_label": label,
                "tactic_ids": tactic_ids,
                "catalogue_state": cat_status,
                "alert_case_count": a_count,
                "pin_count": p_count,
                "cell_state": state,
            }
        )

    return {
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "technique_count": len(cells),
        "cells": cells,
        "summary": summary,
    }
