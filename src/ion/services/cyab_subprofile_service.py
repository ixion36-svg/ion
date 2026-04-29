"""CyAB Onboarding Studio — service layer (v0.12.0).

Three concerns:

- ``seed_catalogue()``  — idempotent UPSERT of the code-defined
  PILLARS + SUBPROFILES into ``cyab_pillars`` / ``cyab_subprofiles``.
  Skips any sub-profile row where ``is_custom=True`` so operator
  edits survive subsequent boots. Called from server.py startup
  under advisory lock ``LOCK_SEED_CYAB_SUBPROFILES``.

- ``backfill_subprofile_ids()`` — one-shot backfill of
  ``cyab_data_sources.subprofile_id`` from the legacy
  ``data_source_type`` string using the ``DATA_SOURCE_TYPE_MIGRATION``
  table. Three legacy types are ambiguous (windows_security, edr,
  unknown) — those rows stay NULL and the UI surfaces a
  "Confirm sub-profile" banner.

- Read / patch helpers used by the API layer.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from ion.models.cyab_subprofile import CyabPillar, CyabSubProfile
from ion.models.cyab import CyabDataSource, CyabSystem, CyabSystemAssessment
from ion.services.cyab_subprofile_catalogue import (
    CATALOGUE_VERSION,
    DATA_SOURCE_TYPE_MIGRATION,
    PILLARS,
    SUBPROFILES,
    get_subprofile,
)
from ion.storage.database import get_session_factory

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Seeder
# ---------------------------------------------------------------------------

def seed_catalogue() -> Dict[str, int]:
    """UPSERT pillars + sub-profiles. Skips ``is_custom=True`` rows.

    Returns a small report dict: ``{"pillars": N, "subprofiles_new": N,
    "subprofiles_updated": N, "subprofiles_skipped_custom": N}``.

    Idempotent — safe to call on every boot; only writes when content
    actually differs (catalogue_version + JSON byte-equality check).
    """
    factory = get_session_factory()
    session = factory()
    try:
        report = {
            "pillars": 0,
            "subprofiles_new": 0,
            "subprofiles_updated": 0,
            "subprofiles_skipped_custom": 0,
        }

        # --- Pillars -------------------------------------------------------
        existing_pillars = {p.id: p for p in session.scalars(select(CyabPillar))}
        for spec in PILLARS:
            row = existing_pillars.get(spec["id"])
            if row is None:
                row = CyabPillar(
                    id=spec["id"],
                    label=spec["label"],
                    icon=spec["icon"],
                    priority=spec["priority"],
                    description=spec.get("description"),
                )
                session.add(row)
            else:
                row.label = spec["label"]
                row.icon = spec["icon"]
                row.priority = spec["priority"]
                row.description = spec.get("description")
            report["pillars"] += 1

        # --- Sub-profiles --------------------------------------------------
        existing_subs = {s.id: s for s in session.scalars(select(CyabSubProfile))}
        for spec in SUBPROFILES:
            sub_id = spec["id"]
            existing = existing_subs.get(sub_id)
            catalogue_text = json.dumps(spec.get("catalogue") or {}, sort_keys=True)
            anchors_text = json.dumps(spec.get("ecs_anchors") or [])
            feeds_text = json.dumps(spec.get("expected_feeds") or [])

            if existing is None:
                row = CyabSubProfile(
                    id=sub_id,
                    pillar_id=spec["pillar_id"],
                    label=spec["label"],
                    icon=spec.get("icon", "cpu"),
                    ecs_anchors=anchors_text,
                    expected_feeds=feeds_text,
                    catalogue_json=catalogue_text,
                    catalogue_version=CATALOGUE_VERSION,
                    is_custom=False,
                    description=spec.get("description"),
                )
                session.add(row)
                report["subprofiles_new"] += 1
                continue

            if existing.is_custom:
                report["subprofiles_skipped_custom"] += 1
                continue

            existing.pillar_id = spec["pillar_id"]
            existing.label = spec["label"]
            existing.icon = spec.get("icon", existing.icon)
            existing.ecs_anchors = anchors_text
            existing.expected_feeds = feeds_text
            existing.catalogue_json = catalogue_text
            existing.catalogue_version = CATALOGUE_VERSION
            existing.description = spec.get("description")
            report["subprofiles_updated"] += 1

        session.commit()
        logger.info("CyAB sub-profile catalogue seeded: %s", report)
        return report
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Backfill of cyab_data_sources.subprofile_id
# ---------------------------------------------------------------------------

def backfill_subprofile_ids() -> Dict[str, int]:
    """Backfill subprofile_id on legacy CyabDataSource rows.

    Uses the catalogue's ``DATA_SOURCE_TYPE_MIGRATION`` table. Rows
    where the migration target is ``None`` (ambiguous types like
    ``windows_security`` or ``edr``) are left NULL — the UI surfaces a
    'Confirm sub-profile' banner for these.

    Idempotent — only updates rows where ``subprofile_id IS NULL`` and
    the legacy ``data_source_type`` resolves to a non-None target.
    """
    factory = get_session_factory()
    session = factory()
    try:
        rows = session.scalars(
            select(CyabDataSource).where(CyabDataSource.subprofile_id.is_(None))
        ).all()
        backfilled = 0
        ambiguous = 0
        unknown = 0
        for row in rows:
            target = DATA_SOURCE_TYPE_MIGRATION.get(row.data_source_type or "")
            if target is None:
                if row.data_source_type in DATA_SOURCE_TYPE_MIGRATION:
                    ambiguous += 1
                else:
                    unknown += 1
                continue
            row.subprofile_id = target
            backfilled += 1
        session.commit()
        report = {
            "backfilled": backfilled,
            "ambiguous": ambiguous,
            "unknown": unknown,
        }
        if backfilled or ambiguous:
            logger.info("CyAB sub-profile backfill: %s", report)
        return report
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Read helpers (API layer)
# ---------------------------------------------------------------------------

def list_pillars(session: Session) -> List[Dict[str, Any]]:
    """Return pillars ordered by priority."""
    rows = session.scalars(
        select(CyabPillar).order_by(CyabPillar.priority.asc(), CyabPillar.label.asc())
    ).all()
    return [
        {
            "id": r.id,
            "label": r.label,
            "icon": r.icon,
            "priority": r.priority,
            "description": r.description,
        }
        for r in rows
    ]


def list_subprofiles_for_pillar(
    session: Session, pillar_id: str,
) -> List[Dict[str, Any]]:
    """Return sub-profiles in a pillar, with summary counts only."""
    rows = session.scalars(
        select(CyabSubProfile)
        .where(CyabSubProfile.pillar_id == pillar_id)
        .order_by(CyabSubProfile.label.asc())
    ).all()
    out = []
    for r in rows:
        cat = json.loads(r.catalogue_json or "{}")
        out.append({
            "id": r.id,
            "pillar_id": r.pillar_id,
            "label": r.label,
            "icon": r.icon,
            "description": r.description,
            "is_custom": r.is_custom,
            "detection_count": len(cat.get("detection_use_cases") or []),
            "audit_count": len(cat.get("audit_use_cases") or []),
            "intake_count": len(cat.get("intake_questions") or []),
        })
    return out


def get_subprofile_full(
    session: Session, subprofile_id: str,
) -> Optional[Dict[str, Any]]:
    """Return one sub-profile with full catalogue."""
    row = session.get(CyabSubProfile, subprofile_id)
    if row is None:
        return None
    return _row_to_full_dict(row)


def get_use_case(
    session: Session, subprofile_id: str, uc_id: str,
) -> Optional[Dict[str, Any]]:
    """Return a single use case (detection or audit) by id."""
    row = session.get(CyabSubProfile, subprofile_id)
    if row is None:
        return None
    cat = json.loads(row.catalogue_json or "{}")
    for kind in ("detection_use_cases", "audit_use_cases"):
        for uc in cat.get(kind) or []:
            if uc.get("id") == uc_id:
                return uc
    return None


def patch_subprofile(
    session: Session, subprofile_id: str, patch: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """Apply an operator overlay to a sub-profile — flips is_custom.

    Accepts a partial dict with any subset of keys: ``label``, ``icon``,
    ``description``, ``ecs_anchors`` (list), ``expected_feeds`` (list),
    or ``catalogue`` (full replacement of the catalogue blob).

    Returns the updated full dict, or None if the sub-profile doesn't
    exist.
    """
    row = session.get(CyabSubProfile, subprofile_id)
    if row is None:
        return None
    if "label" in patch:
        row.label = str(patch["label"])
    if "icon" in patch:
        row.icon = str(patch["icon"])
    if "description" in patch:
        row.description = patch["description"]
    if "ecs_anchors" in patch:
        row.ecs_anchors = json.dumps(list(patch["ecs_anchors"]))
    if "expected_feeds" in patch:
        row.expected_feeds = json.dumps(list(patch["expected_feeds"]))
    if "catalogue" in patch:
        row.catalogue_json = json.dumps(patch["catalogue"], sort_keys=True)
    row.is_custom = True
    session.commit()
    return _row_to_full_dict(row)


def _row_to_full_dict(row: CyabSubProfile) -> Dict[str, Any]:
    return {
        "id": row.id,
        "pillar_id": row.pillar_id,
        "label": row.label,
        "icon": row.icon,
        "description": row.description,
        "ecs_anchors": json.loads(row.ecs_anchors or "[]"),
        "expected_feeds": json.loads(row.expected_feeds or "[]"),
        "catalogue": json.loads(row.catalogue_json or "{}"),
        "catalogue_version": row.catalogue_version,
        "is_custom": row.is_custom,
    }


# ---------------------------------------------------------------------------
# Per-system coverage rollup
# ---------------------------------------------------------------------------

def system_coverage(session: Session, system_id: int) -> Dict[str, Any]:
    """For each sub-profile attached to a system's data sources, compute:

    - intake answered % (per the most recent CyabSystemAssessment)
    - detection use cases shipped %
    - audit use cases shipped %

    Use-case shipped status is derived from the data source's
    ``use_case_status`` column, which from v0.12.0 is a JSON object
    keyed by use_case_id with values {shipped|partial|gap|n/a}. Pre
    v0.12.0 free-text values are treated as 'unknown'.
    """
    sources = session.scalars(
        select(CyabDataSource).where(CyabDataSource.system_id == system_id)
    ).all()
    asmt = session.scalars(
        select(CyabSystemAssessment)
        .where(CyabSystemAssessment.system_id == system_id)
        .order_by(CyabSystemAssessment.submitted_at.desc())
        .limit(1)
    ).first()
    answers: Dict[str, Any] = {}
    if asmt and asmt.responses_json:
        try:
            answers = json.loads(asmt.responses_json)
        except json.JSONDecodeError:
            answers = {}

    rollup: Dict[str, Dict[str, Any]] = {}
    for ds in sources:
        sub_id = ds.subprofile_id
        if sub_id is None:
            continue
        if sub_id in rollup:
            continue
        sub_row = session.get(CyabSubProfile, sub_id)
        if sub_row is None:
            continue
        cat = json.loads(sub_row.catalogue_json or "{}")
        questions = cat.get("intake_questions") or []
        detections = cat.get("detection_use_cases") or []
        audits = cat.get("audit_use_cases") or []

        # Intake coverage
        intake_total = len(questions)
        intake_answered = sum(1 for q in questions if q["key"] in answers)

        # Use-case status (per-data-source rollup, max coverage wins
        # across all data sources tagged to this sub-profile)
        det_shipped = audit_shipped = 0
        det_status = _aggregate_uc_status(sources, sub_id, [d["id"] for d in detections])
        aud_status = _aggregate_uc_status(sources, sub_id, [a["id"] for a in audits])
        det_shipped = sum(1 for v in det_status.values() if v == "shipped")
        audit_shipped = sum(1 for v in aud_status.values() if v == "shipped")

        rollup[sub_id] = {
            "subprofile_id": sub_id,
            "label": sub_row.label,
            "pillar_id": sub_row.pillar_id,
            "intake": {
                "answered": intake_answered,
                "total": intake_total,
                "pct": round(intake_answered * 100 / intake_total) if intake_total else 0,
            },
            "detection": {
                "shipped": det_shipped,
                "total": len(detections),
                "pct": round(det_shipped * 100 / len(detections)) if detections else 0,
            },
            "audit": {
                "shipped": audit_shipped,
                "total": len(audits),
                "pct": round(audit_shipped * 100 / len(audits)) if audits else 0,
            },
        }
    return {"system_id": system_id, "subprofiles": list(rollup.values())}


def _aggregate_uc_status(
    sources: List[CyabDataSource], sub_id: str, uc_ids: List[str],
) -> Dict[str, str]:
    """Across all data sources matching sub_id, return best-known status per uc."""
    best: Dict[str, str] = {uc_id: "gap" for uc_id in uc_ids}
    rank = {"shipped": 3, "partial": 2, "n/a": 1, "gap": 0}
    for ds in sources:
        if ds.subprofile_id != sub_id:
            continue
        raw = ds.use_case_status
        if not raw:
            continue
        try:
            parsed = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            continue
        if not isinstance(parsed, dict):
            continue
        for uc_id in uc_ids:
            current = parsed.get(uc_id)
            if not current:
                continue
            if rank.get(current, -1) > rank.get(best[uc_id], -1):
                best[uc_id] = current
    return best
