"""CISA KEV catalog — load the shipped snapshot, accept operator imports, look up CVEs.

**Why a snapshot and not a feed.** ION ships to air-gapped and siloed sites.
There is no runtime fetch here and there must never be one: the catalog arrives
inside the image (``ion/data/kev_catalog.json``, refreshed at release time by
``scripts/refresh_kev_snapshot.py``) and can be topped up between releases by an
operator uploading a newer file they obtained themselves.

**Staleness is a first-class fact, not a footnote.** Every read surface reports
the catalog version, its release date, and how many days old it is, because a
KEV answer is only as good as the snapshot behind it — "CVE-2026-1234 is not in
KEV" means nothing without "…according to a catalog from six weeks ago".
"""

from __future__ import annotations

import json
import logging
import re
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import func
from sqlalchemy.orm import Session

from ion.models.kev import KevEntry

logger = logging.getLogger(__name__)

# The snapshot that ships in the image.
BUNDLE_PATH = Path(__file__).resolve().parent.parent / "data" / "kev_catalog.json"

# CISA publishes this field as a string. "Unknown" means "not established",
# which is NOT the same as "no" — see the model.
_RANSOMWARE_TRUE = {"known"}


class KevImportError(ValueError):
    """The supplied file is not a usable KEV catalog."""


# ── parsing ──────────────────────────────────────────────────────────────


def _parse_date(value: Any) -> Optional[date]:
    if not value:
        return None
    try:
        return datetime.strptime(str(value)[:10], "%Y-%m-%d").date()
    except ValueError:
        return None


def parse_catalog(payload: Any) -> Tuple[str, Optional[str], List[Dict[str, Any]]]:
    """Validate and normalise a KEV catalog document.

    Raises ``KevImportError`` rather than letting a malformed upload become a
    half-written table — an operator import replaces security data, so it fails
    closed and loudly.
    """
    if not isinstance(payload, dict):
        raise KevImportError("Catalog must be a JSON object")

    vulns = payload.get("vulnerabilities")
    if not isinstance(vulns, list) or not vulns:
        raise KevImportError("Catalog has no 'vulnerabilities' array")

    version = str(payload.get("catalogVersion") or "").strip()
    if not version:
        raise KevImportError("Catalog is missing 'catalogVersion'")

    released = payload.get("dateReleased")

    rows: List[Dict[str, Any]] = []
    for item in vulns:
        if not isinstance(item, dict):
            continue
        cve = str(item.get("cveID") or "").strip().upper()
        # A row without a CVE id cannot be looked up or deduplicated, so it is
        # dropped rather than stored as an unreachable orphan.
        if not cve.startswith("CVE-"):
            continue
        raw_ransom = str(item.get("knownRansomwareCampaignUse") or "").strip()
        rows.append({
            "cve_id": cve,
            "vendor_project": (item.get("vendorProject") or None),
            "product": (item.get("product") or None),
            "vulnerability_name": (item.get("vulnerabilityName") or None),
            "short_description": (item.get("shortDescription") or None),
            "required_action": (item.get("requiredAction") or None),
            "notes": (item.get("notes") or None),
            "date_added": _parse_date(item.get("dateAdded")),
            "due_date": _parse_date(item.get("dueDate")),
            "known_ransomware": raw_ransom.lower() in _RANSOMWARE_TRUE,
            "known_ransomware_raw": raw_ransom or None,
            "cwes": json.dumps(item.get("cwes")) if item.get("cwes") else None,
        })

    if not rows:
        raise KevImportError("Catalog contained no usable CVE entries")
    return version, released, rows


def load_bundle() -> Tuple[str, Optional[str], List[Dict[str, Any]]]:
    if not BUNDLE_PATH.exists():
        raise KevImportError(f"Bundled KEV snapshot missing at {BUNDLE_PATH}")
    return parse_catalog(json.loads(BUNDLE_PATH.read_text(encoding="utf-8")))


# ── writing ──────────────────────────────────────────────────────────────


def _apply(session: Session, version: str, rows: List[Dict[str, Any]], source: str) -> Dict[str, int]:
    """Upsert rows and drop CVEs the new catalog no longer lists.

    CISA does remove entries. Leaving a withdrawn CVE behind would keep ION
    asserting "known exploited" about something the catalog no longer does.
    """
    existing = {e.cve_id: e for e in session.query(KevEntry).all()}
    incoming = {r["cve_id"] for r in rows}
    added = updated = 0

    for row in rows:
        entry = existing.get(row["cve_id"])
        if entry is None:
            entry = KevEntry(**row)
            entry.catalog_version = version
            entry.source = source
            session.add(entry)
            added += 1
        else:
            for k, v in row.items():
                setattr(entry, k, v)
            entry.catalog_version = version
            entry.source = source
            updated += 1

    removed = 0
    for cve, entry in existing.items():
        if cve not in incoming:
            session.delete(entry)
            removed += 1

    session.commit()
    return {"added": added, "updated": updated, "removed": removed, "total": len(rows)}


def seed_from_bundle(session: Session, force: bool = False) -> Dict[str, Any]:
    """Load the shipped snapshot if the database does not already have it.

    Idempotent on the catalog VERSION, and it will not walk an operator's
    newer import backwards: if what is loaded is at least as new as the bundle,
    the seed is a no-op. Versions are ``YYYY.MM.DD`` so a string compare is a
    date compare.
    """
    version, released, rows = load_bundle()
    current = current_version(session)

    if not force and current and current >= version:
        logger.info("KEV seed skipped — loaded catalog %s is not older than bundled %s",
                    current, version)
        return {"skipped": True, "loaded_version": current, "bundle_version": version}

    stats = _apply(session, version, rows, source="bundled")
    logger.info("KEV catalog %s seeded from bundle: %s", version, stats)
    return {"skipped": False, "version": version, "date_released": released, **stats}


def import_catalog(session: Session, payload: Any) -> Dict[str, Any]:
    """Replace the catalog from an operator-supplied document."""
    version, released, rows = parse_catalog(payload)
    stats = _apply(session, version, rows, source="import")
    logger.info("KEV catalog %s imported by operator: %s", version, stats)
    return {"version": version, "date_released": released, **stats}


# ── reading ──────────────────────────────────────────────────────────────


def current_version(session: Session) -> Optional[str]:
    return session.query(func.max(KevEntry.catalog_version)).scalar()


def status(session: Session) -> Dict[str, Any]:
    """Version, size and AGE of the loaded catalog.

    Age is the point: an absent CVE only means "not in KEV" relative to a
    particular snapshot, and the caller cannot judge that without knowing how
    old it is.
    """
    total = session.query(func.count(KevEntry.id)).scalar() or 0
    version = current_version(session)
    newest_added = session.query(func.max(KevEntry.date_added)).scalar()
    sources = [s for (s,) in session.query(KevEntry.source).distinct().all()]

    age_days = None
    if version:
        try:
            snap = datetime.strptime(version[:10], "%Y.%m.%d").date()
            age_days = (datetime.now(timezone.utc).date() - snap).days
        except ValueError:
            age_days = None

    try:
        bundle_version, _, _ = load_bundle()
    except KevImportError:
        bundle_version = None

    return {
        "loaded": total > 0,
        "count": total,
        "catalog_version": version,
        "bundle_version": bundle_version,
        # True when an operator import is newer than what the image shipped —
        # worth showing, because a rebuild would otherwise look like a downgrade.
        "ahead_of_bundle": bool(version and bundle_version and version > bundle_version),
        "newest_entry_added": newest_added.isoformat() if newest_added else None,
        "age_days": age_days,
        "sources": sorted(sources),
    }


def lookup(session: Session, cve_id: str) -> Optional[KevEntry]:
    if not cve_id:
        return None
    return session.query(KevEntry).filter(
        func.upper(KevEntry.cve_id) == cve_id.strip().upper()
    ).one_or_none()


def lookup_many(session: Session, cve_ids: List[str]) -> Dict[str, KevEntry]:
    """Batch lookup — one query, so a page showing N CVEs does not make N."""
    wanted = {c.strip().upper() for c in cve_ids if c}
    if not wanted:
        return {}
    rows = session.query(KevEntry).filter(KevEntry.cve_id.in_(wanted)).all()
    return {r.cve_id: r for r in rows}


# ── prompt ground truth ──────────────────────────────────────────────────

# CVE-YYYY-NNNN.. — the year is 4 digits, the sequence is 4+.
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


def extract_cve_ids(text: str, limit: int = 12) -> List[str]:
    """Distinct CVE ids in order of first appearance."""
    seen: List[str] = []
    for m in CVE_RE.finditer(text or ""):
        cve = m.group(0).upper()
        if cve not in seen:
            seen.append(cve)
        if len(seen) >= limit:
            break
    return seen


def kev_prompt_block(session: Session, text: str, limit: int = 12) -> List[str]:
    """Markdown lines stating, as fact, which CVEs in ``text`` are in KEV.

    This exists for the same reason the deterministic PowerShell decode does:
    "is CVE-X known-exploited" is a lookup, and a model asked to answer it from
    training data will do so confidently and wrongly — in both directions. A
    false "yes" inflates a routine alert; a false "no" buries a live one.

    **A miss is phrased as absence-from-a-snapshot, never as safety.** Given a
    bare "not in KEV" a model reasons "not in KEV -> not urgent -> benign",
    which is exactly backwards for a CVE published last week. The catalog
    version and its age travel with every line so the model cannot read a stale
    absence as evidence.

    Returns [] when there are no CVEs to talk about — never raises.
    """
    try:
        cves = extract_cve_ids(text, limit=limit)
        if not cves:
            return []
        st = status(session)
        if not st.get("loaded"):
            return []
        found = lookup_many(session, cves)
        version = st.get("catalog_version") or "unknown"
        age = st.get("age_days")
        age_str = f"{age} days old" if age is not None else "age unknown"

        lines = [
            "## CISA KEV status (deterministic — DO NOT infer)",
            f"Checked by ION against KEV catalog {version} ({age_str}). Treat these "
            "as ground truth; do not rely on your own recollection of CVE numbers.",
        ]
        for cve in cves:
            entry = found.get(cve)
            if entry is None:
                lines.append(
                    f"- {cve}: NOT PRESENT in KEV catalog {version}. This means the "
                    "catalog held by this deployment does not list it — it is NOT a "
                    "statement that the CVE is unexploited or low risk, and a recently "
                    "published CVE may simply post-date this snapshot."
                )
            else:
                bits = [f"- {cve}: **LISTED IN CISA KEV** (added {entry.date_added})"]
                if entry.vendor_project or entry.product:
                    bits.append(f" — {entry.vendor_project or ''} {entry.product or ''}".rstrip())
                if entry.known_ransomware:
                    bits.append(" — **known ransomware campaign use**")
                if entry.due_date:
                    bits.append(f" — federal remediation due {entry.due_date}")
                lines.append("".join(bits))
        lines.append(
            "KEV listing is corroborating evidence of real-world exploitation. It is "
            "advisory input to your analysis, not an automatic verdict or severity."
        )
        lines.append("")
        return lines
    except Exception:  # noqa: BLE001 — enrichment must never break triage
        logger.debug("KEV prompt block skipped", exc_info=True)
        return []


def search(session: Session, q: str = "", ransomware_only: bool = False,
           limit: int = 50) -> List[KevEntry]:
    query = session.query(KevEntry)
    if q:
        term = f"%{q.strip().lower()}%"
        query = query.filter(
            KevEntry.cve_id.ilike(term)
            | KevEntry.vendor_project.ilike(term)
            | KevEntry.product.ilike(term)
            | KevEntry.vulnerability_name.ilike(term)
        )
    if ransomware_only:
        query = query.filter(KevEntry.known_ransomware.is_(True))
    return (query.order_by(KevEntry.date_added.desc().nullslast())
            .limit(max(1, min(limit, 200))).all())
