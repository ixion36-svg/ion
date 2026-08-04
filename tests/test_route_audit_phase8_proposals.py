"""Route audit phase 8 — TuningProposal retired into DetectionProposal.

Bob wrote `TuningProposal` rows unattended whenever a false-positive verdict
carried a concrete tuning recommendation, and Detection Health filed more — but
the only review UI had no link anywhere in the app, so they accumulated
unreviewed. `DetectionProposal` (the DE module's governed queue, with a decision
record and outcome measurement) had no `alert_id`/`investigation_id`, so Bob's
per-alert recommendations had nowhere to land.

Phase 8 adds that provenance, repoints both write paths, carries any still-open
legacy row across, and retires the old surface *and* its permissions.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from ion.models.detection_proposal import (
    DetectionProposal,
    DetectionProposalChangeType,
    DetectionProposalSource,
    DetectionProposalStatus,
)
from ion.web.server import app


@pytest.fixture(scope="module")
def paths():
    return {r.path for r in app.routes}


def _db():
    import ion.models  # noqa: F401 — registers models
    from ion.models.base import Base

    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    return engine, sessionmaker(bind=engine)()


# ── model absorbs the legacy shape ───────────────────────────────────────


def test_detection_proposal_carries_bob_provenance():
    engine, s = _db()
    p = DetectionProposal(
        rule_name="Suspicious PowerShell",
        change_type=DetectionProposalChangeType.OTHER,
        title="Bob: tuning suggested",
        suggested_change="exclude signed installer path",
        status=DetectionProposalStatus.DRAFT,
        source=DetectionProposalSource.BOB,
        alert_id="alert-123",
        investigation_id=None,
    )
    s.add(p)
    s.commit()
    got = s.get(DetectionProposal, p.id)
    assert got.source == DetectionProposalSource.BOB
    assert got.alert_id == "alert-123"


def test_duplicate_status_survived_the_migration():
    """The legacy queue had a `duplicate` triage option; it must not be lost."""
    assert DetectionProposalStatus.DUPLICATE.value == "duplicate"


def test_source_defaults_to_human():
    engine, s = _db()
    p = DetectionProposal(
        rule_name="r", change_type=DetectionProposalChangeType.EXCLUSION,
        title="t", suggested_change="c",
    )
    s.add(p)
    s.commit()
    assert s.get(DetectionProposal, p.id).source == DetectionProposalSource.HUMAN


# ── the source filter ────────────────────────────────────────────────────


def test_list_proposals_filters_by_source():
    from ion.services.de_proposal_service import list_proposals

    engine, s = _db()
    for src in (DetectionProposalSource.BOB, DetectionProposalSource.HUMAN,
                DetectionProposalSource.BOB):
        s.add(DetectionProposal(
            rule_name="r", change_type=DetectionProposalChangeType.OTHER,
            title="t", suggested_change="c", source=src,
        ))
    s.commit()

    assert len(list_proposals(s)) == 3
    assert len(list_proposals(s, source="bob")) == 2
    assert len(list_proposals(s, source="human")) == 1
    assert len(list_proposals(s, source="all")) == 3


# ── the legacy backfill actually runs ────────────────────────────────────


def test_pending_legacy_rows_are_carried_over_and_backfill_is_idempotent():
    """Retiring the review page must not strand proposals Bob already filed."""
    from ion.storage.database import _run_migrations

    engine, s = _db()
    # a pending legacy row (should carry) and a resolved one (should not)
    s.execute(text(
        "INSERT INTO tuning_proposals (id, alert_id, rule_id, rationale, "
        "suggested_change, status, created_at, updated_at) VALUES "
        "(1, 'alert-9', 'Noisy Rule', 'why', 'do the thing', 'pending', "
        " CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
    ))
    s.execute(text(
        "INSERT INTO tuning_proposals (id, alert_id, rule_id, rationale, "
        "suggested_change, status, created_at, updated_at) VALUES "
        "(2, 'alert-8', 'Done Rule', 'why', 'already handled', 'accepted', "
        " CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
    ))
    s.commit()

    _run_migrations(engine)
    carried = s.execute(text(
        "SELECT legacy_tuning_proposal_id, source, alert_id, rule_name, status "
        "FROM detection_proposals WHERE legacy_tuning_proposal_id IS NOT NULL"
    )).fetchall()
    assert len(carried) == 1, "only the PENDING legacy row should carry over"
    assert carried[0][0] == 1
    assert carried[0][1] == "bob"
    assert carried[0][2] == "alert-9"
    assert carried[0][3] == "Noisy Rule"
    assert carried[0][4] == "draft"

    # running again must not duplicate it
    _run_migrations(engine)
    again = s.execute(text(
        "SELECT COUNT(*) FROM detection_proposals "
        "WHERE legacy_tuning_proposal_id IS NOT NULL"
    )).scalar()
    assert again == 1, "backfill must be idempotent"


# ── the old surface is gone, safely ──────────────────────────────────────


def test_legacy_page_redirects_and_api_is_removed(paths):
    assert "/tuning-proposals" in paths, "bookmarks should redirect, not 404"
    assert not any(p.startswith("/api/tuning-proposals") for p in paths)


def test_legacy_module_and_template_deleted():
    assert not Path("src/ion/web/tuning_proposal_api.py").exists()
    assert not Path("src/ion/web/templates/tuning_proposals.html").exists()


def test_tuning_permissions_removed_only_after_their_enforcement():
    """Removing a seeded permission that is still enforced locks everyone out,
    admin included — so the gate had to move first."""
    auth = Path("src/ion/auth/service.py").read_text(encoding="utf-8")
    assert '("tuning:read"' not in auth
    assert '("tuning:review"' not in auth

    # and nothing anywhere still gates on them
    offenders = []
    for py in Path("src/ion").rglob("*.py"):
        text_ = py.read_text(encoding="utf-8", errors="replace")
        for line in text_.splitlines():
            if ("tuning:read" in line or "tuning:review" in line) and not line.strip().startswith("#"):
                offenders.append(f"{py}: {line.strip()[:70]}")
    assert not offenders, f"tuning:* still enforced: {offenders}"


def test_detection_health_now_files_into_the_de_queue():
    src = Path("src/ion/web/detection_health_api.py").read_text(encoding="utf-8")
    assert "DetectionProposal(" in src
    assert 'require_any_permission(["de:propose"])' in src
    assert "TuningProposal(" not in src


def test_bob_auto_draft_targets_the_governed_queue():
    src = Path("src/ion/services/investigation_service.py").read_text(encoding="utf-8")
    body = src.split("def _write_bob_outputs", 1)[1].split("\ndef ", 1)[0]
    assert "DetectionProposal(" in body
    assert "DetectionProposalSource.BOB" in body
    assert "TuningProposal(" not in body
    # still a draft — Bob never auto-applies
    assert "DetectionProposalStatus.DRAFT" in body
