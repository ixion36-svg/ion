"""False-positive signature governance (8 Oct 2026 review, §8, stage 4).

    "**Implemented:** quirks require concrete scope, future review dates and
    independent verification; expired quirks stop matching. ...

    **Observed asymmetry:** FP signatures lack equivalent
    review/expiry/verification fields despite being reused as known benign
    context."

A quirk is a human-verified, scoped, *expiring* statement that something is
benign. It needs a different person to verify it, it carries a mandatory
review date, and once that date passes it stops having any effect — expiry is
computed on read, so no background worker can fail and leave a stale
assumption live.

An FP signature makes the same kind of claim — "alerts like this are benign"
— and is fed to Bob as known-benign context, but it had only ``enabled`` and
a confidence number. Recorded once, it applied forever, with no second pair
of eyes and no date at which someone had to look again. That is the more
dangerous of the two, because an FP signature suppresses alerts rather than
annotating them.

The one deliberate asymmetry that remains, and the tests pin it:

**An existing ungoverned signature keeps matching.** Making every
pre-upgrade signature inert the moment this ships would silently switch off a
SOC's entire accumulated FP memory, which is a worse surprise than the
governance gap it fixes. So a signature with no review date still matches,
is labelled ``ungoverned``, and is listed for review. A signature whose
review date has *passed* does stop matching — that is the parity the review
asks for, and the SOC chose that date.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import ion.models  # noqa: F401
from ion.models.base import Base
from ion.models.investigation import FalsePositiveSignature
from ion.models.user import User
from ion.storage import investigation_memory_repository as repo
from ion.storage.database import _run_migrations


@pytest.fixture()
def engine(tmp_path):
    eng = create_engine(f"sqlite:///{tmp_path / 'fp_gov.db'}")
    Base.metadata.create_all(eng)
    yield eng
    eng.dispose()


@pytest.fixture()
def db(engine):
    s = sessionmaker(bind=engine, expire_on_commit=False)()
    for uid, name in ((1, "alice"), (2, "bob")):
        s.add(User(id=uid, username=name, email=f"{name}@x", password_hash="x",
                   display_name=name, is_active=True))
    s.commit()
    yield s
    s.close()


ALERT = {
    "rule_id": "rule-123",
    "rule_name": "Suspicious PowerShell",
    "host": "DEV-WEB-01",
    "user": "svc_build",
}


def _record(db, **over):
    kwargs = dict(
        reason="Build agents run this every night",
        rule_id="rule-123",
        host_pattern="DEV-*",
        recorded_by=1,
    )
    kwargs.update(over)
    fp = repo.record_fp(db=db, **kwargs)
    db.commit()
    return fp


def _utc(days=0):
    return datetime.now(timezone.utc) + timedelta(days=days)


# ── Schema ───────────────────────────────────────────────────────────────


class TestSchema:
    @pytest.mark.parametrize("column", [
        "review_date", "verified_by_id", "verified_at", "verification_note",
    ])
    def test_the_governance_columns_exist(self, engine, column):
        names = {c["name"] for c in inspect(engine).get_columns("fp_signatures")}
        assert column in names

    def test_the_migration_adds_them_to_an_existing_table(self, tmp_path):
        """An existing deployment has the pre-governance table.

        Built from scratch rather than by dropping columns off the current
        one: SQLite refuses DROP COLUMN for a column named in a foreign key,
        and verified_by_id is one.
        """
        from sqlalchemy import text

        eng = create_engine(f"sqlite:///{tmp_path / 'upgrade.db'}")
        try:
            Base.metadata.create_all(eng)
            with eng.begin() as conn:
                conn.execute(text("DROP TABLE fp_signatures"))
                conn.execute(text("""
                    CREATE TABLE fp_signatures (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        rule_id VARCHAR(255),
                        rule_name VARCHAR(500),
                        alert_signature VARCHAR(500),
                        host_pattern VARCHAR(255),
                        user_pattern VARCHAR(255),
                        reason TEXT NOT NULL,
                        confidence INTEGER NOT NULL DEFAULT 80,
                        recorded_by INTEGER REFERENCES users(id),
                        recorded_at DATETIME NOT NULL,
                        hit_count INTEGER NOT NULL DEFAULT 0,
                        last_matched_at DATETIME,
                        enabled BOOLEAN NOT NULL DEFAULT 1
                    )
                """))
                # A signature the SOC is already relying on.
                conn.execute(text(
                    "INSERT INTO fp_signatures (rule_id, reason, confidence, "
                    "recorded_at, enabled) VALUES ('rule-old', 'legacy', 80, "
                    "CURRENT_TIMESTAMP, 1)"))

            before = {c["name"] for c in inspect(eng).get_columns("fp_signatures")}
            assert "review_date" not in before

            _run_migrations(eng)
            after = {c["name"] for c in inspect(eng).get_columns("fp_signatures")}
            for column in ("review_date", "verified_by_id", "verified_at",
                           "verification_note"):
                assert column in after, column

            # The pre-existing row survives and is ungoverned, not deleted
            # and not silently given an invented review date.
            with eng.begin() as conn:
                row = conn.execute(text(
                    "SELECT rule_id, review_date FROM fp_signatures")).fetchone()
            assert row[0] == "rule-old"
            assert row[1] is None
        finally:
            eng.dispose()


# ── Governance state ─────────────────────────────────────────────────────


class TestGovernanceState:
    def test_a_new_signature_gets_a_review_date(self, db):
        """Quirks have mandatory expiry; new FP signatures now do too."""
        fp = _record(db)
        assert fp.review_date is not None
        assert fp.review_date.replace(tzinfo=timezone.utc) > datetime.now(timezone.utc)

    def test_the_default_review_window_is_used(self, db):
        fp = _record(db)
        expected = datetime.now(timezone.utc) + timedelta(
            days=repo.FP_DEFAULT_REVIEW_DAYS)
        assert abs((fp.review_date.replace(tzinfo=timezone.utc)
                    - expected).total_seconds()) < 120

    def test_an_explicit_review_date_is_kept(self, db):
        when = _utc(days=14)
        fp = _record(db, review_date=when)
        assert abs((fp.review_date.replace(tzinfo=timezone.utc)
                    - when).total_seconds()) < 2

    def test_a_past_review_date_is_refused_at_creation(self, db):
        """A signature that is born lapsed is a mistake, not a state."""
        with pytest.raises(ValueError):
            _record(db, review_date=_utc(days=-1))

    def test_a_signature_with_no_review_date_is_ungoverned(self, db):
        fp = _record(db)
        fp.review_date = None
        db.commit()
        assert fp.governance_state() == "ungoverned"

    def test_an_unverified_signature_says_so(self, db):
        assert _record(db).governance_state() == "unverified"

    def test_a_verified_in_date_signature_is_active(self, db):
        fp = _record(db)
        repo.verify_fp(db, fp.id, actor_id=2)
        db.commit()
        assert db.get(FalsePositiveSignature, fp.id).governance_state() == "active"

    def test_a_past_review_date_is_lapsed(self, db):
        fp = _record(db)
        repo.verify_fp(db, fp.id, actor_id=2)
        fp.review_date = _utc(days=-1).replace(tzinfo=None)
        db.commit()
        assert fp.governance_state() == "lapsed"

    def test_lapsed_beats_unverified(self, db):
        """Both are true; lapsed is the one that changes behaviour."""
        fp = _record(db)
        fp.review_date = _utc(days=-1).replace(tzinfo=None)
        db.commit()
        assert fp.governance_state() == "lapsed"

    def test_a_disabled_signature_is_disabled_whatever_else(self, db):
        fp = _record(db)
        fp.enabled = False
        db.commit()
        assert fp.governance_state() == "disabled"

    def test_is_expired_is_computed_on_read(self, db):
        """Like quirks: no background worker, so nothing can fail and leave a
        stale assumption live."""
        fp = _record(db)
        assert fp.is_expired() is False
        fp.review_date = _utc(days=-1).replace(tzinfo=None)
        assert fp.is_expired() is True

    def test_no_review_date_is_not_expired(self, db):
        fp = _record(db)
        fp.review_date = None
        assert fp.is_expired() is False

    def test_the_dict_exposes_the_governance(self, db):
        fp = _record(db)
        payload = fp.to_dict()
        assert payload["governance_state"] == "unverified"
        assert payload["review_date"]
        assert payload["expired"] is False
        assert payload["verified_by_id"] is None


# ── Verification is a second pair of eyes ────────────────────────────────


class TestVerification:
    def test_verifying_records_who_and_when(self, db):
        fp = _record(db)
        repo.verify_fp(db, fp.id, actor_id=2, note="Checked the build schedule")
        db.commit()
        fp = db.get(FalsePositiveSignature, fp.id)
        assert fp.verified_by_id == 2
        assert fp.verified_at is not None
        assert "build schedule" in fp.verification_note

    def test_the_recorder_cannot_verify_their_own_signature(self, db):
        """Service-enforced regardless of permissions, exactly as for quirks."""
        fp = _record(db, recorded_by=1)
        with pytest.raises(ValueError):
            repo.verify_fp(db, fp.id, actor_id=1)

    def test_a_signature_with_no_recorder_can_still_be_verified(self, db):
        """Imported or system-created rows have no author to be distinct from."""
        fp = _record(db, recorded_by=None)
        repo.verify_fp(db, fp.id, actor_id=1)
        db.commit()
        assert db.get(FalsePositiveSignature, fp.id).verified_by_id == 1

    def test_verifying_a_missing_signature_is_an_error(self, db):
        with pytest.raises(ValueError):
            repo.verify_fp(db, 9999, actor_id=2)

    def test_reverification_after_a_lapse_is_allowed(self, db):
        fp = _record(db)
        repo.verify_fp(db, fp.id, actor_id=2)
        fp.review_date = _utc(days=-1).replace(tzinfo=None)
        db.commit()
        repo.review_fp(db, fp.id, actor_id=2, extend_days=30)
        db.commit()
        assert db.get(FalsePositiveSignature, fp.id).governance_state() == "active"


# ── Renewing the review ──────────────────────────────────────────────────


class TestReview:
    def test_reviewing_pushes_the_date_out(self, db):
        fp = _record(db, review_date=_utc(days=2))
        repo.review_fp(db, fp.id, actor_id=2, extend_days=60)
        db.commit()
        fp = db.get(FalsePositiveSignature, fp.id)
        assert fp.review_date.replace(tzinfo=timezone.utc) > _utc(days=55)

    def test_reviewing_from_a_lapsed_state_measures_from_now(self, db):
        """Extending from a long-past date would re-lapse immediately."""
        fp = _record(db)
        fp.review_date = _utc(days=-400).replace(tzinfo=None)
        db.commit()
        repo.review_fp(db, fp.id, actor_id=2, extend_days=30)
        db.commit()
        fp = db.get(FalsePositiveSignature, fp.id)
        assert fp.is_expired() is False

    def test_reviewing_records_the_reviewer(self, db):
        fp = _record(db)
        repo.review_fp(db, fp.id, actor_id=2, extend_days=30,
                       note="Still true, build still nightly")
        db.commit()
        fp = db.get(FalsePositiveSignature, fp.id)
        assert fp.verified_by_id == 2
        assert "nightly" in fp.verification_note

    def test_a_non_positive_extension_is_refused(self, db):
        fp = _record(db)
        for bad in (0, -5):
            with pytest.raises(ValueError):
                repo.review_fp(db, fp.id, actor_id=2, extend_days=bad)

    def test_reviewing_an_ungoverned_signature_governs_it(self, db):
        """The path out of the ungoverned state for pre-upgrade rows."""
        fp = _record(db)
        fp.review_date = None
        fp.verified_by_id = None
        db.commit()
        repo.review_fp(db, fp.id, actor_id=2, extend_days=90)
        db.commit()
        assert db.get(FalsePositiveSignature, fp.id).governance_state() == "active"


# ── Matching honours expiry ──────────────────────────────────────────────


class TestMatching:
    def test_an_in_date_signature_matches(self, db):
        _record(db)
        matched, fp = repo.is_likely_fp(ALERT, db)
        assert matched is True
        assert fp is not None

    def test_a_lapsed_signature_does_not_match(self, db):
        """The behavioural parity with quirks the review asks for."""
        fp = _record(db)
        fp.review_date = _utc(days=-1).replace(tzinfo=None)
        db.commit()
        matched, got = repo.is_likely_fp(ALERT, db)
        assert matched is False
        assert got is None

    def test_a_lapsed_signature_does_not_get_its_hit_count_bumped(self, db):
        """It took no part in the decision, so it earned no credit."""
        fp = _record(db)
        fp.review_date = _utc(days=-1).replace(tzinfo=None)
        db.commit()
        repo.is_likely_fp(ALERT, db)
        assert db.get(FalsePositiveSignature, fp.id).hit_count == 0

    def test_an_ungoverned_signature_still_matches(self, db):
        """Deliberate. Disabling a SOC's whole FP memory on upgrade would be
        a worse surprise than the governance gap."""
        fp = _record(db)
        fp.review_date = None
        db.commit()
        matched, got = repo.is_likely_fp(ALERT, db)
        assert matched is True
        assert got.governance_state() == "ungoverned"

    def test_an_unverified_signature_still_matches(self, db):
        """Same reasoning. The review inbox is the pressure, not a kill switch."""
        _record(db)
        matched, got = repo.is_likely_fp(ALERT, db)
        assert matched is True
        assert got.governance_state() == "unverified"

    def test_a_disabled_signature_still_does_not_match(self, db):
        fp = _record(db)
        fp.enabled = False
        db.commit()
        assert repo.is_likely_fp(ALERT, db)[0] is False

    def test_a_lapsed_signature_does_not_shadow_a_valid_one(self, db):
        """The lapsed row has higher confidence, so it is considered first.
        It must be skipped, not allowed to end the search."""
        lapsed = _record(db, confidence=99, reason="stale")
        lapsed.review_date = _utc(days=-1).replace(tzinfo=None)
        db.commit()
        _record(db, confidence=50, reason="current")
        matched, got = repo.is_likely_fp(ALERT, db)
        assert matched is True
        assert got.reason == "current"


# ── The stale list that feeds the review inbox ───────────────────────────


class TestStaleListing:
    def test_a_lapsed_signature_is_stale(self, db):
        fp = _record(db)
        fp.review_date = _utc(days=-1).replace(tzinfo=None)
        db.commit()
        stale = repo.list_fps_needing_review(db)
        assert [s["id"] for s in stale] == [fp.id]
        assert stale[0]["governance_state"] == "lapsed"

    def test_an_ungoverned_signature_is_stale(self, db):
        fp = _record(db)
        fp.review_date = None
        db.commit()
        assert [s["id"] for s in repo.list_fps_needing_review(db)] == [fp.id]

    def test_an_unverified_signature_is_stale(self, db):
        """It is suppressing alerts on one person's judgement."""
        fp = _record(db)
        assert [s["id"] for s in repo.list_fps_needing_review(db)] == [fp.id]

    def test_a_signature_due_soon_is_stale(self, db):
        fp = _record(db, review_date=_utc(days=3))
        repo.verify_fp(db, fp.id, actor_id=2)
        db.commit()
        assert [s["id"] for s in repo.list_fps_needing_review(db)] == [fp.id]

    def test_a_healthy_signature_is_not_stale(self, db):
        fp = _record(db, review_date=_utc(days=120))
        repo.verify_fp(db, fp.id, actor_id=2)
        db.commit()
        assert repo.list_fps_needing_review(db) == []

    def test_a_disabled_signature_is_not_chased(self, db):
        """It is not suppressing anything, so nobody needs to review it."""
        fp = _record(db)
        fp.enabled = False
        db.commit()
        assert repo.list_fps_needing_review(db) == []

    def test_each_entry_says_why_it_needs_review(self, db):
        _record(db)
        entry = repo.list_fps_needing_review(db)[0]
        assert entry["reason_for_review"]
        assert entry["reason"]

    def test_lapsed_sorts_before_due_soon(self, db):
        soon = _record(db, review_date=_utc(days=2), rule_id="rule-soon")
        repo.verify_fp(db, soon.id, actor_id=2)
        lapsed = _record(db, rule_id="rule-lapsed")
        repo.verify_fp(db, lapsed.id, actor_id=2)
        lapsed.review_date = _utc(days=-5).replace(tzinfo=None)
        db.commit()
        assert [s["id"] for s in repo.list_fps_needing_review(db)][0] == lapsed.id

    def test_the_limit_is_honoured(self, db):
        for i in range(4):
            _record(db, rule_id=f"rule-{i}")
        assert len(repo.list_fps_needing_review(db, limit=2)) == 2


# ── Wiring ───────────────────────────────────────────────────────────────


class TestWiring:
    @staticmethod
    def _api():
        return (_SRC / "ion" / "web" / "investigation_memory_api.py"
                ).read_text(encoding="utf-8")

    def test_the_verify_route_exists(self):
        assert "verify" in self._api()

    def test_the_review_route_exists(self):
        assert "review" in self._api()

    def test_the_service_exposes_the_governance_calls(self):
        from ion.services.investigation_memory_service import (
            InvestigationMemoryService,
        )

        for name in ("verify_fp", "review_fp", "fps_needing_review"):
            assert hasattr(InvestigationMemoryService, name), name
