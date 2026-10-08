"""Detection-engineering outcome measurement (review 2026-10-08, §7).

``measure_outcome`` compared a rule's FP closures across two windows of
*different length*:

    before_start = applied - timedelta(days=days)     # always `days` long
    after_end    = min(now, applied + timedelta(days=days))
    ...
    drop_pct = (before - after) / before * 100

So a proposal applied yesterday compared 30 days of "before" against 1
day of "after". A rule closing 90 FPs a month and still closing 3 a day
scored a 96.7% drop on its first day — the rate had not moved at all.
``days_observed`` and a causality caveat were present, but the headline
percentage was the thing people read, and it flattered every change that
had only just landed.

The corrected contract:

* the comparison uses equal-length windows, so the baseline shrinks to
  match however long the change has actually been observed;
* rates per day are reported alongside counts, since that is the figure
  that survives a short window;
* below a minimum observation period there is no percentage at all, and
  the reason says so rather than leaving a reader to notice
  ``days_observed``;
* confirmed-threat yield travels with the noise figures, so a change
  that silenced true positives cannot look like a pure win.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import ion.models  # noqa: F401
from ion.models.alert_triage import AlertCase, AlertTriage
from ion.models.base import Base
from ion.models.detection_proposal import (  # noqa: F401
    DetectionProposal,
    DetectionProposalStatus,
)
from ion.models.user import User
from ion.services import de_proposal_service as svc

RULE = "Suspicious PowerShell Download"


@pytest.fixture()
def engine(tmp_path):
    eng = create_engine(
        f"sqlite:///{tmp_path / 'review_de_outcome.db'}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(eng)
    yield eng
    eng.dispose()


@pytest.fixture()
def db(engine):
    s = sessionmaker(bind=engine, expire_on_commit=False)()
    s.add(User(id=1, username="de", email="de@x", password_hash="x",
               display_name="DE", is_active=True))
    s.commit()
    yield s
    s.close()


def _closed_case(db, *, closed_at: datetime, reason: str, rule: str = RULE):
    """One closed case with one linked triage row for `rule`."""
    case = AlertCase(
        case_number=f"DE-{reason[:2]}-{closed_at.timestamp():.6f}",
        title="measured",
        status="closed",
        severity="medium",
        created_by_id=1,
        closure_reason=reason,
        closed_at=closed_at,
    )
    db.add(case)
    db.flush()
    db.add(AlertTriage(
        es_alert_id=f"a-{case.id}",
        case_id=case.id,
        rule_name=rule,
        status="closed",
    ))
    db.flush()
    return case


def _applied_proposal(db, applied_at: datetime):
    p = DetectionProposal(
        rule_name=RULE,
        title="Scope the download rule to non-admin users",
        suggested_change="NOT user.name: admin*",
        status=DetectionProposalStatus.APPLIED,
        applied_at=applied_at,
    )
    db.add(p)
    db.commit()
    db.refresh(p)
    return p


def _naive(dt: datetime) -> datetime:
    """The columns are naive; drop tzinfo for storage."""
    return dt.replace(tzinfo=None)


# ── Equal-length windows ──────────────────────────────────────────────────


class TestComparableWindows:
    def test_short_observation_does_not_report_a_flattering_drop(self, db):
        """90 FPs/month before, same daily rate after → not a 96% win."""
        now = datetime.now(timezone.utc)
        applied = now - timedelta(days=3)
        p = _applied_proposal(db, _naive(applied))

        # 3 FPs/day for the 30 days before the change.
        for day in range(1, 31):
            for n in range(3):
                _closed_case(
                    db,
                    closed_at=_naive(applied - timedelta(days=day) + timedelta(hours=n + 1)),
                    reason="false_positive",
                )
        # The same 3/day for the 3 days since.
        for day in range(3):
            for n in range(3):
                _closed_case(
                    db,
                    closed_at=_naive(applied + timedelta(days=day) + timedelta(hours=n + 1)),
                    reason="false_positive",
                )
        db.commit()

        out = svc.measure_outcome(db, p.id, days=30)

        # Equal windows: 3 days each way, 9 vs 9.
        assert out["comparable"]["before_count"] == out["comparable"]["after_count"]
        assert out["comparable"]["drop_pct"] == 0.0
        assert out["comparable"]["window_days"] == 3

    def test_real_reduction_is_still_reported(self, db):
        now = datetime.now(timezone.utc)
        applied = now - timedelta(days=4)
        p = _applied_proposal(db, _naive(applied))

        # 4/day before.
        for day in range(1, 11):
            for n in range(4):
                _closed_case(
                    db,
                    closed_at=_naive(applied - timedelta(days=day) + timedelta(hours=n + 1)),
                    reason="false_positive",
                )
        # 1/day after.
        for day in range(4):
            _closed_case(
                db,
                closed_at=_naive(applied + timedelta(days=day) + timedelta(hours=1)),
                reason="false_positive",
            )
        db.commit()

        out = svc.measure_outcome(db, p.id, days=30)
        comparable = out["comparable"]
        assert comparable["window_days"] == 4
        assert comparable["before_count"] == 16
        assert comparable["after_count"] == 4
        assert comparable["drop_pct"] == 75.0

    def test_rates_per_day_are_reported(self, db):
        now = datetime.now(timezone.utc)
        applied = now - timedelta(days=5)
        p = _applied_proposal(db, _naive(applied))

        for day in range(1, 6):
            for n in range(2):
                _closed_case(
                    db,
                    closed_at=_naive(applied - timedelta(days=day) + timedelta(hours=n + 1)),
                    reason="false_positive",
                )
        for day in range(5):
            _closed_case(
                db,
                closed_at=_naive(applied + timedelta(days=day) + timedelta(hours=1)),
                reason="false_positive",
            )
        db.commit()

        out = svc.measure_outcome(db, p.id, days=30)
        assert out["comparable"]["before_per_day"] == pytest.approx(2.0, abs=0.01)
        assert out["comparable"]["after_per_day"] == pytest.approx(1.0, abs=0.01)


# ── Minimum observation period ────────────────────────────────────────────


class TestMinimumObservation:
    def test_same_day_change_reports_no_percentage(self, db):
        now = datetime.now(timezone.utc)
        applied = now - timedelta(hours=2)
        p = _applied_proposal(db, _naive(applied))

        for day in range(1, 31):
            _closed_case(
                db,
                closed_at=_naive(applied - timedelta(days=day)),
                reason="false_positive",
            )
        db.commit()

        out = svc.measure_outcome(db, p.id, days=30)
        assert out["comparable"]["drop_pct"] is None
        assert out["comparable"]["sufficient_observation"] is False
        assert "observ" in out["comparable"]["reason"].lower()

    def test_enough_observation_is_flagged_sufficient(self, db):
        now = datetime.now(timezone.utc)
        applied = now - timedelta(days=10)
        p = _applied_proposal(db, _naive(applied))

        for day in range(1, 21):
            _closed_case(
                db,
                closed_at=_naive(applied - timedelta(days=day)),
                reason="false_positive",
            )
        db.commit()

        out = svc.measure_outcome(db, p.id, days=30)
        assert out["comparable"]["sufficient_observation"] is True
        assert out["comparable"]["drop_pct"] is not None

    def test_minimum_is_stated_in_the_outcome(self, db):
        now = datetime.now(timezone.utc)
        p = _applied_proposal(db, _naive(now - timedelta(days=1)))
        db.commit()
        out = svc.measure_outcome(db, p.id, days=30)
        assert out["comparable"]["min_observation_days"] >= 1


# ── Confirmed-threat yield must travel with the noise numbers ─────────────


class TestConfirmedThreatYield:
    def test_true_positives_are_counted_either_side(self, db):
        now = datetime.now(timezone.utc)
        applied = now - timedelta(days=6)
        p = _applied_proposal(db, _naive(applied))

        for day in range(1, 7):
            _closed_case(
                db,
                closed_at=_naive(applied - timedelta(days=day)),
                reason="false_positive",
            )
        # Two confirmed threats before, none since — the change may have
        # silenced something real.
        for day in (1, 2):
            _closed_case(
                db,
                closed_at=_naive(applied - timedelta(days=day, hours=5)),
                reason="true_positive",
            )
        db.commit()

        out = svc.measure_outcome(db, p.id, days=30)
        yield_ = out["confirmed_threats"]
        assert yield_["before_count"] == 2
        assert yield_["after_count"] == 0
        assert yield_["lost_confirmed_threats"] is True

    def test_no_loss_when_true_positives_continue(self, db):
        now = datetime.now(timezone.utc)
        applied = now - timedelta(days=6)
        p = _applied_proposal(db, _naive(applied))

        _closed_case(
            db, closed_at=_naive(applied - timedelta(days=2)), reason="true_positive"
        )
        _closed_case(
            db, closed_at=_naive(applied + timedelta(days=2)), reason="true_positive"
        )
        db.commit()

        out = svc.measure_outcome(db, p.id, days=30)
        assert out["confirmed_threats"]["lost_confirmed_threats"] is False


# ── Total volume and backwards compatibility ──────────────────────────────


class TestOutcomeShape:
    def test_full_window_figures_are_preserved_but_labelled(self, db):
        now = datetime.now(timezone.utc)
        applied = now - timedelta(days=2)
        p = _applied_proposal(db, _naive(applied))
        for day in range(1, 31):
            _closed_case(
                db,
                closed_at=_naive(applied - timedelta(days=day)),
                reason="false_positive",
            )
        db.commit()

        out = svc.measure_outcome(db, p.id, days=30)
        # The original keys stay, so existing readers keep working.
        assert out["before_count"] == 30
        assert out["window_days"] == 30
        assert out["days_observed"] == 2
        # But they are explicitly the uneven comparison.
        assert "comparable" in out
        assert out["headline"] == out["comparable"]["drop_pct"]

    def test_causality_caveat_survives(self, db):
        now = datetime.now(timezone.utc)
        p = _applied_proposal(db, _naive(now - timedelta(days=5)))
        db.commit()
        out = svc.measure_outcome(db, p.id, days=30)
        assert "causation" in out["note"].lower()

    def test_outcome_is_persisted(self, db):
        now = datetime.now(timezone.utc)
        p = _applied_proposal(db, _naive(now - timedelta(days=5)))
        db.commit()
        svc.measure_outcome(db, p.id, days=30)
        db.expire_all()
        assert db.get(DetectionProposal, p.id).outcome_json["comparable"]
