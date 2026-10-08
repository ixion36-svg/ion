"""The knowledge review inbox (8 Oct 2026 review, §8, stage 4).

    "Improve: a common review inbox for expired assumptions, stale FP
    signatures, contradictory human outcomes and repeated uncertainty. Every
    explanation should have evidence, scope, an owner and a review
    lifecycle."

Stage 4's exit condition is that knowledge changes "trace to evidence and
measured outcomes". ION held four kinds of decaying knowledge and surfaced
none of them as work:

* **Expired quirks.** A lapsed quirk silently stops annotating. Nobody is
  told that an explanation the SOC relied on has gone quiet.
* **Stale FP signatures.** Now detectable after the governance work, but
  still needed somewhere to appear.
* **Contradictory human outcomes.** The same alert closed benign once and
  as a true positive another time means one of those two calls was wrong,
  and nothing was looking.
* **Repeated uncertainty.** A prompt Bob keeps abstaining on is a prompt
  that needs changing, not a queue that needs draining.

What the tests insist on beyond "it lists things":

* **Sample size travels with every rate.** A 100% abstention rate over two
  alerts is not a finding. The review asks repeatedly for sample size and
  denominators to be exposed, and the inbox refuses to raise an item below a
  minimum sample rather than quietly presenting a ratio of small numbers.
* **Every item says who owns it and what to do.** An inbox of observations
  nobody owns becomes another dashboard.
* **An empty inbox is empty.** No filler items, and the counts are zero
  rather than absent.
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
from ion.models.ai_feedback import AIFeedback
from ion.models.base import Base
from ion.models.system_quirk import SystemQuirk, SystemQuirkStatus
from ion.models.user import User
from ion.services import knowledge_review_service as kr
from ion.storage import investigation_memory_repository as fp_repo


@pytest.fixture()
def engine(tmp_path):
    eng = create_engine(f"sqlite:///{tmp_path / 'knowledge_review.db'}")
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


def _utc(days=0):
    return datetime.now(timezone.utc) + timedelta(days=days)


def _quirk(db, *, lapsed=False, status=SystemQuirkStatus.ACTIVE, title="Nightly backup"):
    q = SystemQuirk(
        title=title,
        annotation="The backup agent authenticates as svc_backup every night",
        justification="Confirmed against the backup schedule and the change record",
        scope_users=["svc_backup"],
        status=status,
        review_date=(_utc(days=-3) if lapsed else _utc(days=60)).replace(tzinfo=None),
        raised_by_id=1,
        verified_by_id=2,
        verified_at=datetime.now(timezone.utc).replace(tzinfo=None),
    )
    db.add(q)
    db.commit()
    db.refresh(q)
    return q


def _feedback(db, *, alert_id, human_verdict, auto_escalated=False,
              template_id=None, bob_verdict=None, days_ago=1):
    row = AIFeedback(
        alert_id=alert_id,
        alert_prompt_template_id=template_id,
        bob_suggested_verdict=bob_verdict,
        human_verdict=human_verdict,
        human_closed_by_id=1,
        auto_escalated=auto_escalated,
        created_at=(_utc(days=-days_ago)).replace(tzinfo=None),
    )
    db.add(row)
    db.commit()
    return row


def _fp(db, **over):
    kwargs = dict(reason="Build agents do this", rule_id="rule-1", recorded_by=1)
    kwargs.update(over)
    fp = fp_repo.record_fp(db=db, **kwargs)
    db.commit()
    return fp


def _items(db, kind=None, **kw):
    inbox = kr.review_inbox(db, **kw)
    items = inbox["items"]
    return [i for i in items if kind is None or i["kind"] == kind]


# ── Shape ────────────────────────────────────────────────────────────────


class TestShape:
    def test_an_empty_inbox_is_empty(self, db):
        inbox = kr.review_inbox(db)
        assert inbox["items"] == []
        assert inbox["total"] == 0

    def test_the_counts_are_zero_not_absent(self, db):
        """A missing key reads as "not measured"; zero reads as "none"."""
        counts = kr.review_inbox(db)["by_kind"]
        for kind in kr.REVIEW_KINDS:
            assert counts[kind] == 0

    def test_the_inbox_stamps_when_it_was_computed(self, db):
        assert kr.review_inbox(db)["as_of"]

    def test_every_item_carries_the_governance_quartet(self, db):
        """"evidence, scope, an owner and a review lifecycle"."""
        _quirk(db, lapsed=True)
        _fp(db)
        _feedback(db, alert_id="a1", human_verdict="false_positive")
        _feedback(db, alert_id="a1", human_verdict="true_positive")
        for item in kr.review_inbox(db)["items"]:
            assert item["kind"] in kr.REVIEW_KINDS
            assert item["title"]
            assert item["why"], item["kind"]
            assert item["action"], item["kind"]
            assert item["evidence"], item["kind"]
            assert "owner" in item, item["kind"]
            assert item["link"], item["kind"]

    def test_items_are_ordered_worst_first(self, db):
        _fp(db)                                  # unverified: lower priority
        _quirk(db, lapsed=True)                  # lapsed: already gone quiet
        kinds = [i["kind"] for i in kr.review_inbox(db)["items"]]
        assert kinds.index("expired_quirk") < kinds.index("stale_fp_signature")

    def test_the_limit_is_honoured(self, db):
        for i in range(5):
            _quirk(db, lapsed=True, title=f"Quirk {i}")
        assert len(kr.review_inbox(db, limit=2)["items"]) == 2

    def test_the_total_is_the_true_count_not_the_page(self, db):
        """Otherwise a capped inbox understates the backlog."""
        for i in range(5):
            _quirk(db, lapsed=True, title=f"Quirk {i}")
        inbox = kr.review_inbox(db, limit=2)
        assert len(inbox["items"]) == 2
        assert inbox["total"] == 5

    def test_a_single_kind_can_be_requested(self, db):
        _quirk(db, lapsed=True)
        _fp(db)
        inbox = kr.review_inbox(db, kinds=["expired_quirk"])
        assert {i["kind"] for i in inbox["items"]} == {"expired_quirk"}


# ── Expired quirks ───────────────────────────────────────────────────────


class TestExpiredQuirks:
    def test_a_lapsed_quirk_is_raised(self, db):
        quirk = _quirk(db, lapsed=True)
        items = _items(db, "expired_quirk")
        assert len(items) == 1
        assert items[0]["evidence"]["quirk_id"] == quirk.id

    def test_an_in_date_quirk_is_not_raised(self, db):
        _quirk(db, lapsed=False)
        assert _items(db, "expired_quirk") == []

    def test_a_reverted_quirk_is_not_chased(self, db):
        """It was deliberately withdrawn. Nothing to re-confirm."""
        _quirk(db, lapsed=True, status=SystemQuirkStatus.REVERTED)
        assert _items(db, "expired_quirk") == []

    def test_a_pending_quirk_is_not_chased_for_expiry(self, db):
        """It never took effect, so it cannot have stopped taking effect."""
        _quirk(db, lapsed=True, status=SystemQuirkStatus.PENDING)
        assert _items(db, "expired_quirk") == []

    def test_the_item_says_the_annotation_has_stopped(self, db):
        _quirk(db, lapsed=True)
        item = _items(db, "expired_quirk")[0]
        assert "stopped" in item["why"].lower() or "no longer" in item["why"].lower()

    def test_the_owner_is_the_person_who_raised_it(self, db):
        _quirk(db, lapsed=True)
        assert _items(db, "expired_quirk")[0]["owner"] == "alice"

    def test_the_evidence_includes_how_long_it_has_been_lapsed(self, db):
        _quirk(db, lapsed=True)
        item = _items(db, "expired_quirk")[0]
        assert item["evidence"]["days_lapsed"] >= 2


# ── Stale FP signatures ──────────────────────────────────────────────────


class TestStaleFpSignatures:
    def test_an_unverified_signature_is_raised(self, db):
        fp = _fp(db)
        items = _items(db, "stale_fp_signature")
        assert len(items) == 1
        assert items[0]["evidence"]["fp_id"] == fp.id

    def test_a_lapsed_signature_is_raised(self, db):
        fp = _fp(db)
        fp.review_date = _utc(days=-2).replace(tzinfo=None)
        db.commit()
        assert _items(db, "stale_fp_signature")[0]["evidence"]["governance_state"] == "lapsed"

    def test_a_healthy_signature_is_not_raised(self, db):
        fp = _fp(db, review_date=_utc(days=200))
        fp_repo.verify_fp(db, fp.id, actor_id=2)
        db.commit()
        assert _items(db, "stale_fp_signature") == []

    def test_the_item_carries_the_suppression_count(self, db):
        """How much this signature is actually hiding is the deciding fact."""
        fp = _fp(db)
        fp.hit_count = 412
        db.commit()
        item = _items(db, "stale_fp_signature")[0]
        assert item["evidence"]["hit_count"] == 412

    def test_the_owner_is_the_recorder(self, db):
        _fp(db, recorded_by=2)
        assert _items(db, "stale_fp_signature")[0]["owner"] == "bob"

    def test_an_unowned_signature_is_still_raised(self, db):
        _fp(db, recorded_by=None)
        item = _items(db, "stale_fp_signature")[0]
        assert item["owner"] is None
        assert item["title"]


# ── Contradictory human outcomes ─────────────────────────────────────────


class TestContradictoryOutcomes:
    def test_the_same_alert_closed_two_ways_is_a_contradiction(self, db):
        _feedback(db, alert_id="a1", human_verdict="false_positive")
        _feedback(db, alert_id="a1", human_verdict="true_positive")
        items = _items(db, "contradictory_outcome")
        assert len(items) == 1
        assert items[0]["evidence"]["alert_id"] == "a1"
        assert set(items[0]["evidence"]["verdicts"]) == {
            "false_positive", "true_positive"}

    def test_the_same_verdict_twice_is_not_a_contradiction(self, db):
        _feedback(db, alert_id="a1", human_verdict="false_positive")
        _feedback(db, alert_id="a1", human_verdict="false_positive")
        assert _items(db, "contradictory_outcome") == []

    def test_one_closure_is_not_a_contradiction(self, db):
        _feedback(db, alert_id="a1", human_verdict="false_positive")
        assert _items(db, "contradictory_outcome") == []

    def test_different_alerts_are_not_a_contradiction(self, db):
        """Two alerts legitimately differ. Only the same alert is a conflict."""
        _feedback(db, alert_id="a1", human_verdict="false_positive")
        _feedback(db, alert_id="a2", human_verdict="true_positive")
        assert _items(db, "contradictory_outcome") == []

    def test_rows_without_an_alert_id_are_ignored(self, db):
        """Grouping on NULL would collapse unrelated closures into one item."""
        _feedback(db, alert_id=None, human_verdict="false_positive")
        _feedback(db, alert_id=None, human_verdict="true_positive")
        assert _items(db, "contradictory_outcome") == []

    def test_only_closures_inside_the_window_count(self, db):
        _feedback(db, alert_id="a1", human_verdict="false_positive", days_ago=400)
        _feedback(db, alert_id="a1", human_verdict="true_positive", days_ago=1)
        assert _items(db, "contradictory_outcome", window_days=30) == []

    def test_a_wider_window_finds_it(self, db):
        _feedback(db, alert_id="a1", human_verdict="false_positive", days_ago=100)
        _feedback(db, alert_id="a1", human_verdict="true_positive", days_ago=1)
        assert len(_items(db, "contradictory_outcome", window_days=365)) == 1

    def test_the_evidence_names_who_closed_it_each_way(self, db):
        _feedback(db, alert_id="a1", human_verdict="false_positive")
        _feedback(db, alert_id="a1", human_verdict="true_positive")
        closures = _items(db, "contradictory_outcome")[0]["evidence"]["closures"]
        assert len(closures) == 2
        assert all(c["human_verdict"] for c in closures)

    def test_a_benign_true_positive_differs_from_a_false_positive(self, db):
        """ION distinguishes them deliberately: one was real but harmless, the
        other never happened. Closing an alert both ways is a real conflict."""
        _feedback(db, alert_id="a1", human_verdict="benign_true_positive")
        _feedback(db, alert_id="a1", human_verdict="false_positive")
        assert len(_items(db, "contradictory_outcome")) == 1


# ── Repeated uncertainty ─────────────────────────────────────────────────


class TestRepeatedUncertainty:
    def _abstentions(self, db, template_id, count, resolved=0):
        for i in range(count):
            _feedback(db, alert_id=f"abs-{template_id}-{i}",
                      human_verdict="true_positive", auto_escalated=True,
                      template_id=template_id)
        for i in range(resolved):
            _feedback(db, alert_id=f"ok-{template_id}-{i}",
                      human_verdict="true_positive", auto_escalated=False,
                      template_id=template_id)

    def test_a_prompt_bob_keeps_abstaining_on_is_raised(self, db):
        self._abstentions(db, 7, count=20, resolved=5)
        items = _items(db, "repeated_uncertainty")
        assert len(items) == 1
        assert items[0]["evidence"]["template_id"] == 7

    def test_the_rate_carries_its_denominator(self, db):
        """A rate with no sample size is the error this review keeps naming."""
        self._abstentions(db, 7, count=20, resolved=5)
        evidence = _items(db, "repeated_uncertainty")[0]["evidence"]
        assert evidence["abstentions"] == 20
        assert evidence["sample_size"] == 25
        assert abs(evidence["abstention_rate"] - 0.8) < 0.01

    def test_a_small_sample_is_not_raised_however_bad_the_rate(self, db):
        """100% of two alerts is not a finding."""
        self._abstentions(db, 7, count=2, resolved=0)
        assert _items(db, "repeated_uncertainty") == []

    def test_the_minimum_sample_is_stated_on_the_inbox(self, db):
        inbox = kr.review_inbox(db)
        assert inbox["thresholds"]["min_sample_size"] == kr.MIN_UNCERTAINTY_SAMPLE
        assert inbox["thresholds"]["abstention_rate"] == kr.UNCERTAINTY_RATE

    def test_a_healthy_prompt_is_not_raised(self, db):
        self._abstentions(db, 7, count=1, resolved=40)
        assert _items(db, "repeated_uncertainty") == []

    def test_rows_with_no_template_are_ignored(self, db):
        """There is no prompt to go and change."""
        self._abstentions(db, None, count=30, resolved=0)
        assert _items(db, "repeated_uncertainty") == []

    def test_only_abstentions_inside_the_window_count(self, db):
        for i in range(30):
            _feedback(db, alert_id=f"old-{i}", human_verdict="true_positive",
                      auto_escalated=True, template_id=7, days_ago=400)
        assert _items(db, "repeated_uncertainty", window_days=30) == []

    def test_the_item_points_at_the_prompt(self, db):
        self._abstentions(db, 7, count=20, resolved=5)
        assert "7" in _items(db, "repeated_uncertainty")[0]["link"]

    def test_the_action_is_to_change_the_prompt_not_drain_a_queue(self, db):
        self._abstentions(db, 7, count=20, resolved=5)
        action = _items(db, "repeated_uncertainty")[0]["action"].lower()
        assert "prompt" in action


# ── Summary for a dashboard ──────────────────────────────────────────────


class TestSummary:
    def test_the_summary_counts_without_the_bodies(self, db):
        _quirk(db, lapsed=True)
        _fp(db)
        summary = kr.review_summary(db)
        assert summary["total"] == 2
        assert summary["by_kind"]["expired_quirk"] == 1
        assert "items" not in summary

    def test_an_empty_summary_is_all_zeroes(self, db):
        summary = kr.review_summary(db)
        assert summary["total"] == 0
        assert set(summary["by_kind"]) == set(kr.REVIEW_KINDS)


# ── Wiring ───────────────────────────────────────────────────────────────


class TestWiring:
    def test_the_route_exists(self):
        src = (_SRC / "ion" / "web" / "investigation_memory_api.py"
               ).read_text(encoding="utf-8")
        assert "knowledge-review" in src

    def test_the_route_is_permission_gated(self):
        src = (_SRC / "ion" / "web" / "investigation_memory_api.py"
               ).read_text(encoding="utf-8")
        block = src.split('"/api/knowledge-review"')[1][:500]
        assert "require_permission" in block

    def test_the_summary_route_exists(self):
        src = (_SRC / "ion" / "web" / "investigation_memory_api.py"
               ).read_text(encoding="utf-8")
        assert '"/api/knowledge-review/summary"' in src

    def test_the_page_shows_the_inbox(self):
        tpl = (_SRC / "ion" / "web" / "templates" / "investigation_memory.html"
               ).read_text(encoding="utf-8")
        assert "knowledge-review" in tpl
