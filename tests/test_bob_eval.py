"""Unit tests for Bob Prompt Evaluation Harness.

Pure-Python + real SQLite — no mocks, no network. Tests:
  - _compute_metrics arithmetic (known TP/FP/FN/TN inputs)
  - prompt_body_hash is a snapshot (immutable after run starts)
  - de-dup logic: two ai_feedback rows for same (alert_id, template_id)
    => harness keeps the max-id one
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from ion.models.base import Base
from ion.models.ai_feedback import AIFeedback
from ion.models.alert_prompt import AlertPromptTemplate
from ion.models.user import User
from ion.services.bob_eval_service import (
    _compute_metrics,
    _prompt_hash,
    _fetch_deduped_feedback,
    create_eval_run,
)
from ion.storage.database import _run_migrations


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def engine(tmp_path):
    db_path = tmp_path / "bob_eval_unit_test.db"
    eng = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(eng)
    try:
        _run_migrations(eng)
    except Exception:
        pass
    return eng


@pytest.fixture()
def session(engine):
    factory = sessionmaker(bind=engine)
    sess = factory()
    yield sess
    sess.close()


@pytest.fixture()
def admin_user(session):
    user = User(
        username="testadmin",
        email="testadmin@localhost",
        password_hash="x",
        display_name="Test Admin",
        is_active=True,
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


@pytest.fixture()
def template(session, admin_user):
    tmpl = AlertPromptTemplate(
        name="test-template",
        prompt_text="Investigate this alert carefully.",
        enabled=True,
        priority=50,
        created_by_id=admin_user.id,
    )
    session.add(tmpl)
    session.commit()
    session.refresh(tmpl)
    return tmpl


# ---------------------------------------------------------------------------
# _compute_metrics tests
# ---------------------------------------------------------------------------


class TestComputeMetrics:
    """Arithmetic correctness of precision/recall/F1 computation."""

    def test_perfect_classifier(self):
        p, r, f1 = _compute_metrics(tp=10, fp=0, fn=0, tn=5)
        assert p == 1.0
        assert r == 1.0
        assert f1 == 1.0

    def test_zero_tp_yields_zero_scores(self):
        p, r, f1 = _compute_metrics(tp=0, fp=5, fn=5, tn=2)
        assert p == 0.0
        assert r == 0.0
        assert f1 is None  # 0/(0+0) undefined

    def test_no_fp_no_fn(self):
        """Only TPs — precision and recall both 1.0."""
        p, r, f1 = _compute_metrics(tp=8, fp=0, fn=0, tn=0)
        assert p == 1.0
        assert r == 1.0
        assert f1 == 1.0

    def test_known_values(self):
        # tp=4, fp=1, fn=1, tn=4
        # precision = 4/5 = 0.8, recall = 4/5 = 0.8, f1 = 0.8
        p, r, f1 = _compute_metrics(tp=4, fp=1, fn=1, tn=4)
        assert abs(p - 0.8) < 1e-9
        assert abs(r - 0.8) < 1e-9
        assert abs(f1 - 0.8) < 1e-9

    def test_zero_denominators_return_none(self):
        # No TP, no FP: precision denominator is 0
        p, r, f1 = _compute_metrics(tp=0, fp=0, fn=0, tn=10)
        assert p is None
        assert r is None
        assert f1 is None

    def test_only_fps(self):
        # precision = 0/(0+10) = 0, recall: 0/(0+0) undefined
        p, r, f1 = _compute_metrics(tp=0, fp=10, fn=0, tn=0)
        assert p == 0.0
        assert r is None
        assert f1 is None

    def test_asymmetric_precision_recall(self):
        # tp=3 fp=1 fn=6 -> p=3/4=0.75, r=3/9=0.333, F1 = 2*0.75*0.333/(0.75+0.333)
        p, r, f1 = _compute_metrics(tp=3, fp=1, fn=6, tn=0)
        assert abs(p - 0.75) < 1e-9
        assert abs(r - (3 / 9)) < 1e-9
        expected_f1 = 2 * p * r / (p + r)
        assert abs(f1 - expected_f1) < 1e-9


# ---------------------------------------------------------------------------
# Prompt hash snapshot tests
# ---------------------------------------------------------------------------


class TestPromptHash:
    """prompt_body_hash is a snapshot of prompt_text at run-start time."""

    def test_hash_is_sha256_hex(self):
        h = _prompt_hash("hello world")
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_hash_stable(self):
        h1 = _prompt_hash("test prompt")
        h2 = _prompt_hash("test prompt")
        assert h1 == h2

    def test_different_texts_different_hashes(self):
        h1 = _prompt_hash("prompt A")
        h2 = _prompt_hash("prompt B")
        assert h1 != h2

    def test_snapshot_not_affected_by_later_mutation(self, session, admin_user, template):
        """Mutating template.prompt_text after run creation must not change the stored hash."""
        original_hash = _prompt_hash(template.prompt_text)

        run = create_eval_run(
            template_id=template.id,
            sample_size=10,
            triggered_by_id=admin_user.id,
            session=session,
        )

        assert run.prompt_body_hash == original_hash

        # Mutate the template AFTER the run was created.
        template.prompt_text = "completely different prompt text"
        session.commit()

        # Reload the run — hash should be unchanged.
        session.refresh(run)
        assert run.prompt_body_hash == original_hash
        assert run.prompt_body_hash != _prompt_hash(template.prompt_text)


# ---------------------------------------------------------------------------
# De-duplication tests
# ---------------------------------------------------------------------------


class TestDeduplication:
    """_fetch_deduped_feedback keeps max(id) per (alert_id, template_id)."""

    def _make_feedback(self, session, alert_id, template_id, human_verdict="true_positive"):
        fb = AIFeedback(
            alert_id=alert_id,
            alert_prompt_template_id=template_id,
            bob_suggested_verdict="true_positive",
            human_verdict=human_verdict,
            agreement=True,
            auto_escalated=False,
        )
        session.add(fb)
        session.flush()
        return fb

    def test_dedup_keeps_max_id(self, session, template):
        """Two rows for same (alert_id, template_id) → only max-id row returned."""
        fb1 = self._make_feedback(session, "alert-001", template.id, "pending")
        fb2 = self._make_feedback(session, "alert-001", template.id, "true_positive")
        session.commit()

        assert fb2.id > fb1.id

        rows = _fetch_deduped_feedback(
            session=session,
            template_id=template.id,
            sample_size=100,
        )

        ids = [r["id"] for r in rows]
        assert fb2.id in ids
        assert fb1.id not in ids

    def test_dedup_different_alerts_both_included(self, session, template):
        """Different alert_ids → both max-id rows included."""
        fb_a = self._make_feedback(session, "alert-A", template.id)
        fb_b = self._make_feedback(session, "alert-B", template.id)
        session.commit()

        rows = _fetch_deduped_feedback(
            session=session,
            template_id=template.id,
            sample_size=100,
        )
        ids = {r["id"] for r in rows}
        assert fb_a.id in ids
        assert fb_b.id in ids

    def test_dedup_three_rows_same_alert_keeps_latest(self, session, template):
        """Three rows for same alert → only the newest survives."""
        fb1 = self._make_feedback(session, "alert-X", template.id, "pending")
        fb2 = self._make_feedback(session, "alert-X", template.id, "false_positive")
        fb3 = self._make_feedback(session, "alert-X", template.id, "true_positive")
        session.commit()

        rows = _fetch_deduped_feedback(
            session=session,
            template_id=template.id,
            sample_size=100,
        )
        ids = [r["id"] for r in rows]
        assert len(ids) == 1
        assert ids[0] == fb3.id

    def test_dedup_returns_empty_when_no_rows(self, session, template):
        rows = _fetch_deduped_feedback(
            session=session,
            template_id=template.id,
            sample_size=100,
        )
        assert rows == []

    def test_dedup_respects_sample_size(self, session, template):
        """sample_size cap is honoured."""
        for i in range(10):
            self._make_feedback(session, f"alert-{i}", template.id)
        session.commit()

        rows = _fetch_deduped_feedback(
            session=session,
            template_id=template.id,
            sample_size=3,
        )
        assert len(rows) <= 3
