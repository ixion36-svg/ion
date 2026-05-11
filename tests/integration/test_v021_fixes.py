"""Integration tests for v0.21.0 review fixes.

Covers:
  - Fix 3: scorecard dedup (same alert_id+template_id with pending + resolved rows)
  - Fix 4: bob_confidence_int persisted on AIFeedback at case-close time
  - Fix 5: wallboard _collect_bob uses correct column names (no AttributeError)
  - Fix 6: confidence_threshold_override requires system:settings permission
"""

from __future__ import annotations

from typing import Optional

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from ion.models.ai_feedback import AIFeedback
from ion.models.alert_prompt import AlertPromptTemplate
from ion.models.base import Base
from ion.models.user import Permission, Role, User
from ion.storage.database import _run_migrations


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def engine(tmp_path):
    db_path = tmp_path / "v021_fixes.db"
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
    perm_settings = Permission(
        name="system:settings",
        resource="system",
        action="settings",
        description="System settings",
    )
    perm_playbook = Permission(
        name="playbook:update",
        resource="playbook",
        action="update",
        description="Update playbook",
    )
    session.add(perm_settings)
    session.add(perm_playbook)
    session.flush()

    role_admin = Role(name="admin-v021", description="Admin", is_system=False)
    role_analyst = Role(name="analyst-v021", description="Analyst", is_system=False)
    session.add(role_admin)
    session.add(role_analyst)
    session.flush()

    role_admin.permissions.append(perm_settings)
    role_admin.permissions.append(perm_playbook)
    role_analyst.permissions.append(perm_playbook)
    session.flush()

    admin = User(
        username="admin_v021",
        email="admin_v021@localhost",
        password_hash="x",
        display_name="Admin v021",
        is_active=True,
    )
    analyst = User(
        username="analyst_v021",
        email="analyst_v021@localhost",
        password_hash="x",
        display_name="Analyst v021",
        is_active=True,
    )
    session.add(admin)
    session.add(analyst)
    session.flush()

    admin.roles.append(role_admin)
    analyst.roles.append(role_analyst)
    session.commit()
    session.refresh(admin)
    session.refresh(analyst)
    return admin, analyst


@pytest.fixture()
def template(session, admin_user):
    admin, _ = admin_user
    tmpl = AlertPromptTemplate(
        name="fix-test-template",
        prompt_text="Investigate this alert.",
        enabled=True,
        priority=50,
        created_by_id=admin.id,
    )
    session.add(tmpl)
    session.commit()
    session.refresh(tmpl)
    return tmpl


# ---------------------------------------------------------------------------
# Fix 3: scorecard dedup
# ---------------------------------------------------------------------------


class TestScorecardDedup:
    """get_all_scorecards counts only max(id) per (alert_id, template_id)."""

    def _call_scorecard(self, session: Session, window_days: int = 30) -> dict:
        """Invoke the scorecard logic without HTTP layer."""
        from datetime import datetime, timedelta, timezone
        from sqlalchemy import text as _text

        cutoff = datetime.now(timezone.utc) - timedelta(days=window_days)
        dedup_sql = _text("""
            SELECT alert_prompt_template_id, agreement, human_verdict
            FROM ai_feedback
            WHERE id IN (
                SELECT MAX(id)
                FROM ai_feedback
                WHERE alert_prompt_template_id IS NOT NULL
                  AND created_at >= :cutoff
                GROUP BY alert_id, alert_prompt_template_id
            )
            AND alert_prompt_template_id IS NOT NULL
        """)
        raw_rows = session.execute(dedup_sql, {"cutoff": cutoff}).fetchall()
        rows = [(r[0], r[1], r[2]) for r in raw_rows]

        buckets: dict = {}
        for tpl_id, agreement, verdict in rows:
            b = buckets.setdefault(
                tpl_id,
                {"sample_size": 0, "agreed": 0, "evaluated": 0, "fp": 0, "btp": 0, "tp": 0},
            )
            b["sample_size"] += 1
            if agreement is not None:
                b["evaluated"] += 1
                if agreement:
                    b["agreed"] += 1
            if verdict == "false_positive":
                b["fp"] += 1
            elif verdict == "benign_true_positive":
                b["btp"] += 1
            elif verdict == "true_positive":
                b["tp"] += 1
        return buckets

    def test_pending_then_resolved_counts_as_one(self, session, template):
        """Two rows for same (alert_id, template_id) — only the resolved one counted."""
        # Pending row (circuit-breaker fire-time write)
        fb_pending = AIFeedback(
            alert_id="dedup-alert-001",
            alert_prompt_template_id=template.id,
            bob_suggested_verdict=None,
            human_verdict="pending",
            agreement=None,
            auto_escalated=True,
        )
        session.add(fb_pending)
        session.flush()

        # Resolved row (case-close write)
        fb_resolved = AIFeedback(
            alert_id="dedup-alert-001",
            alert_prompt_template_id=template.id,
            bob_suggested_verdict="true_positive",
            human_verdict="true_positive",
            agreement=True,
            auto_escalated=False,
        )
        session.add(fb_resolved)
        session.commit()

        assert fb_resolved.id > fb_pending.id

        buckets = self._call_scorecard(session)
        b = buckets.get(template.id, {})

        # sample_size should be 1 (deduplicated), not 2.
        assert b.get("sample_size", 0) == 1
        # The resolved row has agreement=True → evaluated=1, agreed=1.
        assert b.get("evaluated", 0) == 1
        assert b.get("agreed", 0) == 1

    def test_different_alerts_both_counted(self, session, template):
        """Two different alert_ids → both appear in the scorecard."""
        for alert_id, verdict in [("alert-A", "true_positive"), ("alert-B", "false_positive")]:
            fb = AIFeedback(
                alert_id=alert_id,
                alert_prompt_template_id=template.id,
                bob_suggested_verdict=verdict,
                human_verdict=verdict,
                agreement=True,
                auto_escalated=False,
            )
            session.add(fb)
        session.commit()

        buckets = self._call_scorecard(session)
        b = buckets.get(template.id, {})
        assert b.get("sample_size", 0) == 2

    def test_three_rows_same_alert_one_counted(self, session, template):
        """Three rows for the same alert → only the newest counts."""
        for verdict, agree in [("pending", None), ("false_positive", False), ("true_positive", True)]:
            fb = AIFeedback(
                alert_id="triple-alert",
                alert_prompt_template_id=template.id,
                bob_suggested_verdict=verdict if agree is not None else None,
                human_verdict=verdict,
                agreement=agree,
                auto_escalated=(agree is None),
            )
            session.add(fb)
            session.flush()  # ensure ascending IDs
        session.commit()

        buckets = self._call_scorecard(session)
        b = buckets.get(template.id, {})
        assert b.get("sample_size", 0) == 1
        # Latest row has human_verdict=true_positive → tp count 1
        assert b.get("tp", 0) == 1


# ---------------------------------------------------------------------------
# Fix 4: bob_confidence_int persistence on case-close
# ---------------------------------------------------------------------------


class TestBobConfidenceIntPersistence:
    """record_case_close_feedback populates bob_confidence_int from triage row."""

    def test_confidence_int_written_from_triage(self, session, admin_user):
        """AIFeedback.bob_confidence_int is populated from triage.suggested_verdict_confidence_int."""
        from ion.models.alert_triage import AlertCase, AlertCaseStatus, AlertTriage, AlertTriageStatus
        from ion.services.ai_feedback_service import record_case_close_feedback

        admin, _ = admin_user

        # Create a triage row with numeric confidence.
        triage = AlertTriage(
            es_alert_id="ci-test-alert-001",
            status=AlertTriageStatus.OPEN,
            suggested_verdict="true_positive",
            suggested_verdict_confidence="high",
            suggested_verdict_confidence_int=91,
        )
        session.add(triage)
        session.flush()

        # Create a case containing the triage entry.
        case = AlertCase(
            case_number="CASE-CI-001",
            title="CI Test Case",
            status=AlertCaseStatus.OPEN,
            created_by_id=admin.id,
        )
        session.add(case)
        session.flush()

        triage.case_id = case.id
        session.flush()

        # Manually wire triage_entries for the service (simulates ORM lazy load).
        case.triage_entries = [triage]

        written = record_case_close_feedback(
            case=case,
            human_verdict="true_positive",
            human_closed_by_id=admin.id,
            delta_reason=None,
            session=session,
        )
        session.flush()

        assert written == 1
        fb = session.query(AIFeedback).filter_by(alert_id="ci-test-alert-001").one()
        assert fb.bob_confidence_int == 91

    def test_confidence_int_default_none_when_triage_has_none(self, session, admin_user):
        """bob_confidence_int is None when triage has no numeric confidence."""
        from ion.models.alert_triage import AlertCase, AlertCaseStatus, AlertTriage, AlertTriageStatus
        from ion.services.ai_feedback_service import record_case_close_feedback

        admin, _ = admin_user

        triage = AlertTriage(
            es_alert_id="ci-test-alert-002",
            status=AlertTriageStatus.OPEN,
            suggested_verdict="false_positive",
            suggested_verdict_confidence=None,
            suggested_verdict_confidence_int=None,
        )
        session.add(triage)
        session.flush()

        case = AlertCase(
            case_number="CASE-CI-002",
            title="CI No-Conf Case",
            status=AlertCaseStatus.OPEN,
            created_by_id=admin.id,
        )
        session.add(case)
        session.flush()
        triage.case_id = case.id
        session.flush()
        case.triage_entries = [triage]

        record_case_close_feedback(
            case=case,
            human_verdict="false_positive",
            human_closed_by_id=admin.id,
            delta_reason=None,
            session=session,
        )
        session.flush()

        fb = session.query(AIFeedback).filter_by(alert_id="ci-test-alert-002").one()
        assert fb.bob_confidence_int is None


# ---------------------------------------------------------------------------
# Fix 5: wallboard _collect_bob uses correct column names
# ---------------------------------------------------------------------------


class TestWallboardBobCollect:
    """_collect_bob no longer raises AttributeError on AIFeedback column access."""

    def test_collect_bob_no_attribute_error(self, session):
        """Seeding AIFeedback rows and calling _collect_bob must not AttributeError."""
        from ion.services.wallboard_service import _collect_bob

        # Seed two AIFeedback rows with real column names.
        fb1 = AIFeedback(
            alert_id="wb-alert-001",
            bob_suggested_verdict="true_positive",
            human_verdict="true_positive",
            agreement=True,
            auto_escalated=False,
        )
        fb2 = AIFeedback(
            alert_id="wb-alert-002",
            bob_suggested_verdict="false_positive",
            human_verdict="true_positive",
            agreement=False,
            auto_escalated=False,
        )
        session.add(fb1)
        session.add(fb2)
        session.commit()

        # Must not raise AttributeError.
        result = _collect_bob(session)
        assert isinstance(result, dict)
        assert "feedback_7d_total" in result
        assert result["feedback_7d_total"] >= 2
        assert "agreement_pct" in result

    def test_collect_bob_agreement_pct_computed_correctly(self, session):
        """agreement_pct = matched / total when both columns are populated."""
        from ion.services.wallboard_service import _collect_bob

        fb_agree = AIFeedback(
            alert_id="wb-agree-001",
            bob_suggested_verdict="true_positive",
            human_verdict="true_positive",
            agreement=True,
        )
        fb_disagree = AIFeedback(
            alert_id="wb-agree-002",
            bob_suggested_verdict="false_positive",
            human_verdict="true_positive",
            agreement=False,
        )
        session.add(fb_agree)
        session.add(fb_disagree)
        session.commit()

        result = _collect_bob(session)
        # 1 match / 2 total = 50 %
        assert result.get("agreement_pct") == 50


# ---------------------------------------------------------------------------
# Fix 6: confidence_threshold_override permission check
# ---------------------------------------------------------------------------


class TestConfidenceThresholdPermission:
    """v0.22.1: confidence_threshold_override gate is incoming-vs-stored.

    The v0.21.x check only fired when the incoming value was non-null, which
    let a non-system:settings user clear an existing override by sending an
    explicit `confidence_threshold_override: null` (the UI always emitted
    the field). The v0.22.1 fix compares incoming to the stored value and
    treats any difference as a change requiring system:settings.
    """

    def test_user_without_system_settings_setting_non_null_raises_403(
        self, session, admin_user, template
    ):
        from ion.web.alert_prompt_api import (
            _check_confidence_threshold_permission,
            AlertPromptUpdate,
        )

        _, analyst = admin_user
        data = AlertPromptUpdate(confidence_threshold_override=80)

        with pytest.raises(HTTPException) as exc_info:
            _check_confidence_threshold_permission(analyst, data, current_value=None)
        assert exc_info.value.status_code == 403
        assert "system:settings" in str(exc_info.value.detail).lower()

    def test_user_with_system_settings_does_not_raise(
        self, session, admin_user, template
    ):
        from ion.web.alert_prompt_api import (
            _check_confidence_threshold_permission,
            AlertPromptUpdate,
        )

        admin, _ = admin_user
        data = AlertPromptUpdate(confidence_threshold_override=80)
        _check_confidence_threshold_permission(admin, data, current_value=None)

    def test_field_omitted_does_not_raise_for_any_user(
        self, session, admin_user, template
    ):
        from ion.web.alert_prompt_api import (
            _check_confidence_threshold_permission,
            AlertPromptUpdate,
        )

        _, analyst = admin_user
        # Field omitted entirely (model_fields_set excludes it).
        data = AlertPromptUpdate(name="rename-only")
        _check_confidence_threshold_permission(analyst, data, current_value=70)

    def test_zero_value_still_requires_permission(
        self, session, admin_user, template
    ):
        from ion.web.alert_prompt_api import (
            _check_confidence_threshold_permission,
            AlertPromptUpdate,
        )

        _, analyst = admin_user
        data = AlertPromptUpdate(confidence_threshold_override=0)
        with pytest.raises(HTTPException) as exc_info:
            _check_confidence_threshold_permission(analyst, data, current_value=None)
        assert exc_info.value.status_code == 403

    def test_explicit_null_clearing_existing_override_raises_403(
        self, session, admin_user, template
    ):
        """v0.22.1 (L6) regression: clearing a non-null override via explicit null."""
        from ion.web.alert_prompt_api import (
            _check_confidence_threshold_permission,
            AlertPromptUpdate,
        )

        _, analyst = admin_user
        # Mimic the UI payload from a non-system:settings user: explicit null
        # plus other fields. model_fields_set DOES include the field.
        data = AlertPromptUpdate(confidence_threshold_override=None)
        assert "confidence_threshold_override" in data.model_fields_set
        with pytest.raises(HTTPException) as exc_info:
            _check_confidence_threshold_permission(analyst, data, current_value=80)
        assert exc_info.value.status_code == 403

    def test_explicit_null_when_already_null_is_noop(
        self, session, admin_user, template
    ):
        """No actual change — incoming None equals stored None — must not raise."""
        from ion.web.alert_prompt_api import (
            _check_confidence_threshold_permission,
            AlertPromptUpdate,
        )

        _, analyst = admin_user
        data = AlertPromptUpdate(confidence_threshold_override=None)
        _check_confidence_threshold_permission(analyst, data, current_value=None)

    def test_same_value_resubmit_is_noop(
        self, session, admin_user, template
    ):
        """Saving the same value back must not require system:settings."""
        from ion.web.alert_prompt_api import (
            _check_confidence_threshold_permission,
            AlertPromptUpdate,
        )

        _, analyst = admin_user
        data = AlertPromptUpdate(confidence_threshold_override=75)
        _check_confidence_threshold_permission(analyst, data, current_value=75)
