"""Tests for triage data loading, case export format, and sync retry fixes."""

import asyncio
import pytest
from unittest.mock import MagicMock, patch, AsyncMock
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from ion.models.base import Base
from ion.models.alert_triage import AlertCase, AlertCaseStatus
from ion.models.user import User
from ion.services.case_description import build_case_description


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine():
    eng = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(eng)
    return eng


@pytest.fixture
def session(engine):
    factory = sessionmaker(bind=engine)
    sess = factory()
    yield sess
    sess.close()


@pytest.fixture
def admin_user(session):
    user = User(username="admin", email="admin@test.local", password_hash="x")
    session.add(user)
    session.flush()
    return user


def _make_case(session, admin_user, **overrides):
    """Helper to create an AlertCase with sensible defaults."""
    defaults = dict(
        case_number="ION-0001",
        title="Test Case",
        description="Test description",
        status=AlertCaseStatus.OPEN,
        severity="high",
        created_by_id=admin_user.id,
        affected_hosts=["host-a"],
        affected_users=["user-a"],
        triggered_rules=["rule-1"],
        evidence_summary="Something suspicious",
        source_alert_ids=["alert-1", "alert-2"],
        observables=[{"type": "ip", "value": "10.0.0.1"}],
    )
    defaults.update(overrides)
    case = AlertCase(**defaults)
    session.add(case)
    session.flush()
    return case


def _run(coro):
    """Run an async coroutine synchronously."""
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Fix 1: loadTriageData → loadTriageBatch in alerts.html
# ---------------------------------------------------------------------------

class TestLoadTriageDataReplacement:
    """Verify the JS template no longer references the undefined loadTriageData()."""

    def test_no_loadTriageData_references(self):
        import pathlib
        html_path = pathlib.Path(__file__).resolve().parents[2] / "src" / "ion" / "web" / "templates" / "alerts.html"
        content = html_path.read_text(encoding="utf-8")
        assert "loadTriageData()" not in content, (
            "alerts.html still contains loadTriageData() — should be loadTriageBatch()"
        )

    def test_loadTriageBatch_exists(self):
        import pathlib
        html_path = pathlib.Path(__file__).resolve().parents[2] / "src" / "ion" / "web" / "templates" / "alerts.html"
        content = html_path.read_text(encoding="utf-8")
        assert "async function loadTriageBatch()" in content, (
            "loadTriageBatch function definition not found in alerts.html"
        )
        # At least 8 call sites + the definition
        assert content.count("loadTriageBatch()") >= 9


# ---------------------------------------------------------------------------
# Fix 2: build_case_description produces richer format than ad-hoc builder
# ---------------------------------------------------------------------------

class TestBuildCaseDescription:
    """Ensure the shared description builder produces the structured markdown."""

    def test_includes_observables_section(self):
        desc = build_case_description(
            description="Brute force detected",
            observables=[{"type": "ip", "value": "10.0.0.1"}],
        )
        assert "**Observables:**" in desc
        assert "10.0.0.1" in desc

    def test_includes_linked_alert_ids(self):
        desc = build_case_description(
            description="Case",
            alert_ids=["abc-123", "def-456"],
        )
        assert "**Linked Alert IDs (2):**" in desc
        assert "`abc-123`" in desc

    def test_includes_all_structured_fields(self):
        desc = build_case_description(
            description="desc",
            affected_hosts=["h1"],
            affected_users=["u1"],
            triggered_rules=["r1"],
            evidence_summary="summary",
            observables=[{"type": "domain", "value": "evil.com"}],
            alert_ids=["a1"],
        )
        for expected in ("**Affected Hosts:**", "**Affected Users:**",
                         "**Triggered Rules:**", "**Evidence Summary:**",
                         "**Observables:**", "**Linked Alert IDs"):
            assert expected in desc, f"Missing section: {expected}"

    def test_empty_inputs_returns_empty(self):
        assert build_case_description() == ""


# ---------------------------------------------------------------------------
# Fix 2b: Shared observable extractor covers all field categories
# ---------------------------------------------------------------------------

class TestObservableExtractor:
    """Verify the shared extract_observables_from_raw covers all field types."""

    def test_extracts_ips(self):
        from ion.services.observable_extractor import extract_observables_from_raw
        raw = {"source": {"ip": "10.0.0.1"}, "destination": {"ip": "10.0.0.2"}}
        obs = extract_observables_from_raw(raw)
        types = {o["type"] for o in obs}
        assert "source_ip" in types
        assert "destination_ip" in types

    def test_extracts_process_info(self):
        """This was missing from the old sync service extractor."""
        from ion.services.observable_extractor import extract_observables_from_raw
        raw = {
            "process": {
                "name": "malware.exe",
                "command_line": "malware.exe --steal-data",
                "pid": "1234",
                "parent": {"name": "explorer.exe"},
            }
        }
        obs = extract_observables_from_raw(raw)
        types = {o["type"] for o in obs}
        assert "process_name" in types
        assert "command_line" in types
        assert "process_id" in types
        assert "parent_process" in types

    def test_extracts_mitre_attack(self):
        """This was missing from the old sync service extractor."""
        from ion.services.observable_extractor import extract_observables_from_raw
        raw = {
            "threat": {
                "technique": {"id": "T1059", "name": "Command and Scripting Interpreter"},
                "tactic": {"name": "Execution"},
            }
        }
        obs = extract_observables_from_raw(raw)
        types = {o["type"] for o in obs}
        assert "mitre_technique" in types
        assert "mitre_technique_name" in types
        assert "mitre_tactic" in types

    def test_extracts_network_ports(self):
        """This was missing from the old sync service extractor."""
        from ion.services.observable_extractor import extract_observables_from_raw
        raw = {"destination": {"port": "443"}, "network": {"protocol": "tcp"}}
        obs = extract_observables_from_raw(raw)
        types = {o["type"] for o in obs}
        assert "port" in types
        assert "protocol" in types

    def test_extracts_registry_keys(self):
        """This was missing from the old sync service extractor."""
        from ion.services.observable_extractor import extract_observables_from_raw
        raw = {"registry": {"path": r"HKLM\Software\Evil", "value": "payload"}}
        obs = extract_observables_from_raw(raw)
        types = {o["type"] for o in obs}
        assert "registry_key" in types
        assert "registry_value" in types

    def test_extracts_kibana_security_fields(self):
        """This was missing from the old sync service extractor."""
        from ion.services.observable_extractor import extract_observables_from_raw
        raw = {
            "kibana.alert.rule.name": "Brute Force Attempt",
            "kibana.alert.severity": "high",
            "kibana.alert.risk_score": "73",
        }
        obs = extract_observables_from_raw(raw)
        types = {o["type"] for o in obs}
        assert "rule_name" in types
        assert "severity" in types
        assert "risk_score" in types

    def test_handles_flattened_dot_notation(self):
        """Kibana Security uses flattened keys like 'source.ip' as a single key."""
        from ion.services.observable_extractor import extract_observables_from_raw
        raw = {"source.ip": "192.168.1.1"}  # Flattened, not nested
        obs = extract_observables_from_raw(raw)
        assert any(o["value"] == "192.168.1.1" for o in obs)

    def test_deduplicates(self):
        from ion.services.observable_extractor import extract_observables_from_raw
        raw = {"host": {"name": "srv01", "hostname": "srv01"}}
        obs = extract_observables_from_raw(raw)
        hostnames = [o for o in obs if o["type"] == "hostname"]
        assert len(hostnames) == 1

    def test_empty_input(self):
        from ion.services.observable_extractor import extract_observables_from_raw
        assert extract_observables_from_raw({}) == []


# ---------------------------------------------------------------------------
# Fix 3: export_cases_to_kibana retry logic
# ---------------------------------------------------------------------------

class TestExportRetryLogic:
    """Test that export_cases_to_kibana catches partially-failed exports."""

    def test_unlinked_case_creates_in_kibana(self, session, admin_user):
        """Case with no kibana_case_id → create_case is called."""
        case = _make_case(session, admin_user, kibana_case_id=None, kibana_case_version=None)
        session.commit()

        with patch("ion.services.kibana_sync_service.get_kibana_cases_service") as mock_get:
            mock_kb = MagicMock()
            mock_kb.enabled = True
            mock_kb.create_case.return_value = {"id": "kb-1", "version": "v1"}
            mock_get.return_value = mock_kb

            from ion.services.kibana_sync_service import KibanaSyncService
            svc = KibanaSyncService()
            svc.kibana_service = mock_kb
            svc.sync_case_status_to_kibana = AsyncMock()

            result = _run(svc.export_cases_to_kibana(session))

        mock_kb.create_case.assert_called_once()
        assert result["exported"] == 1
        assert case.kibana_case_id == "kb-1"
        assert case.kibana_case_version == "v1"

    def test_partial_failure_retries_with_update(self, session, admin_user):
        """Case with kibana_case_id but no version → fetches version then updates."""
        case = _make_case(
            session, admin_user,
            kibana_case_id="kb-orphan",
            kibana_case_version=None,
        )
        session.commit()

        with patch("ion.services.kibana_sync_service.get_kibana_cases_service") as mock_get:
            mock_kb = MagicMock()
            mock_kb.enabled = True
            mock_kb.get_case.return_value = {"id": "kb-orphan", "version": "v5"}
            mock_kb.update_case.return_value = {"id": "kb-orphan", "version": "v6"}
            mock_get.return_value = mock_kb

            from ion.services.kibana_sync_service import KibanaSyncService
            svc = KibanaSyncService()
            svc.kibana_service = mock_kb
            svc.sync_case_status_to_kibana = AsyncMock()

            result = _run(svc.export_cases_to_kibana(session))

        mock_kb.get_case.assert_called_once_with("kb-orphan")
        mock_kb.update_case.assert_called_once()
        mock_kb.create_case.assert_not_called()
        assert case.kibana_case_version == "v6"

    def test_partial_failure_stale_id_creates_new(self, session, admin_user):
        """Case with kibana_case_id that no longer exists in Kibana → creates fresh."""
        case = _make_case(
            session, admin_user,
            kibana_case_id="kb-gone",
            kibana_case_version=None,
        )
        session.commit()

        with patch("ion.services.kibana_sync_service.get_kibana_cases_service") as mock_get:
            mock_kb = MagicMock()
            mock_kb.enabled = True
            mock_kb.get_case.return_value = None  # Kibana case deleted
            mock_kb.create_case.return_value = {"id": "kb-new", "version": "v1"}
            mock_get.return_value = mock_kb

            from ion.services.kibana_sync_service import KibanaSyncService
            svc = KibanaSyncService()
            svc.kibana_service = mock_kb
            svc.sync_case_status_to_kibana = AsyncMock()

            result = _run(svc.export_cases_to_kibana(session))

        mock_kb.create_case.assert_called_once()
        assert case.kibana_case_id == "kb-new"
        assert case.kibana_case_version == "v1"

    def test_fully_linked_case_is_skipped(self, session, admin_user):
        """Case with both kibana_case_id and version → not touched."""
        _make_case(
            session, admin_user,
            kibana_case_id="kb-ok",
            kibana_case_version="v3",
        )
        session.commit()

        with patch("ion.services.kibana_sync_service.get_kibana_cases_service") as mock_get:
            mock_kb = MagicMock()
            mock_kb.enabled = True
            mock_get.return_value = mock_kb

            from ion.services.kibana_sync_service import KibanaSyncService
            svc = KibanaSyncService()
            svc.kibana_service = mock_kb
            svc.sync_case_status_to_kibana = AsyncMock()

            result = _run(svc.export_cases_to_kibana(session))

        assert result["exported"] == 0
        mock_kb.create_case.assert_not_called()
        mock_kb.update_case.assert_not_called()

    def test_export_uses_build_case_description(self, session, admin_user):
        """Verify the export path uses build_case_description (includes Observables section)."""
        case = _make_case(
            session, admin_user,
            kibana_case_id=None,
            kibana_case_version=None,
            observables=[{"type": "ip", "value": "1.2.3.4"}],
            source_alert_ids=["a-1"],
        )
        session.commit()

        with patch("ion.services.kibana_sync_service.get_kibana_cases_service") as mock_get:
            mock_kb = MagicMock()
            mock_kb.enabled = True
            mock_kb.create_case.return_value = {"id": "kb-x", "version": "v1"}
            mock_get.return_value = mock_kb

            from ion.services.kibana_sync_service import KibanaSyncService
            svc = KibanaSyncService()
            svc.kibana_service = mock_kb
            svc.sync_case_status_to_kibana = AsyncMock()

            _run(svc.export_cases_to_kibana(session))

        call_kwargs = mock_kb.create_case.call_args
        description = call_kwargs.kwargs.get("description") or call_kwargs[1].get("description", "")
        # build_case_description adds Observables and Linked Alert IDs sections
        assert "**Observables:**" in description
        assert "**Linked Alert IDs" in description
