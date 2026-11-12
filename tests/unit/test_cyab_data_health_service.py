"""Unit tests for cyab_data_health_service."""

import json

import pytest
from unittest.mock import MagicMock


def test_ingestion_freshness_returns_per_source_rows():
    from ion.services import cyab_data_health_service as svc
    session = MagicMock()
    # 2 mocked data sources
    src1 = MagicMock(id=1, name="winlog", data_source_type="windows-evtx")
    src2 = MagicMock(id=2, name="proxy", data_source_type="generic-syslog")
    # last_event_at attribute may not exist on the model; ensure getattr fallback works
    del src1.last_event_at
    del src2.last_event_at
    session.execute.return_value.scalars.return_value.all.return_value = [src1, src2]

    rows = svc.ingestion_freshness(session, system_id=42)
    assert len(rows) == 2
    assert all("source_name" in r and "last_event_at" in r and "sla_status" in r for r in rows)
    # Without a last_event_at, status should be 'unknown'
    assert all(r["sla_status"] == "unknown" for r in rows)


def test_field_mapping_completeness_returns_zero_to_one():
    from ion.services import cyab_data_health_service as svc
    session = MagicMock()
    # field_mapping is stored as JSON-encoded text on the real model
    src = MagicMock(
        id=1,
        name="winlog",
        data_source_type="windows-evtx",
        field_mapping=json.dumps({"host.name": "Computer"}),
    )
    session.execute.return_value.scalars.return_value.all.return_value = [src]

    rows = svc.field_mapping_completeness(session, system_id=42)
    assert len(rows) == 1
    assert 0.0 <= rows[0]["completeness"] <= 1.0
    assert "missing_fields" in rows[0]


def test_field_mapping_completeness_handles_missing_mapping():
    """Sources with no field_mapping should report 0.0 completeness for known types."""
    from ion.services import cyab_data_health_service as svc
    session = MagicMock()
    src = MagicMock(
        id=1, name="syslog-1", data_source_type="generic-syslog", field_mapping=None
    )
    session.execute.return_value.scalars.return_value.all.return_value = [src]

    rows = svc.field_mapping_completeness(session, system_id=42)
    assert len(rows) == 1
    assert rows[0]["completeness"] == 0.0
    assert set(rows[0]["missing_fields"]) == {"@timestamp", "host.name", "message"}


def test_field_mapping_completeness_unknown_type_returns_none():
    """Unknown source types should return None completeness with a note."""
    from ion.services import cyab_data_health_service as svc
    session = MagicMock()
    src = MagicMock(
        id=1, name="weird", data_source_type="something-novel", field_mapping=None
    )
    session.execute.return_value.scalars.return_value.all.return_value = [src]

    rows = svc.field_mapping_completeness(session, system_id=42)
    assert len(rows) == 1
    assert rows[0]["completeness"] is None
    assert "note" in rows[0]


def test_coverage_rollup_wraps_subprofile_service(monkeypatch):
    from ion.services import cyab_data_health_service as svc
    monkeypatch.setattr(
        "ion.services.cyab_subprofile_service.system_coverage",
        lambda s, sid: {"intake_pct": 0.5, "detection_pct": 0.0, "audit_pct": 0.0},
    )
    out = svc.coverage_rollup(MagicMock(), system_id=42)
    assert isinstance(out, dict)
    assert out["intake_pct"] == 0.5


def test_reconciliation_panel_is_phase2_stub():
    from ion.services import cyab_data_health_service as svc
    out = svc.reconciliation_panel(MagicMock(), system_id=42)
    assert out["available"] is False
    assert "reason" in out


def test_sla_status_thresholds():
    """Verify the SLA status pill mapping for known ages."""
    from datetime import datetime, timedelta, timezone
    from ion.services import cyab_data_health_service as svc

    now = datetime.now(timezone.utc)
    assert svc._sla_status(None) == "unknown"
    assert svc._sla_status(now - timedelta(minutes=5)) == "fresh"
    assert svc._sla_status(now - timedelta(hours=2)) == "amber"
    assert svc._sla_status(now - timedelta(days=2)) == "red"
