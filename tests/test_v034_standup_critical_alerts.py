"""Tests for v0.34.2 daily-standup critical-alerts fix.

Two behaviours verified:

1. When ES is configured and returns an empty list (zero critical alerts),
   the response uses source='elasticsearch' and critical_count=0.
   The AlertTriage fallback must NOT activate.

2. When ES is unconfigured (or errors), the fallback activates with
   source='ion_fallback', and rule_name/title never expose the raw
   es_alert_id UUID.
"""

from __future__ import annotations

import asyncio
import sys
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from ion.web.daily_standup_api import _check_critical_alerts

# ── helpers ───────────────────────────────────────────────────────────────


def _mock_es(*, configured: bool, alerts: list, raises=None):
    es = MagicMock()
    es.is_configured = configured
    if raises:
        es.get_alerts = AsyncMock(side_effect=raises)
    else:
        es.get_alerts = AsyncMock(return_value=alerts)
    return es


def _fake_alert(rule_name=None):
    a = MagicMock()
    a.id = "abc123"
    a.title = "Alert title"
    a.severity = "critical"
    a.status = "open"
    a.host = "web-01"
    a.timestamp = datetime(2026, 5, 28, 12, 0, tzinfo=timezone.utc)
    a.rule_name = rule_name
    return a


def _run(coro):
    return asyncio.run(coro)


# ── Test 1: ES returns empty — no fallback ────────────────────────────────


def test_es_returns_empty_no_fallback():
    """Zero critical alerts from a healthy ES must be returned directly."""
    with patch(
        "ion.services.elasticsearch_service.ElasticsearchService",
        return_value=_mock_es(configured=True, alerts=[]),
    ):
        result = _run(_check_critical_alerts())

    assert result["source"] == "elasticsearch"
    assert result["critical_count"] == 0
    assert result["alerts"] == []


# ── Test 2: ES returns alerts — rule_name populated ───────────────────────


def test_es_returns_alerts_with_rule_name():
    alert = _fake_alert(rule_name="Suspicious Login")
    with patch(
        "ion.services.elasticsearch_service.ElasticsearchService",
        return_value=_mock_es(configured=True, alerts=[alert]),
    ):
        result = _run(_check_critical_alerts())

    assert result["source"] == "elasticsearch"
    assert result["critical_count"] == 1
    assert result["alerts"][0]["rule_name"] == "Suspicious Login"


# ── Test 3: ES alert with null rule_name falls back to title ──────────────


def test_es_null_rule_name_falls_back_to_title():
    alert = _fake_alert(rule_name=None)
    with patch(
        "ion.services.elasticsearch_service.ElasticsearchService",
        return_value=_mock_es(configured=True, alerts=[alert]),
    ):
        result = _run(_check_critical_alerts())

    assert result["source"] == "elasticsearch"
    rn = result["alerts"][0]["rule_name"]
    assert rn is not None
    assert rn != "abc123"  # must not be the es document id
    assert rn in ("Alert title", "(rule unknown)")


# ── Test 4: ES not configured — fallback activates ────────────────────────


def test_es_not_configured_triggers_fallback(tmp_path):
    db_path = tmp_path / "standup_test.db"

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import ion.models  # noqa: F401
    from ion.models.base import Base
    from ion.storage.database import _run_migrations

    engine = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(engine)
    _run_migrations(engine)

    with patch(
        "ion.services.elasticsearch_service.ElasticsearchService",
        return_value=_mock_es(configured=False, alerts=[]),
    ), patch("ion.core.config.get_config") as mock_cfg, patch(
        "ion.storage.database.get_engine", return_value=engine
    ), patch(
        "ion.storage.database.get_session_factory",
        return_value=sessionmaker(bind=engine),
    ):
        mock_cfg.return_value.db_path = str(db_path)
        result = _run(_check_critical_alerts())

    assert result["source"] == "ion_fallback"
    assert "ES not configured" in result["fallback_reason"]


# ── Test 5: ES errors — fallback with error message ───────────────────────


def test_es_error_triggers_fallback(tmp_path):
    db_path = tmp_path / "standup_test2.db"

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import ion.models  # noqa: F401
    from ion.models.base import Base
    from ion.storage.database import _run_migrations

    engine = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(engine)
    _run_migrations(engine)

    with patch(
        "ion.services.elasticsearch_service.ElasticsearchService",
        return_value=_mock_es(
            configured=True, alerts=[], raises=ConnectionError("ES unreachable")
        ),
    ), patch("ion.core.config.get_config") as mock_cfg, patch(
        "ion.storage.database.get_engine", return_value=engine
    ), patch(
        "ion.storage.database.get_session_factory",
        return_value=sessionmaker(bind=engine),
    ):
        mock_cfg.return_value.db_path = str(db_path)
        result = _run(_check_critical_alerts())

    assert result["source"] == "ion_fallback"
    assert "ES error" in result["fallback_reason"]


# ── Test 6: Fallback never exposes raw es_alert_id as display name ─────────


def test_fallback_no_raw_alert_id_in_display(tmp_path):
    db_path = tmp_path / "standup_test3.db"

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import ion.models  # noqa: F401
    from ion.models.alert_triage import AlertTriage, AlertTriageStatus
    from ion.models.base import Base
    from ion.storage.database import _run_migrations

    engine = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(engine)
    _run_migrations(engine)

    RAW_ID = "deadbeef-1234-5678-abcd-000000000000"

    Session = sessionmaker(bind=engine)
    with Session() as s:
        row = AlertTriage(
            es_alert_id=RAW_ID,
            rule_name=None,
            status=AlertTriageStatus.OPEN,
            created_at=datetime.now(timezone.utc).replace(tzinfo=None),
        )
        s.add(row)
        s.commit()

    with patch(
        "ion.services.elasticsearch_service.ElasticsearchService",
        return_value=_mock_es(configured=False, alerts=[]),
    ), patch("ion.core.config.get_config") as mock_cfg, patch(
        "ion.storage.database.get_engine", return_value=engine
    ), patch(
        "ion.storage.database.get_session_factory",
        return_value=sessionmaker(bind=engine),
    ):
        mock_cfg.return_value.db_path = str(db_path)
        result = _run(_check_critical_alerts())

    assert result["source"] == "ion_fallback"
    assert len(result["alerts"]) == 1
    a = result["alerts"][0]
    assert a["title"] != RAW_ID
    assert a["rule_name"] != RAW_ID
    assert a["title"] == "(rule unknown)"
    assert a["rule_name"] == "(rule unknown)"
