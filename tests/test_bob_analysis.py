"""Tests for the v0.23.1 on-demand Bob case-analysis endpoint.

Covers:

- ``POST /api/elasticsearch/alerts/cases/{id}/bob-analysis`` returns 404 on
  a non-existent case.
- With Ollama mocked, the endpoint returns the analysis text + source
  counts (alerts, investigations, observables, similar cases).
- The endpoint does NOT write a Note row (key v0.23.1 behaviour change
  from v0.22.x where Bob auto-commented).
- v0.23.1 regression on investigation_service._post_to_case: after the
  removal of the auto-comment write site, the method no longer creates a
  Note for the case.
"""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, selectinload, sessionmaker

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import ion.models  # noqa: F401
from ion.models.alert_triage import AlertCase, AlertTriage, Note, NoteEntityType
from ion.models.base import Base
from ion.models.user import Permission, Role, User, role_permissions, user_roles
from ion.storage.database import _run_migrations, reset_engine


@pytest.fixture(scope="function")
def engine(tmp_path):
    db_path = tmp_path / "v023_1_bob_analysis.db"
    eng = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(eng)
    _run_migrations(eng)
    yield eng
    eng.dispose()


@pytest.fixture(scope="function")
def db(engine):
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    session = factory()
    yield session
    session.rollback()
    session.close()


@pytest.fixture()
def case_user(db: Session) -> User:
    p = Permission(name="case:read", resource="case", action="read")
    db.add(p)
    db.flush()
    role = Role(name="case-reader", description="Case reader", is_system=False)
    db.add(role)
    db.flush()
    db.execute(role_permissions.insert().values(role_id=role.id, permission_id=p.id))
    u = User(
        username="case_reader",
        email="case_reader@test.ion",
        password_hash="x",
        is_active=True,
        display_name="Case Reader",
    )
    db.add(u)
    db.flush()
    db.execute(user_roles.insert().values(user_id=u.id, role_id=role.id))
    db.commit()
    db.refresh(u)
    return u


@pytest.fixture()
def app_client(engine, case_user, monkeypatch):
    """TestClient with overridden auth + DB and a stubbed OllamaService.chat."""
    reset_engine()
    from ion.web.server import app
    from ion.auth.dependencies import get_current_user, get_db_session
    from ion.web.api import get_db_session as api_get_db_session

    test_sf = sessionmaker(bind=engine, expire_on_commit=False)

    def _session_factory():
        s = test_sf()
        try:
            yield s
        finally:
            s.close()

    def _fake_user():
        s = test_sf()
        try:
            u = (
                s.query(User)
                .options(selectinload(User.roles).selectinload(Role.permissions))
                .filter_by(id=case_user.id)
                .one()
            )
            s.expunge(u)
            return u
        finally:
            s.close()

    # Stub the Ollama chat so we don't need a real LLM. Returns canned content.
    async def _fake_chat(self, messages, **kwargs):
        return {
            "content": (
                "## Verdict\n"
                "true_positive — host PT-LAB-04 shows encoded PowerShell "
                "consistent with T1059.001.\n"
                "## Evidence\n"
                "- rule.name == Suspicious encoded PowerShell\n"
                "- observable.process == powershell.exe\n"
                "## Similar prior cases\n"
                "- None matched closely enough.\n"
                "## Recommended next steps\n"
                "- Isolate PT-LAB-04\n"
                "- Pull the host's recent process tree\n"
            ),
            "model": "stub-llm",
            "done": True,
        }
    monkeypatch.setattr(
        "ion.services.ollama_service.OllamaService.chat", _fake_chat
    )
    monkeypatch.setattr(
        "ion.services.ollama_service.OllamaService.enabled", True, raising=False
    )

    app.dependency_overrides[get_db_session] = _session_factory
    app.dependency_overrides[api_get_db_session] = _session_factory
    app.dependency_overrides[get_current_user] = _fake_user

    with TestClient(app, raise_server_exceptions=False) as client:
        yield client

    app.dependency_overrides.clear()
    reset_engine()


def _make_case(db: Session, user: User, *, observables=None) -> AlertCase:
    case = AlertCase(
        case_number=f"BA-{user.id}-{datetime.utcnow().timestamp():.0f}",
        title="Encoded PowerShell on PT-LAB-04",
        status="open",
        severity="high",
        created_by_id=user.id,
        observables=observables or [
            {"type": "host", "value": "PT-LAB-04", "source": "rule"},
            {"type": "process", "value": "powershell.exe", "source": "rule"},
        ],
    )
    db.add(case)
    db.commit()
    db.refresh(case)
    return case


def _link_triage(db: Session, case: AlertCase, es_alert_id: str,
                  rule_name: str = "Suspicious encoded PowerShell") -> AlertTriage:
    # host / user_name are NOT columns on AlertTriage; they come from the ES
    # alert hit. The prompt builder handles their absence via getattr.
    triage = AlertTriage(
        es_alert_id=es_alert_id,
        status="open",
        case_id=case.id,
        rule_name=rule_name,
        priority="high",
    )
    db.add(triage)
    db.commit()
    return triage


# ── Tests ─────────────────────────────────────────────────────────────────


class TestBobAnalysisEndpoint:
    def test_returns_404_when_case_missing(self, app_client):
        r = app_client.post(
            "/api/elasticsearch/alerts/cases/999999/bob-analysis"
        )
        assert r.status_code == 404

    def test_returns_analysis_with_source_counts(
        self, app_client, db, case_user
    ):
        case = _make_case(db, case_user)
        _link_triage(db, case, "alert-ba-001")

        r = app_client.post(
            f"/api/elasticsearch/alerts/cases/{case.id}/bob-analysis"
        )
        assert r.status_code == 200, r.text
        data = r.json()
        assert "true_positive" in data["analysis"]
        assert data["model"] == "stub-llm"
        s = data["sources"]
        assert s["alerts_count"] == 1
        assert s["observables_count"] == 2
        assert s["investigations_count"] == 0
        assert s["similar_cases_count"] == 0

    def test_endpoint_does_not_write_a_note(
        self, app_client, db, case_user
    ):
        """v0.23.1 contract: generation is display-only — no Note row written."""
        case = _make_case(db, case_user)
        _link_triage(db, case, "alert-ba-002")

        notes_before = db.execute(
            text("SELECT COUNT(*) FROM notes WHERE entity_id = :cid"),
            {"cid": str(case.id)},
        ).scalar()
        assert notes_before == 0

        r = app_client.post(
            f"/api/elasticsearch/alerts/cases/{case.id}/bob-analysis"
        )
        assert r.status_code == 200

        notes_after = db.execute(
            text("SELECT COUNT(*) FROM notes WHERE entity_id = :cid"),
            {"cid": str(case.id)},
        ).scalar()
        assert notes_after == 0, "Bob analysis must NOT auto-create a Note"


# ── Regression: investigation_service._post_to_case no longer writes notes ──


class TestPostToCaseRemovesAutoComment:
    def test_post_to_case_does_not_create_a_note(self, db, case_user, monkeypatch):
        """v0.23.1: the auto-comment write site in _post_to_case is removed.

        Side-effects that SHOULD remain: IOC merge + status transitions.
        Side-effect that MUST be gone: Note creation on the case.
        """
        from ion.services.investigation_service import InvestigationService

        case = _make_case(db, case_user)
        triage = _link_triage(db, case, "alert-post-to-case-001")

        svc = InvestigationService()
        # Force the service to use this test's session factory + skip ES.
        monkeypatch.setattr(
            svc, "_get_es", lambda: type("X", (), {
                "update_alert_workflow_status": lambda self, *a, **kw: None,
            })()
        )
        monkeypatch.setattr(
            "ion.storage.database.get_session_factory",
            lambda engine=None: sessionmaker(bind=db.bind, expire_on_commit=False),
            raising=False,
        )

        import asyncio
        asyncio.run(svc._post_to_case(
            alert_id="alert-post-to-case-001",
            inv_id=1,
            verdict="true_positive",
            severity="high",
            summary="dummy verdict — must not be persisted as a note",
            iocs={"ips": ["10.0.0.5"]},
        ))

        notes_count = db.execute(
            text("SELECT COUNT(*) FROM notes WHERE entity_id = :cid"),
            {"cid": str(case.id)},
        ).scalar()
        assert notes_count == 0, (
            "_post_to_case must not auto-create a Note in v0.23.1"
        )

        # IOC merge side-effect should still have happened.
        db.refresh(case)
        obs_values = [o.get("value") for o in (case.observables or [])]
        assert "10.0.0.5" in obs_values, (
            "_post_to_case should still merge IOCs into case.observables"
        )
