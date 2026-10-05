"""A refused request leaves a row in audit_logs.

Policy refusals and permission denials went only to the application log, so a
deployment could not answer "who was refused what, from where" from the
database. The refusal path raises immediately, abandoning the request session,
so the row has to be written on its own committed session — a row added to the
request's session would roll back with the request and leave nothing behind.

These pin that the row survives the raise, that it carries who/what/where, and
that a failure to record never turns a refusal into a 500.
"""

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from starlette.requests import Request

import ion.auth.dependencies as deps
from ion.models.base import Base
from ion.models.user import AuditLog, User


@pytest.fixture
def audit_db(monkeypatch):
    """Point audit_refusal's independent session at a temp database."""
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    with factory() as s:
        s.add(User(id=1, username="analyst", email="n@x.y", password_hash="x"))
        s.commit()
    monkeypatch.setattr("ion.storage.database.get_engine", lambda *a, **k: engine)
    monkeypatch.setattr("ion.storage.database.get_session_factory", lambda *a, **k: factory)
    yield factory
    engine.dispose()


def _request(path="/api/cases", method="GET"):
    return Request({
        "type": "http", "method": method, "path": path, "query_string": b"",
        "headers": [], "client": ("198.51.100.7", 9000),
    })


def _user(flagged=False, tenant_id=None):
    return SimpleNamespace(
        id=1, username="analyst", email="n@x.y", must_change_password=flagged,
        has_permission=lambda p: False, has_any_permission=lambda p: False,
        tenant_id=tenant_id,
    )


def _rows(factory):
    with factory() as s:
        return s.query(AuditLog).all()


def _enforced(on=True):
    return patch("ion.auth.dependencies.get_config",
                 return_value=SimpleNamespace(enforce_password_change=on, db_path=None))


# ── the row survives the raise ─────────────────────────────────────────────

def test_permission_denial_is_recorded(audit_db):
    deps._permission_denied(_user(), "case:read", _request("/api/cases"))
    rows = _rows(audit_db)
    assert len(rows) == 1
    row = rows[0]
    assert row.action == "permission_denied"
    assert row.user_id == 1
    assert row.ip_address == "198.51.100.7"
    details = json.loads(row.details)
    assert details["required"] == "case:read"
    assert details["path"] == "/api/cases"
    assert details["method"] == "GET"


def test_password_change_refusal_is_recorded(audit_db):
    svc = MagicMock()
    svc.validate_session.return_value = _user(flagged=True)
    with _enforced():
        with pytest.raises(HTTPException):
            deps._authenticate(_request("/api/cases"), "tok", svc)
    rows = _rows(audit_db)
    assert [r.action for r in rows] == ["password_change_required"]
    assert rows[0].user_id == 1


def test_refusal_row_outlives_an_aborted_request_session(audit_db):
    """The request session is rolled back; the audit row must still be there."""
    with audit_db() as request_session:
        deps._permission_denied(_user(), "case:read", _request())
        request_session.rollback()
    assert len(_rows(audit_db)) == 1


def test_mcp_tool_denial_is_recorded(audit_db):
    import ion.web.mcp_api as mcp

    msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
           "params": {"name": "list_alerts", "arguments": {}}}
    result = mcp._handle_message(msg, _user(), _request("/api/mcp", "POST"))
    assert "Permission denied" in json.dumps(result)
    rows = _rows(audit_db)
    assert len(rows) == 1
    details = json.loads(rows[0].details)
    assert details["tool"] == "list_alerts"
    assert details["entry"] == "mcp"


def test_tenant_unavailable_is_recorded(audit_db):
    svc = MagicMock()
    with patch("ion.services.tenant_service.multi_tenant_enabled", return_value=True), \
         patch("ion.services.tenant_service.resolve_tenant_for_user", return_value=None):
        with pytest.raises(HTTPException) as caught:
            deps._resolve_tenant_binding(_request(), _user(tenant_id=4), svc)
    assert caught.value.status_code == 403
    rows = _rows(audit_db)
    assert [r.action for r in rows] == ["tenant_unavailable"]
    assert json.loads(rows[0].details)["bound_tenant_id"] == 4


def test_tenant_resolve_failure_is_recorded(audit_db):
    svc = MagicMock()
    with patch("ion.services.tenant_service.multi_tenant_enabled", return_value=True), \
         patch("ion.services.tenant_service.resolve_tenant_for_user",
               side_effect=RuntimeError("lookup exploded")):
        with pytest.raises(HTTPException) as caught:
            deps._resolve_tenant_binding(_request(), _user(), svc)
    assert caught.value.status_code == 503
    assert [r.action for r in _rows(audit_db)] == ["tenant_resolve_failed"]


# ── recording must never change the outcome ────────────────────────────────

def test_a_broken_audit_write_still_refuses(monkeypatch):
    """Losing the record must not downgrade a refusal into a 500."""
    monkeypatch.setattr("ion.storage.database.get_engine",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("no db")))
    exc = deps._permission_denied(_user(), "case:read", _request())
    assert exc.status_code == 403


def test_audit_without_a_request_is_tolerated(audit_db):
    deps.audit_refusal("permission_denied", _user(), None, required="case:read")
    row = _rows(audit_db)[0]
    assert row.ip_address is None
    assert json.loads(row.details) == {"required": "case:read"}


def test_denied_caller_is_not_told_the_permission(audit_db):
    """The taxonomy goes to the record, not to whoever was refused."""
    exc = deps._permission_denied(_user(), "case:read", _request())
    assert "case:read" not in str(exc.detail)
    assert json.loads(_rows(audit_db)[0].details)["required"] == "case:read"
