"""Tests for the ION MCP server endpoint (v0.40.0).

Covers:
- JSON-RPC 2.0 protocol contract (initialize / ping / unknown method / parse error)
- Auth gate (401 when unauthenticated)
- tools/list — permission filtering (caller only sees tools they can use)
- tools/call — dispatch, unknown tool, permission denied
- Each of the 8 tool implementations against a mock DB
- Batch request handling
- Notification handling (HTTP 202 / no response body)
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import ion.web.mcp_api as mcp_mod
from ion.web.mcp_api import router as mcp_router

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _app():
    app = FastAPI()
    app.include_router(mcp_router)
    return app


def _user(perms: list[str] | None = None) -> MagicMock:
    """Return a mock User with has_permission returning True for ``perms``.

    Pass ``perms=None`` for the default full-permission set, or an explicit
    list (including ``[]`` for zero permissions).
    """
    user = MagicMock()
    user.id = 1
    user.username = "analyst"
    if perms is None:
        _perms = {"alert:read", "case:read", "case:update", "observable:read", "playbook:read"}
    else:
        _perms = set(perms)
    user.has_permission.side_effect = lambda p: p in _perms
    return user


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _rpc(method: str, params=None, req_id=1) -> dict:
    msg: dict = {"jsonrpc": "2.0", "method": method, "id": req_id}
    if params is not None:
        msg["params"] = params
    return msg


def _post(client: TestClient, body: dict | list) -> dict:
    resp = client.post("/api/mcp", json=body)
    return resp


@pytest.fixture(autouse=True)
def _enable_mcp_by_default(monkeypatch):
    """Most tests assume the endpoint is toggled on. The dedicated
    ``TestFeatureFlag`` test deletes this to assert the default-off 404."""
    monkeypatch.setenv("ION_MCP_ENABLED", "true")


# ---------------------------------------------------------------------------
# Feature flag — OFF by default
# ---------------------------------------------------------------------------


class TestFeatureFlag:
    def test_mcp_enabled_default_off(self, monkeypatch):
        monkeypatch.delenv("ION_MCP_ENABLED", raising=False)
        assert mcp_mod.mcp_enabled() is False

    @pytest.mark.parametrize("val", ["true", "1", "yes", "on", "TRUE", "On"])
    def test_mcp_enabled_truthy_values(self, monkeypatch, val):
        monkeypatch.setenv("ION_MCP_ENABLED", val)
        assert mcp_mod.mcp_enabled() is True

    @pytest.mark.parametrize("val", ["false", "0", "no", "off", ""])
    def test_mcp_disabled_values(self, monkeypatch, val):
        monkeypatch.setenv("ION_MCP_ENABLED", val)
        assert mcp_mod.mcp_enabled() is False

    def test_endpoint_404_when_disabled(self, monkeypatch):
        monkeypatch.delenv("ION_MCP_ENABLED", raising=False)
        client = TestClient(_app())
        resp = client.post("/api/mcp", json=_rpc("initialize"))
        assert resp.status_code == 404

    def test_disabled_endpoint_does_no_auth(self, monkeypatch):
        # Flag is checked before auth: even a request that WOULD authenticate
        # gets 404, and _authenticate is never called.
        monkeypatch.delenv("ION_MCP_ENABLED", raising=False)
        with patch.object(mcp_mod, "_authenticate") as mock_auth:
            client = TestClient(_app())
            resp = client.post("/api/mcp", json=_rpc("ping"))
        assert resp.status_code == 404
        mock_auth.assert_not_called()

    def test_endpoint_reachable_when_enabled(self, monkeypatch):
        monkeypatch.setenv("ION_MCP_ENABLED", "true")
        with patch.object(mcp_mod, "_authenticate", return_value=_user()):
            client = TestClient(_app())
            resp = client.post("/api/mcp", json=_rpc("ping"))
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Auth gate
# ---------------------------------------------------------------------------


class TestAuthGate:
    def test_401_when_no_token(self):
        client = TestClient(_app())
        resp = _post(client, _rpc("initialize"))
        assert resp.status_code == 401
        data = resp.json()
        assert data["error"]["code"] == -32001

    def test_authenticated_request_reaches_handler(self):
        with patch.object(mcp_mod, "_authenticate", return_value=_user()):
            client = TestClient(_app())
            resp = _post(client, _rpc("ping"))
        assert resp.status_code == 200
        assert resp.json()["result"] == {}


# ---------------------------------------------------------------------------
# JSON-RPC protocol
# ---------------------------------------------------------------------------


class TestJsonRpcProtocol:
    @pytest.fixture(autouse=True)
    def authed(self):
        with patch.object(mcp_mod, "_authenticate", return_value=_user()):
            yield

    def test_initialize(self):
        client = TestClient(_app())
        resp = _post(client, _rpc("initialize", {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "pytest", "version": "1.0"},
        }))
        assert resp.status_code == 200
        result = resp.json()["result"]
        assert result["protocolVersion"] == "2025-03-26"
        assert result["serverInfo"]["name"] == "ION MCP Server"
        assert "tools" in result["capabilities"]

    def test_ping(self):
        client = TestClient(_app())
        resp = _post(client, _rpc("ping"))
        assert resp.status_code == 200
        assert resp.json()["result"] == {}

    def test_unknown_method_returns_minus_32601(self):
        client = TestClient(_app())
        resp = _post(client, _rpc("nonexistent/method"))
        assert resp.status_code == 200
        data = resp.json()
        assert data["error"]["code"] == -32601

    def test_parse_error_on_non_json_body(self):
        with patch.object(mcp_mod, "_authenticate", return_value=_user()):
            client = TestClient(_app())
            resp = client.post("/api/mcp", content=b"not json", headers={"Content-Type": "application/json"})
        assert resp.status_code == 400
        assert resp.json()["error"]["code"] == -32700

    def test_notification_returns_202_no_body(self):
        client = TestClient(_app())
        # Notification: no "id" field
        notif = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        resp = _post(client, notif)
        assert resp.status_code == 202

    def test_ping_notification_returns_202(self):
        client = TestClient(_app())
        notif = {"jsonrpc": "2.0", "method": "ping"}
        resp = _post(client, notif)
        assert resp.status_code == 202

    def test_response_id_echoes_request_id(self):
        client = TestClient(_app())
        resp = _post(client, _rpc("ping", req_id=42))
        assert resp.json()["id"] == 42

    def test_null_id_treated_as_notification(self):
        # JSON-RPC 2.0 discourages id: null but allows it.
        # Our implementation treats it the same as a missing id (notification → 202).
        client = TestClient(_app())
        resp = _post(client, {"jsonrpc": "2.0", "method": "ping", "id": None})
        assert resp.status_code == 202


# ---------------------------------------------------------------------------
# tools/list — permission filtering
# ---------------------------------------------------------------------------


class TestToolsList:
    def test_returns_all_tools_for_full_user(self):
        with patch.object(mcp_mod, "_authenticate", return_value=_user()):
            client = TestClient(_app())
            resp = _post(client, _rpc("tools/list"))
        tools = resp.json()["result"]["tools"]
        names = {t["name"] for t in tools}
        assert names == {
            "list_alerts", "get_alert", "list_cases", "get_case",
            "search_observables", "get_observable", "list_playbooks", "add_case_note",
        }

    def test_filters_by_permission(self):
        # User with ONLY alert:read
        user = _user(perms=["alert:read"])
        with patch.object(mcp_mod, "_authenticate", return_value=user):
            client = TestClient(_app())
            resp = _post(client, _rpc("tools/list"))
        names = {t["name"] for t in resp.json()["result"]["tools"]}
        assert names == {"list_alerts", "get_alert"}
        assert "list_cases" not in names

    def test_no_private_keys_in_response(self):
        with patch.object(mcp_mod, "_authenticate", return_value=_user()):
            client = TestClient(_app())
            resp = _post(client, _rpc("tools/list"))
        for tool in resp.json()["result"]["tools"]:
            for key in tool:
                assert not key.startswith("_")

    def test_each_tool_has_required_fields(self):
        with patch.object(mcp_mod, "_authenticate", return_value=_user()):
            client = TestClient(_app())
            resp = _post(client, _rpc("tools/list"))
        for tool in resp.json()["result"]["tools"]:
            assert "name" in tool
            assert "description" in tool
            assert "inputSchema" in tool


# ---------------------------------------------------------------------------
# tools/call — dispatch layer
# ---------------------------------------------------------------------------


class TestToolsCallDispatch:
    @pytest.fixture(autouse=True)
    def authed(self):
        with patch.object(mcp_mod, "_authenticate", return_value=_user()):
            yield

    def test_unknown_tool_returns_tool_error(self):
        client = TestClient(_app())
        resp = _post(client, _rpc("tools/call", {"name": "does_not_exist", "arguments": {}}))
        result = resp.json()["result"]
        assert result["isError"] is True
        assert "Unknown tool" in result["content"][0]["text"]

    def test_permission_denied_on_missing_perm(self):
        user = _user(perms=[])  # no permissions at all
        with patch.object(mcp_mod, "_authenticate", return_value=user):
            client = TestClient(_app())
            resp = _post(client, _rpc("tools/call", {"name": "list_alerts", "arguments": {}}))
        result = resp.json()["result"]
        assert result["isError"] is True
        assert "Permission denied" in result["content"][0]["text"]

    def test_tool_exception_returns_tool_error_not_500(self):
        with patch.object(mcp_mod, "_tool_list_alerts", side_effect=RuntimeError("db down")):
            client = TestClient(_app())
            resp = _post(client, _rpc("tools/call", {"name": "list_alerts", "arguments": {}}))
        assert resp.status_code == 200
        result = resp.json()["result"]
        assert result["isError"] is True
        text = result["content"][0]["text"]
        # The tool failure is surfaced as an error, but the raw exception
        # message must NOT be leaked to the client (py/stack-trace-exposure);
        # only a generic label / exception type name is returned.
        assert "Tool error" in text
        assert "db down" not in text


# ---------------------------------------------------------------------------
# Batch requests
# ---------------------------------------------------------------------------


class TestBatchRequests:
    def test_batch_returns_list(self):
        with patch.object(mcp_mod, "_authenticate", return_value=_user()):
            client = TestClient(_app())
            resp = _post(client, [
                _rpc("ping", req_id=1),
                _rpc("ping", req_id=2),
            ])
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) == 2
        ids = {d["id"] for d in data}
        assert ids == {1, 2}

    def test_batch_of_notifications_returns_204(self):
        with patch.object(mcp_mod, "_authenticate", return_value=_user()):
            client = TestClient(_app())
            resp = _post(client, [
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
            ])
        assert resp.status_code == 204


# ---------------------------------------------------------------------------
# Tool: list_alerts
# ---------------------------------------------------------------------------


def _mock_triage(id_=1, status="open", rule="Suspicious Login"):
    row = MagicMock()
    row.id = id_
    row.es_alert_id = f"es-{id_}"
    row.rule_name = rule
    row.status = MagicMock()
    row.status.value = status
    row.priority = "high"
    row.case_id = None
    row.mitre_techniques = ["T1078"]
    row.source_system = "prod"
    row.suggested_verdict = None
    row.created_at = datetime(2025, 1, 1, tzinfo=timezone.utc)
    row.updated_at = datetime(2025, 1, 2, tzinfo=timezone.utc)
    return row


class TestToolListAlerts:
    def _call(self, args=None):
        return mcp_mod._tool_list_alerts(args or {})

    def test_returns_alerts(self):
        fake_row = _mock_triage()
        mock_session = MagicMock()
        mock_session.query.return_value.order_by.return_value.limit.return_value.all.return_value = [fake_row]
        with patch.object(mcp_mod, "get_session_factory") as mock_factory:
            mock_factory.return_value.return_value = mock_session
            result = self._call({"limit": 10})
        assert result["isError"] is False
        import json
        data = json.loads(result["content"][0]["text"])
        assert data["total"] == 1
        assert data["alerts"][0]["id"] == 1
        assert data["alerts"][0]["status"] == "open"

    def test_invalid_status_returns_tool_error(self):
        result = self._call({"status": "nonsense"})
        assert result["isError"] is True
        assert "Invalid status" in result["content"][0]["text"]

    def test_limit_capped_at_200(self):
        mock_session = MagicMock()
        mock_session.query.return_value.order_by.return_value.limit.return_value.all.return_value = []
        with patch.object(mcp_mod, "get_session_factory") as mock_factory:
            mock_factory.return_value.return_value = mock_session
            self._call({"limit": 9999})
        # limit() call should be 200
        mock_session.query.return_value.order_by.return_value.limit.assert_called_with(200)

    def test_session_closed_on_success(self):
        mock_session = MagicMock()
        mock_session.query.return_value.order_by.return_value.limit.return_value.all.return_value = []
        with patch.object(mcp_mod, "get_session_factory") as mock_factory:
            mock_factory.return_value.return_value = mock_session
            self._call()
        mock_session.close.assert_called_once()


# ---------------------------------------------------------------------------
# Tool: get_alert
# ---------------------------------------------------------------------------


class TestToolGetAlert:
    def _call(self, args):
        return mcp_mod._tool_get_alert(args)

    def test_returns_detail(self):
        row = _mock_triage()
        row.analyst_notes = "looks sus"
        row.observables = [{"type": "ipv4", "value": "1.2.3.4"}]
        row.suggested_verdict_confidence_int = 80
        mock_session = MagicMock()
        mock_session.query.return_value.filter_by.return_value.first.return_value = row
        with patch.object(mcp_mod, "get_session_factory") as mock_factory:
            mock_factory.return_value.return_value = mock_session
            result = self._call({"alert_id": 1})
        import json
        data = json.loads(result["content"][0]["text"])
        assert data["analyst_notes"] == "looks sus"
        assert data["suggested_verdict_confidence_int"] == 80

    def test_not_found(self):
        mock_session = MagicMock()
        mock_session.query.return_value.filter_by.return_value.first.return_value = None
        with patch.object(mcp_mod, "get_session_factory") as mock_factory:
            mock_factory.return_value.return_value = mock_session
            result = self._call({"alert_id": 999})
        assert result["isError"] is True
        assert "not found" in result["content"][0]["text"]

    def test_non_int_id_returns_error(self):
        result = self._call({"alert_id": "abc"})
        assert result["isError"] is True


# ---------------------------------------------------------------------------
# Tool: list_cases
# ---------------------------------------------------------------------------


def _mock_case(id_=1, status="open", severity="high"):
    case = MagicMock()
    case.id = id_
    case.case_number = f"INC-{id_:03d}"
    case.title = "Suspicious Activity"
    case.status = MagicMock()
    case.status.value = status
    case.severity = severity
    case.created_by = MagicMock()
    case.created_by.username = "analyst"
    case.assigned_to = None
    case.closure_reason = None
    case.created_at = datetime(2025, 1, 1, tzinfo=timezone.utc)
    case.updated_at = datetime(2025, 1, 2, tzinfo=timezone.utc)
    return case


class TestToolListCases:
    def _call(self, args=None):
        return mcp_mod._tool_list_cases(args or {})

    def test_returns_cases(self):
        mock_session = MagicMock()
        query_chain = mock_session.query.return_value.options.return_value
        query_chain.order_by.return_value.limit.return_value.all.return_value = [_mock_case()]
        with patch.object(mcp_mod, "get_session_factory") as mock_factory:
            mock_factory.return_value.return_value = mock_session
            result = self._call()
        import json
        data = json.loads(result["content"][0]["text"])
        assert data["total"] == 1
        assert data["cases"][0]["case_number"] == "INC-001"

    def test_invalid_status_returns_error(self):
        result = self._call({"status": "unknown_status"})
        assert result["isError"] is True

    def test_severity_filter_applied(self):
        mock_session = MagicMock()
        query_chain = mock_session.query.return_value.options.return_value
        # filter by status then filter by severity, then order_by then limit then all
        query_chain.filter.return_value.order_by.return_value.limit.return_value.all.return_value = []
        with patch.object(mcp_mod, "get_session_factory") as mock_factory:
            mock_factory.return_value.return_value = mock_session
            self._call({"severity": "critical"})
        # filter() should have been called once (for severity, since no status)
        query_chain.filter.assert_called_once()


# ---------------------------------------------------------------------------
# Tool: get_case
# ---------------------------------------------------------------------------


class TestToolGetCase:
    def _call(self, args):
        return mcp_mod._tool_get_case(args)

    def test_returns_detail_with_notes(self):
        case = _mock_case()
        case.description = "Malware spread"
        case.closure_notes = None
        case.affected_hosts = [{"hostname": "ws01"}]
        case.affected_users = []
        case.triggered_rules = []
        case.evidence_summary = "Hash match on endpoint"
        case.triage_entries = [MagicMock()]
        note = MagicMock()
        note.id = 5
        note.content = "Analyst reviewed"
        note.created_at = datetime(2025, 1, 3, tzinfo=timezone.utc)
        case.notes = [note]

        mock_session = MagicMock()
        mock_session.query.return_value.options.return_value.filter_by.return_value.first.return_value = case
        with patch.object(mcp_mod, "get_session_factory") as mock_factory:
            mock_factory.return_value.return_value = mock_session
            result = self._call({"case_id": 1})
        import json
        data = json.loads(result["content"][0]["text"])
        assert data["alert_count"] == 1
        assert data["notes"][0]["content"] == "Analyst reviewed"
        assert data["affected_hosts"] == [{"hostname": "ws01"}]

    def test_not_found(self):
        mock_session = MagicMock()
        mock_session.query.return_value.options.return_value.filter_by.return_value.first.return_value = None
        with patch.object(mcp_mod, "get_session_factory") as mock_factory:
            mock_factory.return_value.return_value = mock_session
            result = self._call({"case_id": 404})
        assert result["isError"] is True


# ---------------------------------------------------------------------------
# Tool: search_observables
# ---------------------------------------------------------------------------


def _mock_obs(id_=1, obs_type="ipv4", value="1.2.3.4", threat="high"):
    obs = MagicMock()
    obs.id = id_
    obs.type = MagicMock()
    obs.type.value = obs_type
    obs.value = value
    obs.threat_level = MagicMock()
    obs.threat_level.value = threat
    obs.sighting_count = 3
    obs.is_ioc = True
    obs.is_watched = False
    obs.is_ignored = False
    obs.first_seen = datetime(2025, 1, 1, tzinfo=timezone.utc)
    obs.last_seen = datetime(2025, 1, 5, tzinfo=timezone.utc)
    return obs


class TestToolSearchObservables:
    def _call(self, args=None):
        return mcp_mod._tool_search_observables(args or {})

    def test_delegates_to_observable_service(self):
        mock_obs = _mock_obs()
        mock_session = MagicMock()
        mock_svc = MagicMock()
        mock_svc.search.return_value = ([mock_obs], 1)

        with patch.object(mcp_mod, "get_session_factory") as mock_factory, \
             patch.object(mcp_mod, "ObservableService", return_value=mock_svc):
            mock_factory.return_value.return_value = mock_session
            result = self._call({"query": "1.2.3", "type": "ipv4", "limit": 20})

        mock_svc.search.assert_called_once_with(
            query="1.2.3",
            types=["ipv4"],
            threat_level=None,
            limit=20,
        )
        import json
        data = json.loads(result["content"][0]["text"])
        assert data["total"] == 1
        assert data["observables"][0]["value"] == "1.2.3.4"

    def test_no_type_passes_none(self):
        mock_session = MagicMock()
        mock_svc = MagicMock()
        mock_svc.search.return_value = ([], 0)

        with patch.object(mcp_mod, "get_session_factory") as mock_factory, \
             patch.object(mcp_mod, "ObservableService", return_value=mock_svc):
            mock_factory.return_value.return_value = mock_session
            self._call({})

        _, kwargs = mock_svc.search.call_args
        assert kwargs["types"] is None


# ---------------------------------------------------------------------------
# Tool: get_observable
# ---------------------------------------------------------------------------


class TestToolGetObservable:
    def _call(self, args):
        return mcp_mod._tool_get_observable(args)

    def test_returns_enrichments(self):
        obs = _mock_obs()
        obs.normalized_value = "1.2.3.4"
        obs.watch_reason = None
        obs.tags = ["malware"]
        obs.notes = None
        obs.tlp = "amber"
        obs.pap = "green"
        enrich = MagicMock()
        enrich.source = "opencti"
        enrich.is_malicious = True
        enrich.score = 90
        enrich.labels = ["apt"]
        enrich.enriched_at = datetime(2025, 1, 4, tzinfo=timezone.utc)
        obs.enrichments = [enrich]

        mock_session = MagicMock()
        mock_session.query.return_value.options.return_value.filter_by.return_value.first.return_value = obs
        with patch.object(mcp_mod, "get_session_factory") as mock_factory:
            mock_factory.return_value.return_value = mock_session
            result = self._call({"observable_id": 1})

        import json
        data = json.loads(result["content"][0]["text"])
        assert data["tlp"] == "amber"
        assert data["enrichments"][0]["source"] == "opencti"
        assert data["enrichments"][0]["is_malicious"] is True

    def test_not_found(self):
        mock_session = MagicMock()
        mock_session.query.return_value.options.return_value.filter_by.return_value.first.return_value = None
        with patch.object(mcp_mod, "get_session_factory") as mock_factory:
            mock_factory.return_value.return_value = mock_session
            result = self._call({"observable_id": 99})
        assert result["isError"] is True


# ---------------------------------------------------------------------------
# Tool: list_playbooks
# ---------------------------------------------------------------------------


class TestToolListPlaybooks:
    def _call(self, args=None):
        return mcp_mod._tool_list_playbooks(args or {})

    def test_returns_playbooks(self):
        pb = MagicMock()
        pb.to_dict.return_value = {"id": 1, "name": "Phishing Response", "is_active": True}
        mock_session = MagicMock()
        mock_repo = MagicMock()
        mock_repo.list_playbooks.return_value = [pb]

        with patch.object(mcp_mod, "get_session_factory") as mock_factory, \
             patch.object(mcp_mod, "PlaybookRepository", return_value=mock_repo):
            mock_factory.return_value.return_value = mock_session
            result = self._call({"active_only": True})

        mock_repo.list_playbooks.assert_called_once_with(active_only=True)
        import json
        data = json.loads(result["content"][0]["text"])
        assert data["total"] == 1
        assert data["playbooks"][0]["name"] == "Phishing Response"

    def test_active_only_defaults_true(self):
        mock_session = MagicMock()
        mock_repo = MagicMock()
        mock_repo.list_playbooks.return_value = []

        with patch.object(mcp_mod, "get_session_factory") as mock_factory, \
             patch.object(mcp_mod, "PlaybookRepository", return_value=mock_repo):
            mock_factory.return_value.return_value = mock_session
            self._call({})

        mock_repo.list_playbooks.assert_called_once_with(active_only=True)


# ---------------------------------------------------------------------------
# Tool: add_case_note
# ---------------------------------------------------------------------------


class TestToolAddCaseNote:
    def _call(self, args, user=None):
        return mcp_mod._tool_add_case_note(args, user or _user())

    def test_creates_note(self):
        case = _mock_case()
        mock_session = MagicMock()
        mock_session.query.return_value.filter_by.return_value.first.return_value = case

        # Simulate session.refresh populating note fields
        created_note = MagicMock()
        created_note.id = 7
        created_note.case_id = 1
        created_note.content = "MCP note"
        created_note.created_at = datetime(2025, 1, 6, tzinfo=timezone.utc)

        def _refresh_side_effect(obj):
            obj.id = 7
            obj.case_id = 1
            obj.content = "MCP note"
            obj.created_at = datetime(2025, 1, 6, tzinfo=timezone.utc)

        mock_session.refresh.side_effect = _refresh_side_effect

        with patch.object(mcp_mod, "get_session_factory") as mock_factory, \
             patch("ion.web.mcp_api.Note") as MockNote:
            mock_factory.return_value.return_value = mock_session
            note_instance = MagicMock()
            note_instance.id = 7
            note_instance.case_id = 1
            note_instance.content = "MCP note"
            note_instance.created_at = datetime(2025, 1, 6, tzinfo=timezone.utc)
            MockNote.return_value = note_instance
            result = self._call({"case_id": 1, "content": "MCP note"})

        mock_session.add.assert_called_once()
        mock_session.commit.assert_called_once()
        import json
        data = json.loads(result["content"][0]["text"])
        assert data["content"] == "MCP note"

    def test_case_not_found_returns_tool_error(self):
        mock_session = MagicMock()
        mock_session.query.return_value.filter_by.return_value.first.return_value = None
        with patch.object(mcp_mod, "get_session_factory") as mock_factory:
            mock_factory.return_value.return_value = mock_session
            result = self._call({"case_id": 999, "content": "note"})
        assert result["isError"] is True
        assert "not found" in result["content"][0]["text"]

    def test_empty_content_returns_error(self):
        result = self._call({"case_id": 1, "content": "  "})
        assert result["isError"] is True
        assert "empty" in result["content"][0]["text"]

    def test_non_int_case_id_returns_error(self):
        result = self._call({"case_id": "bad", "content": "note"})
        assert result["isError"] is True

    def test_session_rolled_back_on_db_error(self):
        case = _mock_case()
        mock_session = MagicMock()
        mock_session.query.return_value.filter_by.return_value.first.return_value = case
        mock_session.commit.side_effect = Exception("db error")

        with patch.object(mcp_mod, "get_session_factory") as mock_factory, \
             patch("ion.web.mcp_api.Note"):
            mock_factory.return_value.return_value = mock_session
            with pytest.raises(Exception, match="db error"):
                self._call({"case_id": 1, "content": "note"})

        mock_session.rollback.assert_called_once()
        mock_session.close.assert_called_once()


# ---------------------------------------------------------------------------
# v0.49.3 code-review fixes
# ---------------------------------------------------------------------------


class TestLimitLowerBound:
    """limit=-1 must not reach Query.limit() — SQLite treats LIMIT -1 as
    'no limit' and dumps the whole table."""

    def test_list_alerts_negative_limit_clamped_to_1(self):
        mock_session = MagicMock()
        mock_session.query.return_value.order_by.return_value.limit.return_value.all.return_value = []
        with patch.object(mcp_mod, "get_session_factory") as mock_factory:
            mock_factory.return_value.return_value = mock_session
            mcp_mod._tool_list_alerts({"limit": -1})
        mock_session.query.return_value.order_by.return_value.limit.assert_called_with(1)

    def test_list_cases_zero_limit_clamped_to_1(self):
        mock_session = MagicMock()
        chain = mock_session.query.return_value.options.return_value
        chain.order_by.return_value.limit.return_value.all.return_value = []
        with patch.object(mcp_mod, "get_session_factory") as mock_factory:
            mock_factory.return_value.return_value = mock_session
            mcp_mod._tool_list_cases({"limit": 0})
        chain.order_by.return_value.limit.assert_called_with(1)

    def test_search_observables_negative_limit_clamped_to_1(self):
        mock_session = MagicMock()
        with patch.object(mcp_mod, "get_session_factory") as mock_factory, \
             patch.object(mcp_mod, "ObservableService") as MockSvc:
            mock_factory.return_value.return_value = mock_session
            MockSvc.return_value.search.return_value = ([], 0)
            mcp_mod._tool_search_observables({"limit": -5})
        assert MockSvc.return_value.search.call_args.kwargs["limit"] == 1


class TestBatchNonObjectEntries:
    """A JSON-RPC batch entry that is not an object must yield a per-item
    -32600 error, not an AttributeError -> 500."""

    def test_batch_with_non_object_entries_returns_per_item_errors(self):
        with patch.object(mcp_mod, "_authenticate", return_value=_user()):
            client = TestClient(_app())
            resp = _post(client, [1, "x", _rpc("ping", req_id=7)])
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) == 3
        errors = [d for d in data if "error" in d]
        assert len(errors) == 2
        assert all(e["error"]["code"] == -32600 for e in errors)
        assert all(e["id"] is None for e in errors)
        ok = [d for d in data if "result" in d]
        assert len(ok) == 1 and ok[0]["id"] == 7

    def test_batch_of_only_invalid_entries_still_200(self):
        with patch.object(mcp_mod, "_authenticate", return_value=_user()):
            client = TestClient(_app())
            resp = _post(client, [None, 42])
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 2
        assert all(d["error"]["code"] == -32600 for d in data)


class TestAddCaseNoteSyncsSideEffects:
    """MCP-added notes must propagate to ES + Kibana exactly like the REST
    route (case_lifecycle_api.add_case_note) — otherwise external views
    silently diverge from the ION DB."""

    def _call_with_mocks(self):
        case = _mock_case()
        case.kibana_case_id = "kb-123"
        mock_session = MagicMock()
        mock_session.query.return_value.filter_by.return_value.first.return_value = case

        with patch.object(mcp_mod, "get_session_factory") as mock_factory, \
             patch("ion.web.mcp_api.Note"), \
             patch.object(mcp_mod, "_schedule_case_es_sync") as mock_es, \
             patch.object(mcp_mod, "sync_note_to_kibana") as mock_kb:
            mock_factory.return_value.return_value = mock_session
            result = mcp_mod._tool_add_case_note(
                {"case_id": 1, "content": "MCP note"}, _user()
            )
        return result, mock_es, mock_kb

    def test_note_triggers_es_case_sync(self):
        _, mock_es, _ = self._call_with_mocks()
        mock_es.assert_called_once_with(1)

    def test_note_syncs_to_kibana_as_comment(self):
        _, _, mock_kb = self._call_with_mocks()
        mock_kb.assert_called_once_with("kb-123", "analyst", "MCP note")


class TestAddCaseNoteKibanaOffLoop:
    """AUDIT-4: sync_note_to_kibana is a blocking httpx POST (5s timeout);
    _tool_add_case_note executes ON the event loop (sync dispatch inside the
    async endpoint), so the Kibana call must be handed off — never run
    inline while a loop is running on this thread."""

    def test_kibana_sync_not_called_on_event_loop(self):
        import asyncio
        import threading

        case = _mock_case()
        case.kibana_case_id = "kb-9"
        mock_session = MagicMock()
        mock_session.query.return_value.filter_by.return_value.first.return_value = case

        seen = {}
        done = threading.Event()

        def _probe(kibana_case_id, username, content):
            try:
                asyncio.get_running_loop()
                seen["on_loop"] = True
            except RuntimeError:
                seen["on_loop"] = False
            done.set()

        async def _drive():
            with patch.object(mcp_mod, "get_session_factory") as mock_factory, \
                 patch("ion.web.mcp_api.Note"), \
                 patch.object(mcp_mod, "_schedule_case_es_sync"), \
                 patch.object(mcp_mod, "sync_note_to_kibana", side_effect=_probe):
                mock_factory.return_value.return_value = mock_session
                result = mcp_mod._tool_add_case_note(
                    {"case_id": 1, "content": "note"}, _user()
                )
                # give the executor a moment to run the handed-off call
                for _ in range(50):
                    if done.is_set():
                        break
                    await asyncio.sleep(0.05)
            return result

        asyncio.run(_drive())
        assert done.is_set(), "Kibana sync was never invoked"
        assert seen.get("on_loop") is False, (
            "blocking Kibana HTTP ran ON the event loop"
        )
