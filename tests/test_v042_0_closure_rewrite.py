"""v0.42.0 — AI closure-note rewrite endpoint (POST /api/ai/closure/rewrite).

The endpoint polishes an analyst's draft closing comment via Ollama. These
tests stub both the auth dependency and the Ollama service so they run without
a live model or login flow.
"""

import pytest
from fastapi.testclient import TestClient

from ion.auth.dependencies import get_current_user
from ion.models.user import User
from ion.web import ai_api
from ion.web.server import app


class _StubOllama:
    """Minimal stand-in for OllamaService used by the rewrite endpoint."""

    def __init__(self, available=True):
        self._available = available
        self.last_prompt = None

    async def is_available(self):
        return self._available

    async def chat(self, messages, context_type=None, temperature=None,
                   max_tokens=None, user_id=None):
        self.last_prompt = messages[0]["content"]
        self.last_max_tokens = max_tokens
        return {"content": "  Polished closing rationale.  ", "model": "stub-model"}


@pytest.fixture
def client(monkeypatch):
    fake_user = User(
        id=7,
        username="analyst",
        email="analyst@localhost",
        password_hash="x",
        display_name="Analyst",
        is_active=True,
    )
    app.dependency_overrides[get_current_user] = lambda: fake_user
    yield TestClient(app)
    app.dependency_overrides.clear()


def test_rewrite_polishes_draft(client, monkeypatch):
    stub = _StubOllama()
    monkeypatch.setattr(ai_api, "get_ollama_service", lambda: stub)

    resp = client.post(
        "/api/ai/closure/rewrite",
        json={
            "draft": "host pwned, fp, closing",
            "reason": "false_positive",
            "case_title": "Suspicious PowerShell on WS-01",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    # Response is stripped of surrounding whitespace.
    assert data["content"] == "Polished closing rationale."
    assert data["model"] == "stub-model"
    # Prompt carries the draft + a humanised reason label + the case title.
    assert "host pwned, fp, closing" in stub.last_prompt
    assert "false positive" in stub.last_prompt
    assert "Suspicious PowerShell on WS-01" in stub.last_prompt
    # v0.44.0: output is length-capped (prompt instruction + a token ceiling).
    assert "paragraph" in stub.last_prompt.lower()
    assert stub.last_max_tokens == 400
    # No case_id supplied → no precedents were gathered.
    assert data["precedents_used"] == 0


def test_rewrite_with_case_id_is_graceful_without_pgvector(client, monkeypatch):
    """Passing case_id must not break when no embedding store is available —
    the precedent lookup is best-effort and degrades to zero precedents."""
    stub = _StubOllama()
    monkeypatch.setattr(ai_api, "get_ollama_service", lambda: stub)

    resp = client.post(
        "/api/ai/closure/rewrite",
        json={"draft": "closing as benign", "reason": "benign_true_positive", "case_id": 123},
    )
    assert resp.status_code == 200
    assert resp.json()["precedents_used"] == 0


def test_rewrite_empty_draft_requests_skeleton(client, monkeypatch):
    stub = _StubOllama()
    monkeypatch.setattr(ai_api, "get_ollama_service", lambda: stub)

    resp = client.post(
        "/api/ai/closure/rewrite",
        json={"draft": "", "reason": "duplicate"},
    )
    assert resp.status_code == 200
    # Empty-draft branch asks the model for a skeleton rather than a rewrite.
    assert "has not written a closing comment yet" in stub.last_prompt
    assert "duplicate" in stub.last_prompt


def test_rewrite_unavailable_ai_returns_503(client, monkeypatch):
    monkeypatch.setattr(ai_api, "get_ollama_service", lambda: _StubOllama(available=False))

    resp = client.post(
        "/api/ai/closure/rewrite",
        json={"draft": "x", "reason": "true_positive"},
    )
    assert resp.status_code == 503
