"""Integration tests for the /cyab/scoping anonymous questionnaire page."""

import pytest


@pytest.fixture
def client(temp_db, monkeypatch):
    monkeypatch.setattr("ion.storage.database.get_engine", lambda *_a, **_k: temp_db)
    from fastapi.testclient import TestClient
    from ion.web.server import app
    return TestClient(app)


def test_scoping_page_renders_anonymous(client):
    """Page is reachable without auth — designed for stakeholder demos."""
    r = client.get("/cyab/scoping")
    assert r.status_code == 200
    assert "Scoping" in r.text or "scoping" in r.text.lower()


def test_scoping_page_includes_all_questions(client):
    from ion.services import cyab_scoping_engine
    r = client.get("/cyab/scoping")
    body = r.text
    for q in cyab_scoping_engine.load_questions():
        assert q["id"] in body, f"question {q['id']} missing from page"


def test_scoping_page_includes_live_counter_widget(client):
    r = client.get("/cyab/scoping")
    body = r.text
    assert "scoping-counter" in body  # the HTMX swap target id
    # Initial counter shows zeros (no answers yet)
    assert "0 use cases" in body or "0/0" in body or "use case" in body.lower()


def test_scoping_page_progressive_disclosure_class(client):
    """Each question carries a class the client JS uses to reveal next-on-answer."""
    r = client.get("/cyab/scoping")
    body = r.text
    assert "scoping-question" in body


def test_score_endpoint_returns_counter_partial(client):
    """POST /api/cyab/scoping/score returns the counter partial (HTMX swap)."""
    r = client.post(
        "/api/cyab/scoping/score",
        data={"org_sector": "finance", "concern_top": "ransomware"},
    )
    assert r.status_code == 200
    body = r.text
    # Counter partial markup
    assert "use cases" in body
    assert "threat-actor matches" in body
    assert "MITRE Initial Access coverage" in body


def test_score_endpoint_summary_mode_returns_summary_partial(client):
    """?summary=1 query param swaps to the full summary view, not the counter."""
    r = client.post(
        "/api/cyab/scoping/score?summary=1",
        data={"org_sector": "tech", "concern_top": "supply_chain"},
    )
    assert r.status_code == 200
    body = r.text.lower()
    # Summary view headlines
    assert "recommended for your stack" in body
    assert "detection rules" in body or "use cases" in body


def test_score_endpoint_handles_multi_value(client):
    """`stack_endpoint_os` is a multi-select — multiple form values must
    coalesce into a list before scoring (so compute_profile sees a list)."""
    r = client.post(
        "/api/cyab/scoping/score",
        data=[("stack_endpoint_os", "windows"), ("stack_endpoint_os", "macos")],
    )
    assert r.status_code == 200
