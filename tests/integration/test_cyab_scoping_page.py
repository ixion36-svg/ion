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
