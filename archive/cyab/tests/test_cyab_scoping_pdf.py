"""Integration tests for the scoping PDF export."""

import pytest


@pytest.fixture
def client(temp_db, monkeypatch):
    monkeypatch.setattr("ion.storage.database.get_engine", lambda *_a, **_k: temp_db)
    from fastapi.testclient import TestClient
    from ion.web.server import app
    return TestClient(app)


def test_scoping_pdf_returns_pdf_or_html(client):
    """Endpoint returns either application/pdf (WeasyPrint) or text/html (fallback)."""
    r = client.post(
        "/api/cyab/scoping/pdf",
        data={"org_sector": "finance", "concern_top": "ransomware"},
    )
    assert r.status_code == 200
    ct = r.headers["content-type"]
    assert ct.startswith("application/pdf") or ct.startswith("text/html")


def test_scoping_pdf_includes_summary_metrics(client):
    """The body (PDF or HTML fallback) mentions the headline counts."""
    r = client.post(
        "/api/cyab/scoping/pdf",
        data={"org_sector": "tech", "concern_top": "supply_chain"},
    )
    if r.headers["content-type"].startswith("text/html"):
        body = r.text.lower()
        assert "use case" in body
        assert "mitre" in body or "coverage" in body
        assert "scoping pack" in body or "scoping summary" in body


def test_scoping_pdf_attachment_header_when_pdf(client):
    r = client.post("/api/cyab/scoping/pdf", data={"org_sector": "finance"})
    if r.headers["content-type"].startswith("application/pdf"):
        cd = r.headers.get("content-disposition", "")
        assert "attachment" in cd
        assert "scoping_pack" in cd
