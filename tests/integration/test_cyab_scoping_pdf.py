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


# ---------------------------------------------------------------------------
# Abuse guards: the scoping endpoints are deliberately ANONYMOUS (public
# stakeholder tools), so they can't hide behind auth. The PDF render drives an
# uncapped WeasyPrint job from arbitrary form data — an availability (DoS)
# vector. These guards bound the work per-request (input caps) and per-source
# (rate limit) without breaking the anonymous UX.
# ---------------------------------------------------------------------------


def test_scoping_pdf_rejects_oversized_body(client):
    """A body larger than the cap is refused (413) before any render work."""
    huge = "x" * (300 * 1024)  # ~300 KB, over the 256 KB cap
    r = client.post("/api/cyab/scoping/pdf", data={"org_sector": huge})
    assert r.status_code == 413


def test_scoping_pdf_rejects_too_many_fields(client):
    """Far more answer fields than the questionnaire has is refused (413)."""
    data = {f"q{i}": "1" for i in range(400)}  # over the 300-field cap
    r = client.post("/api/cyab/scoping/pdf", data=data)
    assert r.status_code == 413


def test_scoping_pdf_normal_request_still_ok(client):
    """A legitimate small submission is unaffected by the guards."""
    r = client.post(
        "/api/cyab/scoping/pdf",
        data={"org_sector": "finance", "concern_top": "ransomware"},
    )
    assert r.status_code == 200


def test_scoping_pdf_rate_limited_after_burst(client, monkeypatch):
    """A flood from one source trips the rate limit (429). Uses a private
    bucket so it neither pollutes nor is polluted by other tests."""
    monkeypatch.setattr(
        "ion.web.api._trusted_client_ip",
        lambda request: "ratelimit-test-bucket",
    )
    saw_429 = False
    for _ in range(15):  # limit is 10/minute
        r = client.post("/api/cyab/scoping/pdf", data={"org_sector": "finance"})
        if r.status_code == 429:
            saw_429 = True
            break
    assert saw_429, "burst of scoping/pdf requests was never rate-limited"
