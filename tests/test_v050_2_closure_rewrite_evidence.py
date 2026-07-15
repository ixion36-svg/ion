"""v0.50.2 — evidence-grounded, NIST SP 800-61-structured closure rewrite.

The AI closure rewrite (POST /api/ai/closure/rewrite, v0.42.0) previously
sent the model NO case evidence — only the draft, reason, title, and a
similar-case precedent block — so with a thin draft the model's only
concrete material was precedent and it parroted "a similar case NNNNN was
closed as …". This release:

1. Feeds the model THIS case's own evidence (`_gather_closure_evidence`):
   case description / hosts / users / rules / observables / evidence
   summary, triage rule names + MITRE union + analyst triage notes, the
   latest DECISIVE Bob investigation summary, and the TI-enrichment digest.
2. Structures the note per NIST SP 800-61 incident documentation —
   Summary / Evidence / Rationale / Follow-up — quoting real values.
3. Makes the analyst's draft + selected closure reason authoritative for
   the disposition.
4. Demotes precedent to at most one trailing sentence in Rationale.
"""

import pytest
from fastapi.testclient import TestClient

# Import models at module top so they register on the shared Base.metadata
# before the `session` fixture's create_all runs.
from ion.auth.dependencies import get_current_user
from ion.models.alert_triage import AlertCase, AlertTriage
from ion.models.investigation import Investigation
from ion.models.user import User
from ion.web import ai_api
from ion.web.server import app


class _StubOllama:
    def __init__(self, available=True):
        self._available = available
        self.last_prompt = None

    async def is_available(self):
        return self._available

    async def chat(self, messages, context_type=None, temperature=None,
                   max_tokens=None, user_id=None):
        self.last_prompt = messages[0]["content"]
        self.last_max_tokens = max_tokens
        return {"content": "Summary: stub note.", "model": "stub-model"}


@pytest.fixture
def client():
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


# ---------------------------------------------------------------------------
# _gather_closure_evidence
# ---------------------------------------------------------------------------

def _seed_case(session) -> AlertCase:
    case = AlertCase(
        case_number="CASE-EV-1",
        title="Suspicious PowerShell on WS-01",
        description="Encoded PowerShell observed on WS-01.",
        created_by_id=1,
        affected_hosts=["WS-01"],
        affected_users=["jdoe"],
        triggered_rules=["Suspicious PowerShell Execution"],
        observables=[{"type": "ip", "value": "10.9.8.7"},
                     {"type": "hash", "value": "abc123"}],
        evidence_summary="Process tree showed powershell.exe -enc launched by outlook.exe.",
        source_alert_ids=["ev-alert-1"],
    )
    session.add(case)
    session.commit()
    session.add(AlertTriage(
        es_alert_id="ev-alert-1",
        case_id=case.id,
        rule_name="Suspicious PowerShell Execution",
        mitre_techniques=[{"technique_id": "T1059.001"}, "T1027"],
        analyst_notes="Confirmed with user — macro-enabled doc from phishing mail.",
    ))
    session.add(Investigation(
        alert_id_ref="ev-alert-1",
        alert_signature="sig",
        status="completed",
        verdict="true_positive",
        summary_text="Encoded command decodes to a download cradle.",
    ))
    session.commit()
    return case


def test_evidence_block_carries_case_facts(session, monkeypatch):
    case = _seed_case(session)
    monkeypatch.setattr(ai_api, "get_session", lambda: iter([session]))
    block = ai_api._gather_closure_evidence(case.id)
    assert "Encoded PowerShell observed on WS-01." in block
    assert "Affected hosts: WS-01" in block
    assert "Affected users: jdoe" in block
    assert "ip=10.9.8.7" in block and "hash=abc123" in block
    assert "powershell.exe -enc" in block
    assert "MITRE techniques: T1027, T1059.001" in block  # union, sorted, both shapes
    assert "Analyst triage note: Confirmed with user" in block
    assert "AI investigation (true_positive): Encoded command decodes" in block


def test_evidence_skips_inconclusive_investigation(session, monkeypatch):
    case = _seed_case(session)
    # A NEWER inconclusive run must not displace the decisive one.
    session.add(Investigation(
        alert_id_ref="ev-alert-1",
        alert_signature="sig",
        status="completed",
        verdict="inconclusive",
        summary_text="Could not determine.",
    ))
    session.commit()
    monkeypatch.setattr(ai_api, "get_session", lambda: iter([session]))
    block = ai_api._gather_closure_evidence(case.id)
    assert "Could not determine." not in block
    assert "Encoded command decodes" in block


def test_evidence_missing_case_returns_empty(session, monkeypatch):
    monkeypatch.setattr(ai_api, "get_session", lambda: iter([session]))
    assert ai_api._gather_closure_evidence(999_999) == ""


def test_evidence_is_bounded(session, monkeypatch):
    case = _seed_case(session)
    case.evidence_summary = "x" * 20_000
    case.description = "y" * 20_000
    session.commit()
    monkeypatch.setattr(ai_api, "get_session", lambda: iter([session]))
    block = ai_api._gather_closure_evidence(case.id)
    assert len(block) <= 3000


# ---------------------------------------------------------------------------
# Endpoint prompt structure
# ---------------------------------------------------------------------------

def test_rewrite_prompt_is_evidence_grounded_and_structured(client, monkeypatch):
    stub = _StubOllama()
    monkeypatch.setattr(ai_api, "get_ollama_service", lambda: stub)
    monkeypatch.setattr(
        ai_api, "_gather_closure_evidence",
        lambda cid: "Affected hosts: WS-01\nExtracted observables: ip=10.9.8.7",
    )
    monkeypatch.setattr(ai_api, "_gather_closure_precedents", lambda cid: [])

    resp = client.post(
        "/api/ai/closure/rewrite",
        json={
            "draft": "benign admin activity, closing",
            "reason": "benign_true_positive",
            "case_id": 42,
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["evidence_used"] is True
    p = stub.last_prompt
    # Evidence is in the prompt and framed as the only citable facts.
    assert "ip=10.9.8.7" in p
    assert "ONLY facts you may cite" in p
    # NIST SP 800-61 structure with the four labelled sections.
    assert "NIST SP 800-61" in p
    for label in ("Summary:", "Evidence:", "Rationale:", "Follow-up:"):
        assert label in p
    # The outcome selection is bound into the Rationale instruction.
    assert 'closing as "benign true positive"' in p
    # The analyst's draft is authoritative.
    assert "benign admin activity, closing" in p
    assert "AUTHORITATIVE" in p


def test_rewrite_without_case_id_has_no_evidence_block(client, monkeypatch):
    stub = _StubOllama()
    monkeypatch.setattr(ai_api, "get_ollama_service", lambda: stub)

    resp = client.post(
        "/api/ai/closure/rewrite",
        json={"draft": "closing", "reason": "false_positive"},
    )
    assert resp.status_code == 200
    assert resp.json()["evidence_used"] is False
    assert "ONLY facts you may cite" not in stub.last_prompt
    # Structure instructions still apply even without gathered evidence.
    assert "NIST SP 800-61" in stub.last_prompt


def test_precedent_is_demoted_to_trailing_sentence(client, monkeypatch):
    stub = _StubOllama()
    monkeypatch.setattr(ai_api, "get_ollama_service", lambda: stub)
    monkeypatch.setattr(ai_api, "_gather_closure_evidence", lambda cid: "")
    monkeypatch.setattr(
        ai_api, "_gather_closure_precedents",
        lambda cid: [{
            "case_number": "CASE-00025",
            "closure_reason": "benign_true_positive",
            "closure_notes": "Benign admin script.",
        }],
    )

    resp = client.post(
        "/api/ai/closure/rewrite",
        json={"draft": "closing", "reason": "benign_true_positive", "case_id": 42},
    )
    assert resp.status_code == 200
    assert resp.json()["precedents_used"] == 1
    p = stub.last_prompt
    assert "CASE-00025" in p
    # Demotion instructions: background only, one trailing Rationale sentence.
    assert "background only" in p
    assert "END of the Rationale" in p
    assert "never let it substitute" in p


def test_empty_draft_skeleton_keeps_structure(client, monkeypatch):
    stub = _StubOllama()
    monkeypatch.setattr(ai_api, "get_ollama_service", lambda: stub)

    resp = client.post(
        "/api/ai/closure/rewrite",
        json={"draft": "", "reason": "duplicate"},
    )
    assert resp.status_code == 200
    p = stub.last_prompt
    assert "has not written a closing comment yet" in p
    assert "[observable]" in p
    for label in ("Summary:", "Evidence:", "Rationale:", "Follow-up:"):
        assert label in p
