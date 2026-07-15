"""v0.51.0 — Playbook RAG layer (RAG rework Phase 3).

Bob's system prompt gains a fourth budget-gated layer: the SOC's documented
response playbooks. Two arms, deterministic first:

1. Structured trigger-condition match (rule patterns / severity / MITRE) —
   precise, auditable, needs no Ollama.
2. Embedding-similarity fallback over the new ``playbook_embeddings`` table
   (populated by ``playbook_embedding_service``) — only when nothing
   matches structurally.

Layer order is now KB(1) → exemplars(2) → playbooks(3) → skills(4); gate
``ION_PLAYBOOK_RAG_ENABLED`` default ON.
"""


from ion.models.playbook import Playbook, PlaybookStep
from ion.models.playbook_embedding import PlaybookEmbedding
from ion.services import playbook_embedding_service as pbe
from ion.services.alert_prompt_service import (
    AlertPromptService,
    _format_playbook_context_for_prompt,
    _playbook_rag_enabled,
)


class _StubEmbed:
    def __init__(self):
        self.is_enabled = True
        self.model_tag = "stub+tp1"
        self.model = "stub"

    def embed(self, text, mode="document"):
        return [0.1] * 768


def _seed_playbook(session, *, name="Phishing response", active=True,
                   rule_patterns=None) -> Playbook:
    pb = Playbook(
        name=name,
        description="Standard response for credential phishing alerts.",
        is_active=active,
        trigger_conditions={
            "rule_patterns": rule_patterns or ["Suspicious PowerShell"],
            "mitre_techniques": ["T1566"],
        },
        priority=10,
        created_by_id=1,
    )
    session.add(pb)
    session.commit()
    session.add_all([
        PlaybookStep(
            playbook_id=pb.id, step_order=1, step_type="manual_checklist",
            title="Isolate the affected host", is_required=True,
        ),
        PlaybookStep(
            playbook_id=pb.id, step_order=2, step_type="manual_checklist",
            title="Reset the user's credentials",
        ),
    ])
    session.commit()
    return pb


# ---------------------------------------------------------------------------
# Source text + background loop
# ---------------------------------------------------------------------------

def test_playbook_source_text_carries_name_rules_mitre_steps(session):
    pb = _seed_playbook(session)
    text = pbe._playbook_source_text(pb)
    assert "Playbook: Phishing response" in text
    assert "Description: Standard response" in text
    assert "Rules: Suspicious PowerShell" in text
    assert "MITRE: T1566" in text
    assert text.index("Isolate the affected host") < text.index(
        "Reset the user's credentials"
    )


def test_loop_embeds_active_and_skips_fresh(session, monkeypatch):
    stub = _StubEmbed()
    monkeypatch.setattr(pbe, "get_embedding_service", lambda: stub)
    pb = _seed_playbook(session)

    out = pbe.run_playbook_embedding_once(session)
    assert out["embedded"] == 1
    row = session.get(PlaybookEmbedding, pb.id)
    assert row is not None and row.model_name == "stub+tp1"

    out2 = pbe.run_playbook_embedding_once(session)
    assert out2["embedded"] == 0
    assert out2["skipped_fresh"] == 1


def test_loop_removes_row_when_playbook_deactivated(session, monkeypatch):
    stub = _StubEmbed()
    monkeypatch.setattr(pbe, "get_embedding_service", lambda: stub)
    pb = _seed_playbook(session, name="To be disabled")
    pbe.run_playbook_embedding_once(session)
    assert session.get(PlaybookEmbedding, pb.id) is not None

    pb.is_active = False
    session.commit()
    out = pbe.run_playbook_embedding_once(session)
    assert out["removed_inactive"] == 1
    assert session.get(PlaybookEmbedding, pb.id) is None


def test_loop_re_embeds_on_edit(session, monkeypatch):
    stub = _StubEmbed()
    monkeypatch.setattr(pbe, "get_embedding_service", lambda: stub)
    pb = _seed_playbook(session, name="Editable")
    pbe.run_playbook_embedding_once(session)
    old_hash = session.get(PlaybookEmbedding, pb.id).source_text_hash

    pb.description = "Rewritten procedure."
    session.commit()
    out = pbe.run_playbook_embedding_once(session)
    assert out["embedded"] == 1
    assert session.get(PlaybookEmbedding, pb.id).source_text_hash != old_hash


# ---------------------------------------------------------------------------
# Retrieval — deterministic arm + gate
# ---------------------------------------------------------------------------

def test_deterministic_match_returns_playbook_with_steps(session, monkeypatch):
    # Embedding disabled — the deterministic arm must work without Ollama.
    monkeypatch.setenv("ION_EMBEDDING_ENABLED", "false")
    _seed_playbook(session)
    svc = AlertPromptService(session)
    hits = svc._get_playbook_context_for_alert(
        {"rule_name": "Suspicious PowerShell Execution", "severity": "high"}
    )
    assert len(hits) == 1
    hit = hits[0]
    assert hit["name"] == "Phishing response"
    assert hit["matched_via"] == "trigger match"
    assert hit["steps"][0] == "Isolate the affected host (required)"
    assert hit["steps"][1] == "Reset the user's credentials"


def test_inactive_playbook_never_matches(session, monkeypatch):
    monkeypatch.setenv("ION_EMBEDDING_ENABLED", "false")
    _seed_playbook(session, name="Disabled PB", active=False)
    svc = AlertPromptService(session)
    hits = svc._get_playbook_context_for_alert(
        {"rule_name": "Suspicious PowerShell Execution"}
    )
    assert hits == []


def test_gate_defaults_on_and_disables(session, monkeypatch):
    assert _playbook_rag_enabled() is True
    monkeypatch.setenv("ION_PLAYBOOK_RAG_ENABLED", "false")
    assert _playbook_rag_enabled() is False
    _seed_playbook(session, name="Gated PB")
    svc = AlertPromptService(session)
    assert svc._get_playbook_context_for_alert(
        {"rule_name": "Suspicious PowerShell Execution"}
    ) == []


# ---------------------------------------------------------------------------
# Prompt formatting + render_system_prompt integration
# ---------------------------------------------------------------------------

def test_format_playbook_context_empty_and_full():
    assert _format_playbook_context_for_prompt([]) == ""
    block = _format_playbook_context_for_prompt([{
        "name": "Phishing response",
        "description": "Standard response.",
        "steps": ["Isolate the affected host (required)"],
        "matched_via": "trigger match",
    }])
    assert "## Relevant Response Playbooks" in block
    assert "### Phishing response (via trigger match)" in block
    assert "- Isolate the affected host (required)" in block


def test_render_system_prompt_carries_playbook_layer(session, monkeypatch):
    # KB/exemplar embedding layers no-op without Ollama; the playbook
    # layer's deterministic arm still fires.
    monkeypatch.setenv("ION_EMBEDDING_ENABLED", "false")
    _seed_playbook(session)
    svc = AlertPromptService(session)
    prompt = svc.render_system_prompt(
        None, {"rule_name": "Suspicious PowerShell Execution"}
    )
    assert "## Relevant Response Playbooks" in prompt
    assert "Phishing response" in prompt
    assert "Isolate the affected host" in prompt
    # Output contract still terminates the prompt (never budget-gated).
    assert prompt.rstrip().endswith(prompt.rstrip()[-20:])


def test_render_system_prompt_gate_off_removes_layer(session, monkeypatch):
    monkeypatch.setenv("ION_EMBEDDING_ENABLED", "false")
    monkeypatch.setenv("ION_PLAYBOOK_RAG_ENABLED", "false")
    _seed_playbook(session, name="Hidden PB")
    svc = AlertPromptService(session)
    prompt = svc.render_system_prompt(
        None, {"rule_name": "Suspicious PowerShell Execution"}
    )
    assert "Relevant Response Playbooks" not in prompt
