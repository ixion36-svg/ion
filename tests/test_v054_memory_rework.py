"""v0.54.0 — RAG Phase 4: investigation-memory rework + prompt-stack alignment.

Three changes under test:

1. **Confidence-first memory** — ``past_investigations_for_signature`` now
   orders by ``confidence_int`` DESC (NULLS LAST) with recency tie-break,
   and the memory context block shows each prior verdict's confidence.
2. **Analyst disagreement** — new ``feedback_outcomes_for_signature`` reads
   the AIFeedback ledger for the rule (dedup MAX(id) per (alert_id,
   template_id) among resolved rows, ``pending`` fire-time rows excluded)
   and the memory block renders a human-review-outcomes section with
   explicit ANALYST DISAGREED lines.
3. **Prompt-stack alignment** — the five RAG layers moved into the shared
   ``AlertPromptService.build_rag_context_blocks`` and ``bob_analysis_api``
   now consumes it (plus the template guide and the memory block) instead
   of a bespoke bare prompt.
"""

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from ion.models.ai_feedback import AIFeedback
from ion.models.investigation import Investigation
from ion.storage import investigation_memory_repository as repo

SIG = "Suspicious PowerShell Encoded Command"


def _mk_inv(
    session,
    *,
    sig=SIG,
    verdict="true_positive",
    conf=None,
    status="completed",
    days_ago=0,
    summary="prior summary line",
):
    inv = Investigation(
        alert_id_ref=f"alert-{days_ago}-{conf}",
        alert_signature=sig,
        status=status,
        verdict=verdict,
        severity_assessment="high",
        summary_text=summary,
        confidence_int=conf,
        created_at=datetime.now(timezone.utc) - timedelta(days=days_ago),
    )
    session.add(inv)
    session.flush()
    return inv


def _mk_fb(
    session,
    inv,
    *,
    alert_id="a-1",
    template_id=1,
    bob="true_positive",
    human="false_positive",
    agreement=False,
    conf=None,
    delta_reason=None,
):
    fb = AIFeedback(
        investigation_id=inv.id if inv is not None else None,
        alert_id=alert_id,
        alert_prompt_template_id=template_id,
        bob_suggested_verdict=bob,
        bob_confidence_int=conf,
        human_verdict=human,
        agreement=agreement,
        delta_reason=delta_reason,
    )
    session.add(fb)
    session.flush()
    return fb


# ---------------------------------------------------------------------------
# 1. Confidence-first ordering
# ---------------------------------------------------------------------------

def test_past_investigations_confidence_desc_nulls_last(session):
    _mk_inv(session, conf=40, days_ago=0)
    _mk_inv(session, conf=95, days_ago=10)
    _mk_inv(session, conf=None, days_ago=1)
    _mk_inv(session, conf=70, days_ago=5)
    session.commit()

    out = repo.past_investigations_for_signature(SIG, session, limit=5)
    assert [i.confidence_int for i in out] == [95, 70, 40, None]


def test_past_investigations_recency_breaks_confidence_ties(session):
    older = _mk_inv(session, conf=80, days_ago=10)
    newer = _mk_inv(session, conf=80, days_ago=1)
    session.commit()

    out = repo.past_investigations_for_signature(SIG, session, limit=5)
    assert [i.id for i in out] == [newer.id, older.id]


def test_past_investigations_still_completed_only(session):
    _mk_inv(session, conf=99, status="pending")
    done = _mk_inv(session, conf=50)
    session.commit()

    out = repo.past_investigations_for_signature(SIG, session, limit=5)
    assert [i.id for i in out] == [done.id]


# ---------------------------------------------------------------------------
# 2. AIFeedback outcomes for a signature
# ---------------------------------------------------------------------------

def test_feedback_outcomes_dedup_and_pending_excluded(session):
    inv = _mk_inv(session)
    # Fire-time sentinel row — must never surface.
    _mk_fb(session, inv, alert_id="a-1", template_id=1,
           human="pending", agreement=None)
    # Two resolved rows for the same (alert, template) — MAX(id) wins.
    _mk_fb(session, inv, alert_id="a-1", template_id=1,
           human="true_positive", agreement=True)
    latest = _mk_fb(session, inv, alert_id="a-1", template_id=1,
                    human="false_positive", agreement=False)
    session.commit()

    out = repo.feedback_outcomes_for_signature(SIG, session)
    assert [r.id for r in out] == [latest.id]
    assert out[0].human_verdict == "false_positive"


def test_feedback_outcomes_scoped_to_signature_and_linked_rows(session):
    ours = _mk_inv(session, sig=SIG)
    other = _mk_inv(session, sig="Some Other Rule")
    kept = _mk_fb(session, ours, alert_id="a-1")
    _mk_fb(session, other, alert_id="a-2")           # other rule
    _mk_fb(session, None, alert_id="a-3")            # no investigation link
    session.commit()

    out = repo.feedback_outcomes_for_signature(SIG, session)
    assert [r.id for r in out] == [kept.id]


# ---------------------------------------------------------------------------
# 3. Memory context block rendering
# ---------------------------------------------------------------------------

def _memory_service_bound_to(session, monkeypatch):
    from ion.services.investigation_memory_service import (
        InvestigationMemoryService,
    )
    svc = InvestigationMemoryService()

    @contextmanager
    def _fake_session():
        yield session

    monkeypatch.setattr(svc, "_session", _fake_session)
    return svc


def test_context_block_shows_confidence_and_orders_by_it(session, monkeypatch):
    _mk_inv(session, conf=30, days_ago=0, summary="low-confidence run")
    _mk_inv(session, conf=90, days_ago=9, summary="high-confidence run")
    session.commit()

    svc = _memory_service_bound_to(session, monkeypatch)
    block = svc.build_context_block_for_alert({"alert_signature": SIG})

    assert "most confident first" in block
    assert "confidence=90" in block
    hi = block.index("confidence=90")
    lo = block.index("confidence=30")
    assert hi < lo


def test_context_block_renders_analyst_disagreement(session, monkeypatch):
    inv = _mk_inv(session)
    _mk_fb(session, inv, alert_id="a-1", template_id=1,
           bob="true_positive", human="false_positive",
           agreement=False, conf=82, delta_reason="scheduled admin task")
    _mk_fb(session, inv, alert_id="a-2", template_id=1,
           bob="false_positive", human="false_positive", agreement=True)
    session.commit()

    svc = _memory_service_bound_to(session, monkeypatch)
    block = svc.build_context_block_for_alert({"alert_signature": SIG})

    assert "Human review outcomes for this rule" in block
    assert "1 agreed" in block and "1 disagreed" in block
    assert "**ANALYST DISAGREED**" in block
    assert "AI said true_positive (confidence 82)" in block
    assert "human closed as **false_positive**" in block
    assert "scheduled admin task" in block
    assert "Weigh the human closures" in block


def test_context_block_no_ledger_rows_no_outcome_section(session, monkeypatch):
    _mk_inv(session, conf=50)
    session.commit()

    svc = _memory_service_bound_to(session, monkeypatch)
    block = svc.build_context_block_for_alert({"alert_signature": SIG})
    assert "Human review outcomes" not in block
    assert "ANALYST DISAGREED" not in block


# ---------------------------------------------------------------------------
# 4. Shared RAG-layer builder
# ---------------------------------------------------------------------------

def _detached_renderer(monkeypatch, *, kb=None, playbooks=None, ti=None,
                       skills_block=""):
    from ion.services.alert_prompt_service import _DetachedRenderer
    svc = _DetachedRenderer()
    monkeypatch.setattr(svc, "_get_kb_context_for_alert", lambda alert: kb or [])
    monkeypatch.setattr(svc, "_get_gold_exemplars_for_alert", lambda alert: [])
    monkeypatch.setattr(
        svc, "_get_playbook_context_for_alert", lambda alert: playbooks or []
    )
    monkeypatch.setattr(
        svc, "_get_ti_report_context_for_alert", lambda alert: ti or []
    )
    import ion.services.skill_loader as sl
    monkeypatch.setattr(sl, "select_skills_for_alert", lambda alert: [])
    monkeypatch.setattr(sl, "format_skills_for_prompt", lambda s: skills_block)
    return svc


_KB_HIT = {"document_id": 1, "name": "KB doc", "excerpt": "kb text",
           "similarity": 0.9, "chunk_index": 0}
_PB_HIT = {"playbook_id": 1, "name": "PB", "description": "steps",
           "steps": ["Contain host"], "matched_via": "trigger match"}
_TI_HIT = {"report_id": 1, "name": "TI report", "published": "2026-07-01",
           "source": "CTI", "similarity": 0.8, "excerpt": "ti passage"}


def test_build_rag_context_blocks_priority_order(monkeypatch):
    svc = _detached_renderer(
        monkeypatch, kb=[_KB_HIT], playbooks=[_PB_HIT], ti=[_TI_HIT],
        skills_block="\n\n## Skills\nskill body\n",
    )
    blocks = svc.build_rag_context_blocks({"rule_name": "r"}, remaining=10_000)
    joined = "".join(blocks)
    assert len(blocks) == 4
    assert (
        joined.index("KB doc")
        < joined.index("Response Playbooks")
        < joined.index("Threat Intelligence")
        < joined.index("Skills")
    )


def test_build_rag_context_blocks_drops_over_budget_layer(monkeypatch):
    from ion.services.alert_prompt_service import (
        _estimate_tokens,
        _format_kb_context_for_prompt,
        _format_playbook_context_for_prompt,
        _format_ti_report_context_for_prompt,
    )
    fat_pb = dict(_PB_HIT, description="x" * 300,
                  steps=[f"step {i} " * 20 for i in range(10)])
    kb_cost = _estimate_tokens(_format_kb_context_for_prompt([_KB_HIT]))
    ti_cost = _estimate_tokens(_format_ti_report_context_for_prompt([_TI_HIT]))
    pb_cost = _estimate_tokens(_format_playbook_context_for_prompt([fat_pb]))
    assert pb_cost > ti_cost  # fixture sanity — playbook must be the fat one

    svc = _detached_renderer(monkeypatch, kb=[_KB_HIT], playbooks=[fat_pb],
                             ti=[_TI_HIT])
    # Budget fits KB + TI exactly; the playbook layer between them doesn't.
    blocks = svc.build_rag_context_blocks(
        {"rule_name": "r"}, remaining=kb_cost + ti_cost
    )
    joined = "".join(blocks)
    assert "KB doc" in joined
    assert "Response Playbooks" not in joined   # too fat for the budget
    assert "Threat Intelligence" in joined      # still admitted after the drop


def test_build_rag_context_blocks_empty_inputs(monkeypatch):
    svc = _detached_renderer(monkeypatch)
    assert svc.build_rag_context_blocks({}, remaining=1000) == []
    assert svc.build_rag_context_blocks({"rule_name": "r"}, remaining=0) == []


def test_render_system_prompt_uses_shared_blocks(monkeypatch):
    from ion.services.alert_prompt_service import (
        _DetachedRenderer,
    )
    svc = _DetachedRenderer()
    monkeypatch.setattr(
        svc, "build_rag_context_blocks",
        lambda alert, remaining: ["\n\n## FAKE RAG BLOCK\n"],
    )
    out = svc.render_system_prompt(None, {"rule_name": "r"})
    assert "FAKE RAG BLOCK" in out
    # The output contract still trails every rendered prompt.
    assert out.index("FAKE RAG BLOCK") < out.index("Output Contract — MANDATORY")


# ---------------------------------------------------------------------------
# 5. bob_analysis_api alignment
# ---------------------------------------------------------------------------

def test_representative_alert_prefers_raw_and_backfills():
    from ion.models.alert_triage import AlertCase, AlertTriage
    from ion.web.bob_analysis_api import _build_representative_alert

    case = AlertCase(severity="high")
    case.mitre_techniques = ["T1059.001"]
    triage = AlertTriage(rule_name="Triage Rule")
    raw = {"rule_name": "Raw Rule", "host": {"name": "ws-01"}}

    rep = _build_representative_alert(case, [triage], raw)
    assert rep["rule_name"] == "Raw Rule"          # raw wins
    assert rep["host"] == {"name": "ws-01"}
    assert rep["severity"] == "high"               # backfilled from case
    assert rep["mitre_tags"] == ["T1059.001"]


def test_representative_alert_synthetic_without_es():
    from ion.models.alert_triage import AlertCase, AlertTriage
    from ion.web.bob_analysis_api import _build_representative_alert

    case = AlertCase(severity="medium")
    triage = AlertTriage(rule_name="Triage Rule")
    rep = _build_representative_alert(case, [triage], None)
    assert rep["rule_name"] == "Triage Rule"
    assert rep["severity"] == "medium"


def test_augment_system_prompt_appends_guide_and_blocks(session, monkeypatch):
    from ion.services.alert_prompt_service import AlertPromptService
    from ion.web.bob_analysis_api import _SYSTEM_PROMPT, _augment_system_prompt

    template = SimpleNamespace(
        name="PowerShell Guide", description="What this rule means.",
        severity_hint="high", prompt_text="Check the encoded command.",
    )
    monkeypatch.setattr(
        AlertPromptService, "resolve_template_for_alert",
        lambda self, alert: template,
    )
    monkeypatch.setattr(
        AlertPromptService, "build_rag_context_blocks",
        lambda self, alert, remaining: ["\n\n## Relevant KB\nkb text\n"],
    )

    prompt, meta = _augment_system_prompt(session, {"rule_name": "r"})
    assert prompt.startswith(_SYSTEM_PROMPT)
    assert "Per-Rule Investigation Guide: PowerShell Guide" in prompt
    assert "Check the encoded command." in prompt
    assert "Relevant KB" in prompt
    assert meta == {"template": "PowerShell Guide", "rag_blocks": 1}


def test_augment_system_prompt_bare_on_empty_alert(session):
    from ion.web.bob_analysis_api import _SYSTEM_PROMPT, _augment_system_prompt
    prompt, meta = _augment_system_prompt(session, {})
    assert prompt == _SYSTEM_PROMPT
    assert meta == {"template": None, "rag_blocks": 0}


def test_user_prompt_carries_memory_block():
    from ion.models.alert_triage import AlertCase
    from ion.web.bob_analysis_api import _build_user_prompt

    case = AlertCase(case_number="CASE-00042", title="t", severity="low",
                     status="open")
    out = _build_user_prompt(
        case, [], [], [], [],
        memory_block="## Investigation memory\n- **ANALYST DISAGREED**: x",
    )
    assert "## Investigation memory" in out
    assert out.index("Investigation memory") < out.index("Produce the verdict")
