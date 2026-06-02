"""v0.37.0 — embedding text quality (Phase 2b).

Two improvements to what the RAG vectors carry:

1. `_alert_text_for_embedding` (query vector) appends higher-signal
   sections after the aligned core: Elastic `reason`, MITRE tags, and a
   compact TI-enrichment verdict digest — when present on the alert dict.
2. `_case_source_text` (stored case vector) only embeds Bob's AI summary
   when the investigation reached a DECISIVE verdict (not NULL / not
   "inconclusive") — inconclusive boilerplate is noise that pulls
   unrelated cases together.

The first five alert sections stay aligned with the case builder so the
query vector remains comparable to stored case vectors.
"""

from __future__ import annotations

# Import models at module top so they register on the shared Base.metadata
# before the `session` fixture's create_all runs.
from ion.models.alert_triage import AlertCase  # noqa: F401
from ion.models.investigation import Investigation

# ---------------------------------------------------------------------------
# _enrichment_digest
# ---------------------------------------------------------------------------

def test_enrichment_digest_non_dict_returns_empty():
    from ion.services.alert_prompt_service import _enrichment_digest
    assert _enrichment_digest(None) == ""
    assert _enrichment_digest("nope") == ""
    assert _enrichment_digest({}) == ""
    assert _enrichment_digest({"ip": {}, "domain": {}}) == ""  # all empty kinds


def test_enrichment_digest_summarises_verdicts():
    from ion.services.alert_prompt_service import _enrichment_digest
    enr = {
        "ip": {"1.2.3.4": "VirusTotal 45/70 malicious"},
        "hash": {"abc123": "known ransomware"},
        "domain": {},
    }
    out = _enrichment_digest(enr)
    assert "ip:" in out and "1.2.3.4" in out and "malicious" in out
    assert "hash:" in out and "abc123" in out
    assert "domain" not in out  # empty kind skipped


def test_enrichment_digest_bounded():
    from ion.services.alert_prompt_service import _enrichment_digest
    enr = {"ip": {f"10.0.0.{i}": "x" * 100 for i in range(50)}}
    out = _enrichment_digest(enr, max_chars=120)
    assert len(out) <= 120


# ---------------------------------------------------------------------------
# _alert_text_for_embedding
# ---------------------------------------------------------------------------

def _full_alert() -> dict:
    return {
        "alert_signature": "Suspicious PowerShell",
        "description": "Encoded command observed",
        "host": "WORKSTATION-7",
        "user_name": "jdoe",
        "rule_id": "rule-123",
        "alert_reason": "process powershell.exe with -enc flag on WORKSTATION-7",
        "mitre_tags": ["T1059.001", "T1027"],
        "enrichment": {"ip": {"9.9.9.9": "malicious C2"}},
    }


def test_alert_text_core_sections_present_and_ordered():
    from ion.services.alert_prompt_service import _alert_text_for_embedding
    text = _alert_text_for_embedding(_full_alert())
    for label in ("Title:", "Description:", "Hosts:", "Users:", "Rules:"):
        assert label in text
    # Core order preserved
    assert (
        text.index("Title:") < text.index("Description:") < text.index("Hosts:")
        < text.index("Users:") < text.index("Rules:")
    )


def test_alert_text_appends_enrichment_after_core():
    from ion.services.alert_prompt_service import _alert_text_for_embedding
    text = _alert_text_for_embedding(_full_alert())
    assert "Reason: process powershell.exe" in text
    assert "MITRE: T1059.001, T1027" in text
    assert "Enrichment: ip: 9.9.9.9" in text
    # New sections come AFTER the aligned core
    assert text.index("Rules:") < text.index("Reason:") < text.index("MITRE:") < text.index("Enrichment:")


def test_alert_text_omits_absent_sections():
    from ion.services.alert_prompt_service import _alert_text_for_embedding
    text = _alert_text_for_embedding({"rule_name": "Some rule", "host": "h1"})
    assert "Reason:" not in text
    assert "MITRE:" not in text
    assert "Enrichment:" not in text


def test_alert_text_reason_from_nested_kibana_shape():
    from ion.services.alert_prompt_service import _alert_text_for_embedding
    # dotted flat key
    t1 = _alert_text_for_embedding({"rule_name": "r", "kibana.alert.reason": "flat dotted reason"})
    assert "Reason: flat dotted reason" in t1
    # nested dict key
    t2 = _alert_text_for_embedding({"rule_name": "r", "kibana": {"alert": {"reason": "nested reason"}}})
    assert "Reason: nested reason" in t2


def test_alert_text_ignores_non_list_mitre():
    from ion.services.alert_prompt_service import _alert_text_for_embedding
    text = _alert_text_for_embedding({"rule_name": "r", "mitre_tags": "T1059"})  # str, not list
    assert "MITRE:" not in text


# ---------------------------------------------------------------------------
# _case_source_text — decisive-summary filter (needs a DB session)
# ---------------------------------------------------------------------------

def _mk_case(session, alert_ref: str) -> AlertCase:
    case = AlertCase(
        case_number=f"CASE-{alert_ref}",
        title="Test case",
        created_by_id=1,
        source_alert_ids=[alert_ref],
    )
    session.add(case)
    session.commit()
    return case


def _mk_inv(session, alert_ref: str, verdict, summary: str):
    inv = Investigation(
        alert_id_ref=alert_ref,
        alert_signature="sig",
        status="completed",
        verdict=verdict,
        summary_text=summary,
    )
    session.add(inv)
    session.commit()
    return inv


def test_case_source_includes_decisive_ai_summary(session):
    from ion.services.case_embedding_service import _case_source_text
    case = _mk_case(session, "alert-decisive")
    _mk_inv(session, "alert-decisive", "true_positive", "Confirmed credential theft.")
    text = _case_source_text(session, case)
    assert "AI summary: Confirmed credential theft." in text


def test_case_source_excludes_inconclusive_ai_summary(session):
    from ion.services.case_embedding_service import _case_source_text
    case = _mk_case(session, "alert-inconclusive")
    _mk_inv(session, "alert-inconclusive", "inconclusive", "Insufficient evidence to determine.")
    text = _case_source_text(session, case)
    assert "AI summary" not in text


def test_case_source_excludes_null_verdict(session):
    from ion.services.case_embedding_service import _case_source_text
    case = _mk_case(session, "alert-null")
    _mk_inv(session, "alert-null", None, "Some summary text.")
    text = _case_source_text(session, case)
    assert "AI summary" not in text


def test_case_source_prefers_decisive_over_inconclusive(session):
    from ion.services.case_embedding_service import _case_source_text
    case = _mk_case(session, "alert-mixed")
    # Older decisive, newer inconclusive — filter must still pick the decisive one.
    _mk_inv(session, "alert-mixed", "false_positive", "Benign admin activity.")
    _mk_inv(session, "alert-mixed", "inconclusive", "Could not determine.")
    text = _case_source_text(session, case)
    assert "AI summary: Benign admin activity." in text
    assert "Could not determine." not in text


# ---------------------------------------------------------------------------
# Shared core-section formatter + length caps
# ---------------------------------------------------------------------------

def test_format_core_sections_order_and_skip_falsy():
    from ion.services.embedding_service import format_core_embedding_sections
    parts = format_core_embedding_sections(
        title="T", description="D", hosts="H", users=None, rules="R"
    )
    assert parts == ["Title: T", "Description: D", "Hosts: H", "Rules: R"]  # Users skipped


def test_format_core_sections_clips_description():
    from ion.services.embedding_service import format_core_embedding_sections
    parts = format_core_embedding_sections(description="x" * 5000, description_cap=1000)
    assert parts == ["Description: " + "x" * 1000]


def test_alert_text_clips_long_reason():
    from ion.services.alert_prompt_service import _alert_text_for_embedding
    text = _alert_text_for_embedding({"rule_name": "r", "alert_reason": "y" * 5000})
    # Reason section capped at 600 chars
    assert "Reason: " + "y" * 600 in text
    assert "y" * 601 not in text


def test_case_source_clips_long_ai_summary(session):
    from ion.services.case_embedding_service import _case_source_text
    case = _mk_case(session, "alert-long")
    _mk_inv(session, "alert-long", "true_positive", "z" * 5000)
    text = _case_source_text(session, case)
    assert "z" * 1500 in text
    assert "z" * 1501 not in text
