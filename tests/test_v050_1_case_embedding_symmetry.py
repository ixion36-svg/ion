"""v0.50.1 — case-side MITRE/enrichment embedding symmetry.

Since v0.37.0 the alert *query* vector carries ``MITRE:`` and
``Enrichment:`` sections, but the stored *case* vector only had that
signal incidentally in prose. This release closes the asymmetry:

1. ``_case_source_text`` appends a ``MITRE:`` section — the deduped,
   sorted union of ``AlertTriage.mitre_techniques`` across the case's
   triage entries (dict shape and legacy bare-string shape both accepted).
2. It appends an ``Enrichment:`` section — the shared digest over the
   ``enrichment`` sub-dict of recent ``Investigation.ioc_snapshot_json``
   snapshots (factual TI output, so no decisive-verdict filter).
3. The digest implementation moved to ``embedding_service.
   format_enrichment_digest`` so query and case builders cannot drift;
   ``alert_prompt_service._enrichment_digest`` is now an alias to it.

Cases with neither section produce byte-identical source text to
pre-v0.50.1, so their hash is unchanged and they are NOT re-embedded.
"""

from __future__ import annotations

# Import models at module top so they register on the shared Base.metadata
# before the `session` fixture's create_all runs.
from ion.models.alert_triage import AlertCase, AlertTriage
from ion.models.investigation import Investigation


def _mk_case(session, ref: str, **kw) -> AlertCase:
    case = AlertCase(
        case_number=f"CASE-{ref}",
        title="Test case",
        created_by_id=1,
        source_alert_ids=[ref],
        **kw,
    )
    session.add(case)
    session.commit()
    return case


def _mk_triage(session, ref: str, case_id: int, techniques) -> AlertTriage:
    triage = AlertTriage(
        es_alert_id=ref,
        case_id=case_id,
        mitre_techniques=techniques,
    )
    session.add(triage)
    session.commit()
    return triage


def _mk_inv(session, ref: str, ioc_snapshot_json=None, verdict=None,
            summary=None) -> Investigation:
    inv = Investigation(
        alert_id_ref=ref,
        alert_signature="sig",
        status="completed",
        verdict=verdict,
        summary_text=summary,
        ioc_snapshot_json=ioc_snapshot_json,
    )
    session.add(inv)
    session.commit()
    return inv


# ---------------------------------------------------------------------------
# Shared digest — one implementation for both vector builders
# ---------------------------------------------------------------------------

def test_digest_alias_is_the_shared_implementation():
    from ion.services.alert_prompt_service import _enrichment_digest
    from ion.services.embedding_service import format_enrichment_digest
    assert _enrichment_digest is format_enrichment_digest


# ---------------------------------------------------------------------------
# MITRE section
# ---------------------------------------------------------------------------

def test_case_mitre_union_dict_shape_sorted_deduped(session):
    from ion.services.case_embedding_service import _case_source_text
    case = _mk_case(session, "mitre-dict")
    _mk_triage(session, "t1-mitre-dict", case.id, [
        {"technique_id": "T1059.001", "technique_name": "PowerShell",
         "tactic_name": "Execution", "source": "manual"},
        {"technique_id": "T1027", "technique_name": "Obfuscation",
         "tactic_name": "Defense Evasion", "source": "auto"},
    ])
    _mk_triage(session, "t2-mitre-dict", case.id, [
        {"technique_id": "T1027"},  # duplicate across triage rows
        {"technique_id": "T1003"},
    ])
    text = _case_source_text(session, case)
    # Union, deduped, sorted — stable regardless of triage-row order.
    assert "MITRE: T1003, T1027, T1059.001" in text


def test_case_mitre_accepts_legacy_bare_strings(session):
    from ion.services.case_embedding_service import _case_source_text
    case = _mk_case(session, "mitre-str")
    _mk_triage(session, "t1-mitre-str", case.id, ["T1566", "T1078"])
    text = _case_source_text(session, case)
    assert "MITRE: T1078, T1566" in text


def test_case_mitre_capped_at_20(session):
    from ion.services.case_embedding_service import (
        _MITRE_MAX_TECHNIQUES,
        _case_mitre_techniques,
    )
    case = _mk_case(session, "mitre-cap")
    _mk_triage(
        session, "t1-mitre-cap", case.id,
        [{"technique_id": f"T1{i:03d}"} for i in range(30)],
    )
    ids = _case_mitre_techniques(session, case)
    assert len(ids) == _MITRE_MAX_TECHNIQUES


def test_case_mitre_ignores_other_cases_and_uncased_triage(session):
    from ion.services.case_embedding_service import _case_source_text
    case = _mk_case(session, "mitre-scope")
    other = _mk_case(session, "mitre-scope-other")
    _mk_triage(session, "t-other-case", other.id, [{"technique_id": "T9999"}])
    _mk_triage(session, "t-no-case", None, [{"technique_id": "T8888"}])
    text = _case_source_text(session, case)
    assert "MITRE:" not in text


def test_case_mitre_tolerates_malformed_entries(session):
    from ion.services.case_embedding_service import _case_source_text
    case = _mk_case(session, "mitre-malformed")
    _mk_triage(session, "t1-mitre-malformed", case.id, [
        {"technique_name": "no id"},  # dict without technique_id
        {"technique_id": ""},
        "",
        "T1110",
    ])
    text = _case_source_text(session, case)
    assert "MITRE: T1110" in text


# ---------------------------------------------------------------------------
# Enrichment section
# ---------------------------------------------------------------------------

def test_case_enrichment_from_ioc_snapshot(session):
    import json

    from ion.services.case_embedding_service import _case_source_text
    case = _mk_case(session, "enr-basic")
    _mk_inv(session, "enr-basic", ioc_snapshot_json=json.dumps({
        "extracted": {"ip": ["9.9.9.9"]},
        "enrichment": {"ip": {"9.9.9.9": "malicious C2"}},
    }))
    text = _case_source_text(session, case)
    assert "Enrichment: ip: 9.9.9.9 (malicious C2)" in text


def test_case_enrichment_no_verdict_filter(session):
    # Enrichment is factual TI output — unlike the AI summary, an
    # inconclusive investigation's enrichment still counts.
    import json

    from ion.services.case_embedding_service import _case_source_text
    case = _mk_case(session, "enr-inconclusive")
    _mk_inv(
        session, "enr-inconclusive", verdict="inconclusive",
        summary="Could not determine.",
        ioc_snapshot_json=json.dumps(
            {"enrichment": {"hash": {"abc123": "known ransomware"}}}
        ),
    )
    text = _case_source_text(session, case)
    assert "Enrichment: hash: abc123 (known ransomware)" in text
    assert "AI summary" not in text  # v0.37.0 decisive filter still holds


def test_case_enrichment_skips_empty_newest_snapshot(session):
    # Newest snapshot has empty enrichment (no IOCs that run) — the
    # lookback finds the older snapshot that carries real verdicts.
    import json

    from ion.services.case_embedding_service import _case_source_text
    case = _mk_case(session, "enr-lookback")
    _mk_inv(session, "enr-lookback", ioc_snapshot_json=json.dumps(
        {"enrichment": {"domain": {"evil.example": "phishing kit"}}}
    ))
    _mk_inv(session, "enr-lookback", ioc_snapshot_json=json.dumps(
        {"enrichment": {"ip": {}, "domain": {}, "url": {}, "hash": {}}}
    ))
    text = _case_source_text(session, case)
    assert "Enrichment: domain: evil.example (phishing kit)" in text


def test_case_enrichment_tolerates_malformed_snapshot(session):
    from ion.services.case_embedding_service import _case_source_text
    case = _mk_case(session, "enr-malformed")
    _mk_inv(session, "enr-malformed", ioc_snapshot_json="{not json")
    _mk_inv(session, "enr-malformed", ioc_snapshot_json='"a bare string"')
    text = _case_source_text(session, case)
    assert "Enrichment:" not in text


def test_case_enrichment_digest_bounded(session):
    import json

    from ion.services.case_embedding_service import _case_enrichment_digest
    case = _mk_case(session, "enr-bound")
    _mk_inv(session, "enr-bound", ioc_snapshot_json=json.dumps(
        {"enrichment": {"ip": {f"10.0.0.{i}": "x" * 100 for i in range(50)}}}
    ))
    digest = _case_enrichment_digest(session, case)
    assert 0 < len(digest) <= 400


# ---------------------------------------------------------------------------
# Section ordering + hash stability for untouched cases
# ---------------------------------------------------------------------------

def test_symmetry_sections_sit_between_evidence_and_ai_summary(session):
    import json

    from ion.services.case_embedding_service import _case_source_text
    case = _mk_case(session, "order", evidence_summary="Lateral movement seen")
    _mk_triage(session, "t1-order", case.id, [{"technique_id": "T1021"}])
    _mk_inv(
        session, "order", verdict="true_positive",
        summary="Confirmed intrusion.",
        ioc_snapshot_json=json.dumps(
            {"enrichment": {"ip": {"9.9.9.9": "C2"}}}
        ),
    )
    text = _case_source_text(session, case)
    assert (
        text.index("Evidence:") < text.index("MITRE:")
        < text.index("Enrichment:") < text.index("AI summary:")
    )


def test_case_without_mitre_or_enrichment_text_unchanged(session):
    # Pre-v0.50.1 byte-compatibility: a case with no triage MITRE and no
    # IOC snapshots must produce the exact same source text as before, so
    # its hash is unchanged and the loop does NOT re-embed it.
    from ion.services.case_embedding_service import _case_source_text
    case = _mk_case(
        session, "plain",
        description="A plain case",
        evidence_summary="Some evidence",
    )
    _mk_inv(session, "plain", verdict="true_positive", summary="Confirmed.")
    text = _case_source_text(session, case)
    assert text == (
        "Title: Test case\n"
        "Description: A plain case\n"
        "Evidence: Some evidence\n"
        "AI summary: Confirmed."
    )
