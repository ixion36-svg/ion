"""v0.49.3 live-integration finding (Kibana 8.19.11): the Cases API rejects
an empty description ("The description field cannot be an empty string",
400), and ION's 60s sync loop retried such cases forever. A case created
without a description (allowed by CaseCreate) produced exactly that."""

from __future__ import annotations

from ion.services.case_description import build_case_description


def test_empty_inputs_yield_non_empty_description():
    out = build_case_description(
        description="",
        affected_hosts=None,
        affected_users=None,
        evidence_summary=None,
        observables=None,
        alert_ids=None,
        triggered_rules=None,
    )
    assert out.strip(), "empty description reaches Kibana as '' -> 400 + endless retry"


def test_whitespace_description_yields_non_empty():
    out = build_case_description(
        description="   \n  ",
        affected_hosts=None,
        affected_users=None,
        evidence_summary=None,
        observables=None,
        alert_ids=None,
        triggered_rules=None,
    )
    assert out.strip()


def test_real_description_passes_through():
    out = build_case_description(
        description="Something happened",
        affected_hosts=["h1"],
        affected_users=None,
        evidence_summary=None,
        observables=None,
        alert_ids=None,
        triggered_rules=None,
    )
    assert "Something happened" in out and "h1" in out
