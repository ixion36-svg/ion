"""v0.89.0 — lean case description.

Observable values and the linked-alert-id enumeration no longer render into the
case description: observables post as a separate enrichment Note
(``post_enrichment_note``) and alerts show as first-class links on the case.
"""

from ion.services.case_description import build_case_description


def test_description_omits_observables_and_alert_ids():
    out = build_case_description(
        description="Lateral movement across two hosts.",
        affected_hosts=["WIN-DC01", "WIN-FS02"],
        affected_users=["svc-backup"],
        triggered_rules=["T1021 - Remote Services"],
        observables=[
            {"type": "ip", "value": "185.22.11.9"},
            {"type": "domain", "value": "c2.evil.test"},
        ],
        alert_ids=[f"alert-{i}" for i in range(23)],
    )
    # Kept: narrative + context labels.
    assert "Lateral movement across two hosts." in out
    assert "**Affected Hosts:** WIN-DC01, WIN-FS02" in out
    assert "**Affected Users:** svc-backup" in out
    assert "**Triggered Rules:** T1021 - Remote Services" in out
    # Dropped: observable values and the linked-alert-id enumeration.
    assert "185.22.11.9" not in out
    assert "c2.evil.test" not in out
    assert "alert-" not in out
    assert "Linked Alert" not in out
    assert "Observables" not in out


def test_description_empty_falls_back():
    # Kibana >= 8.19 rejects an empty description; the builder must never
    # return "".
    assert build_case_description() == "_No description provided._"


def test_description_preserves_evidence_summary():
    out = build_case_description(description="x", evidence_summary="ES text")
    assert "**Evidence Summary:**" in out
    assert "ES text" in out
