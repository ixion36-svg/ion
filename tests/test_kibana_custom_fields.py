"""Kibana native case custom fields — the value builder.

The live provisioning + case-create-with-customFields flow was verified against
Kibana 9.4.4 (ion_case_number/severity/rules/hosts land on the case); here we
lock the pure value-builder that maps ION case metadata onto those fields.
"""

from ion.services.kibana_cases_service import ION_CASE_CUSTOM_FIELDS, build_ion_custom_fields


def test_build_maps_case_metadata():
    cf = build_ion_custom_fields(
        case_number="CASE-0001", severity="high",
        triggered_rules=["T1021", "T1059"], affected_hosts=["h1", "h2"],
    )
    d = {c["key"]: c["value"] for c in cf}
    assert d == {
        "ion_case_number": "CASE-0001",
        "ion_severity": "high",
        "ion_rules": "T1021, T1059",
        "ion_hosts": "h1, h2",
    }
    assert all(c["type"] == "text" for c in cf)


def test_build_empty_sends_null_but_all_keys():
    cf = build_ion_custom_fields()
    assert all(c["value"] is None for c in cf)
    # every defined field must be present in the payload (Kibana expects them)
    assert {c["key"] for c in cf} == {f["key"] for f in ION_CASE_CUSTOM_FIELDS}
