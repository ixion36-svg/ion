"""v0.39.0 — PCAP finding → MITRE ATT&CK technique mapping.

Pins the category→technique map, title-level refinements, catalogue validation
(unknown IDs are dropped, never surfaced), and the deduped case-level rollup.
"""
from ion.services.pcap_service import (
    _FINDING_MITRE,
    Finding,
    _attach_mitre,
    _build_mitre_summary,
    _load_attack_catalogue,
)


def _f(category, title="x", severity="medium"):
    return Finding(category=category, severity=severity, title=title, detail="")


def test_every_mapped_id_is_catalogue_valid():
    """The static map must reference only real ATT&CK technique IDs."""
    catalogue = _load_attack_catalogue()
    assert catalogue, "ATT&CK catalogue failed to load"
    for category, ids in _FINDING_MITRE.items():
        for tid in ids:
            assert tid in catalogue, f"{category} maps to unknown technique {tid}"


def test_category_mapping():
    findings = [
        _f("Command & Control"), _f("DGA Detection"),
        _f("DNS Tunneling"), _f("Data Exfiltration"),
        _f("Reconnaissance"), _f("credential_capture"),
    ]
    _attach_mitre(findings)
    by_cat = {f.category: f.mitre for f in findings}
    assert by_cat["Command & Control"] == ["T1071", "T1571"]
    assert by_cat["DGA Detection"] == ["T1568.002"]
    assert "T1071.004" in by_cat["DNS Tunneling"]
    assert "T1048" in by_cat["Data Exfiltration"]
    assert by_cat["Reconnaissance"] == ["T1046"]
    assert by_cat["credential_capture"] == ["T1040"]


def test_title_refinement_known_malware():
    f = _f("tls_fingerprint", title="1 known-malware JA4 fingerprint(s) detected")
    _attach_mitre([f])
    assert "T1071.001" in f.mitre
    assert "T1573.002" in f.mitre


def test_title_refinement_cobalt_strike():
    f = _f("TLS Certificate", title="Known-malicious TLS certificate: Cobalt Strike default certificate")
    _attach_mitre([f])
    assert "T1573.002" in f.mitre


def test_unknown_category_yields_empty():
    f = _f("Totally Made Up")
    _attach_mitre([f])
    assert f.mitre == []


def test_no_duplicate_ids():
    # TLS Certificate base map already has T1573; refinement adds T1573.002 not a dup
    f = _f("TLS Certificate", title="known-malware cobalt strike")
    _attach_mitre([f])
    assert len(f.mitre) == len(set(f.mitre))


def test_build_summary_dedup_and_named():
    findings = [_f("Command & Control"), _f("Suspicious Port")]  # both include T1571
    _attach_mitre(findings)
    summary = _build_mitre_summary(findings)
    ids = [t["id"] for t in summary]
    assert ids == sorted(ids)              # sorted
    assert len(ids) == len(set(ids))        # deduped (T1571 appears once)
    t1571 = next(t for t in summary if t["id"] == "T1571")
    assert t1571["name"] == "Non-Standard Port"
    assert t1571["tactic_ids"]              # populated from catalogue
