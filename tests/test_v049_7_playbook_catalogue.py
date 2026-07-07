"""v0.49.7 — Bob AlertPromptTemplate catalogue expansion + threshold tuning.

Covers: catalogue integrity (unique names, every template MITRE-mapped), the 10
new templates, the confidence-threshold seeding FIX (the override was defined on
the model but never passed through the seeder), and MITRE-tier routing to a new
template.
"""

from ion.services.alert_prompt_service import (
    _DEFAULT_TEMPLATES,
    _TEMPLATE_MITRE_MAP,
    _TEMPLATE_THRESHOLD_MAP,
    seed_default_templates,
)
from ion.storage.alert_prompt_repository import AlertPromptRepository

NEW_TEMPLATES = [
    "DCSync / NTDS.dit Extraction",
    "Remote Access / RMM Tooling",
    "Resource Hijacking / Cryptomining",
    "Data Destruction / Wiper",
    "Rogue Account Creation",
    "GPO / Domain Policy Modification",
    "AD Certificate Services / Ticket Forgery",
    "Account Access Removal",
    "BITS Jobs — Ingress / Persistence",
    "Collection & Archiving / Data Staging",
]


def test_catalogue_integrity():
    names = [t["name"] for t in _DEFAULT_TEMPLATES]
    assert len(names) == len(set(names)), "duplicate template names"
    assert len(names) >= 64  # 54 original + 10 v0.49.7 additions
    for n in names:
        assert n in _TEMPLATE_MITRE_MAP, f"{n} has no MITRE mapping"


def test_new_templates_present_and_mapped():
    names = {t["name"] for t in _DEFAULT_TEMPLATES}
    for n in NEW_TEMPLATES:
        assert n in names, f"missing new template {n}"
        assert _TEMPLATE_MITRE_MAP[n].get("techniques"), f"{n} has no techniques"
        assert _TEMPLATE_MITRE_MAP[n].get("tactics"), f"{n} has no tactics"


def test_threshold_map_keys_all_valid():
    names = {t["name"] for t in _DEFAULT_TEMPLATES}
    for k in _TEMPLATE_THRESHOLD_MAP:
        assert k in names, f"threshold override for unknown template: {k}"


def test_seed_wires_confidence_threshold(session):
    """The v0.49.7 fix: seed_default_templates must persist the per-template
    override. Before the fix it was never passed to repo.create()."""
    inserted = seed_default_templates(session)
    assert inserted >= 64
    by_name = {t.name: t for t in AlertPromptRepository(session).list_all()}
    # a "raise" override (noisy telemetry → abstain more)
    assert by_name["Sysmon Event 7 — Image/DLL Loaded"].confidence_threshold_override == 75
    # a "lower" override (critical → surface more)
    assert by_name["Ransomware Indicators"].confidence_threshold_override == 45
    # a new template's inline override
    assert by_name["DCSync / NTDS.dit Extraction"].confidence_threshold_override == 45
    # an un-tuned template keeps NULL → global default applies
    assert by_name["Web Application Attack"].confidence_threshold_override is None


def test_new_template_routes_by_mitre_technique(session):
    """An alert tagged T1003.006 (DCSync) with no group/regex match should route
    to the DCSync template on the MITRE tier (it out-prioritises the generic
    Credential Access template, which only maps the parent T1003)."""
    seed_default_templates(session)
    repo = AlertPromptRepository(session)
    alert = {"rule_id": "vendor-edr-rule-98311", "rule": {"mitre": {"id": ["T1003.006"]}}}
    match = repo.find_matching(alert)
    assert match is not None
    assert match.name == "DCSync / NTDS.dit Extraction"


if __name__ == "__main__":
    import sys

    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
