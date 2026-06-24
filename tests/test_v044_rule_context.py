"""v0.44.0 — rule description + investigation guide reach the LLM prompt.

`_build_alert_summary` must surface the detection rule's own prose
(`kibana.alert.rule.description`) and its investigation guide / note
(`kibana.alert.rule.note` / `parameters.note`) so Bob reasons with the
detection author's intent — capped so a verbose guide can't blow the
user-prompt token budget, and omitted entirely when absent.
"""
from ion.services.investigation_service import InvestigationService


def test_rule_description_and_guide_surface_in_summary():
    svc = InvestigationService()
    alert = {
        "_id": "a1",
        "kibana.alert.rule.name": "Suspicious Encoded PowerShell",
        "kibana.alert.rule.description": "Detects base64-encoded PowerShell commonly used by loaders.",
        "kibana.alert.rule.note": "## Triage\n1. Inspect the parent process\n2. Decode the -enc payload",
        "process.name": "powershell.exe",
    }
    s = svc._build_alert_summary(alert)
    assert s["rule_description"].startswith("Detects base64-encoded PowerShell")
    assert "Triage" in s["rule_investigation_guide"]
    assert "Decode the -enc payload" in s["rule_investigation_guide"]


def test_rule_fields_fall_back_to_legacy_and_parameters_aliases():
    svc = InvestigationService()
    alert = {
        "_id": "a2",
        "signal.rule.description": "legacy signal description",
        "kibana.alert.rule.parameters.note": "guide stored under parameters.note",
    }
    s = svc._build_alert_summary(alert)
    assert s["rule_description"] == "legacy signal description"
    assert s["rule_investigation_guide"] == "guide stored under parameters.note"


def test_long_investigation_guide_is_capped():
    svc = InvestigationService()
    alert = {"_id": "a3", "kibana.alert.rule.note": "S" * 5000}
    s = svc._build_alert_summary(alert)
    guide = s["rule_investigation_guide"]
    assert guide.endswith("…[truncated]")
    # Capped near 1000 chars (plus the short marker), well under what would
    # crowd out the alert facts.
    assert len(guide) <= 1000 + len(" …[truncated]")


def test_rule_context_omitted_when_absent():
    svc = InvestigationService()
    s = svc._build_alert_summary({"_id": "a4", "process.name": "cmd.exe"})
    assert "rule_description" not in s
    assert "rule_investigation_guide" not in s


def test_detection_rule_context_section_rendered_in_user_prompt():
    svc = InvestigationService()
    summary = svc._build_alert_summary(
        {
            "_id": "a5",
            "kibana.alert.rule.description": "Detects LSASS credential dumping.",
            "kibana.alert.rule.note": "Check lsass.exe access and the parent process.",
            "process.name": "mimikatz.exe",
        }
    )
    body = svc._build_user_prompt_body(summary, {}, [], "", {})
    assert "## Detection rule context" in body
    assert "What this rule detects:" in body
    assert "Detects LSASS credential dumping." in body
    assert "Author's investigation guide:" in body
    assert "Check lsass.exe access" in body
    # The rule fields appear in the dedicated section, NOT duplicated as flat
    # alert-summary key/value lines.
    assert "- rule_description:" not in body
    assert "- rule_investigation_guide:" not in body


def test_no_detection_rule_context_section_when_absent():
    svc = InvestigationService()
    summary = svc._build_alert_summary({"_id": "a6", "process.name": "cmd.exe"})
    body = svc._build_user_prompt_body(summary, {}, [], "", {})
    assert "## Detection rule context" not in body
