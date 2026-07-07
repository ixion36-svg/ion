"""v0.49.6 — Threat-Intel "recently active" widget fixes.

Bug A: "Recently Seen MITRE Techniques" was empty/garbage because the
aggregation assumed bare-string technique ids, but the manual triage-edit PUT
stores dicts ({"technique_id": "T1059", ...}) — str(dict) never matched a Txxxx
id. Now shape-tolerant.

Bug B: "Recently Active Observables" was polluted by rule-field / command-content
roles (process_name, command_line, file_path, registry_*). A hide_rule_observables
toggle (default on) filters them via observable_service.DISPLAY_ONLY_TYPES.
"""

from ion.models.alert_triage import AlertCase, AlertTriage
from ion.web.threat_intel_api import recently_active


def _seed(session):
    session.add(AlertCase(
        case_number="CASE-9001", title="t", created_by_id=1,
        observables=[
            {"type": "source_ip", "value": "45.77.1.1"},
            {"type": "domain", "value": "evil.example"},
            {"type": "command_line", "value": "powershell -enc AAAA"},
            {"type": "process_name", "value": "evil.exe"},
            {"type": "file_path", "value": "C:/temp/x"},
        ],
    ))
    # Dict shape (manual triage-edit PUT) + bare-string shape (seeds/fixtures).
    session.add(AlertTriage(es_alert_id="a-1", mitre_techniques=[
        {"technique_id": "T1059", "technique_name": "Command and Scripting"},
    ]))
    session.add(AlertTriage(es_alert_id="a-2", mitre_techniques=["T1071"]))
    session.commit()


def test_mitre_tolerates_dict_and_string_shapes(session):
    _seed(session)
    r = recently_active(days=30, top_n=10, hide_rule_observables=True, session=session, user=None)
    ids = {t["id"] for t in r["techniques"]}
    assert "T1059" in ids   # dict shape → technique_id extracted
    assert "T1071" in ids   # bare-string shape still works
    # no stringified-dict junk ("{'technique_id': ...}")
    assert all("{" not in t["id"] for t in r["techniques"])


def test_hide_rule_observables_default_on(session):
    _seed(session)
    r = recently_active(days=30, top_n=10, hide_rule_observables=True, session=session, user=None)
    types = {o["type"] for o in r["observables"]}
    assert "source_ip" in types and "domain" in types          # real IOCs kept
    assert "command_line" not in types                          # rule-field dropped
    assert "process_name" not in types and "file_path" not in types


def test_hide_rule_observables_opt_out(session):
    _seed(session)
    r = recently_active(days=30, top_n=10, hide_rule_observables=False, session=session, user=None)
    types = {o["type"] for o in r["observables"]}
    assert "command_line" in types and "process_name" in types  # opt-out brings them back


if __name__ == "__main__":
    import sys

    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
