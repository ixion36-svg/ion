"""The auto-grouped case description should be structured, not a flat sentence.

Before: "Auto-grouped by rule + host + user. Contributing alerts: 2. Grouping
key: rule='X', host='Y', user='Z'." — hard to scan in the case UI.
"""
from ion.services.case_grouper_service import _render_case_description


def test_description_has_structured_fields():
    d = _render_case_description(rule_key="Suspicious PowerShell EncodedCommand",
                                 host="FIN-WKS-04", user="jbloggs",
                                 n_alerts=2, severity="high")
    # scannable labelled fields
    assert "Rule" in d and "Suspicious PowerShell EncodedCommand" in d
    assert "Host" in d and "FIN-WKS-04" in d
    assert "User" in d and "jbloggs" in d
    assert "2" in d  # alert count
    assert "high" in d.lower()


def test_description_handles_missing_host_user():
    d = _render_case_description(rule_key="Some Rule", host=None, user=None,
                                 n_alerts=1, severity=None)
    assert "Some Rule" in d
    assert "1" in d
    # no crash, still structured
    assert "Host" in d and "User" in d
