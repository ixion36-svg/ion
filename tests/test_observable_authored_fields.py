"""A rule's documentation is not evidence.

Reported from a live SOC, 8 October 2026: a detection rule was producing
false-positive observables on every alert it raised, and the values were
coming out of the rule's own investigation guide.

``_alert_to_text_blob`` flattens an alert into one string for
``extract_iocs``. It walks every value in the document, and a Kibana
security alert carries the whole rule definition alongside the event:

    kibana.alert.rule.note              the investigation guide
    kibana.alert.rule.description       the rule's own prose
    kibana.alert.rule.false_positives   a list of known-benign examples
    kibana.alert.rule.references        links the author cited
    kibana.alert.rule.setup             deployment instructions
    kibana.alert.rule.query             the query, including any hunted IOC
    kibana.alert.rule.threat            MITRE references

Every IP, domain and hash a rule author wrote into an investigation guide
therefore became an observable on *every* alert that rule ever raised,
attached to a host that never contacted it. ``false_positives`` is the
sharpest case: the field exists to list values that are explicitly benign,
and ION was extracting them as indicators.

The blob already learned a version of this lesson once -- it used to
``json.dumps`` the alert and mis-read dotted ECS keys as domains, and was
changed to walk values only. This is the same mistake one level up: the
*values* of authored fields are no more evidence than the field names were.

So the walk becomes path-aware and skips the rule-definition subtree.
``kibana.alert.reason`` is deliberately kept: it is generated per alert
from the matched event, so a hostname in it is a real sighting.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from ion.services.investigation_service import _alert_to_text_blob


def alert(**overrides):
    """A Kibana security alert with both event data and rule metadata."""
    doc = {
        "@timestamp": "2026-10-08T10:00:00.000Z",
        "host": {"name": "WKS-FINANCE07", "ip": ["10.20.30.40"]},
        "source": {"ip": "203.0.113.55"},
        "destination": {"ip": "198.51.100.9", "domain": "real-c2.example"},
        "process": {"name": "powershell.exe"},
        "kibana": {
            "alert": {
                "reason": (
                    "powershell.exe connected to real-c2.example on "
                    "WKS-FINANCE07"
                ),
                "rule": {
                    "name": "Suspicious outbound from documented-host.example",
                    "description": (
                        "Detects beaconing. For example, traffic to "
                        "192.0.2.77 or evil-example.test is typical of this "
                        "family, hash "
                        "d41d8cd98f00b204e9800998ecf8427e."
                    ),
                    "note": (
                        "## Investigation guide\n"
                        "Check whether the host contacted 192.0.2.88 or "
                        "docs-example.test. Known C2 ranges include "
                        "203.0.113.0/24. Hash of the loader: "
                        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca"
                        "495991b7852b855."
                    ),
                    "false_positives": [
                        "Backup software contacting backup-vendor.example",
                        "Monitoring from 192.0.2.99",
                    ],
                    "references": [
                        "https://attack.mitre.org/techniques/T1071/",
                        "https://research-blog.example/post/1",
                    ],
                    "setup": "Install the agent and enable 192.0.2.1 as a collector.",
                    "query": 'destination.domain:"hunted-domain.example"',
                    "threat": [{"framework": "MITRE ATT&CK"}],
                },
            }
        },
    }
    doc.update(overrides)
    return doc


@pytest.fixture
def blob():
    return _alert_to_text_blob(alert())


# -- The values that must never be extracted ------------------------------


class TestAuthoredFieldsAreExcluded:
    @pytest.mark.parametrize("value,where", [
        ("192.0.2.77", "rule.description"),
        ("evil-example.test", "rule.description"),
        ("d41d8cd98f00b204e9800998ecf8427e", "rule.description"),
        ("192.0.2.88", "rule.note (investigation guide)"),
        ("docs-example.test", "rule.note (investigation guide)"),
        ("203.0.113.0/24", "rule.note (investigation guide)"),
        ("backup-vendor.example", "rule.false_positives"),
        ("192.0.2.99", "rule.false_positives"),
        ("research-blog.example", "rule.references"),
        ("192.0.2.1", "rule.setup"),
        ("hunted-domain.example", "rule.query"),
        ("documented-host.example", "rule.name"),
    ])
    def test_a_value_from_the_rule_definition_is_not_in_the_blob(
        self, blob, value, where
    ):
        assert value not in blob, (
            f"{value!r} comes from {where}, which the rule author wrote. "
            f"Extracting it makes every alert from this rule carry an "
            f"observable the host never touched."
        )

    def test_the_loader_hash_from_the_guide_is_not_extracted(self, blob):
        assert (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            not in blob
        )


# -- The values that must still be extracted ------------------------------


class TestEventDataSurvives:
    @pytest.mark.parametrize("value,where", [
        ("WKS-FINANCE07", "host.name"),
        ("10.20.30.40", "host.ip"),
        ("203.0.113.55", "source.ip"),
        ("198.51.100.9", "destination.ip"),
        ("real-c2.example", "destination.domain"),
        ("powershell.exe", "process.name"),
    ])
    def test_event_fields_are_still_in_the_blob(self, blob, value, where):
        assert value in blob, f"{value} ({where}) is real evidence"

    def test_the_alert_reason_is_kept(self, blob):
        """kibana.alert.reason is generated per alert from the matched
        event, unlike everything under kibana.alert.rule. A hostname in it
        is a real sighting, so excluding it would lose true positives."""
        assert "powershell.exe connected to real-c2.example" in blob

    def test_a_legacy_signal_format_alert_is_handled(self):
        """Older alerts nest the same metadata under signal.rule."""
        doc = {
            "host": {"name": "SRV-01"},
            "signal": {
                "rule": {
                    "description": "Example traffic to 192.0.2.50",
                    "note": "Check 192.0.2.60 as well.",
                },
                "reason": "something happened on SRV-01",
            },
        }
        blob = _alert_to_text_blob(doc)
        assert "SRV-01" in blob
        assert "192.0.2.50" not in blob
        assert "192.0.2.60" not in blob


# -- Robustness -----------------------------------------------------------


class TestRobustness:
    def test_an_alert_with_no_rule_metadata_is_unchanged(self):
        doc = {"host": {"name": "H1"}, "source": {"ip": "1.2.3.4"}}
        blob = _alert_to_text_blob(doc)
        assert "H1" in blob and "1.2.3.4" in blob

    def test_a_field_merely_named_like_the_rule_subtree_is_kept(self):
        """The exclusion is by path, not by the word "rule" appearing
        somewhere: a process called rule.exe is still evidence."""
        doc = {"process": {"name": "rule.exe"}, "user": {"name": "note"}}
        blob = _alert_to_text_blob(doc)
        assert "rule.exe" in blob

    def test_an_ip_shaped_dict_key_still_surfaces(self):
        """The values-only walk kept IP-shaped keys deliberately, for
        field-keyed aggregation maps. That must survive this change."""
        doc = {"aggregations": {"192.168.5.5": {"count": 3}}}
        assert "192.168.5.5" in _alert_to_text_blob(doc)

    def test_a_malformed_alert_does_not_raise(self):
        for bad in (None, [], "a string", 42):
            assert isinstance(_alert_to_text_blob(bad), str)

    def test_rule_metadata_nested_under_parameters_is_also_excluded(self):
        """Kibana mirrors much of the rule definition under
        kibana.alert.rule.parameters, so excluding only the top level
        would let the same text back in by another path."""
        doc = {
            "kibana": {"alert": {"rule": {"parameters": {
                "note": "Look for 192.0.2.123",
                "description": "and bad-param.example",
            }}}},
            "host": {"name": "H2"},
        }
        blob = _alert_to_text_blob(doc)
        assert "H2" in blob
        assert "192.0.2.123" not in blob
        assert "bad-param.example" not in blob
