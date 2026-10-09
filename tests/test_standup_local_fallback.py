"""The ION-local fallback shows what it actually knows.

When Elasticsearch is unreachable the standup falls back to ION's own
AlertTriage table. That path hardcoded ``severity: "(unknown)"`` and
``host: "—"`` for every row, while the row itself carries ``priority``,
``source_system`` and ``observables``.

The result was a deck that said "(unknown)" against every alert at
precisely the moment the SOC had nothing but local state to brief from.
A fallback that discards the data it has is worse than no fallback: it
looks like an answer.

What it genuinely cannot know stays "—". The point is to stop throwing
away what is on the row, not to invent a host.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from ion.web.daily_standup_api import _fallback_alert_row


class _Row:
    """Stand-in for an AlertTriage row."""

    def __init__(self, **kw):
        self.es_alert_id = kw.get("es_alert_id", "abc-123")
        self.rule_name = kw.get("rule_name")
        self.priority = kw.get("priority")
        self.status = kw.get("status", "open")
        self.observables = kw.get("observables")
        self.source_system = kw.get("source_system")
        self.created_at = kw.get("created_at")
        self.analyst_notes = kw.get("analyst_notes")


class TestSeverity:
    def test_it_uses_the_priority_on_the_row(self):
        assert _fallback_alert_row(_Row(priority="critical"))["severity"] \
            == "critical"

    def test_no_priority_is_stated_as_unknown_not_guessed(self):
        """A missing priority is a real gap. Defaulting it to medium
        would put a number on the slide that nobody recorded."""
        assert _fallback_alert_row(_Row())["severity"] == "(unknown)"


class TestHost:
    def test_a_hostname_observable_is_used(self):
        row = _Row(observables=[
            {"type": "ipv4", "value": "10.1.2.3"},
            {"type": "hostname", "value": "FIN-WS-214"},
        ])
        assert _fallback_alert_row(row)["host"] == "FIN-WS-214"

    def test_the_source_system_is_the_next_best_thing(self):
        """Not the host, but it tells a room which estate the alert came
        from, which beats an em-dash."""
        row = _Row(source_system="endpoint")
        assert _fallback_alert_row(row)["host"] == "endpoint"

    def test_a_hostname_beats_the_source_system(self):
        row = _Row(observables=[{"type": "host", "value": "HR-WS-07"}],
                   source_system="endpoint")
        assert _fallback_alert_row(row)["host"] == "HR-WS-07"

    def test_nothing_known_stays_an_em_dash(self):
        assert _fallback_alert_row(_Row())["host"] == "—"

    def test_malformed_observables_do_not_raise(self):
        """Observables are JSON written by several code paths. A deck
        must not 500 because one row holds a string instead of a dict."""
        for bad in ("not-a-list", [None], ["plain"], [{"no": "type"}], {}):
            assert _fallback_alert_row(_Row(observables=bad))["host"] \
                == "—"


class TestTheRuleName:
    def test_the_snapshot_is_used_when_present(self):
        row = _Row(rule_name="Suspicious PowerShell Execution")
        assert _fallback_alert_row(row)["rule_name"] == \
            "Suspicious PowerShell Execution"

    def test_the_raw_alert_id_is_never_shown_as_a_name(self):
        """An opaque ES uuid on a meeting screen tells nobody
        anything."""
        row = _Row(es_alert_id="8f2c1d44-0b19-4f0e-9a77-2c5f7e1a9b33")
        out = _fallback_alert_row(row)
        assert row.es_alert_id not in out["rule_name"]
        assert row.es_alert_id not in out["title"]

    def test_analyst_notes_are_not_promoted_to_a_rule_name(self):
        """Notes are somebody's prose about the alert, not the name of
        the detection that fired. Showing them in a Rule column would
        misattribute an analyst's words to the ruleset."""
        row = _Row(analyst_notes="looks like a false positive to me")
        assert _fallback_alert_row(row)["rule_name"] == "(rule unknown)"


class TestTheShape:
    def test_every_key_the_deck_reads_is_present(self):
        out = _fallback_alert_row(_Row())
        for key in ("id", "title", "severity", "status", "host",
                    "timestamp", "rule_name"):
            assert key in out, key
