"""The prefilled case title is deterministic, and the description is full.

Runs static/js/case-draft.js under node. The title used to be the lead
alert's rule name, so the same alerts got a different title depending on
which one sorted first.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "src/ion/web/static/js/case-draft.js"
NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="node is not installed")


def draft(alerts):
    js = f"const d=require({json.dumps(str(SCRIPT))});console.log(JSON.stringify(d.build({json.dumps(alerts)})))"
    out = subprocess.run([NODE, "-e", js], capture_output=True, text=True, encoding="utf-8", check=True)
    return json.loads(out.stdout)


def _burst():
    rules = ["Rule A", "Rule B", "Rule C", "Rule D"]
    return [{
        "id": f"a{i}", "host": "WS-01", "user": "j.doe", "severity": "high" if i % 3 else "critical",
        "rule_name": rules[i % 4], "timestamp": f"2026-11-19T10:{i // 2:02d}:{(i % 2) * 30:02d}Z",
        "source_ip": "10.0.0.5", "process_name": "powershell.exe",
    } for i in range(30)]


def test_title_is_volume_and_host_not_the_latest_rule():
    alerts = _burst()
    assert draft(alerts)["title"] == "Investigation: 30 alerts on WS-01"
    assert draft(list(reversed(alerts)))["title"] == "Investigation: 30 alerts on WS-01"


def test_titles_for_many_hosts_no_host_and_one_alert():
    assert draft([{"host": "a"}, {"host": "b"}])["title"] == "Investigation: 2 alerts across 2 hosts"
    assert draft([{"user": "j.doe"}])["title"] == "Investigation: 1 alert for j.doe"
    assert draft([{}, {}])["title"] == "Investigation: 2 alerts"


def test_description_has_the_window_entities_rules_and_key_fields():
    d = draft(_burst())
    desc = d["description"]
    assert "First alert: 2026-11-19 10:00:00 UTC" in desc
    assert "Last alert: 2026-11-19 10:14:30 UTC (span 14m 30s)" in desc
    assert "Affected hosts (1): WS-01" in desc
    assert "Affected users (1): j.doe" in desc
    assert "Rules (4): Rule A ×8, Rule B ×8, Rule C ×7, Rule D ×7" in desc
    assert "Source IPs: 10.0.0.5" in desc and "Processes: powershell.exe" in desc
    assert d["severity"] == "critical"


def test_highlighted_fields_come_from_the_rule():
    raw = {"kibana.alert.rule.parameters": {"investigation_fields": {"field_names": ["dns.question.name"]}},
           "dns": {"question": {"name": "evil.example"}}}
    desc = draft([{"raw_data": raw}])["description"]
    assert "Highlighted fields:\n  dns.question.name: evil.example" in desc
