"""The ATT&CK guidance drill-down on Detection Health.

The panel has to keep four answers apart, because collapsing any two of them
tells an engineer something untrue about a rule:

  * the snapshot did not load,
  * the rule's alerts carry no technique,
  * the techniques are there but the snapshot has no strategy for them,
  * guidance follows.

Only the last is a statement about MITRE's coverage, and only the second is a
finding about the rule's own mapping.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ion.models.alert_triage import AlertTriage
from ion.services.detection_health_service import get_rule_attack_guidance
from ion.web.ui.detection_health import attack_panel, attack_url

_LOADED = {"loaded": True, "attack_version": "20.1"}
_ROOT = Path(__file__).resolve().parent.parent
_FRAGMENT = (_ROOT / "src" / "ion" / "web" / "templates" / "_fragments"
             / "detection_health_attack.html")
_PAGE_CSS = _ROOT / "frontend" / "ion-pages.css"


# --------------------------------------------------------------------------
# URL building
# --------------------------------------------------------------------------

def test_attack_url_percent_encodes_a_free_text_rule_name():
    """Rule names come out of AlertTriage, so they are arbitrary text."""
    url = attack_url("Defender Tampering & Co", 30)
    assert url == (
        "/ui/detection-health/attack?rule=Defender+Tampering+%26+Co&days=30"
    )


def test_attack_url_handles_the_unmapped_bucket_and_a_missing_window():
    assert "rule=%28unmapped%29" in attack_url("(unmapped)", None)
    assert "days=" not in attack_url("(unmapped)", None)
    assert "rule=" in attack_url(None, 90)


# --------------------------------------------------------------------------
# Panel states
# --------------------------------------------------------------------------

def test_unreadable_snapshot_is_not_an_absence_of_guidance():
    panel = attack_panel({"snapshot": {"loaded": False}, "rule_name": "r"})
    assert panel["state"] == "unloaded"


def test_no_technique_on_the_alerts_is_its_own_state():
    panel = attack_panel({
        "snapshot": _LOADED, "techniques": [],
        "techniques_without_guidance": [],
    })
    assert panel["state"] == "untagged"


def test_techniques_with_no_strategy_is_distinct_from_untagged():
    panel = attack_panel({
        "snapshot": _LOADED, "techniques": [],
        "techniques_without_guidance": ["T1099"],
    })
    assert panel["state"] == "unmatched"
    assert panel["without_guidance"] == ["T1099"]


def test_ok_state_totals_the_analytics():
    panel = attack_panel({
        "snapshot": _LOADED,
        "techniques": [
            {"technique_id": "T1685", "analytic_count": 7, "strategies": []},
            {"technique_id": "T1055", "analytic_count": 3, "strategies": []},
        ],
        "techniques_without_guidance": [],
    })
    assert panel["state"] == "ok"
    assert panel["analytic_total"] == 10
    assert panel["attack_version"] == "20.1"


def test_a_missing_analytic_count_does_not_crash_the_total():
    """The count is summed for a header, and a header must not 500."""
    panel = attack_panel({
        "snapshot": _LOADED,
        "techniques": [{"technique_id": "T1685"}],
        "techniques_without_guidance": [],
    })
    assert panel["analytic_total"] == 0


# --------------------------------------------------------------------------
# The service behind it
# --------------------------------------------------------------------------

def _alert(session, alert_id, rule_name, techniques, days_ago=1):
    created = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(
        days=days_ago)
    session.add(AlertTriage(
        es_alert_id=alert_id, rule_name=rule_name,
        mitre_techniques=techniques, created_at=created, updated_at=created,
    ))
    session.commit()


def test_retired_ids_on_an_alert_still_find_guidance(session):
    """The regression this panel exists to avoid.

    An alert triaged before a catalogue bump carries the id of its day.
    Looked up unresolved, T1562.001 finds nothing and the panel would say
    MITRE publishes no detection for it.
    """
    _alert(session, "a1", "Defender Tampering", ["T1562.001"])

    payload = get_rule_attack_guidance(session, "Defender Tampering", days=90)

    assert payload["techniques"], "retired id found no guidance"
    tech = payload["techniques"][0]
    assert tech["technique_id"] == "T1685"
    assert tech["retired_from"] == ["T1562.001"]
    assert tech["analytic_count"] > 0


def test_current_ids_are_not_marked_retired(session):
    _alert(session, "a2", "Injection Rule", ["T1055"])

    payload = get_rule_attack_guidance(session, "Injection Rule", days=90)

    tech = payload["techniques"][0]
    assert tech["technique_id"] == "T1055"
    assert tech["retired_from"] == []


def test_log_sources_are_collected_once_per_rule(session):
    _alert(session, "a3", "Telemetry Rule", ["T1055"])

    payload = get_rule_attack_guidance(session, "Telemetry Rule", days=90)

    sources = payload["log_sources"]
    assert sources
    keys = [(s["name"], s["channel"]) for s in sources]
    assert len(keys) == len(set(keys)), "log sources should be deduped"
    assert all(s["technique_ids"] for s in sources)


def test_a_rule_with_no_alerts_reports_untagged_not_a_failure(session):
    payload = get_rule_attack_guidance(session, "Rule With No Alerts", days=90)

    assert payload["alerts_seen"] == 0
    assert payload["techniques"] == []
    assert attack_panel(payload)["state"] == "untagged"


def test_alerts_outside_the_window_are_not_counted(session):
    _alert(session, "a4", "Old Rule", ["T1055"], days_ago=200)

    payload = get_rule_attack_guidance(session, "Old Rule", days=30)

    assert payload["alerts_seen"] == 0


def test_the_unmapped_bucket_selects_rows_with_no_rule_name(session):
    """"(unmapped)" is the label the table shows for a NULL rule_name."""
    _alert(session, "a5", None, ["T1055"])

    payload = get_rule_attack_guidance(session, "(unmapped)", days=90)

    assert payload["alerts_seen"] == 1
    assert payload["techniques"][0]["technique_id"] == "T1055"


# --------------------------------------------------------------------------
# UI contract
# --------------------------------------------------------------------------

def test_every_dha_class_the_fragment_uses_has_a_rule():
    """A class the page sheet does not carry is a silent no-op.

    There is no error and no visual clue -- the element simply renders
    unstyled, which is how `border-l-2` (absent from the trimmed build) got
    into this panel in the first place.
    """
    used = set(re.findall(r"\bdha-[a-z-]+", _FRAGMENT.read_text(encoding="utf-8")))
    assert used, "fragment should carry semantic dha- classes"
    css = _PAGE_CSS.read_text(encoding="utf-8")
    missing = {c for c in used if f".{c}" not in css}
    assert not missing, f"no rule in ion-pages.css for: {sorted(missing)}"


def test_the_fragment_carries_no_inline_style_block():
    """The `styled` column in docs/UI_REDESIGN.md, for this fragment."""
    text = _FRAGMENT.read_text(encoding="utf-8")
    assert "<style" not in text
    assert "style=" not in text


def test_the_panel_rules_are_page_scoped():
    """Page sheets scope to body[data-page=...] so they cannot leak."""
    css = _PAGE_CSS.read_text(encoding="utf-8")
    for line in css.splitlines():
        if ".dha-" in line and line.strip().startswith("body"):
            assert 'body[data-page="detection_health"]' in line
