"""ATT&CK v20.1 catalogue: detection strategies, analytics, and revocations.

The contract these pin:

* the bundled snapshots load, and say so when they do not -- an unreadable
  snapshot must not look like "MITRE wrote no detection for this";
* a retired technique id resolves forward, because ION compares two sets of
  technique ids in several places and a miss there reads as "no coverage";
* a compliance control mapped to retired ids still scores when TIDE reports
  the modern ones.
"""

from __future__ import annotations

import pytest

from ion.services import attack_detection_service as ads
from ion.services import attack_revocation_service as ars
from ion.services import compliance_mapping_service as cms
from ion.services.mitre_navigator_service import generate_navigator_layer

# --------------------------------------------------------------------------
# Detection strategies / analytics snapshot
# --------------------------------------------------------------------------

def test_detection_snapshot_loads_at_v20():
    status = ads.snapshot_status()
    assert status["loaded"] is True
    assert status["error"] is None
    assert status["attack_version"] == "20.1"


def test_snapshot_carries_strategies_and_analytics():
    counts = ads.snapshot_status()["counts"]
    # v18 replaced the per-technique detection text with these two objects;
    # a snapshot without them is a pre-v18 build.
    assert counts["strategies"] > 600
    assert counts["analytics"] > 1500
    assert counts["techniques_with_detection"] > 600


def test_every_strategy_names_a_technique_and_an_analytic():
    for strategy in ads._load()["strategies"]:
        assert strategy["technique_ids"], f"{strategy['id']} detects nothing"
        assert strategy["analytics"], f"{strategy['id']} holds no analytic"


def test_analytics_carry_platform_and_log_sources():
    analytics = ads.analytics_for_technique("T1055")
    assert analytics, "T1055 should have analytics in v20.1"
    first = analytics[0]
    assert first["id"].startswith("AN")
    assert first["strategy_id"].startswith("DET")
    assert first["platforms"]


def test_log_sources_for_technique_dedupes_and_names_the_analytics():
    sources = ads.log_sources_for_technique("T1055")
    assert sources
    keys = [(s["name"], s["channel"]) for s in sources]
    assert len(keys) == len(set(keys)), "log sources should be deduped"
    assert all(s["analytic_ids"] for s in sources)


def test_no_parent_fallback_for_subtechniques():
    """A sub-technique must not inherit its parent's analytics.

    Claiming the parent's detection against a sub-technique overstates
    coverage MITRE did not write.
    """
    parent = {s["id"] for s in ads.strategies_for_technique("T1055")}
    child = {s["id"] for s in ads.strategies_for_technique("T1055.001")}
    assert parent and child
    assert parent != child


def test_unknown_technique_returns_empty_not_error():
    assert ads.strategies_for_technique("T9999") == []
    assert ads.analytics_for_technique("") == []


def test_missing_snapshot_reports_unloaded(monkeypatch, tmp_path):
    """The failure that must never look like an empty result."""
    ads.reset_cache()
    monkeypatch.setattr(ads, "_SNAPSHOT_PATH", tmp_path / "absent.json")
    try:
        status = ads.snapshot_status()
        assert status["loaded"] is False
        assert status["error"]
        assert ads.attack_version() is None
    finally:
        ads.reset_cache()


# --------------------------------------------------------------------------
# Revocations
# --------------------------------------------------------------------------

def test_revocation_map_loads():
    status = ars.status()
    assert status["loaded"] is True
    assert status["count"] > 100


@pytest.mark.parametrize("old,new", [
    ("T1562.002", "T1685.001"),   # Disable Windows Event Logging
    ("T1562.004", "T1686"),       # Disable or Modify System Firewall
    ("T1562.009", "T1688"),       # Safe Mode Boot
    ("T1562.010", "T1689"),       # Downgrade Attack
    ("T1070.001", "T1685.005"),   # Clear Windows Event Logs
    ("T1070.002", "T1685.006"),   # Clear Linux or Mac System Logs
    ("T1574.002", "T1574.001"),   # DLL Side-Loading -> DLL
    ("T1656", "T1684.001"),       # Impersonation
])
def test_retired_ids_resolve_forward(old, new):
    assert ars.resolve(old) == new
    assert ars.is_revoked(old) is True


def test_impair_defenses_tree_moved():
    """T1562 is the id most likely to be written down somewhere in ION."""
    assert ars.resolve("T1562") == "T1685"
    assert ars.replacement_name("T1562")


def test_current_and_unknown_ids_pass_through():
    assert ars.resolve("T1055") == "T1055"
    assert ars.resolve("T9999") == "T9999"
    assert ars.is_revoked("T1055") is False


def test_resolve_is_case_insensitive_and_trims():
    assert ars.resolve("  t1562.002  ") == "T1685.001"


def test_resolve_all_dedupes_to_the_same_target():
    # Three retired ids that all land on T1685.
    assert ars.resolve_all(["T1562", "T1562.001", "T1562.006"]) == {"T1685"}


def test_resolve_never_returns_none_for_falsy_input():
    assert ars.resolve("") == ""


def test_resolution_is_idempotent():
    """Resolving an already-resolved id must not move it again."""
    for old in ("T1562", "T1562.002", "T1070.001"):
        once = ars.resolve(old)
        assert ars.resolve(once) == once


# --------------------------------------------------------------------------
# Consumers
# --------------------------------------------------------------------------

def test_navigator_layer_declares_the_snapshot_version():
    """The exported layer used to claim ATT&CK v14 regardless of the data."""
    layer = generate_navigator_layer(tide_service=None)
    assert layer["versions"]["attack"] == "20"


def test_compliance_scores_a_control_mapped_to_retired_ids():
    """AU-12 maps to T1070.001/.002 and T1562.002, all retired at v18/v19.

    TIDE reporting the modern replacements must still satisfy it; before the
    revocation map the intersection missed and the control read as a gap.
    """
    framework = cms.get_framework("nist_800_53")
    au12 = next(c for c in framework["controls"] if c["id"] == "AU-12")
    assert set(au12["techniques"]) >= {"T1070.001", "T1070.002", "T1562.002"}

    covered = {"T1070", "T1685.005", "T1685.006", "T1685.001"}
    scored = cms._score_framework(framework, covered)
    au12_scored = next(
        c for c in scored["controls"] if c["control_id"] == "AU-12"
    )
    assert au12_scored["gap_techniques"] == []
    assert au12_scored["score"] == 100
    assert au12_scored["state"] == "covered"


def test_compliance_still_reports_a_genuine_gap():
    """The resolver must not turn every control green."""
    framework = cms.get_framework("nist_800_53")
    scored = cms._score_framework(framework, set())
    au12 = next(c for c in scored["controls"] if c["control_id"] == "AU-12")
    assert au12["gap_techniques"]
    assert au12["state"] == "blind"
