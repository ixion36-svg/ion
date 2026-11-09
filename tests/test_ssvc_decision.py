"""SSVC deployer decisions over the bundled CERT/CC table.

Two things this pins. The table is a transcription, so it has to be complete
and match the published tree at the corners. And the decision has to carry
which of its four inputs were evidence and which were defaults, because three
of them are properties of a deployment ION cannot observe.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from ion.services import ssvc_service as ssvc


def _vuln(**kw):
    base = {"exploit_available": False, "exploit_in_the_wild": False}
    base.update(kw)
    return SimpleNamespace(**base)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for env in ("ION_SSVC_EXPOSURE", "ION_SSVC_AUTOMATABLE",
                "ION_SSVC_HUMAN_IMPACT"):
        monkeypatch.delenv(env, raising=False)
    ssvc.reset_cache()
    yield
    ssvc.reset_cache()


# --------------------------------------------------------------------------
# The table itself
# --------------------------------------------------------------------------

def test_the_table_loads_and_is_complete():
    s = ssvc.status()
    assert s["loaded"] is True
    assert s["error"] is None
    # 3 exploitation x 3 exposure x 2 automatable x 4 human impact.
    assert s["rows"] == 72


def test_the_four_outcomes_are_the_published_ones():
    assert ssvc.status()["outcomes"] == [
        "defer", "immediate", "out-of-cycle", "scheduled",
    ]


def test_decision_points_match_the_published_vocabulary():
    points = ssvc.decision_points()
    assert points["exploitation"] == ["active", "none", "public poc"]
    assert points["exposure"] == ["controlled", "open", "small"]
    assert points["automatable"] == ["no", "yes"]
    assert points["human_impact"] == ["high", "low", "medium", "very high"]


@pytest.mark.parametrize("inputs,expected", [
    # The corners of the published tree, transcribed from CERT/CC's CSV.
    (("active", "open", "yes", "very high"), "immediate"),
    (("none", "small", "no", "low"), "defer"),
    (("active", "controlled", "no", "medium"), "scheduled"),
])
def test_known_rows_decide_as_published(inputs, expected):
    assert ssvc.decide(*inputs) == expected


def test_every_combination_has_a_row():
    """A hole in the tree decides nothing, and reads the same as a decision."""
    points = ssvc.decision_points()
    for e in points["exploitation"]:
        for x in points["exposure"]:
            for a in points["automatable"]:
                for h in points["human_impact"]:
                    assert ssvc.decide(e, x, a, h), f"no row for {e}/{x}/{a}/{h}"


def test_an_unknown_combination_returns_none_not_a_default():
    assert ssvc.decide("active", "open", "yes", "catastrophic") is None


def test_lookup_is_case_and_space_insensitive():
    assert ssvc.decide(" ACTIVE ", "Open", "YES", "Very High") == "immediate"


# --------------------------------------------------------------------------
# Exploitation, the one input derived from evidence
# --------------------------------------------------------------------------

def test_kev_outranks_the_local_flags():
    """KEV is a confirmed observation; the flag is whatever someone ticked."""
    got = ssvc.exploitation_for(_vuln(exploit_available=True),
                                kev_entry=object())
    assert got["value"] == ssvc.EXPLOIT_ACTIVE
    assert "KEV" in got["basis"]


def test_in_the_wild_without_kev_is_still_active():
    got = ssvc.exploitation_for(_vuln(exploit_in_the_wild=True))
    assert got["value"] == ssvc.EXPLOIT_ACTIVE


def test_a_public_exploit_is_poc_not_active():
    got = ssvc.exploitation_for(_vuln(exploit_available=True))
    assert got["value"] == ssvc.EXPLOIT_POC


def test_none_reports_the_age_of_the_catalogue_it_is_relative_to():
    """"Not in KEV" is only true against a particular snapshot."""
    got = ssvc.exploitation_for(_vuln(), kev_age_days=42)
    assert got["value"] == ssvc.EXPLOIT_NONE
    assert "42 days old" in got["basis"]


# --------------------------------------------------------------------------
# Assumptions must never read as measurements
# --------------------------------------------------------------------------

def test_unset_inputs_are_reported_as_assumed():
    result = ssvc.assess(_vuln())
    assert result["decision"]
    assert result["assumed_count"] == 3
    assert set(result["unset_env"]) == {
        "ION_SSVC_EXPOSURE", "ION_SSVC_AUTOMATABLE", "ION_SSVC_HUMAN_IMPACT",
    }
    assert all(not a["configured"] for a in result["assumed"].values())


def test_a_configured_input_is_not_reported_as_assumed(monkeypatch):
    monkeypatch.setenv("ION_SSVC_EXPOSURE", "open")
    result = ssvc.assess(_vuln())
    assert result["assumed"]["exposure"]["configured"] is True
    assert result["assumed"]["exposure"]["value"] == "open"
    assert result["assumed_count"] == 2


def test_an_illegal_env_value_falls_back_rather_than_missing_the_table(monkeypatch):
    """A value the table does not know would make every lookup return None."""
    monkeypatch.setenv("ION_SSVC_EXPOSURE", "enormous")
    result = ssvc.assess(_vuln())
    assert result["assumed"]["exposure"]["value"] == "controlled"
    assert result["assumed"]["exposure"]["configured"] is False
    assert result["decision"] is not None


def test_kev_listed_vulnerability_escalates_the_decision(monkeypatch):
    """The point of the feature: evidence of exploitation moves the answer."""
    monkeypatch.setenv("ION_SSVC_EXPOSURE", "open")
    monkeypatch.setenv("ION_SSVC_AUTOMATABLE", "yes")
    monkeypatch.setenv("ION_SSVC_HUMAN_IMPACT", "very high")

    quiet = ssvc.assess(_vuln())
    exploited = ssvc.assess(_vuln(), kev_entry=object())

    assert exploited["decision"] == "immediate"
    assert quiet["decision"] != exploited["decision"]


def test_an_unreadable_table_declines_rather_than_defers(monkeypatch, tmp_path):
    """`defer` is an instruction. A failed read must not produce one."""
    ssvc.reset_cache()
    monkeypatch.setattr(ssvc, "_TABLE_PATH", tmp_path / "absent.json")
    try:
        result = ssvc.assess(_vuln())
        assert result["decision"] is None
        assert "could not be read" in result["reason"]
        assert ssvc.status()["loaded"] is False
    finally:
        ssvc.reset_cache()
