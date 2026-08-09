"""Manually-created cases trigger Bob too (not just auto-grouped cases)."""
from ion.web.case_lifecycle_api import _should_investigate_new_case


def test_manual_case_with_alerts_triggers_bob():
    assert _should_investigate_new_case(False, ["a1"], True) is True
    assert _should_investigate_new_case(False, ["a1", "a2"], True) is True


def test_skips_when_auto_closed_fp():
    assert _should_investigate_new_case(True, ["a1"], True) is False


def test_skips_when_no_alerts():
    assert _should_investigate_new_case(False, [], True) is False
    assert _should_investigate_new_case(False, None, True) is False


def test_skips_when_auto_investigate_disabled():
    assert _should_investigate_new_case(False, ["a1"], False) is False
