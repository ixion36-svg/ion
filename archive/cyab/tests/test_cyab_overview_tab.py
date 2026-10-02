"""Integration tests for the Overview tab (checklist view)."""

import pytest


def test_overview_tab_shows_critical_first(client, make_system):
    sys_id = make_system(name="ov-crit-test")
    r = client.get(f"/cyab/systems/{sys_id}/tab/overview")
    assert r.status_code == 200
    body = r.text.lower()
    # Critical items HLD, NETWORK_TOPOLOGY, OWNERS appear before non-critical
    crit_pos = body.find("critical")
    design_pos = body.find("design")
    assert crit_pos != -1 and crit_pos < design_pos


def test_overview_tab_groups_by_category(client, make_system):
    sys_id = make_system(name="ov-group-test")
    r = client.get(f"/cyab/systems/{sys_id}/tab/overview")
    body = r.text
    for cat in ("Critical", "Design", "Operational", "Security", "Compliance"):
        assert cat in body


def test_overview_lists_default_checklist_items(client, make_system):
    sys_id = make_system(name="ov-items-test")
    r = client.get(f"/cyab/systems/{sys_id}/tab/overview")
    body = r.text
    for label in ("HLD", "LLD", "Network Topology", "Owners", "Runbook"):
        assert label in body
