"""Integration tests for the Data Health tab + API endpoint.

Plan literal references inline ``admin_session`` + ``system_id`` fixtures.
Per task adjustments we use the project-wide ``client`` + ``make_system``
from ``conftest.py`` (the conftest ``client`` fixture already injects an
admin user via dependency overrides, so no login is needed).
"""

import pytest


def test_data_health_api_returns_three_panels(client, make_system):
    sys_id = make_system(name="dh-test")
    r = client.get(f"/api/cyab/systems/{sys_id}/data-health")
    assert r.status_code == 200
    data = r.json()
    assert "ingestion_freshness" in data
    assert "field_mapping_completeness" in data
    assert "coverage_rollup" in data
    assert data.get("reconciliation", {}).get("available") is False


def test_data_health_tab_renders_three_panels(client, make_system):
    sys_id = make_system(name="dh-tab-test")
    r = client.get(f"/cyab/systems/{sys_id}/tab/data-health")
    assert r.status_code == 200
    body = r.text.lower()
    assert "ingestion" in body
    assert "field mapping" in body
    assert "coverage" in body
    assert "reconciliation" in body  # phase-2 stub also visible (greyed)
