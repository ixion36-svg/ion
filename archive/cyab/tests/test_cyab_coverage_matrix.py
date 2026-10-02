"""Integration tests for the fleet coverage matrix backend + page.

Uses the project-wide ``client`` + ``temp_db`` fixtures from
``tests/integration/conftest.py`` (which already inject an admin user via
dependency overrides — no login required). The matrix endpoint resolves
its DB session through a dynamic import inside the function, so the
conftest's monkeypatch of ``ion.storage.database.get_engine`` is honoured
regardless of test ordering across the suite.
"""

import pytest


@pytest.fixture
def three_systems(temp_db):
    """Three systems with mixed health states.

    The CyAB convention (matching ``/api/cyab/systems`` and the systems
    list page) is that ``soc_analyst_owner`` is the system owner field.
    The matrix endpoint exposes it as ``owner`` on the wire.
    ``business_unit`` doubles as the pillar proxy.
    """
    from sqlalchemy.orm import sessionmaker
    from ion.models.cyab import CyabDataSource, CyabSystem
    Session = sessionmaker(bind=temp_db)
    s = Session()
    sys_healthy = CyabSystem(
        name="prod-healthy", department="Identity",
        soc_analyst_owner="alice", status="ACTIVE",
        sign_dept_name="d", sign_soc_name="s",
    )
    sys_amber = CyabSystem(
        name="prod-amber", department="Endpoint",
        soc_analyst_owner="bob",
    )
    sys_red = CyabSystem(
        name="prod-red", department="Cloud",
        soc_analyst_owner="alice",
    )
    s.add_all([sys_healthy, sys_amber, sys_red])
    s.flush()
    s.add(CyabDataSource(
        system_id=sys_healthy.id, name="winlog",
        data_source_type="windows-evtx",
        field_mapping='{"@timestamp": "ts", "host.name": "h", '
                      '"event.code": "ec", "user.name": "u"}',
    ))
    s.commit()
    ids = {"healthy": sys_healthy.id, "amber": sys_amber.id, "red": sys_red.id}
    s.close()
    yield ids


def test_matrix_endpoint_returns_one_row_per_system(client, three_systems):
    r = client.get("/api/cyab/coverage/matrix")
    assert r.status_code == 200
    data = r.json()
    assert "rows" in data and len(data["rows"]) == 3
    assert "aggregates" in data
    assert "dimensions" in data


def test_matrix_row_has_seven_dimension_cells(client, three_systems):
    r = client.get("/api/cyab/coverage/matrix")
    data = r.json()
    expected_dimensions = {
        "ingestion_fresh", "fields_mapped", "intake_done",
        "detections_shipped", "audit_shipped", "checklist_done",
        "signed_off",
    }
    for row in data["rows"]:
        assert set(row["cells"].keys()) == expected_dimensions
        for dim, cell in row["cells"].items():
            assert cell["status"] in ("green", "amber", "red", "unknown")


def test_matrix_aggregates_strip(client, three_systems):
    r = client.get("/api/cyab/coverage/matrix")
    data = r.json()
    agg = data["aggregates"]
    assert "pct_systems_healthy" in agg
    assert "pct_critical_missing" in agg
    assert "pct_stale_ingestion" in agg
    for v in agg.values():
        assert 0 <= v <= 100


def test_matrix_filter_by_owner(client, three_systems):
    r = client.get("/api/cyab/coverage/matrix?owner=alice")
    data = r.json()
    assert len(data["rows"]) == 2  # prod-healthy and prod-red
    for row in data["rows"]:
        assert row["owner"] == "alice"


def test_matrix_filter_any_red(client, three_systems):
    r = client.get("/api/cyab/coverage/matrix?any_red=1")
    data = r.json()
    # Only systems with at least one red cell should appear
    for row in data["rows"]:
        assert any(c["status"] == "red" for c in row["cells"].values())


# ----------------------------------------------------------------------
# Task 9 — /cyab/coverage page (matrix UI + filters + deep-link cells)
# ----------------------------------------------------------------------


def test_coverage_page_renders(client, three_systems):
    r = client.get("/cyab/coverage")
    assert r.status_code == 200
    body = r.text
    for sys_name in ("prod-healthy", "prod-amber", "prod-red"):
        assert sys_name in body


def test_coverage_page_shows_aggregate_strip(client, three_systems):
    r = client.get("/cyab/coverage")
    body = r.text.lower()
    assert "% systems healthy" in body or "systems healthy" in body
    assert "critical-missing" in body or "critical missing" in body
    assert "stale-ingestion" in body or "stale ingestion" in body


def test_coverage_page_cells_link_to_per_system_tabs(client, three_systems):
    r = client.get("/cyab/coverage")
    body = r.text
    sid = three_systems["healthy"]
    # Each row's cells deep-link into the relevant tab on the per-system page
    assert f"/cyab/systems/{sid}/" in body or f"/cyab/systems/{sid}#" in body


def test_coverage_filter_form_present(client, three_systems):
    r = client.get("/cyab/coverage")
    body = r.text
    assert 'name="owner"' in body
    assert 'name="pillar"' in body
    assert 'name="any_red"' in body
