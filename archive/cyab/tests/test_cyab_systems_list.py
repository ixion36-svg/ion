"""Integration tests for the /cyab/systems portfolio list."""

import pytest


@pytest.fixture
def diverse_systems(temp_db):
    """4 systems across pillars / statuses / owners for filter testing."""
    from sqlalchemy.orm import sessionmaker
    from ion.models.cyab import CyabSystem
    Session = sessionmaker(bind=temp_db)
    s = Session()
    rows = [
        CyabSystem(name="prod-sso",  department="Identity", soc_analyst_owner="alice", status="ACTIVE"),
        CyabSystem(name="prod-dns",  department="Network",  soc_analyst_owner="bob",   status="DRAFT"),
        CyabSystem(name="prod-edr",  department="Endpoint", soc_analyst_owner="alice", status="ACTIVE"),
        CyabSystem(name="dev-test",  department="Eng",      soc_analyst_owner="carol", status="DRAFT"),
    ]
    s.add_all(rows)
    s.commit()
    ids = [r.id for r in rows]
    s.close()
    yield ids


def test_systems_list_renders_table(client, diverse_systems):
    r = client.get("/cyab/systems")
    assert r.status_code == 200
    body = r.text
    for col in ("Name", "Pillar", "Sub-profile", "Owner", "Progress", "Last edited", "Status"):
        assert col in body
    # The page shell loads the table via HTMX (hx-trigger=load), but we
    # also want the table partial reachable directly. Probe it too so the
    # rows are actually present.
    r2 = client.get("/cyab/systems/_table")
    body2 = r2.text
    for n in ("prod-sso", "prod-dns", "prod-edr", "dev-test"):
        assert n in body2


def test_systems_list_includes_section_nav(client):
    r = client.get("/cyab/systems")
    assert "cyab-section-nav" in r.text


def test_systems_list_search_filters_by_name(client, diverse_systems):
    r = client.get("/cyab/systems/_table?q=sso")
    body = r.text
    assert "prod-sso" in body
    assert "prod-dns" not in body
    # No full page chrome — partial only
    assert "<html" not in body


def test_systems_list_filter_by_owner(client, diverse_systems):
    r = client.get("/cyab/systems/_table?owner=alice")
    body = r.text
    assert "prod-sso" in body and "prod-edr" in body
    assert "prod-dns" not in body


def test_systems_list_filter_by_status(client, diverse_systems):
    r = client.get("/cyab/systems/_table?status=DRAFT")
    body = r.text
    assert "prod-dns" in body and "dev-test" in body
    assert "prod-sso" not in body


def test_systems_list_export_csv(client, diverse_systems):
    r = client.post("/api/cyab/systems/bulk",
                    json={"action": "export-csv",
                          "system_ids": diverse_systems[:2]})
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert "prod-sso" in r.text


def test_systems_list_bulk_mark_reviewed(client, diverse_systems):
    r = client.post("/api/cyab/systems/bulk",
                    json={"action": "mark-reviewed",
                          "system_ids": diverse_systems[:2]})
    assert r.status_code == 200
    body = r.json()
    assert body["affected"] == 2
