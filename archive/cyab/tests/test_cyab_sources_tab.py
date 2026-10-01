"""Integration tests for the Sources tab — data sources + demarcation + SAL + field mapping.

The plan literal references ``admin_session`` + ``system_with_source``
fixtures. We use the project-wide ``client`` + ``make_system`` from
``conftest.py`` and create the data source inline (the conftest
``client`` fixture already injects an admin user via dependency
overrides, so no login is needed).
"""

import pytest


def _attach_source(temp_db, system_id: int, **fields) -> int:
    from sqlalchemy.orm import sessionmaker
    from ion.models.cyab import CyabDataSource
    Session = sessionmaker(bind=temp_db)
    s = Session()
    fields.setdefault("name", "winlog")
    fields.setdefault("data_source_type", "windows-evtx")
    src = CyabDataSource(system_id=system_id, **fields)
    s.add(src)
    s.commit()
    src_id = src.id
    s.close()
    return src_id


def test_sources_tab_lists_data_sources(client, make_system, temp_db):
    sys_id = make_system(name="prod-src-test")
    _attach_source(temp_db, sys_id)
    r = client.get(f"/cyab/systems/{sys_id}/tab/sources")
    assert r.status_code == 200
    assert "winlog" in r.text


def test_sources_tab_includes_demarcation_block(client, make_system, temp_db):
    sys_id = make_system(name="prod-src-demarc")
    _attach_source(temp_db, sys_id)
    r = client.get(f"/cyab/systems/{sys_id}/tab/sources")
    body = r.text.lower()
    assert "system source" in body
    assert "siem" in body or "data lake" in body


def test_sources_tab_includes_sal_section(client, make_system, temp_db):
    sys_id = make_system(name="prod-src-sal")
    _attach_source(temp_db, sys_id)
    r = client.get(f"/cyab/systems/{sys_id}/tab/sources")
    body = r.text
    for tier in ("SAL-1", "SAL-2", "SAL-3"):
        assert tier in body


def test_sources_tab_includes_field_mapping_editor(client, make_system, temp_db):
    sys_id = make_system(name="prod-src-fm")
    _attach_source(temp_db, sys_id)
    r = client.get(f"/cyab/systems/{sys_id}/tab/sources")
    assert "field-mapping" in r.text or "Field mapping" in r.text


def test_sources_tab_empty_state_when_no_sources(client, make_system):
    sys_id = make_system(name="prod-src-empty")
    r = client.get(f"/cyab/systems/{sys_id}/tab/sources")
    assert r.status_code == 200
    assert "No data sources" in r.text or "no data sources" in r.text.lower()
