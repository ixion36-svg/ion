"""Regression tests for the v0.39.x PCAP/observable fixes:

  1. Arkime auto-case now pushes the case to Kibana AND attaches the source
     alert (previously the alert was never linked to the Kibana case on
     auto-create; only the close path updated the alert).
  3a. IOC text extraction no longer mis-extracts dotted ECS field NAMES
     (host.name, event.dataset, kibana.alert.rule.name) as domain observables —
     via values-only blob construction AND a field-name guard in the extractor.
  3b. Observable gains an `is_ignored` flag with a search filter; ignored
     observables are excluded from the search results by default.
"""

import types


# ---------------------------------------------------------------------------
# 3a. Extractor: field names are not domains; real domains still extracted
# ---------------------------------------------------------------------------
def test_field_name_guard():
    from ion.services.ioc_text_extractor import _looks_like_field_name

    # ECS field paths (every segment is a field token) -> rejected
    for fn in ("host.name", "event.dataset", "kibana.alert.rule.name",
               "source.ip", "user.name", "url.domain"):
        assert _looks_like_field_name(fn), fn
    # Real domains (at least one non-field label) -> kept
    for dom in ("microsoft.com", "host.io", "evil-c2.net", "mail.google.com"):
        assert not _looks_like_field_name(dom), dom


def test_extract_iocs_skips_field_names():
    from ion.services.ioc_text_extractor import extract_iocs

    # Text containing both field names and a real domain
    text = "host.name event.dataset kibana.alert.rule.name evil-c2.net"
    domains = extract_iocs(text).get("domains", [])
    assert "evil-c2.net" in domains
    for fn in ("host.name", "event.dataset", "kibana.alert.rule.name"):
        assert fn not in domains


def test_alert_to_text_blob_is_values_only():
    from ion.services.investigation_service import _alert_to_text_blob

    alert = {
        "host": {"name": "WORKSTATION-01"},
        "event": {"dataset": "endpoint"},
        "url": {"domain": "evil-c2.net"},
        "tags": ["t1"],
    }
    blob = _alert_to_text_blob(alert)
    # Field NAMES must not appear as standalone tokens
    tokens = set(blob.split())
    assert "host" not in tokens and "event" not in tokens and "dataset" not in tokens
    # VALUES must be present
    assert "evil-c2.net" in blob and "WORKSTATION-01" in blob


def test_end_to_end_no_field_name_domains():
    from ion.services.investigation_service import _alert_to_text_blob
    from ion.services.ioc_text_extractor import extract_iocs

    alert = {
        "host": {"name": "SRV-DC01"},
        "event": {"dataset": "network"},
        "destination": {"domain": "bad-actor.xyz"},
        "kibana": {"alert": {"rule": {"name": "Suspicious DNS"}}},
    }
    iocs = extract_iocs(_alert_to_text_blob(alert))
    domains = iocs.get("domains", [])
    assert "bad-actor.xyz" in domains
    assert "host.name" not in domains and "event.dataset" not in domains


# ---------------------------------------------------------------------------
# 3b. Observable is_ignored flag + search filter
# ---------------------------------------------------------------------------
def _obs_db():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from ion.models import observable as obs_mod

    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    # Create Observable + its related tables (enrichments, links) that the
    # service touches via relationships.
    for cls_name in ("Observable", "ObservableEnrichment", "ObservableLink"):
        cls = getattr(obs_mod, cls_name, None)
        if cls is not None:
            cls.__table__.create(engine, checkfirst=True)
    return sessionmaker(bind=engine)()


def test_observable_search_excludes_ignored_by_default():
    from ion.models.observable import Observable, ObservableType
    from ion.services.observable_service import ObservableService

    session = _obs_db()
    session.add(Observable(type=ObservableType.DOMAIN, value="keep.com",
                           normalized_value="keep.com", is_ignored=False))
    session.add(Observable(type=ObservableType.DOMAIN, value="ignored.com",
                           normalized_value="ignored.com", is_ignored=True))
    session.commit()

    svc = ObservableService(session)
    # Default (exclude ignored)
    rows, _ = svc.search(is_ignored=False)
    vals = {o.value for o in rows}
    assert "keep.com" in vals and "ignored.com" not in vals
    # Only ignored
    rows, _ = svc.search(is_ignored=True)
    assert {o.value for o in rows} == {"ignored.com"}
    # No filter -> both
    rows, _ = svc.search()
    assert {o.value for o in rows} == {"keep.com", "ignored.com"}


def test_observable_update_sets_is_ignored():
    from ion.models.observable import Observable, ObservableType

    session = _obs_db()
    o = Observable(type=ObservableType.DOMAIN, value="x.com",
                   normalized_value="x.com")
    session.add(o)
    session.commit()
    assert o.is_ignored is False
    o.is_ignored = True
    session.commit()
    assert session.get(Observable, o.id).is_ignored is True


# ---------------------------------------------------------------------------
# 1. Arkime auto-case pushes to Kibana + attaches the alert
# ---------------------------------------------------------------------------
def test_arkime_auto_case_attaches_alert_to_kibana(monkeypatch):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from ion.models.alert_triage import AlertCase, AlertTriage
    from ion.services import arkime_auto_case_service as svc
    from ion.services import kibana_sync_helpers

    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    AlertCase.__table__.create(engine)
    AlertTriage.__table__.create(engine)
    session = sessionmaker(bind=engine)()

    # Capture the Kibana sync call.
    calls = {}

    def _fake_sync(**kw):
        calls.update(kw)
        return {"kibana_case_id": "kb-123", "kibana_case_version": "v1"}

    monkeypatch.setattr(kibana_sync_helpers, "sync_new_case_to_kibana", _fake_sync)

    alert = types.SimpleNamespace(
        id="alert-xyz", title="Beaconing detected", severity="high",
        arkime_node="node1", network_community_id="1:abc",
        source_system="elastic", source_ip="10.0.0.5",
        destination_ip="8.8.8.8", timestamp=None,
    )

    svc._create_case_for_alert(session, alert, bob_id=1, enqueue_fn=lambda **kw: None)

    # The alert id must be passed for attachment, and the kibana id persisted.
    assert calls.get("alert_ids") == ["alert-xyz"], calls
    case = session.query(AlertCase).first()
    assert case is not None and case.kibana_case_id == "kb-123"
    assert case.source_alert_ids == ["alert-xyz"]
