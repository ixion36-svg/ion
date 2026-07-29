"""v0.59.0 — Cases redesign backend: observable extraction + auto-enrichment.

Pins the shared frontend contract and the air-gap guarantees:
- (a) the alert-list path emits observables in the {type,value,threat_level,
  score,source} contract shape, and persisted enrichment hydrates them;
- (b) auto_enrich_new_observable actually awaits the enrich coroutine (the
  pre-v0.59.0 "never awaited" bug), and is a silent no-op — threat_level stays
  "unknown" — when OpenCTI is unconfigured (air-gapped);
- (c) post_enrichment_note composes the expected Threat Enrichment Summary Note
  (entity_type=CASE) and is a no-op when there's nothing enrichable to report.
"""

import asyncio
from datetime import datetime

from ion.models.alert_triage import AlertCase, AlertCaseStatus, Note, NoteEntityType
from ion.models.observable import (
    Observable,
    ObservableEnrichment,
    ObservableLink,
    ObservableLinkType,
    ObservableType,
    ThreatLevel,
)
from ion.models.user import User
from ion.services.observable_extractor import (
    ENRICHABLE_CONTRACT_TYPES,
    to_contract_observables,
)
from ion.services.observable_service import (
    ObservableService,
    hydrate_persisted_enrichment,
)
from ion.web.case_lifecycle_api import post_enrichment_note

_CONTRACT_KEYS = {"type", "value", "threat_level", "score", "source"}


# ── (a) list-path contract shape ─────────────────────────────────────────────


def test_to_contract_observables_shape():
    raw = {
        "source.ip": "1.2.3.4",
        "host.name": "web01",
        "process.name": "evil.exe",
        "file.hash.sha256": "a" * 64,
        "url.full": "http://bad.example/x",
    }
    obs = to_contract_observables(raw)
    assert obs, "expected observables extracted from raw"

    # Every dict carries exactly the contract keys.
    for o in obs:
        assert set(o.keys()) == _CONTRACT_KEYS
        assert o["type"] in {
            "ip", "domain", "url", "sha256", "sha1", "md5",
            "email", "host", "user", "file", "process", "registry",
        }

    by_type = {o["type"]: o for o in obs}
    # Enrichable types default to "unknown"; display-only types get null.
    assert by_type["ip"]["threat_level"] == "unknown"
    assert by_type["ip"]["value"] == "1.2.3.4"
    assert by_type["ip"]["score"] is None and by_type["ip"]["source"] is None
    assert by_type["sha256"]["threat_level"] == "unknown"
    assert by_type["host"]["threat_level"] is None
    assert by_type["process"]["threat_level"] is None
    # host/user/file/process/registry are NOT enrichable per the contract.
    assert "host" not in ENRICHABLE_CONTRACT_TYPES


def test_hydrate_persisted_enrichment_fills_from_db(session):
    obs = Observable(
        type=ObservableType.IPV4,
        value="1.2.3.4",
        normalized_value="1.2.3.4",
        threat_level=ThreatLevel.MEDIUM,
    )
    session.add(obs)
    session.flush()
    session.add(ObservableEnrichment(
        observable_id=obs.id, source="opencti", enriched_at=datetime.utcnow(),
        is_malicious=True, score=55, labels=["c2"],
    ))
    session.commit()

    alerts = [{
        "id": "a1",
        "observables": [
            {"type": "ip", "value": "1.2.3.4", "threat_level": "unknown", "score": None, "source": None},
            {"type": "ip", "value": "9.9.9.9", "threat_level": "unknown", "score": None, "source": None},
        ],
    }]
    hydrate_persisted_enrichment(session, alerts)

    filled, absent = alerts[0]["observables"]
    assert filled["threat_level"] == "medium"
    assert filled["score"] == 55
    assert filled["source"] == "opencti"
    # Unknown / not-yet-persisted observable keeps the defaults.
    assert absent["threat_level"] == "unknown"
    assert absent["score"] is None and absent["source"] is None


# ── (b) auto-enrich awaits the coroutine + air-gap no-op ──────────────────────


class _FakeOpenCTI:
    def __init__(self, configured):
        self.is_configured = configured


def test_auto_enrich_runs_the_coroutine(session, monkeypatch):
    obs = Observable(
        type=ObservableType.IPV4, value="5.6.7.8", normalized_value="5.6.7.8",
    )
    session.add(obs)
    session.commit()

    svc = ObservableService(session)

    # Force OpenCTI "configured" so we exercise the enrich path.
    monkeypatch.setattr(
        "ion.services.observable_service.get_opencti_service",
        lambda: _FakeOpenCTI(True),
    )

    ran = {"flag": False}

    async def _fake_enrich(observable_id, source="opencti"):
        ran["flag"] = True  # proves the coroutine was actually awaited
        target = svc.get_by_id(observable_id)
        target.threat_level = ThreatLevel.HIGH
        return ObservableEnrichment(
            observable_id=observable_id, source="opencti",
            enriched_at=datetime.utcnow(), is_malicious=True, score=90,
        )

    svc.enrich = _fake_enrich  # type: ignore[method-assign]

    result = svc.auto_enrich_new_observable(obs)

    assert ran["flag"] is True  # NOT the old "never awaited" dead coroutine
    assert result is not None
    assert obs.threat_level == ThreatLevel.HIGH
    assert obs.last_auto_enriched is not None  # throttle stamp updated


def test_auto_enrich_airgap_noop(session, monkeypatch):
    obs = Observable(
        type=ObservableType.IPV4, value="10.0.0.9", normalized_value="10.0.0.9",
    )
    session.add(obs)
    session.commit()

    svc = ObservableService(session)
    # OpenCTI unconfigured (air-gapped default).
    monkeypatch.setattr(
        "ion.services.observable_service.get_opencti_service",
        lambda: _FakeOpenCTI(False),
    )

    # Guard: enrich must never be invoked on the air-gap path.
    def _boom(*a, **k):
        raise AssertionError("enrich must not run when OpenCTI is unconfigured")

    svc.enrich = _boom  # type: ignore[method-assign]

    result = svc.auto_enrich_new_observable(obs)

    assert result is None
    assert obs.threat_level == ThreatLevel.UNKNOWN
    assert obs.last_auto_enriched is None


# ── (c) enrichment auto-note ──────────────────────────────────────────────────


def _user(session, uid=1):
    u = User(id=uid, username=f"eng{uid}", email=f"e{uid}@x", password_hash="x",
             display_name="Eng", is_active=True)
    session.add(u)
    session.flush()
    return u


def _case(session, num="C-1", created_by=1):
    c = AlertCase(case_number=num, title=f"case {num}", created_by_id=created_by,
                  status=AlertCaseStatus.OPEN)
    session.add(c)
    session.flush()
    return c


def _link_case(session, obs_id, case_id, context):
    session.add(ObservableLink(
        observable_id=obs_id, link_type=ObservableLinkType.CASE,
        entity_id=case_id, context=context,
    ))


def test_post_enrichment_note_composes_and_writes(session):
    _user(session)
    case = _case(session)

    obs = Observable(
        type=ObservableType.IPV4, value="1.2.3.4", normalized_value="1.2.3.4",
        threat_level=ThreatLevel.HIGH,
    )
    session.add(obs)
    session.flush()
    session.add(ObservableEnrichment(
        observable_id=obs.id, source="opencti", enriched_at=datetime.utcnow(),
        is_malicious=True, score=85, labels=["c2", "apt"],
        threat_actors=[{"name": "APT29", "id": "x"}],
    ))
    _link_case(session, obs.id, case.id, "source_ip")
    session.commit()

    note = asyncio.run(post_enrichment_note(session, case.id, 1, "eng1"))

    assert note is not None
    assert note.entity_type == NoteEntityType.CASE
    assert note.entity_id == str(case.id)
    assert note.user_id == 1
    assert note.content.startswith("**Threat Enrichment Summary** (OpenCTI, TLP:AMBER)")
    assert "1.2.3.4" in note.content
    assert "high" in note.content
    assert "(85)" in note.content
    assert "APT29" in note.content

    # Persisted as a CASE note.
    stored = session.query(Note).filter(
        Note.entity_type == NoteEntityType.CASE,
        Note.entity_id == str(case.id),
    ).all()
    assert len(stored) == 1

    # Idempotent-ish: a second call with identical content writes nothing new.
    again = asyncio.run(post_enrichment_note(session, case.id, 1, "eng1"))
    assert again is None
    stored2 = session.query(Note).filter(
        Note.entity_type == NoteEntityType.CASE,
        Note.entity_id == str(case.id),
    ).all()
    assert len(stored2) == 1


def test_post_enrichment_note_noop_without_enrichable(session):
    _user(session)
    case = _case(session, num="C-2")

    # A display-only observable (hostname) linked to the case — nothing to
    # report. And an enrichable-but-unenriched IP (air-gap: unknown, no
    # enrichment) — also nothing to report.
    host = Observable(type=ObservableType.HOSTNAME, value="web01",
                      normalized_value="web01")
    ip = Observable(type=ObservableType.IPV4, value="8.8.8.8",
                    normalized_value="8.8.8.8", threat_level=ThreatLevel.UNKNOWN)
    session.add_all([host, ip])
    session.flush()
    _link_case(session, host.id, case.id, "hostname")
    _link_case(session, ip.id, case.id, "source_ip")
    session.commit()

    note = asyncio.run(post_enrichment_note(session, case.id, 1, "eng1"))
    assert note is None
    assert session.query(Note).filter(
        Note.entity_type == NoteEntityType.CASE,
        Note.entity_id == str(case.id),
    ).count() == 0
