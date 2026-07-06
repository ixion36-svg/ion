"""v0.49.3 code-review fixes (v0.39.8 baseline F1, F2, F4): make the
analyst is_ignored suppression actually work.

F2: the merge compared the raw extracted value `v.lower()` against
    Observable.normalized_value, but normalize_value does more than lowercase
    (CVE uppercases, MAC rewrites separators, domains strip trailing dots), so
    ignored CVEs/MACs/dotted-domains never matched and re-surfaced.
F1: suppression only guarded the NEW-merge append; observables already in
    case.observables before being ignored were never pruned, and the
    shared-observables correlation query didn't exclude is_ignored at all.
F4: the ignored-values load swallowed every error to an empty set silently,
    disabling suppression on any transient DB hiccup with no log.
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from ion.models import observable as obs_mod
from ion.models.observable import Observable, ObservableType


@pytest.fixture
def db():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    for cls_name in ("Observable", "ObservableEnrichment", "ObservableLink"):
        cls = getattr(obs_mod, cls_name, None)
        if cls is not None:
            cls.__table__.create(engine, checkfirst=True)
    s = sessionmaker(bind=engine)()
    yield s
    s.close()


@pytest.fixture
def full_session(tmp_path):
    """Full-schema session for endpoint-level behavioral tests."""
    from ion.models.document import Base

    engine = create_engine(f"sqlite:///{tmp_path / 'full.db'}")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    yield s
    s.close()


def _add_ignored(db, obs_type, value, normalized):
    db.add(Observable(type=obs_type, value=value, normalized_value=normalized, is_ignored=True))
    db.commit()


class TestIgnoredMatchNormalization:
    """The extracted raw IOC must be matched against the ignore set the same
    way it was normalized when stored — not by naive lower()."""

    def _matches(self, db, obs_type, extracted):
        from ion.services.investigation_service import (
            _ignored_normalized_values,
            _is_ignored_ioc,
        )

        ignored = _ignored_normalized_values(db)
        return _is_ignored_ioc(obs_type, extracted, ignored)

    def test_cve_uppercase_is_suppressed(self, db):
        _add_ignored(db, ObservableType.CVE, "CVE-2024-1234", "CVE-2024-1234")
        assert self._matches(db, "cve", "cve-2024-1234") is True

    def test_domain_trailing_dot_is_suppressed(self, db):
        _add_ignored(db, ObservableType.DOMAIN, "evil.com.", "evil.com")
        assert self._matches(db, "domain", "evil.com.") is True

    def test_mac_separator_variant_is_suppressed(self, db):
        _add_ignored(db, ObservableType.MAC_ADDRESS, "AA-BB-CC-DD-EE-FF", "aa:bb:cc:dd:ee:ff")
        assert self._matches(db, "mac_address", "AA-BB-CC-DD-EE-FF") is True

    def test_type_scoped_no_cross_type_match(self, db):
        # An ignored domain must not suppress an unrelated email of the same text.
        _add_ignored(db, ObservableType.DOMAIN, "mail.com", "mail.com")
        assert self._matches(db, "email", "mail.com") is False

    def test_non_ignored_value_passes_through(self, db):
        _add_ignored(db, ObservableType.DOMAIN, "evil.com", "evil.com")
        assert self._matches(db, "domain", "good.com") is False


class TestIgnoredLoadIsLoud:
    """F4: a failure loading the ignore set must be logged, not silently
    swallowed into 'suppress nothing'."""

    def test_db_error_logs_warning(self, monkeypatch, caplog):
        import logging as _logging

        from ion.services import investigation_service as inv

        class _BoomDB:
            def query(self, *a, **k):
                raise RuntimeError("db down")

        with caplog.at_level(_logging.WARNING, logger="ion.services.investigation_service"):
            out = inv._ignored_normalized_values(_BoomDB())
        assert out == set()  # safe fallback preserved
        assert any("ignore" in r.message.lower() for r in caplog.records), (
            "silent failure — suppression disabled with no log"
        )


class TestPruneIgnored:
    """F1: observables already merged into case.observables before being
    ignored must be pruned on the next pass, not just excluded from new adds."""

    def test_prune_removes_now_ignored_entries(self, db):
        from ion.services.investigation_service import (
            _ignored_normalized_values,
            _prune_ignored_observables,
        )

        _add_ignored(db, ObservableType.DOMAIN, "evil.com", "evil.com")
        case_observables = [
            {"type": "domain", "value": "evil.com", "source": "investigation"},
            {"type": "domain", "value": "good.com", "source": "investigation"},
        ]
        ignored = _ignored_normalized_values(db)
        pruned = _prune_ignored_observables(case_observables, ignored)
        assert [o["value"] for o in pruned] == ["good.com"]


class TestSharedObservablesExcludesIgnored:
    """F1: the cross-case correlation endpoint must not surface analyst-ignored
    observables. Behavioral: real DB, real endpoint call (AUDIT-8 replaced a
    tautological source-string scan)."""

    def test_endpoint_excludes_ignored_observable(self, full_session):
        import asyncio

        from ion.models.alert_triage import AlertCase, AlertCaseStatus
        from ion.models.observable import (
            Observable,
            ObservableLink,
            ObservableLinkType,
            ObservableType,
        )
        from ion.web.case_lifecycle_api import get_case_similar_observables

        s = full_session
        case_a = AlertCase(case_number="CASE-0001", title="a", description="d",
                           status=AlertCaseStatus.OPEN, severity="low", created_by_id=1)
        case_b = AlertCase(case_number="CASE-0002", title="b", description="d",
                           status=AlertCaseStatus.OPEN, severity="low", created_by_id=1)
        s.add_all([case_a, case_b])
        ignored = Observable(type=ObservableType.IPV4, value="203.0.113.9",
                             normalized_value="203.0.113.9", is_ignored=True)
        kept = Observable(type=ObservableType.DOMAIN, value="evil.example",
                          normalized_value="evil.example", is_ignored=False)
        s.add_all([ignored, kept])
        s.flush()
        # both observables linked to case A AND sighted in case B
        for obs in (ignored, kept):
            for cid in (case_a.id, case_b.id):
                s.add(ObservableLink(observable_id=obs.id,
                                     link_type=ObservableLinkType.CASE,
                                     entity_id=cid, context="test"))
        s.commit()

        out = asyncio.run(get_case_similar_observables(
            case_id=case_a.id, current_user=None, session=s
        ))
        values = {e["observable"]["value"] for e in out["shared"]}
        assert "evil.example" in values
        assert "203.0.113.9" not in values, (
            "analyst-ignored observable still drives cross-case correlation"
        )


class TestReadPathsPruneIgnored:
    """Belt-and-braces: the case-detail JSON must not serve observables that
    are currently analyst-ignored, even for a case never re-investigated since
    the flag was set. Behavioral: real DB, real endpoint call (AUDIT-8
    replaced a tautological source-string scan)."""

    def test_case_detail_response_excludes_ignored(self, full_session):
        import asyncio

        from ion.models.alert_triage import AlertCase, AlertCaseStatus
        from ion.models.observable import Observable, ObservableType
        from ion.web.case_lifecycle_api import get_case_detail

        s = full_session
        s.add(Observable(type=ObservableType.IPV4, value="203.0.113.9",
                         normalized_value="203.0.113.9", is_ignored=True))
        case = AlertCase(
            case_number="CASE-0001", title="t", description="d",
            status=AlertCaseStatus.OPEN, severity="low", created_by_id=1,
            observables=[
                {"type": "source_ip", "value": "203.0.113.9"},
                {"type": "domain", "value": "keep.example"},
            ],
        )
        s.add(case)
        s.commit()

        out = asyncio.run(get_case_detail(
            case_id=case.id, current_user=None, session=s
        ))
        values = {o["value"] for o in out["observables"]}
        assert values == {"keep.example"}, (
            f"ignored observable served in case detail: {values}"
        )


class TestRoleTypedEntriesArePruned:
    """AUDIT-2: case.observables stores role strings (source_ip,
    destination_hostname, subject_user...) from observable_extractor; the
    ignore flag lands on an Observable row typed via LEGACY_TYPE_MAP
    (source_ip -> IPV4). Suppression must bridge that mapping or it misses
    the commonest indicators in network cases."""

    def test_ignored_ip_prunes_source_ip_entry(self, db):
        from ion.services.investigation_service import (
            _ignored_normalized_values,
            _prune_ignored_observables,
        )

        _add_ignored(db, ObservableType.IPV4, "203.0.113.9", "203.0.113.9")
        case_observables = [
            {"type": "source_ip", "value": "203.0.113.9"},
            {"type": "destination_ip", "value": "198.51.100.2"},
        ]
        pruned = _prune_ignored_observables(case_observables, _ignored_normalized_values(db))
        assert [o["value"] for o in pruned] == ["198.51.100.2"]

    def test_ignored_hostname_prunes_destination_hostname_entry(self, db):
        from ion.services.investigation_service import (
            _ignored_normalized_values,
            _prune_ignored_observables,
        )

        _add_ignored(db, ObservableType.HOSTNAME, "EVIL-HOST.", "evil-host")
        case_observables = [{"type": "destination_hostname", "value": "EVIL-HOST."}]
        pruned = _prune_ignored_observables(case_observables, _ignored_normalized_values(db))
        assert pruned == []

    def test_ignored_user_prunes_subject_user_entry(self, db):
        from ion.services.investigation_service import (
            _ignored_normalized_values,
            _prune_ignored_observables,
        )

        _add_ignored(db, ObservableType.USER_ACCOUNT, "SVC_Backup", "svc_backup")
        case_observables = [{"type": "subject_user", "value": "SVC_Backup"}]
        pruned = _prune_ignored_observables(case_observables, _ignored_normalized_values(db))
        assert pruned == []


class TestKibanaExportExcludesIgnored:
    """AUDIT-3: descriptions pushed to Kibana must not carry analyst-ignored
    observables — this sink was left unfiltered by the first fix pass."""

    def test_helper_prunes_ignored_for_kibana(self, db):
        from ion.services.kibana_sync_service import _observables_for_kibana

        _add_ignored(db, ObservableType.IPV4, "203.0.113.9", "203.0.113.9")
        out = _observables_for_kibana(db, [
            {"type": "source_ip", "value": "203.0.113.9"},
            {"type": "domain", "value": "keep.example"},
        ])
        assert [o["value"] for o in out] == ["keep.example"]

    def test_both_description_builders_use_the_pruned_helper(self):
        """Structural pin: every build_case_description call in the sync
        service must source its observables from _observables_for_kibana
        (an AST check — not satisfiable by comments)."""
        import ast
        import pathlib

        src = pathlib.Path("src/ion/services/kibana_sync_service.py").read_text(encoding="utf-8")
        tree = ast.parse(src)
        calls = [
            n for n in ast.walk(tree)
            if isinstance(n, ast.Call)
            and (
                (isinstance(n.func, ast.Name) and n.func.id == "build_case_description")
                or (isinstance(n.func, ast.Attribute) and n.func.attr == "build_case_description")
            )
        ]
        assert calls, "expected build_case_description call sites"
        for call in calls:
            obs_kw = next((k for k in call.keywords if k.arg == "observables"), None)
            assert obs_kw is not None, f"line {call.lineno}: no observables kwarg"
            v = obs_kw.value
            # accept _observables_for_kibana(...) or a conditional over it
            names = {n.func.id for n in ast.walk(v)
                     if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
            assert "_observables_for_kibana" in names, (
                f"line {call.lineno}: observables not routed through _observables_for_kibana"
            )
