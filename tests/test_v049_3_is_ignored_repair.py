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
    """F1: the cross-case correlation query must not surface analyst-ignored
    observables."""

    def test_query_filters_is_ignored(self):
        import inspect

        from ion.web import case_lifecycle_api

        src = inspect.getsource(case_lifecycle_api.get_case_similar_observables)
        assert "is_ignored" in src, (
            "shared-observables correlation still surfaces ignored observables"
        )


class TestReadPathsPruneIgnored:
    """Belt-and-braces: the case-detail JSON and the Kibana description must
    not serve observables that are currently analyst-ignored, even for a case
    that hasn't been re-investigated since the flag was set."""

    def test_case_detail_filters_ignored(self):
        import inspect

        from ion.web import case_lifecycle_api

        src = inspect.getsource(case_lifecycle_api.get_case_detail)
        assert "_prune_ignored_observables" in src or "is_ignored" in src, (
            "case-detail still serves analyst-ignored observables"
        )
