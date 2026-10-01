"""Tests for system_resolver_service — namespace → CyAB + TIDE identity.

This module had no tests at all when the coverage ratchet first measured the
tree, despite being the reason CyAB's two registry tables were kept out of
the archive: `elasticsearch_api` stamps `cyab_system_name` and
`tide_system_id` onto every alert in the queue from this resolver, so a
silent failure here degrades the whole alert list rather than one page.

Three things carry the risk and are covered below:

  * the dict contract — callers merge the result straight into an alert dict,
    so every key must be present even when nothing resolves;
  * the TIDE linkage, including the deliberate fallback where CyAB and TIDE
    share a system name but no id;
  * the module-level cache, which is process-global and therefore the thing
    most likely to leak state between requests.
"""

from __future__ import annotations

import pytest

from ion.models.cyab import CyabDataSource, CyabSystem
from ion.services import system_resolver_service as resolver

EMPTY_KEYS = {
    "cyab_system_id",
    "cyab_system_name",
    "cyab_data_source_id",
    "cyab_data_source_name",
    "tide_system_id",
    "tide_system_name",
}


@pytest.fixture(autouse=True)
def _clear_resolver_cache():
    """The cache is module-global, so it outlives any one test.

    Without this every test after the first would read the previous test's
    map and pass for the wrong reason.
    """
    resolver.invalidate()
    yield
    resolver.invalidate()


@pytest.fixture
def no_tide(monkeypatch):
    """Default: TIDE returns nothing, so only the CyAB legs resolve."""
    monkeypatch.setattr(resolver, "get_tide_service", lambda: _FakeTide([]))


class _FakeTide:
    def __init__(self, systems, raises=False):
        self._systems = systems
        self._raises = raises
        self.calls = 0

    def get_systems(self):
        self.calls += 1
        if self._raises:
            raise RuntimeError("TIDE unreachable")
        return self._systems


def _make_system(session, name="Production Endpoints", department="IT"):
    sys_row = CyabSystem(name=name, department=department)
    session.add(sys_row)
    session.flush()
    return sys_row


def _make_source(session, sys_row, *, namespace, name="CrowdStrike production",
                 tide_system_id=None):
    ds = CyabDataSource(
        system_id=sys_row.id,
        name=name,
        data_namespace=namespace,
        tide_system_id=tide_system_id,
    )
    session.add(ds)
    session.flush()
    return ds


class TestResolveNamespace:
    """The flat-dict contract callers merge into an alert."""

    def test_none_namespace_returns_the_full_shape(self, session, no_tide):
        out = resolver.resolve_namespace(session, None)
        assert out["source_system"] is None
        assert EMPTY_KEYS <= set(out)
        assert all(out[k] is None for k in EMPTY_KEYS)

    def test_empty_namespace_returns_the_full_shape(self, session, no_tide):
        out = resolver.resolve_namespace(session, "")
        assert all(out[k] is None for k in EMPTY_KEYS)

    def test_unknown_namespace_keeps_source_system_and_nulls_the_rest(
        self, session, no_tide
    ):
        """An unmapped alert still renders; it just has no system attached."""
        out = resolver.resolve_namespace(session, "never-seen")
        assert out["source_system"] == "never-seen"
        assert all(out[k] is None for k in EMPTY_KEYS)

    def test_resolves_to_its_cyab_system_and_data_source(self, session, no_tide):
        sys_row = _make_system(session)
        ds = _make_source(session, sys_row, namespace="production")
        session.commit()

        out = resolver.resolve_namespace(session, "production")

        assert out["source_system"] == "production"
        assert out["cyab_system_id"] == sys_row.id
        assert out["cyab_system_name"] == "Production Endpoints"
        assert out["cyab_data_source_id"] == ds.id
        assert out["cyab_data_source_name"] == "CrowdStrike production"

    @pytest.mark.parametrize("sent", ["PRODUCTION", "  production  ", "Production"])
    def test_lookup_ignores_case_and_surrounding_space(self, session, no_tide, sent):
        """ES namespaces arrive with whatever casing the shipper used."""
        sys_row = _make_system(session)
        _make_source(session, sys_row, namespace="production")
        session.commit()

        out = resolver.resolve_namespace(session, sent)

        assert out["cyab_system_id"] == sys_row.id
        # The raw string the caller passed is echoed back untouched.
        assert out["source_system"] == sent

    def test_source_with_no_namespace_is_not_resolvable(self, session, no_tide):
        sys_row = _make_system(session)
        _make_source(session, sys_row, namespace=None)
        _make_source(session, sys_row, namespace="", name="blank")
        _make_source(session, sys_row, namespace="   ", name="spaces")
        session.commit()

        assert resolver.list_known_systems(session) == []


class TestTideLinkage:
    """The leg that makes TIDE use cases reachable from an alert."""

    def test_tide_name_resolves_through_the_tide_system_id(self, session, monkeypatch):
        monkeypatch.setattr(
            resolver, "get_tide_service",
            lambda: _FakeTide([{"id": "tide-8f2c", "name": "Prod Endpoints (TIDE)"}]),
        )
        sys_row = _make_system(session)
        _make_source(session, sys_row, namespace="production",
                     tide_system_id="tide-8f2c")
        session.commit()

        out = resolver.resolve_namespace(session, "production")

        assert out["tide_system_id"] == "tide-8f2c"
        assert out["tide_system_name"] == "Prod Endpoints (TIDE)"

    def test_tide_name_falls_back_to_a_matching_system_name(self, session, monkeypatch):
        """CyAB and TIDE are often named alike on purpose, with no id linking them."""
        monkeypatch.setattr(
            resolver, "get_tide_service",
            lambda: _FakeTide([{"id": "tide-other", "name": "Production Endpoints"}]),
        )
        sys_row = _make_system(session, name="Production Endpoints")
        _make_source(session, sys_row, namespace="production", tide_system_id=None)
        session.commit()

        out = resolver.resolve_namespace(session, "production")

        assert out["tide_system_name"] == "Production Endpoints"
        assert out["tide_system_id"] is None

    def test_unmatched_tide_id_keeps_the_id_but_not_a_name(self, session, monkeypatch):
        monkeypatch.setattr(
            resolver, "get_tide_service",
            lambda: _FakeTide([{"id": "tide-aaa", "name": "Something Else"}]),
        )
        sys_row = _make_system(session, name="Production Endpoints")
        _make_source(session, sys_row, namespace="production",
                     tide_system_id="tide-missing")
        session.commit()

        out = resolver.resolve_namespace(session, "production")

        assert out["tide_system_id"] == "tide-missing"
        assert out["tide_system_name"] is None

    def test_malformed_tide_entries_are_ignored(self, session, monkeypatch):
        """TIDE rows missing an id or a name are skipped, not half-indexed."""
        monkeypatch.setattr(
            resolver, "get_tide_service",
            lambda: _FakeTide([
                {"id": None, "name": "No Id"},
                {"id": "tide-no-name", "name": None},
                {"id": "tide-ok", "name": "Usable System"},
            ]),
        )
        sys_row = _make_system(session, name="No Id")
        _make_source(session, sys_row, namespace="production",
                     tide_system_id="tide-no-name")
        session.commit()

        out = resolver.resolve_namespace(session, "production")

        # Neither malformed entry may produce a name — not by id lookup, and
        # not by the name fallback, which would otherwise match "No Id".
        assert out["tide_system_name"] is None
        assert out["tide_system_id"] == "tide-no-name"

    def test_tide_outage_still_resolves_the_cyab_legs(self, session, monkeypatch):
        """A TIDE outage must not blank the system name on every alert."""
        monkeypatch.setattr(
            resolver, "get_tide_service", lambda: _FakeTide([], raises=True)
        )
        sys_row = _make_system(session)
        _make_source(session, sys_row, namespace="production",
                     tide_system_id="tide-8f2c")
        session.commit()

        out = resolver.resolve_namespace(session, "production")

        assert out["cyab_system_name"] == "Production Endpoints"
        assert out["tide_system_id"] == "tide-8f2c"
        assert out["tide_system_name"] is None


class TestCache:
    """Process-global state — the part most likely to serve stale answers."""

    def test_repeat_lookups_build_the_map_once(self, session, monkeypatch):
        fake = _FakeTide([])
        monkeypatch.setattr(resolver, "get_tide_service", lambda: fake)
        sys_row = _make_system(session)
        _make_source(session, sys_row, namespace="production")
        session.commit()

        for _ in range(3):
            resolver.resolve_namespace(session, "production")

        assert fake.calls == 1, "cache rebuilt on a warm path"

    def test_invalidate_forces_the_next_call_to_rebuild(self, session, monkeypatch):
        fake = _FakeTide([])
        monkeypatch.setattr(resolver, "get_tide_service", lambda: fake)
        sys_row = _make_system(session)
        _make_source(session, sys_row, namespace="production")
        session.commit()

        resolver.resolve_namespace(session, "production")
        resolver.invalidate()
        resolver.resolve_namespace(session, "production")

        assert fake.calls == 2

    def test_a_source_added_after_invalidate_is_visible(self, session, no_tide):
        """CyAB write endpoints call invalidate() so edits land immediately."""
        sys_row = _make_system(session)
        _make_source(session, sys_row, namespace="production")
        session.commit()
        resolver.resolve_namespace(session, "production")

        _make_source(session, sys_row, namespace="staging", name="CrowdStrike staging")
        session.commit()
        resolver.invalidate()

        assert resolver.resolve_namespace(session, "staging")["cyab_system_id"] == sys_row.id

    def test_a_failed_rebuild_is_swallowed(self, session, monkeypatch):
        """A database blip must not propagate into alert serialisation."""
        def boom(_session):
            raise RuntimeError("database gone")

        monkeypatch.setattr(resolver, "_build_cache", boom)

        out = resolver.resolve_namespace(session, "production")

        assert out["source_system"] == "production"
        assert out["cyab_system_id"] is None


class TestBulkResolve:
    """Used by the alerts list to enrich a page in one cache build."""

    def test_keys_are_the_raw_strings_the_caller_passed(self, session, no_tide):
        """The caller indexes back in with the alert's own source_system."""
        sys_row = _make_system(session)
        _make_source(session, sys_row, namespace="production")
        session.commit()

        out = resolver.bulk_resolve(session, ["PRODUCTION"])

        assert "PRODUCTION" in out
        assert out["PRODUCTION"]["cyab_system_id"] == sys_row.id

    def test_repeated_namespaces_are_resolved_once(self, session, no_tide, monkeypatch):
        """Counting calls, not keys: a dict would dedupe on its own, so
        asserting on the result would pass even with the guard removed."""
        sys_row = _make_system(session)
        _make_source(session, sys_row, namespace="production")
        session.commit()

        calls = []
        real = resolver.resolve_namespace

        def counting(sess, ns):
            calls.append(ns)
            return real(sess, ns)

        monkeypatch.setattr(resolver, "resolve_namespace", counting)
        out = resolver.bulk_resolve(session, ["production"] * 5)

        assert list(out) == ["production"]
        assert calls == ["production"]

    def test_none_entries_are_skipped(self, session, no_tide):
        out = resolver.bulk_resolve(session, [None, None])
        assert out == {}

    def test_known_and_unknown_namespaces_both_come_back(self, session, no_tide):
        sys_row = _make_system(session)
        _make_source(session, sys_row, namespace="production")
        session.commit()

        out = resolver.bulk_resolve(session, ["production", "orphan"])

        assert out["production"]["cyab_system_name"] == "Production Endpoints"
        assert out["orphan"]["cyab_system_name"] is None
        assert out["orphan"]["source_system"] == "orphan"


class TestListKnownSystems:
    """Feeds the filter dropdowns."""

    def test_lists_every_mapped_namespace(self, session, no_tide):
        sys_row = _make_system(session)
        _make_source(session, sys_row, namespace="production")
        _make_source(session, sys_row, namespace="staging", name="CrowdStrike staging")
        session.commit()

        assert {r["namespace"] for r in resolver.list_known_systems(session)} == {
            "production", "staging",
        }

    def test_sorted_by_display_name(self, session, no_tide):
        alpha = _make_system(session, name="Alpha Estate")
        zulu = _make_system(session, name="Zulu Estate", department="Ops")
        _make_source(session, zulu, namespace="zulu-ns", name="z-source")
        _make_source(session, alpha, namespace="alpha-ns", name="a-source")
        session.commit()

        names = [r["display_name"] for r in resolver.list_known_systems(session)]

        assert names == ["Alpha Estate", "Zulu Estate"]

    def test_namespace_is_lowercased_in_the_map(self, session, no_tide):
        sys_row = _make_system(session)
        _make_source(session, sys_row, namespace="PRODUCTION")
        session.commit()

        assert resolver.list_known_systems(session)[0]["namespace"] == "production"
