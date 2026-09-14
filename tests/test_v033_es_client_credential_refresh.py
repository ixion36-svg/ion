"""Tests for ES client credential-refresh fix (Finding #2 from CODE_REVIEW_ION.md).

Before the fix, _get_es_client() returned a stale cached client even when
credentials changed at runtime (admin wizard update). Now it compares a
fingerprint of (headers, auth) and recreates the client on mismatch.

The single slot became a pool when tenants gained their own Elasticsearch: a
slot holds one estate, so alternating tenants evicted each other and rebuilt a
connection pool per request. The contracts below are unchanged — same creds and
loop reuse, different creds or loop do not — but a displaced client is now kept
rather than disposed, which is the whole point.
"""

import pytest

import ion.services.elasticsearch_service as es_mod
from ion.services.elasticsearch_service import _creds_fingerprint, _get_es_client


@pytest.fixture(autouse=True)
def reset_es_client():
    """Empty the client pool before and after every test."""
    es_mod._es_pool.clear()
    yield
    import asyncio

    for entry in list(es_mod._es_pool.values()):
        if not entry.client.is_closed:
            try:
                asyncio.run(entry.client.aclose())
            except Exception:
                pass
    es_mod._es_pool.clear()


class TestCredsFingerprint:
    def test_same_creds_produce_same_fingerprint(self):
        h = {"Authorization": "ApiKey abc123", "Content-Type": "application/json"}
        assert _creds_fingerprint(h, None) == _creds_fingerprint(h, None)

    def test_different_api_keys_produce_different_fingerprints(self):
        h1 = {"Authorization": "ApiKey key_A", "Content-Type": "application/json"}
        h2 = {"Authorization": "ApiKey key_B", "Content-Type": "application/json"}
        assert _creds_fingerprint(h1, None) != _creds_fingerprint(h2, None)

    def test_different_basic_auth_produce_different_fingerprints(self):
        h = {"Content-Type": "application/json"}
        assert _creds_fingerprint(h, ("user", "pass1")) != _creds_fingerprint(h, ("user", "pass2"))

    def test_dict_insertion_order_does_not_matter(self):
        h1 = {"Content-Type": "application/json", "Authorization": "ApiKey x"}
        h2 = {"Authorization": "ApiKey x", "Content-Type": "application/json"}
        assert _creds_fingerprint(h1, None) == _creds_fingerprint(h2, None)


class TestGetEsClientCredentialRefresh:
    _timeout = __import__("httpx").Timeout(30.0, connect=3.0)

    def test_same_credentials_return_same_client(self):
        headers = {"Authorization": "ApiKey key_A", "Content-Type": "application/json"}
        c1 = _get_es_client(headers, None, False, self._timeout)
        c2 = _get_es_client(headers, None, False, self._timeout)
        assert c1 is c2

    def test_changed_credentials_return_new_client(self):
        h1 = {"Authorization": "ApiKey key_A", "Content-Type": "application/json"}
        h2 = {"Authorization": "ApiKey key_B", "Content-Type": "application/json"}
        c1 = _get_es_client(h1, None, False, self._timeout)
        c2 = _get_es_client(h2, None, False, self._timeout)
        assert c1 is not c2

    def test_a_rotation_replaces_rather_than_accumulates(self):
        """Same estate, new credentials: one entry, not two.

        Keying the pool on the fingerprint would make a rotation look like a new
        estate and leave the superseded client pooled forever.
        """
        h1 = {"Authorization": "ApiKey key_A", "Content-Type": "application/json"}
        h2 = {"Authorization": "ApiKey key_B", "Content-Type": "application/json"}
        _get_es_client(h1, None, False, self._timeout)
        _get_es_client(h2, None, False, self._timeout)
        assert len(es_mod._es_pool) == 1
        assert {e.fp for e in es_mod._es_pool.values()} == {_creds_fingerprint(h2, None)}

    def test_two_tenants_do_not_evict_each_other(self):
        """The defect a single slot caused: alternating estates rebuilding a
        connection pool on every request. Estates are separated by tenant, not
        by credentials — see test_a_rotation_replaces_rather_than_accumulates."""
        from ion.core.tenant_context import tenant_scope

        h1 = {"Authorization": "ApiKey tenant_A", "Content-Type": "application/json"}
        h2 = {"Authorization": "ApiKey tenant_B", "Content-Type": "application/json"}
        with tenant_scope(1):
            a_first = _get_es_client(h1, None, False, self._timeout)
        with tenant_scope(2):
            b = _get_es_client(h2, None, False, self._timeout)
        with tenant_scope(1):
            a_again = _get_es_client(h1, None, False, self._timeout)

        assert a_first is not b
        assert a_first is a_again, "the other tenant's request displaced this client"


class TestGetEsClientEventLoopBinding:
    """Regression for 'RuntimeError: Event loop is closed': background services
    run ES queries via asyncio.run() (a fresh, short-lived loop each cycle).
    A client bound to a dead loop must NOT be reused on a new loop."""
    _timeout = __import__("httpx").Timeout(30.0, connect=3.0)

    def test_client_recreated_on_a_different_event_loop(self):
        import asyncio
        headers = {"Authorization": "ApiKey key_A", "Content-Type": "application/json"}
        seen = []

        async def grab():
            # Same creds each time; do NOT close, so reuse would be by loop only.
            c = _get_es_client(headers, None, False, self._timeout)
            seen.append(id(c))

        asyncio.run(grab())   # loop #1 — creates client bound to loop #1
        asyncio.run(grab())   # loop #2 (fresh) — must rebind, not reuse loop #1's
        assert seen[0] != seen[1], "client must be recreated on a new event loop"

    def test_same_loop_reuses_client(self):
        import asyncio
        headers = {"Authorization": "ApiKey key_A", "Content-Type": "application/json"}
        seen = []

        async def two_calls():
            seen.append(id(_get_es_client(headers, None, False, self._timeout)))
            seen.append(id(_get_es_client(headers, None, False, self._timeout)))

        asyncio.run(two_calls())  # both calls on the same loop -> pooled/reused
        assert seen[0] == seen[1], "same loop + same creds must reuse the client"

    def test_close_empties_the_pool(self):
        headers = {"Authorization": "ApiKey key_A", "Content-Type": "application/json"}
        _get_es_client(headers, None, False, self._timeout)
        assert len(es_mod._es_pool) == 1
        es_mod._close_es_client()
        assert len(es_mod._es_pool) == 0

    def test_closing_one_estate_leaves_the_others_connected(self):
        """Re-pointing one tenant must not drop every other tenant's connections."""
        h1 = {"Authorization": "ApiKey tenant_A", "Content-Type": "application/json"}
        h2 = {"Authorization": "ApiKey tenant_B", "Content-Type": "application/json"}
        _get_es_client(h1, None, False, self._timeout)
        b = _get_es_client(h2, None, False, self._timeout)
        es_mod._close_es_client(_creds_fingerprint(h1, None))
        remaining = [e.client for e in es_mod._es_pool.values()]
        assert remaining == [b]

    def test_the_pool_is_bounded(self):
        """More live (estate, loop) pairs than expected must not grow forever."""
        for i in range(es_mod._ES_POOL_MAX + 6):
            _get_es_client(
                {"Authorization": f"ApiKey k{i}", "Content-Type": "application/json"},
                None, False, self._timeout,
            )
        assert len(es_mod._es_pool) <= es_mod._ES_POOL_MAX
