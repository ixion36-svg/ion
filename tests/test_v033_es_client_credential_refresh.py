"""Tests for ES client credential-refresh fix (Finding #2 from CODE_REVIEW_ION.md).

Before the fix, _get_es_client() returned a stale cached client even when
credentials changed at runtime (admin wizard update). Now it compares a
fingerprint of (headers, auth) and recreates the client on mismatch.
"""

import pytest

import ion.services.elasticsearch_service as es_mod
from ion.services.elasticsearch_service import _creds_fingerprint, _get_es_client


@pytest.fixture(autouse=True)
def reset_es_client():
    """Reset module-level client state before and after every test."""
    es_mod._es_client = None
    es_mod._es_client_creds = None
    es_mod._es_client_loop = None
    yield
    if es_mod._es_client is not None and not es_mod._es_client.is_closed:
        import asyncio
        try:
            asyncio.run(es_mod._es_client.aclose())
        except Exception:
            pass
    es_mod._es_client = None
    es_mod._es_client_creds = None
    es_mod._es_client_loop = None


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

    def test_credential_fingerprint_updated_after_refresh(self):
        h1 = {"Authorization": "ApiKey key_A", "Content-Type": "application/json"}
        h2 = {"Authorization": "ApiKey key_B", "Content-Type": "application/json"}
        _get_es_client(h1, None, False, self._timeout)
        fp_after_first = es_mod._es_client_creds
        _get_es_client(h2, None, False, self._timeout)
        fp_after_second = es_mod._es_client_creds
        assert fp_after_first != fp_after_second
        assert fp_after_second == _creds_fingerprint(h2, None)


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

    def test_close_clears_creds(self):
        headers = {"Authorization": "ApiKey key_A", "Content-Type": "application/json"}
        _get_es_client(headers, None, False, self._timeout)
        assert es_mod._es_client_creds is not None
        es_mod._close_es_client()
        assert es_mod._es_client is None
        assert es_mod._es_client_creds is None
