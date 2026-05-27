"""Tests for ES client credential-refresh fix (Finding #2 from CODE_REVIEW_ION.md).

Before the fix, _get_es_client() returned a stale cached client even when
credentials changed at runtime (admin wizard update). Now it compares a
fingerprint of (headers, auth) and recreates the client on mismatch.
"""

import pytest

import ion.services.elasticsearch_service as es_mod
from ion.services.elasticsearch_service import _get_es_client, _creds_fingerprint


@pytest.fixture(autouse=True)
def reset_es_client():
    """Reset module-level client state before and after every test."""
    es_mod._es_client = None
    es_mod._es_client_creds = None
    yield
    if es_mod._es_client is not None and not es_mod._es_client.is_closed:
        import asyncio
        try:
            loop = asyncio.get_event_loop()
            loop.run_until_complete(es_mod._es_client.aclose())
        except Exception:
            pass
    es_mod._es_client = None
    es_mod._es_client_creds = None


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

    def test_close_clears_creds(self):
        headers = {"Authorization": "ApiKey key_A", "Content-Type": "application/json"}
        _get_es_client(headers, None, False, self._timeout)
        assert es_mod._es_client_creds is not None
        es_mod._close_es_client()
        assert es_mod._es_client is None
        assert es_mod._es_client_creds is None
