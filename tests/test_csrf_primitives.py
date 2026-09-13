"""Unit tests for the CSRF primitives — no app, no database, no I/O."""

import pytest

from ion.core.csrf import (
    derive_token,
    expected_origins,
    origin_allowed,
    tokens_match,
)


def test_derive_token_is_deterministic():
    assert derive_token("session-abc") == derive_token("session-abc")


def test_derive_token_differs_per_session():
    assert derive_token("session-abc") != derive_token("session-xyz")


def test_derive_token_is_not_the_session_token():
    assert derive_token("session-abc") != "session-abc"


def test_derive_token_empty_session_returns_empty():
    assert derive_token("") == ""


def test_tokens_match_accepts_the_derived_token():
    assert tokens_match("session-abc", derive_token("session-abc")) is True


def test_tokens_match_rejects_another_sessions_token():
    assert tokens_match("session-abc", derive_token("session-xyz")) is False


@pytest.mark.parametrize("presented", ["", "   ", "not-hex", "0" * 64])
def test_tokens_match_rejects_junk(presented):
    assert tokens_match("session-abc", presented) is False


def test_tokens_match_rejects_empty_session():
    assert tokens_match("", derive_token("session-abc")) is False


def test_expected_origins_includes_request_host():
    origins = expected_origins("ion.local:8000", "http", "https://ion.example", ())
    assert "http://ion.local:8000" in origins


def test_expected_origins_includes_configured_base_url():
    origins = expected_origins("ion.local", "http", "https://ion.example", ())
    assert "https://ion.example" in origins


def test_expected_origins_includes_extras_and_strips_paths():
    origins = expected_origins("ion.local", "http", "https://ion.example", ["https://alt.example/ignored"])
    assert "https://alt.example" in origins


def test_expected_origins_ignores_unparseable_values():
    origins = expected_origins("ion.local", "http", "not-a-url", ["also-not-a-url", ""])
    assert origins == {"http://ion.local"}


def test_origin_allowed_when_both_headers_absent():
    # curl / CI / integrations send neither. Rejecting would break automation
    # for no gain, since a hostile client can forge or omit the header anyway.
    assert origin_allowed("", "", {"https://ion.example"}) is True


def test_origin_allowed_when_origin_matches():
    assert origin_allowed("https://ion.example", "", {"https://ion.example"}) is True


def test_origin_rejected_when_origin_is_foreign():
    assert origin_allowed("https://evil.example", "", {"https://ion.example"}) is False


def test_origin_falls_back_to_referer_when_origin_absent():
    assert origin_allowed("", "https://ion.example/alerts", {"https://ion.example"}) is True


def test_origin_rejected_when_referer_is_foreign():
    assert origin_allowed("", "https://evil.example/x", {"https://ion.example"}) is False


def test_origin_rejected_when_literally_null():
    # A sandboxed iframe sends `Origin: null`. Present-but-unparseable must be
    # rejected, not treated as an absent header.
    assert origin_allowed("null", "", {"https://ion.example"}) is False


def test_origin_header_wins_over_referer():
    assert origin_allowed("https://evil.example", "https://ion.example/x", {"https://ion.example"}) is False
