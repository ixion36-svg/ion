"""Regression test for the v0.31.8 python-jose → PyJWT migration.

The JWT validation path at src/ion/auth/oidc.py:OIDCValidator.validate_token
was previously implemented with python-jose. v0.31.8 retired python-jose
to drop the transitive `ecdsa` dep (CVE-2024-23342 Minerva timing attack
on P-256). PyJWT has the same semantics for our RS256-only Keycloak path
and drops the ecdsa transitive entirely.

These tests sign a token with a self-generated RSA keypair, expose the
public key to the validator via its in-memory JWKS cache, and assert
end-to-end happy path + tampering rejection. No network, no Keycloak.

If a future contributor swaps the JWT library again, these tests will
either pass (semantics preserved) or fail loudly (semantics drift).
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.utils import to_base64url_uint

from ion.auth.oidc import OIDCValidationError, OIDCValidator
from ion.auth.oidc_config import OIDCConfig


def _make_config() -> OIDCConfig:
    return OIDCConfig(
        enabled=True,
        keycloak_url="https://example.test",
        realm="r",
        client_id="client-x",
    )


def _make_keypair_and_jwk():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    nums = private.public_key().public_numbers()
    jwk = {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": "test-kid",
        "n": to_base64url_uint(nums.n).decode("ascii"),
        "e": to_base64url_uint(nums.e).decode("ascii"),
    }
    return private, jwk


def _issue_token(private_key, cfg: OIDCConfig, **claim_overrides):
    now = int(time.time())
    claims = {
        "sub": "user-123",
        "email": "a@b.com",
        "preferred_username": "ab",
        "aud": cfg.client_id,
        "iss": cfg.issuer_url,
        "iat": now,
        "exp": now + 3600,
        "realm_access": {"roles": ["analyst"]},
        "name": "A B",
    }
    claims.update(claim_overrides)
    return pyjwt.encode(claims, private_key, algorithm="RS256", headers={"kid": "test-kid"})


@pytest.fixture
def validator():
    cfg = _make_config()
    v = OIDCValidator(cfg)
    private, jwk = _make_keypair_and_jwk()
    v._jwks_cache = {"keys": [jwk]}
    v._jwks_cache_time = 1e12  # never expire for the test
    return v, private, cfg


def test_happy_path_returns_claims(validator):
    v, private, cfg = validator
    token = _issue_token(private, cfg)
    data = v.validate_token(token)
    assert data.sub == "user-123"
    assert data.email == "a@b.com"
    assert data.preferred_username == "ab"
    assert data.roles == ["analyst"]
    assert data.name == "A B"


def test_tampered_signature_rejected(validator):
    v, private, cfg = validator
    token = _issue_token(private, cfg)
    # Flip a couple of characters in the signature segment.
    bad = token[:-2] + ("AA" if not token.endswith("AA") else "BB")
    with pytest.raises(OIDCValidationError):
        v.validate_token(bad)


def test_expired_token_rejected(validator):
    v, private, cfg = validator
    # iat in the past, exp in the past.
    token = _issue_token(private, cfg, iat=1, exp=2)
    with pytest.raises(OIDCValidationError) as exc:
        v.validate_token(token)
    # Message includes 'expired' so callers can distinguish (the wrapper
    # raises a plain OIDCValidationError but preserves the underlying
    # PyJWT message — useful for diagnostics).
    assert "expired" in str(exc.value).lower()


def test_wrong_audience_rejected(validator):
    v, private, cfg = validator
    token = _issue_token(private, cfg, aud="some-other-client")
    with pytest.raises(OIDCValidationError):
        v.validate_token(token)


def test_wrong_issuer_rejected(validator):
    v, private, cfg = validator
    token = _issue_token(private, cfg, iss="https://attacker.test/realms/r")
    with pytest.raises(OIDCValidationError):
        v.validate_token(token)


def test_missing_kid_rejected(validator):
    v, private, cfg = validator
    now = int(time.time())
    # Sign a token without a kid header. PyJWT defaults to no kid unless
    # the headers dict supplies one, so we explicitly omit it here.
    token = pyjwt.encode(
        {
            "sub": "user-123",
            "email": "a@b.com",
            "preferred_username": "ab",
            "aud": cfg.client_id,
            "iss": cfg.issuer_url,
            "iat": now,
            "exp": now + 3600,
        },
        private,
        algorithm="RS256",
    )
    with pytest.raises(OIDCValidationError) as exc:
        v.validate_token(token)
    assert "key id" in str(exc.value).lower() or "kid" in str(exc.value).lower()


def test_unknown_kid_rejected(validator):
    v, private, cfg = validator
    now = int(time.time())
    token = pyjwt.encode(
        {
            "sub": "user-123",
            "email": "a@b.com",
            "preferred_username": "ab",
            "aud": cfg.client_id,
            "iss": cfg.issuer_url,
            "iat": now,
            "exp": now + 3600,
        },
        private,
        algorithm="RS256",
        headers={"kid": "some-other-kid"},
    )
    with pytest.raises(OIDCValidationError) as exc:
        v.validate_token(token)
    assert "not found in jwks" in str(exc.value).lower()


def test_missing_sub_rejected(validator):
    v, private, cfg = validator
    now = int(time.time())
    token = pyjwt.encode(
        {
            "email": "a@b.com",
            "preferred_username": "ab",
            "aud": cfg.client_id,
            "iss": cfg.issuer_url,
            "iat": now,
            "exp": now + 3600,
            # NOTE: no `sub` claim.
        },
        private,
        algorithm="RS256",
        headers={"kid": "test-kid"},
    )
    with pytest.raises(OIDCValidationError) as exc:
        v.validate_token(token)
    assert "sub" in str(exc.value).lower()
