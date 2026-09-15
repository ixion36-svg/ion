"""v0.97.0 — DE module Phase 4: offline licence verification + availability gating.

Enforcement ships dormant (ION_DE_LICENSE_ENFORCED off) so the module behaves as
before; these pin both the crypto and the gate matrix for when it is turned on.
"""

import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ion.licensing import gating
from ion.licensing.licence_service import LicenceService, LicenceStatus


def _keypair():
    priv = Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return priv_pem, pub_pem


def _mint(priv_pem, modules=("detection_engineering",), exp=None, customer="acme"):
    claims = {"customer_id": customer, "modules": list(modules),
              "licence_id": "t", "iat": int(time.time())}
    if exp is not None:
        claims["exp"] = exp
    return jwt.encode(claims, priv_pem, algorithm="EdDSA")


# ── licence verification ─────────────────────────────────────────────────────

def test_valid_licence_entitles_module():
    priv, pub = _keypair()
    st = LicenceService(public_key_pem=pub).verify(_mint(priv))
    assert st.valid and st.entitles("detection_engineering")
    assert st.customer_id == "acme" and not st.expired


def test_wrong_key_rejected():
    priv, _ = _keypair()
    _, other_pub = _keypair()
    assert not LicenceService(public_key_pem=other_pub).verify(_mint(priv)).valid


def test_tampered_rejected():
    priv, pub = _keypair()
    tok = _mint(priv)
    assert not LicenceService(public_key_pem=pub).verify(tok[:-4] + "aaaa").valid


def test_empty_source_is_invalid():
    _, pub = _keypair()
    assert not LicenceService(public_key_pem=pub).verify("").valid


def test_expired_is_signed_but_flagged():
    """Signed-but-expired stays valid+entitled; expiry is informational here."""
    priv, pub = _keypair()
    st = LicenceService(public_key_pem=pub).verify(_mint(priv, exp=int(time.time()) - 10))
    assert st.valid and st.expired and st.entitles("detection_engineering")


def test_modules_must_be_a_list():
    priv, pub = _keypair()
    tok = jwt.encode(
        {"customer_id": "x", "modules": "detection_engineering", "iat": int(time.time())},
        priv, algorithm="EdDSA",
    )
    assert not LicenceService(public_key_pem=pub).verify(tok).valid


# ── availability gating ──────────────────────────────────────────────────────

class _StubLicence:
    def __init__(self, status):
        self._s = status

    def status(self):
        return self._s


def _configure(monkeypatch, *, enforced, flag, status=None):
    from ion.core.config import get_config
    cfg = get_config()
    monkeypatch.setattr(cfg, "de_license_enforced", enforced, raising=False)
    monkeypatch.setattr(cfg, "de_module_enabled", flag, raising=False)
    monkeypatch.setattr(gating, "get_licence_service",
                        lambda: _StubLicence(status or LicenceStatus()))


def test_dormant_default_is_available(monkeypatch):
    _configure(monkeypatch, enforced=False, flag=False)
    assert gating.de_module_available() is True


def test_enforced_flag_off_is_dark(monkeypatch):
    _configure(monkeypatch, enforced=True, flag=False,
               status=LicenceStatus(valid=True, modules=["detection_engineering"]))
    assert gating.de_module_available() is False


def test_enforced_no_licence_is_dark(monkeypatch):
    _configure(monkeypatch, enforced=True, flag=True, status=LicenceStatus(valid=False))
    assert gating.de_module_available() is False


def test_enforced_and_licensed_is_available(monkeypatch):
    _configure(monkeypatch, enforced=True, flag=True,
               status=LicenceStatus(valid=True, modules=["detection_engineering"]))
    assert gating.de_module_available() is True


def test_enforced_wrong_module_is_dark(monkeypatch):
    _configure(monkeypatch, enforced=True, flag=True,
               status=LicenceStatus(valid=True, modules=["some_other_module"]))
    assert gating.de_module_available() is False


def test_require_de_module_404_when_dark(monkeypatch):
    from fastapi import HTTPException
    _configure(monkeypatch, enforced=True, flag=False, status=LicenceStatus(valid=False))
    with pytest.raises(HTTPException) as ei:
        gating.require_de_module()
    assert ei.value.status_code == 404


def test_require_de_module_passes_when_available(monkeypatch):
    _configure(monkeypatch, enforced=False, flag=False)
    assert gating.require_de_module() is None
