"""Security defaults from the external review: ION-04, ION-05, ION-06.

All three findings had the same shape. The control existed and was correctly
built -- HMAC verification with compare_digest, the must_change_password gate,
the Secure cookie flag -- and shipped switched off, so a deployment that never
read the docs ran without it. A control that ships disabled is not a control.

These tests pin the defaults, not the mechanisms; the mechanisms have their own
tests. What must not regress is that ION is safe when nothing is configured,
and that relaxing it takes an explicit, named, logged opt-out (ION_DEV_MODE).
"""

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ion.core.config import Config  # noqa: E402


@pytest.fixture
def clean_env(monkeypatch):
    """A process with none of the security env vars set."""
    for var in (
        "ION_DEV_MODE",
        "ION_COOKIE_SECURE",
        "ION_WEBHOOK_REQUIRE_SIGNATURE",
        "ION_ENFORCE_PASSWORD_CHANGE",
        "ION_ADMIN_PASSWORD",
    ):
        monkeypatch.delenv(var, raising=False)
    return monkeypatch


# --------------------------------------------------------------------------
# ION-06 / ION-05 / ION-04: the defaults themselves
# --------------------------------------------------------------------------

def test_secure_flags_default_on():
    c = Config()
    assert c.cookie_secure is True, "ION-06: Secure cookie flag must default on"
    assert c.webhook_require_signature is True, "ION-05: signature enforcement must default on"
    assert c.enforce_password_change is True, "ION-04: password-change gate must default on"


def test_dev_mode_defaults_off():
    assert Config().dev_mode is False


def test_config_file_without_the_keys_keeps_the_secure_defaults(tmp_path):
    """A config.json written before the flip must not silently restore the old behaviour.

    Config.from_file supplies its own per-key defaults, so flipping only the
    dataclass default would leave every existing deployment insecure.
    """
    path = tmp_path / "config.json"
    path.write_text('{"base_url": "https://ion.example"}', encoding="utf-8")
    c = Config.from_file(path)
    assert c.base_url == "https://ion.example", "guard: the file must actually be read"
    assert c.cookie_secure is True
    assert c.webhook_require_signature is True
    assert c.enforce_password_change is True


def test_config_file_can_still_turn_them_off(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(
        '{"cookie_secure": false, "webhook_require_signature": false,'
        ' "enforce_password_change": false}',
        encoding="utf-8",
    )
    c = Config.from_file(path)
    assert c.cookie_secure is False
    assert c.webhook_require_signature is False
    assert c.enforce_password_change is False


# --------------------------------------------------------------------------
# ION-06: dev_mode is the only thing that relaxes the cookie
# --------------------------------------------------------------------------

def test_dev_mode_drops_cookie_secure(clean_env):
    import ion.core.config as cfg

    clean_env.setenv("ION_DEV_MODE", "true")
    cfg._config = None
    try:
        c = cfg.get_config()
        assert c.dev_mode is True
        assert c.cookie_secure is False, "plain-HTTP dev needs the Secure flag off or login breaks"
    finally:
        cfg._config = None


def test_explicit_cookie_secure_beats_dev_mode(clean_env):
    """ION_COOKIE_SECURE is an explicit instruction; dev_mode is only a default-shifter."""
    import ion.core.config as cfg

    clean_env.setenv("ION_DEV_MODE", "true")
    clean_env.setenv("ION_COOKIE_SECURE", "true")
    cfg._config = None
    try:
        assert cfg.get_config().cookie_secure is True
    finally:
        cfg._config = None


def test_no_env_at_all_is_secure(clean_env):
    import ion.core.config as cfg

    cfg._config = None
    try:
        c = cfg.get_config()
        assert c.dev_mode is False
        assert c.cookie_secure is True
    finally:
        cfg._config = None


# --------------------------------------------------------------------------
# ION-04: a weak admin password blocks startup outside dev
# --------------------------------------------------------------------------

@pytest.mark.parametrize("password", ["changeme", "admin", "password"])
def test_weak_admin_password_blocks_startup(clean_env, password):
    """The fallback when ION_ADMIN_PASSWORD is unset is the literal "changeme"."""
    import ion.core.config as cfg
    import ion.web.server as server

    clean_env.setenv("ION_ADMIN_PASSWORD", password)
    cfg._config = None
    try:
        with pytest.raises(SystemExit):
            server._validate_startup_config()
    finally:
        cfg._config = None


def test_unset_admin_password_blocks_startup(clean_env):
    import ion.core.config as cfg
    import ion.web.server as server

    assert "ION_ADMIN_PASSWORD" not in os.environ
    cfg._config = None
    try:
        with pytest.raises(SystemExit):
            server._validate_startup_config()
    finally:
        cfg._config = None


def test_dev_mode_downgrades_it_to_a_warning(clean_env):
    import ion.core.config as cfg
    import ion.web.server as server

    clean_env.setenv("ION_DEV_MODE", "true")
    clean_env.setenv("ION_ADMIN_PASSWORD", "changeme")
    cfg._config = None
    try:
        server._validate_startup_config()  # must not raise
    finally:
        cfg._config = None


def test_strong_admin_password_starts(clean_env):
    import ion.core.config as cfg
    import ion.web.server as server

    clean_env.setenv("ION_ADMIN_PASSWORD", "t8Qv-Zr2%wLm9Kd!xPa4")
    cfg._config = None
    try:
        server._validate_startup_config()
    finally:
        cfg._config = None


# --------------------------------------------------------------------------
# ION-05: a webhook that can never deliver is refused at creation
# --------------------------------------------------------------------------

def test_creating_a_secretless_webhook_is_refused_while_enforcement_is_on(clean_env):
    """The receiver rejects unsigned deliveries, so a secret-less webhook is dead on arrival."""
    import ion.core.config as cfg
    from ion.services.webhook_service import WebhookService

    cfg._config = None
    try:
        assert cfg.get_config().webhook_require_signature is True
        with pytest.raises(ValueError, match="secret is required"):
            WebhookService().create_webhook(name="dead-on-arrival", secret=None)
    finally:
        cfg._config = None


def test_to_file_from_file_round_trip_preserves_an_explicit_opt_out(tmp_path):
    """to_file and from_file must agree on key shape, or a saved opt-out is lost."""
    path = tmp_path / "config.json"
    c = Config()
    c.cookie_secure = False
    c.webhook_require_signature = False
    c.to_file(path)
    back = Config.from_file(path)
    assert back.cookie_secure is False
    assert back.webhook_require_signature is False
