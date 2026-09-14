"""Deliberate default positions for ION's feature flags and TLS verification.

Every default here was chosen rather than inherited, so each is pinned. The two
that matter most are the ones deliberately left OFF: shipping them on would be a
defensible choice, and without a test saying otherwise a later reader is likely
to "fix" them.
"""

import importlib
import logging
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import ion.core.config as config_mod  # noqa: E402

FLAG_ENV = {
    "alert_detail_v2": "ION_ALERT_DETAIL_V2",
    "alert_field_pins": "ION_ALERT_FIELD_PINS",
    "bob_custom_templates": "ION_BOB_CUSTOM_TEMPLATES",
    "chat_grounding_check": "ION_CHAT_GROUNDING_CHECK",
}


@pytest.fixture
def fresh_config(monkeypatch):
    """A Config built with no ION_* flag env vars set."""

    def _build(**env):
        for var in FLAG_ENV.values():
            monkeypatch.delenv(var, raising=False)
        for k, v in env.items():
            monkeypatch.setenv(k, v)
        monkeypatch.setattr(config_mod, "_config", None, raising=False)
        return config_mod.get_config()

    return _build


# --------------------------------------------------------------------------
# Graduated to on. These shipped opt-in and have since been the intended
# experience; opt-in kept them invisible to anyone who never read the env file.
# --------------------------------------------------------------------------


@pytest.mark.parametrize("flag", sorted(FLAG_ENV))
def test_graduated_features_default_on(fresh_config, flag):
    assert getattr(fresh_config(), flag) is True


@pytest.mark.parametrize("flag,var", sorted(FLAG_ENV.items()))
def test_each_can_still_be_turned_off(fresh_config, flag, var):
    assert getattr(fresh_config(**{var: "false"}), flag) is False


@pytest.mark.parametrize("flag,var", sorted(FLAG_ENV.items()))
def test_an_unrecognised_value_does_not_silently_disable(fresh_config, flag, var):
    """_get_env_bool falls back to its `default` arg, which for a default-on flag
    must be True -- otherwise a typo'd value turns the feature off in silence."""
    assert getattr(fresh_config(**{var: "maybe"}), flag) is True


def test_field_pins_needs_detail_v2_to_do_anything(fresh_config):
    """Pinning renders inside the v2 panel, so on-without-v2 would be inert."""
    cfg = fresh_config()
    assert cfg.alert_field_pins is True and cfg.alert_detail_v2 is True


# --------------------------------------------------------------------------
# Deliberately left off.
# --------------------------------------------------------------------------


def test_account_lockout_stays_opt_in(fresh_config):
    """Decided 2026-09-14: the self-lockout risk outweighs the brute-force
    protection for this estate. The implementation is complete and gated, not
    missing -- turn it on with ION_ACCOUNT_LOCKOUT_ENABLED=true."""
    assert fresh_config().account_lockout_enabled is False


def test_pii_anonymisation_stays_opt_in(fresh_config):
    """Decided 2026-09-14: Bob runs on-prem, so PII never leaves the estate and
    anonymising costs analysis fidelity -- Bob would see tokens, not hostnames."""
    assert fresh_config().pii_anon_enabled is False


def test_dev_and_debug_stay_off(fresh_config):
    cfg = fresh_config()
    assert cfg.dev_mode is False
    assert cfg.debug_mode is False


def test_response_actions_stay_off_and_dry_run_stays_on(fresh_config):
    """Two independent brakes on anything that touches a real firewall or EDR."""
    cfg = fresh_config()
    assert cfg.response_actions_enabled is False
    assert cfg.response_actions_live is False
    assert cfg.exec_dry_run is True


def test_the_security_controls_that_ship_on_stay_on(fresh_config):
    cfg = fresh_config()
    for flag in (
        "cookie_secure",
        "csrf_enabled",
        "webhook_require_signature",
        "enforce_password_change",
        "authz_alert_enabled",
    ):
        assert getattr(cfg, flag) is True, f"{flag} regressed to off"


# --------------------------------------------------------------------------
# TLS verification is off for the internal integrations by choice. The choice
# is only acceptable while it is loudly announced.
# --------------------------------------------------------------------------


def _startup_warnings(monkeypatch, **env):
    monkeypatch.setenv("ION_ADMIN_PASSWORD", "Tst-Startup-N0t-Real-9f3a2b")
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setattr(config_mod, "_config", None, raising=False)

    server = importlib.import_module("ion.web.server")
    captured = []

    class Capture(logging.Handler):
        def emit(self, record):
            captured.append(record.getMessage())

    handler = Capture()
    logger = logging.getLogger("ion.web.server")
    logger.addHandler(handler)
    try:
        server._validate_startup_config()
    except SystemExit:
        pass
    finally:
        logger.removeHandler(handler)
    return captured


def test_unverified_tls_is_announced_at_startup(monkeypatch):
    msgs = [m for m in _startup_warnings(monkeypatch) if "TLS certificate" in m]
    assert msgs, "unverified TLS is not announced anywhere at startup"
    text = msgs[0]
    assert "on-path attacker" in text, "the warning does not say what the risk is"
    assert "ION_CA_BUNDLE" in text, "the warning does not say how to fix it"


def test_the_warning_names_the_env_var_for_each_integration(monkeypatch):
    text = next(m for m in _startup_warnings(monkeypatch) if "TLS certificate" in m)
    assert "ION_ELASTICSEARCH_VERIFY_SSL=true" in text
    assert "ION_OIDC_VERIFY_SSL=true" in text


def test_disabled_integrations_are_not_named(monkeypatch):
    """Warning about TIDE on an estate that does not run TIDE is noise."""
    text = next(m for m in _startup_warnings(monkeypatch) if "TLS certificate" in m)
    assert "TIDE" not in text
    assert "Arkime" not in text
    assert "DFIR-IRIS" not in text


def test_no_warning_once_verification_is_on(monkeypatch):
    verified = {
        var: "true"
        for var in (
            "ION_OIDC_VERIFY_SSL",
            "ION_ELASTICSEARCH_VERIFY_SSL",
            "ION_KIBANA_VERIFY_SSL",
            "ION_OLLAMA_VERIFY_SSL",
            "ION_GITLAB_VERIFY_SSL",
            "ION_OPENCTI_VERIFY_SSL",
            "ION_ARKIME_VERIFY_SSL",
            "ION_TIDE_VERIFY_SSL",
            "ION_DFIR_IRIS_VERIFY_SSL",
        )
    }
    msgs = [m for m in _startup_warnings(monkeypatch, **verified) if "TLS certificate" in m]
    assert msgs == [], "warns even with verification fully on"


def test_verify_ssl_false_really_disables_verification():
    """get_ssl_verify is the single resolver; False must not quietly become True."""
    assert config_mod.get_ssl_verify(False) is False


def test_a_ca_bundle_is_only_used_when_verifying(monkeypatch):
    monkeypatch.setattr(config_mod, "_config", None, raising=False)
    monkeypatch.setenv("ION_CA_BUNDLE", "/etc/ssl/estate-ca.pem")
    assert config_mod.get_ssl_verify(True) == "/etc/ssl/estate-ca.pem"
    assert config_mod.get_ssl_verify(False) is False


def test_internet_facing_integrations_verify_by_default(fresh_config):
    """The internal/external split is the justification for the internal default."""
    cfg = fresh_config()
    for flag in ("virustotal_verify_ssl", "shodan_verify_ssl", "smtp_verify_ssl"):
        assert getattr(cfg, flag) is True, f"{flag} should verify — it leaves the estate"


def test_every_response_adapter_verifies_by_default(fresh_config):
    """These act on production infrastructure; an impersonated endpoint is worse."""
    cfg = fresh_config()
    for flag in (
        "exec_firewall_verify_ssl",
        "exec_dns_sinkhole_verify_ssl",
        "exec_edr_verify_ssl",
        "exec_email_gateway_verify_ssl",
        "exec_ad_verify_ssl",
    ):
        assert getattr(cfg, flag) is True, f"{flag} regressed"


# --------------------------------------------------------------------------
# Env-only flag, no config field.
# --------------------------------------------------------------------------


def test_chat_vector_rag_defaults_on(monkeypatch):
    from ion.services.ai_context_service import _chat_vector_rag_enabled

    monkeypatch.delenv("ION_CHAT_VECTOR_RAG", raising=False)
    assert _chat_vector_rag_enabled() is True
    monkeypatch.setenv("ION_CHAT_VECTOR_RAG", "false")
    assert _chat_vector_rag_enabled() is False


def test_no_flag_env_var_leaked_into_this_process():
    """A stray export would make every default test above vacuous."""
    leaked = [v for v in FLAG_ENV.values() if v in os.environ]
    assert leaked == [], f"env leaked into the test process: {leaked}"


# --------------------------------------------------------------------------
# .env.deploy claims, in its own header, that every flag is "shown at its
# built-in default". Nothing enforced that, which is how four lines came to
# advertise the opposite of what the code did.
# --------------------------------------------------------------------------


# Only the feature-flag block promises to show built-in defaults. Elsewhere a
# commented `#ION_X=true` is a fill-in-the-blanks template for enabling an
# integration, sitting beside `#ION_X_URL=REPLACE_WITH_...`, and means the
# opposite thing.
_FLAG_BLOCK_HEADER = "Feature flags"


def _env_deploy_bool_flags():
    """Commented `#ION_*=true|false` lines inside the feature-flag block only."""
    import re

    path = Path(__file__).resolve().parent.parent / ".env.deploy"
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()

    start = next(
        (i for i, ln in enumerate(lines) if _FLAG_BLOCK_HEADER in ln and ln.startswith("#")),
        None,
    )
    assert start is not None, (
        f"no {_FLAG_BLOCK_HEADER!r} block in .env.deploy — this test is scoped to it"
    )

    out = {}
    for line in lines[start:]:
        m = re.match(r"^#(ION_[A-Z0-9_]+)=(true|false)\s*(?:#.*)?$", line.strip())
        if m:
            out[m.group(1)] = m.group(2) == "true"
    assert out, "feature-flag block parsed as empty"
    return out


def _code_bool_defaults():
    """Map ION_* env var -> the Config field default it overrides."""
    import ast
    import re

    src = (Path(__file__).resolve().parent.parent / "src/ion/core/config.py").read_text(
        encoding="utf-8"
    )
    cls = next(
        n for n in ast.parse(src).body if isinstance(n, ast.ClassDef) and n.name == "Config"
    )
    field_default = {
        n.target.id: ast.literal_eval(n.value)
        for n in cls.body
        if isinstance(n, ast.AnnAssign)
        and isinstance(n.annotation, ast.Name)
        and n.annotation.id == "bool"
        and n.value is not None
    }
    out = {}
    for m in re.finditer(r'_config\.(\w+)\s*=\s*_get_env_bool\(\s*"([^"]+)"', src):
        field, var = m.group(1), m.group(2)
        if field in field_default:
            out[var] = field_default[field]
    return out


def test_env_deploy_advertises_the_real_defaults():
    documented = _env_deploy_bool_flags()
    actual = _code_bool_defaults()

    drift = {
        var: (documented[var], actual[var])
        for var in documented.keys() & actual.keys()
        if documented[var] != actual[var]
    }
    assert not drift, "\n".join(
        f"  {var}: .env.deploy says {d}, config.py defaults to {a}"
        for var, (d, a) in sorted(drift.items())
    )


def test_the_graduated_flags_are_documented_as_on():
    documented = _env_deploy_bool_flags()
    for var in FLAG_ENV.values():
        assert documented.get(var) is True, f"{var} not shown as on in .env.deploy"
