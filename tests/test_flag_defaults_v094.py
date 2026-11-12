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

# Default-OFF flags whose env var the fixture must also clear, or an ambient
# value in the shell would make the "stays opt-in" assertions below pass or
# fail for the wrong reason.
OPT_IN_ENV = {
    "comm_templates_seed": "ION_COMM_TEMPLATES_SEED",
}


@pytest.fixture
def fresh_config(monkeypatch):
    """A Config built with no ION_* flag env vars set."""

    def _build(**env):
        for var in (*FLAG_ENV.values(), *OPT_IN_ENV.values()):
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


def test_comm_template_seeding_stays_opt_in(fresh_config):
    """Startup seeding is the ONLY path by which rows reach comm_templates --
    there is no seeding endpoint and no UI -- so defaulting it on would mean
    every boot wrote six rows into a production database nobody asked for.
    Turn it on with ION_COMM_TEMPLATES_SEED=true; it is idempotent once on."""
    assert fresh_config().comm_templates_seed is False


def test_comm_template_seeding_can_be_turned_on(fresh_config):
    assert fresh_config(ION_COMM_TEMPLATES_SEED="true").comm_templates_seed is True


def test_a_typod_seeding_value_does_not_silently_enable(fresh_config):
    """_get_env_bool falls back to its `default`, which for this flag is False --
    so a typo leaves the database untouched rather than writing to it."""
    assert fresh_config(ION_COMM_TEMPLATES_SEED="maybe").comm_templates_seed is False


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
# .env.deploy shows each optional knob at its built-in default, apart from the
# master switch of an opt-in section. Nothing enforced that, which is how four
# lines came to advertise the opposite of what the code did. The UI-managed
# flags this used to check left the file: Settings shows their live values.
# --------------------------------------------------------------------------

_KNOB_BLOCK_HEADER = "Optional knobs with no settings-UI field"

# Shown set to the value that enables them; their code default is off.
_OPT_IN_SWITCHES = {
    "ION_METRICS_ENABLED",
    "ION_APM_ENABLED",
    "ION_ARKIME_RTMON_ENABLED",
    "ION_AI_LARGE_PDF_ENABLED",
}


def _documented_knobs() -> dict[str, str]:
    import re

    text = (Path(__file__).resolve().parent.parent / ".env.deploy").read_text(encoding="utf-8")
    assert _KNOB_BLOCK_HEADER in text, f"no {_KNOB_BLOCK_HEADER!r} block in .env.deploy"
    block = text[text.index(_KNOB_BLOCK_HEADER):]
    return {
        k: v.split("#")[0].strip()
        for k, v in re.findall(r"^#([A-Z_][A-Z0-9_]*)=(.*)$", block, re.M)
    }


def _literal_defaults() -> dict[str, set[str]]:
    """VAR -> the literal defaults its readers pass, normalised to text.

    A default given as a named constant is not literal and is left out, so
    a knob read only that way is not checked here.
    """
    import re

    call = re.compile(
        r'\w+\(\s*["\'](ION_[A-Z0-9_]+)["\']\s*,\s*'
        r'(?:["\']([^"\']*)["\']|(True|False|-?\d+(?:\.\d+)?))\s*\)'
    )
    out: dict[str, set[str]] = {}
    for path in (Path(__file__).resolve().parent.parent / "src/ion").rglob("*.py"):
        for var, text, bare in call.findall(path.read_text(encoding="utf-8", errors="ignore")):
            out.setdefault(var, set()).add((text if not bare else bare).lower())
    return out


def _same(documented: str, code: str) -> bool:
    try:
        return float(documented) == float(code)
    except ValueError:
        return documented.lower() == code


def test_env_deploy_advertises_the_real_defaults():
    documented = _documented_knobs()
    actual = _literal_defaults()
    checked = [
        k for k in documented
        if k in actual and k not in _OPT_IN_SWITCHES and "REPLACE_WITH" not in documented[k]
    ]
    # A pattern that stopped matching would compare nothing and pass.
    assert len(checked) > 30, f"only {len(checked)} knobs had a literal default"
    drift = {
        k: (documented[k], sorted(actual[k]))
        for k in checked
        if not any(_same(documented[k], c) for c in actual[k])
    }
    assert not drift, "\n".join(
        f"  {k}: .env.deploy says {d!r}, code defaults to {c}" for k, (d, c) in sorted(drift.items())
    )


def test_opt_in_switches_are_really_off_by_default():
    actual = _literal_defaults()
    documented = _documented_knobs()
    for var in _OPT_IN_SWITCHES:
        assert documented.get(var) == "true", f"{var} not shown as the switch to turn on"
        assert actual.get(var, {""}) <= {"", "false", "0"}, f"{var} defaults on: {actual.get(var)}"
