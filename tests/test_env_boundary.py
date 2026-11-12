"""The shipped .env templates must match the agreed boundary.

The check runs both ways on purpose. A managed key reappearing would quietly
re-break the settings UI, and a missing required key is worse than untidy:
docker-compose.yml declares ION_DB_PASSWORD with `:?`, so Compose refuses to
start without it, and a template that omits it hands someone a file that
cannot boot.
"""
import re
from pathlib import Path

import pytest

from ion.core.config import BOOTSTRAP_ENV_KEYS, ENV_FIELD_MAP

# Only these two secrets are structurally pinned to the environment:
# Compose interpolates ION_DB_PASSWORD before ION exists, and
# ION_ADMIN_PASSWORD has no Config field so it cannot be stored at all.
# The other six integration secrets now live in config.json.
STRUCTURAL_ENV_KEYS = frozenset({
    "ION_DB_PASSWORD",
    "ION_ADMIN_PASSWORD",
})

TEMPLATES = ("env.example", "env.template")


def _keys(path: Path) -> set[str]:
    if not path.exists():
        pytest.skip(f"{path} not present")
    return set(re.findall(r"^([A-Z_]+)=", path.read_text(encoding="utf-8"), re.M))


@pytest.mark.parametrize("name", TEMPLATES)
def test_template_holds_only_secrets_and_bootstrap(name):
    repo_root = Path(__file__).resolve().parents[1]
    keys = _keys(repo_root / f".{name}")
    allowed = STRUCTURAL_ENV_KEYS | BOOTSTRAP_ENV_KEYS
    stray = sorted(keys - allowed)
    assert stray == [], (
        "these belong in the settings UI, not .env: " + ", ".join(stray)
    )


def test_bootstrap_and_managed_sets_do_not_overlap():
    managed = set(ENV_FIELD_MAP.values())
    assert not (managed & set(BOOTSTRAP_ENV_KEYS))


def test_structural_secrets_are_not_claimed_as_bootstrap():
    assert not (STRUCTURAL_ENV_KEYS & set(BOOTSTRAP_ENV_KEYS))


@pytest.mark.parametrize("name", TEMPLATES)
def test_template_holds_every_required_key(name):
    """One-directional checks let .env.example ship without ION_DB_PASSWORD."""
    repo_root = Path(__file__).resolve().parents[1]
    keys = _keys(repo_root / f".{name}")
    required = STRUCTURAL_ENV_KEYS | BOOTSTRAP_ENV_KEYS
    missing = sorted(required - keys)
    assert missing == [], (
        f".{name} is missing required keys: " + ", ".join(missing)
    )


# docker-compose.yml always injects these into the ion container, so they are
# environment-held whatever .env says and the template is where they are set.
COMPOSE_INJECTED = frozenset({"ION_BASE_URL", "ION_OLLAMA_URL", "ION_CA_BUNDLE"})


def _deploy_template() -> str:
    path = Path(__file__).resolve().parents[1] / ".env.deploy"
    if not path.exists():
        pytest.skip(".env.deploy not present")
    return path.read_text(encoding="utf-8")


def test_deploy_template_names_no_ui_managed_key():
    """.env.deploy is a working template people deploy from.

    It is not held to the 8-key boundary, because it carries deployment
    tuning with no Config field (resource limits, Postgres tuning, pool
    sizes). Every ENV_FIELD_MAP key is editable on the Settings page, and a
    live one here would silently override it on every deployment made from
    this file. Commented ones count too: they invite exactly that.
    """
    named = set(re.findall(r"^#?\s?([A-Z_][A-Z0-9_]*)=", _deploy_template(), re.M))
    stray = sorted((named & set(ENV_FIELD_MAP.values())) - COMPOSE_INJECTED)
    assert stray == [], (
        ".env.deploy names keys managed in the settings UI, which would "
        "silently override it: " + ", ".join(stray)
    )


def test_deploy_template_sets_both_structural_secrets():
    live = set(re.findall(r"^([A-Z_]+)=", _deploy_template(), re.M))
    assert STRUCTURAL_ENV_KEYS <= live


def test_deploy_template_sets_no_database_url():
    """Compose builds ION_DATABASE_URL from ION_DB_PASSWORD and its
    `environment:` entry outranks env_file, so a URL here is dead and a
    second copy of the password to get out of step."""
    assert not re.search(r"^ION_DATABASE_URL=", _deploy_template(), re.M)


# ── Consequences of the pruning ──
#
# Removing a key from .env hands the decision to whatever default was behind
# it. ION_COOKIE_SECURE is the case that bit: docker-entrypoint.sh seeded the
# first-boot config.json with
# `cookie_secure=os.environ.get('ION_COOKIE_SECURE', 'false') == 'true'`, which
# was harmless while .env.template shipped ION_COOKIE_SECURE=true and became
# the operative value the moment the key left. Config's own default is True;
# the entrypoint must not override it.

ENTRYPOINT = "docker-entrypoint.sh"


def test_entrypoint_does_not_seed_cookie_secure():
    repo_root = Path(__file__).resolve().parents[1]
    path = repo_root / ENTRYPOINT
    if not path.exists():
        pytest.skip(f"{ENTRYPOINT} not present")
    text = path.read_text(encoding="utf-8")
    assert "cookie_secure=os.environ.get" not in text, (
        "docker-entrypoint.sh is seeding cookie_secure again. Its env default "
        "decides the value for every fresh deployment and persists it to "
        "config.json, where get_config() finds no environment variable to "
        "correct it. Leave it out: Config defaults it True, and get_config() "
        "still applies ION_COOKIE_SECURE and the dev_mode relaxation."
    )


def test_a_pruned_env_still_yields_secure_cookies(monkeypatch, tmp_path):
    """The end state the test above protects, asserted end to end.

    Replicates the entrypoint's first-boot seed with .env pruned to the 8-key
    boundary, then loads the config the way the app does.
    """
    from ion.core import config as config_mod
    from ion.core.config import Config

    for key in ("ION_COOKIE_SECURE", "ION_DEV_MODE"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("ION_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(config_mod, "_config", None, raising=False)

    # docker-entrypoint.sh, first boot: db_path and oidc_enabled only.
    Config(
        db_path=tmp_path / ".ion" / "ion.db",
        oidc_enabled=False,
    ).to_file(tmp_path / ".ion" / "config.json")

    assert config_mod.get_config().cookie_secure is True
    monkeypatch.setattr(config_mod, "_config", None, raising=False)


def test_dev_mode_can_still_relax_the_cookie(monkeypatch, tmp_path):
    """Not seeding it must not break plain-HTTP development.

    get_config() drops cookie_secure when dev_mode is on, so the relaxation
    survives without the entrypoint writing anything.
    """
    from ion.core import config as config_mod

    monkeypatch.delenv("ION_COOKIE_SECURE", raising=False)
    monkeypatch.setenv("ION_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("ION_DEV_MODE", "true")
    monkeypatch.setattr(config_mod, "_config", None, raising=False)
    assert config_mod.get_config().cookie_secure is False
    monkeypatch.setattr(config_mod, "_config", None, raising=False)
