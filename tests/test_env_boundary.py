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
