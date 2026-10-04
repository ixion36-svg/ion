"""Where did each config value actually come from?

The settings UI renders environment-backed fields read-only, so a wrong answer
here is worse than no answer: it invites an edit that silently does nothing.
"""
import dataclasses

import pytest

from ion.core import config as config_mod
from ion.core.config import (
    ENV_FIELD_MAP,
    Config,
    config_field_source,
    config_field_sources,
)


@pytest.fixture(autouse=True)
def _reset_config(monkeypatch):
    """Each test starts from a known, un-cached config."""
    monkeypatch.setattr(config_mod, "_config", None, raising=False)
    yield
    monkeypatch.setattr(config_mod, "_config", None, raising=False)


def test_every_mapped_field_exists_on_config():
    """A typo in the map would silently report 'default' forever."""
    known = {f.name for f in dataclasses.fields(Config)}
    unknown = sorted(set(ENV_FIELD_MAP) - known)
    assert unknown == [], f"ENV_FIELD_MAP names fields that do not exist: {unknown}"


def test_env_backed_field_reports_environment(monkeypatch):
    monkeypatch.setenv("ION_ELASTICSEARCH_URL", "http://es.example:9200")
    assert config_field_source("elasticsearch_url") == "environment"


def test_blank_env_var_is_not_a_source(monkeypatch):
    """An empty value is how people 'unset' a key in .env; it must not count."""
    monkeypatch.setenv("ION_ELASTICSEARCH_URL", "   ")
    assert config_field_source("elasticsearch_url") != "environment"


def test_file_backed_field_reports_file(monkeypatch, tmp_path):
    monkeypatch.delenv("ION_ELASTICSEARCH_URL", raising=False)
    cfg_dir = tmp_path / ".ion"
    cfg_dir.mkdir()
    (cfg_dir / "config.json").write_text(
        '{"elasticsearch_url": "http://from-file:9200"}', encoding="utf-8"
    )
    monkeypatch.setenv("ION_DATA_DIR", str(tmp_path))
    assert config_field_source("elasticsearch_url") == "file"


def test_unset_field_reports_default(monkeypatch, tmp_path):
    monkeypatch.delenv("ION_ELASTICSEARCH_URL", raising=False)
    monkeypatch.setenv("ION_DATA_DIR", str(tmp_path))
    assert config_field_source("elasticsearch_url") == "default"


def test_unmapped_field_reports_default():
    assert config_field_source("not_a_real_field") == "default"


def test_sources_covers_the_whole_map(monkeypatch, tmp_path):
    monkeypatch.setenv("ION_DATA_DIR", str(tmp_path))
    sources = config_field_sources()
    assert set(sources) == set(ENV_FIELD_MAP)
    assert set(sources.values()) <= {"environment", "file", "default"}


def test_secret_fields_are_mapped():
    """These stay badgeable: if anyone re-adds the env var, the UI must say so.

    (They no longer live in .env — Config.to_file persists them to config.json —
    but an operator re-adding one must not get a silent override.)
    """
    for field in (
        "elasticsearch_password",
        "kibana_password",
        "arkime_password",
        "gitlab_token",
        "opencti_token",
    ):
        assert field in ENV_FIELD_MAP


def test_env_field_map_matches_override_block():
    """ENV_FIELD_MAP must cover every override get_config() actually applies.

    The map is what the settings UI badges. A field that get_config() reads from
    the environment but the map omits is editable in the UI and silently
    overridden with no badge — the exact failure this whole mechanism exists to
    prevent. This test re-derives the pairs from the source and compares, so
    adding an override without a map entry fails here rather than in the field.

    Regenerate the map rather than hand-editing it.
    """
    import dataclasses
    import re
    from pathlib import Path

    src = Path(__file__).resolve().parents[1] / "src" / "ion" / "core" / "config.py"
    text = src.read_text(encoding="utf-8")
    known = {f.name for f in dataclasses.fields(Config)}

    derived = {}
    pattern = re.compile(
        r"_config\.([a-z_0-9]+)\s*=\s*(.+?)"
        r"(?=\n\s*(?:if|elif|else|_config\.|#|try|except|for|return|\Z))",
        re.S,
    )
    for match in pattern.finditer(text):
        field, rhs = match.group(1), match.group(2)
        if field not in known:
            continue
        envs = [
            e for e in re.findall(r'"([A-Z][A-Z0-9_]*)"', rhs)
            if e.startswith(("ION_", "OLLAMA_"))
        ]
        if envs:
            derived.setdefault(field, envs[0])

    missing = sorted(set(derived) - set(ENV_FIELD_MAP))
    assert missing == [], (
        "get_config() reads these from the environment but ENV_FIELD_MAP omits "
        "them, so the UI cannot badge them: " + ", ".join(missing)
    )

    disagree = {
        f: (ENV_FIELD_MAP[f], derived[f])
        for f in derived
        if ENV_FIELD_MAP.get(f) != derived[f]
    }
    assert disagree == {}, f"map disagrees with the override block: {disagree}"


def test_indirect_overrides_are_mapped():
    """Some overrides are invisible to the generator, and must not be dropped.

    get_config() assigns base_url from a local (`_env_base_url`) rather than
    from a literal os.environ.get call, so regenerating ENV_FIELD_MAP from the
    source silently lost it once already. The field is genuinely environment
    held — docker-compose.yml injects ION_BASE_URL with a default — so losing
    it means the settings UI offers an edit that cannot win, with no badge.
    """
    indirect = {"base_url": "ION_BASE_URL"}
    for field, env in indirect.items():
        assert ENV_FIELD_MAP.get(field) == env, (
            f"{field} must stay mapped to {env}; the generator cannot derive it"
        )
