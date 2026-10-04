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
    """The eight secrets stay in .env, so the UI must be able to badge them."""
    for field in (
        "elasticsearch_password",
        "kibana_password",
        "arkime_password",
        "gitlab_token",
        "opencti_token",
    ):
        assert field in ENV_FIELD_MAP
