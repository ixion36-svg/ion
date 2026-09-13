"""CSRF configuration loading and environment override tests."""

import json
import os
from pathlib import Path

import pytest

import ion.core.config
from ion.core.config import Config


@pytest.fixture
def reset_global_config(monkeypatch):
    """Reset the global _config singleton before each test."""
    # Save the original reference
    original_config = ion.core.config._config

    # Reset it to None before the test
    monkeypatch.setattr(ion.core.config, "_config", None)

    yield

    # Restore after the test
    monkeypatch.setattr(ion.core.config, "_config", original_config)


def test_from_file_loads_csrf_enabled_false(tmp_path):
    """Config.from_file loads csrf_enabled: false from JSON."""
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps({"csrf_enabled": False}))

    config = Config.from_file(config_file)
    assert config.csrf_enabled is False


def test_from_file_loads_csrf_enabled_true(tmp_path):
    """Config.from_file loads csrf_enabled: true from JSON."""
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps({"csrf_enabled": True}))

    config = Config.from_file(config_file)
    assert config.csrf_enabled is True


def test_from_file_defaults_csrf_enabled_to_true(tmp_path):
    """Config.from_file defaults csrf_enabled to true when not in JSON."""
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps({}))

    config = Config.from_file(config_file)
    assert config.csrf_enabled is True


def test_env_override_false_disables_csrf(monkeypatch, reset_global_config, tmp_path):
    """ION_CSRF_ENABLED=false in environment disables CSRF."""
    monkeypatch.setenv("ION_CSRF_ENABLED", "false")
    monkeypatch.chdir(tmp_path)

    # Create a minimal .ion/config.json with default csrf_enabled
    ion_dir = tmp_path / ".ion"
    ion_dir.mkdir()
    config_file = ion_dir / "config.json"
    config_file.write_text(json.dumps({"csrf_enabled": True}))

    from ion.core.config import get_config
    config = get_config()
    assert config.csrf_enabled is False


def test_file_config_survives_when_env_unset(monkeypatch, reset_global_config, tmp_path):
    """File-configured csrf_enabled: false survives when ION_CSRF_ENABLED is unset."""
    # Ensure the env var is not set
    monkeypatch.delenv("ION_CSRF_ENABLED", raising=False)
    monkeypatch.chdir(tmp_path)

    # Create .ion/config.json with csrf_enabled: false
    ion_dir = tmp_path / ".ion"
    ion_dir.mkdir()
    config_file = ion_dir / "config.json"
    config_file.write_text(json.dumps({"csrf_enabled": False}))

    from ion.core.config import get_config
    config = get_config()
    assert config.csrf_enabled is False


def test_default_csrf_enabled_true_when_nothing_set(monkeypatch, reset_global_config, tmp_path):
    """Default csrf_enabled is True when no file config and no env var."""
    monkeypatch.delenv("ION_CSRF_ENABLED", raising=False)
    monkeypatch.chdir(tmp_path)

    # No config file at all
    ion_dir = tmp_path / ".ion"
    ion_dir.mkdir()

    from ion.core.config import get_config
    config = get_config()
    assert config.csrf_enabled is True


def test_env_override_true_enables_csrf(monkeypatch, reset_global_config, tmp_path):
    """ION_CSRF_ENABLED=true in environment enables CSRF even if file has false."""
    monkeypatch.setenv("ION_CSRF_ENABLED", "true")
    monkeypatch.chdir(tmp_path)

    # Create a config.json with csrf_enabled: false
    ion_dir = tmp_path / ".ion"
    ion_dir.mkdir()
    config_file = ion_dir / "config.json"
    config_file.write_text(json.dumps({"csrf_enabled": False}))

    from ion.core.config import get_config
    config = get_config()
    assert config.csrf_enabled is True
