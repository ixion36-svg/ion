"""Every setting the UI shows must also be savable.

Three hand-maintained lists describe ION's configuration and all three had
drifted apart:

    Config dataclass   162 fields   what the application reads
    ENV_FIELD_MAP      151 fields   what an environment variable can set
    Config.to_file     141 fields   what a save actually writes

So twenty settings could be set in memory, reported as saved, and quietly
lost on the next start -- ``response_actions_enabled``,
``response_actions_live``, ``csrf_enabled``, ``multi_tenant``,
``ca_bundle``, ``workforce_enabled`` among them. ``from_file`` reads all
162 back, so only the write side dropped them: the exact "a save that
reports success and changes nothing" failure that the ``_drop_env_held``
docstring says v0.99.7 exists to close, still live for those twenty.

The fix is to stop hand-listing. ``to_file`` now serialises the dataclass,
so a field added to ``Config`` is persisted without anyone remembering,
and the three lists can only agree.

On top of that, a generic field update so the settings inventory is
editable rather than merely visible. The rules it has to hold:

* an environment-held field is never written, because ``get_config`` ranks
  the environment above the file and the save would be a no-op that
  reported success;
* a value is coerced to the field's declared type, or rejected -- storing
  the string "false" in a boolean is how a disabled feature turns itself
  back on;
* an unknown field name is rejected rather than silently attached to the
  config object, where it would read back fine and never be persisted;
* a blank secret means "keep the current one", matching every existing
  form on the page, so saving a section does not wipe credentials the
  operator could not see to retype.
"""

from __future__ import annotations

import dataclasses
import json
import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from ion.core.config import ENV_FIELD_MAP, Config
from ion.web.admin_api import coerce_config_value, is_field_editable_via_api


# -- Persistence coverage --------------------------------------------------


class TestEverySettingPersists:
    @pytest.fixture
    def saved(self, tmp_path):
        config = Config()
        path = tmp_path / "config.json"
        config.to_file(path)
        return json.loads(path.read_text(encoding="utf-8"))

    def test_every_env_backed_field_is_written(self, saved):
        missing = sorted(set(ENV_FIELD_MAP) - set(saved))
        assert not missing, (
            f"{len(missing)} settings can be set but not saved, so a save "
            f"reports success and loses them: {missing[:12]}"
        )

    @pytest.mark.parametrize("field", [
        "response_actions_enabled",
        "response_actions_live",
        "csrf_enabled",
        "multi_tenant",
        "ca_bundle",
        "workforce_enabled",
    ])
    def test_the_fields_that_were_dropped_are_written(self, saved, field):
        assert field in saved

    def test_it_is_not_a_hand_written_list(self, saved):
        """Derived from the dataclass, so the three lists cannot drift
        again. Asserting the relationship, not a count."""
        names = {f.name for f in dataclasses.fields(Config)}
        assert set(saved) == names

    def test_a_round_trip_preserves_values(self, tmp_path):
        config = Config()
        config.response_actions_live = True
        config.csrf_enabled = False
        config.max_versions_to_keep = 7
        path = tmp_path / "config.json"
        config.to_file(path)

        back = Config.from_file(path)
        assert back.response_actions_live is True
        assert back.csrf_enabled is False
        assert back.max_versions_to_keep == 7

    def test_paths_survive_the_round_trip(self, tmp_path):
        """db_path is a Path, which json cannot serialise directly."""
        config = Config()
        path = tmp_path / "config.json"
        config.to_file(path)
        raw = json.loads(path.read_text(encoding="utf-8"))
        assert isinstance(raw["db_path"], str)
        assert Path(Config.from_file(path).db_path) == Path(config.db_path)

    def test_the_file_is_still_written_private(self, tmp_path):
        """It holds credentials in plaintext. Rebuilding the writer must not
        lose the 0600."""
        import os
        import stat
        path = tmp_path / "config.json"
        Config().to_file(path)
        mode = stat.S_IMODE(os.stat(path).st_mode)
        if os.name == "nt":
            pytest.skip("POSIX mode bits are not meaningful on Windows")
        assert mode == 0o600, oct(mode)


# -- Type coercion ---------------------------------------------------------


class TestCoercion:
    @pytest.mark.parametrize("raw,expected", [
        (True, True), (False, False),
        ("true", True), ("True", True), ("1", True), ("yes", True), ("on", True),
        ("false", False), ("False", False), ("0", False), ("no", False), ("off", False),
    ])
    def test_booleans(self, raw, expected):
        assert coerce_config_value("csrf_enabled", raw) is expected

    def test_a_non_boolean_string_is_rejected(self):
        """Storing "maybe" as truthy is how a disabled feature turns itself
        back on."""
        with pytest.raises(ValueError):
            coerce_config_value("csrf_enabled", "maybe")

    @pytest.mark.parametrize("raw,expected", [(5, 5), ("5", 5), (" 7 ", 7)])
    def test_integers(self, raw, expected):
        assert coerce_config_value("max_versions_to_keep", raw) == expected

    @pytest.mark.parametrize("raw", ["", "abc", "1.5", None])
    def test_a_non_integer_is_rejected(self, raw):
        with pytest.raises(ValueError):
            coerce_config_value("max_versions_to_keep", raw)

    def test_strings_pass_through(self):
        assert coerce_config_value("oidc_realm", "ion") == "ion"

    def test_a_string_field_accepts_an_empty_value(self):
        """Clearing a non-secret string is a legitimate edit."""
        assert coerce_config_value("oidc_realm", "") == ""

    def test_an_unknown_field_is_rejected(self):
        """Setting an unknown name would attach to the config object, read
        back fine for the rest of the process, and never persist."""
        with pytest.raises(ValueError):
            coerce_config_value("not_a_real_setting", "x")

    def test_a_boolean_field_does_not_accept_an_integer_string_by_accident(self):
        assert coerce_config_value("csrf_enabled", "0") is False


# -- What may be written at all --------------------------------------------


class TestEditability:
    def test_a_known_field_is_editable(self):
        assert is_field_editable_via_api("response_actions_live") is True

    def test_an_unknown_field_is_not(self):
        assert is_field_editable_via_api("nonsense") is False

    def test_db_path_is_not_editable(self):
        """Repointing the database from a settings form would detach the
        running application from its own data, mid-request, with no
        migration and no way back through the same screen."""
        assert is_field_editable_via_api("db_path") is False

    def test_a_restart_required_field_is_declared(self):
        """An operator who turns CSRF back on and sees "updated" is
        entitled to think the application is protected. It is bound into
        middleware at startup, so it is not."""
        from ion.web.admin_api import _RESTART_REQUIRED
        assert "csrf_enabled" in _RESTART_REQUIRED
        assert "debug_mode" in _RESTART_REQUIRED

    def test_a_live_field_is_not_declared_restart_required(self):
        """Over-declaring costs a needless restart; under-declaring costs a
        setting the operator believes is in force. Both matter, so the list
        is not simply everything."""
        from ion.web.admin_api import _RESTART_REQUIRED
        assert "oidc_realm" not in _RESTART_REQUIRED
        assert "elasticsearch_url" not in _RESTART_REQUIRED

    def test_an_environment_held_field_is_refused(self, monkeypatch):
        """get_config ranks the environment above the file, so writing one
        of these stores a value that never takes effect."""
        from ion.core import config as config_mod
        from ion.web.admin_api import env_blocks_write

        monkeypatch.setenv("ION_CSRF_ENABLED", "true")
        config_mod.set_config(None)
        try:
            assert env_blocks_write("csrf_enabled") is True
            assert env_blocks_write("oidc_realm") is False
        finally:
            config_mod.set_config(None)
