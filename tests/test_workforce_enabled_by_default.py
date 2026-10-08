"""The workforce lifecycle ships on.

It was behind ``workforce_enabled = False``, so a fresh deployment had the
whole module 404 and the nav link hidden: role profiles, joining journeys,
requirement verification, the expiry sweep, the ORBAT, the org tree and
leaver records were all present, migrated and inert.

That is the wrong default for what it does. Onboarding and offboarding are
not optional extras for a SOC -- "who is cleared to be on this console
today, and what did we take off them when they left" is a question every
deployment has to answer, and a module that answers it silently off is a
module nobody discovers until an assessor asks.

Turning it on does not grant anybody anything. A journey still has to be
assigned, requirements still have to be verified, and ``sync_granted_roles``
still decides what a journey confers. What changes is that the module is
visible and usable rather than returning 404 to someone who has no way to
tell the difference between "off" and "broken".

The flag stays, because a deployment that genuinely does not want it should
be able to turn it off, and because the setting is now visible and editable
in Settings rather than only in .env.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from ion.core.config import Config


class TestTheDefault:
    def test_workforce_is_on_for_a_fresh_config(self):
        assert Config().workforce_enabled is True

    def test_the_flag_still_exists(self):
        """On by default, not removed: a deployment that does not want the
        module must still be able to switch it off."""
        assert hasattr(Config(), "workforce_enabled")

    def test_it_can_still_be_turned_off_from_the_environment(self, monkeypatch):
        from ion.core import config as config_mod

        monkeypatch.setenv("ION_WORKFORCE_ENABLED", "false")
        config_mod.set_config(None)
        try:
            assert config_mod.get_config().workforce_enabled is False
        finally:
            config_mod.set_config(None)

    def test_it_can_still_be_turned_off_from_the_config_file(self, tmp_path):
        config = Config()
        config.workforce_enabled = False
        path = tmp_path / "config.json"
        config.to_file(path)
        assert Config.from_file(path).workforce_enabled is False

    def test_a_config_file_written_before_this_change_keeps_its_value(
        self, tmp_path
    ):
        """An existing deployment that never set the flag now gets the new
        default, which is the intent. One that deliberately set it false
        must keep that -- a default change that silently re-enables a module
        somebody turned off is a different kind of bug."""
        import json

        path = tmp_path / "config.json"
        path.write_text(json.dumps({"workforce_enabled": False}), encoding="utf-8")
        assert Config.from_file(path).workforce_enabled is False


class TestTheGate:
    def test_the_api_gate_reads_the_config(self):
        """The gate must stay config-driven rather than being deleted, or
        turning the module off would leave the endpoints reachable."""
        source = (
            _SRC / "ion" / "web" / "workforce_api.py"
        ).read_text(encoding="utf-8")
        assert "get_config().workforce_enabled" in source

    def test_the_nav_still_asks_before_showing_the_link(self):
        base = (
            _SRC / "ion" / "web" / "templates" / "base.html"
        ).read_text(encoding="utf-8")
        assert "workforce_available()" in base
