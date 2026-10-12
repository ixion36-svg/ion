"""The /ui router discovers its page modules instead of listing them.

A module list would be one line that all 35 remaining conversions edit,
which is the single thing that turns independent work into conflicts.
Discovery removes it, and these tests are what discovery costs: a listed
module announces itself, a discovered one has to be checked for.

The failure discovery invites is a module that exists and serves nothing,
which on a fragment endpoint shows the user an empty panel that reads as
"no data" rather than "not wired up".
"""
from __future__ import annotations

import importlib
import pathlib
import pkgutil
import sys

import pytest

import ion.web.ui as ui


def _module_names() -> list[str]:
    return sorted(
        m.name for m in pkgutil.iter_modules(ui.__path__)
        if not m.name.startswith("_")
    )


def test_discovery_finds_the_page_modules():
    """Positive control. An empty list would make every test below vacuous."""
    found = ui._page_modules()
    assert "service_accounts" in found
    assert "bob_eval" in found
    assert found == _module_names()


def test_helpers_are_excluded_by_the_underscore_convention():
    assert "_shared" not in ui._page_modules()


def test_every_page_module_exposes_a_router():
    for name in ui._page_modules():
        mod = importlib.import_module(f"ion.web.ui.{name}")
        assert getattr(mod, "router", None) is not None, name


def test_every_module_route_is_actually_mounted():
    """The test that catches the real failure mode.

    A module can define a perfectly good router and still serve nothing if
    the loader drops it. Compare what the modules declare against what the
    package mounts, rather than trusting the loop that does the mounting.
    """
    declared = set()
    for name in ui._page_modules():
        mod = importlib.import_module(f"ion.web.ui.{name}")
        for route in mod.router.routes:
            declared.add("/ui" + route.path)

    mounted = {r.path for r in ui.router.routes}
    assert declared, "no module declared any route, so this proves nothing"
    assert declared <= mounted, f"declared but not mounted: {declared - mounted}"


def _drop_package_from_sys_modules() -> None:
    for name in [m for m in sys.modules if m == "ion.web.ui"
                 or m.startswith("ion.web.ui.")]:
        del sys.modules[name]


def test_a_module_without_a_router_is_an_error_not_a_skip():
    """A silent skip is the whole hazard, so prove the loader refuses.

    The probe is planted in the real package directory. Appending to the
    imported package's `__path__` does not work: dropping the package from
    sys.modules to force a reimport discards that `__path__` with it, so the
    reimport searches the original directory and never sees the probe. That
    version of this test passed a broken loader.
    """
    probe = pathlib.Path(ui.__path__[0]) / "zzprobe_no_router.py"
    probe.write_text("# deliberately defines no router\n", encoding="utf-8")
    try:
        _drop_package_from_sys_modules()
        with pytest.raises(ImportError, match="defines no `router`"):
            importlib.import_module("ion.web.ui")
    finally:
        probe.unlink(missing_ok=True)
        # The bytecode would be rediscovered as a module on the next run.
        for cached in (probe.parent / "__pycache__").glob("zzprobe_no_router.*"):
            cached.unlink(missing_ok=True)
        _drop_package_from_sys_modules()
        importlib.import_module("ion.web.ui")
