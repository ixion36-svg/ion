"""A fragment that calls an API function directly bypasses its gate.

`ion/web/ui/*.py` modules reuse the endpoint functions their JSON
counterparts call, which is deliberate: the two cannot drift apart if they
share an implementation. But a FastAPI dependency is enforced by FastAPI,
not by Python. Call the endpoint as a plain function and its body runs
with none of its `Depends(...)` applied.

I shipped that. `/ui/pcap/case-options` is gated on the pcap page's
`alert:read` and called `case_lifecycle_api.list_cases`, whose signature
carries `Depends(require_permission("case:read"))`. Called directly, that
dependency never ran, so anyone who could open the pcap page could read
the open case list. It was found in a browser session and by no test,
which is why this file exists.

Two things I got wrong writing it, both worth recording because both made
it weaker than it looks:

The first version matched only double quotes, and reported four working
modules that declare `require_permission('alert:read')` on their router
with single quotes. A false positive here is a failing test on working
code, which is worse than the hole it looks for.

The second version checked whether the *module* mentioned the permission
anywhere. That passed with the real guard deleted, because the same module
also calls `has_permission("case:read")` to decide whether to show an
attach button, and that unrelated mention satisfied it. So the check is
scoped to the function that makes the call, plus what that function
inherits: its own route decorator, the module's router dependencies, and
the module's PERMISSION constants. Proven by deleting the guard and
watching it fail.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
UI = ROOT / "src/ion/web/ui"
WEB = ROOT / "src/ion/web"

#: Shared helpers, not pages.
SKIP = {"__init__.py", "_shared.py", "template_render.py"}

MODULES = sorted(p for p in UI.glob("*.py") if p.name not in SKIP)
IDS = [p.stem for p in MODULES]

#: A permission name, either quote style.
NEEDS = re.compile(r"""require_permission\(\s*['"]([^'"]+)['"]""")
CHECKS = re.compile(r"""has_permission\(\s*['"]([^'"]+)['"]""")
CONSTS = re.compile(r"""^\s*PERMISSION\w*\s*=\s*['"]([^'"]+)['"]""", re.M)

#: Any module-level constant holding something that looks like a
#: permission, so `has_permission(PINS_PERMISSION)` counts. Without this
#: the check missed a guard written against a named constant, which is
#: how the cases module's own guard first read as absent.
NAMED = re.compile(
    r"""^\s*([A-Z][A-Z0-9_]*)\s*=\s*['"]([a-z_]+:[a-z_]+)['"]""", re.M)
#: The same two calls, taking a name rather than a literal.
BY_NAME = re.compile(
    r"""(?:has_permission|require_permission)\(\s*([A-Z][A-Z0-9_]*)\s*\)""")


def _api_permissions(module_name: str) -> dict[str, set[str]]:
    """Every function in an api module mapped to the permissions its own
    signature or decorators declare."""
    path = WEB / (module_name + ".py")
    if not path.exists():
        return {}
    text = path.read_text(encoding="utf-8")
    out: dict[str, set[str]] = {}
    for node in ast.walk(ast.parse(text)):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        source = ast.get_source_segment(text, node) or ""
        names = set(NEEDS.findall(source.split("):", 1)[0]))
        for dec in node.decorator_list:
            names |= set(NEEDS.findall(
                ast.get_source_segment(text, dec) or ""))
        if names:
            out[node.name] = names
    return out


#: `READ = require_permission("case:read")` at module level, then
#: `Depends(READ)` on the route. _cases_board.py does this, and the first
#: scoped version of the check reported it as a hole.
ALIASES = re.compile(
    r"""^\s*(\w+)\s*=\s*require_permission\(\s*['"]([^'"]+)['"]""", re.M)


def _ambient(text: str) -> set[str]:
    """What every function in the module holds without asking: the
    PERMISSION constants, and any router-level dependency."""
    held = set(CONSTS.findall(text))
    for line in text.splitlines():
        if "APIRouter(" in line or "dependencies=" in line:
            held |= set(NEEDS.findall(line))
    # A router built across several lines.
    for match in re.finditer(r"APIRouter\((.*?)\)\n", text, re.S):
        held |= set(NEEDS.findall(match.group(1)))
    return held


def _alias_permissions(text: str) -> dict[str, str]:
    return dict(ALIASES.findall(text))


def _unguarded_calls(path: Path) -> list[str]:
    """Calls into an api module whose declared permission nothing on the
    path to that call holds."""
    text = path.read_text(encoding="utf-8")
    ambient = _ambient(text)
    aliases = _alias_permissions(text)
    unmet: list[str] = []

    for node in ast.walk(ast.parse(text)):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        source = ast.get_source_segment(text, node) or ""
        # What this function holds: ambient, its own decorators, and any
        # explicit check inside its own body.
        held = set(ambient) | set(CHECKS.findall(source)) \
            | set(NEEDS.findall(source))
        for dec in node.decorator_list:
            held |= set(NEEDS.findall(
                ast.get_source_segment(text, dec) or ""))
        # Depends(READ), where READ names a require_permission earlier in
        # the module.
        for name, permission in aliases.items():
            if re.search(r"Depends\(\s*%s\s*\)" % re.escape(name), source):
                held.add(permission)
        # has_permission(PINS_PERMISSION), where the constant holds the
        # name. A guard written against a constant read as absent before
        # this, which is how the cases module failed its own check.
        named = dict(NAMED.findall(text))
        for name in BY_NAME.findall(source):
            if name in named:
                held.add(named[name])

        for api_module, fn in re.findall(
                r"(?:await\s+)?(\w+_api)\.(\w+)\s*\(", source):
            missing = _api_permissions(api_module).get(fn, set()) - held
            if missing:
                unmet.append("%s() calls %s.%s which needs %s"
                             % (node.name, api_module, fn, sorted(missing)))
    return sorted(set(unmet))


@pytest.mark.parametrize("path", MODULES, ids=IDS)
def test_a_fragment_holds_every_permission_it_calls_through(path):
    unmet = _unguarded_calls(path)
    assert not unmet, (
        "%s: these run with none of the callee's Depends(...) applied, "
        "and nothing on the path to the call holds what it requires: %s"
        % (path.name, unmet))


def test_the_check_catches_the_bug_it_was_written_for(tmp_path):
    """A positive control, built by taking the real module and removing
    the one guard. The previous version of this file passed that, because
    the module mentions the same permission elsewhere for an unrelated
    reason."""
    real = (UI / "pcap.py").read_text(encoding="utf-8")
    assert 'if not current_user.has_permission("case:read"):' in real, (
        "the guard moved; this control no longer reproduces the bug")

    broken = tmp_path / "pcap.py"
    broken.write_text(
        real.replace('if not current_user.has_permission("case:read"):',
                     "if False:"),
        encoding="utf-8")
    unmet = _unguarded_calls(broken)
    assert any("list_cases" in u and "case:read" in u for u in unmet), unmet


def test_an_unrelated_mention_elsewhere_does_not_satisfy_the_check(tmp_path):
    """The exact way the second version of this file was vacuous."""
    fake = tmp_path / "fake.py"
    fake.write_text(
        'PERMISSION = "alert:read"\n'
        'def shows_a_button(user):\n'
        '    return user.has_permission("case:read")\n'
        'def panel():\n'
        '    return case_lifecycle_api.list_cases()\n',
        encoding="utf-8")
    unmet = _unguarded_calls(fake)
    assert any("panel()" in u for u in unmet), unmet


def test_a_module_level_alias_counts_as_holding_the_permission(tmp_path):
    """`READ = require_permission("case:read")` then `Depends(READ)`.
    _cases_board.py does this, and the scoped-but-alias-blind version of
    this check reported it as a hole on working code."""
    fake = tmp_path / "fake.py"
    fake.write_text(
        'READ = require_permission("case:read")\n'
        'async def board(user=Depends(READ)):\n'
        '    return await case_lifecycle_api.list_cases()\n',
        encoding="utf-8")
    assert _unguarded_calls(fake) == []

    # And the alias must be the thing doing the work: a different
    # permission behind the same name is still a hole.
    other = tmp_path / "other.py"
    other.write_text(
        'READ = require_permission("alert:read")\n'
        'async def board(user=Depends(READ)):\n'
        '    return await case_lifecycle_api.list_cases()\n',
        encoding="utf-8")
    assert _unguarded_calls(other) != []


def test_a_guard_written_against_a_constant_is_recognised(tmp_path):
    """`has_permission(PINS_PERMISSION)` rather than a literal.

    The cases module guards its pins read that way, and the check read it
    as absent until constants resolved, which made it fail on working
    code. The other half of the control is that removing that guard still
    fails, so resolving the constant did not just silence it.
    """
    real = (UI / "cases.py").read_text(encoding="utf-8")
    assert "if not current_user.has_permission(PINS_PERMISSION):" in real, (
        "the guard moved; this control no longer reproduces the case")
    assert _unguarded_calls(UI / "cases.py") == []

    broken = tmp_path / "cases.py"
    broken.write_text(
        real.replace(
            "if not current_user.has_permission(PINS_PERMISSION):",
            "if False:"),
        encoding="utf-8")
    unmet = _unguarded_calls(broken)
    assert any("list_pins_endpoint" in u for u in unmet), unmet


def test_both_quote_styles_are_recognised():
    """The regression that made the first version fail on four working
    modules."""
    assert NEEDS.findall('Depends(require_permission("a:b"))') == ["a:b"]
    assert NEEDS.findall("Depends(require_permission('a:b'))") == ["a:b"]
