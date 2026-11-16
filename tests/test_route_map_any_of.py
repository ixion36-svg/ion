"""The route map said "and" where the code says "or".

`permission_of` collected every permission it found into one flat list and
rendered it with `" + ".join(...)`. The separator means all-of everywhere
else in that table, so an any-of gate was reported as requiring all of its
permissions at once:

    POST /api/alert-prompts   playbook:create + playbook:delete + playbook:update

The route takes `require_any_permission(_MANAGE_PERMS)`. Any one of those
three is enough.

This is worse than the blank cell it replaced. A blank says "this tool
could not tell", which sends a reader to the source. A `+` says something
definite and false, and false in the direction that looks safer, so
somebody auditing who can reach an endpoint would conclude it is more
tightly held than it is. The same flattening reached fifteen more routes
when require_integration_access was taught to the tool, which is
`integration:read` **or** `alert:read`.

Pre-existing, not introduced by that change: the `+` on
/api/alert-prompts is in the route map as far back as it has been
generated.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MAP = ROOT / "docs/ROUTE_MAP.md"


def _row(method: str, path: str) -> str:
    text = MAP.read_text(encoding="utf-8")
    pattern = re.compile(
        r"^\| " + method + r" \| `" + re.escape(path) + r"` \| ([^|]*)\|",
        re.M)
    match = pattern.search(text)
    assert match, (method, path)
    return match.group(1).strip().strip("`")


# ---------------------------------------------------------------------------
# any-of must not read as all-of
# ---------------------------------------------------------------------------


def test_an_any_permission_route_is_not_reported_as_needing_all_of_them():
    """require_any_permission(_MANAGE_PERMS): one of the three is enough."""
    cell = _row("POST", "/api/alert-prompts")
    assert "+" not in cell, cell
    assert "or" in cell, cell
    for name in ("playbook:create", "playbook:delete", "playbook:update"):
        assert name in cell, (name, cell)


def test_the_integration_gate_is_reported_as_either_permission():
    """`has_permission("integration:read") or has_permission("alert:read")`."""
    cell = _row("GET", "/api/integrations/logs")
    assert "+" not in cell, cell
    assert "or" in cell, cell
    assert "alert:read" in cell
    assert "integration:read" in cell


def test_a_single_permission_route_is_still_rendered_plain():
    """No decoration where there is nothing to disambiguate."""
    cell = _row("GET", "/api/alert-prompts")
    assert cell == "playbook:read", cell


def test_a_page_route_is_still_rendered_plain():
    cell = _row("GET", "/alerts")
    assert cell == "alert:read", cell


# ---------------------------------------------------------------------------
# The separator has to mean one thing
# ---------------------------------------------------------------------------


def test_no_row_mixes_the_two_separators_without_grouping():
    """A cell carrying both has to make the grouping explicit, or the
    reader cannot tell which binds tighter."""
    text = MAP.read_text(encoding="utf-8")
    for line in text.splitlines():
        if not line.startswith("| "):
            continue
        cells = line.split("|")
        if len(cells) < 4:
            continue
        cell = cells[3].strip().strip("`")
        if " + " in cell and " or " in cell:
            assert "(" in cell and ")" in cell, cell


def test_the_map_is_current_so_these_rows_are_what_the_tool_emits():
    """Otherwise this file is asserting against a stale document."""
    result = subprocess.run(
        [sys.executable, "tools/route_map.py", "--check"],
        cwd=ROOT, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout[-2000:] + result.stderr[-2000:]
