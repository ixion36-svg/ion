"""Every served stylesheet is either scanned or excluded on the record.

`tools/dead_css.py` held a hand-written SHEETS list, and the comment above
it records what that cost once already:

    alerts-queue.css was missing from this list and so had never been
    scanned. It is loaded by alerts.html rather than base.html, which is
    how it was overlooked.

It happened again, and larger. The same block says of the page sheets:
"Adding them here is the point of that column: once a page's CSS is in a
linked sheet, this tool's vetted scanner covers it." Only
`ion-pages.css` was ever added. Twenty-four page sheets the redesign
created sat outside the scan while the tool's own comment said they were
inside it, and `docs/UI_REDESIGN.md` repeated the claim.

A list that has to be remembered will be forgotten, so the list is
derived from the directory now and the exclusions are named with reasons.
This test is the part that cannot be forgotten: a new sheet is either
scanned or it is excluded deliberately, and there is no third state where
it is quietly uncovered.

It deliberately does not assert anything about how many dead rules are
found. The scanner reports candidates and `--write` deletes them, and
`tests/test_dead_css.py` is the suite that keeps the scanner honest about
what it can see. Coverage and accuracy are different questions.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tools.dead_css import (  # noqa: E402
    BUILD_INPUTS, CSS_DIR, EXCLUDED, REPO, SHEETS, sheet_path,
)


def test_every_sheet_on_disk_is_scanned_or_excluded():
    on_disk = {path.name for path in CSS_DIR.glob("*.css")}
    accounted = set(SHEETS) | set(EXCLUDED)
    assert on_disk - accounted == set(), sorted(on_disk - accounted)


def test_the_build_inputs_under_frontend_are_scanned():
    """Deriving the list from CSS_DIR dropped both of these, because they
    are build inputs under frontend/ and a listing of the served directory
    does not see them. `sheet_path` resolves them and its docstring says
    they are the ones most worth scanning: ion-legacy.css is the largest
    remaining pile of legacy rules, and ion-pages.css holds the CSS lifted
    out of template <style> blocks, which is the redesign's own output.
    """
    for name in BUILD_INPUTS:
        assert (REPO / "frontend" / name).exists(), name
        assert name in SHEETS, name


def test_every_scanned_sheet_resolves_to_a_file_that_exists():
    """A name in the list whose file is elsewhere reads as coverage that
    does not happen, which is exactly how the build inputs were lost."""
    for sheet in SHEETS:
        assert sheet_path(sheet).exists(), sheet


def test_no_sheet_is_both_scanned_and_excluded():
    assert set(SHEETS) & set(EXCLUDED) == set()


def test_every_exclusion_carries_a_reason():
    """The reason is the whole value of an exclusion. Without one, the next
    person cannot tell a vendor file from an oversight."""
    for name, reason in EXCLUDED.items():
        assert reason and len(reason) > 20, (name, reason)


def test_the_redesigns_page_sheets_are_actually_covered():
    """The specific claim that was false. These are the sheets the
    `styled` column produced, and the column's stated purpose was to
    bring them under this scanner."""
    # pcap, documents and discover have since been retired into the one
    # build, which tools/dead_css.py deliberately does not scan; they are
    # pinned by tests/test_retired_page_sheets.py instead.
    for sheet in ("cases-page.css", "chat-page.css",
                  "analytics-page.css", "ion-shell.css", "login-page.css"):
        assert sheet in SHEETS, sheet


def test_the_compiled_tailwind_output_is_not_scanned():
    """ion.css is generated, and its utility classes are matched by
    construction rather than by name, so scanning it would report most of
    a framework as dead."""
    assert "ion.css" in EXCLUDED
    assert "ion.css" not in SHEETS
