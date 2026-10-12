"""The snapshot and rollback paths in tools/grok_fragment_tranche.py.

The driver hands a page to an external worker, verifies the result, and
either keeps it or puts the tree back. The rollback is the part nobody
watches, because it only runs when a conversion has already failed, and a
rollback that silently corrupts a file is worse than one that refuses.

Both tests here pin a real defect. Neither was visible in the code: the
first was found by running the rollback against a page that already had a
fragment, and the second by noticing that a rolled-back page left nothing
to diagnose.
"""
from __future__ import annotations

import hashlib
import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

import grok_fragment_tranche as gft  # noqa: E402


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def fake_page(tmp_path, monkeypatch):
    """A page, its fragment, its module and its test, in a throwaway repo.

    Pointed at a temporary tree rather than the real one, so a test of the
    rollback cannot roll back the checkout it is running in.
    """
    repo = tmp_path / "repo"
    templates = repo / "src/ion/web/templates"
    fragments = templates / "_fragments"
    ui = repo / "src/ion/web/ui"
    tests = repo / "tests/unit"
    for d in (fragments, ui, tests):
        d.mkdir(parents=True)

    monkeypatch.setattr(gft, "REPO", repo)
    monkeypatch.setattr(gft, "TEMPLATES", templates)
    monkeypatch.setattr(gft, "FRAGMENTS", fragments)
    monkeypatch.setattr(gft, "UI", ui)
    monkeypatch.setattr(gft, "TESTS", tests)
    monkeypatch.setattr(gft, "REJECTED", repo / ".grok-rejected")

    # The page and its fragment share a basename, which is the house naming
    # convention and the thing that broke the rollback.
    page = templates / "widget.html"
    frag = fragments / "widget.html"
    page.write_bytes(b"PAGE: the original template\n")
    frag.write_bytes(b"FRAGMENT: the converted partial\n")
    return {"repo": repo, "page": page, "frag": frag,
            "ui": ui / "widget.py", "test": tests / "test_ui_fragment_widget.py"}


def test_a_page_and_its_fragment_do_not_share_one_backup(fake_page, tmp_path):
    """The defect: backups were keyed by basename.

    `templates/widget.html` and `templates/_fragments/widget.html` both
    flattened to `widget.html` in the backup directory, so the second copy
    overwrote the first and both originals pointed at the same file. A
    rollback then wrote the fragment's contents into the page template and
    reported that it had restored both. Every page converted so far has a
    fragment named exactly after it, so this would have fired on the first
    re-run of any of them.
    """
    snap = gft.snapshot("widget.html", tmp_path / "backups")
    assert len(snap["backups"]) == 2
    assert len(set(snap["backups"].values())) == 2, (
        "two originals share one backup file, so one of them cannot be "
        "restored")


def test_rollback_restores_each_same_named_file_to_its_own_content(
        fake_page, tmp_path):
    """The consequence of the above, driven end to end.

    Both files are scribbled on, as a failed conversion would, and each
    must come back with its own bytes rather than its neighbour's.
    """
    page, frag = fake_page["page"], fake_page["frag"]
    want = {page: _sha(page), frag: _sha(frag)}

    snap = gft.snapshot("widget.html", tmp_path / "backups")
    page.write_bytes(b"a failed conversion rewrote the page\n")
    frag.write_bytes(b"a failed conversion rewrote the fragment\n")

    gft.roll_back(snap)

    assert _sha(page) == want[page], "the page came back with other content"
    assert _sha(frag) == want[frag], "the fragment came back with other content"
    assert page.read_bytes().startswith(b"PAGE:")
    assert frag.read_bytes().startswith(b"FRAGMENT:")


def test_rollback_deletes_what_the_conversion_created(fake_page, tmp_path):
    """The other half of a rollback. A created module left behind is worse
    than a modified one, because discovery imports it and the app refuses to
    start on a module with no router."""
    snap = gft.snapshot("widget.html", tmp_path / "backups")
    fake_page["ui"].write_bytes(b"router = None\n")
    fake_page["test"].write_bytes(b"def test_x(): pass\n")

    gft.roll_back(snap)

    assert not fake_page["ui"].exists()
    assert not fake_page["test"].exists()
    assert fake_page["page"].exists(), "the page itself must survive"


def test_rejected_work_is_kept_before_it_is_undone(fake_page):
    """The defect that made a failed page undiagnosable.

    A rollback discarded the work and kept only a summary line, so a page
    that spent 2853 seconds and failed two of its own tests left neither
    the failing test names nor the module nor the fragment. Most of a
    conversion that fails two tests is usually right.
    """
    fake_page["ui"].write_bytes(b"router = None\n")
    snap = {"stem": "widget", "existed": [], "backups": {}}

    notes = gft.preserve(snap)

    assert notes, "preserve reported nothing, so nothing was kept"
    out = sorted(gft.REJECTED.glob("widget-*"))
    assert len(out) == 1
    kept = {p.name for p in out[0].rglob("*") if p.is_file()}
    assert kept == {"widget.html", "widget.py"}, kept

    # Mirrored, not flattened, for the same reason the backups are.
    assert (out[0] / "src/ion/web/templates/widget.html").exists()
    assert (out[0] / "src/ion/web/templates/_fragments/widget.html").exists()
    shutil.rmtree(out[0])


def test_preserve_changes_nothing_in_the_tree(fake_page):
    """It runs immediately before a rollback, so a preserve that moved a
    file rather than copying it would leave the rollback nothing to put
    back."""
    page, frag = fake_page["page"], fake_page["frag"]
    before = {page: _sha(page), frag: _sha(frag)}

    gft.preserve({"stem": "widget", "existed": [], "backups": {}})

    assert {page: _sha(page), frag: _sha(frag)} == before
    for out in gft.REJECTED.glob("widget-*"):
        shutil.rmtree(out)
