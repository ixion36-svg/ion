"""`.agents/skills` must stay a faithful mirror of `.claude/skills`.

The mirror exists so the AGENTS convention finds the same skills Claude Code
does. It had drifted to a pre-v0.99.7 snapshot, and the copy that rotted was
`release-bump/check_versions.py` with `.env.example` and `.env.template`
missing from `CANONICAL_FILES` -- the exact omission that once shipped a wrong
image tag while the checker reported PASS. A stale drift checker is worse than
no drift checker: it answers the question wrongly and nobody looks again.

Only two differences are legitimate, and both are mechanical: the mirror points
at its own tree for the helper scripts, and names AGENTS.md where the original
names CLAUDE.md. Anything else means the copies have diverged.
"""
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE = REPO_ROOT / ".claude" / "skills"
MIRROR = REPO_ROOT / ".agents" / "skills"

# Applied to the SOURCE text to predict the mirror's text.
ADAPTATIONS = (
    (".claude/skills/", ".agents/skills/"),
    ("`CLAUDE.md`", "`AGENTS.md`"),
    ("<repo>/.claude/skills/", "<repo>/.agents/skills/"),
)


def _rel(root: Path) -> set[str]:
    return {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}


def _skip_if_absent() -> None:
    if not SOURCE.is_dir() or not MIRROR.is_dir():
        pytest.skip("skill trees not present in this checkout")


def test_mirror_holds_exactly_the_same_files():
    _skip_if_absent()
    source, mirror = _rel(SOURCE), _rel(MIRROR)
    assert mirror == source, (
        f"missing from .agents: {sorted(source - mirror)}; "
        f"unexpected in .agents: {sorted(mirror - source)}"
    )


@pytest.mark.parametrize("rel", sorted(_rel(SOURCE)) if SOURCE.is_dir() else [])
def test_mirror_matches_source_bar_the_documented_adaptations(rel):
    _skip_if_absent()
    expected = (SOURCE / rel).read_text(encoding="utf-8")
    for old, new in ADAPTATIONS:
        expected = expected.replace(old, new)
    actual = (MIRROR / rel).read_text(encoding="utf-8")
    assert actual == expected, (
        f".agents/skills/{rel} has drifted from .claude/skills/{rel}. "
        "Re-sync it (byte-for-byte, applying only the documented adaptations) "
        "rather than editing one copy."
    )


def test_no_absolute_path_is_baked_into_either_tree():
    """A path with a developer's home directory in it works on one machine."""
    _skip_if_absent()
    offenders = [
        p.relative_to(REPO_ROOT).as_posix()
        for root in (SOURCE, MIRROR)
        for p in root.rglob("*")
        if p.is_file()
        and any(
            marker in p.read_text(encoding="utf-8", errors="replace")
            for marker in ("C:\\Users\\", "C:/Users/", "/home/")
        )
    ]
    assert not offenders, f"absolute paths baked into: {offenders}"
