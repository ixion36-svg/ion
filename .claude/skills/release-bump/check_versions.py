#!/usr/bin/env python3
"""ION release-bump drift checker.

Reads the canonical version from pyproject.toml, then verifies every file
in CANONICAL_FILES carries a matching version string. Reports drift.

Why: ION's __version__ string rotted across 13 releases in 2025 because
the 8 places it appears were never centralised. This script is the
guardrail. Run before every release-tag commit and on demand.
"""
from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

# Repo root: this file lives at <repo>/.claude/skills/release-bump/check_versions.py
REPO = Path(__file__).resolve().parents[3]
PYPROJECT = REPO / "pyproject.toml"

# Canonical files that MUST carry the current ION version on every release.
# Per _spec_v0_22.md §5.4, re-confirmed at v0.29.1.
#
# Each entry is (relative-path, regex, mode). Mode:
#   "single"     — exactly one match expected; that match must equal target
#   "all"        — one or more matches expected; ALL must equal target
#   "first"      — take the first match (use for CHANGELOG.md, which lists
#                  historical versions below the current one)
CANONICAL_FILES: list[tuple[str, str, str]] = [
    ("pyproject.toml",         r'^version\s*=\s*"([0-9.]+)"',                       "single"),
    ("src/ion/__init__.py",    r'__version__\s*=\s*"([0-9.]+)"',                    "single"),
    ("README.md",              r'version-([0-9.]+)-blue',                           "single"),
    ("Dockerfile",             r'org\.opencontainers\.image\.version="([0-9.]+)"',  "single"),
    ("docker-compose.yml",     r'ixion36/ion:\$\{ION_VERSION:-([0-9.]+)\}',         "all"),
    (".env.deploy",            r'^ION_VERSION=([0-9.]+)',                           "single"),
    ("CHANGELOG.md",           r'^## v([0-9.]+)',                                   "first"),
    # ION shipping docs all carry an `<!-- ion-doc:version=X.Y.Z -->` stamp
    # near the top — that's the canonical anchor. Many docs/*.md files use
    # the same pattern; extend this list when a new shipping doc starts
    # carrying the stamp.
    ("SECURITY_ASSESSMENT.md", r'<!-- ion-doc:version=([0-9.]+)',                   "first"),
]


def canonical_version() -> str:
    with PYPROJECT.open("rb") as f:
        return tomllib.load(f)["project"]["version"]


def find_matches(path: Path, pattern: str, mode: str) -> list[str] | None:
    text = path.read_text(encoding="utf-8", errors="replace")
    matches = re.findall(pattern, text, re.MULTILINE)
    if not matches:
        return None
    if mode == "first":
        return [matches[0]]
    return matches


def main() -> int:
    target = canonical_version()
    print(f"Canonical version (pyproject.toml): {target}")
    print()
    drift: list[str] = []
    missing: list[str] = []
    unmatched: list[str] = []

    for rel, pattern, mode in CANONICAL_FILES:
        p = REPO / rel
        if not p.exists():
            missing.append(rel)
            print(f"  ?? {rel:32}  FILE MISSING")
            continue

        found = find_matches(p, pattern, mode)
        if found is None:
            unmatched.append(rel)
            print(f"  ?  {rel:32}  PATTERN NOT FOUND  (regex may need updating)")
            continue

        if all(v == target for v in found):
            extra = f"  (x{len(found)})" if len(found) > 1 else ""
            print(f"  OK {rel:32}  {found[0]}{extra}")
        else:
            drift.append(rel)
            unique = sorted(set(found))
            print(f"  X  {rel:32}  {','.join(unique)}  (expected {target})")

    print()

    if missing:
        print("Missing canonical files (list may be stale — re-confirm against _spec_v0_22.md §5.4):")
        for m in missing:
            print(f"  - {m}")
        print()

    fail = bool(drift or missing or unmatched)
    if fail:
        if drift:
            print(f"FAIL: {len(drift)} file(s) drifted from pyproject.toml.")
        if unmatched:
            print(f"WARN: {len(unmatched)} file(s) had no matching version pattern.")
        return 1

    print("PASS: all canonical files match pyproject.toml.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
