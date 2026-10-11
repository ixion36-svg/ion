#!/usr/bin/env python3
"""PostToolUse hook: run ruff check on edited Python files under src/.

Reads the Claude Code hook event from stdin, extracts the file path, runs
`ruff check` if and only if the file is a .py under the ION src/ tree, and
prints any findings. Non-blocking — surfaces issues without aborting the
edit, so the model sees them in its next turn.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def main() -> int:
    try:
        event = json.load(sys.stdin)
    except json.JSONDecodeError:
        # Not a JSON event — exit quietly; hooks must never break the harness.
        return 0

    tool_input = event.get("tool_input") or {}
    file_path = tool_input.get("file_path") or tool_input.get("path")
    if not file_path:
        return 0

    p = Path(file_path)
    if p.suffix != ".py":
        return 0

    # Only act on files within the ION src/ tree, where the per-file-ignore
    # rules in pyproject.toml [tool.ruff] are tuned. Outside src/ would emit
    # noise (tests, scripts, seed files) that the project deliberately runs
    # ruff against only in CI.
    try:
        rel_parts = p.resolve().parts
    except OSError:
        return 0
    if "src" not in rel_parts:
        return 0

    # Find the repo root by walking up until we hit pyproject.toml.
    cur = p.resolve().parent
    repo: Path | None = None
    for parent in [cur, *cur.parents]:
        if (parent / "pyproject.toml").exists():
            repo = parent
            break
    if repo is None:
        return 0

    result = subprocess.run(
        ["ruff", "check", str(p)],
        cwd=str(repo),
        capture_output=True,
        text=True,
    )
    out = (result.stdout + result.stderr).strip()
    if result.returncode == 0:
        return 0

    # Non-zero — surface findings to the model. Use stderr so Claude Code
    # treats it as hook feedback rather than tool output.
    print(f"ruff check {p.name}:", file=sys.stderr)
    print(out, file=sys.stderr)
    # Return 0 — non-blocking. The findings are advisory.
    return 0


if __name__ == "__main__":
    sys.exit(main())
