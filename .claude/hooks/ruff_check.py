#!/usr/bin/env python3
"""PostToolUse hook: run ruff check on edited Python files under src/.

Reads the Claude Code hook event from stdin, extracts the file path, runs
`ruff check` if and only if the file is a .py under the ION src/ tree, and
prints any findings. Non-blocking — surfaces issues without aborting the
edit, so the model sees them in its next turn.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


def _hook_repo() -> Path | None:
    """The checkout this hook is installed in, found from the hook's own path.

    This is the trust anchor for everything below. The repo root decides which
    ruff binary runs and which directory it runs in, so it must NOT be derived
    from the edited file's path: that path comes from the hook event, and a .py
    edited inside an untrusted tree (an extracted archive, a third-party
    checkout) would otherwise point this at that tree's .venv/Scripts/ruff.exe
    or let a ruff.py at its root satisfy the `-m ruff` fallback. ``__file__``
    is fixed at install time and is not influenced by the event.
    """
    try:
        here = Path(__file__).resolve()
    except OSError:
        return None
    for parent in here.parents:
        if (parent / "pyproject.toml").exists():
            return parent
    return None


def _ruff_cmd(repo: Path) -> list[str] | None:
    """Return a runnable ruff command, or None if ruff cannot be found.

    The hook is invoked as bare ``python``, which on Windows resolves to the
    system install rather than the project venv — so ``ruff`` is usually NOT
    on PATH even though ``.venv/Scripts/ruff.exe`` exists. Calling it by bare
    name raised FileNotFoundError on every edit under src/, and because the
    call was unguarded the hook died with a traceback instead of staying the
    advisory no-op it documents itself as.

    ``repo`` must be the hook's own checkout (see _hook_repo), never a root
    walked up from the event path.
    """
    exe = "ruff.exe" if sys.platform == "win32" else "ruff"
    bindir = "Scripts" if sys.platform == "win32" else "bin"
    candidates = [
        Path(sys.executable).parent / exe,       # same env as this interpreter
        repo / ".venv" / bindir / exe,           # this checkout's own venv
    ]
    for c in candidates:
        if c.exists():
            return [str(c), "check"]
    found = shutil.which("ruff")
    if found:
        return [found, "check"]
    # Last resort: ruff as a module of whatever interpreter we are. Run with
    # safe sys.path so the working directory cannot shadow the ruff module.
    try:
        probe = subprocess.run(
            [sys.executable, "-P", "-m", "ruff", "--version"],
            cwd=str(repo),
            env={**os.environ, "PYTHONSAFEPATH": "1"},
            capture_output=True,
            timeout=15,
        )
        if probe.returncode == 0:
            return [sys.executable, "-P", "-m", "ruff", "check"]
    except Exception:
        pass
    return None


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

    # Resolve the trust anchor first, then require the edited file to live
    # inside it. Only files within THIS checkout's src/ tree are linted, where
    # the per-file-ignore rules in pyproject.toml [tool.ruff] are tuned.
    # Outside src/ would emit noise (tests, scripts, seed files) that the
    # project deliberately runs ruff against only in CI; outside the checkout
    # entirely is somebody else's code, linted with the wrong config.
    repo = _hook_repo()
    if repo is None:
        return 0

    try:
        target = p.resolve()
    except OSError:
        return 0
    try:
        target.relative_to(repo / "src")
    except ValueError:
        return 0

    cmd = _ruff_cmd(repo)
    if cmd is None:
        # No ruff anywhere. Silence beats a traceback: this hook is advisory.
        return 0

    try:
        result = subprocess.run(
            [*cmd, str(target)],
            cwd=str(repo),
            capture_output=True,
            text=True,
            timeout=60,
        )
    except Exception as exc:  # never let a hook break the harness
        print(f"ruff_check: skipped ({exc.__class__.__name__}: {exc})", file=sys.stderr)
        return 0

    out = (result.stdout + result.stderr).strip()
    if result.returncode == 0:
        return 0

    # Non-zero — surface findings to the model. Use stderr so Claude Code
    # treats it as hook feedback rather than tool output.
    print(f"ruff check {target.name}:", file=sys.stderr)
    print(out, file=sys.stderr)
    # Return 0 — non-blocking. The findings are advisory.
    return 0


if __name__ == "__main__":
    sys.exit(main())
