#!/usr/bin/env python3
"""PreToolUse hook: gate edits to security-sensitive ION paths.

Refuses Edit/Write on files where an accidental change breaks auth, TLS or
container startup silently. Say so explicitly and re-issue, or edit by hand.

**Two shapes were tried before this one and neither gated anything**, both
proven by writing a probe file to a matching path and finding it on disk:

- ``{"continue": false}`` ends the agent loop *after* the tool has run, so the
  edit lands and only the turn stops. This hook shipped that way, so between
  its introduction and 2026-10-01 it never prevented a single edit.
- ``permissionDecision: "ask"`` defers to the permission system, which
  auto-approves under auto mode. A gate that is a no-op in the mode most work
  happens in is not a gate.

A non-zero exit with the reason on stderr is what actually refuses a call.

``Dockerfile`` and ``docker-compose*.yml`` are deliberately NOT listed: the
release ritual edits both every bump, and a wrong change to either fails
loudly at build time rather than silently weakening a running system. This
list is for changes whose damage is quiet.
"""
from __future__ import annotations

import json
import sys
from pathlib import PurePosixPath, PureWindowsPath

# Glob-like patterns for paths that must require user confirmation before
# being edited. Match is case-insensitive and tested against both POSIX
# and Windows-style paths.
SENSITIVE_PATTERNS = [
    "src/ion/auth/oidc.py",         # Keycloak OIDC, RS256 algorithm pin
    "src/ion/auth/*.py",            # all auth modules
    "docker-entrypoint.sh",         # container startup
    ".env",                         # local secrets
    ".env.deploy",                  # deploy defaults
    "*.pem",                        # certs (TIDE etc.)
    "*.key",                        # private keys
    "*.crt",                        # certs
]


def matches_any(path: str, patterns: list[str]) -> str | None:
    pp = PurePosixPath(path.replace("\\", "/").lower())
    pw = PureWindowsPath(path.lower())
    for pat in patterns:
        pat_low = pat.lower()
        if pp.match(pat_low) or pw.match(pat_low):
            return pat
        # Also test against the basename for simple filename patterns.
        if pp.name and PurePosixPath(pp.name).match(pat_low):
            return pat
    return None


def main() -> int:
    try:
        event = json.load(sys.stdin)
    except json.JSONDecodeError:
        return 0

    tool = event.get("tool_name")
    if tool not in {"Edit", "Write", "MultiEdit"}:
        return 0

    tool_input = event.get("tool_input") or {}
    file_path = tool_input.get("file_path") or tool_input.get("path")
    if not file_path:
        return 0

    hit = matches_any(file_path, SENSITIVE_PATTERNS)
    if not hit:
        return 0

    reason = (
        f"sensitive_paths_guard: refused to write {file_path} "
        f"(matched {hit!r}). This file controls auth, TLS or container startup, "
        f"and a wrong change here fails quietly rather than loudly. If the "
        f"change is intentional, say so and re-issue it, or make it by hand."
    )
    print(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": reason,
                }
            }
        )
    )
    print(reason, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
