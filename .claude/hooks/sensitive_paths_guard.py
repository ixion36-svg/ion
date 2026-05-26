#!/usr/bin/env python3
"""PreToolUse hook: gate edits to security-sensitive ION paths.

Blocks Edit/Write on files where an accidental change can break auth, TLS,
or container startup. Outputs a JSON decision the harness uses to ask the
user to ack-and-retry. Non-fatal: the user can re-confirm and proceed.
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
    "docker-compose*.yml",          # service composition
    "Dockerfile",                   # image build
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

    decision = {
        "continue": False,
        "stopReason": (
            f"sensitive_paths_guard: blocked edit to {file_path} "
            f"(matched pattern: {hit}). This file controls auth, TLS, or "
            f"container startup. Confirm the change is intentional and the "
            f"impact is understood before proceeding (re-issue the edit "
            f"after acknowledging)."
        ),
    }
    print(json.dumps(decision))
    return 0


if __name__ == "__main__":
    sys.exit(main())
