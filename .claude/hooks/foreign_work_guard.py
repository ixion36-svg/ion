#!/usr/bin/env python3
"""PreToolUse hook: keep ION Wazuh Edition work out of this tree.

`~/Projects/ion-wazuh` is a separate product with the same package name
(`ion`) and the same directory layout, so a file written to the wrong
checkout looks native and `git status` is the only thing that notices. On
2026-09-28 the sibling repo was seeded by copying *this* working tree
including uncommitted work; the copy left, the originals did not, and three
Wazuh modules plus 115 lines of edits sat here for three days looking like
pending ION work.

ION's own Wazuh references are all INSIDE existing files -- KB articles,
the KEV catalog, `rule.groups` matching in the alert-prompt matcher. None
of them is a Wazuh-NAMED file. So a Wazuh-named file under src/ or tests/
is the sibling product's, and that is what this checks.

Not a refusal: ION main may one day gain Wazuh support deliberately. The
hook makes that a decision someone states rather than a diff nobody reads.
"""
from __future__ import annotations

import json
import sys

#: Directories that hold shipping code. A Wazuh-named file anywhere here is
#: the sibling product's; elsewhere (docs, notes, scratch) it is fine.
GUARDED_ROOTS = ("src", "tests")

#: Substrings in a FILENAME that mark it as the sibling product's.
FOREIGN_MARKERS = ("wazuh",)

SIBLING = "~/Projects/ion-wazuh"

#: A path inside the sibling checkout is exempt -- it belongs there.
SIBLING_DIR = "ion-wazuh"


def foreign_marker(file_path: str) -> str | None:
    """The marker this path trips, or None if it is fine to write.

    Guards only THIS tree: a path inside the sibling checkout is its own
    business, so ``ion-wazuh`` as a directory component exempts it.
    """
    parts = file_path.replace("\\", "/").lower().split("/")

    if any(SIBLING_DIR in part for part in parts[:-1]):
        return None
    if not any(root in parts for root in GUARDED_ROOTS):
        return None

    name = parts[-1]
    return next((m for m in FOREIGN_MARKERS if m in name), None)


def main() -> int:
    """Exit 2 to BLOCK the call; 0 to allow.

    ``{"continue": false}`` is NOT a block -- it stops the agent loop *after*
    the tool has already run, so the file lands and only the turn ends. Proven
    on 2026-10-01: a probe write with that shape created the file. A non-zero
    exit with the reason on stderr is what actually denies a PreToolUse call,
    and the explicit ``permissionDecision`` is emitted alongside it for hosts
    that read the structured form.
    """
    try:
        event = json.load(sys.stdin)
    except json.JSONDecodeError:
        return 0

    if event.get("tool_name") not in {"Edit", "Write", "MultiEdit"}:
        return 0

    tool_input = event.get("tool_input") or {}
    file_path = tool_input.get("file_path") or tool_input.get("path")
    if not file_path:
        return 0

    marker = foreign_marker(file_path)
    if marker is None:
        return 0

    reason = (
        f"foreign_work_guard: refused to write {file_path} "
        f"(filename contains {marker!r}). ION Wazuh Edition lives in {SIBLING}, "
        f"a separate repo with the same package name and layout -- a file written "
        f"here looks native and only `git status` notices. ION's own Wazuh "
        f"references are all inside existing files, never Wazuh-named ones. If "
        f"this really belongs in ION main, say so and re-issue the write; "
        f"otherwise write it in {SIBLING}."
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
