"""Version diff utilities."""

import difflib
from typing import List


class VersionDiffer:
    """Compute diffs between template versions."""

    def compute_diff(self, old_content: str, new_content: str) -> str:
        """Compute a unified diff between two versions."""
        old_lines = old_content.splitlines(keepends=True)
        new_lines = new_content.splitlines(keepends=True)

        diff = difflib.unified_diff(
            old_lines,
            new_lines,
            fromfile="old",
            tofile="new",
            lineterm="",
        )

        return "".join(diff)

    def compute_diff_lines(
        self, old_content: str, new_content: str
    ) -> List[tuple[str, str]]:
        """Compute diff as a list of (change_type, line) tuples.

        Change types: ' ' (unchanged), '+' (added), '-' (removed)
        """
        old_lines = old_content.splitlines()
        new_lines = new_content.splitlines()

        result: List[tuple[str, str]] = []

        matcher = difflib.SequenceMatcher(None, old_lines, new_lines)

        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag == "equal":
                for line in old_lines[i1:i2]:
                    result.append((" ", line))
            elif tag == "replace":
                for line in old_lines[i1:i2]:
                    result.append(("-", line))
                for line in new_lines[j1:j2]:
                    result.append(("+", line))
            elif tag == "delete":
                for line in old_lines[i1:i2]:
                    result.append(("-", line))
            elif tag == "insert":
                for line in new_lines[j1:j2]:
                    result.append(("+", line))

        return result

    def format_diff_colored(self, diff: str) -> str:
        """Format diff with ANSI color codes for terminal display."""
        lines = diff.split("\n")
        colored_lines = []

        for line in lines:
            if line.startswith("+") and not line.startswith("+++"):
                colored_lines.append(f"\033[32m{line}\033[0m")  # Green for additions
            elif line.startswith("-") and not line.startswith("---"):
                colored_lines.append(f"\033[31m{line}\033[0m")  # Red for deletions
            elif line.startswith("@@"):
                colored_lines.append(f"\033[36m{line}\033[0m")  # Cyan for chunk headers
            else:
                colored_lines.append(line)

        return "\n".join(colored_lines)

    def get_stats(self, diff: str) -> dict[str, int]:
        """Get statistics about a diff."""
        lines = diff.split("\n")
        additions = sum(1 for l in lines if l.startswith("+") and not l.startswith("+++"))
        deletions = sum(1 for l in lines if l.startswith("-") and not l.startswith("---"))

        return {
            "additions": additions,
            "deletions": deletions,
            "total_changes": additions + deletions,
        }
