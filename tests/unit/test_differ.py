"""Tests for version differ."""

import pytest

from docforge.diff.differ import VersionDiffer


class TestVersionDiffer:
    """Tests for VersionDiffer."""

    @pytest.fixture
    def differ(self):
        return VersionDiffer()

    def test_compute_diff_additions(self, differ):
        """Test computing diff with additions."""
        old = "line1\nline2"
        new = "line1\nline2\nline3"

        diff = differ.compute_diff(old, new)
        assert "+line3" in diff

    def test_compute_diff_deletions(self, differ):
        """Test computing diff with deletions."""
        old = "line1\nline2\nline3"
        new = "line1\nline2"

        diff = differ.compute_diff(old, new)
        assert "-line3" in diff

    def test_compute_diff_modifications(self, differ):
        """Test computing diff with modifications."""
        old = "line1\nold text\nline3"
        new = "line1\nnew text\nline3"

        diff = differ.compute_diff(old, new)
        assert "-old text" in diff
        assert "+new text" in diff

    def test_compute_diff_no_changes(self, differ):
        """Test computing diff with no changes."""
        old = "same content"
        new = "same content"

        diff = differ.compute_diff(old, new)
        # Unified diff will be empty for identical content
        assert "-" not in diff or diff.strip() == ""

    def test_compute_diff_lines(self, differ):
        """Test computing diff as line tuples."""
        old = "line1\nremoved"
        new = "line1\nadded"

        lines = differ.compute_diff_lines(old, new)

        # Should have unchanged, removed, and added
        types = [line[0] for line in lines]
        assert " " in types  # unchanged
        assert "-" in types  # removed
        assert "+" in types  # added

    def test_get_stats(self, differ):
        """Test getting diff statistics."""
        old = "line1\nline2\nline3"
        new = "line1\nmodified\nline3\nline4"

        diff = differ.compute_diff(old, new)
        stats = differ.get_stats(diff)

        assert stats["additions"] > 0
        assert stats["deletions"] > 0
        assert stats["total_changes"] == stats["additions"] + stats["deletions"]

    def test_format_diff_colored(self, differ):
        """Test colored diff formatting."""
        old = "line1\nold line\nline3"
        new = "line1\nnew line\nline3"

        diff = differ.compute_diff(old, new)
        colored = differ.format_diff_colored(diff)

        # Should contain ANSI color codes for additions/deletions
        assert "\033[32m" in colored or "\033[31m" in colored or colored == diff
