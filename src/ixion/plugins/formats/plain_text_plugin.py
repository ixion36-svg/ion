"""Plain text format plugin."""

from pathlib import Path


class PlainTextPlugin:
    """Plugin for plain text format."""

    @property
    def name(self) -> str:
        return "text"

    @property
    def extensions(self) -> list[str]:
        return [".txt", ".text"]

    def read(self, path: Path) -> str:
        """Read content from a text file."""
        return path.read_text(encoding="utf-8")

    def write(self, content: str, path: Path) -> None:
        """Write content to a text file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def convert(self, content: str, from_format: str) -> str:
        """Convert content from another format to plain text."""
        if from_format == "markdown":
            # Strip markdown formatting (basic)
            import re

            # Remove headers
            content = re.sub(r"^#+\s*", "", content, flags=re.MULTILINE)
            # Remove bold/italic
            content = re.sub(r"\*\*([^*]+)\*\*", r"\1", content)
            content = re.sub(r"\*([^*]+)\*", r"\1", content)
            content = re.sub(r"__([^_]+)__", r"\1", content)
            content = re.sub(r"_([^_]+)_", r"\1", content)
            # Remove links but keep text
            content = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", content)
            # Remove code blocks markers
            content = re.sub(r"```\w*\n?", "", content)
            content = re.sub(r"`([^`]+)`", r"\1", content)
            return content
        elif from_format == "html":
            # Strip HTML tags
            from bs4 import BeautifulSoup

            soup = BeautifulSoup(content, "html.parser")
            return soup.get_text()
        else:
            return content
