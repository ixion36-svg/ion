"""Markdown format plugin."""

from pathlib import Path


class MarkdownPlugin:
    """Plugin for Markdown format."""

    @property
    def name(self) -> str:
        return "markdown"

    @property
    def extensions(self) -> list[str]:
        return [".md", ".markdown"]

    def read(self, path: Path) -> str:
        """Read content from a Markdown file."""
        return path.read_text(encoding="utf-8")

    def write(self, content: str, path: Path) -> None:
        """Write content to a Markdown file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def convert(self, content: str, from_format: str) -> str:
        """Convert content from another format to Markdown."""
        if from_format == "html":
            # Convert HTML to Markdown (basic conversion)
            from bs4 import BeautifulSoup
            import re

            soup = BeautifulSoup(content, "html.parser")

            # Convert headers
            for i in range(1, 7):
                for tag in soup.find_all(f"h{i}"):
                    tag.replace_with(f"{'#' * i} {tag.get_text()}\n\n")

            # Convert bold
            for tag in soup.find_all(["strong", "b"]):
                tag.replace_with(f"**{tag.get_text()}**")

            # Convert italic
            for tag in soup.find_all(["em", "i"]):
                tag.replace_with(f"*{tag.get_text()}*")

            # Convert links
            for tag in soup.find_all("a"):
                href = tag.get("href", "")
                tag.replace_with(f"[{tag.get_text()}]({href})")

            # Convert paragraphs
            for tag in soup.find_all("p"):
                tag.replace_with(f"{tag.get_text()}\n\n")

            # Convert code
            for tag in soup.find_all("code"):
                tag.replace_with(f"`{tag.get_text()}`")

            result = soup.get_text()
            # Clean up extra whitespace
            result = re.sub(r"\n{3,}", "\n\n", result)
            return result.strip()

        elif from_format == "text":
            # Plain text is already valid markdown
            return content

        else:
            return content

    def to_html(self, content: str) -> str:
        """Convert Markdown to HTML."""
        import markdown

        return markdown.markdown(content, extensions=["tables", "fenced_code"])
