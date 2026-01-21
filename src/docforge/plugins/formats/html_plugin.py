"""HTML format plugin."""

from pathlib import Path


class HtmlPlugin:
    """Plugin for HTML format."""

    @property
    def name(self) -> str:
        return "html"

    @property
    def extensions(self) -> list[str]:
        return [".html", ".htm"]

    def read(self, path: Path) -> str:
        """Read content from an HTML file."""
        return path.read_text(encoding="utf-8")

    def write(self, content: str, path: Path) -> None:
        """Write content to an HTML file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def convert(self, content: str, from_format: str) -> str:
        """Convert content from another format to HTML."""
        if from_format == "markdown":
            import markdown

            return markdown.markdown(content, extensions=["tables", "fenced_code"])

        elif from_format == "text":
            # Wrap plain text in pre tag and escape HTML
            import html

            escaped = html.escape(content)
            return f"<pre>{escaped}</pre>"

        else:
            return content

    def wrap_with_template(
        self,
        content: str,
        title: str = "Document",
        css: str | None = None,
    ) -> str:
        """Wrap HTML content in a full document template."""
        style = ""
        if css:
            style = f"<style>{css}</style>"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    {style}
</head>
<body>
{content}
</body>
</html>"""
