"""Format handler plugins."""

from docforge.plugins.formats.markdown_plugin import MarkdownPlugin
from docforge.plugins.formats.plain_text_plugin import PlainTextPlugin
from docforge.plugins.formats.html_plugin import HtmlPlugin
from docforge.plugins.formats.docx_plugin import DocxPlugin

__all__ = [
    "MarkdownPlugin",
    "PlainTextPlugin",
    "HtmlPlugin",
    "DocxPlugin",
]
