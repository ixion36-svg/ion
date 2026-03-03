"""Plugin base protocol and registry."""

from pathlib import Path
from typing import Protocol, runtime_checkable, Optional


@runtime_checkable
class FormatPlugin(Protocol):
    """Protocol for format handler plugins."""

    @property
    def name(self) -> str:
        """Plugin name/format identifier."""
        ...

    @property
    def extensions(self) -> list[str]:
        """Supported file extensions."""
        ...

    def read(self, path: Path) -> str:
        """Read content from a file."""
        ...

    def write(self, content: str, path: Path) -> None:
        """Write content to a file."""
        ...

    def convert(self, content: str, from_format: str) -> str:
        """Convert content from another format to this format."""
        ...


class PluginRegistry:
    """Registry for format plugins."""

    def __init__(self):
        self._plugins: dict[str, FormatPlugin] = {}
        self._extension_map: dict[str, str] = {}
        self._register_default_plugins()

    def _register_default_plugins(self) -> None:
        """Register built-in plugins."""
        from ion.plugins.formats.plain_text_plugin import PlainTextPlugin
        from ion.plugins.formats.markdown_plugin import MarkdownPlugin
        from ion.plugins.formats.html_plugin import HtmlPlugin
        from ion.plugins.formats.docx_plugin import DocxPlugin

        self.register(PlainTextPlugin())
        self.register(MarkdownPlugin())
        self.register(HtmlPlugin())
        self.register(DocxPlugin())

    def register(self, plugin: FormatPlugin) -> None:
        """Register a plugin."""
        self._plugins[plugin.name] = plugin
        for ext in plugin.extensions:
            self._extension_map[ext.lower()] = plugin.name

    def get_plugin(self, name_or_extension: str) -> Optional[FormatPlugin]:
        """Get a plugin by name or file extension."""
        # Try direct name lookup
        if name_or_extension in self._plugins:
            return self._plugins[name_or_extension]

        # Try extension lookup
        ext = name_or_extension.lower()
        if not ext.startswith("."):
            ext = f".{ext}"
        if ext in self._extension_map:
            return self._plugins[self._extension_map[ext]]

        return None

    def get_plugin_for_file(self, path: Path) -> Optional[FormatPlugin]:
        """Get the appropriate plugin for a file based on its extension."""
        return self.get_plugin(path.suffix)

    def list_plugins(self) -> list[str]:
        """List all registered plugin names."""
        return list(self._plugins.keys())

    def list_extensions(self) -> dict[str, str]:
        """List all supported extensions and their plugin names."""
        return dict(self._extension_map)
