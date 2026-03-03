"""Custom exceptions for ION."""


class IonError(Exception):
    """Base exception for ION errors."""

    pass


class TemplateNotFoundError(IonError):
    """Raised when a template is not found."""

    def __init__(self, template_id: int):
        self.template_id = template_id
        super().__init__(f"Template with ID {template_id} not found")


class VersionNotFoundError(IonError):
    """Raised when a version is not found."""

    def __init__(self, template_id: int, version_number: int):
        self.template_id = template_id
        self.version_number = version_number
        super().__init__(
            f"Version {version_number} not found for template {template_id}"
        )


class RenderError(IonError):
    """Raised when template rendering fails."""

    def __init__(self, message: str, template_id: int | None = None):
        self.template_id = template_id
        super().__init__(message)


class ValidationError(IonError):
    """Raised when validation fails."""

    def __init__(self, field: str, message: str):
        self.field = field
        super().__init__(f"Validation error for '{field}': {message}")


class ExtractionError(IonError):
    """Raised when template extraction fails."""

    def __init__(self, message: str, source_file: str | None = None):
        self.source_file = source_file
        super().__init__(message)


class PluginError(IonError):
    """Raised when a plugin operation fails."""

    def __init__(self, plugin_name: str, message: str):
        self.plugin_name = plugin_name
        super().__init__(f"Plugin '{plugin_name}' error: {message}")
