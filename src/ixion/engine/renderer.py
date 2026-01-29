"""Jinja2 template rendering engine."""

import re
from typing import Any, Set
from jinja2 import TemplateSyntaxError, UndefinedError, Undefined
from jinja2.sandbox import SandboxedEnvironment, SecurityError

from ixion.core.exceptions import RenderError


class TemplateRenderer:
    """Jinja2-based template renderer using sandboxed environment.

    Uses SandboxedEnvironment to prevent Server-Side Template Injection (SSTI)
    attacks by restricting access to dangerous attributes and methods.
    """

    def __init__(self):
        # Use SandboxedEnvironment to prevent SSTI attacks
        # This blocks access to dangerous attributes like __class__, __mro__, etc.
        self.env = SandboxedEnvironment(
            autoescape=False,  # Templates are for document generation, not HTML
            trim_blocks=True,
            lstrip_blocks=True,
        )
        self._register_filters()

    def _register_filters(self) -> None:
        """Register custom Jinja2 filters."""
        self.env.filters["upper"] = str.upper
        self.env.filters["lower"] = str.lower
        self.env.filters["title"] = str.title
        self.env.filters["capitalize"] = str.capitalize
        self.env.filters["strip"] = str.strip

        def default_filter(value: Any, default_val: Any = "") -> Any:
            """Return default if value is None, empty, or undefined."""
            if value is None or value == "" or isinstance(value, Undefined):
                return default_val
            return value

        self.env.filters["default"] = default_filter

    def render(self, template_content: str, data: dict[str, Any]) -> str:
        """Render a template with the given data.

        The template is rendered in a sandboxed environment that prevents
        access to dangerous Python internals.
        """
        try:
            template = self.env.from_string(template_content)
            return template.render(**data)
        except SecurityError as e:
            raise RenderError(f"Security violation: {e}")
        except TemplateSyntaxError as e:
            raise RenderError(f"Template syntax error: {e.message} at line {e.lineno}")
        except UndefinedError as e:
            raise RenderError(f"Undefined variable: {e.message}")
        except Exception as e:
            raise RenderError(f"Render error: {str(e)}")

    def extract_variables(self, template_content: str) -> Set[str]:
        """Extract variable names from a template."""
        variables: Set[str] = set()
        loop_vars: Set[str] = set()

        # First, find all loop variables (these should be excluded)
        for_pattern = r"\{%\s*for\s+(\w+)\s+in\s+(\w+)"
        for match in re.finditer(for_pattern, template_content):
            loop_vars.add(match.group(1))  # The iteration variable
            variables.add(match.group(2))   # The collection variable

        # Match {{ variable }} patterns
        simple_pattern = r"\{\{\s*(\w+)(?:\s*\|[^}]*)?\s*\}\}"
        for match in re.finditer(simple_pattern, template_content):
            variables.add(match.group(1))

        # Match {{ obj.attr }} patterns (get the root object)
        dot_pattern = r"\{\{\s*(\w+)\.\w+"
        for match in re.finditer(dot_pattern, template_content):
            variables.add(match.group(1))

        # Match {% if variable %} patterns
        if_pattern = r"\{%\s*if\s+(\w+)"
        for match in re.finditer(if_pattern, template_content):
            variables.add(match.group(1))

        # Remove Jinja2 built-ins and loop variables
        builtins = {"loop", "self", "true", "false", "none", "True", "False", "None"}
        variables -= builtins
        variables -= loop_vars

        return variables

    def validate(self, template_content: str) -> tuple[bool, str | None]:
        """Validate template syntax without rendering."""
        try:
            self.env.from_string(template_content)
            return True, None
        except TemplateSyntaxError as e:
            return False, f"Syntax error at line {e.lineno}: {e.message}"
        except Exception as e:
            return False, str(e)
