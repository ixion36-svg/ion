"""Tests for template renderer."""

import pytest

from ion.engine.renderer import TemplateRenderer
from ion.core.exceptions import RenderError


class TestTemplateRenderer:
    """Tests for TemplateRenderer."""

    @pytest.fixture
    def renderer(self):
        return TemplateRenderer()

    def test_render_simple(self, renderer):
        """Test rendering a simple template."""
        content = "Hello {{ name }}!"
        result = renderer.render(content, {"name": "World"})
        assert result == "Hello World!"

    def test_render_with_filters(self, renderer):
        """Test rendering with Jinja2 filters."""
        content = "Hello {{ name | upper }}!"
        result = renderer.render(content, {"name": "world"})
        assert result == "Hello WORLD!"

    def test_render_with_conditionals(self, renderer):
        """Test rendering with if statements."""
        content = "{% if show %}Visible{% endif %}"
        assert renderer.render(content, {"show": True}) == "Visible"
        assert renderer.render(content, {"show": False}) == ""

    def test_render_with_loops(self, renderer):
        """Test rendering with for loops."""
        content = "{% for item in items %}{{ item }},{% endfor %}"
        result = renderer.render(content, {"items": ["a", "b", "c"]})
        assert result == "a,b,c,"

    def test_render_syntax_error(self, renderer):
        """Test handling syntax errors."""
        content = "{% if unclosed"
        with pytest.raises(RenderError):
            renderer.render(content, {})

    def test_extract_variables_simple(self, renderer):
        """Test extracting simple variables."""
        content = "Hello {{ name }}, your email is {{ email }}"
        variables = renderer.extract_variables(content)
        assert variables == {"name", "email"}

    def test_extract_variables_with_filters(self, renderer):
        """Test extracting variables with filters."""
        content = "{{ name | upper }} - {{ date | default('N/A') }}"
        variables = renderer.extract_variables(content)
        assert variables == {"name", "date"}

    def test_extract_variables_from_loops(self, renderer):
        """Test extracting loop variables."""
        content = "{% for item in items %}{{ item }}{% endfor %}"
        variables = renderer.extract_variables(content)
        assert "items" in variables
        assert "item" not in variables  # Loop variable shouldn't be included

    def test_extract_variables_from_conditionals(self, renderer):
        """Test extracting conditional variables."""
        content = "{% if show_details %}Details{% endif %}"
        variables = renderer.extract_variables(content)
        assert "show_details" in variables

    def test_validate_valid_template(self, renderer):
        """Test validating a valid template."""
        content = "Hello {{ name }}!"
        valid, error = renderer.validate(content)
        assert valid is True
        assert error is None

    def test_validate_invalid_template(self, renderer):
        """Test validating an invalid template."""
        content = "{% if unclosed"
        valid, error = renderer.validate(content)
        assert valid is False
        assert error is not None

    def test_render_nested_object(self, renderer):
        """Test rendering with nested objects."""
        content = "{{ user.name }} - {{ user.email }}"
        result = renderer.render(content, {
            "user": {"name": "John", "email": "john@example.com"}
        })
        assert result == "John - john@example.com"

    def test_render_default_filter(self, renderer):
        """Test default filter."""
        content = "{{ missing | default('N/A') }}"
        result = renderer.render(content, {})
        assert result == "N/A"
