"""Generate templates from documents with detected patterns."""

from dataclasses import dataclass
from typing import List
from pathlib import Path

from docforge.extraction.pattern_detector import PatternDetector, PatternMatch
from docforge.extraction.variable_inferrer import VariableInferrer, InferredVariable
from docforge.plugins import PluginRegistry


@dataclass
class GeneratedTemplate:
    """Result of template generation."""

    content: str
    variables: List[InferredVariable]
    original_text: str
    replacements_made: int


class TemplateGenerator:
    """Generate templates from documents."""

    def __init__(self):
        self.detector = PatternDetector()
        self.inferrer = VariableInferrer()
        self.plugin_registry = PluginRegistry()

    def analyze(
        self, text: str, min_confidence: float = 0.5
    ) -> tuple[List[PatternMatch], List[InferredVariable]]:
        """Analyze text and return detected patterns and inferred variables."""
        matches = self.detector.detect(text, min_confidence)
        variables = self.inferrer.infer(matches)
        return matches, variables

    def analyze_file(
        self, path: Path, min_confidence: float = 0.5
    ) -> tuple[List[PatternMatch], List[InferredVariable], str]:
        """Analyze a file and return patterns, variables, and content."""
        # Read file content using appropriate plugin
        plugin = self.plugin_registry.get_plugin_for_file(path)
        if plugin:
            text = plugin.read(path)
        else:
            text = path.read_text(encoding="utf-8")

        matches, variables = self.analyze(text, min_confidence)
        return matches, variables, text

    def generate(
        self,
        text: str,
        min_confidence: float = 0.7,
        use_filters: bool = True,
    ) -> GeneratedTemplate:
        """Generate a template from text."""
        matches = self.detector.detect(text, min_confidence)
        variables = self.inferrer.infer(matches)

        # Create template by replacing matches with Jinja2 variables
        template_content = self._replace_with_variables(text, matches, use_filters)

        return GeneratedTemplate(
            content=template_content,
            variables=variables,
            original_text=text,
            replacements_made=len(matches),
        )

    def generate_from_file(
        self,
        path: Path,
        min_confidence: float = 0.7,
        use_filters: bool = True,
    ) -> GeneratedTemplate:
        """Generate a template from a file."""
        # Read file content
        plugin = self.plugin_registry.get_plugin_for_file(path)
        if plugin:
            text = plugin.read(path)
        else:
            text = path.read_text(encoding="utf-8")

        return self.generate(text, min_confidence, use_filters)

    def _replace_with_variables(
        self,
        text: str,
        matches: List[PatternMatch],
        use_filters: bool,
    ) -> str:
        """Replace detected patterns with Jinja2 variables."""
        # Track variable name counts for uniqueness
        name_counts: dict[str, int] = {}

        # Sort matches by position (descending) to replace from end
        sorted_matches = sorted(matches, key=lambda m: m.start, reverse=True)

        result = text

        for match in sorted_matches:
            # Get unique variable name
            base_name = match.suggested_name
            if base_name in name_counts:
                name_counts[base_name] += 1
                var_name = f"{base_name}_{name_counts[base_name]}"
            else:
                name_counts[base_name] = 1
                var_name = base_name

            # Build Jinja2 variable expression
            if use_filters:
                filter_expr = self._get_filter_for_type(match.pattern_type)
                if filter_expr:
                    jinja_var = f"{{{{ {var_name}{filter_expr} }}}}"
                else:
                    jinja_var = f"{{{{ {var_name} }}}}"
            else:
                jinja_var = f"{{{{ {var_name} }}}}"

            # Replace in text
            result = result[: match.start] + jinja_var + result[match.end :]

        return result

    def _get_filter_for_type(self, pattern_type: str) -> str:
        """Get Jinja2 filter suggestion based on pattern type."""
        filter_map = {
            "date_iso": "",
            "date_us": "",
            "date_eu": "",
            "currency_usd": "",
            "currency_eur": "",
            "percentage": "",
            "email": " | lower",
            "name_pattern": " | title",
        }
        return filter_map.get(pattern_type, "")

    def generate_with_manual_markers(
        self,
        text: str,
        markers: List[tuple[int, int, str]],
    ) -> GeneratedTemplate:
        """Generate template with manually specified replacement markers.

        Args:
            text: The source text
            markers: List of (start, end, variable_name) tuples
        """
        # Sort by position descending
        sorted_markers = sorted(markers, key=lambda m: m[0], reverse=True)

        result = text

        for start, end, var_name in sorted_markers:
            jinja_var = f"{{{{ {var_name} }}}}"
            result = result[:start] + jinja_var + result[end:]

        # Create basic variable info
        variables = [
            InferredVariable(
                name=var_name,
                var_type="string",
                occurrences=1,
                confidence=1.0,
                sample_values=[text[start:end]],
                pattern_types=["manual"],
            )
            for start, end, var_name in markers
        ]

        return GeneratedTemplate(
            content=result,
            variables=variables,
            original_text=text,
            replacements_made=len(markers),
        )
