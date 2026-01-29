"""Generate templates from documents with detected patterns."""

from dataclasses import dataclass, field
from typing import List, Optional, Dict
from pathlib import Path

from ixion.extraction.pattern_detector import PatternDetector, PatternMatch
from ixion.extraction.enhanced_detector import EnhancedPatternDetector, EnhancedMatch, convert_to_pattern_match
from ixion.extraction.variable_inferrer import VariableInferrer, InferredVariable
from ixion.plugins import PluginRegistry


@dataclass
class GeneratedTemplate:
    """Result of template generation."""

    content: str
    variables: List[InferredVariable]
    original_text: str
    replacements_made: int
    nlp_used: bool = False
    detection_stats: Dict = field(default_factory=dict)


class TemplateGenerator:
    """Generate templates from documents.

    Supports both regex-based and NLP-based entity detection.
    """

    def __init__(self, use_nlp: bool = True):
        """Initialize the template generator.

        Args:
            use_nlp: Whether to use NLP-based detection (spaCy NER).
                    Falls back to regex-only if spaCy is not available.
        """
        self.use_nlp = use_nlp
        self.enhanced_detector = EnhancedPatternDetector(use_nlp=use_nlp)
        self.regex_detector = PatternDetector()  # Keep for backwards compatibility
        self.inferrer = VariableInferrer()
        self.plugin_registry = PluginRegistry()

    @property
    def nlp_available(self) -> bool:
        """Check if NLP detection is available."""
        return self.enhanced_detector.nlp_available

    def analyze(
        self,
        text: str,
        min_confidence: float = 0.5,
        use_nlp: Optional[bool] = None,
    ) -> tuple[List[PatternMatch], List[InferredVariable], Dict]:
        """Analyze text and return detected patterns and inferred variables.

        Args:
            text: The text to analyze.
            min_confidence: Minimum confidence threshold (0-1).
            use_nlp: Override NLP setting for this call. None uses instance default.

        Returns:
            Tuple of (matches, variables, stats) where stats contains detection info.
        """
        should_use_nlp = use_nlp if use_nlp is not None else self.use_nlp

        # Get detection summary with both sources
        summary = self.enhanced_detector.get_detection_summary(
            text, min_confidence
        )

        # Convert enhanced matches back to PatternMatch for compatibility
        matches = [convert_to_pattern_match(m) for m in summary["matches"]]

        # Infer variables
        variables = self.inferrer.infer(matches)

        stats = {
            "total_matches": summary["total_count"],
            "by_type": summary["by_type"],
            "by_source": summary["by_source"],
            "nlp_available": summary["nlp_available"],
            "nlp_used": should_use_nlp and summary["nlp_available"],
        }

        return matches, variables, stats

    def analyze_file(
        self,
        path: Path,
        min_confidence: float = 0.5,
        use_nlp: Optional[bool] = None,
    ) -> tuple[List[PatternMatch], List[InferredVariable], str, Dict]:
        """Analyze a file and return patterns, variables, content, and stats.

        Args:
            path: Path to the file to analyze.
            min_confidence: Minimum confidence threshold (0-1).
            use_nlp: Override NLP setting for this call.

        Returns:
            Tuple of (matches, variables, content, stats).
        """
        # Read file content using appropriate plugin
        plugin = self.plugin_registry.get_plugin_for_file(path)
        if plugin:
            text = plugin.read(path)
        else:
            text = path.read_text(encoding="utf-8")

        matches, variables, stats = self.analyze(text, min_confidence, use_nlp)
        return matches, variables, text, stats

    def generate(
        self,
        text: str,
        min_confidence: float = 0.7,
        use_filters: bool = True,
        use_nlp: Optional[bool] = None,
    ) -> GeneratedTemplate:
        """Generate a template from text.

        Args:
            text: The text to generate a template from.
            min_confidence: Minimum confidence threshold (0-1).
            use_filters: Whether to add Jinja2 filters based on pattern type.
            use_nlp: Override NLP setting for this call.

        Returns:
            GeneratedTemplate with the template content and variables.
        """
        matches, variables, stats = self.analyze(text, min_confidence, use_nlp)

        # Create template by replacing matches with Jinja2 variables
        template_content = self._replace_with_variables(text, matches, use_filters)

        return GeneratedTemplate(
            content=template_content,
            variables=variables,
            original_text=text,
            replacements_made=len(matches),
            nlp_used=stats.get("nlp_used", False),
            detection_stats=stats,
        )

    def generate_from_file(
        self,
        path: Path,
        min_confidence: float = 0.7,
        use_filters: bool = True,
        use_nlp: Optional[bool] = None,
    ) -> GeneratedTemplate:
        """Generate a template from a file.

        Args:
            path: Path to the file.
            min_confidence: Minimum confidence threshold (0-1).
            use_filters: Whether to add Jinja2 filters.
            use_nlp: Override NLP setting for this call.

        Returns:
            GeneratedTemplate with the template content and variables.
        """
        # Read file content
        plugin = self.plugin_registry.get_plugin_for_file(path)
        if plugin:
            text = plugin.read(path)
        else:
            text = path.read_text(encoding="utf-8")

        return self.generate(text, min_confidence, use_filters, use_nlp)

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
            # Regex-detected types
            "date_iso": "",
            "date_us": "",
            "date_eu": "",
            "currency_usd": "",
            "currency_eur": "",
            "percentage": "",
            "email": " | lower",
            "name_pattern": " | title",
            # NLP-detected types
            "person_name": " | title",
            "organization": "",
            "location": " | title",
            "date_nlp": "",
            "time": "",
            "currency_nlp": "",
            "percentage_nlp": "",
            "number": "",
            "ordinal": "",
            "quantity": "",
            "facility": "",
            "product": "",
            "event": "",
            "work_of_art": "",
            "law": "",
            "language": "",
            "group": "",
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
