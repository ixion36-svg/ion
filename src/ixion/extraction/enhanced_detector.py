"""Enhanced pattern detector combining regex patterns with NLP-based NER."""

from dataclasses import dataclass
from typing import Dict, List, Optional, Set

from ixion.extraction.pattern_detector import PatternDetector, PatternMatch
from ixion.extraction.nlp_service import get_nlp_service, NEREntity


@dataclass
class EnhancedMatch:
    """Represents a detected pattern from either regex or NER."""

    pattern_type: str
    value: str
    start: int
    end: int
    confidence: float
    suggested_name: str
    source: str  # "regex" or "nlp"
    nlp_label: Optional[str] = None  # Original NER label if from NLP


class EnhancedPatternDetector:
    """Pattern detector that combines regex patterns with NLP-based NER.

    This detector uses both approaches:
    1. Regex patterns for structured data (emails, phones, URLs, dates in specific formats)
    2. NLP/NER for semantic entities (names, organizations, locations, contextual dates)

    The results are merged, with conflicts resolved by confidence score.
    """

    def __init__(self, use_nlp: bool = True):
        """Initialize the enhanced detector.

        Args:
            use_nlp: Whether to use NLP-based detection. Set to False to use regex only.
        """
        self.regex_detector = PatternDetector()
        self.use_nlp = use_nlp
        self._nlp_service = None

    @property
    def nlp_service(self):
        """Lazy-load NLP service."""
        if self._nlp_service is None:
            self._nlp_service = get_nlp_service()
        return self._nlp_service

    @property
    def nlp_available(self) -> bool:
        """Check if NLP is available."""
        return self.use_nlp and self.nlp_service.is_available

    def detect(
        self,
        text: str,
        min_confidence: float = 0.5,
        use_nlp: Optional[bool] = None,
    ) -> List[EnhancedMatch]:
        """Detect patterns using both regex and NLP.

        Args:
            text: The text to analyze.
            min_confidence: Minimum confidence threshold (0-1).
            use_nlp: Override the default NLP setting for this call.

        Returns:
            List of detected patterns, merged and deduplicated.
        """
        should_use_nlp = use_nlp if use_nlp is not None else self.use_nlp

        # Get regex matches
        regex_matches = self._get_regex_matches(text, min_confidence)

        # Get NLP matches if enabled
        nlp_matches = []
        if should_use_nlp and self.nlp_available:
            nlp_matches = self._get_nlp_matches(text, min_confidence)

        # Merge and deduplicate
        all_matches = self._merge_matches(regex_matches, nlp_matches)

        # Sort by position
        all_matches.sort(key=lambda m: m.start)

        return all_matches

    def _get_regex_matches(
        self, text: str, min_confidence: float
    ) -> List[EnhancedMatch]:
        """Get matches from regex patterns."""
        regex_results = self.regex_detector.detect(text, min_confidence)

        return [
            EnhancedMatch(
                pattern_type=m.pattern_type,
                value=m.value,
                start=m.start,
                end=m.end,
                confidence=m.confidence,
                suggested_name=m.suggested_name,
                source="regex",
            )
            for m in regex_results
        ]

    def _get_nlp_matches(
        self, text: str, min_confidence: float
    ) -> List[EnhancedMatch]:
        """Get matches from NLP-based NER."""
        entities = self.nlp_service.extract_entities(text, min_confidence)

        return [
            EnhancedMatch(
                pattern_type=e.pattern_type,
                value=e.text,
                start=e.start,
                end=e.end,
                confidence=e.confidence,
                suggested_name=e.suggested_name,
                source="nlp",
                nlp_label=e.label,
            )
            for e in entities
        ]

    def _merge_matches(
        self,
        regex_matches: List[EnhancedMatch],
        nlp_matches: List[EnhancedMatch],
    ) -> List[EnhancedMatch]:
        """Merge regex and NLP matches, handling overlaps.

        Strategy:
        1. For exact overlaps, keep the higher confidence match
        2. For partial overlaps, prefer regex for structured data, NLP for semantic
        3. Keep non-overlapping matches from both sources
        """
        all_matches = regex_matches + nlp_matches

        if not all_matches:
            return []

        # Sort by confidence (descending), then by start position
        all_matches.sort(key=lambda m: (-m.confidence, m.start))

        # Track covered character ranges
        covered: Set[int] = set()
        result: List[EnhancedMatch] = []

        # Structured pattern types that regex handles better
        regex_preferred = {
            "email", "url", "phone_us", "phone_intl",
            "date_iso", "date_us", "date_eu",
            "currency_usd", "currency_eur", "percentage",
            "placeholder_bracket", "placeholder_angle", "placeholder_underscore",
            "address_zip",
        }

        for match in all_matches:
            match_range = set(range(match.start, match.end))

            # Check overlap with already selected matches
            overlap = match_range & covered

            if not overlap:
                # No overlap - add the match
                result.append(match)
                covered.update(match_range)
            elif len(overlap) < len(match_range) * 0.5:
                # Less than 50% overlap - might be a different entity
                # Check if it's a significantly different type
                pass  # For now, skip partial overlaps

        return result

    def detect_by_source(
        self,
        text: str,
        source: str,
        min_confidence: float = 0.5,
    ) -> List[EnhancedMatch]:
        """Detect patterns from a specific source only.

        Args:
            text: The text to analyze.
            source: "regex" or "nlp".
            min_confidence: Minimum confidence threshold.

        Returns:
            List of matches from the specified source.
        """
        if source == "regex":
            return self._get_regex_matches(text, min_confidence)
        elif source == "nlp":
            if self.nlp_available:
                return self._get_nlp_matches(text, min_confidence)
            return []
        else:
            raise ValueError(f"Unknown source: {source}. Use 'regex' or 'nlp'.")

    def get_detection_summary(
        self,
        text: str,
        min_confidence: float = 0.5,
    ) -> Dict:
        """Get a summary of all detections with statistics.

        Returns:
            Dictionary with matches, counts by type, and source statistics.
        """
        matches = self.detect(text, min_confidence)

        # Count by pattern type
        type_counts: Dict[str, int] = {}
        for m in matches:
            type_counts[m.pattern_type] = type_counts.get(m.pattern_type, 0) + 1

        # Count by source
        source_counts = {"regex": 0, "nlp": 0}
        for m in matches:
            source_counts[m.source] += 1

        # Get unique values by type
        values_by_type: Dict[str, List[str]] = {}
        for m in matches:
            if m.pattern_type not in values_by_type:
                values_by_type[m.pattern_type] = []
            if m.value not in values_by_type[m.pattern_type]:
                values_by_type[m.pattern_type].append(m.value)

        return {
            "matches": matches,
            "total_count": len(matches),
            "by_type": type_counts,
            "by_source": source_counts,
            "unique_values_by_type": values_by_type,
            "nlp_available": self.nlp_available,
        }


def convert_to_pattern_match(enhanced: EnhancedMatch) -> PatternMatch:
    """Convert an EnhancedMatch back to a PatternMatch for compatibility."""
    return PatternMatch(
        pattern_type=enhanced.pattern_type,
        value=enhanced.value,
        start=enhanced.start,
        end=enhanced.end,
        confidence=enhanced.confidence,
        suggested_name=enhanced.suggested_name,
    )
