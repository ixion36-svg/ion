"""Pattern detection for template extraction."""

import re
from dataclasses import dataclass
from typing import List


@dataclass
class PatternMatch:
    """Represents a detected pattern in text."""

    pattern_type: str
    value: str
    start: int
    end: int
    confidence: float
    suggested_name: str


class PatternDetector:
    """Detect patterns in documents for template extraction."""

    def __init__(self):
        self.patterns = {
            "email": {
                "regex": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
                "confidence": 0.95,
                "suggested_name": "email",
            },
            "date_iso": {
                "regex": r"\b\d{4}-\d{2}-\d{2}\b",
                "confidence": 0.9,
                "suggested_name": "date",
            },
            "date_us": {
                "regex": r"\b\d{1,2}/\d{1,2}/\d{2,4}\b",
                "confidence": 0.85,
                "suggested_name": "date",
            },
            "date_eu": {
                "regex": r"\b\d{1,2}\.\d{1,2}\.\d{2,4}\b",
                "confidence": 0.85,
                "suggested_name": "date",
            },
            "phone_us": {
                "regex": r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
                "confidence": 0.85,
                "suggested_name": "phone",
            },
            "phone_intl": {
                "regex": r"\b\+\d{1,3}[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,9}\b",
                "confidence": 0.8,
                "suggested_name": "phone",
            },
            "url": {
                "regex": r"https?://[^\s<>\"']+",
                "confidence": 0.95,
                "suggested_name": "url",
            },
            "currency_usd": {
                "regex": r"\$\d{1,3}(?:,\d{3})*(?:\.\d{2})?",
                "confidence": 0.9,
                "suggested_name": "amount",
            },
            "currency_eur": {
                "regex": r"€\d{1,3}(?:\.\d{3})*(?:,\d{2})?",
                "confidence": 0.9,
                "suggested_name": "amount",
            },
            "percentage": {
                "regex": r"\b\d+(?:\.\d+)?%",
                "confidence": 0.85,
                "suggested_name": "percentage",
            },
            "placeholder_bracket": {
                "regex": r"\[([A-Z][A-Z0-9_\s]+)\]",
                "confidence": 0.95,
                "suggested_name": None,  # Use captured group
            },
            "placeholder_angle": {
                "regex": r"<([A-Z][A-Z0-9_\s]+)>",
                "confidence": 0.95,
                "suggested_name": None,
            },
            "placeholder_underscore": {
                "regex": r"_{3,}",
                "confidence": 0.7,
                "suggested_name": "field",
            },
            "name_pattern": {
                "regex": r"\b(?:Mr\.|Mrs\.|Ms\.|Dr\.)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+",
                "confidence": 0.8,
                "suggested_name": "name",
            },
            "company_suffix": {
                "regex": r"\b[A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+)*\s+(?:Inc\.|LLC|Ltd\.|Corp\.|Co\.)",
                "confidence": 0.85,
                "suggested_name": "company",
            },
            "address_zip": {
                "regex": r"\b\d{5}(?:-\d{4})?\b",
                "confidence": 0.7,
                "suggested_name": "zip_code",
            },
        }

    def detect(self, text: str, min_confidence: float = 0.5) -> List[PatternMatch]:
        """Detect all patterns in the text above minimum confidence."""
        matches: List[PatternMatch] = []

        for pattern_type, pattern_info in self.patterns.items():
            regex = pattern_info["regex"]
            base_confidence = pattern_info["confidence"]
            suggested_name = pattern_info["suggested_name"]

            for match in re.finditer(regex, text):
                # Determine the variable name
                if suggested_name is None:
                    # Use captured group if available
                    if match.groups():
                        var_name = match.group(1).lower().replace(" ", "_")
                    else:
                        var_name = pattern_type
                else:
                    var_name = suggested_name

                # Adjust confidence based on context
                confidence = self._adjust_confidence(
                    base_confidence, match, text, pattern_type
                )

                if confidence >= min_confidence:
                    matches.append(
                        PatternMatch(
                            pattern_type=pattern_type,
                            value=match.group(0),
                            start=match.start(),
                            end=match.end(),
                            confidence=confidence,
                            suggested_name=var_name,
                        )
                    )

        # Sort by position
        matches.sort(key=lambda m: m.start)

        # Remove overlapping matches, keeping higher confidence
        return self._remove_overlaps(matches)

    def _adjust_confidence(
        self, base_confidence: float, match: re.Match, text: str, pattern_type: str
    ) -> float:
        """Adjust confidence based on context."""
        confidence = base_confidence

        # Check for common labels before the match
        labels = {
            "email": ["email", "e-mail", "contact"],
            "phone": ["phone", "tel", "telephone", "mobile", "cell"],
            "date": ["date", "on", "dated"],
            "name": ["name", "to", "from", "attention", "attn"],
            "amount": ["amount", "total", "price", "cost", "fee"],
            "url": ["website", "link", "url"],
        }

        # Get text before match
        start = max(0, match.start() - 50)
        context_before = text[start : match.start()].lower()

        # Check if any relevant labels appear before
        for key, label_list in labels.items():
            if key in pattern_type:
                for label in label_list:
                    if label in context_before:
                        confidence = min(1.0, confidence + 0.05)
                        break

        return confidence

    def _remove_overlaps(self, matches: List[PatternMatch]) -> List[PatternMatch]:
        """Remove overlapping matches, keeping higher confidence ones."""
        if not matches:
            return matches

        result: List[PatternMatch] = []
        matches_sorted = sorted(matches, key=lambda m: (-m.confidence, m.start))

        covered = set()

        for match in matches_sorted:
            # Check if this range is already covered
            match_range = set(range(match.start, match.end))
            if not match_range & covered:
                result.append(match)
                covered.update(match_range)

        # Return in position order
        result.sort(key=lambda m: m.start)
        return result

    def detect_by_type(
        self, text: str, pattern_types: List[str], min_confidence: float = 0.5
    ) -> List[PatternMatch]:
        """Detect only specific pattern types."""
        all_matches = self.detect(text, min_confidence)
        return [m for m in all_matches if m.pattern_type in pattern_types]
