"""Variable inference from detected patterns."""

from dataclasses import dataclass
from typing import List
from collections import defaultdict

from ixion.extraction.pattern_detector import PatternMatch


@dataclass
class InferredVariable:
    """Represents an inferred template variable."""

    name: str
    var_type: str
    occurrences: int
    confidence: float
    sample_values: List[str]
    pattern_types: List[str]


class VariableInferrer:
    """Infer template variables from detected patterns."""

    # Map pattern types to variable types
    TYPE_MAP = {
        "email": "email",
        "date_iso": "date",
        "date_us": "date",
        "date_eu": "date",
        "phone_us": "phone",
        "phone_intl": "phone",
        "url": "url",
        "currency_usd": "currency",
        "currency_eur": "currency",
        "percentage": "number",
        "placeholder_bracket": "string",
        "placeholder_angle": "string",
        "placeholder_underscore": "string",
        "name_pattern": "name",
        "company_suffix": "string",
        "address_zip": "string",
    }

    def infer(self, matches: List[PatternMatch]) -> List[InferredVariable]:
        """Infer variables from pattern matches."""
        # Group matches by suggested name
        grouped: dict[str, List[PatternMatch]] = defaultdict(list)

        for match in matches:
            grouped[match.suggested_name].append(match)

        variables: List[InferredVariable] = []

        for name, group_matches in grouped.items():
            # Deduplicate the name if needed
            unique_name = self._make_unique_name(name, variables)

            # Determine the most common pattern type
            pattern_types = [m.pattern_type for m in group_matches]
            primary_type = max(set(pattern_types), key=pattern_types.count)

            # Calculate aggregate confidence
            avg_confidence = sum(m.confidence for m in group_matches) / len(group_matches)

            # Get unique sample values
            sample_values = list(set(m.value for m in group_matches))[:5]

            # Determine variable type
            var_type = self.TYPE_MAP.get(primary_type, "string")

            variables.append(
                InferredVariable(
                    name=unique_name,
                    var_type=var_type,
                    occurrences=len(group_matches),
                    confidence=avg_confidence,
                    sample_values=sample_values,
                    pattern_types=list(set(pattern_types)),
                )
            )

        # Sort by confidence (descending) then by occurrences (descending)
        variables.sort(key=lambda v: (-v.confidence, -v.occurrences))

        return variables

    def _make_unique_name(
        self, name: str, existing: List[InferredVariable]
    ) -> str:
        """Ensure variable name is unique."""
        existing_names = {v.name for v in existing}

        if name not in existing_names:
            return name

        # Add numeric suffix
        counter = 2
        while f"{name}_{counter}" in existing_names:
            counter += 1

        return f"{name}_{counter}"

    def filter_by_confidence(
        self, variables: List[InferredVariable], min_confidence: float
    ) -> List[InferredVariable]:
        """Filter variables by minimum confidence."""
        return [v for v in variables if v.confidence >= min_confidence]

    def suggest_required(
        self, variables: List[InferredVariable]
    ) -> List[InferredVariable]:
        """Suggest which variables should be required."""
        # Variables with high confidence and/or multiple occurrences
        # are likely required
        for var in variables:
            # Mark as required if high confidence or multiple occurrences
            var.required = var.confidence >= 0.8 or var.occurrences > 1  # type: ignore

        return variables

    def to_schema(self, variables: List[InferredVariable]) -> dict:
        """Convert inferred variables to a JSON schema."""
        properties = {}
        required = []

        for var in variables:
            prop = {
                "type": self._json_schema_type(var.var_type),
                "description": f"Inferred from {', '.join(var.pattern_types)}",
            }

            # Add format hints
            if var.var_type == "email":
                prop["format"] = "email"
            elif var.var_type == "date":
                prop["format"] = "date"
            elif var.var_type == "url":
                prop["format"] = "uri"

            # Add examples
            if var.sample_values:
                prop["examples"] = var.sample_values

            properties[var.name] = prop

            # Determine if required
            if var.confidence >= 0.8 or var.occurrences > 1:
                required.append(var.name)

        return {
            "type": "object",
            "properties": properties,
            "required": required,
        }

    def _json_schema_type(self, var_type: str) -> str:
        """Convert internal type to JSON schema type."""
        type_map = {
            "string": "string",
            "email": "string",
            "date": "string",
            "phone": "string",
            "url": "string",
            "currency": "number",
            "number": "number",
            "name": "string",
        }
        return type_map.get(var_type, "string")
