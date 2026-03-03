"""Data loading utilities for template rendering."""

import json
import csv
from pathlib import Path
from typing import Any

from ion.core.exceptions import ValidationError


class DataLoader:
    """Load data from various file formats."""

    def load(self, path: Path) -> dict[str, Any]:
        """Load data from a file based on its extension."""
        if not path.exists():
            raise ValidationError("data_file", f"File not found: {path}")

        suffix = path.suffix.lower()

        if suffix == ".json":
            return self.load_json(path)
        elif suffix == ".csv":
            return self.load_csv(path)
        else:
            raise ValidationError(
                "data_file", f"Unsupported file format: {suffix}. Use .json or .csv"
            )

    def load_json(self, path: Path) -> dict[str, Any]:
        """Load data from a JSON file."""
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                raise ValidationError(
                    "data_file", "JSON file must contain an object at the root level"
                )
            return data
        except json.JSONDecodeError as e:
            raise ValidationError("data_file", f"Invalid JSON: {e}")

    def load_csv(self, path: Path) -> dict[str, Any]:
        """Load data from a CSV file.

        Returns a dict with:
        - 'rows': list of row dicts
        - 'headers': list of column names
        - Each column name also available as a list of values
        """
        try:
            with open(path, "r", encoding="utf-8", newline="") as f:
                reader = csv.DictReader(f)
                rows = list(reader)
                headers = reader.fieldnames or []

            result: dict[str, Any] = {
                "rows": rows,
                "headers": headers,
            }

            # Also provide columns as separate lists
            for header in headers:
                result[header] = [row.get(header, "") for row in rows]

            return result
        except csv.Error as e:
            raise ValidationError("data_file", f"Invalid CSV: {e}")

    def load_string(self, content: str, format: str = "json") -> dict[str, Any]:
        """Load data from a string."""
        if format == "json":
            try:
                data = json.loads(content)
                if not isinstance(data, dict):
                    raise ValidationError(
                        "data", "JSON must contain an object at the root level"
                    )
                return data
            except json.JSONDecodeError as e:
                raise ValidationError("data", f"Invalid JSON: {e}")
        else:
            raise ValidationError("format", f"Unsupported format: {format}")
