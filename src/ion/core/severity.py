"""The alert severities ION renders, and the names senders use for them.

One table, because an alert reaches the queue by more than one door (an
Elasticsearch document, a webhook delivery, an analyst's triage update) and
the queue has one set of badges. A door with its own copy of the table is a
door that drifts.
"""
from __future__ import annotations

from typing import Any

SEVERITIES = ("critical", "high", "medium", "low", "info")

_ALIASES = {
    "1": "critical", "critical": "critical", "crit": "critical",
    "2": "high", "high": "high",
    "3": "medium", "medium": "medium", "med": "medium", "warning": "medium",
    "4": "low", "low": "low",
    "5": "info", "info": "info", "informational": "info",
}


def normalize_severity(value: Any, default: str = "medium") -> str:
    """The severity ION renders for whatever a source called it.

    Anything unrecognised becomes `default`. Use this where the alert must
    still be accepted; a caller that should refuse an unknown value checks
    membership of `SEVERITIES` instead.
    """
    return _ALIASES.get(str(value).strip().lower(), default)
