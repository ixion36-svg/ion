"""Version compatibility checking for integration connectors.

Declares supported version ranges for external services and provides
utilities to check detected versions against those ranges.
"""

import re
from dataclasses import dataclass
from typing import Tuple


@dataclass(frozen=True)
class VersionRange:
    """Supported version range for an external service."""
    min_version: str
    max_version: str
    recommended_version: str


# --- Supported version ranges (update these when upgrading) ---

ELASTICSEARCH_VERSIONS = VersionRange(
    min_version="8.0.0",
    max_version="9.3.0",
    recommended_version="9.3.0",
)

KIBANA_VERSIONS = VersionRange(
    min_version="8.0.0",
    max_version="9.3.0",
    recommended_version="9.3.0",
)


def parse_version(version_string: str) -> Tuple[int, ...]:
    """Parse a version string like '9.3.0-SNAPSHOT' into a tuple of ints.

    Strips pre-release suffixes (-SNAPSHOT, -rc1, etc.) and splits on dots.
    Returns (0, 0, 0) if the string cannot be parsed.
    """
    if not version_string:
        return (0, 0, 0)

    # Strip everything after a hyphen (pre-release suffix)
    clean = re.split(r"[-+]", version_string)[0].strip()

    try:
        parts = tuple(int(p) for p in clean.split("."))
    except (ValueError, AttributeError):
        return (0, 0, 0)

    # Pad to at least 3 components
    while len(parts) < 3:
        parts = parts + (0,)

    return parts


def check_version_compatibility(
    detected_version: str,
    version_range: VersionRange,
) -> dict:
    """Check whether a detected version falls within the supported range.

    Args:
        detected_version: Version string reported by the external service.
        version_range: The supported VersionRange to check against.

    Returns:
        Dict with keys:
            is_compatible (bool): Always True — we never block a working connection.
            in_range (bool): True if the version is within min..max inclusive.
            message (str): Human-readable explanation.
            detected (str): The raw detected version string.
            tested_range (str): "min_version - max_version".
            recommended (str): The recommended version.
    """
    detected = parse_version(detected_version)
    vmin = parse_version(version_range.min_version)
    vmax = parse_version(version_range.max_version)

    in_range = vmin <= detected <= vmax

    if in_range:
        message = f"Version {detected_version} is within tested range ({version_range.min_version} - {version_range.max_version})"
    elif detected < vmin:
        message = (
            f"Version {detected_version} is below the minimum tested version "
            f"({version_range.min_version}). Consider upgrading to {version_range.recommended_version}."
        )
    else:
        message = (
            f"Version {detected_version} is above the maximum tested version "
            f"({version_range.max_version}). ION has not been validated against this version."
        )

    return {
        "is_compatible": True,
        "in_range": in_range,
        "message": message,
        "detected": detected_version,
        "tested_range": f"{version_range.min_version} - {version_range.max_version}",
        "recommended": version_range.recommended_version,
    }
