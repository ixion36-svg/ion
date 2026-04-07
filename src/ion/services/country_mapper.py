"""Threat actor country attribution — resolves actor names/aliases to ISO country codes.

Ported from TIDE's cti_helper.py ISO_MAP. Uses name and alias matching to determine
the most likely country of origin for threat actor groups.
"""

import re
from typing import Optional

# Actor name / alias → ISO 3166-1 alpha-2 country code (lowercase)
# Sorted longest-first during matching to avoid partial hits.
ISO_MAP = {
    # Russia
    "RU": "ru", "RUSSIA": "ru", "RUSSIAN": "ru", "USSR": "ru",
    "TURLA": "ru", "VENOMOUS BEAR": "ru", "WATERBUG": "ru", "IRON HUNTER": "ru",
    "APT28": "ru", "FANCY BEAR": "ru", "APT29": "ru", "COZY BEAR": "ru",
    "NOBELIUM": "ru", "SANDWORM": "ru", "DRAGONFLY": "ru", "WIZARD SPIDER": "ru",
    "GAMAREDON": "ru", "PRIMITIVE BEAR": "ru", "MIDNIGHT BLIZZARD": "ru",
    "FOREST BLIZZARD": "ru", "STAR BLIZZARD": "ru", "SEASHELL BLIZZARD": "ru",
    "EMBER BEAR": "ru", "VOODOO BEAR": "ru", "ENERGETIC BEAR": "ru",
    "BERSERK BEAR": "ru", "CALLISTO": "ru",
    # China
    "CN": "cn", "CHINA": "cn", "CHINESE": "cn", "PRC": "cn",
    "APT41": "cn", "WICKED PANDA": "cn", "APT40": "cn", "MUSTANG PANDA": "cn",
    "HAFNIUM": "cn", "APT31": "cn", "APT10": "cn", "STONE PANDA": "cn",
    "APT27": "cn", "EMISSARY PANDA": "cn", "WINNTI": "cn",
    "VOLT TYPHOON": "cn", "BRONZE SILHOUETTE": "cn",
    "SALT TYPHOON": "cn", "FLAX TYPHOON": "cn", "CHARCOAL TYPHOON": "cn",
    "SILK TYPHOON": "cn", "RASPBERRY TYPHOON": "cn",
    "APT1": "cn", "COMMENT CREW": "cn", "APT3": "cn", "GOTHIC PANDA": "cn",
    "APT17": "cn", "DEPUTY DOG": "cn", "DEEP PANDA": "cn",
    "AQUATIC PANDA": "cn", "JUDGMENT PANDA": "cn",
    # North Korea
    "KP": "kp", "NORTH KOREA": "kp", "DPRK": "kp", "PYONGYANG": "kp",
    "LAZARUS": "kp", "HIDDEN COBRA": "kp", "KIMSUKY": "kp", "VELVET CHOLLIMA": "kp",
    "ANDARIEL": "kp", "SILENT CHOLLIMA": "kp", "ONYX SLEET": "kp", "PLUTONIUM": "kp",
    "APT37": "kp", "RICOCHET CHOLLIMA": "kp", "SCARCRUFT": "kp", "INKYSQUID": "kp",
    "APT38": "kp", "BLUENOROFF": "kp", "STARDUST CHOLLIMA": "kp",
    "LABYRINTH CHOLLIMA": "kp", "DIAMOND SLEET": "kp", "CITRINE SLEET": "kp",
    "JADE SLEET": "kp", "SAPPHIRE SLEET": "kp",
    # Iran
    "IR": "ir", "IRAN": "ir", "IRANIAN": "ir",
    "APT33": "ir", "ELFIN": "ir", "APT34": "ir", "OILRIG": "ir",
    "MUDDYWATER": "ir", "APT35": "ir", "CHARMING KITTEN": "ir",
    "APT42": "ir", "PHOSPHORUS": "ir", "MINT SANDSTORM": "ir",
    "PEACH SANDSTORM": "ir", "MANGO SANDSTORM": "ir",
    "COTTON SANDSTORM": "ir", "CRIMSON SANDSTORM": "ir",
    # Vietnam
    "VN": "vn", "VIETNAM": "vn", "OCEANLOTUS": "vn", "APT32": "vn",
    "CANVAS CYCLONE": "vn",
    # India
    "IN": "in", "INDIA": "in", "SIDEWINDER": "in", "PATCHWORK": "in",
    # Pakistan
    "PK": "pk", "PAKISTAN": "pk", "TRANSPARENT TRIBE": "pk", "APT36": "pk",
    # Israel
    "IL": "il", "ISRAEL": "il", "UNIT 8200": "il",
    # South Korea
    "KR": "kr", "SOUTH KOREA": "kr", "DARKHOTEL": "kr",
    # USA
    "US": "us", "USA": "us", "EQUATION GROUP": "us",
    "SCATTERED SPIDER": "us", "OCTO TEMPEST": "us", "0KTAPUS": "us",
    # Turkey
    "TR": "tr", "TURKEY": "tr", "SEA TURTLE": "tr",
    # Belarus
    "BY": "by", "BELARUS": "by", "GHOSTWRITER": "by",
}

# Country code → display name
COUNTRY_NAMES = {
    "ru": "Russia", "cn": "China", "kp": "North Korea", "ir": "Iran",
    "vn": "Vietnam", "in": "India", "pk": "Pakistan", "il": "Israel",
    "kr": "South Korea", "us": "United States", "tr": "Turkey", "by": "Belarus",
}

# Pre-sorted keywords (longest first for greedy matching)
_SORTED_KEYWORDS = sorted(ISO_MAP.keys(), key=len, reverse=True)


def get_country_code(name: str, aliases: Optional[list[str]] = None) -> Optional[str]:
    """Resolve a threat actor's country of origin from name and aliases.

    Args:
        name: Threat actor name (e.g. "APT28", "Lazarus Group")
        aliases: Optional list of alternative names

    Returns:
        ISO 3166-1 alpha-2 code (lowercase) or None if unknown.
    """
    # Build a single search string from name + aliases
    parts = [name or ""]
    if aliases:
        parts.extend(aliases)
    search_text = " ".join(parts).upper()

    for keyword in _SORTED_KEYWORDS:
        pattern = r"\b" + re.escape(keyword) + r"\b"
        if re.search(pattern, search_text):
            return ISO_MAP[keyword]

    return None


def get_country_name(code: Optional[str]) -> str:
    """Return human-readable country name for a code, or empty string."""
    if not code:
        return ""
    return COUNTRY_NAMES.get(code, code.upper())


def country_code_to_flag(code: Optional[str]) -> str:
    """Convert ISO country code to Unicode flag emoji.

    e.g. "ru" → "🇷🇺", "cn" → "🇨🇳"
    """
    if not code or len(code) != 2:
        return ""
    return "".join(chr(0x1F1E6 + ord(c) - ord("a")) for c in code.lower())
