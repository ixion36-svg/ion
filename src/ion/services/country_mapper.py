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

# Country code → display name (threat-actor attribution set; display names
# here win over the ISO table below, e.g. "Russia" not "Russian Federation")
COUNTRY_NAMES = {
    "ru": "Russia", "cn": "China", "kp": "North Korea", "ir": "Iran",
    "vn": "Vietnam", "in": "India", "pk": "Pakistan", "il": "Israel",
    "kr": "South Korea", "us": "United States", "tr": "Turkey", "by": "Belarus",
}

# Full ISO 3166-1 alpha-2 → display name (static — air-gapped, no GeoIP dep).
# Used to render the 2-letter codes ES geo pipelines ship
# (source.geo.country_iso_code) as human-readable names.
ISO2_COUNTRY_NAMES = {
    "AD": "Andorra", "AE": "United Arab Emirates", "AF": "Afghanistan",
    "AG": "Antigua and Barbuda", "AI": "Anguilla", "AL": "Albania",
    "AM": "Armenia", "AO": "Angola", "AQ": "Antarctica", "AR": "Argentina",
    "AS": "American Samoa", "AT": "Austria", "AU": "Australia", "AW": "Aruba",
    "AX": "Åland Islands", "AZ": "Azerbaijan", "BA": "Bosnia and Herzegovina",
    "BB": "Barbados", "BD": "Bangladesh", "BE": "Belgium", "BF": "Burkina Faso",
    "BG": "Bulgaria", "BH": "Bahrain", "BI": "Burundi", "BJ": "Benin",
    "BL": "Saint Barthélemy", "BM": "Bermuda", "BN": "Brunei", "BO": "Bolivia",
    "BQ": "Bonaire", "BR": "Brazil", "BS": "Bahamas", "BT": "Bhutan",
    "BV": "Bouvet Island", "BW": "Botswana", "BY": "Belarus", "BZ": "Belize",
    "CA": "Canada", "CC": "Cocos Islands", "CD": "DR Congo",
    "CF": "Central African Republic", "CG": "Congo", "CH": "Switzerland",
    "CI": "Côte d'Ivoire", "CK": "Cook Islands", "CL": "Chile", "CM": "Cameroon",
    "CN": "China", "CO": "Colombia", "CR": "Costa Rica", "CU": "Cuba",
    "CV": "Cabo Verde", "CW": "Curaçao", "CX": "Christmas Island",
    "CY": "Cyprus", "CZ": "Czechia", "DE": "Germany", "DJ": "Djibouti",
    "DK": "Denmark", "DM": "Dominica", "DO": "Dominican Republic",
    "DZ": "Algeria", "EC": "Ecuador", "EE": "Estonia", "EG": "Egypt",
    "EH": "Western Sahara", "ER": "Eritrea", "ES": "Spain", "ET": "Ethiopia",
    "FI": "Finland", "FJ": "Fiji", "FK": "Falkland Islands", "FM": "Micronesia",
    "FO": "Faroe Islands", "FR": "France", "GA": "Gabon",
    "GB": "United Kingdom", "GD": "Grenada", "GE": "Georgia",
    "GF": "French Guiana", "GG": "Guernsey", "GH": "Ghana", "GI": "Gibraltar",
    "GL": "Greenland", "GM": "Gambia", "GN": "Guinea", "GP": "Guadeloupe",
    "GQ": "Equatorial Guinea", "GR": "Greece", "GS": "South Georgia",
    "GT": "Guatemala", "GU": "Guam", "GW": "Guinea-Bissau", "GY": "Guyana",
    "HK": "Hong Kong", "HM": "Heard Island", "HN": "Honduras", "HR": "Croatia",
    "HT": "Haiti", "HU": "Hungary", "ID": "Indonesia", "IE": "Ireland",
    "IL": "Israel", "IM": "Isle of Man", "IN": "India",
    "IO": "British Indian Ocean Territory", "IQ": "Iraq", "IR": "Iran",
    "IS": "Iceland", "IT": "Italy", "JE": "Jersey", "JM": "Jamaica",
    "JO": "Jordan", "JP": "Japan", "KE": "Kenya", "KG": "Kyrgyzstan",
    "KH": "Cambodia", "KI": "Kiribati", "KM": "Comoros",
    "KN": "Saint Kitts and Nevis", "KP": "North Korea", "KR": "South Korea",
    "KW": "Kuwait", "KY": "Cayman Islands", "KZ": "Kazakhstan", "LA": "Laos",
    "LB": "Lebanon", "LC": "Saint Lucia", "LI": "Liechtenstein",
    "LK": "Sri Lanka", "LR": "Liberia", "LS": "Lesotho", "LT": "Lithuania",
    "LU": "Luxembourg", "LV": "Latvia", "LY": "Libya", "MA": "Morocco",
    "MC": "Monaco", "MD": "Moldova", "ME": "Montenegro", "MF": "Saint Martin",
    "MG": "Madagascar", "MH": "Marshall Islands", "MK": "North Macedonia",
    "ML": "Mali", "MM": "Myanmar", "MN": "Mongolia", "MO": "Macao",
    "MP": "Northern Mariana Islands", "MQ": "Martinique", "MR": "Mauritania",
    "MS": "Montserrat", "MT": "Malta", "MU": "Mauritius", "MV": "Maldives",
    "MW": "Malawi", "MX": "Mexico", "MY": "Malaysia", "MZ": "Mozambique",
    "NA": "Namibia", "NC": "New Caledonia", "NE": "Niger",
    "NF": "Norfolk Island", "NG": "Nigeria", "NI": "Nicaragua",
    "NL": "Netherlands", "NO": "Norway", "NP": "Nepal", "NR": "Nauru",
    "NU": "Niue", "NZ": "New Zealand", "OM": "Oman", "PA": "Panama",
    "PE": "Peru", "PF": "French Polynesia", "PG": "Papua New Guinea",
    "PH": "Philippines", "PK": "Pakistan", "PL": "Poland",
    "PM": "Saint Pierre and Miquelon", "PN": "Pitcairn", "PR": "Puerto Rico",
    "PS": "Palestine", "PT": "Portugal", "PW": "Palau", "PY": "Paraguay",
    "QA": "Qatar", "RE": "Réunion", "RO": "Romania", "RS": "Serbia",
    "RU": "Russia", "RW": "Rwanda", "SA": "Saudi Arabia",
    "SB": "Solomon Islands", "SC": "Seychelles", "SD": "Sudan", "SE": "Sweden",
    "SG": "Singapore", "SH": "Saint Helena", "SI": "Slovenia",
    "SJ": "Svalbard and Jan Mayen", "SK": "Slovakia", "SL": "Sierra Leone",
    "SM": "San Marino", "SN": "Senegal", "SO": "Somalia", "SR": "Suriname",
    "SS": "South Sudan", "ST": "São Tomé and Príncipe", "SV": "El Salvador",
    "SX": "Sint Maarten", "SY": "Syria", "SZ": "Eswatini",
    "TC": "Turks and Caicos Islands", "TD": "Chad",
    "TF": "French Southern Territories", "TG": "Togo", "TH": "Thailand",
    "TJ": "Tajikistan", "TK": "Tokelau", "TL": "Timor-Leste",
    "TM": "Turkmenistan", "TN": "Tunisia", "TO": "Tonga", "TR": "Turkey",
    "TT": "Trinidad and Tobago", "TV": "Tuvalu", "TW": "Taiwan",
    "TZ": "Tanzania", "UA": "Ukraine", "UG": "Uganda",
    "UM": "US Minor Outlying Islands", "US": "United States", "UY": "Uruguay",
    "UZ": "Uzbekistan", "VA": "Vatican City",
    "VC": "Saint Vincent and the Grenadines", "VE": "Venezuela",
    "VG": "British Virgin Islands", "VI": "US Virgin Islands", "VN": "Vietnam",
    "VU": "Vanuatu", "WF": "Wallis and Futuna", "WS": "Samoa", "XK": "Kosovo",
    "YE": "Yemen", "YT": "Mayotte", "ZA": "South Africa", "ZM": "Zambia",
    "ZW": "Zimbabwe",
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
    """Return human-readable country name for an ISO alpha-2 code (any case),
    or the upper-cased code itself when unknown; empty string for no code."""
    if not code:
        return ""
    code = str(code).strip()
    return (
        COUNTRY_NAMES.get(code.lower())
        or ISO2_COUNTRY_NAMES.get(code.upper())
        or code.upper()
    )


def country_code_to_flag(code: Optional[str]) -> str:
    """Convert ISO country code to Unicode flag emoji.

    e.g. "ru" → "🇷🇺", "cn" → "🇨🇳"
    """
    if not code or len(code) != 2:
        return ""
    return "".join(chr(0x1F1E6 + ord(c) - ord("a")) for c in code.lower())
