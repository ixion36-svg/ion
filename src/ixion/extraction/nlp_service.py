"""NLP service using NLTK for enhanced entity recognition with SOC support."""

import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any

logger = logging.getLogger(__name__)

# Try to import NLTK, gracefully handle if not installed
try:
    import nltk
    from nltk import word_tokenize, pos_tag, ne_chunk
    from nltk.tree import Tree
    NLTK_AVAILABLE = True
except (ImportError, Exception) as e:
    NLTK_AVAILABLE = False
    nltk = None
    logger.debug(f"NLTK not available: {e}")

# Try to import spellchecker
try:
    from spellchecker import SpellChecker
    SPELLCHECK_AVAILABLE = True
except ImportError:
    SPELLCHECK_AVAILABLE = False
    SpellChecker = None


@dataclass
class NEREntity:
    """Represents a named entity detected by NLP."""

    text: str
    label: str  # Entity type label
    start: int  # Character offset
    end: int
    confidence: float
    suggested_name: str  # Suggested variable name
    pattern_type: str  # Mapped pattern type for compatibility


@dataclass
class TableData:
    """Represents a detected table structure."""

    start: int
    end: int
    rows: List[List[str]]
    headers: List[str]
    row_count: int
    col_count: int
    raw_text: str


@dataclass
class SpellCheckResult:
    """Represents spell check results for text."""

    original: str
    corrected: str
    misspelled: List[Dict[str, Any]] = field(default_factory=list)
    suggestion_count: int = 0


# Mapping from NLTK entity labels to our pattern types and variable names
ENTITY_MAPPING: Dict[str, Tuple[str, str, float]] = {
    # NLTK label -> (pattern_type, suggested_name, base_confidence)
    "PERSON": ("person_name", "name", 0.85),
    "ORGANIZATION": ("organization", "company", 0.80),
    "GPE": ("location", "location", 0.80),  # Geo-Political Entity (cities, countries)
    "LOCATION": ("location", "location", 0.75),
    "FACILITY": ("facility", "facility", 0.70),
    "GSP": ("location", "location", 0.75),  # Geo-Socio-Political
}

# SOC-specific regex patterns for cybersecurity entities
SOC_PATTERNS: Dict[str, Tuple[str, str, float, str]] = {
    # Pattern name -> (regex, suggested_name, confidence, description)
    "ipv4": (
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
        "ip_address", 0.95, "IPv4 Address"
    ),
    "ipv6": (
        r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b',
        "ipv6_address", 0.90, "IPv6 Address"
    ),
    "mac_address": (
        r'\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b',
        "mac_address", 0.95, "MAC Address"
    ),
    "cve": (
        r'\bCVE-\d{4}-\d{4,7}\b',
        "cve_id", 0.98, "CVE Identifier"
    ),
    "mitre_attack": (
        r'\b[TMS]\d{4}(?:\.\d{3})?\b',
        "mitre_technique", 0.90, "MITRE ATT&CK ID"
    ),
    "md5_hash": (
        r'\b[a-fA-F0-9]{32}\b',
        "md5_hash", 0.85, "MD5 Hash"
    ),
    "sha1_hash": (
        r'\b[a-fA-F0-9]{40}\b',
        "sha1_hash", 0.85, "SHA1 Hash"
    ),
    "sha256_hash": (
        r'\b[a-fA-F0-9]{64}\b',
        "sha256_hash", 0.90, "SHA256 Hash"
    ),
    "domain": (
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|org|net|edu|gov|mil|io|co|uk|de|fr|jp|au|ca|info|biz|xyz|online)\b',
        "domain", 0.85, "Domain Name"
    ),
    "url": (
        r'https?://[^\s<>"\']+',
        "url", 0.95, "URL"
    ),
    "email": (
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        "email", 0.95, "Email Address"
    ),
    "port": (
        r'\b(?:port\s*)?(?:tcp|udp)?[:/]?\s*(\d{1,5})\b',
        "port", 0.70, "Port Number"
    ),
    "windows_path": (
        r'[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*',
        "file_path", 0.85, "Windows File Path"
    ),
    "unix_path": (
        r'(?:/[^/\s:*?"<>|]+)+/?',
        "file_path", 0.75, "Unix File Path"
    ),
    "registry_key": (
        r'\b(?:HKEY_[A-Z_]+|HK[A-Z]{2})\\[^\s]+',
        "registry_key", 0.90, "Windows Registry Key"
    ),
    "timestamp_iso": (
        r'\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b',
        "timestamp", 0.95, "ISO Timestamp"
    ),
    "timestamp_common": (
        r'\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2},?\s+\d{4}\s+\d{1,2}:\d{2}(?::\d{2})?\s*(?:AM|PM|am|pm)?\b',
        "timestamp", 0.85, "Common Timestamp"
    ),
    "severity": (
        r'\b(?:CRITICAL|HIGH|MEDIUM|LOW|INFO|INFORMATIONAL|WARNING|ALERT|EMERGENCY|ERROR|DEBUG)\b',
        "severity", 0.90, "Severity Level"
    ),
    "hostname": (
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)\b(?=\s*[\[\(:]|\s+(?:said|reported|detected))',
        "hostname", 0.70, "Hostname"
    ),
    "process_name": (
        r'\b\w+\.(?:exe|dll|sys|bat|ps1|sh|py|jar)\b',
        "process", 0.85, "Process/Executable"
    ),
    "event_id": (
        r'\b(?:Event\s*ID|EventID)[:\s]*(\d+)\b',
        "event_id", 0.90, "Windows Event ID"
    ),
    "user_account": (
        r'\b(?:(?:DOMAIN|NT AUTHORITY|SYSTEM)\\)?[A-Za-z][A-Za-z0-9_-]{2,20}\b(?=\s+(?:logged|accessed|attempted|failed))',
        "user_account", 0.75, "User Account"
    ),
}

# Table detection patterns
TABLE_PATTERNS = [
    # Markdown table
    r'(?:^\|.+\|$\n)+',
    # ASCII table with borders
    r'(?:^[+|-]+$\n)+(?:^\|.+\|$\n)+(?:^[+|-]+$\n)?',
    # Tab/space separated with header line
    r'^.+(?:\t|  +).+$\n^[-=]+(?:\t|  +)[-=]+.+$\n(?:^.+(?:\t|  +).+$\n)+',
    # CSV-like
    r'^(?:[^,\n]+,)+[^,\n]+$(?:\n^(?:[^,\n]+,)+[^,\n]+$)+',
]


class NLPService:
    """Service for NLP-based entity recognition using NLTK with SOC enhancements."""

    _instance: Optional["NLPService"] = None
    _initialized: bool = False

    def __new__(cls):
        """Singleton pattern to avoid loading data multiple times."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        """Initialize the NLP service."""
        if not self._initialized:
            self._initialized = True
            self._data_loaded = False
            self._spell_checker = None
            self._compiled_soc_patterns: Dict[str, re.Pattern] = {}
            self._compile_soc_patterns()

    def _compile_soc_patterns(self):
        """Pre-compile SOC regex patterns for performance."""
        for name, (pattern, _, _, _) in SOC_PATTERNS.items():
            try:
                self._compiled_soc_patterns[name] = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
            except re.error as e:
                logger.warning(f"Failed to compile SOC pattern '{name}': {e}")

    @property
    def is_available(self) -> bool:
        """Check if NLTK is available."""
        return NLTK_AVAILABLE

    @property
    def spellcheck_available(self) -> bool:
        """Check if spell checking is available."""
        return SPELLCHECK_AVAILABLE

    def load_model(self, model_name: Optional[str] = None) -> bool:
        """Load the NLTK data.

        Args:
            model_name: Ignored for NLTK compatibility.

        Returns:
            True if data loaded successfully, False otherwise.
        """
        if not NLTK_AVAILABLE:
            logger.warning("NLTK is not installed. Install with: pip install nltk")
            return False

        if self._data_loaded:
            return True

        try:
            # Download required NLTK data quietly
            for resource in ['punkt', 'punkt_tab', 'averaged_perceptron_tagger',
                           'averaged_perceptron_tagger_eng', 'maxent_ne_chunker',
                           'maxent_ne_chunker_tab', 'words']:
                try:
                    nltk.data.find(f'tokenizers/{resource}' if 'punkt' in resource
                                  else f'taggers/{resource}' if 'tagger' in resource
                                  else f'chunkers/{resource}' if 'chunker' in resource
                                  else f'corpora/{resource}')
                except LookupError:
                    nltk.download(resource, quiet=True)

            self._data_loaded = True
            logger.info("NLTK NER data loaded successfully")
            return True
        except Exception as e:
            logger.warning(f"Failed to load NLTK data: {e}")
            return False

    def _init_spell_checker(self):
        """Initialize spell checker if available."""
        if SPELLCHECK_AVAILABLE and self._spell_checker is None:
            self._spell_checker = SpellChecker()

    def _find_entity_position(self, text: str, entity_text: str, start_from: int = 0) -> Tuple[int, int]:
        """Find the character position of an entity in the original text."""
        # Try exact match first
        pos = text.find(entity_text, start_from)
        if pos != -1:
            return pos, pos + len(entity_text)

        # Try case-insensitive match
        lower_text = text.lower()
        lower_entity = entity_text.lower()
        pos = lower_text.find(lower_entity, start_from)
        if pos != -1:
            return pos, pos + len(entity_text)

        return -1, -1

    def extract_soc_entities(self, text: str, min_confidence: float = 0.5) -> List[NEREntity]:
        """Extract SOC-specific entities using regex patterns.

        Args:
            text: Text to analyze.
            min_confidence: Minimum confidence threshold.

        Returns:
            List of detected SOC entities.
        """
        entities = []
        seen_spans = set()  # Avoid duplicate detections

        for name, (pattern_str, suggested_name, confidence, description) in SOC_PATTERNS.items():
            if confidence < min_confidence:
                continue

            compiled = self._compiled_soc_patterns.get(name)
            if not compiled:
                continue

            for match in compiled.finditer(text):
                start, end = match.start(), match.end()
                span = (start, end)

                # Skip if we've already detected something at this position
                if any(s <= start < e or s < end <= e for s, e in seen_spans):
                    continue

                entity_text = match.group()

                # Skip if it's just numbers (port pattern can match random numbers)
                if name == "port" and not re.search(r'(?:port|tcp|udp|:)', entity_text, re.I):
                    continue

                seen_spans.add(span)
                entities.append(NEREntity(
                    text=entity_text,
                    label=description,
                    start=start,
                    end=end,
                    confidence=confidence,
                    suggested_name=suggested_name,
                    pattern_type=name,
                ))

        return sorted(entities, key=lambda e: e.start)

    def extract_entities(
        self,
        text: str,
        min_confidence: float = 0.5,
        entity_types: Optional[List[str]] = None,
        include_soc: bool = True,
    ) -> List[NEREntity]:
        """Extract named entities from text.

        Args:
            text: The text to analyze.
            min_confidence: Minimum confidence threshold (0-1).
            entity_types: Optional list of entity types to extract.
            include_soc: Whether to include SOC-specific entity detection.

        Returns:
            List of detected entities.
        """
        entities = []

        # Extract SOC-specific entities first (regex-based)
        if include_soc:
            soc_entities = self.extract_soc_entities(text, min_confidence)
            if entity_types:
                soc_entities = [e for e in soc_entities if e.pattern_type in entity_types]
            entities.extend(soc_entities)

        # Extract NLP entities using NLTK
        if self.load_model():
            try:
                tokens = word_tokenize(text)
                tagged = pos_tag(tokens)
                tree = ne_chunk(tagged)

                seen_spans = {(e.start, e.end) for e in entities}
                last_pos = 0

                for chunk in tree:
                    if isinstance(chunk, Tree):
                        label = chunk.label()

                        if label not in ENTITY_MAPPING:
                            continue

                        pattern_type, suggested_name, base_confidence = ENTITY_MAPPING[label]

                        if entity_types and pattern_type not in entity_types:
                            continue

                        entity_text = " ".join(word for word, tag in chunk.leaves())
                        start, end = self._find_entity_position(text, entity_text, last_pos)

                        if start == -1:
                            continue

                        # Skip if overlapping with existing entity
                        if any(s <= start < e or s < end <= e for s, e in seen_spans):
                            continue

                        last_pos = end
                        confidence = self._calculate_confidence(entity_text, label, base_confidence)

                        if confidence >= min_confidence:
                            seen_spans.add((start, end))
                            entities.append(NEREntity(
                                text=entity_text,
                                label=label,
                                start=start,
                                end=end,
                                confidence=confidence,
                                suggested_name=suggested_name,
                                pattern_type=pattern_type,
                            ))
            except Exception as e:
                logger.warning(f"NLTK processing error: {e}")

        return sorted(entities, key=lambda e: e.start)

    def _calculate_confidence(
        self, entity_text: str, label: str, base_confidence: float
    ) -> float:
        """Calculate confidence score for an entity."""
        confidence = base_confidence

        words = entity_text.split()
        if len(words) > 1:
            confidence = min(1.0, confidence + 0.05)
        if len(words) > 2:
            confidence = min(1.0, confidence + 0.03)

        if label in ("PERSON", "ORGANIZATION", "GPE"):
            if entity_text[0].isupper():
                confidence = min(1.0, confidence + 0.03)
            if all(w[0].isupper() for w in words if w):
                confidence = min(1.0, confidence + 0.02)

        if len(entity_text) < 3:
            confidence = max(0.3, confidence - 0.15)

        if entity_text.isupper() and len(entity_text) > 2:
            confidence = max(0.5, confidence - 0.1)

        return confidence

    def detect_tables(self, text: str) -> List[TableData]:
        """Detect and parse tables in text.

        Args:
            text: Text to analyze for tables.

        Returns:
            List of detected tables with parsed data.
        """
        tables = []

        # Try to detect markdown tables
        md_table_pattern = re.compile(r'(\|.+\|\n)+', re.MULTILINE)
        for match in md_table_pattern.finditer(text):
            table_text = match.group()
            rows = []
            headers = []

            lines = [l.strip() for l in table_text.strip().split('\n') if l.strip()]
            for i, line in enumerate(lines):
                # Skip separator lines
                if re.match(r'^[\|\-\:\s]+$', line):
                    continue

                cells = [c.strip() for c in line.split('|') if c.strip()]
                if i == 0:
                    headers = cells
                else:
                    rows.append(cells)

            if headers or rows:
                tables.append(TableData(
                    start=match.start(),
                    end=match.end(),
                    rows=rows,
                    headers=headers,
                    row_count=len(rows),
                    col_count=len(headers) if headers else (len(rows[0]) if rows else 0),
                    raw_text=table_text,
                ))

        # Try to detect CSV-like tables
        csv_pattern = re.compile(r'^([^,\n]+(?:,[^,\n]+)+)$(?:\n^([^,\n]+(?:,[^,\n]+)+)$)+', re.MULTILINE)
        for match in csv_pattern.finditer(text):
            # Skip if overlapping with markdown table
            if any(t.start <= match.start() < t.end for t in tables):
                continue

            table_text = match.group()
            lines = table_text.strip().split('\n')
            headers = [c.strip() for c in lines[0].split(',')]
            rows = [[c.strip() for c in line.split(',')] for line in lines[1:]]

            tables.append(TableData(
                start=match.start(),
                end=match.end(),
                rows=rows,
                headers=headers,
                row_count=len(rows),
                col_count=len(headers),
                raw_text=table_text,
            ))

        # Try to detect tab-separated tables
        tsv_pattern = re.compile(r'^([^\t\n]+(?:\t[^\t\n]+)+)$(?:\n^([^\t\n]+(?:\t[^\t\n]+)+)$)+', re.MULTILINE)
        for match in tsv_pattern.finditer(text):
            if any(t.start <= match.start() < t.end for t in tables):
                continue

            table_text = match.group()
            lines = table_text.strip().split('\n')
            headers = [c.strip() for c in lines[0].split('\t')]
            rows = [[c.strip() for c in line.split('\t')] for line in lines[1:]]

            tables.append(TableData(
                start=match.start(),
                end=match.end(),
                rows=rows,
                headers=headers,
                row_count=len(rows),
                col_count=len(headers),
                raw_text=table_text,
            ))

        return sorted(tables, key=lambda t: t.start)

    def spell_check(self, text: str, ignore_patterns: Optional[List[str]] = None) -> SpellCheckResult:
        """Perform spell checking on text.

        Args:
            text: Text to spell check.
            ignore_patterns: Regex patterns to ignore (e.g., technical terms).

        Returns:
            SpellCheckResult with corrections and suggestions.
        """
        if not SPELLCHECK_AVAILABLE:
            return SpellCheckResult(
                original=text,
                corrected=text,
                misspelled=[],
                suggestion_count=0,
            )

        self._init_spell_checker()

        # Default patterns to ignore (technical/SOC terms)
        default_ignore = [
            r'\b[A-Z]{2,}\b',  # Acronyms
            r'\b\d+\b',  # Numbers
            r'CVE-\d+-\d+',  # CVE IDs
            r'[TMS]\d{4}',  # MITRE IDs
            r'[a-fA-F0-9]{32,}',  # Hashes
            r'\S+@\S+',  # Emails
            r'https?://\S+',  # URLs
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IPs
            r'\w+\.\w{2,4}',  # File extensions / domains
        ]

        ignore_list = default_ignore + (ignore_patterns or [])

        # Find words to check (excluding ignored patterns)
        words = re.findall(r'\b[a-zA-Z]+\b', text)
        words_to_check = []

        for word in words:
            should_ignore = False
            for pattern in ignore_list:
                if re.match(pattern, word):
                    should_ignore = True
                    break
            if not should_ignore and len(word) > 2:
                words_to_check.append(word.lower())

        # Find misspelled words
        misspelled = self._spell_checker.unknown(words_to_check)
        corrections = []

        for word in misspelled:
            candidates = self._spell_checker.candidates(word)
            if candidates:
                correction = self._spell_checker.correction(word)
                # Find all positions of this word in text
                pattern = re.compile(r'\b' + re.escape(word) + r'\b', re.IGNORECASE)
                for match in pattern.finditer(text):
                    corrections.append({
                        'word': match.group(),
                        'start': match.start(),
                        'end': match.end(),
                        'correction': correction,
                        'suggestions': list(candidates)[:5],
                    })

        # Create corrected text
        corrected = text
        for corr in sorted(corrections, key=lambda x: x['start'], reverse=True):
            # Preserve case
            original = corr['word']
            fixed = corr['correction']
            if original[0].isupper():
                fixed = fixed.capitalize()
            if original.isupper():
                fixed = fixed.upper()
            corrected = corrected[:corr['start']] + fixed + corrected[corr['end']:]

        return SpellCheckResult(
            original=text,
            corrected=corrected,
            misspelled=corrections,
            suggestion_count=len(corrections),
        )

    def suggest_rewrites(self, text: str, style: str = "professional") -> List[Dict[str, Any]]:
        """Suggest text improvements and rewrites.

        Args:
            text: Text to analyze.
            style: Target style ('professional', 'concise', 'formal', 'technical').

        Returns:
            List of rewrite suggestions.
        """
        suggestions = []

        # Common patterns to improve
        improvements = {
            "professional": [
                (r'\bi think\b', "Consider using more definitive language", "In my assessment"),
                (r'\bmaybe\b', "Consider being more decisive", "possibly/likely"),
                (r'\bstuff\b', "Use more specific terminology", "items/data/artifacts"),
                (r'\bgot\b', "Use formal alternatives", "obtained/received"),
                (r'\ba lot of\b', "Quantify when possible", "numerous/significant"),
                (r'\bbasically\b', "Remove filler words", "[remove]"),
                (r'\bvery\b', "Use stronger adjectives", "[use specific adjective]"),
                (r'\breally\b', "Remove or strengthen", "[remove or specify]"),
            ],
            "concise": [
                (r'\bin order to\b', "Simplify", "to"),
                (r'\bdue to the fact that\b', "Simplify", "because"),
                (r'\bat this point in time\b', "Simplify", "now/currently"),
                (r'\bin the event that\b', "Simplify", "if"),
                (r'\bprior to\b', "Simplify", "before"),
                (r'\bsubsequent to\b', "Simplify", "after"),
                (r'\bwith regard to\b', "Simplify", "about/regarding"),
                (r'\bfor the purpose of\b', "Simplify", "to/for"),
            ],
            "technical": [
                (r'\bbroken\b', "Use technical term", "malfunctioning/failed"),
                (r'\bslow\b', "Be specific", "degraded performance/high latency"),
                (r'\bcrashed\b', "Use technical term", "terminated unexpectedly/exception occurred"),
                (r'\bhacked\b', "Use technical term", "compromised/breached"),
                (r'\bvirus\b', "Use specific term if known", "malware/trojan/ransomware"),
                (r'\bbug\b', "Use technical term", "defect/vulnerability/issue"),
            ],
            "formal": [
                (r"\bcan't\b", "Use formal form", "cannot"),
                (r"\bwon't\b", "Use formal form", "will not"),
                (r"\bdon't\b", "Use formal form", "do not"),
                (r"\bdoesn't\b", "Use formal form", "does not"),
                (r"\bisn't\b", "Use formal form", "is not"),
                (r"\baren't\b", "Use formal form", "are not"),
                (r"\bwe're\b", "Use formal form", "we are"),
                (r"\bthey're\b", "Use formal form", "they are"),
                (r"\bit's\b", "Use formal form", "it is"),
            ],
        }

        patterns = improvements.get(style, improvements["professional"])

        for pattern, reason, suggestion in patterns:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                suggestions.append({
                    'original': match.group(),
                    'start': match.start(),
                    'end': match.end(),
                    'reason': reason,
                    'suggestion': suggestion,
                    'style': style,
                })

        # Check for passive voice (simplified detection)
        passive_pattern = r'\b(?:is|are|was|were|been|being)\s+\w+ed\b'
        for match in re.finditer(passive_pattern, text):
            suggestions.append({
                'original': match.group(),
                'start': match.start(),
                'end': match.end(),
                'reason': "Consider active voice",
                'suggestion': "[rewrite in active voice]",
                'style': 'active_voice',
            })

        # Check for long sentences
        sentences = re.split(r'[.!?]+', text)
        pos = 0
        for sentence in sentences:
            sentence = sentence.strip()
            if len(sentence.split()) > 30:
                start = text.find(sentence, pos)
                if start != -1:
                    suggestions.append({
                        'original': sentence[:50] + '...' if len(sentence) > 50 else sentence,
                        'start': start,
                        'end': start + len(sentence),
                        'reason': f"Long sentence ({len(sentence.split())} words) - consider breaking up",
                        'suggestion': "[split into shorter sentences]",
                        'style': 'readability',
                    })
            pos += len(sentence) + 1

        return sorted(suggestions, key=lambda s: s['start'])

    def apply_rewrites(
        self,
        text: str,
        style: str = "professional",
        apply_all: bool = True,
        selected_indices: Optional[List[int]] = None,
    ) -> Dict[str, Any]:
        """Apply rewrite suggestions to text and return the rewritten version.

        Args:
            text: Original text to rewrite.
            style: Target style ('professional', 'concise', 'formal', 'technical').
            apply_all: If True, apply all suggestions. If False, use selected_indices.
            selected_indices: List of suggestion indices to apply (if apply_all is False).

        Returns:
            Dictionary with original text, rewritten text, and applied changes.
        """
        suggestions = self.suggest_rewrites(text, style)

        if not suggestions:
            return {
                "original": text,
                "rewritten": text,
                "changes_applied": 0,
                "changes": [],
            }

        # Filter suggestions if not applying all
        if not apply_all and selected_indices is not None:
            suggestions = [s for i, s in enumerate(suggestions) if i in selected_indices]

        # Sort by position (descending) to apply from end to start
        # This preserves character positions as we modify
        suggestions_to_apply = sorted(suggestions, key=lambda s: s['start'], reverse=True)

        rewritten = text
        changes = []

        for suggestion in suggestions_to_apply:
            original = suggestion['original']
            replacement = suggestion['suggestion']
            start = suggestion['start']
            end = suggestion['end']

            # Skip suggestions that are just guidance (in brackets)
            if replacement.startswith('[') and replacement.endswith(']'):
                continue

            # Handle special cases
            if replacement == "[remove]":
                # Remove the word and any trailing space
                if end < len(rewritten) and rewritten[end] == ' ':
                    end += 1
                replacement = ""
            elif '/' in replacement:
                # Multiple options - take the first one
                replacement = replacement.split('/')[0]

            # Apply the replacement
            before = rewritten[:start]
            after = rewritten[end:]

            # Preserve case if original was capitalized
            if original and original[0].isupper() and replacement:
                replacement = replacement[0].upper() + replacement[1:]

            rewritten = before + replacement + after
            changes.append({
                "original": original,
                "replacement": replacement,
                "reason": suggestion['reason'],
            })

        return {
            "original": text,
            "rewritten": rewritten,
            "changes_applied": len(changes),
            "changes": list(reversed(changes)),  # Return in original order
            "style": style,
        }

    def analyze_document(
        self,
        text: str,
        min_confidence: float = 0.5,
        include_tables: bool = True,
        include_spell_check: bool = False,
        include_rewrites: bool = False,
        rewrite_style: str = "professional",
    ) -> Dict:
        """Perform comprehensive NLP analysis on a document.

        Returns:
            Dictionary with entities, tables, statistics, and analysis results.
        """
        result = {
            "available": True,
            "entities": [],
            "entity_counts": {},
            "soc_entity_counts": {},
            "tables": [],
            "sentence_count": 0,
            "token_count": 0,
        }

        if not self.load_model():
            result["available"] = False
            result["error"] = "NLTK not available"
            # Still try SOC pattern detection
            entities = self.extract_soc_entities(text, min_confidence)
            result["entities"] = entities
        else:
            entities = self.extract_entities(text, min_confidence)
            result["entities"] = entities

        # Count entities by type
        for ent in entities:
            result["entity_counts"][ent.pattern_type] = result["entity_counts"].get(ent.pattern_type, 0) + 1
            if ent.pattern_type in SOC_PATTERNS:
                result["soc_entity_counts"][ent.pattern_type] = result["soc_entity_counts"].get(ent.pattern_type, 0) + 1

        # Detect tables
        if include_tables:
            tables = self.detect_tables(text)
            result["tables"] = [
                {
                    "start": t.start,
                    "end": t.end,
                    "headers": t.headers,
                    "row_count": t.row_count,
                    "col_count": t.col_count,
                    "preview": t.rows[:3] if t.rows else [],
                }
                for t in tables
            ]

        # Count sentences and tokens
        if self._data_loaded:
            try:
                from nltk.tokenize import sent_tokenize
                sentences = sent_tokenize(text)
                tokens = word_tokenize(text)
                result["sentence_count"] = len(sentences)
                result["token_count"] = len(tokens)
            except Exception:
                result["sentence_count"] = len(text.split('.'))
                result["token_count"] = len(text.split())
        else:
            result["sentence_count"] = len(text.split('.'))
            result["token_count"] = len(text.split())

        # Spell check if requested
        if include_spell_check:
            spell_result = self.spell_check(text)
            result["spell_check"] = {
                "misspelled_count": spell_result.suggestion_count,
                "misspelled": spell_result.misspelled[:20],  # Limit results
            }

        # Rewrite suggestions if requested
        if include_rewrites:
            rewrites = self.suggest_rewrites(text, rewrite_style)
            result["rewrite_suggestions"] = rewrites[:20]  # Limit results

        return result

    def get_model_info(self) -> Dict:
        """Get information about the NLP backend."""
        if not self.load_model():
            return {
                "available": False,
                "model_name": "nltk",
                "error": "NLTK data not loaded",
                "soc_patterns_available": True,
                "soc_pattern_count": len(SOC_PATTERNS),
                "spellcheck_available": SPELLCHECK_AVAILABLE,
            }

        return {
            "available": True,
            "model_name": "nltk-maxent_ne_chunker",
            "pipeline": ["tokenize", "pos_tag", "ne_chunk"],
            "entity_labels": list(ENTITY_MAPPING.keys()),
            "soc_patterns_available": True,
            "soc_pattern_count": len(SOC_PATTERNS),
            "soc_patterns": list(SOC_PATTERNS.keys()),
            "spellcheck_available": SPELLCHECK_AVAILABLE,
        }


# Singleton instance
_nlp_service: Optional[NLPService] = None


def get_nlp_service() -> NLPService:
    """Get the NLP service singleton instance."""
    global _nlp_service
    if _nlp_service is None:
        _nlp_service = NLPService()
    return _nlp_service
