"""AI-powered document analysis service using Ollama.

Replaces NLTK-based NLP with AI for entity extraction, spell checking, and rewrites.
Keeps the fast regex-based SOC pattern detection.
"""

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple

from ion.services.ollama_service import get_ollama_service, OllamaError

logger = logging.getLogger(__name__)


# SOC-specific regex patterns for cybersecurity entities (kept from nlp_service)
SOC_PATTERNS: Dict[str, Tuple[str, str, float, str]] = {
    "ipv4": (
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
        "ip_address", 0.95, "IPv4 Address"
    ),
    "ipv6": (
        r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b',
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
    "severity": (
        r'\b(?:CRITICAL|HIGH|MEDIUM|LOW|INFO|INFORMATIONAL|WARNING|ALERT|EMERGENCY|ERROR|DEBUG)\b',
        "severity", 0.90, "Severity Level"
    ),
    "process_name": (
        r'\b\w+\.(?:exe|dll|sys|bat|ps1|sh|py|jar)\b',
        "process", 0.85, "Process/Executable"
    ),
    "event_id": (
        r'\b(?:Event\s*ID|EventID)[:\s]*(\d+)\b',
        "event_id", 0.90, "Windows Event ID"
    ),
}


@dataclass
class Entity:
    """Represents a detected entity."""
    text: str
    label: str
    start: int
    end: int
    confidence: float
    suggested_name: str
    pattern_type: str
    source: str = "regex"  # "regex" or "ai"


@dataclass
class SpellCheckResult:
    """Result of spell checking."""
    original: str
    corrected: str
    misspelled: List[Dict[str, Any]] = field(default_factory=list)
    suggestion_count: int = 0


@dataclass
class RewriteResult:
    """Result of text rewriting."""
    original: str
    rewritten: str
    changes_applied: int = 0
    changes: List[Dict[str, Any]] = field(default_factory=list)
    style: str = "professional"


class AIDocumentService:
    """AI-powered document analysis service."""

    _instance: Optional["AIDocumentService"] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if not hasattr(self, '_initialized'):
            self._initialized = True
            self._compiled_patterns: Dict[str, re.Pattern] = {}
            self._compile_patterns()

    def _compile_patterns(self):
        """Pre-compile regex patterns."""
        for name, (pattern, _, _, _) in SOC_PATTERNS.items():
            try:
                self._compiled_patterns[name] = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
            except re.error as e:
                logger.warning(f"Failed to compile pattern '{name}': {e}")

    async def is_ai_available(self) -> bool:
        """Check if AI service is available."""
        ollama = get_ollama_service()
        return await ollama.is_available()

    def extract_soc_entities(self, text: str, min_confidence: float = 0.5) -> List[Entity]:
        """Extract SOC-specific entities using fast regex patterns."""
        entities = []
        seen_spans = set()

        for name, (_, suggested_name, confidence, description) in SOC_PATTERNS.items():
            if confidence < min_confidence:
                continue

            compiled = self._compiled_patterns.get(name)
            if not compiled:
                continue

            for match in compiled.finditer(text):
                start, end = match.start(), match.end()
                span = (start, end)

                if any(s <= start < e or s < end <= e for s, e in seen_spans):
                    continue

                seen_spans.add(span)
                entities.append(Entity(
                    text=match.group(),
                    label=description,
                    start=start,
                    end=end,
                    confidence=confidence,
                    suggested_name=suggested_name,
                    pattern_type=name,
                    source="regex",
                ))

        return sorted(entities, key=lambda e: e.start)

    async def extract_entities_with_ai(
        self,
        text: str,
        min_confidence: float = 0.5,
        include_soc: bool = True,
    ) -> List[Entity]:
        """Extract entities using AI for semantic entities + regex for SOC patterns."""
        entities = []

        # Always get SOC entities first (fast regex)
        if include_soc:
            entities.extend(self.extract_soc_entities(text, min_confidence))

        # Get AI-detected entities for semantic content
        ollama = get_ollama_service()
        if not await ollama.is_available():
            return entities

        # Truncate text if too long
        analyze_text = text[:8000] if len(text) > 8000 else text

        prompt = f"""Analyze this text and extract named entities. Return ONLY a JSON array with entities found.
Each entity should have: "text", "label" (PERSON, ORGANIZATION, LOCATION, DATE, PRODUCT), "start" (char index), "end" (char index).

Text to analyze:
---
{analyze_text}
---

Return ONLY valid JSON array, no explanation. Example: [{{"text": "John Smith", "label": "PERSON", "start": 0, "end": 10}}]
If no entities found, return: []"""

        try:
            result = await ollama.chat(
                messages=[{"role": "user", "content": prompt}],
                context_type="analyst",
                temperature=0.1,
            )

            content = result.get("content", "").strip()
            # Try to extract JSON from response
            json_match = re.search(r'\[.*\]', content, re.DOTALL)
            if json_match:
                ai_entities = json.loads(json_match.group())
                seen_spans = {(e.start, e.end) for e in entities}

                label_mapping = {
                    "PERSON": ("person_name", "name"),
                    "ORGANIZATION": ("organization", "company"),
                    "LOCATION": ("location", "location"),
                    "DATE": ("date", "date"),
                    "PRODUCT": ("product", "product"),
                }

                for ent in ai_entities:
                    if not isinstance(ent, dict):
                        continue

                    start = ent.get("start", 0)
                    end = ent.get("end", 0)

                    # Skip if overlapping with existing entity
                    if any(s <= start < e or s < end <= e for s, e in seen_spans):
                        continue

                    label = ent.get("label", "UNKNOWN")
                    pattern_type, suggested = label_mapping.get(label, ("unknown", "value"))

                    entities.append(Entity(
                        text=ent.get("text", ""),
                        label=label,
                        start=start,
                        end=end,
                        confidence=0.80,
                        suggested_name=suggested,
                        pattern_type=pattern_type,
                        source="ai",
                    ))
                    seen_spans.add((start, end))

        except (json.JSONDecodeError, OllamaError, AttributeError, TypeError) as e:
            logger.warning(f"AI entity extraction failed: {e}")

        return sorted(entities, key=lambda e: e.start)

    async def spell_check(self, text: str) -> SpellCheckResult:
        """Perform spell checking using AI."""
        ollama = get_ollama_service()
        if not await ollama.is_available():
            return SpellCheckResult(original=text, corrected=text)

        # Truncate if too long
        check_text = text[:4000] if len(text) > 4000 else text

        prompt = f"""Check this text for spelling errors. Return ONLY a JSON object with:
- "corrected": the full corrected text
- "errors": array of {{"word": "misspelled", "correction": "correct", "position": char_index}}

Ignore technical terms, acronyms, and proper nouns. Focus on actual misspellings.

Text:
---
{check_text}
---

Return ONLY valid JSON, no explanation."""

        try:
            result = await ollama.chat(
                messages=[{"role": "user", "content": prompt}],
                context_type="default",
                temperature=0.1,
            )

            content = result.get("content", "").strip()
            json_match = re.search(r'\{.*\}', content, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
                if isinstance(data, dict):
                    errors = data.get("errors", [])
                    valid_errors = [
                        {"word": e.get("word"), "correction": e.get("correction"), "start": e.get("position", 0)}
                        for e in errors if isinstance(e, dict)
                    ]
                    return SpellCheckResult(
                        original=text,
                        corrected=data.get("corrected", text),
                        misspelled=valid_errors,
                        suggestion_count=len(valid_errors),
                    )
        except (json.JSONDecodeError, OllamaError, AttributeError, TypeError) as e:
            logger.warning(f"AI spell check failed: {e}")

        return SpellCheckResult(original=text, corrected=text)

    async def suggest_rewrites(self, text: str, style: str = "professional") -> List[Dict[str, Any]]:
        """Get rewrite suggestions using AI."""
        ollama = get_ollama_service()
        if not await ollama.is_available():
            return []

        style_descriptions = {
            "professional": "formal, clear business writing",
            "concise": "shorter, more direct phrasing",
            "technical": "precise technical terminology",
            "formal": "formal academic or legal style",
        }

        style_desc = style_descriptions.get(style, "professional style")
        check_text = text[:4000] if len(text) > 4000 else text

        prompt = f"""Analyze this text and suggest improvements for {style_desc}.
Return ONLY a JSON array of suggestions. Each suggestion:
- "original": the original phrase
- "suggestion": the improved version
- "reason": brief explanation
- "start": character position in text
- "end": end position

Focus on: clarity, conciseness, word choice, passive voice issues.
Limit to 10 most important suggestions.

Text:
---
{check_text}
---

Return ONLY valid JSON array, no explanation."""

        try:
            result = await ollama.chat(
                messages=[{"role": "user", "content": prompt}],
                context_type="engineering",
                temperature=0.3,
            )

            content = result.get("content", "").strip()
            json_match = re.search(r'\[.*\]', content, re.DOTALL)
            if json_match:
                suggestions = json.loads(json_match.group())
                # Filter to only valid dict entries
                valid_suggestions = []
                for s in suggestions[:10]:
                    if isinstance(s, dict):
                        valid_suggestions.append({
                            "original": s.get("original", ""),
                            "suggestion": s.get("suggestion", ""),
                            "reason": s.get("reason", ""),
                            "start": s.get("start", 0),
                            "end": s.get("end", 0),
                            "style": style,
                        })
                return valid_suggestions
        except (json.JSONDecodeError, OllamaError, AttributeError, TypeError) as e:
            logger.warning(f"AI rewrite suggestions failed: {e}")

        return []

    async def apply_rewrites(
        self,
        text: str,
        style: str = "professional",
    ) -> RewriteResult:
        """Apply rewrites to text using AI."""
        ollama = get_ollama_service()
        if not await ollama.is_available():
            return RewriteResult(original=text, rewritten=text, style=style)

        style_descriptions = {
            "professional": "formal, clear business writing",
            "concise": "shorter, more direct phrasing",
            "technical": "precise technical terminology",
            "formal": "formal academic or legal style",
        }

        style_desc = style_descriptions.get(style, "professional style")
        check_text = text[:4000] if len(text) > 4000 else text

        prompt = f"""Rewrite this text in {style_desc}. Return ONLY a JSON object with:
- "rewritten": the full improved text
- "changes": array of {{"original": "old phrase", "replacement": "new phrase", "reason": "why"}}

Preserve meaning, improve clarity and style. List the main changes made.

Text:
---
{check_text}
---

Return ONLY valid JSON, no explanation."""

        try:
            result = await ollama.chat(
                messages=[{"role": "user", "content": prompt}],
                context_type="engineering",
                temperature=0.3,
            )

            content = result.get("content", "").strip()
            json_match = re.search(r'\{.*\}', content, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
                if isinstance(data, dict):
                    changes = data.get("changes", [])
                    valid_changes = [c for c in changes if isinstance(c, dict)]
                    return RewriteResult(
                        original=text,
                        rewritten=data.get("rewritten", text),
                        changes_applied=len(valid_changes),
                        changes=valid_changes,
                        style=style,
                    )
        except (json.JSONDecodeError, OllamaError, AttributeError, TypeError) as e:
            logger.warning(f"AI rewrite failed: {e}")

        return RewriteResult(original=text, rewritten=text, style=style)

    async def analyze_document(
        self,
        text: str,
        min_confidence: float = 0.5,
        include_spell_check: bool = False,
        include_rewrites: bool = False,
        rewrite_style: str = "professional",
    ) -> Dict[str, Any]:
        """Comprehensive document analysis using AI."""
        result = {
            "ai_available": await self.is_ai_available(),
            "entities": [],
            "entity_counts": {},
            "soc_entity_counts": {},
            "word_count": len(text.split()),
            "char_count": len(text),
        }

        # Extract entities
        entities = await self.extract_entities_with_ai(text, min_confidence)
        result["entities"] = [
            {
                "text": e.text,
                "label": e.label,
                "start": e.start,
                "end": e.end,
                "confidence": e.confidence,
                "pattern_type": e.pattern_type,
                "source": e.source,
            }
            for e in entities
        ]

        # Count entities
        for ent in entities:
            result["entity_counts"][ent.pattern_type] = result["entity_counts"].get(ent.pattern_type, 0) + 1
            if ent.pattern_type in SOC_PATTERNS:
                result["soc_entity_counts"][ent.pattern_type] = result["soc_entity_counts"].get(ent.pattern_type, 0) + 1

        # Spell check if requested
        if include_spell_check:
            spell = await self.spell_check(text)
            result["spell_check"] = {
                "misspelled_count": spell.suggestion_count,
                "misspelled": spell.misspelled[:20],
            }

        # Rewrites if requested
        if include_rewrites:
            suggestions = await self.suggest_rewrites(text, rewrite_style)
            result["rewrite_suggestions"] = suggestions

        return result

    def get_service_info(self) -> Dict[str, Any]:
        """Get service information."""
        return {
            "service": "ai_document_service",
            "backend": "ollama",
            "soc_patterns_available": True,
            "soc_pattern_count": len(SOC_PATTERNS),
            "soc_patterns": list(SOC_PATTERNS.keys()),
            "features": ["entity_extraction", "spell_check", "rewrite_suggestions"],
        }


# Singleton instance
_service: Optional[AIDocumentService] = None


def get_ai_document_service() -> AIDocumentService:
    """Get the AI document service singleton."""
    global _service
    if _service is None:
        _service = AIDocumentService()
    return _service
