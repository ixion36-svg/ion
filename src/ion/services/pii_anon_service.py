"""PII anonymising proxy for LLM calls.

Before any SIEM event is sent to an LLM, sensitive fields (usernames,
hostnames, RFC1918 IPs, emails) are replaced with stable tokens such as
``USER-0001`` / ``HOST-0001`` / ``IP-0001``. The same ``TokenMap`` is used
after generation to restore the real values in the model's response so the
final report is readable to analysts but the originals never leave the
stack.

Field selection is driven by ``src/ion/data/pii_fields.yaml``. Each rule
declares:

* ``match_paths`` — dot-separated ECS-style paths in the event to tokenise.
* ``token_prefix`` — the PREFIX in ``PREFIX-0001``.
* ``strategy`` — ``exact_value`` (tokenise the full string value) or
  ``regex`` (only tokenise values that match the supplied pattern).
* ``smart_find_in_text`` — when true, after path-based tokenisation the
  tokeniser also walks every string-valued field in the event and replaces
  any *already-collected* original with its token. That way a hostname
  mentioned inside ``message`` is redacted too.

The ``preserve_paths`` whitelist lists fields that MUST NOT be tokenised
under any circumstances (hashes, rule IDs, command lines, etc.) — operators
can audit the YAML to see exactly what is allowed to leave the stack.
"""

from __future__ import annotations

import copy
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# Default location of the field-map file (inside the installed package).
_DEFAULT_FIELDS_FILE = (
    Path(__file__).resolve().parent.parent / "data" / "pii_fields.yaml"
)


# ────────────────────────────────────────────────────────────────────────
# Data classes
# ────────────────────────────────────────────────────────────────────────

@dataclass
class PIIFieldRule:
    """A single anonymisation rule loaded from YAML."""

    name: str
    match_paths: List[str]
    token_prefix: str
    smart_find_in_text: bool = False
    strategy: str = "exact_value"  # "exact_value" | "regex"
    regex: Optional[str] = None
    _compiled: Optional[re.Pattern] = None

    def compile_regex(self) -> None:
        if self.strategy == "regex" and self.regex and self._compiled is None:
            self._compiled = re.compile(self.regex)

    def value_matches(self, value: str) -> bool:
        """Does ``value`` qualify for tokenisation under this rule?"""
        if self.strategy == "exact_value":
            return True
        if self.strategy == "regex":
            self.compile_regex()
            if self._compiled is None:
                return False
            return self._compiled.search(value) is not None
        return False


@dataclass
class TokenMap:
    """Bidirectional token mapping for one investigation/LLM call.

    Each ``tokenize_event`` call gets a fresh ``TokenMap``; counters are per
    prefix and per instance, so there is no cross-investigation leakage.
    """

    forward: Dict[str, str] = field(default_factory=dict)  # original -> token
    reverse: Dict[str, str] = field(default_factory=dict)  # token -> original
    _counters: Dict[str, int] = field(default_factory=dict)

    def get_or_create(self, original: str, prefix: str) -> str:
        """Return the existing token for ``original`` or mint a new one."""
        existing = self.forward.get(original)
        if existing is not None:
            return existing
        next_id = self._counters.get(prefix, 0) + 1
        self._counters[prefix] = next_id
        token = f"{prefix}-{next_id:04d}"
        self.forward[original] = token
        self.reverse[token] = original
        return token


# ────────────────────────────────────────────────────────────────────────
# Service
# ────────────────────────────────────────────────────────────────────────

class PIIAnonService:
    """Load PII rules and tokenise/detokenise payloads around LLM calls."""

    def __init__(
        self,
        fields_file: Optional[str] = None,
        enabled: bool = False,
    ):
        self.enabled = enabled
        self.fields_file = Path(fields_file) if fields_file else _DEFAULT_FIELDS_FILE
        self.rules: List[PIIFieldRule] = []
        self.preserve_paths: List[str] = []
        self._preserve_exact: set[str] = set()
        self._preserve_prefixes: List[str] = []  # for "foo.*" wildcards
        self._load_fields()

    # ── YAML loading ────────────────────────────────────────────────

    def _load_fields(self) -> None:
        """Load the YAML field map. Failures disable the service."""
        if not self.fields_file.exists():
            logger.warning(
                "PII fields file not found: %s (service disabled)",
                self.fields_file,
            )
            self.enabled = False
            return
        try:
            import yaml  # imported lazily so the module still imports
        except ImportError:
            logger.error(
                "PyYAML is not installed — PII anon service disabled. "
                "Add 'pyyaml' to pyproject.toml dependencies."
            )
            self.enabled = False
            return

        try:
            with self.fields_file.open("r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
        except Exception as exc:  # pragma: no cover - defensive
            logger.error("Failed to parse %s: %s", self.fields_file, exc)
            self.enabled = False
            return

        for raw in data.get("fields", []) or []:
            rule = PIIFieldRule(
                name=raw.get("name", ""),
                match_paths=list(raw.get("match_paths", []) or []),
                token_prefix=raw.get("token_prefix", "TOKEN"),
                smart_find_in_text=bool(raw.get("smart_find_in_text", False)),
                strategy=raw.get("strategy", "exact_value"),
                regex=raw.get("regex"),
            )
            rule.compile_regex()
            self.rules.append(rule)

        self.preserve_paths = list(data.get("preserve_paths", []) or [])
        for path in self.preserve_paths:
            if path.endswith(".*"):
                self._preserve_prefixes.append(path[:-2])
            else:
                self._preserve_exact.add(path)

        logger.info(
            "PIIAnonService loaded %d rule(s), %d preserve path(s) from %s",
            len(self.rules),
            len(self.preserve_paths),
            self.fields_file,
        )

    # ── Public API ──────────────────────────────────────────────────

    def is_enabled(self) -> bool:
        return bool(self.enabled) and bool(self.rules)

    def tokenize_event(self, event: dict) -> Tuple[dict, TokenMap]:
        """Deep-copy ``event`` and tokenise it. Returns ``(redacted, map)``."""
        mapping = TokenMap()
        if not event or not self.rules:
            return copy.deepcopy(event) if event else {}, mapping

        redacted = copy.deepcopy(event)

        # Pass 1 — path-based tokenisation.
        for rule in self.rules:
            for path in rule.match_paths:
                if self._is_preserved(path):
                    continue
                self._tokenize_path(redacted, path, rule, mapping)

        # Pass 2 — smart_find across all string-valued fields.
        # We only substitute originals that rules with smart_find_in_text=true
        # collected. Originals are matched as whole tokens where possible.
        smart_originals: List[Tuple[str, str]] = []
        for original, token in mapping.forward.items():
            # Replace longer strings first so a hostname that is a prefix of
            # another hostname doesn't get mangled.
            smart_originals.append((original, token))
        smart_originals.sort(key=lambda pair: len(pair[0]), reverse=True)
        if smart_originals:
            self._smart_find_walk(redacted, smart_originals, path_stack=[])

        return redacted, mapping

    def tokenize_text(self, text: str, mapping: TokenMap) -> str:
        """Forward-substitute ``mapping`` over an arbitrary string."""
        if not text or not mapping.forward:
            return text
        # Longer originals first to avoid clobbering substrings.
        for original in sorted(mapping.forward, key=len, reverse=True):
            token = mapping.forward[original]
            text = text.replace(original, token)
        return text

    def detokenize_text(self, text: str, mapping: TokenMap) -> str:
        """Reverse-substitute tokens back to their originals in ``text``."""
        if not text or not mapping.reverse:
            return text
        # Tokens have a fixed format so order doesn't matter, but sort for
        # determinism.
        for token in sorted(mapping.reverse, key=len, reverse=True):
            original = mapping.reverse[token]
            text = text.replace(token, original)
        return text

    # ── Internals ───────────────────────────────────────────────────

    def _is_preserved(self, path: str) -> bool:
        if path in self._preserve_exact:
            return True
        for prefix in self._preserve_prefixes:
            if path == prefix or path.startswith(prefix + "."):
                return True
        return False

    def _tokenize_path(
        self,
        node: Any,
        path: str,
        rule: PIIFieldRule,
        mapping: TokenMap,
    ) -> None:
        """Walk a dot-path and tokenise the leaf value(s).

        Handles nested dicts and lists of dicts. If an intermediate key maps
        to a list, we recurse into every item. Missing keys are ignored.
        """
        parts = path.split(".")
        self._walk_and_tokenize(node, parts, rule, mapping)

    def _walk_and_tokenize(
        self,
        node: Any,
        parts: List[str],
        rule: PIIFieldRule,
        mapping: TokenMap,
    ) -> None:
        if node is None or not parts:
            return
        head, rest = parts[0], parts[1:]

        if isinstance(node, list):
            for item in node:
                self._walk_and_tokenize(item, parts, rule, mapping)
            return

        if not isinstance(node, dict):
            return

        if head not in node:
            return

        if not rest:
            # Leaf — tokenise value (or each string in a list of strings).
            value = node[head]
            node[head] = self._tokenize_leaf(value, rule, mapping)
            return

        child = node[head]
        if isinstance(child, list):
            for item in child:
                self._walk_and_tokenize(item, rest, rule, mapping)
        else:
            self._walk_and_tokenize(child, rest, rule, mapping)

    def _tokenize_leaf(
        self,
        value: Any,
        rule: PIIFieldRule,
        mapping: TokenMap,
    ) -> Any:
        if isinstance(value, list):
            return [self._tokenize_leaf(v, rule, mapping) for v in value]
        if not isinstance(value, str) or not value:
            return value
        if not rule.value_matches(value):
            return value
        return mapping.get_or_create(value, rule.token_prefix)

    def _smart_find_walk(
        self,
        node: Any,
        originals: List[Tuple[str, str]],
        path_stack: List[str],
    ) -> Any:
        """Walk the event replacing any original string in string fields."""
        if isinstance(node, dict):
            for key, value in list(node.items()):
                full_path = ".".join(path_stack + [key])
                if self._is_preserved(full_path):
                    continue
                node[key] = self._smart_find_walk(
                    value, originals, path_stack + [key]
                )
            return node
        if isinstance(node, list):
            for i, item in enumerate(node):
                node[i] = self._smart_find_walk(item, originals, path_stack)
            return node
        if isinstance(node, str) and node:
            new_val = node
            for original, token in originals:
                if original and original in new_val:
                    new_val = new_val.replace(original, token)
            return new_val
        return node


# ────────────────────────────────────────────────────────────────────────
# Singleton
# ────────────────────────────────────────────────────────────────────────

_pii_anon_service: Optional[PIIAnonService] = None


def get_pii_anon_service() -> PIIAnonService:
    """Return the process-wide ``PIIAnonService`` instance."""
    global _pii_anon_service
    if _pii_anon_service is None:
        try:
            from ion.core.config import get_config

            config = get_config()
            enabled = bool(getattr(config, "pii_anon_enabled", False))
            fields_file = getattr(config, "pii_fields_file", "") or None
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Could not read config for PIIAnonService: %s", exc)
            enabled = False
            fields_file = None
        _pii_anon_service = PIIAnonService(
            fields_file=fields_file,
            enabled=enabled,
        )
    return _pii_anon_service


def reset_pii_anon_service() -> None:
    """Reset the singleton (used for tests / config reloads)."""
    global _pii_anon_service
    _pii_anon_service = None
