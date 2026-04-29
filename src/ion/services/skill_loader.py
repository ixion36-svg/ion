"""Elastic Agent Skills consumer — Bob's 6th matcher tier (v0.13.1).

Reads ``SKILL.md`` folders from the bundled image and an optional runtime
override directory; matches them against the current alert via the
keyword fields in the YAML frontmatter (``matches_rule_groups``,
``matches_techniques``, ``tags``, ``when_to_use``); injects matching
skills into the prompt rendered by ``render_system_prompt``.

**No embeddings.** The matcher is keyword-driven; works on an estate
with ``ION_EMBEDDING_ENABLED=false`` and ``ION_KB_RAG_ENABLED=false``.
This is intentional — Skills are *prompt augmentations*, not retrieval
results, and the matching dimension (technique-id / rule-group / explicit
tag) is well-defined enough to not need vector similarity.

**Layout:**

```
<bundled>/data/skills/<skill-name>/SKILL.md   ← image-baked, two seeded
<runtime>/skills/<skill-name>/SKILL.md        ← optional operator overlay
```

Bundled skills load on import; runtime skills load on demand from the
configured directory. Skills with the same ``name`` from runtime override
bundled ones.

**Skill format** (YAML frontmatter + Markdown body):

```markdown
---
name: elasticsearch-esql
description: short summary
when_to_use: |
  free-text gating clause; the matcher does keyword scan
tags:
  - elastic
  - esql
matches_rule_groups:
  - elastic_security
matches_techniques:
  - any   # or specific T-ids: T1059, T1003.001, etc
---

(Markdown body — injected verbatim into the system prompt when matched.)
```

See ``reference_elastic_agent_skills.md`` for the format origin (Anthropic /
Elastic-published agent skills).
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class Skill:
    """A loaded SKILL.md."""
    name: str
    description: str = ""
    when_to_use: str = ""
    tags: List[str] = field(default_factory=list)
    matches_rule_groups: List[str] = field(default_factory=list)
    matches_techniques: List[str] = field(default_factory=list)
    body: str = ""
    source_path: Optional[str] = None


def _parse_frontmatter(text: str) -> tuple[Dict[str, Any], str]:
    """Parse a `---\\nyaml\\n---\\nbody` markdown frontmatter.

    Returns (frontmatter_dict, body_str). On parse failure, returns
    ``({}, text)``.

    Avoids importing PyYAML — uses a small line-oriented parser that
    handles the keys we care about (string values, list values via
    ``- item`` notation, multi-line strings via ``|`` blocks). For more
    complex frontmatter, switch to ``yaml.safe_load``.
    """
    if not text.startswith("---"):
        return {}, text
    # Split on the second '---' marker
    rest = text[3:].lstrip("\n")
    end = rest.find("\n---")
    if end == -1:
        return {}, text
    yaml_block = rest[:end]
    body = rest[end + 4:].lstrip("\n")

    try:
        # Try real PyYAML first — it's already in deps for ECS configs.
        import yaml  # type: ignore[import-not-found]
        meta = yaml.safe_load(yaml_block) or {}
        if not isinstance(meta, dict):
            meta = {}
        return meta, body
    except Exception:
        # Fall back to the line-oriented parser.
        meta: Dict[str, Any] = {}
        current_key: Optional[str] = None
        current_list: Optional[List[str]] = None
        block_buf: Optional[List[str]] = None
        block_indent = 0
        for line in yaml_block.splitlines():
            stripped = line.rstrip()
            if not stripped:
                continue
            indent = len(line) - len(line.lstrip())
            if block_buf is not None:
                if indent >= block_indent or not stripped:
                    block_buf.append(line[block_indent:] if indent >= block_indent else stripped)
                    continue
                else:
                    meta[current_key] = "\n".join(block_buf).rstrip()
                    block_buf = None
                    current_key = None
                    # fall through to handle this line normally
            if stripped.startswith("- ") and current_list is not None:
                current_list.append(stripped[2:].strip().strip('"').strip("'"))
                continue
            if ":" in stripped:
                key, _, val = stripped.partition(":")
                key = key.strip()
                val = val.strip()
                current_list = None
                if val == "|":
                    current_key = key
                    block_buf = []
                    block_indent = indent + 2  # standard YAML 2-space indent
                    continue
                if val == "":
                    # likely opening a list
                    current_key = key
                    current_list = []
                    meta[key] = current_list
                    continue
                # scalar value
                meta[key] = val.strip('"').strip("'")
                current_key = key
        if block_buf is not None and current_key is not None:
            meta[current_key] = "\n".join(block_buf).rstrip()
        return meta, body


def _load_skill_from_file(path: Path) -> Optional[Skill]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        logger.warning("skill_loader: could not read %s: %s", path, exc)
        return None
    meta, body = _parse_frontmatter(text)
    name = meta.get("name") or path.parent.name
    if not name:
        logger.warning("skill_loader: %s has no name; skipping", path)
        return None
    def _as_list(v: Any) -> List[str]:
        if isinstance(v, list):
            return [str(x) for x in v]
        if isinstance(v, str) and v:
            return [s.strip() for s in v.split(",") if s.strip()]
        return []
    return Skill(
        name=str(name),
        description=str(meta.get("description") or ""),
        when_to_use=str(meta.get("when_to_use") or ""),
        tags=_as_list(meta.get("tags")),
        matches_rule_groups=_as_list(meta.get("matches_rule_groups")),
        matches_techniques=_as_list(meta.get("matches_techniques")),
        body=body,
        source_path=str(path),
    )


def _scan_dir(root: Path) -> List[Skill]:
    """Scan a `skills/` root directory for `<skill-name>/SKILL.md` entries."""
    if not root.exists() or not root.is_dir():
        return []
    skills: List[Skill] = []
    for entry in sorted(root.iterdir()):
        if not entry.is_dir():
            continue
        skill_md = entry / "SKILL.md"
        if not skill_md.is_file():
            continue
        skill = _load_skill_from_file(skill_md)
        if skill is not None:
            skills.append(skill)
    return skills


# ---------------------------------------------------------------------------
# Module-level cache (lazy load; reload on demand)
# ---------------------------------------------------------------------------

_BUNDLED_DIR = Path(__file__).resolve().parent.parent / "data" / "skills"
_cache: Optional[Dict[str, Skill]] = None


def _runtime_dir() -> Optional[Path]:
    """Operator-override directory; defaults to <ION_DATA_DIR>/skills."""
    raw = os.environ.get("ION_SKILLS_DIR")
    if raw:
        return Path(raw)
    data_dir = os.environ.get("ION_DATA_DIR")
    if data_dir:
        return Path(data_dir) / "skills"
    return None


def _load_all() -> Dict[str, Skill]:
    """Load bundled + runtime skills; runtime overrides bundled by name."""
    by_name: Dict[str, Skill] = {}
    for s in _scan_dir(_BUNDLED_DIR):
        by_name[s.name] = s
    rt = _runtime_dir()
    if rt is not None:
        for s in _scan_dir(rt):
            by_name[s.name] = s  # runtime overrides bundled
    return by_name


def list_skills(*, force_refresh: bool = False) -> List[Skill]:
    """Return all loaded skills (cached)."""
    global _cache
    if _cache is None or force_refresh:
        _cache = _load_all()
        logger.info(
            "skill_loader: loaded %d skill(s) (%d bundled, %s runtime)",
            len(_cache),
            len(_scan_dir(_BUNDLED_DIR)),
            (_runtime_dir() and "yes") or "no",
        )
    return list(_cache.values())


def get_skill(name: str) -> Optional[Skill]:
    """Look up one skill by name."""
    for s in list_skills():
        if s.name == name:
            return s
    return None


# ---------------------------------------------------------------------------
# Matching: which skills apply to this alert?
# ---------------------------------------------------------------------------


def _alert_techniques(alert: Dict[str, Any]) -> List[str]:
    """Pull MITRE technique ids from the alert payload (best-effort)."""
    techs: List[str] = []
    # ECS shape: alert.kibana.alert.rule.threat[].technique[].id
    threat = (
        alert.get("kibana", {}).get("alert", {}).get("rule", {}).get("threat")
        or alert.get("rule", {}).get("threat")
        or []
    )
    if isinstance(threat, list):
        for entry in threat:
            for t in (entry.get("technique") or []):
                if isinstance(t, dict) and t.get("id"):
                    techs.append(str(t["id"]))
    # Sigma / Talon / ION shape: explicit list
    for path in ("threat.technique", "rule.technique_ids", "mitre_techniques"):
        # Best-effort dotted lookup
        cur: Any = alert
        ok = True
        for part in path.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                ok = False
                break
        if ok and isinstance(cur, list):
            techs.extend(str(x) for x in cur)
    return list({t for t in techs if t})


def _alert_rule_groups(alert: Dict[str, Any]) -> List[str]:
    """Pull rule-group / category labels from the alert payload."""
    out: List[str] = []
    rule = alert.get("rule") or alert.get("kibana", {}).get("alert", {}).get("rule") or {}
    for key in ("groups", "category", "tags"):
        v = rule.get(key) if isinstance(rule, dict) else None
        if isinstance(v, list):
            out.extend(str(x) for x in v)
        elif isinstance(v, str):
            out.append(v)
    # ION's rule_groups_json shape
    for v in (alert.get("rule_groups") or []):
        out.append(str(v))
    return [s.lower() for s in out if s]


def _alert_keywords(alert: Dict[str, Any]) -> List[str]:
    """Lowercased alert text for keyword matching against `when_to_use`."""
    parts: List[str] = []
    rule = alert.get("rule") or alert.get("kibana", {}).get("alert", {}).get("rule") or {}
    if isinstance(rule, dict):
        for key in ("name", "description", "language", "type", "category"):
            v = rule.get(key)
            if isinstance(v, str):
                parts.append(v.lower())
    # Top-level convenience fields ION sometimes carries
    for key in ("rule_name", "message"):
        v = alert.get(key)
        if isinstance(v, str):
            parts.append(v.lower())
    return parts


def _technique_matches(skill_techs: List[str], alert_techs: List[str]) -> bool:
    """Parent-sub tolerant technique match."""
    if not skill_techs:
        return False
    if any(t.lower() == "any" or t == "*" for t in skill_techs):
        return True
    skill_set = {t.upper() for t in skill_techs}
    for at in alert_techs:
        au = at.upper()
        if au in skill_set:
            return True
        # parent-sub tolerant: T1059.001 should match a skill targeting T1059
        parent = au.split(".")[0]
        if parent in skill_set:
            return True
        # And vice-versa: skill targeting T1059.001 matches an alert tagged T1059
        for st in skill_set:
            if "." in st and st.split(".")[0] == au:
                return True
    return False


def _group_matches(skill_groups: List[str], alert_groups: List[str]) -> bool:
    if not skill_groups:
        return False
    skill_low = {g.lower() for g in skill_groups}
    return any(g in skill_low for g in alert_groups)


_KW_TOKEN_RE = re.compile(r"[a-z0-9_\-\.]{3,}")


def _when_to_use_matches(skill: Skill, alert_keywords: List[str], alert_techs: List[str], alert_groups: List[str]) -> bool:
    """Match the skill's `when_to_use` clause against the alert.

    Heuristic — extract noteworthy tokens from `when_to_use` and check
    overlap with rule-name / rule-description / technique-ids /
    rule-groups. Lightweight and avoids vector embeddings; trade-off is
    occasional miss / false-match. The L3 / detection-eng can refine the
    `when_to_use` clause to tighten matching over time.
    """
    if not skill.when_to_use:
        return False
    blob = " ".join([
        skill.when_to_use.lower(),
    ])
    tokens = set(_KW_TOKEN_RE.findall(blob))
    if not tokens:
        return False
    haystack = " ".join(alert_keywords + [t.lower() for t in alert_techs] + alert_groups)
    # require ≥ 2 token matches OR an explicit technique id match in the
    # `when_to_use` text (to avoid weak single-keyword overlap)
    explicit_tech = any(t in blob for t in (a.lower() for a in alert_techs))
    if explicit_tech:
        return True
    overlap = sum(1 for tok in tokens if tok in haystack)
    return overlap >= 2


def select_skills_for_alert(alert: Dict[str, Any]) -> List[Skill]:
    """Return the subset of loaded skills that apply to this alert.

    Three matchers — any positive match wins:

    1. Technique-id overlap (parent-sub tolerant) against
       ``matches_techniques`` (or ``"any"``).
    2. Rule-group / category overlap against ``matches_rule_groups``.
    3. Keyword overlap between the skill's ``when_to_use`` clause and the
       alert's rule-name / description / technique tags.

    Skills are returned in load order (deterministic per estate); callers
    typically inject all matched skills into the prompt.
    """
    if alert is None:
        return []
    techs = _alert_techniques(alert)
    groups = _alert_rule_groups(alert)
    keywords = _alert_keywords(alert)

    out: List[Skill] = []
    for skill in list_skills():
        if _technique_matches(skill.matches_techniques, techs):
            out.append(skill)
            continue
        if _group_matches(skill.matches_rule_groups, groups):
            out.append(skill)
            continue
        if _when_to_use_matches(skill, keywords, techs, groups):
            out.append(skill)
            continue
    return out


def format_skills_for_prompt(skills: Iterable[Skill]) -> str:
    """Return a formatted block to inject into the system prompt.

    Rendering: a heading, then each skill's name + body with a separator.
    Empty when no skills match (caller should not append an empty block).
    """
    items = list(skills)
    if not items:
        return ""
    parts: List[str] = ["\n\n---\n## Loaded Skills (Tier-6 augmentation)\n"]
    parts.append(
        "The following Agent Skills apply to this alert based on its "
        "rule-group / technique / keyword profile. Use them as additional "
        "guidance alongside the per-rule investigation template.\n"
    )
    for s in items:
        parts.append(f"\n### Skill — {s.name}\n")
        if s.description:
            parts.append(f"_{s.description.strip()}_\n\n")
        parts.append(s.body.rstrip() + "\n")
    return "".join(parts)
