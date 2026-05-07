"""Skill publisher service — export AlertPromptTemplate rows as SKILL.md folders.

Converts ION's per-rule LLM prompt templates into the Elastic Agent Skills
SKILL.md format consumed by ``skill_loader.py`` (Bob's Tier-6 matcher).
A published skill folder round-trips cleanly through ``_load_skill_from_file``
without modification.

Column → frontmatter mapping
-----------------------------
name               → name          (slugified: spaces→hyphens, lower)
description        → description
rule_groups_json   → matches_rule_groups
mitre_techniques_json → matches_techniques  (falls back to ["any"] when empty)
mitre_tactics_json → tags           (prefixed "tactic:")
rule_ids_json      → when_to_use    (listed for reference in gating clause)
rule_id_pattern    → when_to_use    (appended when present)
prompt_text        → body           (Markdown body after the frontmatter fence)
"""

from __future__ import annotations

import json
import re
from typing import Optional

from ion.models.alert_prompt import AlertPromptTemplate


def _slug(name: str) -> str:
    """Convert a template name to a filesystem-safe skill slug."""
    slug = name.lower()
    slug = re.sub(r"[^a-z0-9]+", "-", slug)
    return slug.strip("-")


def _load_json_list(raw: Optional[str]) -> list[str]:
    if not raw:
        return []
    try:
        val = json.loads(raw)
        return [str(x) for x in val] if isinstance(val, list) else []
    except Exception:
        return []


def _yaml_str(value: str) -> str:
    """Render a scalar string value; quote if it contains YAML special chars."""
    if not value:
        return '""'
    if any(c in value for c in (':', '#', "'", '"', '\n', '[')):
        escaped = value.replace('"', '\\"')
        return f'"{escaped}"'
    return value


def _yaml_list(items: list[str]) -> str:
    """Render a YAML list block (each item on its own ``- item`` line)."""
    if not items:
        return "[]\n"
    lines = [f"  - {_yaml_str(item)}" for item in items]
    return "\n" + "\n".join(lines) + "\n"


def _build_when_to_use(
    rule_ids: list[str],
    rule_id_pattern: Optional[str],
) -> str:
    """Compose the ``when_to_use`` gating clause from matching metadata."""
    parts: list[str] = []
    if rule_ids:
        id_list = ", ".join(rule_ids)
        parts.append(f"Apply when the alert matches one of these rule IDs: {id_list}.")
    if rule_id_pattern:
        parts.append(
            f"Apply when the alert rule ID matches the pattern: {rule_id_pattern}."
        )
    if not parts:
        return "Apply when this investigation template is the best match for the alert."
    return " ".join(parts)


def render_skill_md(
    template: AlertPromptTemplate,
) -> tuple[str, dict[str, bytes]]:
    """Render a SKILL.md for *template*.

    Returns
    -------
    skill_md_content : str
        Full text of the ``SKILL.md`` file (frontmatter + body).
    supporting_files : dict[str, bytes]
        Map of relative filename → bytes for any extra files in the folder.
        Currently always empty; reserved for future use.
    """
    name = _slug(template.name)
    description = template.description or template.name

    rule_ids = _load_json_list(template.rule_ids_json)
    rule_groups = _load_json_list(template.rule_groups_json)
    techniques = _load_json_list(template.mitre_techniques_json)
    tactics = _load_json_list(template.mitre_tactics_json)

    # matches_techniques: use actual list or sentinel "any"
    matches_techniques = techniques if techniques else ["any"]

    # tags: combine tactic slugs with a "ion-template" marker
    tags: list[str] = [f"tactic:{t.lower()}" for t in tactics]
    tags.append("ion-template")

    when_to_use = _build_when_to_use(rule_ids, template.rule_id_pattern)

    # Build frontmatter — hand-rolled YAML to avoid taking a hard PyYAML dep
    # (skill_loader.py already tries PyYAML then falls back; we prefer PyYAML
    # when available, which all ION deployments have, so valid YAML is fine).
    fm_lines: list[str] = [
        "---",
        f"name: {name}",
        f"description: {_yaml_str(description)}",
        "when_to_use: |",
    ]
    for wtu_line in when_to_use.splitlines():
        fm_lines.append(f"  {wtu_line}")
    fm_lines.append("tags:")
    for tag in tags:
        fm_lines.append(f"  - {tag}")
    fm_lines.append("matches_rule_groups:")
    for rg in rule_groups:
        fm_lines.append(f"  - {_yaml_str(rg)}")
    fm_lines.append("matches_techniques:")
    for tech in matches_techniques:
        fm_lines.append(f"  - {tech}")
    fm_lines.append("---")

    frontmatter = "\n".join(fm_lines) + "\n"

    body = template.prompt_text or ""
    if not body.startswith("\n"):
        body = "\n" + body

    skill_md = frontmatter + body

    return skill_md, {}
