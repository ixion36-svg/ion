"""Section type definitions and Jinja2 assembly logic for the visual template editor."""

import json
import re
from typing import Any

# =========================================================================
# Section Type Definitions (9 Generic + 6 SOC-Specific = 15 total)
# =========================================================================

SECTION_TYPES: dict[str, dict[str, Any]] = {
    # --- Generic Sections ---
    "heading": {
        "label": "Heading",
        "category": "generic",
        "icon": "H",
        "description": "Section heading (h1-h4)",
        "fields": [
            {"name": "text", "type": "text", "label": "Heading Text", "required": True},
            {
                "name": "level",
                "type": "select",
                "label": "Level",
                "options": [
                    {"value": "1", "label": "H1"},
                    {"value": "2", "label": "H2"},
                    {"value": "3", "label": "H3"},
                    {"value": "4", "label": "H4"},
                ],
                "default": "2",
            },
        ],
    },
    "text": {
        "label": "Text",
        "category": "generic",
        "icon": "T",
        "description": "Rich text paragraph",
        "supports_variable": True,
        "fields": [
            {"name": "content", "type": "textarea", "label": "Content", "required": True},
        ],
    },
    "table": {
        "label": "Table",
        "category": "generic",
        "icon": "TBL",
        "description": "Dynamic data table",
        "supports_variable": True,
        "fields": [
            {
                "name": "columns",
                "type": "columns",
                "label": "Columns",
                "required": True,
                "description": "Define table columns (name and optional type)",
            },
        ],
    },
    "list": {
        "label": "List",
        "category": "generic",
        "icon": "LI",
        "description": "Bulleted or numbered list",
        "supports_variable": True,
        "fields": [
            {"name": "items", "type": "items", "label": "List Items"},
            {
                "name": "ordered",
                "type": "checkbox",
                "label": "Numbered list",
                "default": False,
            },
        ],
    },
    "key_value": {
        "label": "Key-Value Pairs",
        "category": "generic",
        "icon": "KV",
        "description": "Label-value pairs",
        "supports_variable": True,
        "fields": [
            {"name": "pairs", "type": "pairs", "label": "Key-Value Pairs"},
        ],
    },
    "divider": {
        "label": "Divider",
        "category": "generic",
        "icon": "---",
        "description": "Horizontal rule separator",
        "fields": [],
    },
    "metadata_block": {
        "label": "Metadata Block",
        "category": "generic",
        "icon": "META",
        "description": "Document metadata header with label-variable pairs",
        "fields": [
            {
                "name": "fields",
                "type": "metadata_fields",
                "label": "Metadata Fields",
                "description": "Label and variable name for each metadata field",
            },
        ],
    },
    "signature_block": {
        "label": "Signature Block",
        "category": "generic",
        "icon": "SIG",
        "description": "Approval/signature area",
        "fields": [
            {
                "name": "roles",
                "type": "signature_roles",
                "label": "Signature Roles",
                "description": "Role name and variable name for each signer",
            },
        ],
    },
    "image_placeholder": {
        "label": "Image Placeholder",
        "category": "generic",
        "icon": "IMG",
        "description": "Placeholder for diagram or screenshot",
        "fields": [
            {"name": "caption", "type": "text", "label": "Caption", "required": True},
            {"name": "variable_name", "type": "text", "label": "Variable Name", "required": True},
        ],
    },
    # --- SOC-Specific Sections ---
    "severity_badge": {
        "label": "Severity Badge",
        "category": "soc",
        "icon": "SEV",
        "description": "Color-coded severity indicator",
        "fields": [
            {
                "name": "variable_name",
                "type": "text",
                "label": "Severity Variable",
                "required": True,
                "default": "severity",
            },
        ],
    },
    "ioc_table": {
        "label": "IOC Table",
        "category": "soc",
        "icon": "IOC",
        "description": "Indicators of Compromise table",
        "fields": [
            {
                "name": "variable_name",
                "type": "text",
                "label": "IOC List Variable",
                "required": True,
                "default": "ioc_list",
            },
        ],
    },
    "timeline": {
        "label": "Timeline",
        "category": "soc",
        "icon": "TIME",
        "description": "Incident timeline with timestamp, event, and actor",
        "fields": [
            {
                "name": "variable_name",
                "type": "text",
                "label": "Timeline Entries Variable",
                "required": True,
                "default": "timeline_entries",
            },
        ],
    },
    "mitre_table": {
        "label": "MITRE ATT&CK Table",
        "category": "soc",
        "icon": "ATT",
        "description": "ATT&CK technique references",
        "fields": [
            {
                "name": "variable_name",
                "type": "text",
                "label": "Techniques Variable",
                "required": True,
                "default": "mitre_techniques",
            },
        ],
    },
    "checklist": {
        "label": "Checklist",
        "category": "soc",
        "icon": "CHK",
        "description": "Interactive checkbox list",
        "fields": [
            {"name": "items", "type": "checklist_items", "label": "Checklist Items"},
        ],
    },
    "evidence_block": {
        "label": "Evidence Block",
        "category": "soc",
        "icon": "EVD",
        "description": "Evidence/artifact reference",
        "fields": [
            {"name": "source", "type": "text", "label": "Source", "required": True},
            {"name": "hash", "type": "text", "label": "Hash"},
            {"name": "description", "type": "textarea", "label": "Description"},
            {
                "name": "chain_of_custody_var",
                "type": "text",
                "label": "Chain of Custody Variable",
                "default": "chain_of_custody",
            },
        ],
    },
}


def _slugify(text: str) -> str:
    """Convert label text to a variable name slug."""
    slug = re.sub(r"[^a-z0-9]+", "_", text.lower().strip())
    return slug.strip("_")


def _section_to_jinja2(section: dict) -> str:
    """Convert a single section config dict to Jinja2/Markdown string."""
    stype = section.get("type", "")
    config = section.get("config", {})
    is_variable = config.get("variable", False)
    var_name = config.get("variable_name", "")

    if stype == "heading":
        text = config.get("text", "Heading")
        level = int(config.get("level", 2))
        hashes = "#" * level
        return f"{hashes} {text}"

    if stype == "text":
        if is_variable and var_name:
            return "{{ " + var_name + " }}"
        return config.get("content", "")

    if stype == "table":
        columns = config.get("columns", [])
        if not columns:
            return ""
        if is_variable and var_name:
            # Dynamic table with Jinja2 loop
            headers = " | ".join(col.get("name", "Column") for col in columns)
            separator = " | ".join("---" for _ in columns)
            cells = " | ".join(
                "{{ row." + _slugify(col.get("name", "col")) + " }}" for col in columns
            )
            return (
                f"| {headers} |\n"
                f"| {separator} |\n"
                "{{% for row in " + var_name + " %}}\n"
                f"| {cells} |\n"
                "{% endfor %}"
            )
        else:
            # Static table with placeholder rows
            headers = " | ".join(col.get("name", "Column") for col in columns)
            separator = " | ".join("---" for _ in columns)
            placeholder = " | ".join("" for _ in columns)
            return f"| {headers} |\n| {separator} |\n| {placeholder} |"

    if stype == "list":
        if is_variable and var_name:
            ordered = config.get("ordered", False)
            if ordered:
                return (
                    "{% for item in " + var_name + " %}\n"
                    "{{ loop.index }}. {{ item }}\n"
                    "{% endfor %}"
                )
            return (
                "{% for item in " + var_name + " %}\n"
                "- {{ item }}\n"
                "{% endfor %}"
            )
        items = config.get("items", [])
        ordered = config.get("ordered", False)
        lines = []
        for i, item in enumerate(items, 1):
            text = item if isinstance(item, str) else item.get("text", "")
            if ordered:
                lines.append(f"{i}. {text}")
            else:
                lines.append(f"- {text}")
        return "\n".join(lines)

    if stype == "key_value":
        if is_variable and var_name:
            return (
                "{% for kv in " + var_name + " %}\n"
                "**{{ kv.label }}:** {{ kv.value }}\n"
                "{% endfor %}"
            )
        pairs = config.get("pairs", [])
        lines = []
        for pair in pairs:
            label = pair.get("label", "")
            value = pair.get("value", "")
            lines.append(f"**{label}:** {value}")
        return "\n\n".join(lines)

    if stype == "divider":
        return "---"

    if stype == "metadata_block":
        fields = config.get("fields", [])
        lines = []
        for field in fields:
            label = field.get("label", "Field")
            fvar = field.get("variable_name", _slugify(label))
            lines.append(f"**{label}:** {{{{ {fvar} }}}}")
        return "\n\n".join(lines)

    if stype == "signature_block":
        roles = config.get("roles", [])
        lines = ["", "---", "### Signatures", ""]
        for role in roles:
            role_name = role.get("role_name", "Role")
            rvar = role.get("variable_name", _slugify(role_name))
            lines.append(f"**{role_name}:** {{{{ {rvar} }}}}")
            lines.append("")
        return "\n".join(lines)

    if stype == "image_placeholder":
        caption = config.get("caption", "Image")
        ivar = config.get("variable_name", _slugify(caption))
        return f"![{caption}]({{{{ {ivar} }}}})"

    if stype == "severity_badge":
        svar = config.get("variable_name", "severity")
        return "**Severity:** {{ " + svar + " }}"

    if stype == "ioc_table":
        ivar = config.get("variable_name", "ioc_list")
        return (
            "| Type | Value | Context |\n"
            "| --- | --- | --- |\n"
            "{% for ioc in " + ivar + " %}\n"
            "| {{ ioc.type }} | {{ ioc.value }} | {{ ioc.context }} |\n"
            "{% endfor %}"
        )

    if stype == "timeline":
        tvar = config.get("variable_name", "timeline_entries")
        return (
            "| Timestamp | Event | Actor |\n"
            "| --- | --- | --- |\n"
            "{% for entry in " + tvar + " %}\n"
            "| {{ entry.timestamp }} | {{ entry.event }} | {{ entry.actor }} |\n"
            "{% endfor %}"
        )

    if stype == "mitre_table":
        mvar = config.get("variable_name", "mitre_techniques")
        return (
            "| Technique ID | Name | Tactic |\n"
            "| --- | --- | --- |\n"
            "{% for tech in " + mvar + " %}\n"
            "| {{ tech.id }} | {{ tech.name }} | {{ tech.tactic }} |\n"
            "{% endfor %}"
        )

    if stype == "checklist":
        items = config.get("items", [])
        lines = []
        for item in items:
            text = item.get("text", "") if isinstance(item, dict) else str(item)
            checked = item.get("checked", False) if isinstance(item, dict) else False
            mark = "x" if checked else " "
            lines.append(f"- [{mark}] {text}")
        return "\n".join(lines)

    if stype == "evidence_block":
        source = config.get("source", "")
        hash_val = config.get("hash", "")
        desc = config.get("description", "")
        coc_var = config.get("chain_of_custody_var", "chain_of_custody")
        lines = [
            "#### Evidence",
            "",
            f"**Source:** {source}",
        ]
        if hash_val:
            lines.append(f"**Hash:** {hash_val}")
        if desc:
            lines.append(f"**Description:** {desc}")
        lines.append("")
        lines.append(f"**Chain of Custody:** {{{{ {coc_var} }}}}")
        return "\n".join(lines)

    return ""


def assemble_jinja2(sections: list[dict]) -> str:
    """Convert a list of section config dicts to a single Jinja2 content string.

    Each section is rendered to Jinja2/Markdown and joined with double newlines.
    The resulting string is fully compatible with the existing Jinja2 + Markdown
    render pipeline.
    """
    parts = []
    for section in sections:
        rendered = _section_to_jinja2(section)
        if rendered:
            parts.append(rendered)
    return "\n\n".join(parts)


def extract_variables(sections: list[dict]) -> list[str]:
    """Extract all Jinja2 variable names from sections config.

    Returns a deduplicated list of variable names that appear in the
    assembled Jinja2 output.
    """
    content = assemble_jinja2(sections)
    # Match {{ var }}, {{ var.attr }}, and loop variables
    simple_vars = set(re.findall(r"\{\{\s*(\w+)", content))
    # Also capture variables from for loops: {% for x in var_name %}
    loop_vars = set(re.findall(r"\{%\s*for\s+\w+\s+in\s+(\w+)", content))
    # Remove loop iterator variables (row, item, ioc, entry, tech, kv, loop)
    iterators = {"row", "item", "ioc", "entry", "tech", "kv", "loop"}
    all_vars = (simple_vars | loop_vars) - iterators
    return sorted(all_vars)


def parse_sections_json(sections_json: str | None) -> list[dict] | None:
    """Parse sections_json string to list of dicts. Returns None if empty/invalid."""
    if not sections_json:
        return None
    try:
        data = json.loads(sections_json)
        if isinstance(data, list):
            return data
    except (json.JSONDecodeError, TypeError):
        pass
    return None
