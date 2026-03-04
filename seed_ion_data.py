"""Seed ION with core document templates and collections.

Seeds 4 template collections (Incident Response, Threat Intelligence,
Compliance, SOC Operations) and 5 Jinja2 document templates.

Uses the HTTP API — requires a running ION server.

Environment variables:
  ION_SEED_URL          Base URL (default: http://127.0.0.1:8000)
  ION_ADMIN_PASSWORD    Admin password (default: admin2025)
"""

import os
import sys
import requests

BASE = os.environ.get("ION_SEED_URL", "http://127.0.0.1:8000")
SESSION = requests.Session()


def login():
    r = SESSION.post(
        f"{BASE}/api/auth/login",
        json={"username": "admin", "password": os.environ.get("ION_ADMIN_PASSWORD", "admin2025")},
    )
    r.raise_for_status()
    print("Logged in as admin")


def get_or_create_collection(name, desc, parent_id=None):
    r = SESSION.get(f"{BASE}/api/collections")
    data = r.json()
    cols = data if isinstance(data, list) else data.get("collections", [])
    for c in cols:
        if c["name"] == name:
            return c["id"]
    body = {"name": name, "description": desc}
    if parent_id:
        body["parent_id"] = parent_id
    r = SESSION.post(f"{BASE}/api/collections", json=body)
    if r.status_code == 400:
        r2 = SESSION.get(f"{BASE}/api/collections")
        data2 = r2.json()
        cols2 = data2 if isinstance(data2, list) else data2.get("collections", [])
        for c2 in cols2:
            if c2["name"] == name:
                return c2["id"]
        return None
    r.raise_for_status()
    cid = r.json()["id"]
    print(f"  Created collection: {name} (id={cid})")
    return cid


def create_template(name, content, fmt, collection_id, tags=None):
    r = SESSION.get(f"{BASE}/api/templates", params={"search": name})
    data = r.json()
    tpls = data if isinstance(data, list) else data.get("templates", [])
    for t in tpls:
        if t["name"] == name:
            print(f"  Skipped (exists): {name}")
            return t["id"]
    body = {
        "name": name,
        "content": content,
        "format": fmt,
        "tags": tags or [],
    }
    r = SESSION.post(f"{BASE}/api/templates", json=body)
    r.raise_for_status()
    tid = r.json()["id"]
    # Move template into collection
    SESSION.post(f"{BASE}/api/collections/{collection_id}/templates/{tid}")
    print(f"  Created template: {name} (id={tid})")
    return tid


# ---------------------------------------------------------------------------
# Template content (Jinja2 markdown templates)
# ---------------------------------------------------------------------------

incident_report = r'''# Incident Report: {{ incident_id }}

## Executive Summary
**Date:** {{ date }}
**Severity:** {{ severity }}
**Status:** {{ status }}

{{ executive_summary }}

## Timeline
{% for event in timeline %}
- **{{ event.time }}**: {{ event.description }}
{% endfor %}

## Affected Systems
{% for system in affected_systems %}
- {{ system.hostname }} ({{ system.ip }})
{% endfor %}

## Root Cause Analysis
{{ root_cause }}

## Remediation Actions
{% for action in actions %}
1. {{ action }}
{% endfor %}

## Lessons Learned
{{ lessons_learned }}
'''

threat_actor = r'''# Threat Actor: {{ actor_name }}

## Overview
**Aliases:** {{ aliases | join(", ") }}
**Origin:** {{ origin }}
**Motivation:** {{ motivation }}

## Description
{{ description }}

## TTPs
{% for ttp in ttps %}
- **{{ ttp.technique_id }}**: {{ ttp.name }}
{% endfor %}

## Indicators of Compromise
{% for ioc in iocs %}
- {{ ioc.type }}: `{{ ioc.value }}`
{% endfor %}
'''

daily_summary = r'''# Daily SOC Summary - {{ date }}

## Shift: {{ shift }}
**Analyst:** {{ analyst }}

## Alert Statistics
| Severity | Count | Resolved |
|----------|-------|----------|
{% for stat in stats %}
| {{ stat.severity }} | {{ stat.count }} | {{ stat.resolved }} |
{% endfor %}

## Notable Incidents
{% for incident in incidents %}
### {{ incident.title }}
- **Severity:** {{ incident.severity }}
- **Summary:** {{ incident.summary }}
{% endfor %}

## Handover Notes
{{ handover_notes }}
'''

malware_report = r'''# Malware Analysis Report

## Sample Information
| Property | Value |
|----------|-------|
| Filename | {{ filename }} |
| SHA256 | `{{ sha256 }}` |
| File Type | {{ file_type }} |

## Executive Summary
{{ executive_summary }}

## Network Indicators
{% for indicator in network_indicators %}
- {{ indicator.type }}: `{{ indicator.value }}`
{% endfor %}

## MITRE ATT&CK Mapping
{% for technique in mitre_techniques %}
- **{{ technique.id }}**: {{ technique.name }}
{% endfor %}
'''

compliance_checklist = r'''# {{ framework }} Compliance Checklist

**Assessment Date:** {{ date }}
**Assessor:** {{ assessor }}

## Control Assessment
{% for control in controls %}
| {{ control.id }} | {{ control.description }} | {{ control.status }} |
{% endfor %}

## Summary
- **Compliant:** {{ compliant_count }}
- **Non-Compliant:** {{ non_compliant_count }}
'''

# ---------------------------------------------------------------------------
# Data definitions
# ---------------------------------------------------------------------------

COLLECTIONS = [
    ("Incident Response", "Templates for incident response documentation"),
    ("Threat Intelligence", "Threat intel report templates"),
    ("Compliance", "Compliance and audit templates"),
    ("SOC Operations", "Daily SOC operation templates"),
]

TEMPLATES = [
    ("Incident Report", "Incident Response", "markdown", incident_report, ["incident", "ir"]),
    ("Threat Actor Profile", "Threat Intelligence", "markdown", threat_actor, ["threat-intel", "apt"]),
    ("Daily SOC Summary", "SOC Operations", "markdown", daily_summary, ["soc", "shift-handover"]),
    ("Malware Analysis Report", "Threat Intelligence", "markdown", malware_report, ["malware", "reverse-engineering"]),
    ("Compliance Checklist", "Compliance", "markdown", compliance_checklist, ["compliance", "audit"]),
]


def main():
    login()

    # Create collections
    print("\nCreating collections...")
    collections = {}
    for name, desc in COLLECTIONS:
        cid = get_or_create_collection(name, desc)
        collections[name] = cid

    # Create templates
    print("\nCreating templates...")
    created = 0
    for name, col_name, fmt, content, tags in TEMPLATES:
        col_id = collections.get(col_name)
        if col_id:
            create_template(name, content, fmt, col_id, tags)
            created += 1

    print(f"\nION data seeding complete! ({created} templates across {len(COLLECTIONS)} collections)")


if __name__ == "__main__":
    main()
