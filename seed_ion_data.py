"""Seed ION with test templates and collections."""

import sys
sys.path.insert(0, '/app/src')

from pathlib import Path
from ion.storage.database import get_engine, get_session_factory
from ion.models.template import Template, TemplateVersion
from ion.models.collection import Collection
from datetime import datetime

db_path = Path('/data/.ion/ion.db')
engine = get_engine(db_path)
factory = get_session_factory(engine)
session = factory()

# Create Collections
collections_data = [
    ('Incident Response', 'Templates for incident response documentation'),
    ('Threat Intelligence', 'Threat intel report templates'),
    ('Compliance', 'Compliance and audit templates'),
    ('SOC Operations', 'Daily SOC operation templates'),
]

print('Creating Collections...')
collections = {}
for name, desc in collections_data:
    existing = session.query(Collection).filter_by(name=name).first()
    if not existing:
        c = Collection(name=name, description=desc)
        session.add(c)
        session.flush()
        collections[name] = c
        print(f'  Created: {name}')
    else:
        collections[name] = existing
        print(f'  Exists: {name}')

# Template content (using raw strings to avoid escape issues)
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

templates_data = [
    ('Incident Report', 'Incident Response', 'markdown', incident_report),
    ('Threat Actor Profile', 'Threat Intelligence', 'markdown', threat_actor),
    ('Daily SOC Summary', 'SOC Operations', 'markdown', daily_summary),
    ('Malware Analysis Report', 'Threat Intelligence', 'markdown', malware_report),
    ('Compliance Checklist', 'Compliance', 'markdown', compliance_checklist),
]

print('Creating Templates...')
for name, collection_name, fmt, content in templates_data:
    existing = session.query(Template).filter_by(name=name).first()
    if not existing:
        t = Template(
            name=name,
            format=fmt,
            content=content,
            collection_id=collections[collection_name].id,
            created_by='admin'
        )
        session.add(t)
        session.flush()

        v = TemplateVersion(
            template_id=t.id,
            version=1,
            content=content,
            created_by='admin',
            comment='Initial version'
        )
        session.add(v)
        print(f'  Created: {name}')
    else:
        print(f'  Exists: {name}')

session.commit()
print('\nION data seeding complete!')
print(f'Collections: {session.query(Collection).count()}')
print(f'Templates: {session.query(Template).count()}')
