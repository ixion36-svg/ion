# DocForge MITRE ATT&CK Integration Guide

This guide explains how DocForge extracts, displays, and allows manual tagging of MITRE ATT&CK techniques for security alert investigation.

## Overview

The MITRE ATT&CK framework provides a knowledge base of adversary tactics and techniques. DocForge integrates with this framework to:

- **Auto-extract** technique/tactic data from Elasticsearch alerts
- **Display** technique badges on alerts for quick identification
- **Visualize** technique distribution via an interactive heatmap
- **Enable** manual tagging of alerts with additional techniques
- **Filter** alerts by specific techniques or tactics

### Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         Elasticsearch Cluster                            │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐          │
│  │  SIEM Alerts    │  │  Watcher Alerts │  │  Custom Alerts  │          │
│  │ (threat.* ECS)  │  │ (signal.rule.*) │  │                 │          │
│  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘          │
└───────────┼────────────────────┼────────────────────┼───────────────────┘
            │                    │                    │
            ▼                    ▼                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      DocForge Alert Parser                               │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │  MITRE Extraction:                                               │    │
│  │  • threat.technique.id/name  (primary)                          │    │
│  │  • threat.tactic.name                                           │    │
│  │  • signal.rule.threat[0].technique[0]  (fallback)               │    │
│  └─────────────────────────────────────────────────────────────────┘    │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         DocForge UI (/alerts)                            │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │
│  │  Heatmap    │  │   Badges    │  │   Manual    │  │   Filter    │     │
│  │ (Analytics) │  │ (Per Alert) │  │   Tagging   │  │ by Technique│     │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘     │
└─────────────────────────────────────────────────────────────────────────┘
```

## MITRE ATT&CK Framework Reference

### Tactics (14 Total)

The framework organizes adversary behavior into 14 tactical categories:

| Tactic | ID | Description |
|--------|----|-----------|
| Reconnaissance | TA0043 | Gathering information for planning |
| Resource Development | TA0042 | Establishing resources for operations |
| Initial Access | TA0001 | Getting into the network |
| Execution | TA0002 | Running malicious code |
| Persistence | TA0003 | Maintaining foothold |
| Privilege Escalation | TA0004 | Gaining higher permissions |
| Defense Evasion | TA0005 | Avoiding detection |
| Credential Access | TA0006 | Stealing credentials |
| Discovery | TA0007 | Learning the environment |
| Lateral Movement | TA0008 | Moving through network |
| Collection | TA0009 | Gathering target data |
| Command and Control | TA0011 | Communicating with compromised systems |
| Exfiltration | TA0010 | Stealing data |
| Impact | TA0040 | Disrupting availability or integrity |

### Technique ID Format

Technique IDs follow these patterns:
- **Base technique**: `T####` (e.g., `T1110` - Brute Force)
- **Sub-technique**: `T####.###` (e.g., `T1110.001` - Password Guessing)

## Data Extraction

### ECS Field Mappings

DocForge extracts MITRE data from alerts using these field paths:

| Field | Primary Path (ECS/Seed Data) | Fallback Path (Elastic SIEM) |
|-------|------------------------------|------------------------------|
| Technique ID | `threat.technique.id` | `signal.rule.threat[0].technique[0].id` |
| Technique Name | `threat.technique.name` | `signal.rule.threat[0].technique[0].name` |
| Tactic Name | `threat.tactic.name` | `signal.rule.threat[0].tactic.name` |

### Alert Data Model

The `ElasticsearchAlert` dataclass includes these MITRE fields:

```python
@dataclass
class ElasticsearchAlert:
    # ... existing fields ...

    mitre_technique_id: Optional[str] = None    # e.g., "T1110"
    mitre_technique_name: Optional[str] = None  # e.g., "Brute Force"
    mitre_tactic_name: Optional[str] = None     # e.g., "Credential Access"
```

### Sample Alert with MITRE Data

```json
{
  "@timestamp": "2024-01-15T10:30:00.000Z",
  "kibana.alert.rule.name": "Brute Force Attack Detected",
  "kibana.alert.severity": "high",
  "threat": {
    "technique": {
      "id": "T1110",
      "name": "Brute Force"
    },
    "tactic": {
      "name": "Credential Access"
    }
  },
  "source": {
    "ip": "192.168.1.100"
  },
  "user": {
    "name": "admin"
  }
}
```

## Manual Tagging

### Data Storage

Manual technique tags are stored in the `AlertTriage` model:

```python
class AlertTriage(Base):
    # ... existing fields ...

    mitre_techniques: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
```

### Tag Format

Each technique tag includes:

```json
{
  "technique_id": "T1110",
  "technique_name": "Brute Force",
  "tactic_name": "Credential Access",
  "source": "auto"  // or "manual"
}
```

| Field | Description |
|-------|-------------|
| `technique_id` | MITRE technique ID (required, format: `T####` or `T####.###`) |
| `technique_name` | Human-readable technique name |
| `tactic_name` | Parent tactic name |
| `source` | `"auto"` (extracted from alert) or `"manual"` (analyst-added) |

### Validation

Technique IDs are validated against the pattern: `^T\d{4}(\.\d{3})?$`

Valid examples:
- `T1110` (base technique)
- `T1110.001` (sub-technique)

Invalid examples:
- `1110` (missing T prefix)
- `T110` (wrong digit count)
- `T1110.01` (sub-technique needs 3 digits)

## API Endpoints

### Update Alert Triage with MITRE Techniques

```http
PUT /api/elasticsearch/alerts/{alert_id}/triage
Content-Type: application/json

{
  "verdict": "true_positive",
  "notes": "Confirmed brute force attack",
  "mitre_techniques": [
    {
      "technique_id": "T1110",
      "technique_name": "Brute Force",
      "tactic_name": "Credential Access",
      "source": "auto"
    },
    {
      "technique_id": "T1078",
      "technique_name": "Valid Accounts",
      "tactic_name": "Defense Evasion",
      "source": "manual"
    }
  ]
}
```

### Get MITRE Statistics

```http
GET /api/elasticsearch/alerts/mitre-stats?hours=24
```

Response:
```json
{
  "techniques": {
    "T1110": {
      "name": "Brute Force",
      "tactic": "Credential Access",
      "count": 42
    },
    "T1078": {
      "name": "Valid Accounts",
      "tactic": "Defense Evasion",
      "count": 15
    }
  },
  "tactics": {
    "Credential Access": 57,
    "Defense Evasion": 23,
    "Initial Access": 18
  },
  "total_alerts_with_mitre": 98,
  "time_range_hours": 24
}
```

## UI Components

### Technique Badges

Badges appear in two locations:

1. **Alert Table**: Subtle inline badge showing technique ID
2. **Alert Detail Modal**: Full badges with technique name

Badge styling:
- **Red solid border**: Auto-detected from alert data
- **Purple dashed border**: Manually added by analyst

```
┌─────────────────────────────────────────────────────────────────┐
│  Alert: Brute Force Attack Detected                             │
│  Severity: High  │  Status: Active                               │
│                                                                  │
│  MITRE ATT&CK:                                                   │
│  ┌──────────────┐  ┌──────────────────────┐                     │
│  │ T1110        │  │ T1078 (manual)       │                     │
│  │ Brute Force  │  │ Valid Accounts       │                     │
│  └──────────────┘  └──────────────────────┘                     │
└─────────────────────────────────────────────────────────────────┘
```

### Analytics Heatmap

The heatmap displays technique frequency across all 14 tactics:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        MITRE ATT&CK Technique Heatmap                        │
├─────────────────────────────────────────────────────────────────────────────┤
│ Recon │ Res.Dev │ Init.Acc │ Exec │ Persist │ Priv.Esc │ Def.Eva │ ...     │
├───────┼─────────┼──────────┼──────┼─────────┼──────────┼─────────┼─────────┤
│       │         │  T1566   │T1059 │  T1053  │  T1055   │  T1070  │         │
│       │         │  ████    │██    │  ██     │  ███     │  █      │         │
│       │         │  (12)    │(5)   │  (4)    │  (8)     │  (2)    │         │
├───────┼─────────┼──────────┼──────┼─────────┼──────────┼─────────┼─────────┤
│       │         │  T1190   │T1204 │  T1547  │  T1068   │  T1562  │         │
│       │         │  ██      │█     │  █      │  █       │  ██     │         │
│       │         │  (3)     │(1)   │  (2)    │  (1)     │  (3)    │         │
└───────┴─────────┴──────────┴──────┴─────────┴──────────┴─────────┴─────────┘

Legend: ████ = High frequency (>10)  ██ = Medium (3-10)  █ = Low (1-2)
```

**Features:**
- Cells colored gray→red based on alert count
- Click any cell to filter alerts by that technique
- Unknown techniques (from live data) added dynamically
- Sticky column headers for scrolling

### Manual Tagging Interface

Located in the triage sidebar below observables:

```
┌─────────────────────────────────────────┐
│  MITRE ATT&CK Techniques                │
├─────────────────────────────────────────┤
│  ┌────────────────────────────────────┐ │
│  │ T1110 - Brute Force (auto)        │ │
│  └────────────────────────────────────┘ │
│  ┌────────────────────────────────────┐ │
│  │ T1078 - Valid Accounts     [×]    │ │
│  └────────────────────────────────────┘ │
│                                         │
│  + Add Technique                        │
│  ┌──────────┐ ┌──────────────────────┐ │
│  │ T1078    │ │ Valid Accounts       │ │
│  └──────────┘ └──────────────────────┘ │
│  ┌────────────────────────┐ ┌───────┐  │
│  │ Defense Evasion    ▼   │ │ Add   │  │
│  └────────────────────────┘ └───────┘  │
└─────────────────────────────────────────┘
```

**Features:**
- Shows combined auto + manual techniques
- Remove button (×) only on manual tags
- Add form with ID input, name input, tactic dropdown
- Saves via PUT to triage endpoint

### Filtering by Technique

Filter alerts using:
1. **Heatmap click**: Click any technique cell
2. **Badge click**: Click technique badge on alert
3. **Search**: Type technique ID or name in search box

Clear filters using the existing "Clear Filter" button.

## Configuration

### Environment Variables

No additional configuration required. MITRE extraction uses existing Elasticsearch connection settings:

```bash
DOCFORGE_ELASTICSEARCH_ENABLED=true
DOCFORGE_ELASTICSEARCH_HOSTS=https://elasticsearch:9200
DOCFORGE_ELASTICSEARCH_USERNAME=elastic
DOCFORGE_ELASTICSEARCH_PASSWORD=changeme
```

### Database Migration

The `mitre_techniques` column is added automatically on server startup:

```sql
ALTER TABLE alert_triage ADD COLUMN mitre_techniques JSON
```

## Common Techniques Reference

### Initial Access (TA0001)
| ID | Name |
|----|------|
| T1566 | Phishing |
| T1190 | Exploit Public-Facing Application |
| T1133 | External Remote Services |
| T1078 | Valid Accounts |

### Execution (TA0002)
| ID | Name |
|----|------|
| T1059 | Command and Scripting Interpreter |
| T1204 | User Execution |
| T1053 | Scheduled Task/Job |

### Credential Access (TA0006)
| ID | Name |
|----|------|
| T1110 | Brute Force |
| T1003 | OS Credential Dumping |
| T1555 | Credentials from Password Stores |
| T1558 | Steal or Forge Kerberos Tickets |

### Defense Evasion (TA0005)
| ID | Name |
|----|------|
| T1070 | Indicator Removal |
| T1562 | Impair Defenses |
| T1055 | Process Injection |
| T1027 | Obfuscated Files or Information |

### Command and Control (TA0011)
| ID | Name |
|----|------|
| T1071 | Application Layer Protocol |
| T1105 | Ingress Tool Transfer |
| T1571 | Non-Standard Port |

## Troubleshooting

### MITRE Data Not Appearing on Alerts

1. **Check alert source data:**
   ```bash
   curl -X GET "localhost:9200/.alerts-*/_search" -H "Content-Type: application/json" -d '{
     "query": {"match_all": {}},
     "_source": ["threat.*", "signal.rule.threat"],
     "size": 1
   }'
   ```

2. **Verify field paths exist:**
   - ECS format: `threat.technique.id`, `threat.technique.name`, `threat.tactic.name`
   - SIEM format: `signal.rule.threat[0].technique[0].id`, etc.

3. **Check DocForge logs:**
   ```bash
   grep "mitre" /var/log/docforge/app.log
   ```

### Heatmap Not Loading

1. **Check API response:**
   ```bash
   curl http://localhost:8080/api/elasticsearch/alerts/mitre-stats?hours=24
   ```

2. **Verify alerts have MITRE data:**
   - At least some alerts must have `mitre_technique_id` populated
   - Check browser console for JavaScript errors

### Manual Tags Not Saving

1. **Verify technique ID format:**
   - Must match pattern `T####` or `T####.###`
   - Examples: `T1110`, `T1110.001`

2. **Check API response:**
   - Open browser DevTools → Network tab
   - Look for PUT request to `/api/elasticsearch/alerts/{id}/triage`
   - Check response for validation errors

### Migration Errors

If the `mitre_techniques` column wasn't added:

```bash
# Check column exists
sqlite3 docforge.db ".schema alert_triage"

# Manual migration if needed
sqlite3 docforge.db "ALTER TABLE alert_triage ADD COLUMN mitre_techniques JSON"
```

## Best Practices

### For Detection Engineers

1. **Include MITRE mappings in detection rules:**
   ```yaml
   rule:
     name: "Brute Force SSH Login"
     threat:
       - technique:
           id: T1110
           name: Brute Force
         tactic:
           name: Credential Access
   ```

2. **Use sub-techniques for specificity:**
   - `T1110.001` (Password Guessing) vs `T1110.003` (Password Spraying)
   - Enables more precise analytics

### For Analysts

1. **Add manual tags for:**
   - Techniques discovered during investigation
   - Related techniques not in original alert
   - Sub-techniques when base technique is auto-detected

2. **Use heatmap to identify:**
   - Attack patterns across alerts
   - Gaps in detection coverage
   - Trending techniques

3. **Filter workflow:**
   - Click heatmap cell to focus on technique
   - Review all related alerts
   - Identify patterns or campaigns

## Security Considerations

1. **Access Control**: MITRE tagging requires triage permissions
2. **Audit Trail**: Tag changes are logged with user attribution
3. **Data Integrity**: Technique IDs are validated before storage
4. **No External Calls**: MITRE data is embedded, no external API dependencies

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [Elastic Common Schema - Threat Fields](https://www.elastic.co/guide/en/ecs/current/ecs-threat.html)
- [Elastic Security Detection Rules](https://github.com/elastic/detection-rules)
