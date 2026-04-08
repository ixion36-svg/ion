# ION MITRE ATT&CK Integration

**Version:** 0.9.43

## Overview

ION integrates MITRE ATT&CK across multiple features:

### Alert Triage
- Alerts from Elasticsearch include `threat.technique.id`, `threat.technique.name`, `threat.tactic.name`
- MITRE technique pills displayed on alert detail panels
- Attack Stories auto-map alerts to kill chain phases

### Detection Engineering (TIDE)
- TIDE rules are mapped to MITRE techniques via `mitre_ids` arrays
- Posture tab shows coverage: 142/159 techniques covered
- Gaps tab identifies blind spots by tactic
- Actor Readiness cross-references OpenCTI actor TTPs with TIDE rule coverage

### MITRE Navigator Export
- One-click export of TIDE coverage as ATT&CK Navigator v4.x layer JSON
- Endpoint: `GET /api/mitre-navigator/layer`
- Color-coded: green (4+ rules), yellow (1-3 rules), red (no coverage)
- Open the downloaded `.json` in [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)

### Compliance Mapping
- TIDE rules mapped to 13 NIST CSF controls via technique IDs
- Endpoint: `GET /api/compliance/nist`
- Per-control coverage scores (0-100%)

### Training Simulator
- 8 training scenarios reference specific MITRE techniques
- Analysts learn to identify T1566 (Phishing), T1003 (Credential Dumping), T1558 (Kerberoasting), T1484 (GPO Modification), etc.

## Configuration

MITRE integration is automatic — no additional configuration needed. It works through:
1. **Elasticsearch**: alerts with `threat.*` ECS fields
2. **TIDE**: rules with `mitre_ids` arrays
3. **OpenCTI**: threat actor TTP relationships

## Sub-Technique Handling

ES alerts may store sub-techniques (e.g., `T1003.001`) while TIDE rules use parent techniques (`T1003`). ION handles this with parent/sub matching:
- ES query: `term` + `prefix` matching
- Python: `alert_tid.startswith(tid + ".")` or `tid.startswith(alert_tid + ".")`
