"""Role-based skills questionnaire service.

Each "career role" (L1/L2/L3 SOC Analyst, SOC Engineer, Threat Hunter)
ships with a competency questionnaire heavily biased toward the Elastic
stack — KQL, EQL, Elastic Security rules, Kibana, Fleet/Beats — because
that's the SIEM ION is built around. A user picks a role, rates themselves
1-5 against each question, and the service computes per-area scores plus
an overall match percentage. Results feed three downstream things:

  1. Recommended Knowledge Base articles (matched by capability_key)
  2. Recommended training-sim scenarios (matched by role tier + gap area)
  3. AI tutor narrative via Ollama (personalised study plan)

Static content lives in ROLE_DEFINITIONS so it's version-controlled in
git and reviewable in PRs. Promote to a DB-backed admin UI later if
content needs to be edited frequently.

Scoring scale (one shared rubric across all questions):
  1 = "Never heard of it / never done it"
  2 = "Aware of it / can describe at a high level"
  3 = "Can do it with reference material / supervised"
  4 = "Confident and independent"
  5 = "Could teach it / set the standard"
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from ion.models.skills import KnowledgeArticle, RoleAssessment, UserCareerGoal

logger = logging.getLogger(__name__)


# =========================================================================
# Role definitions
# =========================================================================
#
# Each role:
#   id            slug used as role_id on RoleAssessment
#   name          display name
#   tier          T1/T2/T3/T4 — used to match training sim scenarios
#   description   one-line summary
#   areas         list of competency areas; each area has 5 questions
#   sim_tags      list of strings used to surface relevant sim scenarios
#
# Each question:
#   id            stable string id within the area
#   text          the question (must be a self-rateable competency)
#   guidance      what level-5 looks like — sets the bar
#   capability_key (optional) — links to KnowledgeArticle.capability_key for
#                              recommendation lookup when score is low
# =========================================================================

ROLE_DEFINITIONS: List[Dict[str, Any]] = [
    {
        "id": "l1_soc_analyst",
        "name": "L1 SOC Analyst",
        "tier": "T1",
        "description": "Front-line analyst — alert triage, basic investigation, escalation.",
        "sim_tags": ["l1", "triage", "phishing", "malware-basic"],
        "areas": [
            {
                "id": "elastic_alerts",
                "name": "Elastic Security Alerts",
                "questions": [
                    {
                        "id": "a1",
                        "text": "Open the Elastic Security alerts page, filter by severity 'high', and identify alerts assigned to you",
                        "guidance": "Level 5: knows the workflow_status field, filters by KQL, can save a view as the default queue",
                        "capability_key": "alert_triage",
                    },
                    {
                        "id": "a2",
                        "text": "Acknowledge an alert and add a comment that explains your initial assessment",
                        "guidance": "Level 5: comments capture observables, hypothesis, next steps in standard format",
                        "capability_key": "alert_triage",
                    },
                    {
                        "id": "a3",
                        "text": "Identify whether an alert maps to a MITRE ATT&CK technique and read the threat.technique fields",
                        "guidance": "Level 5: navigates to the MITRE matrix view, understands tactic vs technique vs sub-technique",
                        "capability_key": "mitre_attack",
                    },
                    {
                        "id": "a4",
                        "text": "Tell the difference between a true positive, false positive, and benign true positive",
                        "guidance": "Level 5: applies the right closure_reason every time and documents reasoning",
                        "capability_key": "alert_triage",
                    },
                    {
                        "id": "a5",
                        "text": "Locate the source rule for an alert in the Elastic Security rules library",
                        "guidance": "Level 5: opens the rule, reads the query, understands threshold/indicator/eql rule types",
                        "capability_key": "detection_rules",
                    },
                ],
            },
            {
                "id": "kql_basics",
                "name": "Basic KQL",
                "questions": [
                    {
                        "id": "k1",
                        "text": "Write a KQL query that filters alerts by host name and severity",
                        "guidance": "Level 5: uses field shortcuts, knows when to quote values, handles wildcards correctly",
                        "capability_key": "kql_basics",
                    },
                    {
                        "id": "k2",
                        "text": "Use boolean operators (and, or, not) to combine filter clauses",
                        "guidance": "Level 5: explains operator precedence and uses parentheses correctly",
                        "capability_key": "kql_basics",
                    },
                    {
                        "id": "k3",
                        "text": "Filter on nested fields (e.g. user.name, host.os.family)",
                        "guidance": "Level 5: navigates ECS field structure confidently",
                        "capability_key": "ecs_schema",
                    },
                    {
                        "id": "k4",
                        "text": "Use the 'exists' operator to filter for documents containing a specific field",
                        "guidance": "Level 5: knows the difference between missing field and empty value",
                        "capability_key": "kql_basics",
                    },
                    {
                        "id": "k5",
                        "text": "Save a Discover query as a saved search and share it with the team",
                        "guidance": "Level 5: organises saved searches by use case, knows the access controls",
                        "capability_key": "kibana_basics",
                    },
                ],
            },
            {
                "id": "triage_workflow",
                "name": "Alert Triage Workflow",
                "questions": [
                    {
                        "id": "t1",
                        "text": "Identify the observables in an alert (IPs, hashes, domains, users, hosts) and record them",
                        "guidance": "Level 5: extracts every observable type and records to ION's observables UI",
                        "capability_key": "observable_extraction",
                    },
                    {
                        "id": "t2",
                        "text": "Decide whether an alert needs escalation and to which tier",
                        "guidance": "Level 5: applies the escalation matrix consistently and documents the decision",
                        "capability_key": "escalation",
                    },
                    {
                        "id": "t3",
                        "text": "Create a case in Elastic Security or ION linking related alerts",
                        "guidance": "Level 5: groups multi-alert cases sensibly, sets severity, assigns ownership",
                        "capability_key": "case_management",
                    },
                    {
                        "id": "t4",
                        "text": "Run an enrichment lookup against an IOC (IP, domain, hash) using OpenCTI/VirusTotal",
                        "guidance": "Level 5: interprets enrichment results, knows when threat intel is stale",
                        "capability_key": "ioc_enrichment",
                    },
                    {
                        "id": "t5",
                        "text": "Hand off an investigation cleanly at shift change with all context captured",
                        "guidance": "Level 5: handover note covers state, blockers, next actions, and analyst-of-record",
                        "capability_key": "shift_handover",
                    },
                ],
            },
            {
                "id": "soc_fundamentals",
                "name": "SOC Fundamentals",
                "questions": [
                    {
                        "id": "f1",
                        "text": "Explain the cyber kill chain stages and which Elastic detections you'd expect at each",
                        "guidance": "Level 5: maps real alerts to kill chain stages and uses it to prioritise",
                        "capability_key": "kill_chain",
                    },
                    {
                        "id": "f2",
                        "text": "Explain the NIST 800-61 incident response phases (prepare/detect/contain/eradicate/recover/lessons)",
                        "guidance": "Level 5: knows the SOC's role in each phase",
                        "capability_key": "ir_lifecycle",
                    },
                    {
                        "id": "f3",
                        "text": "Recognise common alert noise sources (vuln scanners, admin tools, misconfigs) and triage them quickly",
                        "guidance": "Level 5: maintains a personal mental list of known-noisy rules with notes",
                        "capability_key": "noise_management",
                    },
                    {
                        "id": "f4",
                        "text": "Explain what an indicator of compromise (IOC) is and the pyramid of pain",
                        "guidance": "Level 5: explains why hashes are easy to evade and why TTPs are not",
                        "capability_key": "ioc_basics",
                    },
                    {
                        "id": "f5",
                        "text": "Describe what data Elastic Agent / Beats collect and where it lands",
                        "guidance": "Level 5: knows endpoint vs winlogbeat vs filebeat and the index naming convention",
                        "capability_key": "elastic_data_sources",
                    },
                ],
            },
        ],
    },

    {
        "id": "l2_soc_analyst",
        "name": "L2 SOC Analyst",
        "tier": "T2",
        "description": "Investigation lead — case ownership, intermediate hunting, rule tuning.",
        "sim_tags": ["l2", "case", "lateral-movement", "credential-access"],
        "areas": [
            {
                "id": "case_management",
                "name": "Case Management",
                "questions": [
                    {
                        "id": "c1",
                        "text": "Build a case timeline that captures the full attack chain across multiple alerts",
                        "guidance": "Level 5: orders events by source timestamp, calls out gaps and pivots",
                        "capability_key": "case_management",
                    },
                    {
                        "id": "c2",
                        "text": "Decide when to merge cases and when to keep them separate",
                        "guidance": "Level 5: applies a consistent rule (same actor / campaign / asset)",
                        "capability_key": "case_management",
                    },
                    {
                        "id": "c3",
                        "text": "Drive a case to closure with the correct closure reason and full evidence summary",
                        "guidance": "Level 5: closure note is reusable as a stand-alone incident report",
                        "capability_key": "case_closure",
                    },
                    {
                        "id": "c4",
                        "text": "Run a post-incident review (PIR) and capture lessons learned",
                        "guidance": "Level 5: PIR action items have owners, dates, and tracked completion",
                        "capability_key": "pir",
                    },
                    {
                        "id": "c5",
                        "text": "Communicate case status to stakeholders without using SOC jargon",
                        "guidance": "Level 5: tailors the message to exec, IT, legal, customer audiences",
                        "capability_key": "stakeholder_comms",
                    },
                ],
            },
            {
                "id": "kql_eql_intermediate",
                "name": "Intermediate KQL & EQL",
                "questions": [
                    {
                        "id": "q1",
                        "text": "Write an EQL sequence query that matches process spawned by another process within 5 seconds",
                        "guidance": "Level 5: uses sequence with maxspan, joins on relevant fields, handles ordering",
                        "capability_key": "eql_sequences",
                    },
                    {
                        "id": "q2",
                        "text": "Use Elastic ES|QL or Lens to aggregate alerts by rule and severity over a time window",
                        "guidance": "Level 5: builds the same view in three ways (Discover, Lens, ES|QL) and explains tradeoffs",
                        "capability_key": "esql_lens",
                    },
                    {
                        "id": "q3",
                        "text": "Write a KQL query that excludes known false-positive hosts using a wildcard or list",
                        "guidance": "Level 5: knows when to use exception lists vs query exclusions vs index-time filters",
                        "capability_key": "fp_management",
                    },
                    {
                        "id": "q4",
                        "text": "Pivot from an alert to all related events for the same host within ±15 minutes",
                        "guidance": "Level 5: builds a reusable Discover view and saves it",
                        "capability_key": "investigation_pivots",
                    },
                    {
                        "id": "q5",
                        "text": "Use Lucene query syntax when KQL falls short (regex, fuzzy)",
                        "guidance": "Level 5: knows which features each language supports and switches deliberately",
                        "capability_key": "lucene",
                    },
                ],
            },
            {
                "id": "rule_tuning",
                "name": "Detection Rule Tuning",
                "questions": [
                    {
                        "id": "r1",
                        "text": "Add an exception to a noisy Elastic Security rule without disabling it entirely",
                        "guidance": "Level 5: scopes the exception narrowly, documents the rationale, schedules review",
                        "capability_key": "rule_tuning",
                    },
                    {
                        "id": "r2",
                        "text": "Recognise when a rule's threshold is wrong and propose the right value",
                        "guidance": "Level 5: backs the proposal with a query showing distribution",
                        "capability_key": "rule_tuning",
                    },
                    {
                        "id": "r3",
                        "text": "Distinguish between rule severity, alert severity, and risk score",
                        "guidance": "Level 5: explains how Elastic computes risk score and when to override",
                        "capability_key": "risk_scoring",
                    },
                    {
                        "id": "r4",
                        "text": "Read a rule's index pattern and understand which data sources it depends on",
                        "guidance": "Level 5: predicts blast radius of disabling a data source on rule coverage",
                        "capability_key": "rule_dependencies",
                    },
                    {
                        "id": "r5",
                        "text": "Test a rule change in a non-prod space before promoting to production",
                        "guidance": "Level 5: maintains a test space with realistic data and uses it",
                        "capability_key": "rule_testing",
                    },
                ],
            },
            {
                "id": "ioc_enrichment",
                "name": "IOC Enrichment & Threat Intel",
                "questions": [
                    {
                        "id": "i1",
                        "text": "Enrich an IP/domain/hash in OpenCTI and interpret the relationships graph",
                        "guidance": "Level 5: traces actor → campaign → TTP → indicator and uses it for context",
                        "capability_key": "opencti",
                    },
                    {
                        "id": "i2",
                        "text": "Decide whether a public threat intel feed is reliable enough to act on",
                        "guidance": "Level 5: evaluates source, age, false-positive rate, attribution confidence",
                        "capability_key": "ti_evaluation",
                    },
                    {
                        "id": "i3",
                        "text": "Add an observable to a watchlist so future sightings auto-alert",
                        "guidance": "Level 5: knows ION's observables + Elastic indicator match rules",
                        "capability_key": "watchlists",
                    },
                    {
                        "id": "i4",
                        "text": "Correlate Elastic alerts with VirusTotal / OTX / abuse.ch results",
                        "guidance": "Level 5: integrates enrichment into case notes routinely",
                        "capability_key": "external_enrichment",
                    },
                    {
                        "id": "i5",
                        "text": "Recognise stale indicators that should be removed from active watchlists",
                        "guidance": "Level 5: enforces a deprecation cadence on the watchlist",
                        "capability_key": "ioc_lifecycle",
                    },
                ],
            },
        ],
    },

    {
        "id": "l3_soc_analyst",
        "name": "L3 SOC Analyst",
        "tier": "T3",
        "description": "Senior analyst — threat hunting, custom rules, attack chain reconstruction.",
        "sim_tags": ["l3", "hunting", "advanced-persistent", "forensic-light"],
        "areas": [
            {
                "id": "threat_hunting",
                "name": "Threat Hunting",
                "questions": [
                    {
                        "id": "h1",
                        "text": "Formulate a hunting hypothesis from a recent threat intel report",
                        "guidance": "Level 5: hypothesis is testable, scoped, and tied to specific TTPs",
                        "capability_key": "hunt_hypothesis",
                    },
                    {
                        "id": "h2",
                        "text": "Run a hypothesis-driven hunt in Elastic using KQL/EQL/ES|QL",
                        "guidance": "Level 5: documents query, expected vs actual results, and disposition",
                        "capability_key": "hunt_execution",
                    },
                    {
                        "id": "h3",
                        "text": "Decide whether a hunt finding becomes an alert, a case, or just a hunt note",
                        "guidance": "Level 5: knows when to promote to detection rule and when to defer",
                        "capability_key": "hunt_disposition",
                    },
                    {
                        "id": "h4",
                        "text": "Track hunt coverage against the MITRE ATT&CK matrix to find blind spots",
                        "guidance": "Level 5: maintains a coverage map and prioritises gaps by actor relevance",
                        "capability_key": "attack_coverage",
                    },
                    {
                        "id": "h5",
                        "text": "Lead a structured hunting sprint and capture the team's findings",
                        "guidance": "Level 5: runs the sprint with a charter, hunt log, and retro",
                        "capability_key": "hunt_program",
                    },
                ],
            },
            {
                "id": "custom_rules",
                "name": "Custom Detection Rules",
                "questions": [
                    {
                        "id": "cr1",
                        "text": "Author a new EQL rule from scratch that detects a specific TTP",
                        "guidance": "Level 5: rule is high-fidelity, well-named, has investigation guide and false-positive notes",
                        "capability_key": "rule_authoring",
                    },
                    {
                        "id": "cr2",
                        "text": "Convert a Sigma rule into an Elastic Security rule",
                        "guidance": "Level 5: knows the field mapping pitfalls and validates the result",
                        "capability_key": "sigma_conversion",
                    },
                    {
                        "id": "cr3",
                        "text": "Use Elastic indicator match rules to alert on watchlist hits",
                        "guidance": "Level 5: handles index size carefully, knows performance constraints",
                        "capability_key": "indicator_match",
                    },
                    {
                        "id": "cr4",
                        "text": "Build a threshold rule that catches brute-force or beaconing patterns",
                        "guidance": "Level 5: tunes window + threshold + cardinality together",
                        "capability_key": "threshold_rules",
                    },
                    {
                        "id": "cr5",
                        "text": "Version-control rule changes via export/import or detection-as-code",
                        "guidance": "Level 5: rules live in git with code review",
                        "capability_key": "detection_as_code",
                    },
                ],
            },
            {
                "id": "attack_chain",
                "name": "Attack Chain Reconstruction",
                "questions": [
                    {
                        "id": "ac1",
                        "text": "Reconstruct the timeline of a multi-host intrusion using winlogbeat + endpoint data",
                        "guidance": "Level 5: produces a single timeline correlating process, network, file events",
                        "capability_key": "timeline_reconstruction",
                    },
                    {
                        "id": "ac2",
                        "text": "Identify lateral movement using authentication logs and network telemetry",
                        "guidance": "Level 5: knows the typical ports, tools, and ECS fields involved",
                        "capability_key": "lateral_movement",
                    },
                    {
                        "id": "ac3",
                        "text": "Identify persistence mechanisms (services, scheduled tasks, registry, cron, autostart)",
                        "guidance": "Level 5: knows the ECS fields and Sysmon event ids that capture each",
                        "capability_key": "persistence",
                    },
                    {
                        "id": "ac4",
                        "text": "Identify exfiltration over DNS, HTTPS, or cloud storage",
                        "guidance": "Level 5: spots beaconing patterns and unusual data volumes",
                        "capability_key": "exfiltration",
                    },
                    {
                        "id": "ac5",
                        "text": "Map a reconstructed chain back to MITRE ATT&CK and produce a kill-chain diagram",
                        "guidance": "Level 5: diagram is publishable in the incident report",
                        "capability_key": "attack_mapping",
                    },
                ],
            },
            {
                "id": "rca_forensics",
                "name": "Root Cause & Forensic Awareness",
                "questions": [
                    {
                        "id": "f1",
                        "text": "Determine the root cause of a confirmed compromise (initial access vector)",
                        "guidance": "Level 5: rules out alternatives with evidence, not assumption",
                        "capability_key": "root_cause",
                    },
                    {
                        "id": "f2",
                        "text": "Decide which artefacts to preserve before they age out (volatile vs persistent)",
                        "guidance": "Level 5: prioritises memory, recent files, network state, in that order",
                        "capability_key": "evidence_preservation",
                    },
                    {
                        "id": "f3",
                        "text": "Triage a suspicious binary safely (sandbox, hash search, strings, behaviour)",
                        "guidance": "Level 5: never executes unknown files outside isolation",
                        "capability_key": "malware_triage",
                    },
                    {
                        "id": "f4",
                        "text": "Hand off to a forensic team with proper chain of custody",
                        "guidance": "Level 5: knows the legal-defensibility implications of each step",
                        "capability_key": "chain_of_custody",
                    },
                    {
                        "id": "f5",
                        "text": "Recognise when an incident needs external IR support and call it in early",
                        "guidance": "Level 5: doesn't delay escalation to protect personal pride",
                        "capability_key": "external_ir",
                    },
                ],
            },
        ],
    },

    {
        "id": "soc_engineer",
        "name": "SOC Engineer",
        "tier": "T3",
        "description": "Pipeline + platform owner — Elastic admin, ingest, integrations, rule lifecycle.",
        "sim_tags": ["engineering", "ingest", "rule-lifecycle", "elastic-admin"],
        "areas": [
            {
                "id": "elastic_admin",
                "name": "Elasticsearch Administration",
                "questions": [
                    {
                        "id": "e1",
                        "text": "Read cluster health and identify yellow / red index issues",
                        "guidance": "Level 5: diagnoses unassigned shards from the allocation API",
                        "capability_key": "cluster_health",
                    },
                    {
                        "id": "e2",
                        "text": "Configure ILM (Index Lifecycle Management) policies for hot/warm/cold/delete",
                        "guidance": "Level 5: balances retention cost vs query latency vs alerting needs",
                        "capability_key": "ilm",
                    },
                    {
                        "id": "e3",
                        "text": "Right-size shards for a given data volume and query pattern",
                        "guidance": "Level 5: applies Elastic's shard sizing guidance and measures it",
                        "capability_key": "shard_sizing",
                    },
                    {
                        "id": "e4",
                        "text": "Manage Elastic users, roles, spaces, and field-level security",
                        "guidance": "Level 5: maps Kibana spaces to SOC tenants/customers cleanly",
                        "capability_key": "elastic_rbac",
                    },
                    {
                        "id": "e5",
                        "text": "Snapshot and restore an index using the snapshot lifecycle policy",
                        "guidance": "Level 5: tests the restore path quarterly",
                        "capability_key": "snapshot_restore",
                    },
                ],
            },
            {
                "id": "ingest_pipelines",
                "name": "Ingest Pipelines & Beats / Agent",
                "questions": [
                    {
                        "id": "ip1",
                        "text": "Onboard a new log source via Elastic Agent + an integration",
                        "guidance": "Level 5: validates the source, tags the data, monitors ingest lag",
                        "capability_key": "log_onboarding",
                    },
                    {
                        "id": "ip2",
                        "text": "Write or modify an ingest pipeline to enrich or normalise documents",
                        "guidance": "Level 5: uses simulate API, handles failures with on_failure processors",
                        "capability_key": "ingest_pipeline",
                    },
                    {
                        "id": "ip3",
                        "text": "Diagnose why an Elastic Agent is dropping events or out of sync",
                        "guidance": "Level 5: reads agent logs + Fleet status + diagnostics bundle",
                        "capability_key": "fleet_diagnostics",
                    },
                    {
                        "id": "ip4",
                        "text": "Map a custom data source into ECS-compliant fields",
                        "guidance": "Level 5: knows the canonical ECS field for each common log shape",
                        "capability_key": "ecs_mapping",
                    },
                    {
                        "id": "ip5",
                        "text": "Set up dead letter queues or rejection handling for malformed documents",
                        "guidance": "Level 5: monitors rejection rates and acts on them",
                        "capability_key": "dlq",
                    },
                ],
            },
            {
                "id": "rule_lifecycle",
                "name": "Detection Rule Lifecycle",
                "questions": [
                    {
                        "id": "rl1",
                        "text": "Manage detection rules in git via the Elastic Detection Rules repo or detection-as-code",
                        "guidance": "Level 5: rules ship via PR with tests and deploy automatically",
                        "capability_key": "detection_as_code",
                    },
                    {
                        "id": "rl2",
                        "text": "Run a rule against historical data to estimate alert volume before enabling",
                        "guidance": "Level 5: backtests with the preview API and documents the result",
                        "capability_key": "rule_backtesting",
                    },
                    {
                        "id": "rl3",
                        "text": "Set up rule-quality metrics (true-positive rate, time-to-disposition)",
                        "guidance": "Level 5: dashboards them and reviews monthly",
                        "capability_key": "rule_metrics",
                    },
                    {
                        "id": "rl4",
                        "text": "Retire a rule that's no longer providing value without losing audit trail",
                        "guidance": "Level 5: archives the rule definition and documents why",
                        "capability_key": "rule_retirement",
                    },
                    {
                        "id": "rl5",
                        "text": "Review and merge rule changes from other engineers",
                        "guidance": "Level 5: provides constructive feedback and catches regressions",
                        "capability_key": "rule_review",
                    },
                ],
            },
            {
                "id": "integrations",
                "name": "Alert Routing & Integrations",
                "questions": [
                    {
                        "id": "in1",
                        "text": "Wire Elastic Security to a downstream SOAR / case system via connectors",
                        "guidance": "Level 5: handles auth refresh, retries, idempotency",
                        "capability_key": "soar_integration",
                    },
                    {
                        "id": "in2",
                        "text": "Configure connector actions (Slack, email, PagerDuty, Jira) on rule actions",
                        "guidance": "Level 5: tunes severity filters so connectors don't spam",
                        "capability_key": "connector_actions",
                    },
                    {
                        "id": "in3",
                        "text": "Sync alert workflow_status and assignee bidirectionally with a downstream system",
                        "guidance": "Level 5: handles version conflicts and reconciliation",
                        "capability_key": "case_sync",
                    },
                    {
                        "id": "in4",
                        "text": "Enable and tune Elastic ML jobs (anomaly detection)",
                        "guidance": "Level 5: knows when ML is overkill and when it earns its cost",
                        "capability_key": "elastic_ml",
                    },
                    {
                        "id": "in5",
                        "text": "Build a Kibana dashboard for an audience (SOC manager, exec, customer) and ship it",
                        "guidance": "Level 5: dashboard answers a specific question and is signed off",
                        "capability_key": "dashboarding",
                    },
                ],
            },
        ],
    },

    {
        "id": "threat_hunter",
        "name": "Threat Hunter",
        "tier": "T4",
        "description": "Proactive hunter — KQL/EQL mastery, ATT&CK alignment, anomaly modelling.",
        "sim_tags": ["hunting", "advanced", "ml", "anomaly"],
        "areas": [
            {
                "id": "hunt_methodology",
                "name": "Hunt Methodology",
                "questions": [
                    {
                        "id": "m1",
                        "text": "Run a structured hunt using the TaHiTI or PEAK methodology",
                        "guidance": "Level 5: produces a hunt report ready for peer review",
                        "capability_key": "hunt_methodology",
                    },
                    {
                        "id": "m2",
                        "text": "Tie a hunt to a specific intelligence requirement or business risk",
                        "guidance": "Level 5: never runs hunts that nobody will action",
                        "capability_key": "intel_requirements",
                    },
                    {
                        "id": "m3",
                        "text": "Apply structured analytic techniques (analysis of competing hypotheses, devil's advocacy)",
                        "guidance": "Level 5: surfaces alternate hypotheses before chasing the obvious one",
                        "capability_key": "analytic_techniques",
                    },
                    {
                        "id": "m4",
                        "text": "Capture every hunt — successful or null result — in a hunt log",
                        "guidance": "Level 5: maintains a searchable hunt library that gets reused",
                        "capability_key": "hunt_log",
                    },
                    {
                        "id": "m5",
                        "text": "Promote a successful hunt query into a production detection rule",
                        "guidance": "Level 5: hands off to engineering with backtest results and FP estimates",
                        "capability_key": "hunt_to_rule",
                    },
                ],
            },
            {
                "id": "advanced_query",
                "name": "Advanced KQL / EQL / ES|QL",
                "questions": [
                    {
                        "id": "aq1",
                        "text": "Write a multi-stage EQL sequence detecting a known attack chain (e.g. macro → spawn → cmd → outbound)",
                        "guidance": "Level 5: minimal false positives, scoped to the right index pattern",
                        "capability_key": "eql_advanced",
                    },
                    {
                        "id": "aq2",
                        "text": "Use ES|QL to perform stats aggregations and joins in a single query",
                        "guidance": "Level 5: prefers ES|QL where it's faster than KQL+Lens",
                        "capability_key": "esql_advanced",
                    },
                    {
                        "id": "aq3",
                        "text": "Use rare/uncommon process or beacon detection via cardinality + bucket aggregations",
                        "guidance": "Level 5: builds reusable rarity hunts saved for periodic re-run",
                        "capability_key": "rarity_hunting",
                    },
                    {
                        "id": "aq4",
                        "text": "Cross-index correlation — hunt across endpoint + network + auth in one query",
                        "guidance": "Level 5: knows when to use enrich processors vs runtime fields vs joins",
                        "capability_key": "cross_index",
                    },
                    {
                        "id": "aq5",
                        "text": "Profile the cost of a hunt query and avoid hammering the cluster",
                        "guidance": "Level 5: uses profile API and reads the explain output",
                        "capability_key": "query_profiling",
                    },
                ],
            },
            {
                "id": "attack_coverage",
                "name": "ATT&CK Coverage",
                "questions": [
                    {
                        "id": "ck1",
                        "text": "Map the team's detection coverage against MITRE ATT&CK and identify priority gaps",
                        "guidance": "Level 5: maintains a Navigator layer and reviews quarterly",
                        "capability_key": "navigator_coverage",
                    },
                    {
                        "id": "ck2",
                        "text": "Run an Atomic Red Team test for a specific technique and verify detection fired",
                        "guidance": "Level 5: tests are documented, repeatable, and audit-trail complete",
                        "capability_key": "atomic_red_team",
                    },
                    {
                        "id": "ck3",
                        "text": "Use OpenCTI / threat intel to prioritise which techniques are relevant for your sector",
                        "guidance": "Level 5: actor-prioritised coverage, not blind matrix-filling",
                        "capability_key": "actor_prioritisation",
                    },
                    {
                        "id": "ck4",
                        "text": "Distinguish between coverage of a technique and DETECTION of a technique",
                        "guidance": "Level 5: validates that the rule actually fires, not just that the field exists",
                        "capability_key": "coverage_validation",
                    },
                    {
                        "id": "ck5",
                        "text": "Lead a purple team exercise from hypothesis through detection improvement",
                        "guidance": "Level 5: drives the loop end-to-end and produces measurable lift",
                        "capability_key": "purple_team",
                    },
                ],
            },
            {
                "id": "anomaly_detection",
                "name": "Anomaly & Behavioural Detection",
                "questions": [
                    {
                        "id": "an1",
                        "text": "Configure an Elastic ML anomaly detection job for user/host behaviour",
                        "guidance": "Level 5: picks the right function, partition, bucket span; explains the result",
                        "capability_key": "elastic_ml",
                    },
                    {
                        "id": "an2",
                        "text": "Distinguish between a true behavioural anomaly and seasonal noise",
                        "guidance": "Level 5: builds in calendar / multi-bucket awareness",
                        "capability_key": "anomaly_interpretation",
                    },
                    {
                        "id": "an3",
                        "text": "Build a baseline of 'normal' for a high-value asset and alert on drift",
                        "guidance": "Level 5: baseline is reviewed and updated as the asset changes",
                        "capability_key": "baselining",
                    },
                    {
                        "id": "an4",
                        "text": "Correlate ML anomalies with rule-based detections to reduce noise",
                        "guidance": "Level 5: uses ML as a pivot, not a primary alert source",
                        "capability_key": "ml_correlation",
                    },
                    {
                        "id": "an5",
                        "text": "Recognise when ML/anomaly is the wrong tool and a deterministic rule is better",
                        "guidance": "Level 5: doesn't throw ML at every problem",
                        "capability_key": "tool_selection",
                    },
                ],
            },
        ],
    },
]


# =========================================================================
# Public questionnaire API
# =========================================================================

def get_role_definitions() -> Dict[str, Any]:
    """Return all role definitions for the picker + questionnaire UI.

    Includes a denormalised question count per role so the UI can show
    "5 sections / 25 questions / ~10 min" up front.
    """
    out_roles = []
    for role in ROLE_DEFINITIONS:
        q_count = sum(len(a["questions"]) for a in role["areas"])
        out_roles.append({
            **role,
            "question_count": q_count,
            "area_count": len(role["areas"]),
        })
    return {
        "roles": out_roles,
        "rating_scale": [
            {"value": 1, "label": "Never heard of it"},
            {"value": 2, "label": "Aware of it"},
            {"value": 3, "label": "Can do it supervised"},
            {"value": 4, "label": "Confident & independent"},
            {"value": 5, "label": "Could teach it"},
        ],
    }


def _find_role(role_id: str) -> Optional[Dict[str, Any]]:
    for role in ROLE_DEFINITIONS:
        if role["id"] == role_id:
            return role
    return None


# =========================================================================
# Scoring
# =========================================================================

def _score_responses(role: Dict[str, Any], responses: Dict[str, Any]) -> Dict[str, Any]:
    """Compute per-area + overall scores from the user's raw responses.

    Returns a dict matching RoleAssessment.scores shape.
    """
    area_scores: Dict[str, Any] = {}
    total = 0
    max_total = 0

    for area in role["areas"]:
        area_responses = responses.get(area["id"], {}) or {}
        area_total = 0
        area_max = 0
        for q in area["questions"]:
            raw = area_responses.get(q["id"], 1)
            try:
                rating = int(raw)
            except (TypeError, ValueError):
                rating = 1
            rating = max(1, min(5, rating))
            area_total += rating
            area_max += 5
        avg = round(area_total / len(area["questions"]), 2) if area["questions"] else 0
        pct = round((area_total / area_max) * 100) if area_max else 0
        area_scores[area["id"]] = {
            "name": area["name"],
            "total": area_total,
            "max": area_max,
            "avg": avg,
            "pct": pct,
        }
        total += area_total
        max_total += area_max

    overall_pct = round((total / max_total) * 100) if max_total else 0
    return {
        "areas": area_scores,
        "overall_total": total,
        "overall_max": max_total,
        "overall_pct": overall_pct,
    }


def _level_for_pct(pct: int) -> str:
    if pct >= 85:
        return "Expert"
    if pct >= 70:
        return "Proficient"
    if pct >= 55:
        return "Capable"
    if pct >= 40:
        return "Developing"
    return "Foundational"


# =========================================================================
# Recommendations: KB + sim + AI
# =========================================================================

# Threshold below which an area is considered a "gap" worth recommending
# remedial content for. Tuned so a fresh L1 with all 3s doesn't trigger
# everything, but a clear weak spot does.
_GAP_PCT_THRESHOLD = 60


def _gap_areas(role: Dict[str, Any], scores: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for area in role["areas"]:
        a_score = scores["areas"].get(area["id"], {})
        if a_score.get("pct", 100) < _GAP_PCT_THRESHOLD:
            out.append({"area": area, "score": a_score})
    out.sort(key=lambda x: x["score"].get("pct", 0))
    return out


def _strength_areas(role: Dict[str, Any], scores: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for area in role["areas"]:
        a_score = scores["areas"].get(area["id"], {})
        if a_score.get("pct", 0) >= 80:
            out.append({"area_id": area["id"], "name": area["name"], "pct": a_score["pct"]})
    return out


def _kb_recommendations(
    session: Session, gap_areas: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Find Knowledge Base capabilities that match the gap areas' question keys.

    KnowledgeArticle stores rows by capability_key (one row per capability).
    Each questionnaire question may carry an optional capability_key — we
    collect those from the GAP areas only and look them up.
    """
    capability_keys: List[str] = []
    seen = set()
    for gap in gap_areas:
        for q in gap["area"]["questions"]:
            ck = q.get("capability_key")
            if ck and ck not in seen:
                seen.add(ck)
                capability_keys.append(ck)
    if not capability_keys:
        return []

    rows = (
        session.query(KnowledgeArticle)
        .filter(KnowledgeArticle.capability_key.in_(capability_keys))
        .all()
    )
    return [
        {
            "capability_key": r.capability_key,
            "doc_status": r.doc_status,
            "has_runbooks": r.has_runbooks,
            "has_procedures": r.has_procedures,
            "spof_risk": r.spof_risk,
        }
        for r in rows
    ]


def _sim_recommendations(role: Dict[str, Any], gap_areas: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Pull training-sim scenarios that match the role's tier + sim_tags.

    Lazy-imported because the sim service is optional in some deployments
    and pulls heavy fixture data on import.
    """
    out: List[Dict[str, Any]] = []
    try:
        from ion.services.training_sim_service import SCENARIOS  # type: ignore
    except Exception:
        return out

    role_tags = set(role.get("sim_tags") or [])
    role_tags.add(role["tier"].lower())
    gap_keys = {q.get("capability_key") for gap in gap_areas for q in gap["area"]["questions"] if q.get("capability_key")}

    for sid, scen in (SCENARIOS or {}).items() if isinstance(SCENARIOS, dict) else []:
        s_tags = {t.lower() for t in (scen.get("tags") or [])}
        s_tier = (scen.get("tier") or "").lower()
        s_tags.add(s_tier)
        # Match if any role tag intersects OR a gap capability matches a sim tag
        if role_tags & s_tags or gap_keys & s_tags:
            out.append({
                "id": sid,
                "name": scen.get("name") or sid,
                "tier": scen.get("tier"),
                "duration_min": scen.get("duration_min"),
                "tags": list(s_tags),
            })
    return out[:6]


def _build_ai_prompt(
    role: Dict[str, Any], scores: Dict[str, Any], gaps: List[Dict[str, Any]]
) -> str:
    """Build the prompt for Ollama tutor mode."""
    gap_lines = []
    for gap in gaps:
        a = gap["area"]
        gap_lines.append(f"- {a['name']}: {gap['score']['pct']}% — questions: " + "; ".join(q["text"] for q in a["questions"][:3]))
    return f"""You are a SOC training advisor. The user just took a self-assessment for the role "{role['name']}" ({role['description']}) and scored {scores['overall_pct']}% overall.

Their weakest areas (under {_GAP_PCT_THRESHOLD}%):
{chr(10).join(gap_lines) if gap_lines else "(none — they're already strong across all areas)"}

Write a focused 4-week study plan. The SOC uses Elastic Security as the SIEM, so prioritise Elastic-stack-specific resources (KQL, EQL, ES|QL, Kibana, Elastic Detection Rules, Elastic Agent / Beats, Fleet, Elastic ML). For each week:
1. One concrete competency to master
2. Two specific exercises in Elastic the user can do this week
3. One way to measure success at the end of the week

Keep it practical, not generic. Avoid platitudes. 250 words max."""


async def _generate_ai_summary(role: Dict[str, Any], scores: Dict[str, Any], gaps: List[Dict[str, Any]]) -> Optional[str]:
    """Ask Ollama for a personalised study plan. Returns None on any failure."""
    if not gaps:
        return None
    try:
        from ion.services.ollama_service import get_ollama_service, OllamaError
        svc = get_ollama_service()
        prompt = _build_ai_prompt(role, scores, gaps)
        result = await svc.chat(
            messages=[{"role": "user", "content": prompt}],
            context_type="security",
            temperature=0.4,
            max_tokens=600,
            user_id=0,
        )
        return (result.get("content") or "").strip() or None
    except Exception as e:
        logger.debug("AI tutor summary failed: %s", e)
        return None


# =========================================================================
# Persistence
# =========================================================================

async def submit_assessment(
    session: Session,
    *,
    user_id: int,
    role_id: str,
    responses: Dict[str, Any],
    notes: Optional[str] = None,
    set_as_target: bool = True,
) -> RoleAssessment:
    """Score, persist, and (optionally) update the user's career goal target_role.

    `set_as_target=True` (default) keeps the existing /training Self-Assessment
    + Training Plan tabs in sync — they read UserCareerGoal.target_role.
    """
    role = _find_role(role_id)
    if role is None:
        raise ValueError(f"Unknown role_id: {role_id}")

    scores = _score_responses(role, responses)
    gaps = _gap_areas(role, scores)
    strengths = _strength_areas(role, scores)
    kb = _kb_recommendations(session, gaps)
    sims = _sim_recommendations(role, gaps)
    ai_summary = await _generate_ai_summary(role, scores, gaps)

    recommendations = {
        "strengths": strengths,
        "gaps": [
            {
                "area_id": g["area"]["id"],
                "name": g["area"]["name"],
                "pct": g["score"]["pct"],
            }
            for g in gaps
        ],
        "kb_articles": kb,
        "sim_scenarios": sims,
        "ai_summary": ai_summary,
        "generated_at": datetime.utcnow().isoformat() + "Z",
    }

    overall_pct = scores["overall_pct"]
    assessment = RoleAssessment(
        user_id=user_id,
        role_id=role_id,
        role_name=role["name"],
        responses=responses,
        scores=scores,
        overall_match_pct=overall_pct,
        overall_level=_level_for_pct(overall_pct),
        recommendations=recommendations,
        notes=notes,
    )
    session.add(assessment)
    session.flush()

    if set_as_target:
        cg = session.query(UserCareerGoal).filter_by(user_id=user_id).first()
        if cg:
            cg.target_role = role["name"]
        else:
            session.add(UserCareerGoal(
                user_id=user_id,
                current_role=role["name"],
                target_role=role["name"],
            ))

    session.commit()
    session.refresh(assessment)
    return assessment


def get_latest_for_user(session: Session, user_id: int) -> Optional[Dict[str, Any]]:
    row = (
        session.query(RoleAssessment)
        .filter_by(user_id=user_id)
        .order_by(desc(RoleAssessment.taken_at))
        .first()
    )
    return _to_dict(row) if row else None


def list_history_for_user(session: Session, user_id: int) -> List[Dict[str, Any]]:
    rows = (
        session.query(RoleAssessment)
        .filter_by(user_id=user_id)
        .order_by(desc(RoleAssessment.taken_at))
        .all()
    )
    return [_to_dict(r) for r in rows]


def collect_capability_keys() -> List[Dict[str, str]]:
    """Return every unique capability_key referenced by role questionnaires.

    Each entry includes the role + area context so the seeder can write a
    useful default note when creating a KnowledgeArticle row.
    """
    seen: Dict[str, Dict[str, str]] = {}
    for role in ROLE_DEFINITIONS:
        for area in role["areas"]:
            for q in area["questions"]:
                ck = q.get("capability_key")
                if ck and ck not in seen:
                    seen[ck] = {
                        "capability_key": ck,
                        "role_name": role["name"],
                        "area_name": area["name"],
                        "first_question": q["text"],
                    }
    return list(seen.values())


def seed_capability_articles(session: Session) -> Dict[str, int]:
    """Create KnowledgeArticle rows for every capability_key the role
    questionnaires reference, so the gap-recommendations tier of Role
    Match has something to surface.

    Idempotent and **safe under concurrent uvicorn workers** — uses
    Postgres `INSERT ... ON CONFLICT DO NOTHING` so a race between
    workers on the same constraint just no-ops instead of raising.
    Returns `{seeded: N, already_present: N, total: N}` for logging.
    """
    keys = collect_capability_keys()
    if not keys:
        return {"seeded": 0, "already_present": 0, "total": 0}

    # How many already exist, for the report only
    existing_count = (
        session.query(KnowledgeArticle.capability_key)
        .filter(KnowledgeArticle.capability_key.in_([k["capability_key"] for k in keys]))
        .count()
    )

    rows = [
        {
            "capability_key": k["capability_key"],
            "doc_status": "undocumented",
            "has_runbooks": False,
            "has_procedures": False,
            "knowledge_sharing": "siloed",
            "spof_risk": True,
            "owner_user_id": None,
            "notes": (
                f"Role Match capability — referenced by {k['role_name']} -> "
                f"{k['area_name']}. Example question: {k['first_question'][:140]}"
            ),
        }
        for k in keys
    ]

    # Postgres-only path — race-safe. SQLite fallback below.
    try:
        from sqlalchemy.dialects.postgresql import insert as pg_insert  # type: ignore
        stmt = pg_insert(KnowledgeArticle).values(rows).on_conflict_do_nothing(
            index_elements=["capability_key"]
        )
        result = session.execute(stmt)
        session.commit()
        # `rowcount` reflects rows actually inserted on Postgres.
        seeded = result.rowcount if result.rowcount and result.rowcount > 0 else 0
    except Exception:
        # Fallback: per-row try/except with savepoints. Slow but portable.
        session.rollback()
        seeded = 0
        for row in rows:
            sp = session.begin_nested()
            try:
                session.add(KnowledgeArticle(**row))
                session.flush()
                sp.commit()
                seeded += 1
            except Exception:
                sp.rollback()
        if seeded:
            session.commit()

    return {
        "seeded": seeded,
        "already_present": existing_count,
        "total": len(keys),
    }


def _to_dict(a: RoleAssessment) -> Dict[str, Any]:
    return {
        "id": a.id,
        "user_id": a.user_id,
        "role_id": a.role_id,
        "role_name": a.role_name,
        "responses": a.responses,
        "scores": a.scores,
        "overall_match_pct": a.overall_match_pct,
        "overall_level": a.overall_level,
        "recommendations": a.recommendations,
        "notes": a.notes,
        "taken_at": a.taken_at.isoformat() if a.taken_at else None,
    }
