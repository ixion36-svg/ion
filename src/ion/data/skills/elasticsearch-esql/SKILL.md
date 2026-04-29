---
name: elasticsearch-esql
description: Authoring and reading ES|QL queries against Elastic-stack indices. Field-path discipline, aggregation patterns, joins via LOOKUP, time-windowing.
when_to_use: |
  Apply when the alert is from an Elastic Security / Beats / Elastic Agent rule,
  when the rule.language is "esql", or when the analyst needs to write a query
  to enrich the investigation against logs-* / .alerts-security.alerts-* indices.
  Apply when the alert payload references ES|QL idioms — STATS, EVAL, WHERE,
  KEEP, DROP, ENRICH, LOOKUP — or when the investigation needs to pivot via
  cross-index correlation.
tags:
  - elastic
  - esql
  - query-language
  - kql-replacement
matches_rule_groups:
  - elastic_security
  - sigma
  - elastic_agent
matches_techniques:
  - any
---

# ES|QL — Elastic-stack query authoring

ES|QL (Elastic Search Query Language) is the canonical query language for
Elastic 8.x onwards, designed to replace and augment KQL for analytical workloads.
Use this skill when investigating Elastic Security alerts that benefit from
ad-hoc enrichment queries.

## Idiomatic structure

```
FROM <index pattern>
| WHERE <predicate>
| EVAL <expression>
| STATS <aggregations>
| KEEP <fields>
| SORT <field> ASC/DESC
| LIMIT <N>
```

Pipe stages execute left-to-right. Keep the data narrow with `KEEP` early to
reduce memory pressure on large indices.

## Field path discipline (ECS)

Always use ECS field paths:
- `event.action`, `event.category`, `event.outcome`
- `process.name`, `process.command_line`, `process.parent.name`, `process.entity_id`
- `host.name`, `user.name`, `user.target.name`
- `source.ip`, `destination.ip`, `source.port`, `destination.port`
- `winlog.event_id`, `winlog.event_data.*` for Windows event log fields
- `azure.signinlogs.properties.*` for Entra sign-in events
- `o365.audit.Operation`, `o365.audit.Workload` for M365 unified audit log

Pre-8.x field paths (`source.user.name`, etc.) have been renamed; favour
the current ECS schema.

## Common aggregation patterns

### Per-host event counts (last hour)

```
FROM logs-*
| WHERE @timestamp > NOW() - 1 hour
| STATS count = COUNT(*) BY host.name
| SORT count DESC
```

### Stack-counting rare values (the rare-tail hunt)

```
FROM logs-windows.sysmon-*
| WHERE event.code == "1"
| STATS count = COUNT(*) BY process.command_line
| SORT count ASC
| LIMIT 100
```

The bottom of this list — singletons — is the rare-tail. Often the highest-
signal subset for hunting LOLBin abuse, novel malware, etc.

### Cross-index correlation via LOOKUP / ENRICH

```
FROM .alerts-security.alerts-*
| WHERE @timestamp > NOW() - 7 days
| LOOKUP host_inventory ON host.name
| WHERE host_inventory.criticality == "high"
```

The `ENRICH` and `LOOKUP` stages provide cross-index joins; useful for
overlaying asset inventory, threat-intel feeds, or per-system metadata.

## Time-windowing

Three forms:
- Absolute: `@timestamp >= "2026-04-01T14:00:00Z"`
- Relative: `@timestamp > NOW() - 24 hours`
- Window aggregation: `STATS ... BY DATE_TRUNC(1 hour, @timestamp)`

For pivoting 30 minutes around a specific event:
```
FROM logs-*
| WHERE @timestamp >= ALERT_TIME - 30 minutes AND @timestamp <= ALERT_TIME + 30 minutes
| WHERE host.name == "<the host>"
| SORT @timestamp ASC
```

## Common pitfalls

1. **Forgetting the index pattern** — ES|QL queries must start with `FROM`.
   No implicit "current index" like KQL has in Discover.
2. **Reading nullable fields** — many ECS fields are nullable. Use
   `IS NOT NULL` filters on aggregation keys to avoid noise rows.
3. **Date math in EVAL** — `EVAL gap = TS_DIFF(@timestamp, prev_ts)` is the
   canonical pattern for inter-arrival intervals (used in beacon-CV detection).

## When to write ES|QL vs KQL

- **KQL** — exploratory single-index lookups in Kibana Discover; quick filtering.
- **ES|QL** — analytical queries with aggregation, cross-index joins, or
  computed fields. The L2 hunt's working language.

When investigating Elastic Security alerts, prefer ES|QL for any pivot that
involves aggregation or joining; KQL for one-off field filtering.

## References

- Elastic ES|QL reference: https://www.elastic.co/guide/en/elasticsearch/reference/current/esql.html
- ECS field reference: https://www.elastic.co/guide/en/ecs/current/
- ION L2 Module 2 (KQL / EQL / ES|QL) — taught from this skill's perspective.
