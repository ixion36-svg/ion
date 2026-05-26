<!-- ion-doc:type=CAPACITY PLAN -->
<!-- ion-doc:title=ION Performance & Capacity Plan -->
<!-- ion-doc:subtitle=Current observed performance, capacity model, scaling levers, monitoring thresholds, load-test plan -->
<!-- ion-doc:version=0.29.1 -->
<!-- ion-doc:classification=PUBLIC -->
<!-- ion-doc:owner=ION Maintainer + Customer Operator -->
<!-- ion-doc:audience=Operators, SRE, customer DA, customer SDM -->
<!-- ion-doc:date=2026-05-12 -->

# 1. Purpose

This document captures ION's **performance and capacity** stance: what it does today, how it scales, and what's planned to close the formal load-test gap (currently UR-NFR-002 = Partial).

## 1.1 Companions

- `docs/HLD.md` §6.2 — NFR performance targets
- `docs/USER_REQUIREMENTS.md` UR-NFR-002 — perception target
- `docs/TRACEABILITY.md` — UR → SR → test trace
- `_mod_iteap.md` §1 — functional test coverage
- `_mod_through_life_plan.md` — operational support model

# 2. Performance targets

| Surface | p95 target | Source |
|---|---|---|
| List pages (e.g. `/alerts`, `/cases`) | < 700 ms | UR-NFR-002 |
| Detail pages (e.g. `/cases/{id}`) | < 1500 ms | UR-NFR-002 |
| Background tasks (alert → case → embedding → PCAP) | < 30 s end-to-end | LLD §6 |
| Bob inference (Ollama) | < 6 s per alert | Bob template config |
| Embedding generation | < 300 ms per case | pgvector + nomic-embed-text |
| Webhook outbound delivery | < 2 s p95 | Adapter timeout |
| Audit log write | < 50 ms p95 | Adapter timeout |

These targets are validated **empirically** in production today. They are not yet validated by a formal load test — that is the gap UR-NFR-002 tracks.

# 3. Capacity model

## 3.1 Sizing axes

ION's load scales along these axes:

| Axis | Driver | Saturation indicator |
|---|---|---|
| Concurrent analysts | RBAC sessions active simultaneously | Worker pool exhaustion |
| Alert volume | Alerts/sec from Elastic | Ingestion queue backlog |
| Cases/day | New cases created | Embedding queue depth |
| PCAP-on-case rate | Cases with `community_id` or IP+time | Arkime adapter latency |
| Bob inference rate | Alerts with matching template | Ollama queue / GPU |
| Concurrent Workbench pinning | Per-case advisory lock contention | Postgres lock-wait |

## 3.2 Default deployment envelope

The recommended default single-instance deployment fits the following profile:

| Resource | Value |
|---|---|
| Concurrent analysts | ≤ 50 |
| Alert volume | ≤ 1000 alerts/hour |
| Cases/day | ≤ 200 |
| PCAP-on-case | ≤ 50/day |
| Bob templates active | All 54 seeded + customer-added |

**Container sizing:**

| Resource | Default | Range |
|---|---|---|
| CPU | 4 vCPU | 2–8 |
| RAM | 8 GB | 4–16 |
| uvicorn workers | 4 | 2–8 |
| DB connection pool | 20 | 10–40 |
| DB connection overflow | 10 | 5–20 |

**Postgres sizing:**

| Resource | Default | Range |
|---|---|---|
| CPU | 4 vCPU | 2–16 |
| RAM | 8 GB | 4–32 |
| Storage | 100 GB | 50 GB – 1 TB (depends on retention) |
| `shared_buffers` | 2 GB | (per Postgres tuning guide) |
| `effective_cache_size` | 6 GB | (3/4 of RAM) |

# 4. Scaling levers

## 4.1 Vertical scaling

| When | Lever |
|---|---|
| Workers exhausted | Increase uvicorn worker count + container CPU |
| DB CPU > 70% sustained | Increase Postgres vCPU |
| pgvector HNSW query slow | Increase RAM for `shared_buffers` |
| Slow-query alarms firing | Tune `slow_query_threshold_ms`; identify query; add index |

## 4.2 Horizontal scaling

| When | Lever |
|---|---|
| > 50 concurrent analysts | Scale ION container to N replicas behind sticky-session load balancer |
| Postgres read-heavy queries (analytics) | Add Postgres read replica; route `/engineering/analytics` reads to replica |
| Bob latency dominant | Scale Ollama horizontally (multiple model servers behind round-robin) |

**Note on horizontal scaling**: ION uses Postgres advisory locks to ensure each background task runs on one node only. This means scaling out the ION container scales the HTTP-serving capacity but does NOT parallelise background work. For environments with very high case-create rates, the right scale is "fewer-but-bigger ION instances" rather than "many small ones."

## 4.3 Storage scaling

| When | Lever |
|---|---|
| Audit log table grows large | Customer-side: archive to SIEM; truncate Postgres after retention window |
| PCAP file storage grows | Customer-side: lifecycle policy on filesystem mount |
| Case embedding storage | Per-case; cap depends on retention of closed cases |
| Bundled ATT&CK / KEV growth | Per-release; small (~50 MB total) |

# 5. Monitoring thresholds (recommended customer-side alarms)

| Metric | Source | Alarm at | Severity |
|---|---|---|---|
| `/health` returning non-200 | Customer monitoring | Any | Critical |
| DB pool utilisation > 80% | `/admin/health-detail` | 80% sustained 5 min | Warning |
| DB pool utilisation > 95% | `/admin/health-detail` | 95% sustained 1 min | Critical |
| Slow-query log rate | ECS stdout | > 10/min sustained 5 min | Warning |
| Bob LLM timeout rate | ECS stdout | > 5% over 1h | Warning |
| Webhook delivery failure rate | `/admin/webhook-log` | > 10% over 1h | Warning |
| Container CPU | Customer monitoring | > 80% sustained 5 min | Warning |
| Container memory | Customer monitoring | > 90% sustained 5 min | Critical |
| Container OOM-killed | Customer monitoring | Any | Critical |
| Disk free on Postgres | Customer monitoring | < 20% remaining | Warning |
| Disk free on Postgres | Customer monitoring | < 10% remaining | Critical |
| Disk free on evidence mount | Customer monitoring | < 20% remaining | Warning |
| Audit log row count growth rate | DB query | Compare baseline; flag 2× spike | Investigation |
| Active sessions count | DB query | Beyond licensed seats | Warning |

# 6. Capacity warning signs (operational triage)

| Symptom | Likely cause | First action |
|---|---|---|
| Cases-list page slow (> 2 s) | Missing index on a filter column / table grew | Check slow-query log; add index |
| Bob suggestions take > 10 s | Ollama queue depth or GPU contention | Scale Ollama OR reduce concurrent Bob calls |
| Workbench pin returns 409 frequently | Advisory lock contention on busy case | Operational: usually transient; investigate if persistent |
| `/health` shows degraded | Specific component down | Read the diagnostic JSON; act per component |
| Webhook backlog grows | n8n / receiver down | Confirm receiver health; ION continues to retry per policy |

# 7. Load-test plan (planned for v0.31.0+)

UR-NFR-002 is currently Partial pending a formal load-test. The plan:

## 7.1 Test profile

| Aspect | Target |
|---|---|
| Tool | k6 (likely) or Locust |
| Test environment | Customer staging (clone of production sizing) |
| Workload | Synthetic: 50 concurrent analysts × typical workflow |
| Duration | 60 minutes at steady-state |
| Ramp | 5-min ramp from 0 to target |

## 7.2 Workflows in the synthetic load

1. Login (OIDC + session establishment)
2. `/alerts` list + open one alert
3. Create case from selected alerts
4. Open case detail; pin 3 artefacts; trigger PCAP auto-analysis
5. Run Bob verdict on each linked alert
6. Close case with `CaseClosureReason`
7. Logout

## 7.3 Pass criteria

| Metric | Pass threshold |
|---|---|
| p95 page-render time (list pages) | < 700 ms |
| p95 page-render time (detail pages) | < 1500 ms |
| Error rate (any 5xx) | < 0.1% |
| Postgres pool utilisation | < 80% sustained |
| Worker pool utilisation | < 70% sustained |
| Memory growth (leak indicator) | No sustained growth over 60 min |

## 7.4 Schedule

- Authored at v0.29.1: **plan only, not executed**
- Execution target: v0.31.0+
- Closes UR-NFR-002 from Partial → Met
- Results published in this document's §8

## 7.5 Re-test cadence

After the initial test:

- Re-run at each MAJOR release
- Re-run if customer environment scales (e.g. new analyst headcount tier crossed)

# 8. Load-test results

**Not yet executed at v0.29.1.** This section will be populated when the load test is run.

(Placeholder for future:)

| Test date | ION version | Result summary | Findings | Mitigations |
|---|---|---|---|---|
| (TBD) | (TBD) | (TBD) | (TBD) | (TBD) |

# 9. Capacity reviews

| Review | Cadence | Owner |
|---|---|---|
| Capacity metrics vs targets | Monthly | Customer ops + maintainer |
| Capacity envelope (sizing model) | Quarterly | Customer ops + maintainer |
| Annual load-test re-execution | Annually | Customer ops + maintainer |
| Capacity planning for upcoming headcount changes | As scheduled | Customer ops |

# 10. Sign-off

- ION maintainer (technical model owner)
- Customer SRE (operational implementation)
- Customer SRO (Acceptance gate)

# 11. Change history

| Version | Date | Author | Change |
|---|---|---|---|
| 1.0 | 2026-05-12 | ION maintainer | Initial capacity plan authored at v0.29.1; load-test plan pending v0.31.0+ execution |
