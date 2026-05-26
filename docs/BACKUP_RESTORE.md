<!-- ion-doc:type=BACKUP & RESTORE RUNBOOK -->
<!-- ion-doc:title=ION Backup & Restore Runbook -->
<!-- ion-doc:subtitle=Standalone operator procedure — what to back up, how to back up, how to restore, RTO/RPO targets -->
<!-- ion-doc:version=0.29.1 -->
<!-- ion-doc:classification=PUBLIC -->
<!-- ion-doc:owner=ION Maintainer + Customer Operator -->
<!-- ion-doc:audience=Operators, SRE, DBA, on-call -->
<!-- ion-doc:date=2026-05-12 -->

# 1. Purpose

This runbook is the **standalone backup + restore procedure** for ION. It is referenced by:

- `_mod_iteap.md` §5 — DR drill procedure
- `_mod_through_life_plan.md` — operational support model
- `_mod_design_passport.md` §10.2 — Through-life claim
- `_mod_ion_incident_response.md` §4 — recovery phase

Operators should run through this document at least once before go-live (the formal DR drill), then quarterly as a sanity check.

## 1.1 Recovery targets

| Target | Value | Source |
|---|---|---|
| **RTO** (Recovery Time Objective) | ≤ 1 hour | `_mod_iteap.md` §5 |
| **RPO** (Recovery Point Objective) | ≤ 24 hours | `_mod_iteap.md` §5 |
| **Availability target** | 99% monthly excl. planned maintenance | `_mod_service_transition.md` §9 |

# 2. What to back up

ION is **stateless** in its container — every persistent piece of data is in Postgres or in customer filesystem mounts. Backups therefore have a small surface.

## 2.1 Backup scope

| Item | Where it lives | Backup needed? |
|---|---|---|
| Postgres database (the `ion` database, including pgvector extension state) | Customer's Postgres instance | **YES — primary** |
| ION container | Docker image (`ixion36/ion:0.29.1`) | NO — re-pullable from Docker Hub |
| Container filesystem ephemeral state | Container internal | NO — rebuilt from image on restart |
| Application logs (audit_log) | (1) Postgres `audit_log` table (covered by DB backup) + (2) customer SIEM | Covered by DB backup + SIEM retention |
| Bundled ATT&CK + KEV snapshots | Inside image at `/app/data/` | NO — versioned with image |
| Customer secrets (env vars, .env.deploy) | Customer secrets-management | Customer secrets-management is the backup source-of-truth |
| Uploaded forensic evidence / PCAP files | Customer filesystem mount (configurable path; default `/var/lib/ion/evidence/`) | **YES — filesystem mount** |

## 2.2 What does NOT need backup

- ION's container filesystem (rebuilt from image)
- Logs in stdout (already shipped to SIEM)
- Bundled reference data (in image)
- Workbench ledger (in Postgres — covered by DB backup)
- Case embeddings (in Postgres — covered by DB backup)

# 3. Backup procedure

## 3.1 Cadence

| Backup type | Cadence | Retention |
|---|---|---|
| Full database backup | Daily, off-peak | 7 days rolling + 4 weekly + 12 monthly |
| Incremental WAL archive | Continuous (Postgres WAL streaming) | 7 days |
| Filesystem mount snapshot | Daily | 7 days rolling |
| Bundle-manifest archive | Per release | Indefinite (small) |

Customer chooses appropriate tooling (pg_dump + cron, pgBackRest, Barman, customer-managed snapshot solution). The procedure below uses `pg_dump` for clarity; customer is free to substitute.

## 3.2 Full database backup

```bash
# As the postgres OS user OR with PGPASSWORD set
TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)
BACKUP_DIR=/var/backups/ion
DB_NAME=ion
DB_USER=ion

pg_dump \
  --host=postgres \
  --username=$DB_USER \
  --dbname=$DB_NAME \
  --format=custom \
  --no-owner \
  --no-acl \
  --compress=6 \
  --file=$BACKUP_DIR/ion-$TIMESTAMP.dump

# Verify the dump is non-empty and well-formed
pg_restore --list $BACKUP_DIR/ion-$TIMESTAMP.dump > /dev/null
echo "Backup OK: $BACKUP_DIR/ion-$TIMESTAMP.dump ($(du -h $BACKUP_DIR/ion-$TIMESTAMP.dump | cut -f1))"
```

**Important:**

- The `pgvector` extension state IS captured by `pg_dump` (extensions are recorded in the dump).
- The `--no-owner` + `--no-acl` flags make the dump portable across Postgres instances; ownership is re-applied at restore.
- The `--format=custom` produces a single binary file with parallel-restore capability.

## 3.3 Filesystem mount snapshot

The customer's filesystem (mounted at e.g. `/var/lib/ion/evidence/` inside the container) holds forensic evidence + PCAP files. Snapshot per customer storage provider:

| Storage backend | Snapshot command |
|---|---|
| LVM | `lvcreate -s -n ion-evidence-snap-$TIMESTAMP /dev/vg/ion-evidence` |
| ZFS | `zfs snapshot pool/ion-evidence@$TIMESTAMP` |
| Cloud (EBS/Azure Disk/etc.) | Cloud-provider snapshot API |
| Customer SAN | Per customer SAN policy |

## 3.4 Encryption at rest

The backup files should be encrypted at rest per customer policy. ION does not encrypt backups itself; customer responsibility. Recommended:

- AES-256-GCM with a customer-managed key
- Key in customer's secret-management; never alongside the encrypted file

## 3.5 Off-site / immutable backup

Per `_mod_through_life_plan.md`, at least one backup copy MUST be:

- In a separate physical location from the primary (cross-site or cloud-region)
- Immutable for the retention window (write-once-read-many, S3 Object Lock, or equivalent)

# 4. Restore procedure

The restore drill follows the same procedure whether triggered by a true DR event or a quarterly drill.

## 4.1 Restore preconditions

- Target Postgres instance running (clean or existing)
- ION container image available (pullable from Docker Hub or customer registry)
- Customer secrets present in customer secrets-management
- Network egress to integration endpoints (Elastic, OpenCTI, etc.) restored

## 4.2 Database restore

```bash
TIMESTAMP=<the chosen backup>
BACKUP_FILE=/var/backups/ion/ion-$TIMESTAMP.dump
DB_NAME=ion
DB_USER=ion

# Stop ION container if running (prevent concurrent writes during restore)
docker stop ion

# (Optional) drop + recreate database for a clean restore
psql --host=postgres --username=postgres -c "DROP DATABASE IF EXISTS $DB_NAME;"
psql --host=postgres --username=postgres -c "CREATE DATABASE $DB_NAME OWNER $DB_USER;"
psql --host=postgres --username=postgres --dbname=$DB_NAME -c "CREATE EXTENSION IF NOT EXISTS vector;"

# Restore from dump
pg_restore \
  --host=postgres \
  --username=$DB_USER \
  --dbname=$DB_NAME \
  --jobs=4 \
  --no-owner \
  --no-acl \
  --verbose \
  $BACKUP_FILE
```

## 4.3 Filesystem mount restore

Per customer storage backend; restore the filesystem snapshot taken in §3.3.

## 4.4 Container restart

```bash
docker start ion

# Wait for startup; typically <30s
sleep 30

# Verify health
curl -sf http://localhost:8000/health | jq '.'
# Expected: {"status":"ok","version":"0.29.1",...}
```

## 4.5 Post-restore verification

Run these checks in order. Each must pass before declaring the restore complete.

| Check | Command | Pass criterion |
|---|---|---|
| Health endpoint | `curl -sf http://localhost:8000/health` | 200 OK + stable JSON |
| Auth surface | `curl -sf http://localhost:8000/login` | 200 OK; renders |
| One read API | `curl -sf -b ion_session=<test-sess> http://localhost:8000/api/cases` | 200 OK; cases visible |
| Audit log spot-check | `psql -c "SELECT COUNT(*), MAX(created_at) FROM audit_log"` | Count > 0; max date matches expected backup window |
| Ledger chain verification | Login as admin; navigate to `/workbench-audit`; OR run CLI `ion verify-ledger` | All chains report ✅ |
| One integration smoke | Open `/integrations`; click "Test" on Elastic | "OK" |
| Bob smoke (if enabled) | Open any alert; verify Bob verdict surface renders | Verdict + confidence or "no template matched" |
| Per-analyst access | Have one analyst log in via OIDC | Session created; permissions correct |

## 4.6 Smoke-test failure procedure

If any post-restore check fails:

1. Capture the failure detail (`/audit-log`, container logs)
2. Decide: roll forward (fix-in-place) or roll back (try an earlier backup)
3. Document the failure in the DR drill record for the next ITEAP §5 review

# 5. RTO / RPO measurement

During each drill, capture:

| Metric | How to measure |
|---|---|
| RTO actual | Wall-clock from "drop" to "all post-restore checks pass" |
| RPO actual | Timestamp of latest audit_log row vs timestamp of simulated failure |
| Restore data integrity | Sample 10 random cases pre-drill; verify all 10 present post-restore with identical content |
| Ledger integrity | All ledger chains verify ✅ post-restore |

A drill is considered passing if:

- RTO actual ≤ 1 hour
- RPO actual ≤ 24 hours
- All sampled data intact
- All ledger chains verify

# 6. Drill cadence

| Drill type | Cadence | Documented in |
|---|---|---|
| Tabletop walk-through | Quarterly | Customer operator log |
| Live restore drill (to a non-prod environment) | Annually | `_mod_iteap.md` §5 |
| Production DR drill (planned, communicated) | Annually OR after material infrastructure change | `_mod_iteap.md` §5 |

# 7. Known limitations + edge cases

| Limitation | Mitigation |
|---|---|
| Backup-restore loses any in-flight Workbench advisory locks | On startup, ION re-acquires advisory locks as background tasks run; no operator action needed |
| Backup-restore does NOT capture customer-side OIDC state at Keycloak | Customer Keycloak has its own backup/restore; orchestrate together if both restoring |
| Backup-restore does NOT capture customer secrets (env vars) | Customer secrets-management handles these out-of-band |
| Bob's Ollama model is not included in ION backup | Ollama is a separate container; customer re-pulls the model |
| pgvector HNSW indexes rebuild on restore (rebuild is slow but transparent) | Allow ~5-10 min for HNSW rebuild on the embeddings table after restore |

# 8. Troubleshooting

| Symptom | Likely cause | Resolution |
|---|---|---|
| `pg_restore: error: could not execute query: extension "vector" does not exist` | pgvector extension not pre-created in target DB | Run `CREATE EXTENSION vector;` first |
| Health endpoint returns 503 after restart | Migrations may be running | Wait 60s; check container logs for migration completion |
| Ledger chain verification fails | Tampering OR partial restore | Treat as incident per `_mod_ion_incident_response.md` IR-S-03 |
| Slow restore | Single-threaded pg_restore | Use `--jobs=4` for parallel restore |
| ION starts but can't reach Postgres | Wrong `DATABASE_URL` env var | Validate env var; check network |
| OIDC login fails after restore | Keycloak JWKS rotated; cached JWKS now stale | Restart ION to refresh JWKS cache |

# 9. Sign-off

- Customer DBA (DB backup procedure owner)
- Customer Operator (filesystem snapshot + restart procedure)
- Customer SRE (overall runbook acceptance)
- ION Maintainer (technical content review)
- Customer SRO (Acceptance gate)

# 10. Change history

| Version | Date | Author | Change |
|---|---|---|---|
| 1.0 | 2026-05-12 | ION maintainer | Initial backup-restore runbook authored at v0.29.1 |
