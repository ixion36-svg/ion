<!-- ion-doc:type=RUNBOOK -->
<!-- ion-doc:title=ION Upgrade Runbook — v0.79.5 → v0.96.3 -->
<!-- ion-doc:classification=INTERNAL -->
<!-- ion-doc:date=2026-09-15 -->

# ION Upgrade Runbook — v0.79.5 → v0.96.3

**Scope:** in-place upgrade of the production ION deployment from `0.79.5` to
`0.96.3` (a jump of 17 releases). Single-node Docker Compose deployment
(`docker-compose.yml` + the PROD copy of `.env.deploy`), private image
`fubsxploitapps/ion:0.96.3`.

**Why now:** the FP-auto-close → Kibana disconnect reported in PROD (a closed
case stayed `open` in Kibana) was fixed in **0.96.2** and is included here. This
upgrade is what delivers that fix to PROD, plus the intervening releases of
features and hardening. (0.96.3 adds only a cosmetic Verdict-Review console-404
fix on top of 0.96.2.)

**Estimated downtime:** ~2–5 min (image already pulled) for the container
recreate + first-boot schema migration.

**Who:** an operator with shell access to the PROD host, the compose project,
and the private-registry pull token.

> ⚠️ **Read §1 before touching anything.** Since v0.94.0 ION *refuses to boot*
> on weak/missing credentials. If PROD's `.env` still carries the 0.79.5-era
> values, the container will exit `1` on first start of 0.96.3 and you'll be
> mid-upgrade with a stopped service. Fix the env in the SAME change as the
> version bump.

---

## 1. Pre-flight — the boot gates (do these first)

These are hard blockers introduced across 0.80→0.96. Verify each in PROD's
deploy env **before** bumping the version.

| Gate | Rule | Where | Fix |
|---|---|---|---|
| **Admin password** | `ION_ADMIN_PASSWORD` weak/common/unset → **fatal `SystemExit(1)`** (unless `ION_DEV_MODE=true`, which PROD must never set). "Weak" = a common-password list plus the literals `changeme`/`password`/`admin`. | `server.py` config validation | Set a strong, unique value. `admin` is the ONLY local account — this is the whole local-credential surface. |
| **DB password** | `ION_DB_PASSWORD` unset → **compose refuses to start** (`${ION_DB_PASSWORD:?…}`). | `docker-compose.yml` (postgres `POSTGRES_PASSWORD` + both ION `ION_DATABASE_URL`s) | Set it in the deploy env. **Must equal the password already baked into the postgres volume** (see command below), or ION can't connect. |
| **ES URL placeholder** | `ION_ELASTICSEARCH_ENABLED=true` with a `REPLACE_WITH…` URL → **fatal**. | `server.py` config validation | Ensure `ION_ELASTICSEARCH_URL` is the real cluster URL. |
| **Inbound webhooks** | `webhook_require_signature` defaults **true** — unsigned inbound webhooks are now **rejected**. | `config.py:56` | If PROD ingests inbound webhooks, configure their HMAC secrets. Only if you knowingly accept unsigned ones: `ION_WEBHOOK_REQUIRE_SIGNATURE=false`. |

Non-fatal but worth setting right while you're in the file:
- `ION_PASSWORD_MIN_LENGTH` policy violations are a **warning**, not fatal.
- `ION_COOKIE_SECURE=true` (behind the TLS terminator) — warning if off.
- `ION_DEBUG_MODE` must be **false/unset** in PROD (else `/docs`, `/redoc`,
  `/openapi.json` are public).
- **Multi-tenancy stays OFF.** Leave `ION_MULTI_TENANT` unset/false — phase 1
  is for a two-estate migration, not this single-estate PROD. No tenant env
  needed. (The `users.tenant_id` column is added automatically; see §4.)

> 🔑 **`ION_ADMIN_PASSWORD` satisfies the boot gate but does NOT change the
> login password.** The stored `admin` hash is seeded only on the *first* boot
> of a fresh DB volume; an existing volume keeps its old hash. So a strong env
> value gets you past the gate, but you still log in with PROD's **existing**
> admin password — and PROD is then running a strong-looking `.env` over a
> possibly-weak stored hash. Rotate the real password in-app after boot (§5f).

**Find the existing DB password** (so `ION_DB_PASSWORD` matches the volume) —
read it off the still-running 0.79.5 container before you change anything:

```bash
docker inspect ion --format '{{range .Config.Env}}{{println .}}{{end}}' \
  | grep ION_DATABASE_URL     # password is between ion: and @postgres
```

**New flags default in your old env.** v0.95.0 rewrote ~63 flag defaults across
0.80→0.96. Any flag absent from PROD's current env now runs at its 0.96.3
default. Diff PROD's env against the shipped `.env.deploy` template and review
anything new for features you want off:

```bash
diff <(grep -oE '^ION_[A-Z_]+' .env.deploy | sort -u) \
     <(grep -oE '^ION_[A-Z_]+' /path/to/prod.env | sort -u)
```

**Dry-run the interpolated env (last pre-flight — zero risk).** This renders the
compose file with variables resolved, **fails fast** if `ION_DB_PASSWORD` is
missing, and shows the `image:` tag that *will* deploy — confirm it says
`0.96.3` before any restart. Use the `--env-file` that matches PROD's actual
mechanism (compose auto-loads `.env`, **not** `.env.deploy` — see §4):

```bash
docker compose --env-file .env.deploy config \
  | grep -E 'image: fubsxploitapps/ion|ION_ADMIN_PASSWORD|ION_MULTI_TENANT'
```

---

## 2. Back up first (non-negotiable)

The Postgres DB is the durable store — cases, triage, notes, and the
**tamper-evident sha256 workbench ledger**. Back it up before the migration
touches the schema.

```bash
# 1. Database dump (adjust container/user/db names to PROD)
docker exec ion-postgres pg_dump -U ion -d ion -Fc -f /tmp/ion_pre_0963.dump
docker cp ion-postgres:/tmp/ion_pre_0963.dump ./ion_pre_0963_$(date +%Y%m%d).dump
```

```bash
# 2. Snapshot the current env and the running image tag (for rollback)
cp .env.deploy .env.deploy.bak_0795
docker image inspect fubsxploitapps/ion:0.79.5 >/dev/null 2>&1 \
  && echo "0.79.5 image present for rollback" \
  || echo "WARNING: 0.79.5 image not local — pull/keep it before proceeding"
```

```bash
# 3. The ion-data volume (/data, ION_DATA_DIR) holds more than the .seeded
#    marker — uploaded files, AI-chat files, any PCAP scratch. Check it and
#    snapshot the volume if it's non-trivial (the DB dump does NOT cover it).
docker exec ion ls -la /data
```

Confirm the dump is non-empty and copied off the container before continuing.

---

## 3. Apply the env changes

Edit PROD's `.env.deploy` (or your secret-injection equivalent):

```bash
ION_VERSION=0.96.3
ION_ADMIN_PASSWORD=<strong-unique-value>        # §1 gate — fatal if weak
ION_DB_PASSWORD=<existing-db-password>           # §1 gate — must match the volume
ION_ELASTICSEARCH_URL=<real-cluster-url>         # no REPLACE_WITH placeholder
ION_COOKIE_SECURE=true
# ION_DEBUG_MODE stays unset/false
# ION_MULTI_TENANT stays unset/false
```

Leave the integration blocks (Kibana, TIDE, OpenCTI, Arkime, OIDC) as PROD
already has them. `ION_KIBANA_CASES_ENABLED=true` must remain set for the
Kibana case-sync fix to have anything to sync to.

---

## 4. Pull the image and deploy

```bash
# Private org registry — retry: registry-1/github IPv6 can be flaky
docker login -u fubsxploitapps   # if not already authenticated
docker compose --env-file .env.deploy pull ion
```

```bash
# Recreate ION (and postgres if compose insists); brief downtime here.
# Use the SAME --env-file your deploy actually relies on. Compose auto-loads
# `.env` only; if PROD keeps its config in `.env.deploy`, pass it explicitly
# (or the stale/auto-loaded `.env` wins and you deploy the wrong tag):
docker compose --env-file .env.deploy up -d
```

**First-boot schema migration is automatic.** ION adds the new columns via
idempotent `ALTER TABLE … ADD COLUMN IF NOT EXISTS` startup migrations
(`storage/database.py`), including `users.tenant_id` (nullable — existing users
stay NULL = platform-global, unchanged access). `create_all` never adds columns
to existing tables, so these startup migrations are the mechanism. They run
under a Postgres advisory lock, so only one worker applies them even with N
workers. No manual SQL required.

---

## 5. Verify

```bash
# 5a. Container reports healthy
docker inspect ion --format '{{.State.Health.Status}}'   # expect: healthy
```

```bash
# 5b. No fatal config errors
docker logs ion --since 5m 2>&1 | grep -iE "CONFIG FATAL|Startup blocked|Configuration validated"
```
The load-bearing line is `Configuration validated: N warning(s), 0 errors` with
no `CONFIG FATAL` / `Startup blocked` lines. (The `ALTER TABLE` migrations may
not log their DDL, so don't wait to see them — a clean config line + a healthy
container is the signal.)

Then in the browser:
- **5c.** Log in as `admin` using PROD's **existing** admin password (the env
  value did NOT change it — see the §1 key note). Dashboard loads.
- **5d.** Footer/version shows **v0.96.3** (`{{ ion_version }}` from
  `src/ion/__init__.py`).
- **5e. Prove the headline fix:** open a case with a linked Kibana case, close
  it (or close its last alert as False Positive). The linked Kibana case should
  flip to **closed within the close request** — not minutes later. This is the
  reason for the upgrade; confirm it end-to-end against PROD's Kibana.
- **5f. Rotate the admin password** in the profile/settings UI so the stored
  hash matches the strong `.env` value. Until you do, PROD is running a
  strong-looking `.env` over its old (possibly weak) stored hash — for a
  security product, close this in the same maintenance window.

---

## 6. Rollback

If 5a–5b fail or the smoke test regresses:

```bash
# 1. Revert version + env (restores ION_VERSION=0.79.5 and the old values)
cp .env.deploy.bak_0795 .env.deploy

# 2. Stop every ion-image service so nothing holds DB connections; keep
#    postgres running. (docker-compose.yml has more than one ion-image service.)
docker compose stop ion
docker compose --env-file .env.deploy up -d postgres   # no-op if already up
docker compose ps                                      # confirm ONLY postgres is up

# 3. Restore the pre-upgrade dump (no ion process may be connected)
docker exec -i ion-postgres pg_restore -U ion -d ion --clean --if-exists \
  < ./ion_pre_0963_YYYYMMDD.dump

# 4. Start ion on the reverted (0.79.5) tag
docker compose --env-file .env.deploy up -d
```

Notes:
- The added columns are additive; 0.79.5 ignores them, so an image-only revert
  is usually enough. Restoring the dump is the clean path if 0.96.x wrote data
  you don't want to keep.
- Keep the `0.79.5` image available locally until 0.96.3 is confirmed good —
  don't prune it.

---

## 7. Post-upgrade follow-ups

- **PROD-verify owed:** GitLab issue mirroring (v0.87.0) — needs `ION_GITLAB_*`
  on PROD to confirm alert → tuning-request → GitLab issue lands.
- **Behavioral changes to expect** (none require action, but support should
  know): v0.92.0 added CSRF protection (X-CSRF-Token from a meta tag + Origin
  check) — third-party scripts hitting the API directly will 403; v0.94.0
  refuses to boot on weak creds (§1); v0.90.0 shipped Response Actions +
  Verdict Review (opt-in, off unless `response_actions_enabled`).
- **Not in this upgrade:** multi-tenancy stays off; RBAC is unchanged.

---

*Sources: `server.py` config validation, `docker-compose.yml`, `.env.deploy`,
`storage/database.py` startup migrations, `CHANGELOG.md` v0.80.0–v0.96.3.
Verified against the 0.96.2 image (0.96.3 differs only by a cosmetic template
fix) on a live ES + Kibana 9.4.4 stack.*
