# Simplifying .env: secrets in the environment, everything else in settings

**Goal:** Cut `.env` from 45 keys to 13 by moving every non-secret setting into
ION's existing in-app settings, and make the remaining environment overrides
visible in the UI instead of silent.

**Problem.** ION already has the settings system this change wants. There is a
settings page with a section per integration, a `PUT /config/<integration>`
endpoint for each, a `/config/test/{integration}` connection tester, and a
persistent store at `$ION_DATA_DIR/.ion/config.json` holding 137 keys. None of
it can win, because `get_config()` ranks environment variables above the config
file (`src/ion/core/config.py:686`). Forty-five keys in `.env` therefore shadow
the UI: a value edited in the app saves successfully and changes nothing.

That is not a theoretical failure. On 2026-10-04 the dashboard reported
`ELASTICSEARCH DEGRADED` for an hour. The cause was `ION_ELASTICSEARCH_PASSWORD`
in `.env` disagreeing with the dev stack, and nothing on screen said where the
value came from.

**Scope.** No new endpoints and no new settings sections. Every integration
present in `.env` already has both. The only code change is source reporting
plus the badge that uses it. Everything else is data migration and deletion.

## The boundary

Secrets stay in the environment. Everything else moves to settings.

**Stays, secret (8).** `ION_ADMIN_PASSWORD`, `ION_DB_PASSWORD`,
`ION_ELASTICSEARCH_PASSWORD`, `ION_KIBANA_PASSWORD`, `ION_ARKIME_PASSWORD`,
`ION_GITLAB_TOKEN`, `ION_OPENCTI_TOKEN`, `ION_TIDE_API_KEY`.

**Stays, read before app config exists (5).** `ION_VERSION` (Compose resolves
the image tag), `ION_DATA_DIR` (locates `config.json` itself, so it cannot live
inside it), `ION_PORT`, `ION_HOST`, `ION_WORKERS` (uvicorn, read at process
start).

**Moves to settings (32).** Every `*_URL`, `*_ENABLED`, `*_USERNAME` and
`*_VERIFY_SSL`, plus `ION_ELASTICSEARCH_ALERT_INDEX`,
`ION_ELASTICSEARCH_CASE_INDEX`, `ION_KIBANA_SPACE_ID`, `ION_GITLAB_PROJECT_ID`,
`ION_TIDE_SPACE`, `ION_LOG_LEVEL`, `ION_BASE_URL`, `ION_DEBUG_MODE`,
`ION_COOKIE_SECURE`.

Integration enablement becomes a toggle in settings rather than a redeploy.
Arkime, GitLab, OpenCTI and TIDE are currently enabled in `.env` while their
containers are not running, which is why the startup warning lists seven
integrations with TLS verification off. After this change that is a switch an
operator flips, and the code for all four stays exactly where it is.

## Source reporting and the badge

`get_config()` keeps its precedence. What changes is that it records, per field,
whether the effective value came from the environment, the config file, or a
default. `GET /config` returns that source alongside each value, and the
settings page renders an environment-sourced field read-only with a "set by
environment" badge, with secret values masked.

This is the part that earns the two-places-per-integration tradeoff the boundary
creates. Without it, the eight remaining secrets reproduce the Elasticsearch
failure exactly: an operator edits a password in the UI, the save succeeds, and
authentication keeps failing with nothing explaining why.

## Migration order

`config.json` was last written on 2026-09-06 and predates the current
Elasticsearch settings, so parts of it are stale. Removing a key from `.env`
makes the app fall back to whatever that file holds. The order therefore
matters, and getting it wrong reverts live integrations to September's values.

1. Capture the current effective config from the running instance
   (`GET /config`) as the source of truth, not the contents of `config.json`.
2. Write those values back through the existing `PUT /config/<integration>`
   endpoints so validation runs and `config.json` becomes current.
3. Confirm each integration with `POST /config/test/{integration}`.
4. Remove the 32 migrated keys from `.env`, keeping a timestamped backup.
5. Recreate the container and confirm by `docker inspect` that it runs the
   intended image, then verify the dashboard reports Elasticsearch connected and
   the startup log shows no new `CONFIG FATAL` lines.

Step 5 uses `docker inspect` rather than the Compose log because `.env` pins
`ION_VERSION` and `up -d` restarts rather than recreates, so the log can report
success while the old container keeps running.

## Verification

- `.env` contains 13 keys and no `*_URL`, `*_ENABLED` or `*_VERIFY_SSL` entries.
- Changing an integration URL in the settings UI takes effect after a restart
  with no `.env` edit.
- A field backed by an environment variable renders read-only and badged, and
  attempting to edit it is not offered rather than silently discarded.
- The startup TLS warning names only the integrations actually enabled.
- Existing config tests pass, with new coverage for source reporting: a field
  set in both places reports `environment`, a field set only in the file reports
  `file`, and an unset field reports `default`.

## Not in this design

**Bootstrap-only.** The alternative boundary puts secrets in `config.json` too
and leaves `.env` holding only what is needed to start the process. It collapses
each integration to a single place, which is the main cost of the chosen split.
It was rejected for now because it moves credentials into a file on the
`ion-data` volume. If the two-places split becomes annoying, this is the version
to revisit.

**Secret management.** Keeping secrets in the environment leaves the door open
to Docker secrets or a vault later. Neither is designed here.

**Archiving unused integrations.** Arkime, GitLab, OpenCTI and TIDE are disabled
by toggle, not removed. They work, and deleting working code to tidy a config
file is a poor trade.
