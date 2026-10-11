## Configuration boundary

`.env` holds two kinds of key and nothing else:

- **Structural secrets** (2): `ION_DB_PASSWORD` and `ION_ADMIN_PASSWORD`.
  Compose interpolates `ION_DB_PASSWORD` into `POSTGRES_PASSWORD` and
  `ION_DATABASE_URL` before any ION process exists, and `ION_ADMIN_PASSWORD` is
  read from `os.environ` in `web/server.py` (there is no `Config` field for it).
  Removing either one stops the stack from starting.
- **Bootstrap** (6): `ION_VERSION`, `ION_DATA_DIR`, `ION_HOST`, `ION_PORT`,
  `ION_WORKERS`, `ION_LOG_LEVEL`. These are read before the app can consult its
  own settings, so they cannot live in `config.json`. `ION_DATA_DIR` locates
  `config.json` itself.

Everything else, including the integration secrets (Elasticsearch, Kibana,
GitLab, OpenCTI, Arkime, TIDE), is managed in the settings UI and stored in
`$ION_DATA_DIR/.ion/config.json`. Secrets cannot be kept out of that file:
`Config.to_file` serialises the whole in-memory config on every section save.
Environment variables still outrank that file, so a key reappearing in `.env`
silently overrides the UI. Settings shows such fields read-only with a "set by
environment" badge; `tests/test_env_boundary.py` keeps the shipped templates
honest. The key sets are `BOOTSTRAP_ENV_KEYS` and `ENV_FIELD_MAP` in
`src/ion/core/config.py`.
