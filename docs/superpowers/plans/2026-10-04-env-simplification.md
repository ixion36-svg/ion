# .env Simplification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cut `.env` from 45 keys to 8 by moving every setting ION can store into its existing in-app settings, and make the remaining environment overrides visible in the UI instead of silent.

**Architecture:** ION already has the settings UI, the `PUT /config/<integration>` endpoints and a persistent `config.json`. Environment variables outrank the file, so the UI cannot win. This plan adds a declarative field-to-env-var map that reports where each field's effective value came from, surfaces that in `GET /config` and the settings page, then migrates values into `config.json` and prunes `.env`.

**Tech Stack:** Python 3.14 (container) / 3.11 and 3.14 (CI matrix), FastAPI, Jinja2, pytest, ruff.

## Global Constraints

- Source of truth for the design: `docs/superpowers/specs/2026-10-04-env-simplification-design.md`.
- Commits in this repo carry no `Co-Authored-By` trailer.
- `pytest` runs against SQLite while production is Postgres. Do not add Postgres-only SQL to any code path this plan touches.
- Total coverage must not fall below `.coverage-floor`. The `cov` CI job enforces it.
- `ruff check` must be clean.
- Secrets never appear in test fixtures, log lines, or committed files. Use obviously fake values such as `env-secret` in tests.

**Revised boundary (2026-10-04, after Task 4 surfaced the reason).** The spec's
original "secrets stay in .env" split is withdrawn: `Config.to_file`
(`config.py:499`) serialises the whole config including secrets, and every
section PUT calls it, so secrets reach `config.json` regardless. The live file
already held `elasticsearch_password` and `opencti_token`. See the spec's
"Revision" section.

Final boundary is **8 keys staying, 37 moving**:

- Six read before the app can consult its own config: `ION_VERSION`,
  `ION_DATA_DIR`, `ION_HOST`, `ION_PORT`, `ION_WORKERS`, `ION_LOG_LEVEL`.
  (`log_level` is not a `Config` field at all, verified against
  `dataclasses.fields(Config)`, 162 fields.)
- Two secrets structurally pinned to the environment: `ION_DB_PASSWORD`, which
  Compose interpolates into `POSTGRES_PASSWORD` (`docker-compose.yml:71`) and
  `ION_DATABASE_URL` (`:145`, `:309`) before ION exists; and
  `ION_ADMIN_PASSWORD`, read from `os.environ` at `server.py:583` and `:785`
  with no `admin_password` field on `Config`, so removing it fails the startup
  weak-password check outright.

Tasks 1 to 3 are unaffected and already complete: environment overrides remain
possible, so they must stay visible.

---

### Task 1: Report where each config field's value came from

**Files:**
- Modify: `src/ion/core/config.py` (append after the `get_config()` definition, currently ending near line 905)
- Test: `tests/test_config_sources.py`

**Interfaces:**
- Consumes: `Config`, `get_config()` from `ion.core.config`.
- Produces:
  - `ENV_FIELD_MAP: dict[str, str]` mapping a `Config` field name to its `ION_*` environment variable name.
  - `config_field_source(field: str) -> str` returning `"environment"`, `"file"` or `"default"`.
  - `config_field_sources() -> dict[str, str]` returning that verdict for every key in `ENV_FIELD_MAP`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_config_sources.py`:

```python
"""Where did each config value actually come from?

The settings UI renders environment-backed fields read-only, so a wrong answer
here is worse than no answer: it invites an edit that silently does nothing.
"""
import dataclasses

import pytest

from ion.core import config as config_mod
from ion.core.config import (
    Config,
    ENV_FIELD_MAP,
    config_field_source,
    config_field_sources,
)


@pytest.fixture(autouse=True)
def _reset_config(monkeypatch):
    """Each test starts from a known, un-cached config."""
    monkeypatch.setattr(config_mod, "_config", None, raising=False)
    yield
    monkeypatch.setattr(config_mod, "_config", None, raising=False)


def test_every_mapped_field_exists_on_config():
    """A typo in the map would silently report 'default' forever."""
    known = {f.name for f in dataclasses.fields(Config)}
    unknown = sorted(set(ENV_FIELD_MAP) - known)
    assert unknown == [], f"ENV_FIELD_MAP names fields that do not exist: {unknown}"


def test_env_backed_field_reports_environment(monkeypatch):
    monkeypatch.setenv("ION_ELASTICSEARCH_URL", "http://es.example:9200")
    assert config_field_source("elasticsearch_url") == "environment"


def test_blank_env_var_is_not_a_source(monkeypatch):
    """An empty value is how people 'unset' a key in .env; it must not count."""
    monkeypatch.setenv("ION_ELASTICSEARCH_URL", "   ")
    assert config_field_source("elasticsearch_url") != "environment"


def test_file_backed_field_reports_file(monkeypatch, tmp_path):
    monkeypatch.delenv("ION_ELASTICSEARCH_URL", raising=False)
    cfg_dir = tmp_path / ".ion"
    cfg_dir.mkdir()
    (cfg_dir / "config.json").write_text(
        '{"elasticsearch_url": "http://from-file:9200"}', encoding="utf-8"
    )
    monkeypatch.setenv("ION_DATA_DIR", str(tmp_path))
    assert config_field_source("elasticsearch_url") == "file"


def test_unset_field_reports_default(monkeypatch, tmp_path):
    monkeypatch.delenv("ION_ELASTICSEARCH_URL", raising=False)
    monkeypatch.setenv("ION_DATA_DIR", str(tmp_path))
    assert config_field_source("elasticsearch_url") == "default"


def test_unmapped_field_reports_default():
    assert config_field_source("not_a_real_field") == "default"


def test_sources_covers_the_whole_map(monkeypatch, tmp_path):
    monkeypatch.setenv("ION_DATA_DIR", str(tmp_path))
    sources = config_field_sources()
    assert set(sources) == set(ENV_FIELD_MAP)
    assert set(sources.values()) <= {"environment", "file", "default"}


def test_secret_fields_are_mapped():
    """The eight secrets stay in .env, so the UI must be able to badge them."""
    for field in (
        "elasticsearch_password",
        "kibana_password",
        "arkime_password",
        "gitlab_token",
        "opencti_token",
    ):
        assert field in ENV_FIELD_MAP
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/test_config_sources.py -v`

Expected: FAIL at import with `ImportError: cannot import name 'ENV_FIELD_MAP' from 'ion.core.config'`.

- [ ] **Step 3: Write the implementation**

Append to `src/ion/core/config.py`, after `get_config()`:

```python
# ── Where did a setting come from? ──
#
# get_config() ranks environment variables above .ion/config.json. That is
# deliberate, but it used to be invisible: a value edited in the settings UI
# saved successfully and changed nothing, which is how the dashboard spent an
# hour reporting ELASTICSEARCH DEGRADED on 2026-10-04.
#
# This map is declarative rather than instrumented into the override block
# above, because that block is several hundred hand-written `if os.environ.get`
# lines and threading a recorder through every one of them would be a far
# larger change for the same answer. test_every_mapped_field_exists_on_config
# guards the map against typos and renames.
ENV_FIELD_MAP: dict[str, str] = {
    # General
    "base_url": "ION_BASE_URL",
    "cookie_secure": "ION_COOKIE_SECURE",
    "debug_mode": "ION_DEBUG_MODE",
    # Elasticsearch
    "elasticsearch_enabled": "ION_ELASTICSEARCH_ENABLED",
    "elasticsearch_url": "ION_ELASTICSEARCH_URL",
    "elasticsearch_username": "ION_ELASTICSEARCH_USERNAME",
    "elasticsearch_password": "ION_ELASTICSEARCH_PASSWORD",
    "elasticsearch_verify_ssl": "ION_ELASTICSEARCH_VERIFY_SSL",
    "elasticsearch_alert_index": "ION_ELASTICSEARCH_ALERT_INDEX",
    "elasticsearch_case_index": "ION_ELASTICSEARCH_CASE_INDEX",
    # Kibana
    "kibana_cases_enabled": "ION_KIBANA_CASES_ENABLED",
    "kibana_url": "ION_KIBANA_URL",
    "kibana_username": "ION_KIBANA_USERNAME",
    "kibana_password": "ION_KIBANA_PASSWORD",
    "kibana_verify_ssl": "ION_KIBANA_VERIFY_SSL",
    "kibana_space_id": "ION_KIBANA_SPACE_ID",
    # GitLab
    "gitlab_enabled": "ION_GITLAB_ENABLED",
    "gitlab_url": "ION_GITLAB_URL",
    "gitlab_token": "ION_GITLAB_TOKEN",
    "gitlab_project_id": "ION_GITLAB_PROJECT_ID",
    "gitlab_verify_ssl": "ION_GITLAB_VERIFY_SSL",
    # OpenCTI
    "opencti_enabled": "ION_OPENCTI_ENABLED",
    "opencti_url": "ION_OPENCTI_URL",
    "opencti_token": "ION_OPENCTI_TOKEN",
    "opencti_verify_ssl": "ION_OPENCTI_VERIFY_SSL",
    # Arkime
    "arkime_enabled": "ION_ARKIME_ENABLED",
    "arkime_url": "ION_ARKIME_URL",
    "arkime_username": "ION_ARKIME_USERNAME",
    "arkime_password": "ION_ARKIME_PASSWORD",
    "arkime_verify_ssl": "ION_ARKIME_VERIFY_SSL",
    # TIDE
    "tide_enabled": "ION_TIDE_ENABLED",
    "tide_url": "ION_TIDE_URL",
    "tide_space": "ION_TIDE_SPACE",
    "tide_verify_ssl": "ION_TIDE_VERIFY_SSL",
    # Ollama
    "ollama_enabled": "ION_OLLAMA_ENABLED",
    "ollama_url": "ION_OLLAMA_URL",
    # OIDC
    "oidc_enabled": "ION_OIDC_ENABLED",
}


def _config_file_path() -> Path:
    """The same path get_config() loads from."""
    data_dir = os.environ.get("ION_DATA_DIR")
    if data_dir:
        return Path(data_dir) / ".ion" / "config.json"
    return Path.cwd() / ".ion" / "config.json"


def config_field_source(field: str) -> str:
    """Report where `field`'s effective value came from.

    Returns "environment", "file" or "default". An unmapped field, or one whose
    environment variable is set to whitespace, reports as if it were unset:
    blanking a key is how people disable it in a .env file.
    """
    env_name = ENV_FIELD_MAP.get(field)
    if env_name and os.environ.get(env_name, "").strip():
        return "environment"

    path = _config_file_path()
    if path.exists():
        try:
            with open(path, encoding="utf-8") as fh:
                stored = json.load(fh)
        except (OSError, json.JSONDecodeError):
            stored = {}
        if isinstance(stored, dict) and field in stored:
            return "file"

    return "default"


def config_field_sources() -> dict[str, str]:
    """config_field_source() for every field the settings UI can show."""
    return {field: config_field_source(field) for field in ENV_FIELD_MAP}
```

Confirm `json` and `Path` are already imported at the top of `config.py`; both are used by `Config.from_file`, so no new imports are expected.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -m pytest tests/test_config_sources.py -v`

Expected: PASS, 8 passed.

If `test_every_mapped_field_exists_on_config` fails, the failure message names the offending keys. Correct them against `dataclasses.fields(Config)` rather than deleting the test.

- [ ] **Step 5: Lint and commit**

```bash
ruff check src/ion/core/config.py tests/test_config_sources.py
git add src/ion/core/config.py tests/test_config_sources.py
git commit -m "feat(config): report whether a setting came from env, file or default

Environment variables outrank .ion/config.json, which made a settings-UI edit
save successfully and change nothing. A declarative field-to-env map answers
where each value came from, so the UI can say so instead of failing silently."
```

---

### Task 2: Expose the sources through GET /config

**Files:**
- Modify: `src/ion/web/admin_api.py:199-310` (the `get_configuration` handler)
- Test: `tests/test_config_sources_api.py`

**Interfaces:**
- Consumes: `config_field_sources()` from Task 1.
- Produces: `GET /api/admin/config` gains a top-level `"sources"` object, `dict[str, str]`, keyed by `Config` field name. Existing section keys are unchanged.

- [ ] **Step 1: Write the failing test**

Create `tests/test_config_sources_api.py`:

```python
"""GET /config must say which fields the environment is holding."""
import pytest


def test_config_response_includes_sources(admin_client, monkeypatch):
    monkeypatch.setenv("ION_ELASTICSEARCH_URL", "http://es.example:9200")

    resp = admin_client.get("/api/admin/config")

    assert resp.status_code == 200
    body = resp.json()
    assert "sources" in body
    assert body["sources"]["elasticsearch_url"] == "environment"


def test_sources_does_not_leak_secret_values(admin_client, monkeypatch):
    """Sources report provenance only. The value stays masked."""
    import json

    monkeypatch.setenv("ION_GITLAB_TOKEN", "env-secret")

    body = admin_client.get("/api/admin/config").json()

    assert body["sources"]["gitlab_token"] == "environment"
    assert "env-secret" not in json.dumps(body)


def test_existing_sections_unchanged(admin_client):
    body = admin_client.get("/api/admin/config").json()
    for section in ("general", "gitlab", "opencti", "elasticsearch"):
        assert section in body
```

If `tests/conftest.py` has no `admin_client` fixture, add one modelled on the authenticated-client fixture the existing API tests use. Check with:

```bash
grep -n "def .*client" tests/conftest.py
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python -m pytest tests/test_config_sources_api.py -v`

Expected: FAIL on `assert "sources" in body` with `KeyError` or an assertion error.

- [ ] **Step 3: Write the implementation**

In `src/ion/web/admin_api.py`, add the import alongside the existing `get_config` import:

```python
from ion.core.config import config_field_sources, get_config
```

Then in `get_configuration`, add one key to the returned dict, as a sibling of `"general"`:

```python
    return {
        # Which fields the environment is holding, so the settings page can
        # render them read-only instead of offering an edit that cannot win.
        "sources": config_field_sources(),
        "general": {
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -m pytest tests/test_config_sources_api.py -v`

Expected: PASS, 3 passed.

- [ ] **Step 5: Lint and commit**

```bash
ruff check src/ion/web/admin_api.py tests/test_config_sources_api.py
git add src/ion/web/admin_api.py tests/test_config_sources_api.py
git commit -m "feat(admin-api): return per-field config sources from GET /config"
```

---

### Task 3: Render environment-backed fields read-only and badged

**Files:**
- Modify: `src/ion/web/templates/settings.html`
- Modify: `src/ion/web/static/css/ion-workspace.css` (append)
- Test: `tests/test_settings_page_render.py`

**Interfaces:**
- Consumes: the `sources` object from Task 2.
- Produces: `applyConfigSources(sources)` in `settings.html`, called after the config fetch resolves.

- [ ] **Step 1: Write the failing test**

Create `tests/test_settings_page_render.py`:

```python
"""The settings page must ship the source-badge code.

This is a render-level guard, not a browser test: it catches the template
losing the hook during a rewrite, which is the realistic regression.
"""


def test_settings_page_defines_source_badge_helper(admin_client):
    html = admin_client.get("/settings").text
    assert "applyConfigSources" in html


def test_settings_page_has_badge_markup(admin_client):
    html = admin_client.get("/settings").text
    assert "set by environment" in html.lower()
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python -m pytest tests/test_settings_page_render.py -v`

Expected: FAIL on `assert "applyConfigSources" in html`.

- [ ] **Step 3: Write the implementation**

In `settings.html`, add the helper inside the existing `<script>` block:

```javascript
// A field the environment holds cannot be changed from here: get_config()
// ranks env above config.json. Show that rather than offering a save that
// silently loses.
function applyConfigSources(sources) {
    if (!sources) return;
    Object.entries(sources).forEach(([field, source]) => {
        if (source !== 'environment') return;
        const input = document.querySelector(`[name="${field}"], #${field}`);
        if (!input) return;
        input.readOnly = true;
        input.disabled = true;
        input.classList.add('cfg-env-locked');
        if (input.parentElement.querySelector('.cfg-env-badge')) return;
        const badge = document.createElement('span');
        badge.className = 'cfg-env-badge';
        badge.textContent = 'set by environment';
        badge.title = `Held by ${field.toUpperCase()} in the environment. ` +
                      'Remove it from .env to manage this here.';
        input.parentElement.appendChild(badge);
    });
}
```

Call it where the config fetch resolves. Find the call site with:

```bash
grep -n "api/admin/config" src/ion/web/templates/settings.html
```

and add, immediately after the response is parsed into `data`:

```javascript
        applyConfigSources(data.sources);
```

Append to `src/ion/web/static/css/ion-workspace.css`:

```css
/* Settings fields the environment holds: visibly not editable here. */
.cfg-env-badge {
    display: inline-block;
    margin-left: 8px;
    padding: 1px 6px;
    border: 1px solid var(--ion-border);
    border-radius: 4px;
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: var(--text-secondary);
    white-space: nowrap;
}
.cfg-env-locked { opacity: 0.6; cursor: not-allowed; }
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -m pytest tests/test_settings_page_render.py -v`

Expected: PASS, 2 passed.

- [ ] **Step 5: Verify in the browser**

The running container serves the packaged copy, not the repo, so copy the files in first:

```bash
P=/opt/venv/lib/python3.14/site-packages/ion/web
docker cp src/ion/web/templates/settings.html ion:$P/templates/settings.html
docker cp src/ion/web/static/css/ion-workspace.css ion:$P/static/css/ion-workspace.css
docker restart ion
```

Open `http://localhost:8000/settings`, go to the Elasticsearch section, and hard-refresh with Ctrl+F5. The stylesheet is cache-busted by `?v={{ ion_version }}`, which has not changed, so without the hard refresh you will be looking at the old CSS.

Expected: while `ION_ELASTICSEARCH_URL` is still in `.env`, the Elasticsearch URL field is greyed, not editable, and carries a "set by environment" badge.

- [ ] **Step 6: Commit**

```bash
git add src/ion/web/templates/settings.html src/ion/web/static/css/ion-workspace.css tests/test_settings_page_render.py
git commit -m "feat(settings): mark environment-held fields read-only with a badge"
```

---

### Task 4: Migrate the live values into config.json

**Files:**
- Create: `scripts/migrate-env-to-settings.ps1`

**Interfaces:**
- Consumes: `GET /api/admin/config` (including `sources` from Task 2) and the existing `PUT /api/admin/config/<integration>` endpoints.
- Produces: an updated `.ion/config.json` inside the `ion-data` volume. Changes no files in the repo.

This task writes values; it does not delete anything. Pruning is Task 5, deliberately separate so a reviewer can reject the deletion while keeping the migration.

- [ ] **Step 1: Capture the current effective config**

`config.json` was last written on 2026-09-06 and predates the current Elasticsearch settings, so it is not the source of truth. The running instance is.

```bash
curl -s -u admin:$ION_ADMIN_PASSWORD http://localhost:8000/api/admin/config \
  > /tmp/ion-config-effective.json
python -c "import json;d=json.load(open('/tmp/ion-config-effective.json'));print(len(d),'sections')"
```

Expected: a section count of 13 or more, including `sources`.

- [ ] **Step 2: Write the migration script**

Create `scripts/migrate-env-to-settings.ps1`:

```powershell
<#
    Copy the running instance's effective settings into config.json via the
    admin API, so that removing keys from .env does not fall back to whatever
    config.json last held. Order matters: config.json predates the current
    Elasticsearch settings, so pruning .env first would silently revert live
    integrations to September's values.

    Run with -DryRun first. It prints every PUT it would make and changes
    nothing.
#>
param(
    [string]$BaseUrl = "http://localhost:8000",
    [Parameter(Mandatory = $true)][string]$AdminPassword,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
$pair = "admin:$AdminPassword"
$auth = @{ Authorization = "Basic " + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($pair)) }

$effective = Invoke-RestMethod -Uri "$BaseUrl/api/admin/config" -Headers $auth

# Only sections with a PUT endpoint. "sources" and read-only sections are skipped.
$sections = @("general", "elasticsearch", "kibana", "gitlab", "opencti",
              "arkime", "tide", "ollama", "oidc", "dfir_iris",
              "abuseipdb", "virustotal")

foreach ($section in $sections) {
    if (-not $effective.PSObject.Properties.Name.Contains($section)) {
        Write-Host "skip   $section (not present in GET /config)"
        continue
    }
    # Strip secret fields. GET /config returns them masked, so writing them
    # back would store the mask itself. Real secret values reach config.json
    # via Config.to_file on the server side, not through this script.
    $obj = $effective.$section
    $clean = [ordered]@{}
    foreach ($prop in $obj.PSObject.Properties) {
        if ($prop.Name -match '(password|token|api_key|secret)') { continue }
        if ($prop.Name -match '_set$') { continue }
        $clean[$prop.Name] = $prop.Value
    }
    $payload = $clean | ConvertTo-Json -Depth 6
    if ($DryRun) {
        Write-Host "DRYRUN PUT /api/admin/config/$section"
        Write-Host $payload
        continue
    }
    try {
        Invoke-RestMethod -Method Put -Uri "$BaseUrl/api/admin/config/$section" `
            -Headers $auth -ContentType "application/json" -Body $payload | Out-Null
        Write-Host "wrote  $section"
    } catch {
        Write-Warning "failed $section : $($_.Exception.Message)"
    }
}
```

The script strips secret-looking fields and the `*_set` booleans before each `PUT`, so a masked value can never be written back as if it were real. Confirm the stripping is doing its job by checking the dry run output in Step 3: no `password`, `token`, `api_key` or `secret` key should appear in any payload.

- [ ] **Step 3: Dry run**

```bash
pwsh -File scripts/migrate-env-to-settings.ps1 -AdminPassword "$ION_ADMIN_PASSWORD" -DryRun
```

Expected: one `DRYRUN PUT` block per section, no errors, nothing written.

- [ ] **Step 4: Run for real, then verify each integration**

```bash
pwsh -File scripts/migrate-env-to-settings.ps1 -AdminPassword "$ION_ADMIN_PASSWORD"
for i in elasticsearch kibana ollama; do
  echo -n "$i: "
  curl -s -u admin:$ION_ADMIN_PASSWORD -X POST \
    "http://localhost:8000/api/admin/config/test/$i" | head -c 200
  echo
done
```

Expected: each returns a success verdict. Arkime, GitLab, OpenCTI and TIDE will fail because those containers are not running; that is expected and is what Task 5 turns off.

- [ ] **Step 5: Commit**

```bash
git add scripts/migrate-env-to-settings.ps1
git commit -m "chore(config): add env-to-settings migration script

Writes the running instance's effective config through the admin API so that
pruning .env cannot fall back to a config.json written in September."
```

---

### Task 5: Prune .env and document the boundary

**Files:**
- Modify: `.env` (not tracked; back it up first)
- Modify: `.env.example`
- Modify: `.env.template`
- Modify: `CLAUDE.md`
- Test: `tests/test_env_boundary.py`

**Interfaces:**
- Consumes: `ENV_FIELD_MAP` from Task 1.
- Produces: `BOOTSTRAP_ENV_KEYS: frozenset[str]` in `ion.core.config`, the keys that legitimately stay in the environment.

- [ ] **Step 1: Write the failing test**

Create `tests/test_env_boundary.py`:

```python
"""The shipped .env templates must match the agreed boundary.

Secrets and bootstrap keys stay. Everything else is managed in the settings UI,
so a non-secret key reappearing in .env.example would quietly re-break it.
"""
import re
from pathlib import Path

import pytest

from ion.core.config import BOOTSTRAP_ENV_KEYS, ENV_FIELD_MAP

# Only these two secrets are structurally pinned to the environment:
# Compose interpolates ION_DB_PASSWORD before ION exists, and
# ION_ADMIN_PASSWORD has no Config field so it cannot be stored at all.
# The other six integration secrets now live in config.json.
STRUCTURAL_ENV_KEYS = frozenset({
    "ION_DB_PASSWORD",
    "ION_ADMIN_PASSWORD",
})

TEMPLATES = ("env.example", "env.template")


def _keys(path: Path) -> set[str]:
    if not path.exists():
        pytest.skip(f"{path} not present")
    return set(re.findall(r"^([A-Z_]+)=", path.read_text(encoding="utf-8"), re.M))


@pytest.mark.parametrize("name", TEMPLATES)
def test_template_holds_only_secrets_and_bootstrap(name):
    repo_root = Path(__file__).resolve().parents[1]
    keys = _keys(repo_root / f".{name}")
    allowed = STRUCTURAL_ENV_KEYS | BOOTSTRAP_ENV_KEYS
    stray = sorted(keys - allowed)
    assert stray == [], (
        "these belong in the settings UI, not .env: " + ", ".join(stray)
    )


def test_bootstrap_and_managed_sets_do_not_overlap():
    managed = set(ENV_FIELD_MAP.values())
    assert not (managed & set(BOOTSTRAP_ENV_KEYS))


def test_structural_secrets_are_not_claimed_as_bootstrap():
    assert not (STRUCTURAL_ENV_KEYS & set(BOOTSTRAP_ENV_KEYS))
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python -m pytest tests/test_env_boundary.py -v`

Expected: FAIL at import with `ImportError: cannot import name 'BOOTSTRAP_ENV_KEYS'`.

- [ ] **Step 3: Define the bootstrap set**

Append to `src/ion/core/config.py`, directly below `ENV_FIELD_MAP`:

```python
# Read before the app can consult its own settings, so these cannot move into
# config.json. ION_DATA_DIR is the strongest case: it is how config.json is
# located. ION_VERSION is read by Compose to resolve the image tag, and
# ION_LOG_LEVEL when logging is configured, which happens before config loads.
BOOTSTRAP_ENV_KEYS: frozenset[str] = frozenset({
    "ION_VERSION",
    "ION_DATA_DIR",
    "ION_HOST",
    "ION_PORT",
    "ION_WORKERS",
    "ION_LOG_LEVEL",
})
```

- [ ] **Step 4: Prune the templates and the live .env**

Back up first, with a timestamp so repeated runs do not clobber each other:

```bash
cp .env ".env.bak.$(date +%Y%m%d-%H%M%S)"
```

Remove every key from `.env`, `.env.example` and `.env.template` that is neither in `STRUCTURAL_ENV_KEYS` nor in `BOOTSTRAP_ENV_KEYS`. The 37 to remove are every value of `ENV_FIELD_MAP` except the two structural secrets:

```bash
python - <<'PY'
import re
from pathlib import Path
from ion.core.config import BOOTSTRAP_ENV_KEYS, ENV_FIELD_MAP

STRUCTURAL = {"ION_DB_PASSWORD", "ION_ADMIN_PASSWORD"}
keep = STRUCTURAL | set(BOOTSTRAP_ENV_KEYS)

for name in (".env", ".env.example", ".env.template"):
    path = Path(name)
    if not path.exists():
        continue
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^([A-Z_]+)=", line)
        if m and m.group(1) not in keep:
            continue
        out.append(line)
    path.write_text("\n".join(out) + "\n", encoding="utf-8")
    print(name, "now", sum(1 for l in out if re.match(r"^[A-Z_]+=", l)), "keys")
PY
```

Expected: `.env now 8 keys`.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `python -m pytest tests/test_env_boundary.py -v`

Expected: PASS, 3 passed.

- [ ] **Step 6: Turn off the integrations you do not run**

Enablement is now a setting, so this is a toggle rather than a redeploy. With `ION_*_ENABLED` gone from `.env`, `config.json` decides. Arkime, GitLab, OpenCTI and TIDE have no containers in this stack, and leaving them on is what makes the startup warning list seven integrations with TLS verification off.

In the settings UI, open each of Arkime, GitLab, OpenCTI and TIDE and switch Enabled off. Or equivalently:

```bash
for i in arkime gitlab opencti tide; do
  curl -s -u admin:$ION_ADMIN_PASSWORD -X PUT \
    -H 'Content-Type: application/json' \
    -d "{\"${i}_enabled\": false}" \
    "http://localhost:8000/api/admin/config/$i" | head -c 120
  echo
done
```

Expected: each returns the updated section with `"<name>_enabled": false`. The code for all four stays in place; this is reversible from the UI.

- [ ] **Step 7: Recreate and verify the running app**

```bash
docker compose -f docker-compose.yml up -d --force-recreate ion
docker inspect ion --format '{{.Config.Image}} {{index .Config.Labels "org.opencontainers.image.version"}}'
docker logs ion 2>&1 | grep -E "CONFIG FATAL|Configuration validated" | tail -3
```

Use `docker inspect`, not the Compose log: `.env` pins `ION_VERSION` and `up -d` restarts rather than recreates, so the log can report success while the old container keeps running.

Expected: the image line reports `0.99.6`, the log shows `Configuration validated` and no `CONFIG FATAL`, and `http://localhost:8000` still reports Elasticsearch connected.

- [ ] **Step 8: Document the boundary in CLAUDE.md**

Add a short section:

```markdown
## Configuration boundary

`.env` holds two kinds of key and nothing else:

- **Secrets** (8): passwords, tokens and API keys.
- **Bootstrap** (6): read before the app can consult its own settings, so they
  cannot live in `config.json`. `ION_DATA_DIR` locates `config.json` itself.

Everything else is managed in the settings UI and stored in
`$ION_DATA_DIR/.ion/config.json`. Environment variables still outrank that
file, so a key reappearing in `.env` silently overrides the UI. Settings shows
such fields read-only with a "set by environment" badge; `tests/test_env_boundary.py`
keeps the shipped templates honest.
```

- [ ] **Step 9: Commit**

```bash
git add .env.example .env.template CLAUDE.md src/ion/core/config.py tests/test_env_boundary.py
git commit -m "refactor(config): prune .env to secrets and bootstrap keys

45 keys down to 14. The other 31 are managed in the settings UI and stored in
config.json, which the app already supported but could never win against."
```

---

## Verification

Run once at the end:

```bash
python -m pytest tests/test_config_sources.py tests/test_config_sources_api.py \
    tests/test_settings_page_render.py tests/test_env_boundary.py -v
ruff check src tests
python -m pytest --cov=ion --cov-report=term | tail -5
```

Expected: all four test files pass, ruff is clean, and total coverage is at or above the number in `.coverage-floor`.

Then confirm by hand:

- `.env` has 8 keys and no `*_URL`, `*_ENABLED` or `*_VERIFY_SSL` entries.
- Changing the Elasticsearch URL in the settings UI and restarting takes effect with no `.env` edit.
- The Elasticsearch **password** field shows the "set by environment" badge and cannot be edited.
- The startup TLS warning names only the integrations actually enabled, not all seven.
