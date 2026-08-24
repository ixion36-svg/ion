---
name: release-bump
description: Walk the ION release-version bump ritual — 8 canonical files in lockstep with pyproject.toml, sanity-grep for stragglers, CHANGELOG/SECURITY_ASSESSMENT delta. Use BEFORE tagging a release.
disable-model-invocation: true
---

# /release-bump — ION release ritual

ION's version string lives in 8 files. Past releases rotted them (`src/ion/__init__.py` was stuck at 0.19.19 across 13 releases). This skill is the canonical checklist + drift checker.

## When to use

- Right before tagging a release (the bump-commit is the LAST commit on the release branch, applied after feature commits land).
- Any time you want to confirm the repo is internally consistent.

## Steps

1. **Read the source of truth.**
   ```
   grep -E '^version = ' pyproject.toml
   ```

2. **Run the drift checker** — reports any of the 8 canonical files that disagree with `pyproject.toml`:
   ```
   python .claude/skills/release-bump/check_versions.py
   ```
   Expected on a clean repo: `PASS: all canonical files match pyproject.toml.`

3. **If drift reported, identify the target version.** Two cases:
   - Drift between releases (rot) → bump everything to match `pyproject.toml`.
   - You're cutting a new release → pick the new vX.Y.Z; bump pyproject FIRST, then everything else.

4. **Bump every file the checker flagged.** Use Edit on each file. Patterns:
   - `pyproject.toml` line ≈7 → `version = "X.Y.Z"`
   - `src/ion/__init__.py` line 3 → `__version__ = "X.Y.Z"`
   - `README.md` → shields badge `version-X.Y.Z-blue`
   - `Dockerfile` → `org.opencontainers.image.version="X.Y.Z"`
   - `docker-compose.yml` → **both** `fubsxploitapps/ion:${ION_VERSION:-X.Y.Z}` occurrences
   - `.env.deploy` → `ION_VERSION=X.Y.Z` (plus header comment if present)
   - `CHANGELOG.md` → new `## vX.Y.Z — YYYY-MM-DD` heading at top + entries
   - `SECURITY_ASSESSMENT.md` → bump `<!-- ion-doc:version=X.Y.Z -->` + `Assessment Date` + `Application Version`, update the compact **current-posture** table's `(vX.Y.Z)` version header (single cell — the values stay 0 unless a finding lands), and add a "Net-New Surfaces" paragraph if material. (The old 70-column per-version trend table was retired at v0.40.0; the checker only anchors on the `ion-doc:version` stamp.)

5. **Re-run the checker** — must now report PASS.

6. **Sanity grep for stragglers** — catches *prior* versions still hiding in the live files:
   ```
   grep -nE 'version *= *"<OLD>"|ION_VERSION:-<OLD>|__version__ *= *"<OLD>"|version-<OLD>-blue' \
     pyproject.toml docker-compose.yml src/ion/__init__.py Dockerfile README.md .env.deploy
   ```
   (Replace `<OLD>` with the previous version.) Expected: empty output.

7. **Confirm the commit shape.** Single commit message:
   ```
   chore(release): vX.Y.Z — version bumps + CHANGELOG + SECURITY_ASSESSMENT delta
   ```
   Applied at the very end of the release ritual, after feature commits land. Touches all 8 files.

8. **Image push** (after the tag lands and the image is built). ION is a
   Guarded Glass product: distribution is the org's PRIVATE repo only, since
   2026-08-20 (the public `ixion36/ion` was retired the same day; dual-push
   lasted exactly one release, v0.82.0). Any pulling host needs `docker login`;
   air-gapped installs keep using `docker save`/`load` tarballs.
   ```
   docker build -t fubsxploitapps/ion:X.Y.Z .
   docker push fubsxploitapps/ion:X.Y.Z
   ```
   Skipping the push is how three releases (0.80.3, 0.81.0, 0.81.2) once
   shipped as tags with no image — the push is part of the release, not an
   afterthought.

## What NOT to bump

Historical annotations in source comments like `# v0.29.1: added IP-fallback path` in `src/ion/services/pcap_analysis_service.py` are permanent feature markers, NOT version stamps. The drift checker ignores them; you should too.

Cross-references in `docs/*.md` ("first shipped in v0.22.0") are also historical and stay as-is.

## Failure modes

- **Checker fails on a file you didn't touch** — that's exactly the rot the skill exists to catch. Bump it.
- **`SECURITY_ASSESSMENT.md` format changed** — the checker uses a forgiving regex. If it fires "PATTERN NOT FOUND", inspect the file and either bump manually or update the regex in `check_versions.py`.
- **New shipping artifact introduced** — if a new file deserves the version stamp (a new compose variant, a new manifest), add it to `CANONICAL_FILES` in `check_versions.py` and document it in `CLAUDE.md`.
