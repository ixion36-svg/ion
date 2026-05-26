<!-- ion-doc:type=CONTRIBUTING -->
<!-- ion-doc:title=Contributing to ION -->
<!-- ion-doc:subtitle=Security-first review expectations, PR template, release ritual pointers -->
<!-- ion-doc:version=0.31.10 -->
<!-- ion-doc:classification=PUBLIC -->
<!-- ion-doc:owner=ION Maintainer (ixion36) -->
<!-- ion-doc:audience=Future contributors, external auditors, anyone preparing a PR -->
<!-- ion-doc:date=2026-05-26 -->

# Contributing to ION

ION is a single-maintainer project today, but every change goes
through a deliberate security review. This file codifies the
expectations so a future contributor or external auditor sees the
same policy applied consistently.

> **TL;DR.** Sign your commits (SSH or GPG — `main` enforces
> `required_signatures=true`), read `docs/SECURE_BY_DESIGN.md`,
> walk your diff against the 20 principles before submitting,
> update `SECURITY_ASSESSMENT.md` if your change introduces new
> attack surface, run the pre-commit hooks (`pre-commit install`
> then `pre-commit run --all-files`), and ship a PR with a clear
> "why" in the title.

## 1. Read these before opening a PR

| Doc | Why |
|---|---|
| [`docs/SECURE_BY_DESIGN.md`](docs/SECURE_BY_DESIGN.md) | The 20 principles every change is reviewed against |
| [`docs/DEVELOPMENT_LIFECYCLE.md`](docs/DEVELOPMENT_LIFECYCLE.md) | Phase-by-phase SDLC; release ritual; SECURITY_ASSESSMENT.md authoring guidance |
| [`CHANGELOG.md`](CHANGELOG.md) (top 5 entries) | The current shape of "what a good commit looks like" |
| [`SECURITY.md`](SECURITY.md) | Vulnerability reporting; do NOT open a public PR for a known CVE |

## 2. Before you commit

### 2.1 Sign your commits

`main` enforces `required_signatures=true` via GitHub branch
protection (v0.31.10). Unsigned commits are rejected at push time.
Set up commit signing once per workstation:

```bash
# 1. Generate a dedicated signing key (ed25519). No passphrase if
#    you rely on workstation disk encryption; otherwise wrap with
#    ssh-agent.
ssh-keygen -t ed25519 -C "<your-email> - GitHub signing" -f ~/.ssh/id_ed25519_github

# 2. Register the public half on GitHub as a Signing Key:
#    https://github.com/settings/ssh/new
#    Set "Key type" dropdown to "Signing Key" (NOT Authentication Key).
cat ~/.ssh/id_ed25519_github.pub  # paste this into GitHub

# 3. Configure git to sign with that key
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519_github.pub
git config --global commit.gpgsign true
git config --global tag.gpgsign true

# 4. Configure allowed_signers so `git verify-commit` works locally
mkdir -p ~/.config/git
EMAIL=$(git config --get user.email)
printf '%s namespaces="git" %s\n' "$EMAIL" \
  "$(cat ~/.ssh/id_ed25519_github.pub)" \
  > ~/.config/git/allowed_signers
git config --global gpg.ssh.allowedSignersFile ~/.config/git/allowed_signers

# 5. Verify on the next commit
git commit --allow-empty -m "test: signature probe"
git log -1 --show-signature   # expects "Good \"git\" signature for <EMAIL>"
git reset --soft HEAD~1       # discard the test (soft preserves working tree)
```

The committer email used in `git config user.email` must match an
email verified on your GitHub account, or use the GitHub noreply
form (`<userid>+<login>@users.noreply.github.com`), which is
auto-verified. Otherwise GitHub renders the commit "Unverified" even
though the signature is technically valid.

GPG signing also works if you prefer — set `gpg.format=openpgp` and
register the public key under "GPG keys" on GitHub. The
branch-protection rule accepts both SSH and GPG signatures.

### 2.2 Run pre-commit hooks

ION ships a `.pre-commit-config.yaml` with the same checks CI runs.
Install once per workstation:

```bash
pip install pre-commit
pre-commit install
```

After that, every `git commit` runs:

- `ruff` — style + import sort + safety lint
- `bandit -r src/ --skip B602,B608,B101 -lll` — high-severity SAST
- `pip-audit --vulnerability-service osv --strict` — SCA against the
  resolved dependency tree

These are the same gates CI enforces — running them locally catches
issues at the workstation rather than after push. If a hook complains,
fix the issue and re-commit; do not `--no-verify`.

### 2.3 Walk the Secure by Design principles

For substantive changes (anything beyond a typo fix), walk your diff
against the 20 principles in `docs/SECURE_BY_DESIGN.md` and answer:

- **P4 Establish context** — what data does this change handle, and
  who can trigger it?
- **P5 Defense in depth** — are auth checks at the route AND service
  layer (TOCTOU rule)?
- **P6 Least privilege** — does the change require a new permission,
  or fit an existing role?
- **P7 Secure defaults** — does any new config default insecure?
- **P11 Don't trust input** — every user-supplied value validated /
  parameterised / sanitised?
- **P12 Make detection easier** — is the behaviour audit-logged?
- **P14 Clean code** — `ruff check src/` clean? Existing patterns
  followed (not new abstractions)?
- **P17 Eliminate vulnerability classes** — could this whole class
  of bug be made unreachable rather than patched per-instance?

You can invoke the AI pair-programmer's `security-reviewer` agent
to walk the diff against the full 20:

```
/agents security-reviewer
```

(See `.claude/agents/security-reviewer.md` for what it checks. The
agent reports findings; the human author decides what to address.)

### 2.4 Update SECURITY_ASSESSMENT.md if you touch attack surface

The release commit appends a delta block to `SECURITY_ASSESSMENT.md`
covering:

- **Net-new surfaces** introduced (new endpoints, new file uploads,
  new external integrations)
- **Net-removed surfaces** (deleted endpoints, decomissioned features)
- **Severity tally for this release** (e.g. `0C / 0H / 0M / 0L`)

The block lives under the "Per-Release Delta" section. Copy the
format of the most recent release entry.

## 3. Commit message conventions

ION uses conventional-commit prefixes:

| Prefix | When to use |
|---|---|
| `feat(<scope>):` | New user-facing capability |
| `fix(<scope>):` | Bug fix |
| `chore(release):` | Version-bump commit only (mechanical) |
| `chore(<scope>):` | Non-feature maintenance (dep bump, CI tweak, etc.) |
| `docs(<scope>):` | Doc-only change |
| `test(<scope>):` | Test-only change |
| `refactor(<scope>):` | Behaviour-preserving code reshape |

Body should answer "why this change?" in 2-5 lines. Files touched and
test coverage are visible in the diff — the message exists to capture
intent and any non-obvious constraint.

The AI pair-programmer signs every co-authored commit with a
`Co-Authored-By:` trailer naming the model and version. Keep that
trailer when the AI helped author or substantially review the change.

## 4. Release ritual

ION releases bump 8 files in lockstep. Run the guided ritual:

```
/release-bump
```

(Skill at `.claude/skills/release-bump/`.) The release-checker
agent (`.claude/agents/release-checker.md`) validates lockstep
before the commit lands.

Patch releases (`X.Y.Z+1`) are for fixes; minor releases (`X.Y+1.0`)
are for new capability. Major releases (`X+1.0.0`) are for breaking
changes — and ION's compatibility surface includes its REST API,
DB schema migrations, and the `ion.web.server:app` Python import.

After the commit, the release-checker walks:

1. The 8 version files are in lockstep.
2. `CHANGELOG.md` has a fresh entry with a date.
3. No stragglers from the previous version remain.
4. `SECURITY_ASSESSMENT.md` has a column for the new version.
5. Working tree is clean.

Then build + push:

```bash
docker build --pull --no-cache -t ixion36/ion:X.Y.Z -t ixion36/ion:latest .
docker push ixion36/ion:X.Y.Z
docker push ixion36/ion:latest
```

The `--pull --no-cache` is load-bearing — without it, the base
image (`python:3.14-slim`) stays at the digest from your previous
build, and any Debian system-package patches published since don't
land in the new image. Skipping this is how a "clean" rebuild can
ship yesterday's CVEs.

## 5. The single-maintainer pattern (P1 audit context)

ION is currently maintained by one human + an AI pair-programmer.
The Secure by Design principle "security is everyone's concern" (P1)
literally requires multiple humans, so ION cannot reach **Met** on
this principle without onboarding a second maintainer or operating
in a customer environment with a Designated Security Officer.

The mitigations encoded in this repo bring P1 to **Mostly Met**:

1. **AI pair-programmer reviews every change.** The maintainer
   author + AI reviewer pattern is recorded in
   `docs/DEVELOPMENT_LIFECYCLE.md` §6.3 and §6.4. The AI's role
   is captured in `CLAUDE.md` and the focused agents under
   `.claude/agents/`.
2. **Pre-commit hooks** (this file's §2.1) — catch the mechanical
   class of issues at the workstation.
3. **`security-reviewer` agent** (`.claude/agents/security-reviewer.md`) —
   walks the diff against the 20 SbD principles before push.
4. **Per-release `SECURITY_ASSESSMENT.md` delta** — formalised
   hostile re-read of the diff documenting every new / removed
   attack surface (§2.3).
5. **External SCA + SAST in CI** — `pip-audit`, `bandit`, `ruff`
   on every push (`.github/workflows/test.yml`).
6. **`CODEOWNERS`** — codifies review responsibility for when a
   second contributor joins; pairs with branch-protection rules
   (P15 — Partial; see `docs/SECURE_BY_DESIGN.md`).

These reduce but do not eliminate the single-maintainer risk. For
higher-assurance deployments, see `docs/DEVELOPMENT_LIFECYCLE.md`
§6.4's "Designated Security Officer" pattern.

## 6. Questions

- Open an issue (non-security questions).
- For security vulnerabilities, see `SECURITY.md` — do **not** open
  a public issue or PR.
