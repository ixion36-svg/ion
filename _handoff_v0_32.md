# Handoff — ION v0.31.9 → next session

**Date:** 2026-05-14
**Released:** v0.31.9 (pushed to `main`, ixion36/ion:0.31.9 + latest on Docker Hub)
**Branch state:** `main` clean ahead of next work cycle.

---

## What landed this session (v0.31.2 → v0.31.9, 8 releases)

A multi-release Secure-by-Design closure run. Started with reorientation
after the memory + CLAUDE.md drift (memory was at v0.19.2, repo was at
v0.31.1), then chained closures and audit advances.

| Version | Headline | Audit movement |
|---|---|---|
| v0.31.2 | SQLEnum filter cleanup + regression guard (no net behaviour change; was misdiagnosed as a bug) | — |
| v0.31.3 | CSP nonce on every `<script>`/`<style>` block; CSP authority moved from nginx to FastAPI middleware | P11 narrowed (was: "no nonce"; now: "inline handlers still permitted via `script-src-attr 'unsafe-inline'`") |
| v0.31.4 | Event-delegation foundation + base.html migrated (7 inline handlers) | P11 progress |
| v0.31.5 | cases.html migrated (48 handlers) + helper extended with `$event` sentinel + per-event args + drag/drop | P11 progress |
| v0.31.6 | alerts.html migrated (194 handlers via new `tools/migrate_inline_handlers.py`); 4 new helper built-ins | P11 progress |
| v0.31.7 | training.html migrated (119 handlers); script patched to detect JS-source-escape edge case | P11 progress |
| v0.31.8 | **P17 CLOSED.** `python-jose → PyJWT`. CVE-2024-23342 dropped from resolved tree. `pip-audit --ignore-vuln` flag removed. | P17: Mostly Met → **Met** |
| v0.31.9 | **P1 PARTIAL → MOSTLY MET.** CONTRIBUTING.md + CODEOWNERS + security-reviewer agent + pre-commit hooks | P1: Partial → **Mostly Met** |

**Net new findings across all 8 releases:** 0C / 0H / 0M / 0L
(no new attack surface introduced)

---

## Secure-by-Design audit — current state (post-v0.31.9)

```
docs/SECURE_BY_DESIGN.md (revision 1.7)

Met        16  P2 P3 P4 P5 P6 P7 P8 P9 P10 P12 P14 P16 P17 P18 P19 P20
Mostly Met  3  P1 (single maintainer + 6 mitigations)
              P11 (CSP strict — inline handlers in 69 templates still pending)
              P13 (data-min audit pending)
Partial     1  P15 (branch protection PARTIAL APPLIED; signed commits pending)
Gap         0  —
```

---

## P15 status — paused mid-closure

**What's done:**

* **Tier 1 branch protection applied on `main`** via `gh api PUT
  /repos/ixion36-svg/ion/branches/main/protection`. Live now:
  * `required_linear_history: true`
  * `allow_force_pushes: false`
  * `allow_deletions: false`
  * `enforce_admins: false` (admin can still direct-push — single-maintainer workflow preserved)
  * `required_status_checks: null` (deferred to Tier 2, when a 2nd contributor joins)
  * `required_pull_request_reviews: null` (same)
  * `required_signatures: false` (deferred until signing is configured locally)
* **`gh` CLI tested** — auth working as `ixion36-svg` with `gist,
  read:org, repo` scopes. **`admin:ssh_signing_key` scope NOT granted** —
  needed to register signing keys via CLI. Either refresh the scope
  (`gh auth refresh -h github.com -s admin:ssh_signing_key`) or use the
  GitHub web UI to register the signing key.

**What's NOT done:**

* **Signed commits.** The SSH key found at `~/.ssh/id_ed25519.pub`
  (`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5...tomo@hetzner`) is the **wrong
  key** — it's for a different server (Hetzner), not the GitHub commit
  signing identity. **DO NOT use this key for GitHub commit signing.**
* The local git signing config I briefly applied (gpg.format=ssh,
  user.signingkey=~/.ssh/id_ed25519.pub, commit.gpgsign=true) was
  **fully reverted** at the end of this session. Verified empty via
  `git config --get gpg.format` etc. — all returned "(unset)".
* The `~/.config/git/allowed_signers` file was removed.
* The `required_signatures` branch-protection rule on GitHub was
  **not enabled** (would have rejected unsigned future commits).

### Resume P15 next session — exact steps

1. **Decide which SSH key to use for GitHub commit signing.** Either:
   * Create a new key dedicated to GitHub:
     ```bash
     ssh-keygen -t ed25519 -C "ixion36@gmail.com — github-signing" -f ~/.ssh/id_ed25519_github
     ```
   * Or use an existing key whose private half is on this Windows machine
     and isn't tied to another service.

2. **Register the public half as a Signing Key on GitHub:**
   * URL: https://github.com/settings/ssh/new
   * **Key type: Signing Key** (the dropdown — NOT Authentication Key)
   * Title: e.g. `tomo Windows — ION signing`
   * Paste the new pubkey

3. **Configure local git** (replace `<key-path>` with the chosen key,
   without the `.pub` suffix — git uses the private key to sign):
   ```bash
   git config --global gpg.format ssh
   git config --global user.signingkey <key-path>.pub
   git config --global commit.gpgsign true
   git config --global tag.gpgsign true

   mkdir -p ~/.config/git
   EMAIL=$(git config --get user.email)  # currently "tomo@example.com" repo-local
   printf '%s namespaces="git" %s\n' "$EMAIL" "$(cat <key-path>.pub)" > ~/.config/git/allowed_signers
   git config --global gpg.ssh.allowedSignersFile ~/.config/git/allowed_signers
   ```

4. **Verify with a test commit:**
   ```bash
   git commit --allow-empty -m "test: signed commit (will be discarded)"
   git log -1 --show-signature
   # Expected: "Good \"git\" signature for <EMAIL>"
   git reset --hard HEAD~1  # discard the test commit
   ```

5. **Push a real signed commit** (any release commit will do). On
   GitHub the commit should show a green "Verified" badge.

6. **Enable `required_signatures` on GitHub:**
   ```bash
   gh api --method POST repos/ixion36-svg/ion/branches/main/protection/required_signatures
   ```

7. **Update P15 audit body** in `docs/SECURE_BY_DESIGN.md`:
   * Status: Partial → **Met**
   * Audit summary recount: 17 Met / 2 Mostly Met / 1 Partial → wait,
     this becomes **17 / 2 / 0 / 0** (we'd be at 17 Met / 2 Mostly Met
     / 1 Partial only if some other principle slipped; otherwise
     check current state at resume time)

8. **Update SDLC §6.4** with the signing-key registration + protection
   rules.

9. **Update `CONTRIBUTING.md` §2.1** — add a signing-required note.

10. **Cut v0.31.10** (or whatever the next number is) — the release
    commit itself is the first signed commit and the test.

### Caveat: my future commits

Once signed commits are enforced, every commit including AI-pair-programmer
co-authored commits must be signed. The signature is on the local git
client side (yours), so this happens automatically once configured.
The `Co-Authored-By: Claude Opus...` trailer is content of the commit
message, unrelated to the signature.

---

## P11 status — in flight

```
4 templates migrated (368 inline handlers):
  base.html       (7)    v0.31.4
  cases.html     (48)    v0.31.5
  alerts.html   (194)    v0.31.6
  training.html (119)    v0.31.7

69 templates remaining (~650 inline onclick= + ~1,650 inline style=""):
  forensics.html  (73)   — next biggest, sibling to cases.html
  observables.html (51)  — already touched in v0.31.3 raw-block fix
  tools.html       (40)
  discover.html    (34)
  documents.html   (31)
  detection_engineering.html (31)
  threat_intel.html (23)
  template_form.html (23)
  playbooks.html   (22)
  ... 60 smaller templates
```

The mechanical migration script (`tools/migrate_inline_handlers.py`) handles
~95% of patterns. Each new template typically surfaces 0-2 new edge
cases for hand-fixing. The event-delegation helper at
`src/ion/web/static/js/event-delegation.js` has stabilised — no new
built-ins were needed across the alerts.html → training.html jump.

To resume P11: pick the next template, run `python
tools/migrate_inline_handlers.py src/ion/web/templates/<name>.html --dry-run`,
review skipped patterns, decide on hand-fixes, then run without
`--dry-run`. Browser-verify via Playwright, ship a release.

After ALL 73 templates are migrated, can flip CSP `script-src-attr 'none'`
and `style-src-attr 'none'` and P11 moves to Met.

---

## P13 status — not started

Data-minimisation audit. Walk the schema, identify:
* Stored fields that aren't actually used by any feature
* Fields with retention longer than necessary
* PII that could be hashed / redacted at storage time

Estimated effort: half-day audit + small follow-up commits.

---

## Outstanding work in working tree (NOT from this session)

The pre-session working tree had a lot of untracked / modified files
(spec_*, research_*, handoff_v0_26.md, backlog_v0_27.md, PDFs in
docs/, seed_test_data.py, tools/). NONE of these were touched by this
session. They remain in the working tree for separate triage.

```
git status --short | head -40
```

… will show the same set as at session start. The `_handoff_v0_32.md`
file (this one) is the only new untracked addition from this session;
everything else is committed.

---

## Memory updates

This handoff doc is the canonical state. Auto-memory
(`~/.claude/projects/.../memory/MEMORY.md`) has been updated alongside
this handoff with a v0.31.x summary entry so next session can orient
quickly even without reading this file.

---

## Recommended next session opener

Pick ONE of:

1. **Resume P15** — register a proper GitHub signing key, configure
   git, enable `required_signatures`. ~20 min total once the key is
   chosen. Closes P15 to **Met**.
2. **Continue P11** — forensics.html migration (~73 handlers, sibling
   to cases.html, low risk). ~30 min.
3. **P13 data-minimisation audit** — half-day. Produces a doc +
   small follow-up commits.

After all three, the SbD audit would be **17 Met / 2 Mostly Met / 0
Partial / 0 Gap** — only P11 (CSP strict — inline handlers in
remaining templates) and the structurally-unclosable P1 (single
maintainer) left as Mostly Met.
