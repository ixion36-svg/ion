# L3 Module 2 — Atomic Red Team Library Deep-Dive

_Authoring source-of-truth for `seed_courses.py` ship of L3 M2 in v0.12.8._

Audience: L3 detection-engineer / purple-team analyst. Prereq: L3 M1 (purple-team flow + IART installation).

## Module shape

8 lessons (7 reading + 1 quiz), 9 questions, ~17k words. Goes deeper than M1's lesson 1.4 (which covered IART basics) into atomic authoring, dependencies, and ecosystem.

## Learning objectives

1. Navigate the **Atomic Red Team repository structure** and find the right atomic for an arbitrary ATT&CK technique.
2. Read and modify the **`T<ID>.yaml` format** — atomic_tests, input_arguments, dependencies, executor, cleanup_command.
3. Author a **custom atomic** for an org-specific TTP not in the public library.
4. Build a **prereq dependency** that downloads / compiles / installs tooling without leaking it permanently.
5. Run **multi-platform atomics** (Windows / Linux / macOS) with platform-conditional logic.
6. Use the **MITRE Adversary Emulation Library** for full-chain actor emulation built on ART primitives.
7. Operate the **chocolatey / nuget cache** and the **CDN-cached download** layer that ART uses.
8. Apply the **safety harness**: dry-run mode, permission auditing, blast-radius checking.

## Lesson plan

### L2.1 — The Atomic Red Team repository structure
~2200 words. Top-level layout (`atomics/`, `Indexes/`, `bin/`, `docs/`). The `Indexes/Indexes-Markdown/` per-platform indexes (windows-index.md, linux-index.md, macos-index.md). The `atomic_indexes/Indexes-CSV/` machine-readable indexes used by IART and integrations. How to find an atomic: ATT&CK technique id → `atomics/T<ID>/T<ID>.yaml`. Cross-reference: ATT&CK Navigator overlay → multiple T-ids → ART repo lookup.

Worked: walk through `atomics/T1059.001/`. Show YAML (14 atomic_tests) + the supporting `src/` files + the `T1059.001.md` human-readable description.

Knowledge check: 1 SHORTANSWER — given a technique id, find the YAML path.

### L2.2 — The atomic_test YAML format
~2400 words. Full YAML schema:

```yaml
attack_technique: T1059.001
display_name: Command and Scripting Interpreter — PowerShell
atomic_tests:
  - name: Encoded PowerShell command
    description: |
      Multi-line description.
    supported_platforms:
      - windows
    input_arguments:
      payload:
        description: Base64-encoded PowerShell command
        type: string
        default: "JABwAGEAd…"
    dependencies:
      - description: PowerShell must be available
        prereq_command: |
          if (Get-Command powershell.exe -ErrorAction SilentlyContinue) { exit 0 } else { exit 1 }
        get_prereq_command: |
          # Recovery if missing — usually a no-op for built-in tools
    executor:
      name: command_prompt
      command: |
        powershell.exe -EncodedCommand #{payload}
      cleanup_command: |
        # No persistence; cleanup is a no-op
```

Field-by-field walkthrough. The `#{var}` interpolation. Multi-step `executor` patterns. Conditional cleanup. The supported_platforms gate.

Worked: read T1078.004 atomic 4 — Entra cloud-account abuse. Identify the input_arguments, the prereq, the executor, and what gets logged.

Knowledge check: 1 MULTI — pick valid YAML fields.

### L2.3 — Authoring a custom atomic for an org-specific TTP
~2400 words. Most threat profiles include sub-TTPs that aren't yet in public ART. Common cases: a vendor-specific exploitation path, a region-specific phishing technique, a sector-specific abuse pattern.

Walk through authoring the YAML from scratch:
1. Pick the technique + sub-technique it maps to.
2. Author the `name` and `description`.
3. Define input_arguments (variables) for any parameter you might tune.
4. Write the prereq commands.
5. Author the executor.
6. Author the cleanup.

Worked: a custom atomic for *T1078.004 — abusing a sector-specific service-principal misconfiguration*. Show the YAML, the prereq (validate the SP exists + has the required permission), the executor (issue the abuse API call), the cleanup (revoke the abused permission).

Submission to the public repo: PR conventions, the test-case requirements (must be reproducible by Red Canary's CI), the legal-review step (some org-specific atomics shouldn't be public).

Knowledge check: 1 SHORTANSWER — author a one-line `prereq_command` for "Sysmon must be installed".

### L2.4 — Dependency engineering
~2200 words. Atomics with non-trivial prereqs (download a binary, compile a tool, install a NuGet package). The `dependencies:` array structure with each entry having `description / prereq_command / get_prereq_command`.

Common dependency patterns:
- Download from a stable URL (chocolatey, GitHub release).
- Compile from source (rare; prefer pre-compiled).
- Install via package manager (apt / yum / chocolatey).
- Copy a file from `atomics/T<ID>/src/`.

The CDN-cached download layer: ART uses `https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/...` for hosted artefacts. IART caches downloaded artefacts under `%TEMP%\\atomic-red-team\\`.

Operational concerns: a prereq that downloads a binary at runtime adds latency (5-30s). For exercise reproducibility, consider pre-staging the binary on the test host and skipping the prereq.

Knowledge check: 1 SINGLE — pick the right dependency structure for "download Mimikatz from the public ART src/ folder".

### L2.5 — Multi-platform atomics; platform-conditional executors
~2000 words. ATT&CK techniques apply across OS; many atomics ship per-platform variants under one technique. The `supported_platforms` field gates which platform IART runs each test on.

Worked: T1003 LSASS / credential dump.
- Test 1 — Windows / sekurlsa::logonpasswords via Mimikatz.
- Test 2 — Windows / comsvcs.dll mini-dump.
- Test 8 — Linux / shadow file copy (T1003.008).
- Test 9 — macOS / dscacheutil dump.

Each variant has its own executor (PowerShell on Win, bash on Linux, sh on macOS). `Invoke-AtomicTest T1003 -TestNumbers 8` correctly routes to the Linux test if the host is Linux.

Cross-platform considerations: file path differences, command-shell differences, cleanup variants.

Knowledge check: 1 SINGLE — given a technique with cross-platform tests, predict which test runs on the host.

### L2.6 — MITRE Adversary Emulation Library
~2400 words. An ART-adjacent library, hosted by MITRE Engenuity CTID. Provides full-chain emulation plans for named adversaries, built on ART atomic primitives.

Repo: https://github.com/center-for-threat-informed-defense/adversary_emulation_library.

Each emulation plan:
- A named actor (FIN6, APT3, OilRig, Carbanak, Sandworm, etc.).
- Phases (initial access → persistence → exfil) following the actor's documented kill chain.
- Each phase maps to one or more ART atomics (referenced by ID).
- A scenario document (PDF) explaining the emulation flow.
- Detection notes from CTID's prior testing.

When to use: full-actor purple-team exercises that go beyond single TTPs. Useful for tabletop + technical hybrid exercises.

How to drive: read the YAML / Markdown / PDF for the chosen plan; queue the atomics in order; run via IART (one at a time, with verification between) or Caldera (chained, agent-based).

Worked: walk through the *FIN6* emulation plan top-to-bottom. The 12 phases, the ATT&CK techniques, the ART atomics each maps to.

Knowledge check: 1 SINGLE — given an adversary, find the plan in the library.

### L2.7 — Safety harness: dry-run, permission auditing, blast radius
~2000 words. Pre-execution sanity. Three habits:

1. **Dry-run mode**: `Invoke-AtomicTest T<ID> -TestNumbers <N> -ShowDetailsBrief` shows the executor + cleanup *without running them*. The L3 reads the dry-run output before executing.

2. **Permission audit**: the test host's user context. Some atomics need admin / SYSTEM; the host should be running with the *minimum* privilege necessary.

3. **Blast-radius check**: read the atomic's executor + cleanup. Confirm:
   - No data destruction outside the test sandbox.
   - No persistence outside the cleanup's scope.
   - No external network calls outside the authorised destinations.
   - No credential-leakage paths (writing creds to log files).

Common failures:
- An atomic's "cleanup" doesn't fully restore state — leaves residual files / keys / scheduled tasks.
- A prereq downloads from a URL that's now defunct, leaving an inconsistent state.
- A multi-step executor fails partway, leaving partial state, and cleanup wasn't designed for that case.

The safety harness:
- Document the dry-run inspection in the exercise log.
- Run the atomic on a *snapshot* host you can revert if cleanup fails.
- Validate the host's state pre-and-post via the SIEM (the host should look the same).

Knowledge check: 1 MULTI — pick valid safety-harness checks.

### L2.8 — Capstone quiz
4 questions covering: YAML schema, custom atomic authoring, multi-platform routing, safety harness.

## Quiz blueprint (9 questions)

- L2.1 — 1 SHORTANSWER (YAML path)
- L2.2 — 1 MULTI (YAML fields)
- L2.3 — 1 SHORTANSWER (prereq_command for Sysmon)
- L2.4 — 1 SINGLE (dependency structure)
- L2.5 — 1 SINGLE (cross-platform routing)
- L2.6 — 1 SINGLE (find adversary plan)
- L2.7 — 1 MULTI (safety harness)
- L2.8 — 2 capstone (custom atomic + multi-platform)

## References

- Atomic Red Team — https://github.com/redcanaryco/atomic-red-team.
- Invoke-AtomicRedTeam — https://github.com/redcanaryco/invoke-atomicredteam.
- MITRE Adversary Emulation Library — https://github.com/center-for-threat-informed-defense/adversary_emulation_library.
- Red Canary blog — atomic-authoring guides.

---

_Implementation: append `mod2 = _add_module(...)` after the existing M1 quiz, before `return course`. Update print to "2 modules, 16 lessons"._
