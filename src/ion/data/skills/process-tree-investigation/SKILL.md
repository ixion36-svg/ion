---
name: process-tree-investigation
description: Reasoning about process parent-child chains, command-line context, and integrity-level shifts during endpoint investigations.
when_to_use: |
  Apply when the alert is endpoint-side and surfaces a process event — Sysmon
  Event ID 1 / 4688, EDR ProcessCreate, comsvcs.dll mini-dumps, mshta /
  rundll32 / regsvr32 LOLBin chains. Apply when the analyst needs to walk the
  parent-process chain, distinguish legitimate parent contexts (e.g.
  WerFault.exe under svchost.exe is benign) from suspicious ones (e.g.
  powershell.exe under winword.exe is the phishing fingerprint).
tags:
  - endpoint
  - sysmon
  - process-tree
  - lolbin
matches_rule_groups:
  - sysmon
  - endpoint
  - edr
  - process
matches_techniques:
  - T1059
  - T1059.001
  - T1059.003
  - T1059.005
  - T1003
  - T1003.001
  - T1055
  - T1218
  - T1547.001
---

# Process-tree investigation

Endpoint investigations live in process trees. The L1's first reflex when an
alert surfaces a process event is to walk the parent chain — the answer is
usually three hops away.

## Field reference (ECS / Sysmon)

| Field | Source | What it carries |
|---|---|---|
| `process.name` | Sysmon 1 / 4688 | Image filename of the spawned process |
| `process.executable` | Sysmon 1 | Full path on disk (catches DLL-side-load via path-vs-name divergence) |
| `process.command_line` | Sysmon 1 | The launch arguments — load-bearing for nearly every endpoint rule |
| `process.parent.name` | Sysmon 1 / 4688 | Spawning process — three-hop chain reads |
| `process.parent.executable` | Sysmon 1 | Parent's full path |
| `process.entity_id` | Sysmon | Unique process id (use to walk the tree) |
| `process.hash.sha256` | Sysmon | Image hash; pivot to VT / sandbox |
| `winlog.event_data.IntegrityLevel` | Sysmon 1 | Low / Medium / High / System — escalation indicator |

## The three-hop walk

When an alert surfaces a process X, walk:
1. **X's parent** — what spawned X?
2. **X's grandparent** — what spawned the parent?
3. **X's great-grandparent** — usually the root of a chain (winlogon, services, explorer)

Fast pivot in ES|QL:

```
FROM logs-windows.sysmon-*
| WHERE process.entity_id == "<X's pid>" OR process.parent.entity_id == "<X's pid>"
   OR process.entity_id == "<X's parent pid>"
| SORT @timestamp ASC
| KEEP @timestamp, process.name, process.command_line, process.parent.name, host.name
```

For the M3 / M4 worked patterns: most endpoint compromises show a clear
"unusual parent" anomaly within 3 hops.

## Common parent-context patterns

### Legitimate (don't escalate)

| Process | Parent | Context |
|---|---|---|
| `WerFault.exe` | `svchost.exe` | Windows error reporting; benign |
| `taskhostw.exe` | `svchost.exe` | Scheduled task host; benign |
| `werfault.exe` | `csrss.exe` | Crash dump |
| `RuntimeBroker.exe` | `svchost.exe` | UWP runtime; benign |
| `MsMpEng.exe` | `services.exe` | Defender; benign |

### Suspicious (escalate)

| Process | Parent | Why suspicious |
|---|---|---|
| `powershell.exe` | `winword.exe` / `excel.exe` / `outlook.exe` | Phishing payload — Office macro spawning shell |
| `cmd.exe` | `mshta.exe` | LOLBin chain — mshta as living-off-the-land launcher |
| `cmd.exe` | `wmiprvse.exe` | WMI lateral movement (T1021.006) or WMI persistence (T1546.003) |
| `<any>` | `lsass.exe` | LSASS hosting code — often credential-dumping injection |
| `regsvr32.exe` | `winword.exe` | Bypassed AppLocker via signed binary |
| `rundll32.exe` | `services.exe` | Suspicious; expect specific DLL targets |

The key reasoning: *legitimate spawn parents are stable across the fleet*. A
1-month-old observation showing `cmd.exe` under `mshta.exe` is the same
fingerprint as a fresh alert showing the same — the pattern is durable.

## Integrity level shifts

`winlog.event_data.IntegrityLevel` shifts during privilege escalation. The
chain to watch:

- Low (browser sandbox / app container) →
- Medium (standard user) →
- High (elevated user) →
- System (SYSTEM)

A child process at a higher integrity level than its parent indicates UAC
bypass or token impersonation (T1134). Sysmon 1 captures this directly.

## Command-line context

Beyond the binary's name, the *command line* is what makes a rule firing
useful. Two patterns:

1. **Encoded payloads** — `-EncodedCommand <base64>`, `-enc <base64>`.
   Decode the base64 to see what the actual command is. Sometimes obfuscated
   further (string concatenation, char codes); see Daniel Bohannon's *Invoke-
   Obfuscation* for the techniques.

2. **LOLBin invocation patterns** — `mshta vbscript:...`, `regsvr32 /u /s /n /i:http://...`,
   `rundll32 url.dll,FileProtocolHandler ...`. LOLBAS catalogues the
   well-known ones; pattern-match the alert's command line against LOLBAS.

## Integration with the four-tier framework

When investigating an endpoint alert:
1. **Tier-1 check** — did the rule fire on this exact pattern? If yes, score.
2. **Tier-2 check** — if no rule fired, search Sysmon 1 for the parent / child
   pattern manually; if found, the gap is a missing rule (detection-eng backlog).
3. **Tier-3 check** — if `process.command_line` is empty, the parser / Sysmon
   config doesn't capture it (SIEM-team backlog; ProcessCreationIncludeCmdLine
   registry switch isn't set).
4. **Tier-4 check** — if no Sysmon data at all for this host, the agent isn't
   deployed (platform backlog).

The L1's reflex on every process-event alert: walk three hops; pivot to
LOLBAS for the launching binary; check command-line decode if encoded.

## References

- LOLBAS: https://lolbas-project.github.io/
- Sysmon configuration: https://github.com/SwiftOnSecurity/sysmon-config
- ION L1 Module 3 (Windows Event Logs); L3 Module 2 (Atomic Red Team).
