"""Append Collections 5 (IR Forensics), 6 (Advanced Malware), 7 (Forensic Tools)."""

chunk = r'''

IR_FORENSICS = [
    {
        "title": "Evidence Collection and Chain of Custody Best Practices",
        "tags": ["chain-of-custody", "evidence-collection", "dfir", "incident-response"],
        "content": """# Evidence Collection and Chain of Custody

## Legal Principles

- **Admissibility**: Evidence must be collected legally; unauthorized access voids it
- **Authenticity**: Must prove evidence hasn't been tampered (cryptographic hashing)
- **Completeness**: Collect all relevant evidence (not just what supports your hypothesis)
- **Reliability**: Document every step so results are reproducible

## Order of Volatility

Collect most volatile evidence first:

```
1. CPU registers, cache            (lost on reboot/shutdown)
2. Physical memory (RAM)           (lost on shutdown, may degrade on reboot)
3. Network connections, routing tables (may change rapidly)
4. Running processes               (lost on shutdown)
5. Open files and handles          (lost on shutdown)
6. System time and uptime          (for correlation)
7. Disk (logical then physical)    (persists but may be modified)
8. Remote logging (SIEM, proxy)    (persists, may be overwritten by rotation)
9. Physical configuration          (hardware info)
10. Archival media (backups)       (most persistent)
```

## Evidence Documentation Template

```
EVIDENCE ITEM FORM

Case Number:      IR-2025-0042
Evidence Item #:  001
Description:      Dell Latitude 5520 laptop, S/N XXXXXXXX
Location Found:   Analyst's desk, Building A Room 203
Time Found:       2025-03-15 14:15:00 UTC
Collected By:     Jane Smith (IR Lead)

Physical Description:
  Make/Model: Dell Latitude 5520
  S/N: XXXXXXXX
  Asset Tag: IT-12345
  Condition: Powered on, user logged in as DOMAIN\jsmith

Actions Taken:
  14:16 — Photographed system in place
  14:17 — Connected WinPmem USB drive
  14:18 — Executed: winpmem_mini_x64_rc2.exe memory.raw
  14:23 — Memory acquisition complete (16 GB)
  14:24 — Disk image started with FTK Imager
  15:45 — Disk image complete (512 GB)

Hashes:
  memory.raw:   SHA256 = abc123...
  disk.E01:     SHA256 = def456...
  MD5 (memory): 111222...
  MD5 (disk):   333444...

Chain of Custody:
  2025-03-15 15:45 — Transferred to locked evidence cabinet (Key #7)
  2025-03-16 09:00 — Retrieved by Bob Jones for analysis
  2025-03-16 17:00 — Returned to evidence cabinet
```

## Write Blocking

Always use hardware write blockers when imaging drives to prevent any modification.

```bash
# Hardware write blockers: Tableau T35689iu, WiebeTech UltraDock

# Software write blocking (Linux — less reliable, last resort):
blockdev --setro /dev/sdb     # Set block device read-only
# Verify:
blockdev --getro /dev/sdb     # Should return 1

# Mount read-only:
mount -o ro,noatime /dev/sdb1 /mnt/evidence
```

## Disk Imaging

```bash
# FTK Imager (Windows — GUI):
# File > Create Disk Image > Physical Drive
# Image type: E01 (EnCase) or RAW
# Hash: SHA256 + MD5

# dd (Linux — command line):
dd if=/dev/sdb of=disk.dd bs=4M conv=noerror,sync status=progress
# Hash verification:
md5sum disk.dd
sha256sum disk.dd

# dcfldd (enhanced dd):
dcfldd if=/dev/sdb of=disk.dd bs=4M hash=sha256 hashlog=disk_hash.txt

# ewfacquire (EnCase format):
ewfacquire /dev/sdb -t evidence_disk -c best -S 2G
# Creates: evidence_disk.E01, evidence_disk.E02, ...

# Verify image:
ewfverify evidence_disk.E01
```

## Network Evidence Preservation

```bash
# Capture current network state before isolation:
netstat -ano > netstat_before_isolation.txt     # Windows
ss -tulpn > ss_output.txt                       # Linux

# Firewall rule backup:
netsh advfirewall export firewall_rules.wfw     # Windows
iptables-save > iptables_backup.txt             # Linux

# ARP table:
arp -a > arp_table.txt

# Route table:
route print > route_table.txt                   # Windows
ip route show > ip_route.txt                    # Linux
```
""",
    },
    {
        "title": "Windows Triage Collection — KAPE, Velociraptor, CyLR",
        "tags": ["kape", "velociraptor", "cylr", "triage", "windows-forensics", "dfir"],
        "content": """# Windows Triage Collection

## KAPE (Kroll Artifact Parser and Extractor)

KAPE collects targeted artifact sets (Targets) and processes them through analysis modules (Modules).

```bash
# Basic collection (collect artifacts to C:\Triage):
kape.exe --tsource C: --tdest C:\Triage --target !BasicCollection

# Common targets:
# !BasicCollection — prefetch, event logs, registry, browser history
# KapeTriage       — comprehensive triage (recommended)
# WebServers       — IIS/Apache logs
# CloudAccounts    — cloud sync artifacts

# Collection + processing in one pass:
kape.exe --tsource C: --tdest C:\Triage --target KapeTriage \
    --mdest C:\Processed --module !EZParser

# Remote collection via UNC path (avoid writing to suspect disk):
kape.exe --tsource C: --tdest \\192.168.1.100\share\Triage --target KapeTriage

# List all available targets:
kape.exe --tlist

# List all available modules:
kape.exe --mlist
```

### KAPE Target Format

```yaml
# Example custom target: Malware Persistence
Description: Collect malware persistence artifacts
Author: SOC Team
Version: 1.0
Id: 12345678-1234-1234-1234-123456789012
RecreateDirectories: true
Targets:
  -
    Name: Run Keys
    Category: Registry
    Path: C:\Windows\System32\config
    FileMask: SOFTWARE
    Recursive: false
    IsDirectory: false
    SaveAsFileName: SOFTWARE
  -
    Name: Startup Folder
    Category: Persistence
    Path: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup
    FileMask: '*'
    Recursive: true
    IsDirectory: false
```

## Velociraptor

Velociraptor is an endpoint query and collection tool using VQL (Velociraptor Query Language).

```bash
# Install server (single binary):
velociraptor config generate -i > server.config.yaml
velociraptor --config server.config.yaml frontend -v

# Collect artifact from endpoint via GUI:
# Hunts > New Hunt > Add Artifacts > select artifacts
# Windows.KapeFiles.Targets
# Windows.System.Pslist
# Windows.Network.Netstat

# VQL queries in client:
velociraptor query "SELECT * FROM pslist()" --config client.config.yaml
velociraptor query "SELECT * FROM netstat()" --config client.config.yaml
```

### Key VQL Artifact Queries

```sql
-- List running processes with hashes:
SELECT Pid, Ppid, Name, CommandLine, Exe,
    hash(path=Exe).MD5 AS MD5,
    hash(path=Exe).SHA256 AS SHA256
FROM pslist()
WHERE Name =~ "(?i)(malware|suspicious)"

-- Find files modified in last hour:
SELECT FullPath, Mtime, Size
FROM glob(globs="C:\\**\\*.exe")
WHERE Mtime > now() - 3600

-- Check run keys:
SELECT Key.FullPath, Name, Data
FROM read_reg_key(globs="HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\**")

-- Check scheduled tasks:
SELECT Name, Command, Status
FROM scheduled_tasks()
WHERE Command =~ "(?i)(temp|appdata|programdata)"

-- Network connections with process info:
SELECT Pid, Name, Status, Laddr.IP, Laddr.Port, Raddr.IP, Raddr.Port
FROM netstat()
WHERE Status = "ESTABLISHED"
```

## CyLR

CyLR (Collect Your Live Response) is a lightweight triage collection tool.

```bash
# Collect to local directory:
CyLR.exe -o C:\Triage

# Collect to SFTP server (avoids writing to local disk):
CyLR.exe -u sftp_user -p sftp_pass -s 192.168.1.100 -port 22

# List what it collects:
CyLR.exe --listfiles

# Default collection includes:
# Event logs, registry hives, prefetch, browser artifacts, MFT, NTUSER.DAT
```

## Live System Commands (Manual Triage)

```powershell
# Quick manual triage script (run as administrator):
$output = "C:\Triage\$(hostname)_$(Get-Date -Format yyyyMMdd_HHmmss)"
New-Item -ItemType Directory -Path $output -Force

# System info
systeminfo > "$output\systeminfo.txt"
hostname > "$output\hostname.txt"
ipconfig /all > "$output\ipconfig.txt"

# Running processes
Get-Process | Select-Object PID, ProcessName, Path, CPU, StartTime |
  Export-Csv "$output\processes.csv"

# Network connections
netstat -ano > "$output\netstat.txt"

# Users and sessions
net user > "$output\users.txt"
query user > "$output\sessions.txt"
Get-LocalUser | Export-Csv "$output\local_users.csv"

# Persistence
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Run |
  Export-Csv "$output\run_keys_hklm.csv"
Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run |
  Export-Csv "$output\run_keys_hkcu.csv"
Get-ScheduledTask | Export-Csv "$output\scheduled_tasks.csv"
Get-Service | Export-Csv "$output\services.csv"

# Startup folder
Get-ChildItem "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" |
  Export-Csv "$output\startup_programs.csv"

# Hash running executables
Get-Process | Where-Object {$_.Path} |
  ForEach-Object {
    [PSCustomObject]@{
      PID = $_.Id; Name = $_.ProcessName; Path = $_.Path
      SHA256 = (Get-FileHash $_.Path -Algorithm SHA256 2>$null).Hash
    }
  } | Export-Csv "$output\process_hashes.csv"
```
""",
    },
    {
        "title": "Ransomware Investigation Playbook — Scoping, Containment, Recovery",
        "tags": ["ransomware", "incident-response", "playbook", "containment", "dfir"],
        "content": """# Ransomware Investigation Playbook

## Initial Detection and Scoping (0-30 minutes)

```bash
# Immediate questions to answer:
# 1. Which systems are encrypted?
# 2. When did encryption begin?
# 3. Is encryption still ongoing?
# 4. What is the ransomware family?
# 5. How did the attacker gain initial access?

# Quick scoping queries (Elastic/SIEM):
# Find encrypted files (unusual extensions):
process.command_line:(*vssadmin* OR *bcdedit*) AND NOT user.name:SYSTEM

# Find mass file operations:
event.action:"FileCreated" AND
file.extension:(lockbit OR conti OR ryuk OR encrypted OR locked)

# Find shadow copy deletion:
process.command_line:(*shadowcopy* OR *vssadmin*) AND event.action:"ProcessCreated"
```

## Containment (30-60 minutes)

```bash
# IMMEDIATE ISOLATION — disconnect from network first:
# Do NOT shut down (preserves memory artifacts)
# Do NOT reboot (may trigger additional encryption or delete logs)

# Isolation methods:
# 1. Physical network disconnection (preferred — pull cable, disable WiFi)
# 2. Firewall block at network level (ACL/VLAN isolation)
# 3. Endpoint isolation via EDR (CrowdStrike, Defender for Endpoint)

# PowerShell emergency isolation:
# Block all traffic except from IR workstation:
netsh advfirewall firewall add rule name="IR BLOCK ALL" dir=out action=block
netsh advfirewall firewall add rule name="IR ALLOW IR" dir=out action=allow remoteip=192.168.1.100
netsh advfirewall firewall add rule name="IR BLOCK IN" dir=in action=block
netsh advfirewall firewall add rule name="IR ALLOW IR IN" dir=in action=allow remoteip=192.168.1.100

# Identify patient zero and propagation:
# Check for lateral movement tools (PsExec, WMI, cobalt strike artifacts)
# Query logs for network shares accessed near encryption time
```

## Evidence Collection

```bash
# Order: memory first, then disk
# 1. Memory acquisition:
winpmem_mini_x64_rc2.exe \\evidence-server\share\IR-2025-001\hostname_memory.raw

# 2. KAPE triage:
kape.exe --tsource C: --tdest \\evidence-server\share\IR-2025-001\hostname_triage \
    --target KapeTriage

# 3. Disk image (if system can be taken offline):
# Attach write-blocker, image with FTK Imager

# 4. Ransom note (photograph and hash):
Get-ChildItem C:\Users\ -Recurse -Filter "*.txt" |
  Where-Object {$_.Name -match "decrypt|ransom|README|HOW_TO"} |
  Get-Content
```

## Ransomware Family Identification

```bash
# 1. Ransom note analysis:
# Format, payment address, contact method identify family

# 2. Encrypted file extension:
# .lockbit, .conti, .ryuk, .alphv, .darkside, .hive

# 3. ID Ransomware (online tool):
# https://id-ransomware.malwarehunterteam.com/
# Submit: ransom note text or encrypted file sample

# 4. Ransom note hash lookup on VirusTotal / Any.Run

# 5. Known decryptors:
# https://www.nomoreransom.org/ — community decryptors
# Check: Emsisoft, Kaspersky, Avast free decryption tools
```

## Recovery Assessment

```bash
# Identify encrypted scope:
Get-ChildItem C:\ -Recurse -File -ErrorAction SilentlyContinue |
  Where-Object {$_.Extension -in @('.lockbit','.conti','.encrypted')} |
  Measure-Object

# Check backup integrity:
# - When was last successful backup?
# - Are VSS snapshots available? (most ransomware deletes these)
vssadmin list shadows

# Check backup systems:
# - Were backup servers also hit?
# - Are backups offline/air-gapped?
# - Do backups predate the infection?

# Estimate recovery time:
# Small environment (100 endpoints): 2-5 days
# Enterprise (1000+ endpoints): 1-3 weeks
```

## Root Cause Investigation

```bash
# Most common initial access vectors for ransomware:

# 1. Phishing email with malicious attachment:
# Check email gateway logs for attachment delivery to patient zero
# Timeline: email delivery → macro execution → C2 beacon → ransomware

# 2. RDP brute force:
# Windows Event Log EventID 4625 (failed logon) spikes before compromise
Get-EventLog Security -InstanceId 4625 | Group-Object -Property MachineName | Sort Count -Desc

# 3. VPN/Citrix exploit:
# Check VPN authentication logs around infection time
# Look for: unusual geolocation, multiple failed attempts then success

# 4. Supply chain / MSP compromise:
# Ransomware deployed via RMM tool (ConnectWise, TeamViewer, Kaseya)
# Check for scheduled tasks or services created by RMM agents
```

## Post-Incident

```bash
# Indicators to share:
# 1. Ransomware binary hashes (MD5/SHA256)
# 2. C2 infrastructure (IPs, domains)
# 3. Mutex names
# 4. Dropped file paths and names
# 5. Registry persistence keys
# 6. Network IOCs (User-Agent, URI patterns)

# Share via:
# - ISAC (Information Sharing and Analysis Center)
# - MISP threat intel platform
# - FBI IC3 / CISA reporting

# Lessons learned:
# - Was this detected by security controls? If not, why?
# - What is the estimated dwell time?
# - What controls would have prevented this?
```
""",
    },
    {
        "title": "Cloud Forensics — AWS CloudTrail, Azure Activity Logs, GCP Audit",
        "tags": ["cloud-forensics", "aws", "azure", "gcp", "dfir", "incident-response"],
        "content": """# Cloud Forensics

## AWS CloudTrail

CloudTrail logs all API calls made to AWS services. Essential for any AWS incident.

```bash
# Enable CloudTrail (if not already enabled):
aws cloudtrail create-trail --name org-trail --s3-bucket-name my-cloudtrail-logs \
    --include-global-service-events --is-multi-region-trail
aws cloudtrail start-logging --name org-trail

# Query recent events (CLI):
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin \
    --start-time "2025-03-15T00:00:00Z" --end-time "2025-03-16T00:00:00Z"

# Query failed authentication:
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin \
    --start-time "2025-03-15T00:00:00Z" | \
    python3 -c "import json,sys; events=json.load(sys.stdin)['Events']; \
    [print(e['EventTime'],e.get('CloudTrailEvent','{}')) for e in events]"

# Query for privilege escalation indicators:
for event in AttachUserPolicy CreateAccessKey CreateUser PutRolePolicy; do
    aws cloudtrail lookup-events \
        --lookup-attributes AttributeKey=EventName,AttributeValue=$event
done

# Query IAM changes:
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventSource,AttributeValue=iam.amazonaws.com \
    --start-time "2025-03-15T00:00:00Z"
```

### CloudTrail Log Analysis with Athena

```sql
-- Create Athena table over CloudTrail S3 bucket:
CREATE EXTERNAL TABLE cloudtrail_logs (
    eventVersion STRING, userIdentity STRUCT<...>, eventTime STRING,
    eventSource STRING, eventName STRING, awsRegion STRING,
    sourceIPAddress STRING, requestParameters STRING, responseElements STRING
)
ROW FORMAT SERDE 'org.openx.data.jsonserde.JsonSerDe'
LOCATION 's3://my-cloudtrail-logs/AWSLogs/123456789012/CloudTrail/';

-- Find console logins from unusual IPs:
SELECT eventTime, userIdentity.userName, sourceIPAddress, responseElements
FROM cloudtrail_logs
WHERE eventName = 'ConsoleLogin'
  AND responseElements LIKE '%Success%'
  AND NOT regexp_like(sourceIPAddress, '^10\.|^192\.168\.|^172\.')
ORDER BY eventTime DESC;

-- Find IAM changes:
SELECT eventTime, userIdentity.arn, eventName, requestParameters
FROM cloudtrail_logs
WHERE eventSource = 'iam.amazonaws.com'
  AND eventName IN ('CreateUser','AttachUserPolicy','CreateAccessKey','PutRolePolicy')
ORDER BY eventTime;

-- Find data exfiltration (S3 GetObject in bulk):
SELECT DATE_TRUNC('hour', from_iso8601_timestamp(eventTime)) AS hour,
       userIdentity.arn, COUNT(*) AS get_count, SUM(requestParameters.contentLength) AS bytes
FROM cloudtrail_logs
WHERE eventName = 'GetObject'
GROUP BY 1, 2
HAVING COUNT(*) > 1000
ORDER BY bytes DESC;
```

## Azure Activity Logs

```bash
# Azure CLI — query activity logs:
az monitor activity-log list \
    --start-time "2025-03-15T00:00:00Z" \
    --end-time "2025-03-16T00:00:00Z" \
    --output json > azure_activity.json

# Filter by event category:
az monitor activity-log list \
    --start-time "2025-03-15T00:00:00Z" \
    --categories Security \
    --output json

# Azure AD sign-in logs (requires Azure AD P1/P2):
az ad audit-log list --filter "createdDateTime ge 2025-03-15T00:00:00Z"

# Microsoft Sentinel KQL queries:
# Unusual sign-in activity:
```

```kql
// Azure AD - Failed sign-ins from unusual locations
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType != "0"    // 0 = success
| summarize FailCount = count() by UserPrincipalName, Location, IPAddress
| where FailCount > 10
| order by FailCount desc

// Azure resource changes:
AzureActivity
| where TimeGenerated > ago(24h)
| where ActivityStatus == "Succeeded"
| where OperationName contains "write" or OperationName contains "delete"
| where Caller !startswith "automation" and Caller !startswith "azure-"
| project TimeGenerated, Caller, OperationName, ResourceGroup, Resource
| order by TimeGenerated desc
```

## GCP Cloud Audit Logs

```bash
# gcloud CLI — query audit logs:
gcloud logging read \
    'logName="projects/my-project/logs/cloudaudit.googleapis.com%2Factivity" AND
     timestamp >= "2025-03-15T00:00:00Z"' \
    --format json > gcp_audit.json

# Filter for IAM changes:
gcloud logging read \
    'logName:"cloudaudit.googleapis.com/activity" AND
     protoPayload.serviceName="iam.googleapis.com"' \
    --format json

# Filter for GCS data access:
gcloud logging read \
    'logName:"cloudaudit.googleapis.com/data_access" AND
     protoPayload.serviceName="storage.googleapis.com" AND
     protoPayload.methodName="storage.objects.get"' \
    --format json | python3 -c "
import json, sys
logs = json.load(sys.stdin)
for entry in logs:
    proto = entry.get('protoPayload', {})
    print(entry.get('timestamp'), proto.get('authenticationInfo',{}).get('principalEmail'), proto.get('resourceName'))
"
```

## Container/Kubernetes Forensics

```bash
# Pod execution history:
kubectl get events --all-namespaces --sort-by='.lastTimestamp' > k8s_events.txt

# Recent pod creates/deletes:
kubectl get events --all-namespaces -o json | \
    python3 -c "
import json, sys
events = json.load(sys.stdin)['items']
for e in events:
    if e['reason'] in ['Created','Killing','Pulled','Started']:
        print(e['lastTimestamp'], e['reason'], e.get('involvedObject',{}).get('name'))
"

# Check for privileged containers (escape risk):
kubectl get pods --all-namespaces -o json | \
    python3 -c "
import json, sys
pods = json.load(sys.stdin)['items']
for pod in pods:
    for container in pod['spec'].get('containers',[]):
        sc = container.get('securityContext',{})
        if sc.get('privileged') or sc.get('runAsRoot'):
            print('PRIVILEGED:', pod['metadata']['namespace'], pod['metadata']['name'], container['name'])
"
```
""",
    },
    {
        "title": "Forensic Report Writing — Structure, Evidence Presentation, Court-Ready",
        "tags": ["forensic-reporting", "dfir", "incident-response", "court-ready"],
        "content": """# Forensic Report Writing

## Report Types

| Report Type | Audience | Focus |
|---|---|---|
| Technical Examination Report | Legal team, opposing experts | Methodology, findings, evidence chain |
| Executive Summary | CISO, C-suite | Impact, risk, remediation status |
| Incident Report | SOC, IT, management | Timeline, affected systems, actions taken |
| Malware Analysis Report | Threat intel, engineering | IOCs, TTPs, detection signatures |

## Technical Report Structure

```
1. COVER PAGE
   - Case number, date, classification
   - Examiner name and credentials
   - Attorney/client (if legal proceeding)

2. EXECUTIVE SUMMARY (1-2 paragraphs)
   - What happened, when, scope of impact
   - Key findings in plain language

3. SCOPE AND METHODOLOGY
   - Systems examined
   - Tools used (name, version, hash)
   - Collection methods
   - Analysis environment

4. FINDINGS
   - Numbered findings with supporting evidence
   - Direct evidence vs. inference clearly labeled

5. TIMELINE
   - Chronological event sequence
   - Source of each timestamp noted

6. INDICATORS OF COMPROMISE
   - Hashes, IPs, domains, file paths, registry keys

7. CONCLUSIONS AND OPINIONS
   - What the evidence proves
   - Reasonable alternative explanations considered and addressed

8. APPENDICES
   - Raw data, screenshots, tool outputs
   - Chain of custody forms
   - Hash verification logs
```

## Writing Guidelines

### Objectivity and Precision

```
BAD:  "The attacker used PowerShell to download malware."
GOOD: "Process execution logs (Windows Event ID 4688) show powershell.exe
       executed with parameters '-EncodedCommand <base64 string>'
       (Appendix A, Event 12345). The decoded command downloads
       'payload.ps1' from hxxp://185[.]220[.]101[.]45/gate (Appendix B).
       This is consistent with an initial access download stage."
```

### Describing Evidence

```
AVOID:
  "The malware was obviously a Cobalt Strike beacon."

USE:
  "The file 'svchost32.exe' (SHA256: abc123...) matched 52 of 72
   antivirus signatures on VirusTotal (accessed 2025-03-16).
   Static analysis identified a Cobalt Strike beacon configuration
   using CobaltStrikeParser v1.4 (hash: def456...).
   The configuration revealed: C2 server 185.220.101.45:443,
   sleep interval 60 seconds, jitter 10%, HTTP GET profile."
```

## Timeline Documentation

```
TIMELINE FORMAT:

Date/Time (UTC)   | Source              | Event Description
------------------|---------------------|--------------------------------
2025-03-15 13:47  | Email gateway logs  | Phishing email received by jsmith@company.com
                  |                     | From: invoice@legitimate-looking.com
                  |                     | Attachment: Invoice_March.docx (hash: aabbcc)
2025-03-15 13:52  | EDR telemetry       | WINWORD.EXE (PID 3421) spawned
                  |                     | powershell.exe (PID 4567) with
                  |                     | -EncodedCommand [base64]
2025-03-15 13:53  | Proxy logs          | HTTP GET to hxxp://185.220.101.45/stage2.ps1
                  |                     | Source: WORKSTATION-01 (10.0.1.45)
                  |                     | Response: 200 OK, 45,234 bytes
2025-03-15 13:54  | Memory forensics    | svchost.exe (PID 1848): RWX VAD region
                  |                     | with MZ header (CS beacon per YARA)
2025-03-15 13:55  | Firewall logs       | TCP/443 ESTABLISHED: 10.0.1.45 → 185.220.101.45
                  | (persistent)        | Periodic ~60s intervals (beaconing pattern)
2025-03-15 14:02  | EDR telemetry       | mimikatz.exe executed (hash matches VirusTotal)
                  |                     | LSASS opened with PROCESS_VM_READ (EventID 4663)
```

## IOC Defanging for Reports

```
# Defang URLs and IPs to prevent accidental clicks/resolution:
http://evil.com      → hxxp://evil[.]com
https://evil.com     → hxxps://evil[.]com
185.220.101.45       → 185[.]220[.]101[.]45
evil@attacker.com    → evil@attacker[.]com

# Python defanging:
ioc = "http://evil.com/gate.php?id=1234"
defanged = ioc.replace("http", "hxxp").replace(".", "[.]")
print(defanged)
# hxxp://evil[.]com/gate[.]php?id=1234
```

## Quality Checklist

```
[ ] All timestamps include timezone (UTC preferred)
[ ] Every claim supported by specific evidence reference
[ ] Tool versions and hashes documented
[ ] Chain of custody forms complete
[ ] Hashes verified before and after acquisition
[ ] No unsupported opinions stated as facts
[ ] IOCs defanged in report
[ ] Classification markings on every page
[ ] Report reviewed by second analyst (peer review)
[ ] Methodology reproducible (another analyst could get same result)
```
""",
    },
    {
        "title": "Network Forensics in IR — PCAP Collection, NetFlow, Zeek Logs",
        "tags": ["network-forensics", "pcap", "netflow", "zeek", "dfir", "incident-response"],
        "content": """# Network Forensics in Incident Response

## Traffic Capture

```bash
# tcpdump — targeted capture:
tcpdump -i eth0 -w capture.pcap host 185.220.101.45  # Single host
tcpdump -i eth0 -w capture.pcap port 4444            # Single port
tcpdump -i eth0 -s 0 -w capture.pcap                 # Full packet capture

# Rotate captures (avoid single huge file):
tcpdump -i eth0 -G 3600 -w "capture_%Y%m%d_%H%M%S.pcap"  # New file every hour

# Wireshark capture filter:
# tcp port 4444 or tcp port 443 and host 185.220.101.45

# Network tap — passive capture without disturbing traffic:
# Hardware: Gigamon, Ixia, NETSCOUT
# Software: SPAN/mirror port on managed switch
```

## Zeek Network Security Monitor

```bash
# Run Zeek on captured PCAP:
zeek -r capture.pcap local.zeek

# Or on live interface:
zeek -i eth0 local.zeek

# Zeek generates structured logs (TSV format):
# conn.log      — all connections (src/dst/port/bytes/duration)
# http.log      — HTTP requests/responses
# ssl.log       — TLS connections (JA3/JA3S, server name, cert info)
# dns.log       — DNS queries and responses
# files.log     — files transferred (with MD5/SHA256)
# notice.log    — security notices
# weird.log     — unusual protocol behavior
```

### Zeek Log Analysis

```bash
# All outbound connections with high byte counts:
zeek-cut id.resp_h id.resp_p proto bytes_out service < conn.log | \
    awk '$4 > 10000000 {print}' | sort -k4 -rn | head -20

# HTTP with suspicious user agents:
zeek-cut ts id.orig_h id.resp_h uri user_agent < http.log | \
    grep -iE "curl|wget|python-requests|go-http|java/|libwww"

# DNS to unusual TLDs or high-entropy domains:
zeek-cut ts id.orig_h query qtype_name answers < dns.log | \
    awk '{if(length($3) > 50) print}'

# TLS to self-signed or suspicious certificates:
zeek-cut ts id.orig_h id.resp_h server_name subject ja3 ja3s < ssl.log | \
    grep -v "microsoft\|google\|amazon\|cloudflare"

# Files with known bad hashes:
zeek-cut md5 sha256 filename mime_type < files.log | \
    # Cross-reference with threat intel hash list
    grep -f known_bad_hashes.txt
```

## NetFlow/IPFIX Analysis

```bash
# NetFlow provides summary-level traffic data (no payload, just metadata)
# Collectors: ntopng, nfdump, SiLK, ElasticFlow

# nfdump queries:
# All flows to/from suspicious IP:
nfdump -R /var/flows/ -s record/bytes \
    "src ip 185.220.101.45 or dst ip 185.220.101.45"

# Large data transfers (> 100MB):
nfdump -R /var/flows/ "bytes > 100000000" -o "fmt:%ts %sa %da %sp %dp %byt %pkt"

# Beaconing detection (regular interval flows):
nfdump -R /var/flows/ -A srcip,dstip,dstport \
    "dst ip 185.220.101.45" -s record/flows

# Top talkers:
nfdump -R /var/flows/ -n 20 -s srcip/bytes

# DNS amplification/tunneling:
nfdump -R /var/flows/ -n 20 -s dstip/bytes "dst port 53"
```

## PCAP Analysis with TShark

```bash
# Extract all HTTP requests:
tshark -r capture.pcap -Y "http.request" -T fields \
    -e frame.time -e ip.src -e ip.dst -e http.request.method \
    -e http.host -e http.request.uri -e http.user_agent

# Extract DNS queries:
tshark -r capture.pcap -Y "dns.flags.response == 0" -T fields \
    -e frame.time -e ip.src -e dns.qry.name -e dns.qry.type

# Extract files from PCAP (HTTP objects):
tshark -r capture.pcap --export-objects http,exported_files/

# Extract TLS handshake details:
tshark -r capture.pcap -Y "tls.handshake.type == 1" -T fields \
    -e ip.src -e ip.dst -e tls.handshake.extensions_server_name

# Decrypt TLS with session key log:
# Browser export: SSLKEYLOGFILE=~/ssl_keys.log chromium
tshark -r capture.pcap -o tls.keylog_file:ssl_keys.log \
    -Y "http" -T fields -e http.request.full_uri -e http.file_data
```

## Evidence Preservation for Network Data

```bash
# Chain of custody for PCAPs:
sha256sum capture.pcap > capture.pcap.sha256
md5sum capture.pcap >> capture.pcap.sha256
echo "Captured by: $(whoami) on $(hostname) at $(date -u)" >> capture.pcap.sha256

# Compress and archive:
gzip -c capture.pcap > capture_$(date +%Y%m%d_%H%M%S).pcap.gz
sha256sum capture_*.pcap.gz > checksums.txt
```
""",
    },
    {
        "title": "Insider Threat Investigation — User Activity Reconstruction",
        "tags": ["insider-threat", "user-activity", "dfir", "incident-response"],
        "content": """# Insider Threat Investigation

## Investigation Principles

Insider threat investigations require strict adherence to HR policies and legal requirements. Always involve HR and legal counsel before beginning. Avoid alerting the subject prematurely.

## Evidence Sources for User Activity

```bash
# Windows User Activity Timeline:
# 1. Windows Event Logs (logon/logoff, process creation)
# 2. NTUSER.DAT (RecentDocs, TypedURLs, UserAssist)
# 3. ShellBags (folder navigation history)
# 4. LNK files (file access history)
# 5. Jump Lists (recently opened files per application)
# 6. Browser history (Chrome, Firefox, Edge)
# 7. Email (Exchange/O365 message trace, Outlook PST/OST)
# 8. USB device history (SetupAPI, USBSTOR registry)
# 9. DLP alerts (if deployed)
# 10. Clipboard history (Windows 10+)
```

## Logon/Logoff Analysis

```bash
# Extract logon events:
Get-EventLog Security -InstanceId 4624,4634,4647,4800,4801 |
    Select-Object TimeGenerated, EventID, Message |
    Export-Csv logon_events.csv

# EventID 4624: Successful logon
# EventID 4634: Account logoff
# EventID 4647: User-initiated logoff
# EventID 4800: Workstation locked
# EventID 4801: Workstation unlocked

# Remote logon events (lateral movement or remote access):
Get-EventLog Security -InstanceId 4624 |
    Where-Object {$_.Message -match "Logon Type:.*10|Logon Type:.*3"} |
    Select TimeGenerated, Message
# Type 3 = Network; Type 10 = Remote Interactive (RDP)

# KQL for Elastic:
event.code:4624 AND winlog.event_data.LogonType:("3" OR "10")
| stats count by winlog.event_data.TargetUserName, source.ip
```

## File Access Investigation

```bash
# Recent documents (NTUSER.DAT):
RECmd.exe -f NTUSER.DAT \
    --kn "Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" \
    --csv output\ --csvf recent_docs.csv

# Files accessed from specific directory (LNK files):
LECmd.exe -d "%APPDATA%\Microsoft\Windows\Recent\" --csv output\ |
    grep "C:\Sensitive_Project"

# USB-connected files:
LECmd.exe -d "%APPDATA%\Microsoft\Windows\Recent\" --csv output\ |
    grep "^E:\|^F:\|^G:\"  # Typical USB drive letters

# Shell history via ShellBags:
# ShellBagsExplorer.exe (GUI) or:
rip.pl -r NTUSER.DAT -p shellbags | grep "Sensitive"
```

## Email Investigation

```bash
# Office 365 Message Trace:
Get-MessageTrace -SenderAddress suspect@company.com \
    -StartDate 2025-03-01 -EndDate 2025-03-16 |
    Select ReceivedDateTime, SenderAddress, RecipientAddress, Subject, Status |
    Export-Csv email_trace.csv

# Check for external forwarding rules (common exfiltration method):
Get-InboxRule -Mailbox suspect@company.com |
    Where-Object {$_.ForwardTo -or $_.ForwardAsAttachmentTo -or $_.RedirectTo}

# Large email attachments sent externally:
Get-MessageTrace -SenderAddress suspect@company.com |
    Where-Object {$_.RecipientAddress -notlike "*@company.com"} |
    Select ReceivedDateTime, RecipientAddress, Subject

# PST/OST offline analysis:
# Tools: pst-extractor, libpff, Kernel PST Viewer
python3 pst_extract.py suspect.pst --output email_export/
```

## Data Staging and Exfiltration Detection

```bash
# Large file copies (DLP or EDR logs):
# Search for bulk file copy operations before resignation/incident

# Unusual external storage usage:
# USBSTOR registry changes near investigation timeframe
RECmd.exe -f SYSTEM --kn "ControlSet001\Enum\USBSTOR" --csv output\
# Cross-reference timestamps with subject's working hours

# Cloud sync upload spikes:
# DLP: flag large uploads to Dropbox, Google Drive, OneDrive, WeTransfer
# Proxy logs: bytes_out to cloud storage providers
grep -iE "dropbox.com|drive.google.com|onedrive.live.com|wetransfer.com" proxy_logs.txt | \
    awk '{print $1, $bytes_out_field}' | sort -k1

# Compressed archives in unusual locations:
# Suspect often stages data in ZIP/7z before exfiltration
Get-ChildItem C:\Users\suspect -Recurse -Include *.zip,*.7z,*.rar -ErrorAction SilentlyContinue |
    Select FullName, Length, CreationTime, LastWriteTime |
    Where-Object {$_.Length -gt 50MB}
```

## User Activity Timeline Reconstruction

```bash
# Build super timeline focused on suspect's activity:
log2timeline.py --storage-file user_timeline.plaso \
    --parsers "prefetch,mft,usnjrnl,winevtx,winreg,chrome_history,firefox_history,lnk,shellbags" \
    /mnt/suspect_disk/

# Filter to suspect's working hours and suspicious file paths:
psort.py -w user_activity.csv -o l2tcsv user_timeline.plaso \
    "user contains 'suspect_username' AND date >= '2025-03-10'"

# Focus on last week before departure/incident
```
""",
    },
    {
        "title": "Business Email Compromise — Investigation Methodology",
        "tags": ["bec", "email-forensics", "incident-response", "dfir"],
        "content": """# Business Email Compromise (BEC) Investigation

## BEC Overview

BEC involves compromised or spoofed business email accounts used for financial fraud, credential harvesting, or supply chain attacks.

## Common BEC Scenarios

| Scenario | Method | Target |
|---|---|---|
| CEO Fraud | Spoofed/compromised executive email | Finance team wire transfer |
| Vendor Email Compromise | Compromised vendor account | Payment redirection |
| W-2 Fraud | Executive impersonation | HR/payroll — employee tax forms |
| Attorney Impersonation | Law firm account compromise | Client fund transfer |
| Account Takeover | Credential phishing | O365/Gmail access |

## Initial Triage

```bash
# Office 365 — check if account was actually compromised:
# 1. Sign-in logs for suspicious activity:
Get-AzureADAuditSignInLogs -Filter "userPrincipalName eq 'victim@company.com'" |
    Select CreatedDateTime, IpAddress, Location, RiskLevel, Status |
    Where-Object {$_.Status.ErrorCode -eq 0} |  # Successful logins
    Export-Csv signins.csv

# 2. Check for suspicious inbox rules:
Get-InboxRule -Mailbox victim@company.com |
    Select Name, Enabled, ForwardTo, DeleteMessage, MoveToFolder, MarkAsRead |
    Format-Table -Wrap

# Common attacker rules:
# - Forward all email to external address
# - Delete emails from specific senders (hide responses)
# - Move replies to subfolder (victim doesn't see replies)

# 3. Check connected apps (OAuth grants):
Get-AzureADServicePrincipal -All $true |
    Where-Object {$_.ReplyUrls -like "*gmail.com*" -or $_.ReplyUrls -like "*protonmail*"}
```

## Email Header Analysis

```bash
# Extract and parse email headers:
# Full headers visible in Outlook: File > Properties

# Key header fields:
# Received: chain shows routing path (read bottom-up)
# Authentication-Results: SPF/DKIM/DMARC results
# X-Originating-IP: actual sender IP
# Message-ID: unique identifier for tracking

# SPF/DKIM/DMARC evaluation:
# Pass = legitimate send path; Fail = spoofed or misconfigured
# DMARC fail = either SPF or DKIM failed + alignment issue

# Python email header parser:
import email
from email import policy

with open("suspicious_email.eml", "rb") as f:
    msg = email.message_from_bytes(f.read(), policy=policy.default)

print("From:", msg["From"])
print("Reply-To:", msg["Reply-To"])
print("Return-Path:", msg["Return-Path"])
print("Authentication-Results:", msg["Authentication-Results"])
for header in msg.get_all("Received", []):
    print("Received:", header[:200])
```

## O365 Investigation via Microsoft Graph

```bash
# Microsoft Graph API — comprehensive O365 forensics:
# 1. Get access token
TOKEN=$(curl -X POST "https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token" \
    -d "client_id=<id>&client_secret=<secret>&scope=https://graph.microsoft.com/.default&grant_type=client_credentials" \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# 2. Get sign-in logs:
curl -H "Authorization: Bearer $TOKEN" \
    "https://graph.microsoft.com/v1.0/auditLogs/signIns?\\$filter=userPrincipalName eq 'victim@company.com'"

# 3. Get mailbox rules:
curl -H "Authorization: Bearer $TOKEN" \
    "https://graph.microsoft.com/v1.0/users/victim@company.com/mailFolders/inbox/messageRules"

# 4. Get email messages (search for specific content):
curl -H "Authorization: Bearer $TOKEN" \
    "https://graph.microsoft.com/v1.0/users/victim@company.com/messages?\\$search='wire transfer'"

# 5. List OAuth app grants:
curl -H "Authorization: Bearer $TOKEN" \
    "https://graph.microsoft.com/v1.0/users/victim@company.com/oauth2PermissionGrants"
```

## Evidence Preservation for BEC

```bash
# Microsoft Purview Compliance Center:
# 1. Place mailbox on Litigation Hold to prevent deletion
Set-Mailbox victim@company.com -LitigationHoldEnabled $true

# 2. Create eDiscovery search:
New-ComplianceSearch -Name "BEC Investigation" \
    -ExchangeLocation victim@company.com \
    -ContentMatchQuery "From:'attacker@external.com'"
Start-ComplianceSearch -Identity "BEC Investigation"

# 3. Export search results:
New-ComplianceSearchAction -SearchName "BEC Investigation" -Export

# 4. Enable audit log search (if not already):
Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true

# 5. Search unified audit log:
Search-UnifiedAuditLog -StartDate "2025-03-01" -EndDate "2025-03-16" \
    -UserIds victim@company.com \
    -Operations "MailboxLogin,Set-InboxRule,New-InboxRule" |
    Select CreationDate, UserIds, Operations, AuditData
```
""",
    },
]
'''

with open("C:/Users/Tomo/ixion/src/ion/data/kb_forensics_advanced.py", "a", encoding="utf-8") as f:
    f.write(chunk)
print("Collection 5 written. Lines:", open("C:/Users/Tomo/ixion/src/ion/data/kb_forensics_advanced.py", encoding="utf-8").read().count("\n"))
