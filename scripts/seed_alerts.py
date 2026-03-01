#!/usr/bin/env python3
"""Seed Elasticsearch with realistic SOC alerts for development/testing.

Usage:
    python scripts/seed_alerts.py [--url URL] [--count N]

Defaults:
    --url   http://localhost:9200
    --count 75
"""

import argparse
import json
import random
import sys
from datetime import datetime, timedelta, timezone

import httpx

# ── Alert Templates ──────────────────────────────────────────────────────

HOSTNAMES = [
    "dc01.corp.local", "dc02.corp.local", "web-srv-01", "web-srv-02",
    "mail-gw-01", "db-srv-01", "db-srv-02", "file-srv-01",
    "vpn-gw-01", "wks-PC0142", "wks-PC0287", "wks-PC0391",
    "wks-PC0455", "linux-jump-01", "kube-node-03", "dev-srv-01",
]

USERNAMES = [
    "jsmith", "admin", "svc_backup", "agarcia", "mchen",
    "SYSTEM", "root", "svc_sql", "tjohnson", "kpatel",
    "bwilliams", "svc_web", "dlee", "NT AUTHORITY\\SYSTEM",
]

SOURCE_IPS = [
    "10.0.1.15", "10.0.2.30", "192.168.1.100", "172.16.0.50",
    "10.0.3.201", "192.168.10.5", "10.10.20.42", "10.0.1.88",
]

EXTERNAL_IPS = [
    "185.220.101.34", "91.219.236.174", "45.155.205.233",
    "194.26.192.64", "23.129.64.218", "198.51.100.77",
    "203.0.113.42", "104.248.39.105", "159.89.173.104",
]

ALERT_TEMPLATES = [
    # ── Credential Access ────────────────────────────────────────────
    {
        "rule_name": "Brute Force Login Attempt Detected",
        "severity": "high",
        "message": "Multiple failed login attempts detected from {src_ip} targeting account '{user}' on {host} — {n} failures in 5 minutes",
        "tags": ["authentication", "brute-force"],
        "mitre": {"technique_id": "T1110", "technique_name": "Brute Force", "tactic": "Credential Access"},
        "fields": {"n": lambda: random.randint(15, 200)},
    },
    {
        "rule_name": "Credential Dumping via LSASS Memory Access",
        "severity": "critical",
        "message": "Process '{proc}' accessed LSASS memory on {host} — possible credential harvesting by user '{user}'",
        "tags": ["credential-access", "lsass", "mimikatz"],
        "mitre": {"technique_id": "T1003.001", "technique_name": "LSASS Memory", "tactic": "Credential Access"},
        "fields": {"proc": lambda: random.choice(["rundll32.exe", "procdump.exe", "unknown_tool.exe", "taskmgr.exe"])},
    },
    {
        "rule_name": "Kerberoasting Activity Detected",
        "severity": "high",
        "message": "Unusual volume of TGS requests for SPN-enabled accounts from {host} by '{user}' — {n} requests in 2 minutes",
        "tags": ["kerberoasting", "active-directory"],
        "mitre": {"technique_id": "T1558.003", "technique_name": "Kerberoasting", "tactic": "Credential Access"},
        "fields": {"n": lambda: random.randint(25, 150)},
    },
    # ── Lateral Movement ─────────────────────────────────────────────
    {
        "rule_name": "Lateral Movement via PsExec",
        "severity": "high",
        "message": "PsExec service installed on {host} from {src_ip} — user '{user}' initiated remote execution",
        "tags": ["lateral-movement", "psexec"],
        "mitre": {"technique_id": "T1021.002", "technique_name": "SMB/Windows Admin Shares", "tactic": "Lateral Movement"},
    },
    {
        "rule_name": "Suspicious RDP Connection from Internal Host",
        "severity": "medium",
        "message": "RDP session initiated from {src_ip} to {host} by '{user}' outside of normal business hours",
        "tags": ["rdp", "lateral-movement", "after-hours"],
        "mitre": {"technique_id": "T1021.001", "technique_name": "Remote Desktop Protocol", "tactic": "Lateral Movement"},
    },
    {
        "rule_name": "WMI Remote Process Execution",
        "severity": "high",
        "message": "WMI was used to execute a process remotely on {host} from {src_ip} by '{user}'",
        "tags": ["wmi", "lateral-movement"],
        "mitre": {"technique_id": "T1047", "technique_name": "Windows Management Instrumentation", "tactic": "Execution"},
    },
    # ── Persistence ──────────────────────────────────────────────────
    {
        "rule_name": "New Scheduled Task Created",
        "severity": "medium",
        "message": "Scheduled task '{task}' created on {host} by '{user}' — executes {proc}",
        "tags": ["persistence", "scheduled-task"],
        "mitre": {"technique_id": "T1053.005", "technique_name": "Scheduled Task", "tactic": "Persistence"},
        "fields": {
            "task": lambda: random.choice(["SystemHealthCheck", "WindowsUpdate_Svc", "ChromeUpdater", "OneDriveSync"]),
            "proc": lambda: random.choice(["powershell.exe -enc ...", "cmd.exe /c schtasks", "C:\\Temp\\update.exe"]),
        },
    },
    {
        "rule_name": "Registry Run Key Modification",
        "severity": "medium",
        "message": "Registry Run key modified on {host} by '{user}' — new entry points to '{path}'",
        "tags": ["persistence", "registry"],
        "mitre": {"technique_id": "T1547.001", "technique_name": "Registry Run Keys", "tactic": "Persistence"},
        "fields": {"path": lambda: random.choice([
            "C:\\Users\\Public\\svchost.exe", "C:\\ProgramData\\updater.exe",
            "C:\\Windows\\Temp\\runtime.exe", "%APPDATA%\\Microsoft\\helper.dll",
        ])},
    },
    # ── Defense Evasion ──────────────────────────────────────────────
    {
        "rule_name": "Windows Defender Exclusion Added",
        "severity": "high",
        "message": "New Windows Defender exclusion path added on {host} by '{user}': '{path}'",
        "tags": ["defense-evasion", "antivirus"],
        "mitre": {"technique_id": "T1562.001", "technique_name": "Disable or Modify Tools", "tactic": "Defense Evasion"},
        "fields": {"path": lambda: random.choice(["C:\\Temp", "C:\\ProgramData\\updates", "C:\\Users\\Public"])},
    },
    {
        "rule_name": "Event Log Cleared",
        "severity": "critical",
        "message": "Windows Security Event Log was cleared on {host} by '{user}'",
        "tags": ["defense-evasion", "log-tampering"],
        "mitre": {"technique_id": "T1070.001", "technique_name": "Clear Windows Event Logs", "tactic": "Defense Evasion"},
    },
    {
        "rule_name": "Timestomping Detected",
        "severity": "medium",
        "message": "File creation timestamp was modified on {host} — '{path}' now shows date from {n} days ago",
        "tags": ["defense-evasion", "timestomp"],
        "mitre": {"technique_id": "T1070.006", "technique_name": "Timestomp", "tactic": "Defense Evasion"},
        "fields": {
            "path": lambda: random.choice(["C:\\Windows\\Temp\\svc.exe", "C:\\Users\\Public\\data.dll"]),
            "n": lambda: random.randint(30, 365),
        },
    },
    # ── Exfiltration / C2 ────────────────────────────────────────────
    {
        "rule_name": "DNS Tunneling Suspected",
        "severity": "high",
        "message": "High volume of DNS TXT queries from {host} to suspicious domain '{domain}' — {n} queries in 10 minutes",
        "tags": ["exfiltration", "dns-tunneling", "c2"],
        "mitre": {"technique_id": "T1071.004", "technique_name": "DNS", "tactic": "Command and Control"},
        "fields": {
            "domain": lambda: random.choice(["xk3j.malware-c2.xyz", "data.evil-dns.net", "c2.b4dpanda.io", "exfil.darknet.ru"]),
            "n": lambda: random.randint(500, 5000),
        },
    },
    {
        "rule_name": "Outbound Connection to Known C2 Server",
        "severity": "critical",
        "message": "Host {host} established connection to known C2 IP {ext_ip}:443 — threat intel match (user: '{user}')",
        "tags": ["c2", "threat-intel", "ioc-match"],
        "mitre": {"technique_id": "T1071.001", "technique_name": "Web Protocols", "tactic": "Command and Control"},
    },
    {
        "rule_name": "Large Data Transfer to External IP",
        "severity": "high",
        "message": "Unusual outbound data transfer from {host} to {ext_ip} — {size}MB transferred over {mins} minutes by '{user}'",
        "tags": ["exfiltration", "data-transfer"],
        "mitre": {"technique_id": "T1048", "technique_name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"},
        "fields": {"size": lambda: random.randint(500, 5000), "mins": lambda: random.randint(5, 60)},
    },
    # ── Initial Access ───────────────────────────────────────────────
    {
        "rule_name": "Phishing Email with Malicious Attachment",
        "severity": "high",
        "message": "Malicious attachment '{file}' delivered to '{user}' on {host} from external sender — sandbox detonation flagged payload",
        "tags": ["phishing", "malware", "initial-access"],
        "mitre": {"technique_id": "T1566.001", "technique_name": "Spearphishing Attachment", "tactic": "Initial Access"},
        "fields": {"file": lambda: random.choice([
            "Invoice_Q4_2026.xlsm", "Resume_Updated.docm", "Shipping_Notice.pdf.exe",
            "Meeting_Notes.zip", "PaymentConfirmation.html",
        ])},
    },
    {
        "rule_name": "Suspicious VPN Login from Unusual Geolocation",
        "severity": "medium",
        "message": "VPN login for '{user}' from {ext_ip} ({country}) — user typically connects from United States",
        "tags": ["vpn", "impossible-travel", "initial-access"],
        "mitre": {"technique_id": "T1133", "technique_name": "External Remote Services", "tactic": "Initial Access"},
        "fields": {"country": lambda: random.choice(["Russia", "China", "North Korea", "Iran", "Romania", "Brazil"])},
    },
    # ── Execution ────────────────────────────────────────────────────
    {
        "rule_name": "Encoded PowerShell Command Execution",
        "severity": "high",
        "message": "PowerShell executed encoded command on {host} by '{user}' — decoded payload contains suspicious keywords",
        "tags": ["powershell", "encoded", "execution"],
        "mitre": {"technique_id": "T1059.001", "technique_name": "PowerShell", "tactic": "Execution"},
    },
    {
        "rule_name": "Suspicious Script Interpreter Spawned",
        "severity": "medium",
        "message": "Process '{proc}' spawned from Office application on {host} by '{user}'",
        "tags": ["execution", "macro", "office"],
        "mitre": {"technique_id": "T1059.005", "technique_name": "Visual Basic", "tactic": "Execution"},
        "fields": {"proc": lambda: random.choice(["wscript.exe", "cscript.exe", "mshta.exe", "powershell.exe"])},
    },
    # ── Discovery ────────────────────────────────────────────────────
    {
        "rule_name": "Internal Network Scan Detected",
        "severity": "medium",
        "message": "Host {host} ({src_ip}) scanned {n} internal IPs on ports 445,3389,22 — possible reconnaissance by '{user}'",
        "tags": ["discovery", "port-scan", "recon"],
        "mitre": {"technique_id": "T1046", "technique_name": "Network Service Discovery", "tactic": "Discovery"},
        "fields": {"n": lambda: random.randint(50, 500)},
    },
    {
        "rule_name": "AD Enumeration via BloodHound/SharpHound",
        "severity": "critical",
        "message": "Active Directory enumeration detected from {host} by '{user}' — LDAP query patterns match SharpHound collection",
        "tags": ["discovery", "bloodhound", "active-directory"],
        "mitre": {"technique_id": "T1087.002", "technique_name": "Domain Account", "tactic": "Discovery"},
    },
    # ── Impact ───────────────────────────────────────────────────────
    {
        "rule_name": "Ransomware File Encryption Activity",
        "severity": "critical",
        "message": "Rapid file modification and renaming detected on {host} — {n} files changed to '.locked' extension in under 2 minutes by '{user}'",
        "tags": ["ransomware", "encryption", "impact"],
        "mitre": {"technique_id": "T1486", "technique_name": "Data Encrypted for Impact", "tactic": "Impact"},
        "fields": {"n": lambda: random.randint(100, 10000)},
    },
    {
        "rule_name": "Shadow Copy Deletion",
        "severity": "critical",
        "message": "Volume shadow copies deleted on {host} via vssadmin.exe by '{user}' — potential ransomware precursor",
        "tags": ["ransomware", "shadow-copy", "impact"],
        "mitre": {"technique_id": "T1490", "technique_name": "Inhibit System Recovery", "tactic": "Impact"},
    },
    # ── Privilege Escalation ─────────────────────────────────────────
    {
        "rule_name": "User Added to Domain Admins Group",
        "severity": "critical",
        "message": "User '{user}' was added to the 'Domain Admins' group on {host} by '{admin}'",
        "tags": ["privilege-escalation", "domain-admins"],
        "mitre": {"technique_id": "T1078.002", "technique_name": "Domain Accounts", "tactic": "Privilege Escalation"},
        "fields": {"admin": lambda: random.choice(["admin", "svc_backup", "SYSTEM"])},
    },
    {
        "rule_name": "Token Impersonation Detected",
        "severity": "high",
        "message": "Process on {host} is impersonating token of '{user}' — possible privilege escalation via token manipulation",
        "tags": ["privilege-escalation", "token"],
        "mitre": {"technique_id": "T1134.001", "technique_name": "Token Impersonation/Theft", "tactic": "Privilege Escalation"},
    },
]


def generate_alert(template: dict, now: datetime, hours_back: int = 24) -> dict:
    """Generate a single alert document from a template."""
    host = random.choice(HOSTNAMES)
    user = random.choice(USERNAMES)
    src_ip = random.choice(SOURCE_IPS)
    ext_ip = random.choice(EXTERNAL_IPS)

    # Random timestamp within the lookback window
    offset_seconds = random.randint(0, hours_back * 3600)
    timestamp = now - timedelta(seconds=offset_seconds)

    # Resolve dynamic fields
    extra = {}
    for key, fn in template.get("fields", {}).items():
        extra[key] = fn()

    # Format message
    msg = template["message"].format(
        host=host, user=user, src_ip=src_ip, ext_ip=ext_ip, **extra
    )

    mitre = template.get("mitre", {})

    # Build ECS-compatible document
    doc = {
        "@timestamp": timestamp.isoformat(),
        "rule": {
            "name": template["rule_name"],
        },
        "event": {
            "action": template["rule_name"],
            "severity": template["severity"],
            "kind": "alert",
            "category": ["intrusion_detection"],
        },
        "message": msg,
        "severity": template["severity"],
        "status": random.choices(["open", "open", "open", "acknowledged"], weights=[5, 5, 5, 1])[0],
        "host": {"name": host},
        "user": {"name": user},
        "source": {"ip": src_ip},
        "destination": {"ip": ext_ip if "ext_ip" in template["message"] else None},
        "tags": template.get("tags", []),
    }

    if mitre:
        doc["threat"] = {
            "technique": {
                "id": mitre.get("technique_id"),
                "name": mitre.get("technique_name"),
            },
            "tactic": {
                "name": mitre.get("tactic"),
            },
        }

    # Clean out None values in destination
    if doc["destination"]["ip"] is None:
        del doc["destination"]

    return doc


def seed_alerts(es_url: str, username: str, password: str, count: int, index: str):
    """Seed alerts into Elasticsearch."""
    now = datetime.now(timezone.utc)

    print(f"Generating {count} alerts...")
    alerts = []
    for _ in range(count):
        template = random.choice(ALERT_TEMPLATES)
        alerts.append(generate_alert(template, now, hours_back=48))

    # Sort by timestamp descending so newest appear first
    alerts.sort(key=lambda a: a["@timestamp"], reverse=True)

    # Bulk index
    print(f"Indexing into {index} at {es_url}...")
    bulk_body = ""
    for alert in alerts:
        bulk_body += json.dumps({"index": {"_index": index}}) + "\n"
        bulk_body += json.dumps(alert) + "\n"

    client = httpx.Client(timeout=30.0)
    resp = client.post(
        f"{es_url}/_bulk",
        content=bulk_body,
        headers={"Content-Type": "application/x-ndjson"},
        auth=(username, password),
    )

    if resp.status_code >= 400:
        print(f"ERROR: {resp.status_code} — {resp.text[:500]}")
        sys.exit(1)

    result = resp.json()
    errors = sum(1 for item in result.get("items", []) if item.get("index", {}).get("error"))
    indexed = len(result.get("items", [])) - errors
    print(f"Done: {indexed} alerts indexed, {errors} errors")

    if errors:
        # Show first error for debugging
        for item in result["items"]:
            err = item.get("index", {}).get("error")
            if err:
                print(f"  First error: {err}")
                break

    # Refresh index for immediate visibility
    client.post(f"{es_url}/{index}/_refresh", auth=(username, password))
    print(f"Index refreshed. Alerts are now searchable.")


def main():
    parser = argparse.ArgumentParser(description="Seed Elasticsearch with test SOC alerts")
    parser.add_argument("--url", default="http://elasticsearch:9200", help="Elasticsearch URL")
    parser.add_argument("--username", default="elastic", help="ES username")
    parser.add_argument("--password", default="testpassword123", help="ES password")
    parser.add_argument("--count", type=int, default=75, help="Number of alerts to generate")
    parser.add_argument("--index", default="alerts-ixion", help="Target index name")
    args = parser.parse_args()

    seed_alerts(args.url, args.username, args.password, args.count, args.index)


if __name__ == "__main__":
    main()
