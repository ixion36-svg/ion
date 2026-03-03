"""Seed realistic SOC alerts into Elasticsearch for testing."""

import requests
import json
import random
from datetime import datetime, timedelta

ES_URL = "http://127.0.0.1:9200"
AUTH = ("elastic", "DocforgeTest2025")
INDEX = "alerts-ion"

def main():
    now = datetime.utcnow()

    # Delete existing index
    try:
        r = requests.delete(f"{ES_URL}/{INDEX}", auth=AUTH, timeout=10)
        print(f"Delete index: {r.status_code}")
    except Exception as e:
        print(f"Delete: {e}")

    # Create index with mapping
    mapping = {
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
                "destination.geo": {
                    "properties": {
                        "country_name": {"type": "keyword"},
                        "city_name": {"type": "keyword"},
                        "location": {"type": "geo_point"},
                    }
                },
                "severity": {"type": "keyword"},
                "status": {"type": "keyword"},
                "tags": {"type": "keyword"},
                "process.name": {"type": "keyword"},
                "process.pid": {"type": "integer"},
                "file.path": {"type": "keyword"},
                "file.hash.sha256": {"type": "keyword"},
                "url.full": {"type": "keyword"},
                "threat.technique.id": {"type": "keyword"},
                "threat.technique.name": {"type": "keyword"},
                "threat.tactic.name": {"type": "keyword"},
            }
        }
    }

    r = requests.put(f"{ES_URL}/{INDEX}", json=mapping, auth=AUTH, timeout=10)
    print(f"Create index: {r.status_code}")

    # --- Reference data ---
    hosts = [
        ("WKS-ANALYST01", "10.10.20.101", "Windows 11"),
        ("WKS-ANALYST02", "10.10.20.102", "Windows 11"),
        ("SRV-DC01", "10.10.10.10", "Windows Server 2022"),
        ("SRV-WEB01", "10.10.30.50", "Ubuntu 22.04"),
        ("SRV-DB01", "10.10.30.60", "RHEL 9"),
        ("SRV-MAIL01", "10.10.30.70", "Windows Server 2022"),
        ("WKS-ENG01", "10.10.20.201", "macOS 14"),
        ("FW-EDGE01", "10.10.1.1", "PAN-OS 11"),
        ("SRV-FILE01", "10.10.30.80", "Windows Server 2022"),
        ("WKS-HR01", "10.10.20.150", "Windows 11"),
    ]

    users = [
        "jsmith", "agarcia", "mwilliams", "tjohnson", "klee",
        "rpatel", "SYSTEM", "svc_backup", "admin", "dchen",
    ]

    geos = [
        {"country_name": "Russia", "city_name": "Moscow", "location": {"lat": 55.75, "lon": 37.62}},
        {"country_name": "China", "city_name": "Beijing", "location": {"lat": 39.90, "lon": 116.40}},
        {"country_name": "United States", "city_name": "New York", "location": {"lat": 40.71, "lon": -74.01}},
        {"country_name": "Brazil", "city_name": "Sao Paulo", "location": {"lat": -23.55, "lon": -46.63}},
        {"country_name": "Germany", "city_name": "Berlin", "location": {"lat": 52.52, "lon": 13.41}},
        {"country_name": "Iran", "city_name": "Tehran", "location": {"lat": 35.69, "lon": 51.39}},
        {"country_name": "North Korea", "city_name": "Pyongyang", "location": {"lat": 39.02, "lon": 125.75}},
        {"country_name": "Nigeria", "city_name": "Lagos", "location": {"lat": 6.52, "lon": 3.38}},
        {"country_name": "India", "city_name": "Mumbai", "location": {"lat": 19.08, "lon": 72.88}},
        {"country_name": "United Kingdom", "city_name": "London", "location": {"lat": 51.51, "lon": -0.13}},
    ]

    src_ips = [
        "185.220.101.34", "45.155.205.99", "103.75.201.2", "198.51.100.23",
        "91.240.118.50", "203.0.113.42", "77.247.181.163", "176.10.99.200",
        "37.120.198.100", "94.102.49.190",
    ]

    dga_domains = ["xkqpt7b2nf.evil.com", "a8dh3kfm2p.xyz", "qw9r4t5y6u.top", "zx3c2v1b0n.info"]
    payloads = ["JABjAGwAaQBlAG4AdAA=", "SW52b2tlLVdlYlJlcXVlc3Q=", "R2V0LUNyZWRlbnRpYWw="]
    hashes = [
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    ]
    procs = ["procdump64.exe", "taskmgr.exe", "rundll32.exe", "cmd.exe"]
    statuses = ["open", "open", "open", "open", "acknowledged", "acknowledged", "resolved"]

    # Alert definitions
    alert_defs = [
        ("Brute Force Authentication Attempt", "critical",
         "Multiple failed authentication attempts detected from {src_ip} targeting {user} on {host} - {count} failures in 5 minutes",
         ["authentication", "brute-force"], "T1110", "Brute Force", "Credential Access", "authentication", "logon-failed"),

        ("Suspicious PowerShell Execution", "high",
         "Encoded PowerShell command executed by {user} on {host}: powershell.exe -EncodedCommand {payload}",
         ["execution", "powershell", "living-off-the-land"], "T1059.001", "PowerShell", "Execution", "process", "process-started"),

        ("Malware Detection - Trojan.GenericKD", "critical",
         "Malware detected on {host}: Trojan.GenericKD.46789012 in C:\\Users\\{user}\\Downloads\\invoice_q4.exe (SHA256: {hash})",
         ["malware", "trojan", "endpoint"], "T1204.002", "Malicious File", "Execution", "malware", "malware-detected"),

        ("Lateral Movement via PsExec", "high",
         "PsExec service installed on {host} by {user} from {src_ip} - possible lateral movement",
         ["lateral-movement", "psexec"], "T1570", "Lateral Tool Transfer", "Lateral Movement", "process", "service-installed"),

        ("Data Exfiltration - Large Upload", "critical",
         "Anomalous data transfer: {user}@{host} uploaded 2.4 GB to external IP {dst_ip} over HTTPS in 15 minutes",
         ["exfiltration", "data-loss"], "T1048", "Exfiltration Over Alternative Protocol", "Exfiltration", "network", "connection-accepted"),

        ("Privilege Escalation - UAC Bypass", "high",
         "UAC bypass detected on {host}: {user} elevated privileges via fodhelper.exe registry modification",
         ["privilege-escalation", "uac-bypass"], "T1548.002", "Bypass User Account Control", "Privilege Escalation", "process", "process-started"),

        ("Suspicious DNS Query - DGA Domain", "medium",
         "DNS query for suspected DGA domain: {dga_domain} from {host} ({src_ip})",
         ["dns", "dga", "c2"], "T1568.002", "Domain Generation Algorithms", "Command and Control", "network", "dns-query"),

        ("Failed Login from Unusual Geo", "medium",
         "Failed login for {user} from {geo_country} ({src_ip}) - location not seen in baseline",
         ["authentication", "geo-anomaly"], "T1078", "Valid Accounts", "Initial Access", "authentication", "logon-failed"),

        ("Ransomware Behavior - Mass File Rename", "critical",
         "Rapid file rename activity on {host}: 847 files renamed to .locked extension by process svchost_update.exe (PID {pid})",
         ["ransomware", "encryption", "critical"], "T1486", "Data Encrypted for Impact", "Impact", "file", "file-renamed"),

        ("Outbound C2 Beacon Detected", "high",
         "Periodic outbound connections from {host} to {dst_ip}:443 every 60s - matches known Cobalt Strike beacon profile",
         ["c2", "cobalt-strike", "beacon"], "T1071.001", "Web Protocols", "Command and Control", "network", "connection-accepted"),

        ("Credential Dumping - LSASS Access", "critical",
         "Process {proc} accessed LSASS memory on {host} - possible credential dumping by {user}",
         ["credential-access", "lsass", "mimikatz"], "T1003.001", "LSASS Memory", "Credential Access", "process", "process-accessed"),

        ("Phishing Email Delivered", "medium",
         'Phishing email delivered to {user}@corp.local - Subject: "Urgent: Update your payment info" from spoofed sender hr-noreply@corp.local',
         ["phishing", "email", "initial-access"], "T1566.001", "Spearphishing Attachment", "Initial Access", "email", "email-delivered"),

        ("Unauthorized RDP Session", "high",
         "RDP session established to {host} from external IP {src_ip} ({geo_country}) - no VPN connection active",
         ["rdp", "external-access", "unauthorized"], "T1021.001", "Remote Desktop Protocol", "Lateral Movement", "authentication", "logon-success"),

        ("Scheduled Task Created", "medium",
         'New scheduled task "WindowsUpdate" created on {host} by {user} - binary: C:\\ProgramData\\svchost_update.exe',
         ["persistence", "scheduled-task"], "T1053.005", "Scheduled Task", "Persistence", "process", "task-created"),

        ("Firewall Rule Modified", "low",
         "Outbound firewall rule added on {host} by {user}: Allow TCP 4444 outbound - potential backdoor port",
         ["defense-evasion", "firewall"], "T1562.004", "Disable or Modify System Firewall", "Defense Evasion", "configuration", "rule-modified"),

        ("Anomalous Service Account Activity", "medium",
         "Service account svc_backup performed interactive logon on {host} from {src_ip} - deviation from baseline",
         ["anomaly", "service-account"], "T1078.002", "Domain Accounts", "Persistence", "authentication", "logon-success"),

        ("SSL Certificate Anomaly", "low",
         "Self-signed SSL certificate detected on outbound connection from {host} to {dst_ip}:8443 - CN=localhost",
         ["network", "ssl", "anomaly"], "T1573.002", "Asymmetric Cryptography", "Command and Control", "network", "tls-established"),

        ("Windows Event Log Cleared", "high",
         "Security event log cleared on {host} by {user} - 14,832 events purged, possible anti-forensics",
         ["defense-evasion", "log-cleared"], "T1070.001", "Clear Windows Event Logs", "Defense Evasion", "process", "log-cleared"),

        ("Kerberoasting Detected", "high",
         "Kerberos TGS requests for {count} SPNs from {user}@{host} in 30 seconds - possible Kerberoasting",
         ["credential-access", "kerberoasting"], "T1558.003", "Kerberoasting", "Credential Access", "authentication", "kerberos-tgs"),

        ("Suspicious Registry Modification", "medium",
         "Registry key HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run modified on {host} by {user} - added svchost_update.exe",
         ["persistence", "registry"], "T1547.001", "Registry Run Keys", "Persistence", "registry", "registry-modified"),

        ("Port Scan Detected", "low",
         "Host {src_ip} scanned {count} ports on {host} ({dst_ip}) in 2 minutes - top ports: 22, 80, 443, 445, 3389",
         ["reconnaissance", "port-scan"], "T1046", "Network Service Discovery", "Discovery", "network", "port-scan"),

        ("Cloud API Key Exposed", "critical",
         "AWS access key AKIA3EXAMPLE found in public Git repository commit by {user} - key associated with production IAM role",
         ["cloud", "secret-exposed", "aws"], "T1552.001", "Credentials In Files", "Credential Access", "configuration", "secret-detected"),
    ]

    # Generate 40 alerts spread across the last 48 hours
    bulk_body = ""
    for i in range(40):
        defn = alert_defs[i % len(alert_defs)]
        rule_name, sev, msg_tpl, tags, tech_id, tech_name, tactic, evt_cat, evt_action = defn

        hours_ago = random.uniform(0.5, 47)
        ts = (now - timedelta(hours=hours_ago)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        host = random.choice(hosts)
        user = random.choice(users)
        src_ip = random.choice(src_ips)
        dst_ip = random.choice(src_ips)
        geo = random.choice(geos)
        status = random.choice(statuses)

        msg = msg_tpl.format(
            src_ip=src_ip,
            user=user,
            host=host[0],
            count=random.randint(15, 500),
            payload=random.choice(payloads),
            hash=random.choice(hashes),
            dst_ip=dst_ip,
            dga_domain=random.choice(dga_domains),
            geo_country=geo["country_name"],
            pid=random.randint(1000, 65000),
            proc=random.choice(procs),
        )

        doc = {
            "@timestamp": ts,
            "event": {
                "severity": sev,
                "action": evt_action,
                "category": evt_cat,
                "kind": "alert",
            },
            "rule": {
                "name": rule_name,
                "description": msg,
            },
            "message": msg,
            "severity": sev,
            "status": status,
            "host": {
                "name": host[0],
                "hostname": host[0],
                "ip": host[1],
                "os": {"name": host[2]},
            },
            "user": {
                "name": user,
                "domain": "CORP",
            },
            "source": {
                "ip": src_ip,
                "port": random.randint(1024, 65535),
                "geo": geo,
            },
            "destination": {
                "ip": dst_ip,
                "port": random.choice([22, 80, 443, 445, 3389, 4444, 8443]),
            },
            "tags": tags,
            "threat": {
                "technique": {"id": tech_id, "name": tech_name},
                "tactic": {"name": tactic},
            },
        }

        if evt_cat == "process":
            doc["process"] = {
                "name": random.choice(procs),
                "pid": random.randint(1000, 65000),
            }

        if evt_cat in ("file", "malware"):
            doc["file"] = {
                "path": f"C:\\Users\\{user}\\Downloads\\invoice_q4.exe",
                "hash": {"sha256": random.choice(hashes)},
            }

        bulk_body += json.dumps({"index": {"_index": INDEX}}) + "\n"
        bulk_body += json.dumps(doc) + "\n"

    # Bulk index
    r = requests.post(
        f"{ES_URL}/_bulk",
        data=bulk_body,
        headers={"Content-Type": "application/x-ndjson"},
        auth=AUTH,
        timeout=30,
    )
    result = r.json()
    errors = result.get("errors", False)
    items = result.get("items", [])
    success = sum(1 for item in items if item.get("index", {}).get("status") in (200, 201))
    print(f"Bulk index: {success}/{len(items)} alerts indexed, errors={errors}")

    # Refresh index
    r = requests.post(f"{ES_URL}/{INDEX}/_refresh", auth=AUTH, timeout=10)
    print(f"Refresh: {r.status_code}")

    # Verify count
    r = requests.get(f"{ES_URL}/{INDEX}/_count", auth=AUTH, timeout=10)
    print(f"Total alerts in index: {r.json().get('count', 0)}")


if __name__ == "__main__":
    main()
