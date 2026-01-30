"""Seed Elastic Security alerts in the correct format for Kibana integration."""

import httpx
import json
import uuid
from datetime import datetime, timedelta
import random

ES_URL = "http://localhost:9200"
AUTH = ("elastic", "testpassword123")
INDEX = ".alerts-security.alerts-default"

def main():
    now = datetime.utcnow()

    # Sample security alerts data
    alerts_data = [
        {
            "rule_name": "Brute Force Authentication Attempt",
            "severity": "critical",
            "risk_score": 95,
            "description": "Multiple failed authentication attempts detected from external IP targeting domain admin account",
            "host": "SRV-DC01",
            "host_ip": "10.10.10.10",
            "user": "administrator",
            "source_ip": "185.220.101.34",
            "tactic": "Credential Access",
            "technique": "T1110",
            "technique_name": "Brute Force",
        },
        {
            "rule_name": "Suspicious PowerShell Execution",
            "severity": "high",
            "risk_score": 73,
            "description": "Encoded PowerShell command executed with suspicious parameters",
            "host": "WKS-ANALYST01",
            "host_ip": "10.10.20.101",
            "user": "jsmith",
            "source_ip": "10.10.20.101",
            "tactic": "Execution",
            "technique": "T1059.001",
            "technique_name": "PowerShell",
        },
        {
            "rule_name": "Malware Detection",
            "severity": "critical",
            "risk_score": 99,
            "description": "Trojan.GenericKD detected in user downloads folder",
            "host": "WKS-HR01",
            "host_ip": "10.10.20.150",
            "user": "mwilliams",
            "source_ip": "10.10.20.150",
            "tactic": "Execution",
            "technique": "T1204.002",
            "technique_name": "Malicious File",
        },
        {
            "rule_name": "Credential Dumping - LSASS Access",
            "severity": "critical",
            "risk_score": 91,
            "description": "Process accessed LSASS memory - possible credential dumping",
            "host": "SRV-FILE01",
            "host_ip": "10.10.30.80",
            "user": "SYSTEM",
            "source_ip": "10.10.30.80",
            "tactic": "Credential Access",
            "technique": "T1003.001",
            "technique_name": "LSASS Memory",
        },
        {
            "rule_name": "Lateral Movement via PsExec",
            "severity": "high",
            "risk_score": 71,
            "description": "PsExec service installed on remote host - possible lateral movement",
            "host": "SRV-WEB01",
            "host_ip": "10.10.30.50",
            "user": "svc_backup",
            "source_ip": "10.10.10.10",
            "tactic": "Lateral Movement",
            "technique": "T1570",
            "technique_name": "Lateral Tool Transfer",
        },
        {
            "rule_name": "Data Exfiltration Detected",
            "severity": "critical",
            "risk_score": 87,
            "description": "Large data transfer to external IP detected over HTTPS",
            "host": "WKS-ENG01",
            "host_ip": "10.10.20.201",
            "user": "dchen",
            "source_ip": "10.10.20.201",
            "tactic": "Exfiltration",
            "technique": "T1048",
            "technique_name": "Exfiltration Over Alternative Protocol",
        },
        {
            "rule_name": "Ransomware Behavior Detected",
            "severity": "critical",
            "risk_score": 99,
            "description": "Rapid file rename activity with encryption extension detected",
            "host": "SRV-FILE01",
            "host_ip": "10.10.30.80",
            "user": "SYSTEM",
            "source_ip": "10.10.30.80",
            "tactic": "Impact",
            "technique": "T1486",
            "technique_name": "Data Encrypted for Impact",
        },
        {
            "rule_name": "C2 Beacon Activity",
            "severity": "high",
            "risk_score": 79,
            "description": "Periodic outbound connections matching known C2 beacon pattern",
            "host": "WKS-ANALYST02",
            "host_ip": "10.10.20.102",
            "user": "agarcia",
            "source_ip": "10.10.20.102",
            "tactic": "Command and Control",
            "technique": "T1071.001",
            "technique_name": "Web Protocols",
        },
    ]

    # Severity to number mapping
    severity_map = {
        "low": 21,
        "medium": 47,
        "high": 73,
        "critical": 99,
    }

    bulk_body = ""
    alert_ids = []

    for i, alert in enumerate(alerts_data):
        # Generate unique alert ID
        alert_id = str(uuid.uuid4())
        alert_ids.append(alert_id)

        # Random time in last 48 hours
        hours_ago = random.uniform(0.5, 47)
        ts = (now - timedelta(hours=hours_ago)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        # Build the alert document in Elastic Security format
        doc = {
            "@timestamp": ts,
            "kibana.alert.rule.uuid": str(uuid.uuid4()),
            "kibana.alert.rule.name": alert["rule_name"],
            "kibana.alert.rule.description": alert["description"],
            "kibana.alert.rule.category": "Custom Query Rule",
            "kibana.alert.rule.consumer": "siem",
            "kibana.alert.rule.producer": "siem",
            "kibana.alert.rule.rule_type_id": "siem.queryRule",
            "kibana.alert.rule.tags": ["ixion", alert["tactic"]],
            "kibana.alert.severity": alert["severity"],
            "kibana.alert.risk_score": alert["risk_score"],
            "kibana.alert.workflow_status": random.choice(["open", "open", "open", "acknowledged"]),
            "kibana.alert.status": "active",
            "kibana.alert.uuid": alert_id,
            "kibana.alert.reason": f"{alert['rule_name']} alert on {alert['host']} by {alert['user']}",
            "kibana.alert.original_time": ts,
            "kibana.alert.depth": 1,
            "kibana.alert.ancestors": [],
            "kibana.space_ids": ["default"],
            "kibana.version": "8.11.0",
            "event.kind": "signal",
            "event.action": "alert",
            "event.category": ["intrusion_detection"],
            "event.type": ["info"],
            "event.module": "security",
            "event.dataset": "security.alert",
            "host.name": alert["host"],
            "host.hostname": alert["host"],
            "host.ip": [alert["host_ip"]],
            "user.name": alert["user"],
            "source.ip": alert["source_ip"],
            "threat.tactic.name": [alert["tactic"]],
            "threat.technique.id": [alert["technique"]],
            "threat.technique.name": [alert["technique_name"]],
            "message": alert["description"],
            "tags": ["ixion", "test-alert"],
        }

        # Add to bulk request
        bulk_body += json.dumps({"index": {"_index": INDEX, "_id": alert_id}}) + "\n"
        bulk_body += json.dumps(doc) + "\n"

    # Bulk index
    print(f"Creating {len(alerts_data)} security alerts...")
    r = httpx.post(
        f"{ES_URL}/_bulk",
        content=bulk_body,
        headers={"Content-Type": "application/x-ndjson"},
        auth=AUTH,
        timeout=30,
    )

    result = r.json()
    errors = result.get("errors", False)
    items = result.get("items", [])
    success = sum(1 for item in items if item.get("index", {}).get("status") in (200, 201))
    print(f"Indexed: {success}/{len(items)} alerts, errors={errors}")

    if errors:
        for item in items:
            if item.get("index", {}).get("error"):
                print(f"  Error: {item['index']['error']}")

    # Refresh index
    r = httpx.post(f"{ES_URL}/{INDEX}/_refresh", auth=AUTH, timeout=10)
    print(f"Refresh: {r.status_code}")

    # Verify count
    r = httpx.get(f"{ES_URL}/{INDEX}/_count", auth=AUTH, timeout=10)
    print(f"Total alerts in security index: {r.json().get('count', 0)}")

    print("\nAlert IDs created:")
    for aid in alert_ids:
        print(f"  {aid}")

    return alert_ids


if __name__ == "__main__":
    main()
