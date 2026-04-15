"""Seed ONE security alert carrying the Arkime linkage fields.

Writes to the same Kibana Security alerts index ION reads from, with:
- network.community_id matching the mock Arkime server
- node matching the mock Arkime capture node

After running this, the new alert will appear on /alerts with the cyan
Arkime icon in its Actions column, and clicking that icon opens the
/alerts/{id}/arkime workspace.
"""

import json
import uuid
from datetime import datetime, timedelta

import requests

ES_URL = "http://127.0.0.1:9200"
AUTH = ("elastic", "DocforgeTest2025")
INDEX = ".alerts-security.alerts-default"

# These MUST match the mock Arkime server's MOCK_NODE / MOCK_COMMUNITY_ID.
MOCK_NODE = "capture01"
MOCK_COMMUNITY_ID = "1:0ECALHJBcs13AkbmCmvNd9CVOkA="


def main():
    now = datetime.utcnow()
    alert_id = str(uuid.uuid4())

    doc = {
        "@timestamp": now.isoformat() + "Z",
        "kibana.version": "8.17.1",
        "kibana.alert.rule.uuid": str(uuid.uuid4()),
        "kibana.alert.rule.name": "Suspicious outbound beaconing to Tor exit node",
        "kibana.alert.rule.description": (
            "Host observed making repeated short-lived connections to an IP "
            "associated with a Tor exit node. Possible C2 beaconing."
        ),
        "kibana.alert.severity": "high",
        "kibana.alert.risk_score": 82,
        "kibana.alert.workflow_status": "open",
        "kibana.alert.status": "active",
        "kibana.alert.reason": (
            "Repeated TCP SYN from 10.50.12.17 → 185.220.101.78:4444 observed "
            "over 8 seconds with regular interval (beaconing pattern)."
        ),
        "kibana.alert.rule.threat": [
            {
                "framework": "MITRE ATT&CK",
                "tactic": {
                    "id": "TA0011",
                    "name": "Command and Control",
                    "reference": "https://attack.mitre.org/tactics/TA0011",
                },
                "technique": [
                    {
                        "id": "T1071",
                        "name": "Application Layer Protocol",
                        "reference": "https://attack.mitre.org/techniques/T1071",
                    }
                ],
            }
        ],
        "host": {
            "name": "WKS-MARKETING-05",
            "hostname": "WKS-MARKETING-05",
            "ip": ["10.50.12.17"],
            "os": {"family": "windows"},
        },
        "user": {"name": "a.mcmillan"},
        "source": {
            "ip": "10.50.12.17",
            "port": 45000,
            "geo": {"country_iso_code": "GB", "country_name": "United Kingdom"},
        },
        "destination": {
            "ip": "185.220.101.78",
            "port": 4444,
            "geo": {"country_iso_code": "DE", "country_name": "Germany"},
        },
        "network": {
            "community_id": MOCK_COMMUNITY_ID,
            "protocol": "tcp",
            "transport": "tcp",
        },
        "node": MOCK_NODE,
        "observer": {"name": MOCK_NODE, "type": "arkime"},
        "event": {
            "kind": "alert",
            "category": ["network", "intrusion_detection"],
            "action": "suspicious-beaconing",
            "severity": 3,
        },
        "data_stream": {
            "dataset": "zeek.conn",
            "namespace": "default",
            "type": "logs",
        },
        "tags": ["arkime-linked", "suspected-c2", "beaconing"],
    }

    # Ensure index exists (Kibana's alert index uses dynamic mapping — a
    # simple empty create is fine if the index doesn't exist yet).
    try:
        r = requests.head(f"{ES_URL}/{INDEX}", auth=AUTH, timeout=10)
        if r.status_code == 404:
            requests.put(f"{ES_URL}/{INDEX}", auth=AUTH, json={}, timeout=10)
            print(f"Created index {INDEX}")
    except Exception as e:
        print(f"index check: {e}")

    r = requests.post(
        f"{ES_URL}/{INDEX}/_doc/{alert_id}?refresh=wait_for",
        auth=AUTH,
        headers={"Content-Type": "application/json"},
        data=json.dumps(doc),
        timeout=15,
    )
    print(f"PUT alert: {r.status_code}")
    if r.status_code not in (200, 201):
        print(r.text)
        return

    print()
    print(f"Alert id:        {alert_id}")
    print(f"Community ID:    {MOCK_COMMUNITY_ID}")
    print(f"Node:            {MOCK_NODE}")
    print(f"Open in browser: http://127.0.0.1:8000/alerts/{alert_id}/arkime")


if __name__ == "__main__":
    main()
