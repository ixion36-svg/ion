"""Seed script: populate network_assets with 20 realistic SOC hosts."""
import sys
sys.path.insert(0, "src")

from datetime import datetime, timedelta, timezone
from ion.storage.database import get_engine, get_session_factory
from ion.models.network_asset import NetworkAsset, NetworkAssetIP, NetworkAssetMAC
from ion.models.base import Base

engine = get_engine()
Base.metadata.create_all(engine)
session = get_session_factory(engine)()
now = datetime.now(timezone.utc)

hosts = [
    {"hostname": "dc01.guardedglass.internal", "display": "DC01.guardedglass.internal",
     "os": ("Windows Server", "2022", "windows", "windows"), "arch": "x86_64",
     "crit": "critical", "env": "prod", "owner": "Infrastructure",
     "ips": [("10.1.1.10", 48200), ("10.1.1.11", 320)], "macs": ["00:50:56:a1:2b:3c"],
     "systems": ["default", "sysmon"], "events": 152400, "h_ago": 0.1},
    {"hostname": "dc02.guardedglass.internal", "display": "DC02.guardedglass.internal",
     "os": ("Windows Server", "2022", "windows", "windows"), "arch": "x86_64",
     "crit": "critical", "env": "prod", "owner": "Infrastructure",
     "ips": [("10.1.1.20", 41000)], "macs": ["00:50:56:a1:4d:5e"],
     "systems": ["default", "sysmon"], "events": 138700, "h_ago": 0.2},
    {"hostname": "exchange01.guardedglass.internal", "display": "EXCHANGE01",
     "os": ("Windows Server", "2019", "windows", "windows"), "arch": "x86_64",
     "crit": "high", "env": "prod", "owner": "Messaging",
     "ips": [("10.1.2.50", 89400)], "macs": ["00:50:56:a1:6f:7a"],
     "systems": ["default", "defender"], "events": 89400, "h_ago": 0.5},
    {"hostname": "web-prod-01", "display": "web-prod-01",
     "os": ("Ubuntu", "22.04", "linux", "ubuntu"), "arch": "x86_64",
     "crit": "high", "env": "prod", "owner": "Web Team",
     "ips": [("10.2.1.100", 245000), ("192.168.3.100", 12000)], "macs": ["02:42:ac:11:00:02"],
     "systems": ["default", "auditbeat"], "events": 257000, "h_ago": 0.05},
    {"hostname": "web-prod-02", "display": "web-prod-02",
     "os": ("Ubuntu", "22.04", "linux", "ubuntu"), "arch": "x86_64",
     "crit": "high", "env": "prod", "owner": "Web Team",
     "ips": [("10.2.1.101", 231000)], "macs": ["02:42:ac:11:00:03"],
     "systems": ["default", "auditbeat"], "events": 231000, "h_ago": 0.1},
    {"hostname": "db-postgres-01", "display": "db-postgres-01",
     "os": ("Rocky Linux", "9.3", "linux", "rhel"), "arch": "x86_64",
     "crit": "critical", "env": "prod", "owner": "DBA Team",
     "ips": [("10.3.1.50", 67000)], "macs": ["00:50:56:b2:1a:2b"],
     "systems": ["default"], "events": 67000, "h_ago": 0.3},
    {"hostname": "elk-node-01", "display": "elk-node-01",
     "os": ("Ubuntu", "22.04", "linux", "ubuntu"), "arch": "x86_64",
     "crit": "high", "env": "prod", "owner": "SOC Engineering",
     "ips": [("10.4.1.10", 520000)], "macs": ["00:50:56:c3:2d:3e"],
     "systems": ["default"], "events": 520000, "h_ago": 0.01},
    {"hostname": "elk-node-02", "display": "elk-node-02",
     "os": ("Ubuntu", "22.04", "linux", "ubuntu"), "arch": "x86_64",
     "crit": "high", "env": "prod", "owner": "SOC Engineering",
     "ips": [("10.4.1.11", 490000)], "macs": ["00:50:56:c3:4f:5a"],
     "systems": ["default"], "events": 490000, "h_ago": 0.02},
    {"hostname": "kibana.guardedglass.internal", "display": "kibana.guardedglass.internal",
     "os": ("Ubuntu", "22.04", "linux", "ubuntu"), "arch": "x86_64",
     "crit": "medium", "env": "prod", "owner": "SOC Engineering",
     "ips": [("10.4.1.20", 34000)], "macs": ["00:50:56:c3:6b:7c"],
     "systems": ["default"], "events": 34000, "h_ago": 1.0},
    {"hostname": "nifi-prod-01", "display": "nifi-prod-01",
     "os": ("Rocky Linux", "9.3", "linux", "rhel"), "arch": "x86_64",
     "crit": "medium", "env": "prod", "owner": "Data Engineering",
     "ips": [("10.5.1.30", 78000)], "macs": ["00:50:56:d4:8e:9f"],
     "systems": ["default", "nifi"], "events": 78000, "h_ago": 2.0},
    {"hostname": "arcsight-collector-01", "display": "arcsight-collector-01",
     "os": ("CentOS", "7.9", "linux", "centos"), "arch": "x86_64",
     "crit": "medium", "env": "prod", "owner": "SOC Engineering",
     "ips": [("10.5.1.40", 112000)], "macs": ["00:50:56:d4:a1:b2"],
     "systems": ["arcsight"], "events": 112000, "h_ago": 0.5},
    {"hostname": "vpn-gw-01.guardedglass.internal", "display": "VPN-GW-01",
     "os": ("Fortinet FortiOS", "7.4.1", "fortios", "fortinet"), "arch": "arm64",
     "crit": "critical", "env": "prod", "owner": "Network",
     "ips": [("10.0.0.1", 890000), ("203.0.113.50", 890000)], "macs": ["00:09:0f:aa:bb:cc"],
     "systems": ["default", "fortinet"], "events": 890000, "h_ago": 0.01},
    {"hostname": "fw-core-01", "display": "fw-core-01",
     "os": ("Palo Alto PAN-OS", "11.1.2", "panos", "paloalto"), "arch": "x86_64",
     "crit": "critical", "env": "prod", "owner": "Network",
     "ips": [("10.0.0.254", 1240000)], "macs": ["00:1b:17:dd:ee:ff"],
     "systems": ["default", "paloalto"], "events": 1240000, "h_ago": 0.01},
    {"hostname": "soc-analyst-ws01", "display": "SOC-ANALYST-WS01",
     "os": ("Windows 11", "23H2", "windows", "windows"), "arch": "x86_64",
     "crit": "low", "env": "prod", "owner": "SOC",
     "ips": [("10.10.1.50", 18000)], "macs": ["d4:5d:64:11:22:33"],
     "systems": ["default", "defender", "sysmon"], "events": 18000, "h_ago": 3.0},
    {"hostname": "soc-analyst-ws02", "display": "SOC-ANALYST-WS02",
     "os": ("Windows 11", "23H2", "windows", "windows"), "arch": "x86_64",
     "crit": "low", "env": "prod", "owner": "SOC",
     "ips": [("10.10.1.51", 15200)], "macs": ["d4:5d:64:44:55:66"],
     "systems": ["default", "defender", "sysmon"], "events": 15200, "h_ago": 1.5},
    {"hostname": "dev-k8s-node-01", "display": "dev-k8s-node-01",
     "os": ("Ubuntu", "24.04", "linux", "ubuntu"), "arch": "x86_64",
     "crit": "low", "env": "dev", "owner": "DevOps",
     "ips": [("10.20.1.10", 44000), ("10.20.1.11", 3200)], "macs": ["02:42:0a:14:01:0a"],
     "systems": ["default"], "events": 47200, "h_ago": 6.0},
    {"hostname": "staging-api-01", "display": "staging-api-01",
     "os": ("Alpine Linux", "3.19", "linux", "alpine"), "arch": "x86_64",
     "crit": "low", "env": "staging", "owner": "QA",
     "ips": [("10.30.1.100", 8900)], "macs": ["02:42:0a:1e:01:64"],
     "systems": ["default"], "events": 8900, "h_ago": 12.0},
    {"hostname": "suricata-sensor-01", "display": "suricata-sensor-01",
     "os": ("Debian", "12", "linux", "debian"), "arch": "x86_64",
     "crit": "high", "env": "prod", "owner": "SOC Engineering",
     "ips": [("10.0.0.100", 3400000)], "macs": ["00:50:56:e5:c3:d4"],
     "systems": ["suricata", "default"], "events": 3400000, "h_ago": 0.01},
    {"hostname": "arkime-capture-01", "display": "arkime-capture-01",
     "os": ("Rocky Linux", "9.3", "linux", "rhel"), "arch": "x86_64",
     "crit": "high", "env": "prod", "owner": "SOC Engineering",
     "ips": [("10.0.0.101", 2100000)], "macs": ["00:50:56:e5:e6:f7"],
     "systems": ["arkime", "default"], "events": 2100000, "h_ago": 0.01},
    {"hostname": "opencti.guardedglass.internal", "display": "opencti.guardedglass.internal",
     "os": ("Ubuntu", "22.04", "linux", "ubuntu"), "arch": "x86_64",
     "crit": "medium", "env": "prod", "owner": "Threat Intel",
     "ips": [("192.168.3.66", 23000)], "macs": ["00:50:56:f6:01:02"],
     "systems": ["default"], "events": 23000, "h_ago": 4.0},
]

for h in hosts:
    ts = now - timedelta(hours=h["h_ago"])
    first = ts - timedelta(days=30)
    os_name, os_ver, os_fam, os_plat = h["os"]
    asset = NetworkAsset(
        hostname=h["hostname"], display_hostname=h["display"],
        os_name=os_name, os_version=os_ver, os_family=os_fam, os_platform=os_plat,
        architecture=h["arch"], first_seen=first, last_seen=ts,
        event_count=h["events"], last_index="logs-endpoint.events.process-default",
        criticality=h["crit"], environment=h["env"], owner=h.get("owner"),
        source_systems=h.get("systems", []),
    )
    session.add(asset)
    session.flush()
    for ip, count in h.get("ips", []):
        session.add(NetworkAssetIP(asset_id=asset.id, ip=ip, first_seen=first, last_seen=ts, event_count=count))
    for mac in h.get("macs", []):
        session.add(NetworkAssetMAC(asset_id=asset.id, mac=mac, first_seen=first, last_seen=ts))

session.commit()
session.close()
print(f"Seeded {len(hosts)} network assets with IPs and MACs")
