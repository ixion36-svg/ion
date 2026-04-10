#!/usr/bin/env python3
"""Seed ALL empty TIDE tables with realistic test data.

Run inside the TIDE container:
    docker cp seed_tide_data.py tide-app:/app/seed_tide_data.py
    docker exec tide-app python /app/seed_tide_data.py
"""

import duckdb
import uuid
import json
from datetime import datetime, timedelta

DB_PATH = "/app/data/tide.duckdb"

def uid():
    return str(uuid.uuid4())

def now():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

def main():
    conn = duckdb.connect(DB_PATH, read_only=False)

    # =====================================================================
    # 1. THREAT ACTORS (real-world names, TTPs, aliases)
    # =====================================================================
    actors = [
        ("APT28", "Russian military cyber unit (GRU Unit 26165). Active since 2004. Targets government, military, security orgs.",
         ["T1566.001","T1059.001","T1003.001","T1071.001","T1027","T1083","T1082","T1005","T1041","T1078"],
         "Fancy Bear, Sofacy, Sednit, Pawn Storm", "Russia",
         ["MITRE ATT&CK","Mandiant"]),
        ("APT29", "Russian SVR cyber espionage group. SolarWinds supply chain compromise (2020).",
         ["T1195.002","T1059.001","T1078.004","T1550.001","T1071.001","T1027","T1140","T1070.006","T1098","T1021.002"],
         "Cozy Bear, Nobelium, The Dukes, Midnight Blizzard", "Russia",
         ["MITRE ATT&CK","CrowdStrike"]),
        ("Lazarus Group", "North Korean state-sponsored APT. Financial theft, ransomware, crypto heists.",
         ["T1566.001","T1204.002","T1059.005","T1059.007","T1055","T1071.001","T1486","T1490","T1027","T1105"],
         "Hidden Cobra, Zinc, Diamond Sleet", "North Korea",
         ["MITRE ATT&CK","FBI"]),
        ("APT41", "Chinese state-sponsored dual espionage and financial group.",
         ["T1190","T1133","T1059.001","T1059.003","T1003","T1021.001","T1070.001","T1071.001","T1560","T1041"],
         "Double Dragon, Winnti, Barium", "China",
         ["MITRE ATT&CK","Mandiant","FireEye"]),
        ("FIN7", "Eastern European financially motivated group. Point-of-sale malware, ransomware.",
         ["T1566.001","T1204.002","T1059.001","T1059.003","T1055.001","T1071.001","T1005","T1041","T1486","T1027"],
         "Carbanak, ITG14, Carbon Spider", "Eastern Europe",
         ["MITRE ATT&CK","CrowdStrike"]),
        ("Sandworm", "Russian GRU Unit 74455. Destructive attacks: NotPetya, Ukrainian power grid.",
         ["T1190","T1059.001","T1059.003","T1021.002","T1003.001","T1486","T1485","T1490","T1491","T1562.001"],
         "Voodoo Bear, Iridium, Seashell Blizzard", "Russia",
         ["MITRE ATT&CK","CISA"]),
        ("Volt Typhoon", "Chinese state-sponsored group targeting US critical infrastructure. Living-off-the-land techniques.",
         ["T1190","T1133","T1059.001","T1078","T1003","T1018","T1046","T1071.004","T1572","T1041"],
         "Bronze Silhouette, DEV-0391, Vanguard Panda", "China",
         ["CISA","Microsoft","MITRE ATT&CK"]),
        ("LockBit", "Ransomware-as-a-Service (RaaS) operation. Most prolific ransomware group 2022-2024.",
         ["T1190","T1133","T1078","T1059.001","T1059.003","T1021.002","T1486","T1490","T1041","T1562.001"],
         "ABCD Ransomware, Gold Mystic", "Global",
         ["FBI","CISA","Europol"]),
    ]

    existing = conn.execute("SELECT count(*) FROM threat_actors").fetchone()[0]
    if existing == 0:
        for name, desc, ttps, aliases, origin, sources in actors:
            conn.execute("""
                INSERT INTO threat_actors (name, description, ttps, ttp_count, aliases, origin, last_updated, source)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, [name, desc, ttps, len(ttps), aliases, origin, datetime.utcnow(), sources])
        print(f"  threat_actors: {len(actors)} inserted")
    else:
        print(f"  threat_actors: skipped ({existing} exist)")

    # =====================================================================
    # 2. HOSTS — 2-3 per system
    # =====================================================================
    systems = conn.execute("SELECT id, name FROM systems").fetchall()
    sys_map = {row[0]: row[1] for row in systems}

    hosts_data = [
        # (system_id_prefix, hostname, ip, os, vendor, model)
        ("07555bf8", "WKS-FIN-001", "10.10.20.101", "Windows 11 Enterprise", "Dell", "Latitude 5540"),
        ("07555bf8", "WKS-HR-002", "10.10.20.102", "Windows 11 Enterprise", "Dell", "Latitude 5540"),
        ("07555bf8", "SRV-DC01", "10.10.10.10", "Windows Server 2022", "HPE", "ProLiant DL380"),
        ("07555bf8", "SRV-DC02", "10.10.10.11", "Windows Server 2022", "HPE", "ProLiant DL380"),
        ("4f2fec49", "ip-10-0-1-50", "10.0.1.50", "Amazon Linux 2023", "AWS", "m5.xlarge"),
        ("4f2fec49", "ip-10-0-2-100", "10.0.2.100", "Amazon Linux 2023", "AWS", "c5.2xlarge"),
        ("4f2fec49", "ip-10-0-3-200", "10.0.3.200", "Ubuntu 22.04 LTS", "AWS", "t3.large"),
        ("8048fd98", "SRV-SQL01", "10.10.10.30", "Windows Server 2022", "HPE", "ProLiant DL560"),
        ("8048fd98", "SRV-PSQL01", "10.10.10.31", "Ubuntu 22.04 LTS", "Dell", "PowerEdge R750"),
        ("49b2a9ce", "SRV-MAIL01", "10.10.10.20", "Windows Server 2022", "HPE", "ProLiant DL360"),
        ("49b2a9ce", "SRV-MAIL-GW", "10.10.10.21", "CentOS 8", "Cisco", "ESA C690"),
        ("a6ef4c1e", "SRV-ADFS01", "10.10.10.40", "Windows Server 2022", "HPE", "ProLiant DL380"),
        ("3e12303f", "FW-CORE-01", "10.10.1.1", "PAN-OS 11.1", "Palo Alto", "PA-5250"),
        ("3e12303f", "FW-DMZ-01", "10.10.1.2", "PAN-OS 11.1", "Palo Alto", "PA-3260"),
        ("3e12303f", "IDS-SENSOR-01", "10.10.1.10", "Suricata 7.0", "Open Source", "Dell R440"),
        ("53e7987a", "PLC-PLANT-01", "192.168.100.10", "Siemens S7-1500 FW4.0", "Siemens", "S7-1500"),
        ("53e7987a", "HMI-OPS-01", "192.168.100.20", "Windows 10 LTSC 2021", "Advantech", "TPC-1551T"),
    ]

    existing_hosts = conn.execute("SELECT count(*) FROM hosts").fetchone()[0]
    if existing_hosts == 0:
        for sys_prefix, hostname, ip, os_name, vendor, model in hosts_data:
            sys_id = next((sid for sid in sys_map if sid.startswith(sys_prefix)), None)
            if not sys_id:
                continue
            conn.execute("""
                INSERT INTO hosts (id, system_id, name, ip_address, os, hardware_vendor, model, source, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, [uid(), sys_id, hostname, ip, os_name, vendor, model, "manual", datetime.utcnow()])
        print(f"  hosts: {len(hosts_data)} inserted")
    else:
        print(f"  hosts: skipped ({existing_hosts} exist)")

    # =====================================================================
    # 3. SOFTWARE INVENTORY — linked to hosts
    # =====================================================================
    host_rows = conn.execute("SELECT id, name FROM hosts").fetchall()
    software_entries = [
        ("Microsoft Office 365", "16.0.17726", "Microsoft", "cpe:2.3:a:microsoft:office:365:*:*:*:*:*:*:*"),
        ("Google Chrome", "124.0.6367.91", "Google", "cpe:2.3:a:google:chrome:124.0.6367.91:*:*:*:*:*:*:*"),
        ("Adobe Acrobat Reader", "2024.002.20687", "Adobe", "cpe:2.3:a:adobe:acrobat_reader:2024.002.20687:*:*:*:*:*:*:*"),
        ("7-Zip", "24.05", "Igor Pavlov", "cpe:2.3:a:7-zip:7-zip:24.05:*:*:*:*:*:*:*"),
        ("Python", "3.12.3", "Python Software Foundation", "cpe:2.3:a:python:python:3.12.3:*:*:*:*:*:*:*"),
        ("OpenSSL", "3.2.1", "OpenSSL Project", "cpe:2.3:a:openssl:openssl:3.2.1:*:*:*:*:*:*:*"),
        ("Apache Log4j", "2.17.1", "Apache", "cpe:2.3:a:apache:log4j:2.17.1:*:*:*:*:*:*:*"),
        ("PostgreSQL", "16.2", "PostgreSQL", "cpe:2.3:a:postgresql:postgresql:16.2:*:*:*:*:*:*:*"),
        ("Nginx", "1.25.4", "F5", "cpe:2.3:a:f5:nginx:1.25.4:*:*:*:*:*:*:*"),
        ("CrowdStrike Falcon", "7.10", "CrowdStrike", ""),
        ("Sysmon", "15.14", "Microsoft", ""),
        ("WinLogBeat", "8.13.0", "Elastic", ""),
    ]

    existing_sw = conn.execute("SELECT count(*) FROM software_inventory").fetchone()[0]
    if existing_sw == 0:
        inserted = 0
        for host_id, host_name in host_rows[:8]:  # first 8 hosts get software
            for sw_name, sw_ver, vendor, cpe in software_entries[:6]:  # 6 apps each
                conn.execute("""
                    INSERT INTO software_inventory (id, system_id, name, version, vendor, cpe, source, created_at, host_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, [uid(), "", sw_name, sw_ver, vendor, cpe or None, "manual", datetime.utcnow(), host_id])
                inserted += 1
        print(f"  software_inventory: {inserted} inserted")
    else:
        print(f"  software_inventory: skipped ({existing_sw} exist)")

    # =====================================================================
    # 4. VULN_DETECTIONS — CVE → rule mappings
    # =====================================================================
    rules = conn.execute(
        "SELECT rule_id, name FROM detection_rules WHERE enabled=1 AND space='default' LIMIT 20"
    ).fetchall()

    vuln_dets = [
        ("CVE-2021-44228", rules[0][0] if len(rules) > 0 else uid(), "Log4Shell — rule detects JNDI lookup attempts", "TIDE"),
        ("CVE-2021-44228", rules[1][0] if len(rules) > 1 else uid(), "Log4Shell — outbound callback detection", "TIDE"),
        ("CVE-2023-23397", rules[2][0] if len(rules) > 2 else uid(), "Outlook NTLM relay — detects SMB auth to external", "TIDE"),
        ("CVE-2024-3400", rules[3][0] if len(rules) > 3 else uid(), "PAN-OS command injection — HTTP pattern match", "TIDE"),
        ("CVE-2023-44487", rules[4][0] if len(rules) > 4 else uid(), "HTTP/2 Rapid Reset DoS — rate anomaly", "TIDE"),
        ("CVE-2024-21762", rules[5][0] if len(rules) > 5 else uid(), "FortiOS SSLVPN — out-of-bounds write attempt", "TIDE"),
        ("CVE-2023-46805", rules[6][0] if len(rules) > 6 else uid(), "Ivanti Connect Secure auth bypass", "TIDE"),
        ("CVE-2024-1709", rules[7][0] if len(rules) > 7 else uid(), "ConnectWise ScreenConnect auth bypass", "TIDE"),
        ("CVE-2023-34362", rules[8][0] if len(rules) > 8 else uid(), "MOVEit Transfer SQLi — file exfil detection", "manual"),
        ("CVE-2024-27198", rules[9][0] if len(rules) > 9 else uid(), "JetBrains TeamCity auth bypass — admin access", "manual"),
    ]

    existing_vd = conn.execute("SELECT count(*) FROM vuln_detections").fetchone()[0]
    if existing_vd == 0:
        for cve, rule_ref, note, source in vuln_dets:
            conn.execute("""
                INSERT INTO vuln_detections (id, cve_id, rule_ref, note, source, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, [uid(), cve, rule_ref, note, source, datetime.utcnow()])
        print(f"  vuln_detections: {len(vuln_dets)} inserted")
    else:
        print(f"  vuln_detections: skipped ({existing_vd} exist)")

    # =====================================================================
    # 5. CVE_TECHNIQUE_OVERRIDES
    # =====================================================================
    overrides = [
        ("CVE-2021-44228", "T1190"),
        ("CVE-2021-44228", "T1059"),
        ("CVE-2023-23397", "T1557"),
        ("CVE-2023-23397", "T1003"),
        ("CVE-2024-3400", "T1190"),
        ("CVE-2024-3400", "T1059.004"),
        ("CVE-2023-44487", "T1498"),
        ("CVE-2024-21762", "T1190"),
        ("CVE-2023-46805", "T1190"),
        ("CVE-2023-46805", "T1078"),
    ]

    existing_ov = conn.execute("SELECT count(*) FROM cve_technique_overrides").fetchone()[0]
    if existing_ov == 0:
        for cve, tid in overrides:
            conn.execute(
                "INSERT INTO cve_technique_overrides (cve_id, technique_id) VALUES (?, ?)",
                [cve, tid]
            )
        print(f"  cve_technique_overrides: {len(overrides)} inserted")
    else:
        print(f"  cve_technique_overrides: skipped ({existing_ov} exist)")

    # =====================================================================
    # 6. STEP_DETECTIONS — link rules to playbook steps
    # =====================================================================
    steps = conn.execute("SELECT id, title, technique_id FROM playbook_steps").fetchall()
    # Find rules that match step techniques
    existing_sd = conn.execute("SELECT count(*) FROM step_detections").fetchone()[0]
    if existing_sd == 0:
        inserted = 0
        for step_id, step_title, step_tid in steps:
            if not step_tid:
                continue
            matching = conn.execute(f"""
                SELECT rule_id, name FROM detection_rules
                WHERE space='default'
                  AND mitre_ids IS NOT NULL
                  AND array_to_string(mitre_ids, ',') LIKE '%{step_tid}%'
                LIMIT 3
            """).fetchall()
            for rule_id, rule_name in matching:
                conn.execute("""
                    INSERT INTO step_detections (id, step_id, rule_ref, note, source)
                    VALUES (?, ?, ?, ?, ?)
                """, [uid(), step_id, rule_id, f"Auto-mapped: {rule_name}", "seed"])
                inserted += 1
        print(f"  step_detections: {inserted} inserted")
    else:
        print(f"  step_detections: skipped ({existing_sd} exist)")

    # =====================================================================
    # 7. SYSTEM_BASELINES — link systems to playbooks
    # =====================================================================
    playbooks = conn.execute("SELECT id, name FROM playbooks").fetchall()
    existing_sb = conn.execute("SELECT count(*) FROM system_baselines").fetchone()[0]
    if existing_sb == 0:
        inserted = 0
        # Apply each playbook to 3-4 systems
        assignments = [
            (0, [0, 1, 3, 4]),  # Insider Threat → Endpoint, AWS, Email, Identity
            (1, [0, 1, 2, 5]),  # Ransomware → Endpoint, AWS, Database, Network
        ]
        sys_list = list(sys_map.keys())
        for pb_idx, sys_indices in assignments:
            if pb_idx >= len(playbooks):
                continue
            pb_id = playbooks[pb_idx][0]
            for si in sys_indices:
                if si >= len(sys_list):
                    continue
                conn.execute("""
                    INSERT INTO system_baselines (id, playbook_id, system_id, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?)
                """, [uid(), pb_id, sys_list[si], datetime.utcnow(), datetime.utcnow()])
                inserted += 1
        print(f"  system_baselines: {inserted} inserted")
    else:
        print(f"  system_baselines: skipped ({existing_sb} exist)")

    # =====================================================================
    # 8. BLIND_SPOTS — acknowledged detection gaps
    # =====================================================================
    existing_bs = conn.execute("SELECT count(*) FROM blind_spots").fetchone()[0]
    if existing_bs == 0:
        blind_spots = [
            ("technique", "T1200", sys_list[0] if sys_list else None, None,
             "USB device detection requires EDR agent with removable media policy — not deployed on all endpoints yet.", "admin"),
            ("technique", "T1052", sys_list[0] if sys_list else None, None,
             "Exfiltration via physical media — relies on DLP which is only deployed on Finance endpoints.", "admin"),
            ("technique", "T1560", None, None,
             "Data compression detection has high FP rate with backup tools. Disabled pending tuning.", "soc_lead"),
            ("technique", "T1046", sys_list[6] if len(sys_list) > 6 else None, None,
             "Network scanning from OT/SCADA hosts is expected behaviour during maintenance windows. Accepted risk.", "admin"),
            ("technique", "T1498", sys_list[5] if len(sys_list) > 5 else None, None,
             "DoS detection at network perimeter delegated to upstream ISP scrubbing. ION will not alert on this.", "admin"),
        ]
        for entity_type, entity_id, system_id, host_id, reason, created_by in blind_spots:
            conn.execute("""
                INSERT INTO blind_spots (id, entity_type, entity_id, system_id, host_id, reason, created_by, created_at, override_type)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, [uid(), entity_type, entity_id, system_id, host_id, reason, created_by, datetime.utcnow(), "accepted_risk"])
        print(f"  blind_spots: {len(blind_spots)} inserted")
    else:
        print(f"  blind_spots: skipped ({existing_bs} exist)")

    conn.close()
    print("\nDone! All TIDE tables populated.")


if __name__ == "__main__":
    main()
