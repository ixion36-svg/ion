"""Seed training plans for multiple users to populate the lead budget dashboard."""

import time
import requests

BASE = "http://127.0.0.1:8000"

USERS_PLANS = [
    {
        "username": "soc_sarah",
        "password": "user2025",
        "plan": {
            "name": "L2 Analyst Path",
            "target_role": "SOC Analyst L2",
            "status": "active",
            "notes": "Targeting L2 analyst role by end of FY25/26",
        },
        "items": [
            {"cert_name": "CompTIA Security+", "provider": "CompTIA", "price": 370, "difficulty": "intermediate", "funding_type": "company", "_status": "completed"},
            {"cert_name": "CompTIA CySA+", "provider": "CompTIA", "price": 392, "difficulty": "intermediate", "funding_type": "company", "_status": "in_progress"},
            {"cert_name": "GIAC GSEC", "provider": "SANS", "price": 8525, "difficulty": "intermediate", "funding_type": "company", "_status": "planned"},
            {"cert_name": "Splunk Core Certified User", "provider": "Splunk", "price": 130, "difficulty": "beginner", "funding_type": "self", "_status": "completed"},
            {"cert_name": "Blue Team Level 1", "provider": "Security Blue Team", "price": 499, "difficulty": "intermediate", "funding_type": "tbd", "_status": "planned"},
        ],
    },
    {
        "username": "soc_marcus",
        "password": "user2025",
        "plan": {
            "name": "Threat Hunter Path",
            "target_role": "Threat Hunter",
            "status": "active",
            "notes": "Contractor upskilling — threat hunting specialisation",
        },
        "items": [
            {"cert_name": "GIAC GCTI", "provider": "SANS", "price": 8525, "difficulty": "advanced", "funding_type": "company", "_status": "planned"},
            {"cert_name": "GIAC GCIH", "provider": "SANS", "price": 8525, "difficulty": "advanced", "funding_type": "company", "_status": "in_progress"},
            {"cert_name": "OffSec OSDA", "provider": "OffSec", "price": 1649, "difficulty": "advanced", "funding_type": "company", "_status": "planned"},
            {"cert_name": "Elastic Certified Analyst", "provider": "Elastic", "price": 400, "difficulty": "intermediate", "funding_type": "self", "_status": "completed"},
            {"cert_name": "CREST CPTIA", "provider": "CREST", "price": 750, "difficulty": "advanced", "funding_type": "tbd", "_status": "planned"},
            {"cert_name": "CompTIA CASP+", "provider": "CompTIA", "price": 494, "difficulty": "advanced", "funding_type": "company", "_status": "planned"},
        ],
    },
    {
        "username": "soc_priya",
        "password": "user2025",
        "plan": {
            "name": "Cyber Defence Foundation",
            "target_role": "Cyber Defence Analyst",
            "status": "active",
            "notes": "Military UCM pathway — cyber defence foundation certs",
        },
        "items": [
            {"cert_name": "CompTIA Network+", "provider": "CompTIA", "price": 358, "difficulty": "beginner", "funding_type": "company", "_status": "completed"},
            {"cert_name": "CompTIA Security+", "provider": "CompTIA", "price": 370, "difficulty": "intermediate", "funding_type": "company", "_status": "completed"},
            {"cert_name": "GIAC GSEC", "provider": "SANS", "price": 8525, "difficulty": "intermediate", "funding_type": "company", "_status": "in_progress"},
            {"cert_name": "GIAC GCIA", "provider": "SANS", "price": 8525, "difficulty": "advanced", "funding_type": "company", "_status": "planned"},
            {"cert_name": "CIS CISMP", "provider": "BCS", "price": 550, "difficulty": "intermediate", "funding_type": "company", "_status": "planned"},
        ],
    },
    {
        "username": "lead1",
        "password": "user2025",
        "plan": {
            "name": "SOC Lead Certification",
            "target_role": "SOC Manager",
            "status": "active",
            "notes": "Management track — leadership and governance certs",
        },
        "items": [
            {"cert_name": "CISSP", "provider": "ISC2", "price": 749, "difficulty": "advanced", "funding_type": "company", "_status": "in_progress"},
            {"cert_name": "CISM", "provider": "ISACA", "price": 760, "difficulty": "advanced", "funding_type": "company", "_status": "planned"},
            {"cert_name": "GIAC GSOM", "provider": "SANS", "price": 8525, "difficulty": "advanced", "funding_type": "company", "_status": "planned"},
            {"cert_name": "ITIL 4 Foundation", "provider": "PeopleCert", "price": 395, "difficulty": "beginner", "funding_type": "self", "_status": "completed"},
            {"cert_name": "ISO 27001 Lead Implementer", "provider": "BSI", "price": 1850, "difficulty": "advanced", "funding_type": "split", "_status": "planned"},
        ],
    },
    {
        "username": "soc_james",
        "password": "user2025",
        "plan": {
            "name": "Cloud Security Pathway",
            "target_role": "Cloud Security Engineer",
            "status": "active",
            "notes": "Contractor — cloud security specialisation",
        },
        "items": [
            {"cert_name": "AWS Solutions Architect Associate", "provider": "AWS", "price": 300, "difficulty": "intermediate", "funding_type": "self", "_status": "completed"},
            {"cert_name": "AWS Security Specialty", "provider": "AWS", "price": 300, "difficulty": "advanced", "funding_type": "company", "_status": "in_progress"},
            {"cert_name": "CCSP", "provider": "ISC2", "price": 599, "difficulty": "advanced", "funding_type": "company", "_status": "planned"},
            {"cert_name": "HashiCorp Terraform Associate", "provider": "HashiCorp", "price": 70, "difficulty": "intermediate", "funding_type": "self", "_status": "completed"},
            {"cert_name": "Azure Security Engineer Associate", "provider": "Microsoft", "price": 165, "difficulty": "intermediate", "funding_type": "tbd", "_status": "planned"},
        ],
    },
    {
        "username": "soc_tom",
        "password": "user2025",
        "plan": {
            "name": "Incident Response Specialist",
            "target_role": "Incident Responder",
            "status": "draft",
            "notes": "Contractor — planning IR specialisation track",
        },
        "items": [
            {"cert_name": "GIAC GCFE", "provider": "SANS", "price": 8525, "difficulty": "advanced", "funding_type": "tbd", "_status": "planned"},
            {"cert_name": "GIAC GCFA", "provider": "SANS", "price": 8525, "difficulty": "advanced", "funding_type": "tbd", "_status": "planned"},
            {"cert_name": "CompTIA Security+", "provider": "CompTIA", "price": 370, "difficulty": "intermediate", "funding_type": "company", "_status": "completed"},
        ],
    },
]


def main():
    for i, entry in enumerate(USERS_PLANS):
        username = entry["username"]
        s = requests.Session()

        # Rate limit: wait between users (5/min limit on login)
        if i > 0:
            print(f"  (waiting 15s for rate limit...)")
            time.sleep(15)

        # Login
        r = s.post(f"{BASE}/api/auth/login", json={
            "username": username,
            "password": entry["password"],
        })
        if r.status_code != 200:
            print(f"[FAIL] {username} login: {r.status_code} {r.text[:200]}")
            continue
        print(f"[OK]   {username} logged in")

        # Create plan (or find existing)
        plan_data = entry["plan"]
        r = s.post(f"{BASE}/api/skills/training-plans", json=plan_data)
        if r.status_code == 409:
            print(f"[SKIP] {username} plan already exists, fetching...")
            r2 = s.get(f"{BASE}/api/skills/training-plans")
            plans = r2.json().get("plans", [])
            plan_id = None
            for p in plans:
                if p["name"] == plan_data["name"]:
                    plan_id = p["id"]
                    break
            if not plan_id:
                print(f"[FAIL] {username} could not find existing plan")
                continue
        elif r.status_code in (200, 201):
            plan_id = r.json()["id"]
            print(f"[OK]   {username} plan created: id={plan_id}")
        else:
            print(f"[FAIL] {username} create plan: {r.status_code} {r.text[:200]}")
            continue

        # Prepare items for bulk add (without _status)
        raw_items = entry["items"]
        api_items = []
        status_map = {}  # cert_name -> desired status
        for item in raw_items:
            status_map[item["cert_name"]] = item["_status"]
            api_items.append({
                "cert_name": item["cert_name"],
                "provider": item.get("provider"),
                "price": item.get("price", 0),
                "difficulty": item.get("difficulty"),
                "funding_type": item.get("funding_type", "tbd"),
            })

        # Add items (wrapped in {"items": [...]})
        r = s.post(f"{BASE}/api/skills/training-plans/{plan_id}/items", json={"items": api_items})
        if r.status_code in (200, 201):
            plan_resp = r.json()
            items_list = plan_resp.get("items", [])
            print(f"[OK]   {username} plan has {len(items_list)} items")

            # Update status for items that need it
            for it in items_list:
                desired = status_map.get(it["cert_name"], "planned")
                if desired != "planned":
                    r3 = s.put(
                        f"{BASE}/api/skills/training-plans/{plan_id}/items/{it['id']}",
                        json={"status": desired},
                    )
                    if r3.status_code == 200:
                        print(f"       {it['cert_name']}: {desired}")
                    else:
                        print(f"[WARN] {it['cert_name']} status update: {r3.status_code}")
        else:
            print(f"[WARN] {username} add items: {r.status_code} {r.text[:200]}")

        # Activate plan if needed
        if plan_data["status"] == "active":
            s.put(f"{BASE}/api/skills/training-plans/{plan_id}", json={"status": "active"})

    print("\nDone! Login as lead1 to view the budget forecast dashboard.")


if __name__ == "__main__":
    main()
