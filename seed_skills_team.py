"""Seed script: Create SOC team members with varied skill assessments.

Creates 8 team members via the HTTP API, then seeds their skill
assessments, career goals, and historical snapshots directly via DB.

Usage:
    python seed_skills_team.py

Requires IXION to be running at http://127.0.0.1:8000
Admin: admin / admin2025
"""

import os
import random
import sys
import time
import requests
from datetime import date, timedelta

BASE = "http://127.0.0.1:8000"

# Add src to path for direct DB access
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

# ── Team profiles ──────────────────────────────────────────────────
TEAM = [
    {
        "username": "soc_sarah",
        "email": "sarah@localhost",
        "display_name": "Sarah Chen",
        "roles": ["analyst"],
        "career": {"current_role": "l2-analyst", "target_role": "threat-hunter"},
        "skills": {
            "siem-operations": 3, "log-analysis": 3, "kql-spl": 3, "log-parsing": 2, "siem-admin": 1,
            "alert-triage": 4, "forensic-collection": 2, "memory-analysis": 1, "timeline-analysis": 2, "ir-frameworks": 2,
            "osint": 2, "stix-taxii": 1, "mitre-attack": 3, "ioc-enrichment": 2, "intel-reporting": 1,
            "sigma-rules": 2, "yara-rules": 1, "detection-tuning": 2, "cicd-detections": 1,
            "python": 2, "powershell": 2, "bash-shell": 1, "git-version-control": 2,
            "tcp-ip-dns": 3, "packet-analysis": 3, "firewall-waf": 1,
        },
    },
    {
        "username": "soc_marcus",
        "email": "marcus@localhost",
        "display_name": "Marcus Williams",
        "roles": ["analyst"],
        "career": {"current_role": "l3-analyst", "target_role": "soc-lead"},
        "skills": {
            "siem-operations": 4, "log-analysis": 4, "kql-spl": 4, "log-parsing": 3, "siem-admin": 3,
            "alert-triage": 5, "forensic-collection": 3, "memory-analysis": 2, "timeline-analysis": 3, "ir-frameworks": 3,
            "osint": 2, "stix-taxii": 2, "mitre-attack": 4, "ioc-enrichment": 3, "intel-reporting": 2,
            "sigma-rules": 3, "yara-rules": 2, "detection-tuning": 4, "detection-coverage": 3,
            "python": 3, "powershell": 3, "bash-shell": 2, "git-version-control": 3,
            "tcp-ip-dns": 3, "packet-analysis": 3, "firewall-waf": 2,
            "team-leadership": 2, "stakeholder-comms": 2, "risk-management": 1,
        },
    },
    {
        "username": "soc_priya",
        "email": "priya@localhost",
        "display_name": "Priya Patel",
        "roles": ["analyst"],
        "career": {"current_role": "threat-intel", "target_role": "threat-hunter"},
        "skills": {
            "siem-operations": 2, "log-analysis": 2, "kql-spl": 2,
            "alert-triage": 3, "ir-frameworks": 2,
            "osint": 5, "stix-taxii": 5, "mitre-attack": 4, "ioc-enrichment": 4, "intel-reporting": 5,
            "sigma-rules": 2, "yara-rules": 2, "detection-tuning": 1,
            "python": 3, "powershell": 1, "bash-shell": 2, "git-version-control": 2,
            "tcp-ip-dns": 2, "packet-analysis": 1,
            "stakeholder-comms": 3, "risk-management": 2,
        },
    },
    {
        "username": "soc_james",
        "email": "james@localhost",
        "display_name": "James O'Brien",
        "roles": ["analyst"],
        "career": {"current_role": "incident-responder", "target_role": "digital-forensics"},
        "skills": {
            "siem-operations": 2, "log-analysis": 3,
            "alert-triage": 4, "forensic-collection": 4, "memory-analysis": 4, "timeline-analysis": 4, "ir-frameworks": 4,
            "mitre-attack": 3, "ioc-enrichment": 2,
            "yara-rules": 2,
            "python": 2, "powershell": 3, "bash-shell": 2,
            "tcp-ip-dns": 3, "packet-analysis": 3,
            "disk-imaging": 4, "reverse-engineering": 2, "sandbox-analysis": 3, "registry-artifact": 4,
        },
    },
    {
        "username": "soc_elena",
        "email": "elena@localhost",
        "display_name": "Elena Kovacs",
        "roles": ["analyst"],
        "career": {"current_role": "detection-engineer", "target_role": "security-engineer"},
        "skills": {
            "siem-operations": 4, "log-analysis": 4, "kql-spl": 5, "log-parsing": 5, "siem-admin": 4,
            "alert-triage": 3, "ir-frameworks": 2,
            "mitre-attack": 4,
            "sigma-rules": 5, "yara-rules": 4, "detection-tuning": 5, "cicd-detections": 4, "detection-coverage": 4,
            "python": 4, "powershell": 2, "bash-shell": 3, "git-version-control": 4,
            "tcp-ip-dns": 3, "firewall-waf": 2, "cloud-platforms": 2, "container-security": 1,
        },
    },
    {
        "username": "soc_tom",
        "email": "tom@localhost",
        "display_name": "Tom Richardson",
        "roles": ["analyst"],
        "career": {"current_role": "l1-analyst", "target_role": "l2-analyst"},
        "skills": {
            "siem-operations": 2, "log-analysis": 1, "kql-spl": 1,
            "alert-triage": 2, "ir-frameworks": 1,
            "mitre-attack": 1,
            "python": 1, "powershell": 1,
            "tcp-ip-dns": 2, "packet-analysis": 1,
        },
    },
    {
        "username": "soc_aisha",
        "email": "aisha@localhost",
        "display_name": "Aisha Mohammed",
        "roles": ["analyst"],
        "career": {"current_role": "security-engineer", "target_role": "cloud-security"},
        "skills": {
            "siem-operations": 3, "log-analysis": 2, "siem-admin": 3,
            "alert-triage": 2, "ir-frameworks": 2,
            "mitre-attack": 2,
            "cicd-detections": 3,
            "python": 4, "powershell": 3, "bash-shell": 4, "git-version-control": 4,
            "tcp-ip-dns": 4, "firewall-waf": 4, "cloud-platforms": 4, "container-security": 3,
            "threat-modeling": 3, "zero-trust": 3, "security-frameworks": 2,
        },
    },
    {
        "username": "soc_chen",
        "email": "chen@localhost",
        "display_name": "Chen Wei",
        "roles": ["analyst"],
        "career": {"current_role": "threat-hunter", "target_role": "malware-analyst"},
        "skills": {
            "siem-operations": 4, "log-analysis": 4, "kql-spl": 5, "log-parsing": 3,
            "alert-triage": 4, "forensic-collection": 3, "memory-analysis": 3, "timeline-analysis": 3, "ir-frameworks": 3,
            "osint": 3, "stix-taxii": 3, "mitre-attack": 5, "ioc-enrichment": 3, "intel-reporting": 2,
            "sigma-rules": 4, "yara-rules": 3, "detection-tuning": 3, "detection-coverage": 3,
            "python": 3, "powershell": 2, "bash-shell": 3, "git-version-control": 3,
            "tcp-ip-dns": 3, "packet-analysis": 4,
            "sandbox-analysis": 3, "reverse-engineering": 2,
            "pentest-tools": 2, "ad-attacks": 2,
        },
    },
]

# Skills to include in historical snapshots
SNAPSHOT_SKILLS = [
    "siem-operations", "log-analysis", "kql-spl", "alert-triage",
    "forensic-collection", "mitre-attack", "osint", "sigma-rules",
    "python", "tcp-ip-dns", "disk-imaging", "threat-modeling",
    "team-leadership", "ir-frameworks", "detection-tuning",
]


def main():
    session = requests.Session()

    # Login as admin
    print("Logging in as admin...")
    resp = session.post(f"{BASE}/api/auth/login", json={
        "username": "admin", "password": "admin2025",
    })
    if resp.status_code != 200:
        print(f"Login failed: {resp.status_code} {resp.text}")
        return
    print("  OK")

    # Create users via API
    for t in TEAM:
        print(f"Creating user {t['username']}...")
        resp = session.post(f"{BASE}/api/users", json={
            "username": t["username"],
            "email": t["email"],
            "password": "user2025",
            "display_name": t["display_name"],
            "roles": t["roles"],
        })
        if resp.status_code == 200:
            print(f"  Created (id={resp.json().get('id')})")
        elif resp.status_code == 400 and "already exists" in resp.text:
            print("  Already exists")
        else:
            print(f"  Error: {resp.status_code} {resp.text}")
        time.sleep(0.1)  # Avoid rate limits

    # ── Direct DB access for skills data ───────────────────────────
    print("\n--- Seeding skills data directly via database ---")
    try:
        from pathlib import Path
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        from ixion.models.base import Base
        from ixion.models.skills import SkillAssessment, UserCareerGoal, AssessmentSnapshot
        from ixion.models.user import User

        # Use the project-local DB (start_ixion.ps1 runs from project dir so CWD=project)
        db_path = Path(os.path.dirname(os.path.abspath(__file__))) / ".ixion" / "ixion.db"
        if not db_path.exists():
            # Fallback to home dir
            db_path = Path.home() / ".ixion" / "ixion.db"
        print(f"Using database: {db_path}")
        engine = create_engine(f"sqlite:///{db_path}", echo=False)

        # Create tables if they don't exist
        Base.metadata.create_all(engine)
        print("Ensured skills tables exist.")

        factory = sessionmaker(bind=engine, expire_on_commit=False)
        db = factory()

        # Seed assessments and career goals for each user
        for t in TEAM:
            user = db.query(User).filter(User.username == t["username"]).first()
            if not user:
                print(f"  User {t['username']} not found, skipping")
                continue

            print(f"Seeding skills for {t['username']} (id={user.id})...")

            # Career goal (upsert)
            goal = db.query(UserCareerGoal).filter(UserCareerGoal.user_id == user.id).first()
            if goal:
                goal.current_role = t["career"]["current_role"]
                goal.target_role = t["career"]["target_role"]
            else:
                db.add(UserCareerGoal(
                    user_id=user.id,
                    current_role=t["career"]["current_role"],
                    target_role=t["career"]["target_role"],
                ))
            print(f"  Career goal: {t['career']['current_role']} -> {t['career']['target_role']}")

            # Skill assessments (upsert)
            count = 0
            for skill_key, rating in t["skills"].items():
                existing = db.query(SkillAssessment).filter(
                    SkillAssessment.user_id == user.id,
                    SkillAssessment.skill_key == skill_key,
                ).first()
                if existing:
                    existing.rating = rating
                else:
                    db.add(SkillAssessment(
                        user_id=user.id,
                        skill_key=skill_key,
                        rating=rating,
                    ))
                count += 1
            print(f"  {count} skill assessments")

        db.commit()

        # Seed historical snapshots (6 weeks)
        print("\nSeeding historical snapshots...")
        today = date.today()
        for weeks_ago in range(6, 0, -1):
            snap_date = today - timedelta(weeks=weeks_ago)
            existing = db.query(AssessmentSnapshot).filter(
                AssessmentSnapshot.snapshot_date == snap_date
            ).first()
            if existing:
                print(f"  {snap_date}: already exists, skipping")
                continue

            count = 0
            for skill_key in SNAPSHOT_SKILLS:
                # Simulate gradual improvement
                base_avg = 2.0 + (6 - weeks_ago) * 0.15 + random.uniform(-0.3, 0.3)
                base_avg = max(1.0, min(5.0, base_avg))
                assessors = random.randint(4, 8)
                coverage = random.randint(1, assessors)

                db.add(AssessmentSnapshot(
                    snapshot_date=snap_date,
                    skill_key=skill_key,
                    avg_proficiency=round(base_avg, 2),
                    num_assessors=assessors,
                    coverage_count=coverage,
                ))
                count += 1

            db.commit()
            print(f"  {snap_date}: {count} skill snapshots")

        # Also create today's snapshot from real aggregated data
        existing = db.query(AssessmentSnapshot).filter(
            AssessmentSnapshot.snapshot_date == today
        ).first()
        if not existing:
            from sqlalchemy import func as sqlfunc
            results = db.query(
                SkillAssessment.skill_key,
                sqlfunc.avg(SkillAssessment.rating).label("avg_prof"),
                sqlfunc.count(SkillAssessment.user_id).label("num"),
            ).group_by(SkillAssessment.skill_key).all()
            cov_results = db.query(
                SkillAssessment.skill_key,
                sqlfunc.count(SkillAssessment.user_id).label("cov"),
            ).filter(SkillAssessment.rating >= 3).group_by(SkillAssessment.skill_key).all()
            cov_map = {r.skill_key: r.cov for r in cov_results}
            snap_count = 0
            for r in results:
                db.add(AssessmentSnapshot(
                    snapshot_date=today,
                    skill_key=r.skill_key,
                    avg_proficiency=round(float(r.avg_prof), 2),
                    num_assessors=r.num,
                    coverage_count=cov_map.get(r.skill_key, 0),
                ))
                snap_count += 1
            db.commit()
            print(f"  {today} (today): {snap_count} skill snapshots from real data")
        else:
            print(f"  {today} (today): already exists")

        db.close()

    except Exception as e:
        print(f"Database seeding failed: {e}")
        import traceback
        traceback.print_exc()
        return

    print("\n=== Done! ===")
    print("8 team members seeded with skill assessments.")
    print("6 weeks of historical snapshots + today's snapshot created.")
    print()
    print("Team members:")
    for t in TEAM:
        print(f"  {t['username']:15s} ({t['display_name']:20s}) {t['career']['current_role']:25s} -> {t['career']['target_role']}")
    print()
    print("Login as any soc_* user (password: user2025) to see self-assessment.")
    print("Login as lead1 or admin to see the Team Skills heatmap.")


if __name__ == "__main__":
    main()
